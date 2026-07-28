#!/usr/bin/env python3
"""taskpulse - audit Windows scheduled tasks and report which ones are silently failing.

Windows tells you a task's Last Run Result as a bare number and nothing else. It never
tells you that a Daily task has no next run time, that a task is overdue, or what
0x8007052E actually means. taskpulse joins those fields and prints a verdict.

Read-only by design. It shells out to `Get-ScheduledTask | Get-ScheduledTaskInfo`,
classifies the result in memory, and prints. What it refuses to do:

  * never creates, edits, enables, disables, deletes, starts or stops a task
  * never opens a network connection, and never asks for or stores a credential
  * never reads or writes a config file - every knob is a command line flag
  * never writes anywhere except stdout, or the one path you pass to --out

Exit codes: 0 = nothing in an Error state, 2 = at least one task in an Error state,
1 = taskpulse itself failed. Suitable as a monitoring check.

Python 3.8+, standard library only.
"""

from __future__ import annotations

import argparse
import csv
import ctypes
import json
import ntpath
import os
import re
import shlex
import subprocess
import sys
from datetime import datetime, timezone

__version__ = "1.0.0"

# Task Scheduler status codes (SCHED_S_*). These are "success" HRESULTs that mean
# something other than "the job ran and worked".
TASK_READY = 0x00041300
TASK_RUNNING = 0x00041301
TASK_DISABLED = 0x00041302
TASK_NOT_YET_RUN = 0x00041303  # 267011 - the most common code on a stock box
TASK_NO_MORE_RUNS = 0x00041304
TASK_NOT_SCHEDULED = 0x00041305
TASK_TERMINATED = 0x00041306
TASK_NO_VALID_TRIGGERS = 0x00041307
TASK_EVENT_TRIGGER = 0x00041308
TASK_SOME_TRIGGERS_FAILED = 0x0004131B
TASK_BATCH_LOGON_PROBLEM = 0x0004131C
TASK_QUEUED = 0x00041325

NON_ERROR_CODES = frozenset(
    [0, TASK_READY, TASK_RUNNING, TASK_DISABLED, TASK_NOT_YET_RUN,
     TASK_NO_MORE_RUNS, TASK_EVENT_TRIGGER, TASK_QUEUED]
)
WARNING_CODES = frozenset(
    [TASK_NOT_SCHEDULED, TASK_TERMINATED, TASK_NO_VALID_TRIGGERS,
     TASK_SOME_TRIGGERS_FAILED, TASK_BATCH_LOGON_PROBLEM]
)

# Trigger buckets where "no next run time" is normal, not a fault. A Logon-triggered
# task has no next run until someone logs on; a Daily task with none is broken.
NO_NEXT_RUN_EXPECTED = frozenset(
    ["", "No Triggers", "One Time", "Logon", "Startup", "Event", "Idle",
     "Registration", "Session State Change"]
)

PYTHON_EXES = frozenset(["python.exe", "pythonw.exe", "py.exe"])
POWERSHELL_EXES = frozenset(["powershell.exe", "pwsh.exe", "powershell_ise.exe"])
CMD_EXES = frozenset(["cmd.exe"])
SCRIPT_HOST_EXES = frozenset(["cscript.exe", "wscript.exe"])
EXT_KIND = {
    ".bat": "BatchScript", ".cmd": "BatchScript", ".jar": "Jar",
    ".js": "JavaScript", ".ps1": "PowerShellScript", ".py": "PythonScript",
    ".pyw": "PythonScript", ".vbs": "VBScript", ".exe": "Executable",
}

PS_QUERY = r"""
$ErrorActionPreference = "Stop"

function Convert-ToIsoUtcOrNull {
    param($Value)
    if ($null -eq $Value) { return $null }
    try {
        if ($Value -is [datetime] -and $Value -ge [datetime]'2000-01-01') {
            return $Value.ToUniversalTime().ToString('o')
        }
    } catch { return $null }
    return $null
}

function Get-TriggerTypeName {
    param($Trigger)
    $name = ""
    try { $name = [string]$Trigger.CimClass.CimClassName } catch { $name = "" }
    if (-not $name) { $name = [string]$Trigger }
    $name = $name -replace '^MSFT_Task', ''
    $name = $name -replace 'Trigger$', ''
    return $name
}

$rows = foreach ($task in Get-ScheduledTask) {
    $info = $null
    try {
        $info = Get-ScheduledTaskInfo -TaskName $task.TaskName -TaskPath $task.TaskPath
    } catch { }

    $exe = ""; $args = ""
    try {
        $a = @($task.Actions)
        if ($a.Count -gt 0) {
            $exe = [string]$a[0].Execute
            $args = [string]$a[0].Arguments
        }
    } catch { }

    $triggerTypes = ""
    try {
        $triggerTypes = (@($task.Triggers) | ForEach-Object { Get-TriggerTypeName $_ } |
            Where-Object { $_ } | Select-Object -Unique) -join " | "
    } catch { }

    [pscustomobject]@{
        task_name             = [string]$task.TaskName
        task_path             = [string]$task.TaskPath
        state                 = [string]$task.State
        enabled               = [bool]$task.Settings.Enabled
        author                = [string]$task.Author
        run_as_user           = [string]$task.Principal.UserId
        executable            = $exe
        arguments             = $args
        trigger_types         = $triggerTypes
        last_run_time         = if ($info) { Convert-ToIsoUtcOrNull $info.LastRunTime } else { $null }
        next_run_time         = if ($info) { Convert-ToIsoUtcOrNull $info.NextRunTime } else { $null }
        last_task_result      = if ($info) { [int64]$info.LastTaskResult } else { $null }
        number_of_missed_runs = if ($info) { [int64]$info.NumberOfMissedRuns } else { $null }
    }
}

$rows | ConvertTo-Json -Depth 4 -Compress
"""


# --------------------------------------------------------------------------
# pure helpers - no Windows API, no subprocess, no clock
# --------------------------------------------------------------------------

def text_of(value):
    """Normalise a possibly-None PowerShell value to a stripped string."""
    if value is None:
        return ""
    return str(value).strip()


def to_unsigned(code):
    """Result codes arrive signed (-2147024894) or unsigned (2147942402). Same code."""
    if code is None or (isinstance(code, str) and not code.strip()):
        return None
    try:
        return int(code) & 0xFFFFFFFF
    except (TypeError, ValueError):
        return None


def describe_result(code):
    """Decode a task result code using the OS message table.

    A hand-maintained HRESULT table is both redundant and wrong: the OS knows
    0x8007052E is "the user name or password is incorrect", which is exactly the
    failure you want named. 0x8007xxxx is HRESULT-wrapped Win32 error xxxx; current
    Windows resolves either form, so unwrapping is belt-and-braces, not a fix.
    """
    unsigned = to_unsigned(code)
    if unsigned is None:
        return "no result recorded"
    if unsigned == 0:
        # Short-circuit: ctypes.FormatError(0) is stateful and returns the
        # "cannot find message text" placeholder after any failed lookup.
        return "success"
    win32 = (unsigned & 0xFFFF) if (unsigned & 0xFFFF0000) == 0x80070000 else unsigned
    formatter = getattr(ctypes, "FormatError", None)  # Windows-only
    message = ""
    if formatter is not None:
        try:
            message = formatter(ctypes.c_long(win32).value).strip()
        except Exception:
            message = ""
    if message and not message.startswith("<") and "message text for message number" not in message:
        return message
    return "unmapped result 0x{:08X}".format(unsigned)


def parse_dt(value):
    """Parse an ISO-8601 timestamp into an aware UTC datetime, or None."""
    text = text_of(value)
    if not text:
        return None
    # PowerShell's round-trip format emits 7 fractional digits; fromisoformat only
    # accepts 3 or 6 before Python 3.11, so truncate rather than fail the parse.
    text = re.sub(r"(\.\d{6})\d+", r"\1", text.replace("Z", "+00:00"))
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def trigger_tokens(trigger_types):
    """Normalise raw trigger class names into a set of bucket tokens."""
    names = {
        "boot": "Startup", "daily": "Daily", "event": "Event", "idle": "Idle",
        "logon": "Logon", "monthly": "Monthly", "monthlydow": "Monthly",
        "registration": "Registration", "sessionstatechange": "Session State Change",
        "time": "One Time", "weekly": "Weekly",
    }
    tokens = set()
    for raw in text_of(trigger_types).split("|"):
        # Accept both the friendly name and the raw CIM class (MSFT_TaskDailyTrigger).
        token = re.sub(r"Trigger$", "", re.sub(r"^MSFT_Task", "", raw.strip()))
        if token:
            tokens.add(names.get(token.lower(), token))
    return tokens


def schedule_bucket(trigger_types):
    """Display label for a task's triggers. Three or more collapse; this is cosmetic."""
    tokens = trigger_tokens(trigger_types)
    if not tokens:
        return "No Triggers"
    if len(tokens) <= 2:
        return " + ".join(sorted(tokens))
    return "Multiple / Other"


def expects_next_run(trigger_types):
    """True when a missing NextRunTime is a genuine fault for these triggers.

    Takes the RAW trigger types, never schedule_bucket()'s label: at three or more
    triggers that label collapses to "Multiple / Other", which would strip the
    exemption from a task whose every trigger is Logon/Event/Registration.

    A blank next run is only expected when EVERY trigger is one that never schedules
    ahead. One Daily trigger sets NextRunTime regardless of what else is attached, so
    "Daily + Logon" with no next run is still broken.
    """
    return not all(token in NO_NEXT_RUN_EXPECTED for token in trigger_tokens(trigger_types))


def unquote(value):
    text = text_of(value)
    if len(text) >= 2 and text[0] == text[-1] == '"':
        return text[1:-1].strip()
    return text


def split_args(value):
    text = text_of(value)
    if not text:
        return []
    try:
        return [part.strip() for part in shlex.split(text, posix=False) if part.strip()]
    except ValueError:
        return [text]


def extension_of(path_value):
    return os.path.splitext(unquote(path_value))[1].lower()


def classify_command(executable, arguments):
    """Find the real script behind an interpreter invocation.

    Returns (target, kind). `python.exe C:\\jobs\\etl.py` reports etl.py, not
    python.exe - the interpreter is never the thing that broke. This is the one
    part of the report Windows genuinely does not give you.
    """
    exe = unquote(executable)
    tokens = [unquote(token) for token in split_args(arguments)]
    lowered = [token.lower() for token in tokens]
    name = ntpath.basename(exe).lower()
    ext = extension_of(exe)

    if name in PYTHON_EXES:
        for token in tokens:
            if token and not token.startswith("-") and extension_of(token) in (".py", ".pyw"):
                return token, "PythonScript"
        if "-c" in lowered:
            return exe, "PythonInline"
        if "-m" in lowered:
            index = lowered.index("-m")
            if index + 1 < len(tokens):
                return tokens[index + 1], "PythonModule"
        return exe, "Python"

    if name in POWERSHELL_EXES:
        for index, token in enumerate(lowered):
            if token in ("-file", "-f") and index + 1 < len(tokens):
                return unquote(tokens[index + 1]), "PowerShellScript"
        for token in tokens:
            if token and not token.startswith("-") and extension_of(token) == ".ps1":
                return token, "PowerShellScript"
        if "-command" in lowered or "-c" in lowered or "-encodedcommand" in lowered:
            return exe, "PowerShellInline"
        return exe, "PowerShell"

    if name in CMD_EXES:
        for token in tokens:
            if token and token[0] not in "/-" and extension_of(token) in (".bat", ".cmd"):
                return token, "BatchScript"
        return exe, "CommandShell"

    if name in SCRIPT_HOST_EXES:
        for token in tokens:
            token_ext = extension_of(token)
            if token and token[0] not in "/-" and token_ext in (".vbs", ".js"):
                return token, "VBScript" if token_ext == ".vbs" else "JavaScript"
        return exe, "ScriptHost"

    if ext in EXT_KIND:
        return exe, EXT_KIND[ext]
    return exe, "Executable" if exe else ""


def health_status(task, now=None):
    """The verdict Windows never computes: join five fields into one word.

    `task` is a plain dict as produced by read_tasks(). `now` is an aware datetime
    used only for the overdue test, so this stays pure and testable.
    """
    if not task.get("enabled", True):
        return "Disabled"

    state = text_of(task.get("state")).lower()
    code = to_unsigned(task.get("last_task_result"))
    missed = int(task.get("number_of_missed_runs") or 0)
    next_run = parse_dt(task.get("next_run_time"))
    triggers = task.get("trigger_types")
    overdue = bool(now and next_run and next_run < now and state != "running")

    if state == "running" or code in (TASK_RUNNING, TASK_QUEUED):
        return "Running"
    if code in WARNING_CODES:
        return "Warning"
    if missed > 0 or overdue:
        return "Warning"
    # TASK_NO_MORE_RUNS *means* "no next run"; a recurring task whose EndBoundary
    # has passed is spent, not broken, so the code exempts it as well as the bucket.
    if next_run is None and code != TASK_NO_MORE_RUNS and expects_next_run(triggers):
        return "Warning"
    if code is None or code == TASK_NOT_YET_RUN:
        return "NotYetRun"
    if code in NON_ERROR_CODES:
        return "Success"
    return "Error"


def attention_reason(task, status, now=None):
    """One sentence saying why this task earned its status."""
    reasons = []
    missed = int(task.get("number_of_missed_runs") or 0)
    code = to_unsigned(task.get("last_task_result"))
    next_run = parse_dt(task.get("next_run_time"))
    triggers = task.get("trigger_types")
    result_text = describe_result(task.get("last_task_result"))

    if missed > 0:
        reasons.append("{} missed run(s)".format(missed))
    if now and next_run and next_run < now:
        hours = (now - next_run).total_seconds() / 3600.0
        reasons.append("next run overdue by {:.1f} hour(s)".format(hours))
    # Same two exemptions as health_status, or the reason contradicts the verdict.
    if next_run is None and code != TASK_NO_MORE_RUNS and expects_next_run(triggers):
        reasons.append("{} task has no next run time".format(
            schedule_bucket(triggers).lower()))
    if status == "Disabled":
        reasons.append("task is disabled")
    elif status == "Running":
        reasons.append("task is currently running")
    elif status == "NotYetRun" and not reasons:
        reasons.append("task has not yet run")
    elif result_text:
        reasons.append(result_text)
    return "; ".join(reasons) or result_text


def evaluate(task, now=None):
    """Enrich one raw task dict into a report row. Pure: dict in, dict out."""
    target, kind = classify_command(task.get("executable"), task.get("arguments"))
    status = health_status(task, now)
    path = text_of(task.get("task_path")) or "\\"
    if not path.endswith("\\"):
        path += "\\"
    return {
        "task": path + text_of(task.get("task_name")),
        "status": status,
        "state": text_of(task.get("state")),
        "enabled": bool(task.get("enabled", True)),
        "schedule": schedule_bucket(task.get("trigger_types")),
        "last_run_time": text_of(task.get("last_run_time")),
        "next_run_time": text_of(task.get("next_run_time")),
        "last_result_code": to_unsigned(task.get("last_task_result")),
        "last_result_text": describe_result(task.get("last_task_result")),
        "missed_runs": int(task.get("number_of_missed_runs") or 0),
        "target": target,
        "target_kind": kind,
        "run_as_user": text_of(task.get("run_as_user")),
        "author": text_of(task.get("author")),
        "reason": attention_reason(task, status, now),
    }


def is_microsoft_task(task):
    """Stock Windows ships ~200 of its own tasks; they drown out yours."""
    path = text_of(task.get("task_path")).replace("/", "\\").lower()
    return path.startswith("\\microsoft\\")


# --------------------------------------------------------------------------
# the only impure function: talk to Task Scheduler
# --------------------------------------------------------------------------

def rows_from_json(raw):
    """Normalise ConvertTo-Json output to a list. Always a list, never None.

    ConvertTo-Json emits a bare object for one row and the literal `null` for zero
    rows, so `json.loads` can hand back a dict or None where a list is expected.
    """
    text = text_of(raw)
    if not text:
        return []
    parsed = json.loads(text)
    if parsed is None:
        return []
    return [parsed] if isinstance(parsed, dict) else list(parsed)


def read_tasks(timeout=120):
    """Run the read-only PowerShell query and return raw task dicts."""
    if os.name != "nt":
        raise RuntimeError("taskpulse reads Windows Task Scheduler; this is not Windows.")
    command = ["powershell", "-NoProfile", "-NonInteractive",
               "-ExecutionPolicy", "Bypass", "-Command", PS_QUERY]
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=timeout)
    stdout = result.stdout.decode("utf-8", "replace")
    if result.returncode != 0:
        raise RuntimeError("Task Scheduler query failed: "
                           + result.stderr.decode("utf-8", "replace").strip())
    return rows_from_json(stdout)


# --------------------------------------------------------------------------
# output
# --------------------------------------------------------------------------

COLUMNS = ["status", "task", "schedule", "last_result_text", "reason"]


def render_table(rows):
    header = ["STATUS", "TASK", "SCHEDULE", "LAST RESULT", "WHY"]
    table = [header] + [[str(row.get(key, "")) for key in COLUMNS] for row in rows]
    widths = [min(60, max(len(line[i]) for line in table)) for i in range(len(header))]
    out = []
    for index, line in enumerate(table):
        cells = [cell[:widths[i]].ljust(widths[i]) for i, cell in enumerate(line)]
        out.append("  ".join(cells).rstrip())
        if index == 0:
            out.append("  ".join("-" * width for width in widths))
    return "\n".join(out)


def write_output(rows, fmt, stream):
    if fmt == "json":
        json.dump(rows, stream, indent=2, sort_keys=True)
        stream.write("\n")
    elif fmt == "csv":
        fields = list(evaluate({}).keys())
        writer = csv.DictWriter(stream, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
    else:
        stream.write(render_table(rows) + "\n" if rows else "No tasks need attention.\n")


# --------------------------------------------------------------------------
# self-test - offline, no network, no credentials, no Task Scheduler
# --------------------------------------------------------------------------

def self_test():
    checks = [0]

    def ok(condition, label):
        checks[0] += 1
        if not condition:
            raise AssertionError("FAIL #{}: {}".format(checks[0], label))

    windows = hasattr(ctypes, "FormatError")
    now = datetime(2026, 7, 28, 12, 0, tzinfo=timezone.utc)

    # --- result codes arrive both signed and unsigned; both must normalise ---
    ok(to_unsigned(-2147024894) == 0x80070002, "signed form normalises to unsigned")
    ok(to_unsigned(2147942402) == 0x80070002, "unsigned form passes through")
    ok(to_unsigned(267011) == TASK_NOT_YET_RUN, "267011 is SCHED_S_TASK_HAS_NOT_RUN")
    ok(to_unsigned(None) is None, "missing code stays None")
    ok(to_unsigned("") is None, "empty code stays None")
    ok(to_unsigned("267011") == 267011, "numeric string is accepted")
    ok(to_unsigned("nonsense") is None, "junk code does not raise")
    ok(describe_result(None) == "no result recorded", "None result is reported, not guessed")
    ok(describe_result(0) == "success", "0 is success without touching the message table")
    ok(describe_result(-2147024894) == describe_result(0x80070002),
       "signed and unsigned decode identically")

    if windows:
        # Real codes observed on a live box. The OS message table is the source of
        # truth; a hand-written table gets 0x8007052E and 0x8007007A wrong.
        ok("cannot find the file" in describe_result(0x80070002).lower(),
           "0x80070002 unwraps to Win32 2 (file not found)")
        ok("user name or password" in describe_result(0x8007052E).lower(),
           "0x8007052E is a bad service-account password")
        ok("data area" in describe_result(0x8007007A).lower(),
           "0x8007007A is not 'access denied'")
        ok("has not yet run" in describe_result(267011).lower(),
           "scheduler status codes decode too")
        ok("currently running" in describe_result(TASK_RUNNING).lower(),
           "TASK_RUNNING decodes")
        ok(describe_result(0x40010004).startswith("unmapped result 0x"),
           "codes with no message text report as unmapped")
        ok(describe_result(0) == "success",
           "FormatError(0) statefulness cannot leak after a failed lookup")
        ok(describe_result(0x80070002) == describe_result(2),
           "0x8007xxxx and bare xxxx decode to the same text")

    # --- trigger buckets ---
    ok(schedule_bucket("Daily") == "Daily", "single daily trigger")
    ok(schedule_bucket("MSFT_TaskDailyTrigger") == "Daily", "raw CIM class name maps")
    ok(schedule_bucket("Logon") == "Logon", "logon bucket")
    ok(schedule_bucket("") == "No Triggers", "no triggers")
    ok(schedule_bucket("Daily | Weekly") == "Daily + Weekly", "two buckets combine sorted")
    ok(schedule_bucket("Daily | Weekly | Logon") == "Multiple / Other", "three or more collapse")
    ok(schedule_bucket("Boot") == "Startup", "boot maps to startup")
    ok(expects_next_run("Daily") is True, "a daily task must have a next run")
    ok(expects_next_run("Logon") is False, "a logon task legitimately has none")
    ok(expects_next_run("Event") is False, "an event task legitimately has none")
    ok(expects_next_run("") is False, "an untriggered task legitimately has none")
    ok(expects_next_run("Daily | Logon") is True,
       "the Daily half of a mixed task still owes a next run")
    ok(expects_next_run("Registration | Logon | Event") is False,
       "3+ triggers keep their exemption; the display label collapses, the check must not")
    ok(schedule_bucket("Registration | Logon | Event") == "Multiple / Other",
       "the display label still collapses at 3+")
    ok(expects_next_run("MSFT_TaskLogonTrigger | MSFT_TaskEventTrigger "
                        "| MSFT_TaskRegistrationTrigger") is False,
       "raw CIM class names normalise before the exemption check")
    ok(trigger_tokens("Daily | Daily | MSFT_TaskDailyTrigger") == {"Daily"},
       "duplicate and raw spellings of one trigger collapse to one token")

    # --- wrapper unwrapping: report the script, not the interpreter ---
    ok(classify_command(r"C:\Python313\python.exe", r"C:\jobs\etl.py --full")
       == (r"C:\jobs\etl.py", "PythonScript"), "python wrapper unwraps to the .py")
    ok(classify_command(r"C:\Python313\python.exe", r'"C:\my jobs\etl.py"')
       == (r"C:\my jobs\etl.py", "PythonScript"), "quoted script path is unquoted")
    ok(classify_command("python.exe", '-c "import x"')[1] == "PythonInline",
       "python -c has no script file and is labelled inline")
    ok(classify_command("python.exe", "-m pip list") == ("pip", "PythonModule"),
       "python -m reports the module")
    ok(classify_command("powershell.exe", r'-NoProfile -File "C:\jobs\sync.ps1"')
       == (r"C:\jobs\sync.ps1", "PowerShellScript"), "-File wins over positional scan")
    ok(classify_command("powershell.exe", r"C:\jobs\sync.ps1")[1] == "PowerShellScript",
       "positional .ps1 is found without -File")
    ok(classify_command("powershell.exe", "-Command Get-Date")[1] == "PowerShellInline",
       "powershell -Command is inline, not a script")
    ok(classify_command("cmd.exe", r"/c C:\jobs\nightly.bat")
       == (r"C:\jobs\nightly.bat", "BatchScript"), "cmd /c switch is skipped")
    ok(classify_command("cscript.exe", r"//B C:\jobs\legacy.vbs")
       == (r"C:\jobs\legacy.vbs", "VBScript"), "cscript switch is skipped")
    ok(classify_command(r"C:\tools\backup.exe", "") == (r"C:\tools\backup.exe", "Executable"),
       "a direct exe is its own target")
    ok(classify_command("", "") == ("", ""), "an actionless task classifies empty")

    # --- health: the verdict Windows does not compute ---
    base = {"enabled": True, "state": "Ready", "trigger_types": "Daily",
            "last_task_result": 0, "number_of_missed_runs": 0,
            "next_run_time": "2026-07-29T02:00:00+00:00"}

    def variant(**kwargs):
        row = dict(base)
        row.update(kwargs)
        return row

    ok(health_status(base, now) == "Success", "green task is Success")
    ok(health_status(variant(enabled=False), now) == "Disabled", "disabled short-circuits")
    ok(health_status(variant(state="Running", last_task_result=None), now) == "Running",
       "running state wins over a missing result")
    ok(health_status(variant(last_task_result=TASK_QUEUED), now) == "Running",
       "queued counts as running")
    ok(health_status(variant(last_task_result=-2147024894), now) == "Error",
       "a signed failure HRESULT is an Error")
    ok(health_status(variant(last_task_result=TASK_NOT_YET_RUN), now) == "NotYetRun",
       "never-run is not a failure")
    ok(health_status(variant(last_task_result=None), now) == "NotYetRun",
       "no result recorded is not a failure")
    ok(health_status(variant(number_of_missed_runs=3), now) == "Warning",
       "missed runs are a Warning even with result 0")
    ok(health_status(variant(next_run_time="2026-07-27T02:00:00+00:00"), now) == "Warning",
       "next run in the past is overdue")
    ok(health_status(variant(next_run_time="2026-07-27T02:00:00+00:00", state="Running"), now)
       == "Running", "a long-running task is not overdue")
    ok(health_status(variant(next_run_time=None), now) == "Warning",
       "a daily task with no next run is broken")
    ok(health_status(variant(next_run_time=None, trigger_types="Logon"), now) == "Success",
       "a logon task with no next run is NOT a fault")
    ok(health_status(variant(next_run_time=None, trigger_types="Event"), now) == "Success",
       "an event task with no next run is NOT a fault")
    ok(health_status(variant(last_task_result=TASK_NO_VALID_TRIGGERS), now) == "Warning",
       "no-valid-triggers is a Warning, not an Error")
    ok(health_status(variant(last_task_result=TASK_TERMINATED), now) == "Warning",
       "user-terminated is a Warning")
    ok(health_status(variant(last_task_result=TASK_NO_MORE_RUNS, next_run_time=None,
                             trigger_types="One Time"), now) == "Success",
       "a spent one-time task is fine")
    spent_daily = variant(last_task_result=TASK_NO_MORE_RUNS, next_run_time=None,
                          trigger_types="Daily")
    ok(health_status(spent_daily, now) == "Success",
       "a Daily task past its EndBoundary reports NO_MORE_RUNS, which is not a fault")
    ok("no next run time" not in attention_reason(spent_daily, "Success", now),
       "the reason must not contradict the verdict on a spent recurring task")
    all_exempt = variant(next_run_time=None,
                         trigger_types="Registration | Logon | Event")
    ok(health_status(all_exempt, now) == "Success",
       "3+ exempt triggers with no next run is not a fault (live \\Microsoft\\...\\UserTask)")
    ok(health_status(variant(next_run_time=None, trigger_types="Daily | Logon"), now)
       == "Warning", "a Daily trigger in the mix still demands a next run")
    ok(health_status(variant(last_task_result=0x800705B4), now) == "Error",
       "a timeout HRESULT is an Error")
    ok(health_status(base, None) == "Success",
       "overdue detection is skipped when no clock is supplied")

    # --- timestamps ---
    ok(parse_dt("2026-07-28T12:00:00Z") == now, "Z suffix parses as UTC")
    ok(parse_dt("2026-07-28T12:00:00") == now, "naive timestamps are assumed UTC")
    ok(parse_dt("") is None and parse_dt(None) is None, "blank timestamps are None")
    ok(parse_dt("not a date") is None, "unparseable timestamps do not raise")
    ok(parse_dt("2026-07-28T12:00:00.0000000Z") == now,
       "PowerShell's 7-digit fractional seconds parse (fromisoformat takes 6 pre-3.11)")
    ok(parse_dt("2026-07-28T07:00:00-05:00") == now, "offsets convert to UTC")
    ok(health_status(variant(next_run_time="2026-07-29T02:00:00.0000000Z"), now) == "Success",
       "a real PowerShell timestamp is not mistaken for a missing next run")

    # --- row assembly and filtering ---
    row = evaluate(dict(base, task_path="\\Jobs\\", task_name="etl",
                        executable="python.exe", arguments=r"C:\jobs\etl.py"), now)
    ok(row["task"] == r"\Jobs\etl", "task path and name join")
    ok(row["target"] == r"C:\jobs\etl.py" and row["target_kind"] == "PythonScript",
       "row carries the unwrapped target")
    ok(row["status"] == "Success" and row["missed_runs"] == 0, "row carries the verdict")
    ok(evaluate(dict(base, task_path="", task_name="orphan"))["task"] == "\\orphan",
       "an empty task path still yields a rooted name")
    ok(set(COLUMNS).issubset(evaluate({}).keys()), "every rendered column exists on a row")
    ok(evaluate({})["status"] in ("NotYetRun", "Warning"), "an empty dict does not crash")
    ok(is_microsoft_task({"task_path": "\\Microsoft\\Windows\\Defrag\\"}) is True,
       "Microsoft tasks are detected for exclusion")
    ok(is_microsoft_task({"task_path": "\\Jobs\\"}) is False, "your own tasks are kept")

    # --- the PowerShell bridge always yields a list, never None ---
    ok(rows_from_json("null") == [], "ConvertTo-Json emits 'null' for zero rows, not ''")
    ok(rows_from_json("") == [] and rows_from_json("   ") == [], "empty output is no rows")
    ok(rows_from_json('{"task_name": "solo"}') == [{"task_name": "solo"}],
       "ConvertTo-Json unwraps a single row to a bare object")
    ok(rows_from_json('[{"task_name": "a"}, {"task_name": "b"}]')
       == [{"task_name": "a"}, {"task_name": "b"}], "many rows pass through")
    ok(all(isinstance(rows_from_json(text), list) for text in ("null", "", "{}", "[]")),
       "read_tasks' caller can always iterate the result")

    # --- reasons name the actual problem ---
    ok("2 missed run(s)" in attention_reason(variant(number_of_missed_runs=2), "Warning", now),
       "reason names the missed run count")
    ok("overdue" in attention_reason(variant(next_run_time="2026-07-27T12:00:00+00:00"),
                                     "Warning", now), "reason names overdue")
    ok("24.0 hour(s)" in attention_reason(variant(next_run_time="2026-07-27T12:00:00+00:00"),
                                          "Warning", now), "overdue is quantified in hours")
    ok("no next run time" in attention_reason(variant(next_run_time=None), "Warning", now),
       "reason names the missing next run")
    ok(attention_reason(variant(enabled=False), "Disabled", now) == "task is disabled",
       "disabled reason is plain")

    # --- rendering never explodes ---
    ok("STATUS" in render_table([row]), "table renders a header")
    ok(r"\Jobs\etl" in render_table([row]), "table renders the task name")
    ok(json.loads(json.dumps([row])) == [row], "rows are JSON-serialisable")

    print("self-test passed: {} assertions, offline, no credentials.".format(checks[0]))
    if not windows:
        print("note: OS message-table assertions skipped (not Windows).")
    return 0


# --------------------------------------------------------------------------

def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="taskpulse",
        description="Audit every Windows scheduled task and report which ones are silently failing.",
        epilog="Read-only: taskpulse never modifies, starts, stops or deletes a task, "
               "never uses the network, and never needs credentials.",
    )
    parser.add_argument("--format", choices=["table", "json", "csv"], default="table",
                        help="output format (default: table)")
    parser.add_argument("--out", metavar="PATH", help="write to PATH instead of stdout")
    parser.add_argument("--all", action="store_true",
                        help="include Microsoft's own tasks under \\Microsoft\\ (noisy)")
    parser.add_argument("--show-ok", action="store_true",
                        help="include healthy tasks, not just Warning/Error")
    parser.add_argument("--match", metavar="REGEX",
                        help="only tasks whose full path matches this regex")
    parser.add_argument("--timeout", type=int, default=120, metavar="SECONDS",
                        help="Task Scheduler query timeout (default: 120)")
    parser.add_argument("--self-test", action="store_true",
                        help="run the offline assertion suite and exit")
    parser.add_argument("--version", action="version", version="taskpulse " + __version__)
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()

    try:
        tasks = read_tasks(args.timeout)
    except Exception as error:
        sys.stderr.write("taskpulse: {}\n".format(error))
        return 1

    if not args.all:
        tasks = [task for task in tasks if not is_microsoft_task(task)]

    now = datetime.now(timezone.utc)
    rows = [evaluate(task, now) for task in tasks]

    if args.match:
        pattern = re.compile(args.match, re.IGNORECASE)
        rows = [row for row in rows if pattern.search(row["task"])]
    if not args.show_ok:
        rows = [row for row in rows if row["status"] in ("Warning", "Error")]
    rows.sort(key=lambda row: (row["status"] != "Error", row["task"].lower()))

    if args.out:
        with open(args.out, "w", encoding="utf-8", newline="") as handle:
            write_output(rows, args.format, handle)
        sys.stderr.write("taskpulse: wrote {} row(s) to {}\n".format(len(rows), args.out))
    else:
        write_output(rows, args.format, sys.stdout)

    return 2 if any(row["status"] == "Error" for row in rows) else 0


if __name__ == "__main__":
    sys.exit(main())
