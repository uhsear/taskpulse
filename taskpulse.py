#!/usr/bin/env python3
"""taskpulse - audit Windows scheduled tasks and report which ones are silently failing.

Windows tells you a task's Last Run Result as a bare number and nothing else. It never
tells you that a Daily task has no next run time, that a task is overdue, or what
0x8007052E actually means. taskpulse joins those fields and prints a verdict.

Read-only by design. It shells out to `Get-ScheduledTask | Get-ScheduledTaskInfo`,
classifies the result in memory, and prints. With --history it also reads the Task Scheduler
Operational event log, which turns the one-slot snapshot into a week of runs and a duration
baseline. What it refuses to do:

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
import io
import json
import ntpath
import os
import re
import shlex
import subprocess
import sys
from datetime import datetime, timedelta, timezone

__version__ = "1.1.0"

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

# --history duration baseline. Advisory only: it never reaches health_status. A run at several
# times a task's own mean, or suspiciously fast, is invisible to exit-code health but worth a
# column. Gated at five completed runs so a new task's first couple of runs cannot set a
# baseline off one sample.
MIN_RUNS_FOR_DURATION_BASELINE = 5
DURATION_ANOMALY_HIGH_RATIO = 2.0
DURATION_ANOMALY_LOW_RATIO = 0.33

# One fetch of the Operational log. See PS_HISTORY for why the count matters.
HISTORY_MAX_EVENTS = 5000

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

PS_HISTORY = r"""
$ErrorActionPreference = "Stop"

$LogName = "Microsoft-Windows-TaskScheduler/Operational"
$DaysBack = __DAYS_BACK__
$MaxEvents = __MAX_EVENTS__
$MinRecordId = __MIN_RECORD_ID__

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

function Get-XmlDataMap {
    param([xml]$XmlEvent)
    $map = @{}
    if ($null -ne $XmlEvent -and $null -ne $XmlEvent.Event -and
        $null -ne $XmlEvent.Event.EventData -and $null -ne $XmlEvent.Event.EventData.Data) {
        foreach ($node in @($XmlEvent.Event.EventData.Data)) {
            $name = [string]$node.Name
            if ($name) { $map[$name] = [string]$node.'#text' }
        }
    }
    return $map
}

# Measured on a busy server: the Operational log carries roughly 920 events a day, and only
# about a quarter of them belong to the tasks you monitor - the rest is a browser updater and
# Windows Error Reporting. A flat 5000-event window therefore reaches back about 5 days, not
# the 30 you asked for. Once a watermark exists, fetch only records newer than it, so the
# event budget is never spent re-reading history you already have. The time window below is
# the cold-start branch, used only until the first watermark exists.
if ($MinRecordId -gt 0) {
    $xpath = "*[System[(EventRecordID > $MinRecordId) and (EventID=100 or EventID=102 or EventID=200 or EventID=201)]]"
    $events = Get-WinEvent -LogName $LogName -FilterXPath $xpath -MaxEvents $MaxEvents -ErrorAction SilentlyContinue
} else {
    $start = (Get-Date).AddDays(-1 * $DaysBack)
    $events = Get-WinEvent -FilterHashtable @{
        LogName = $LogName
        Id = @(100, 102, 200, 201)
        StartTime = $start
    } -MaxEvents $MaxEvents -ErrorAction SilentlyContinue
}

$rows = foreach ($event in $events) {
    $xmlEvent = $null
    try { [xml]$xmlEvent = $event.ToXml() } catch { $xmlEvent = $null }

    $dataMap = Get-XmlDataMap $xmlEvent
    $instanceId = [string]$dataMap['InstanceId']
    if (-not $instanceId) { $instanceId = [string]$dataMap['TaskInstanceId'] }

    [pscustomobject]@{
        event_id = [int]$event.Id
        event_record_id = [int64]$event.RecordId
        event_time_utc = Convert-ToIsoUtcOrNull $event.TimeCreated
        task_full_name = [string]$dataMap['TaskName']
        instance_id = $instanceId
        result_code = if ($dataMap.ContainsKey('ResultCode') -and $dataMap['ResultCode'] -ne '') { [int64]$dataMap['ResultCode'] } else { $null }
    }
}

$rows | ConvertTo-Json -Depth 6 -Compress
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


def to_int(value):
    """Parse an event id or an event record id. None rather than an exception on junk."""
    if value is None:
        return None
    try:
        return int(value)
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


def full_task_name(task):
    r"""The rooted \Path\Name that Task Scheduler puts in the inventory and in the event log.

    Both sides of the --history join build the name here rather than each spelling it out, so
    a trailing-separator difference cannot silently drop a task's whole run history.
    """
    path = text_of(task.get("task_path")) or "\\"
    if not path.endswith("\\"):
        path += "\\"
    return path + text_of(task.get("task_name"))


def duration_ratio(stats):
    """Last run's duration as a multiple of this task's own mean, or None.

    Advisory only - the caller must not feed this to health_status. Returns None below
    MIN_RUNS_FOR_DURATION_BASELINE completed runs, because a baseline drawn from one or two
    samples flags every normal task on its third run.
    """
    if stats.get("completed_run_count", 0) < MIN_RUNS_FOR_DURATION_BASELINE:
        return None
    mean = stats.get("mean_duration_seconds")
    last = stats.get("last_duration_seconds")
    if not mean or last is None:
        return None
    return last / mean


def evaluate(task, now=None, stats=None):
    """Enrich one raw task dict into a report row. Pure: dict in, dict out.

    `stats` is this task's entry from summarize_runs() when --history ran, else None. The
    history columns are emitted either way, so the CSV header does not change with the flag.
    """
    target, kind = classify_command(task.get("executable"), task.get("arguments"))
    status = health_status(task, now)
    stats = stats or {}
    ratio = duration_ratio(stats)
    anomaly = 1 if ratio is not None and (
        ratio > DURATION_ANOMALY_HIGH_RATIO or ratio < DURATION_ANOMALY_LOW_RATIO) else 0
    failures = int(stats.get("failures_last_7_days", 0) or 0)
    runs = int(stats.get("runs_last_7_days", 0) or 0)
    reasons = [attention_reason(task, status, now)]
    if failures:
        # The whole point of --history: a task whose last run was green can have failed every
        # night for weeks, and the snapshot Task Scheduler keeps has one slot.
        reasons.append("{} of {} run(s) in the last 7 days failed".format(failures, runs))
    if anomaly:
        reasons.append("last run took {:.1f}x its own baseline".format(ratio))
    return {
        "task": full_task_name(task),
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
        "reason": "; ".join([part for part in reasons if part]),
        "runs_last_7_days": runs,
        "failures_last_7_days": failures,
        "last_duration_seconds": stats.get("last_duration_seconds"),
        "duration_ratio": round(ratio, 3) if ratio is not None else None,
        "is_duration_anomaly": anomaly,
    }


# --------------------------------------------------------------------------
# run history - the Operational log, grouped into runs (--history)
# --------------------------------------------------------------------------

def run_status(end_time, code):
    """Verdict for one run in the event log, not for the task as a whole.

    A run with no 102 event has not finished; a finished run with no 201 event recorded no
    result, which is Unknown rather than Success.
    """
    if not text_of(end_time):
        return "Running"
    normalized = to_unsigned(code)
    if normalized is None:
        return "Unknown"
    if normalized in NON_ERROR_CODES:
        return "Success"
    if normalized in WARNING_CODES:
        return "Warning"
    return "Error"


def build_run_rows(events, tasks):
    """Group Operational-log events into one row per run instance. Pure: events in, rows out.

    Events 100 and 102 bracket a run and 201 carries the result code. A run whose 100 event
    fell outside the fetch window used to emit a run with no start time at all - 57 such rows
    in the table this was ported from - so the earliest observed event time is used instead
    and the row carries start_time_estimated, which stops an estimate reading as a
    measurement. A group with nothing datable at all is dropped, not emitted with no start.

    An event naming a task that is not in `tasks` is skipped, so a filtered inventory yields a
    filtered history rather than rows nothing can be joined to.
    """
    known = set(full_task_name(task) for task in tasks if text_of(task.get("task_name")))
    grouped = {}

    for raw in events:
        instance_id = text_of(raw.get("instance_id"))
        task_name = text_of(raw.get("task_full_name"))
        if not instance_id or task_name not in known:
            continue
        group = grouped.setdefault(instance_id, {
            "task": task_name,
            "instance_id": instance_id,
            "start_time": None,
            "end_time": None,
            "first_event_time": None,
            "result_code": None,
            "max_event_record_id": None,
        })

        event_id = to_int(raw.get("event_id"))
        event_time = text_of(raw.get("event_time_utc"))
        event_dt = parse_dt(event_time)
        record_id = to_int(raw.get("event_record_id"))

        if record_id is not None:
            prior = group["max_event_record_id"]
            group["max_event_record_id"] = record_id if prior is None else max(prior, record_id)
        if event_dt is not None:
            first = parse_dt(group["first_event_time"])
            if first is None or event_dt < first:
                group["first_event_time"] = event_time
            if event_id == 100:
                existing = parse_dt(group["start_time"])
                if existing is None or event_dt < existing:
                    group["start_time"] = event_time
            elif event_id == 102:
                existing = parse_dt(group["end_time"])
                if existing is None or event_dt > existing:
                    group["end_time"] = event_time
        if event_id == 201:
            code = to_unsigned(raw.get("result_code"))
            if code is not None:
                group["result_code"] = code

    rows = []
    for group in grouped.values():
        start_estimated = 0
        start_time = group["start_time"]
        if not start_time:
            start_time = group["first_event_time"]
            start_estimated = 1 if start_time else 0
        if not start_time:
            continue  # nothing datable at all - an unusable row, not a row with no start
        start_dt = parse_dt(start_time)
        end_dt = parse_dt(group["end_time"])
        duration = (round((end_dt - start_dt).total_seconds(), 2)
                    if start_dt and end_dt and end_dt >= start_dt else None)
        rows.append({
            "task": group["task"],
            "instance_id": group["instance_id"],
            "start_time": start_time,
            "start_time_estimated": start_estimated,
            "end_time": text_of(group["end_time"]),
            "duration_seconds": duration,
            "result_code": group["result_code"],
            "run_status": run_status(group["end_time"], group["result_code"]),
            "max_event_record_id": group["max_event_record_id"],
        })
    rows.sort(key=lambda row: (row["task"].lower(), row["start_time"]))
    return rows


def summarize_runs(run_rows, now):
    """Per-task 7-day counts, last duration and completed-run mean. Pure, one dict per task.

    `now` is injected and never read from the clock. The version this was ported from took no
    clock and called the wall clock inside the cutoff, so every test written against a pinned
    clock passed on the day it was written and failed a week later.
    """
    cutoff = now - timedelta(days=7)
    summary = {}

    for run in run_rows:
        key = text_of(run.get("task"))
        if not key:
            continue
        entry = summary.setdefault(key, {
            "runs_last_7_days": 0, "failures_last_7_days": 0,
            "completed_run_count": 0, "last_duration_seconds": None,
            "_last_start": None, "_duration_sum": 0.0,
        })
        started = parse_dt(run.get("start_time"))
        duration = run.get("duration_seconds")
        if started is not None:
            if entry["_last_start"] is None or started > entry["_last_start"]:
                entry["_last_start"] = started
                entry["last_duration_seconds"] = duration
            if started >= cutoff:
                entry["runs_last_7_days"] += 1
                if run.get("run_status") == "Error":
                    entry["failures_last_7_days"] += 1
        if duration is not None:
            entry["completed_run_count"] += 1
            entry["_duration_sum"] += duration

    for entry in summary.values():
        entry.pop("_last_start")
        total = entry.pop("_duration_sum")
        count = entry["completed_run_count"]
        entry["mean_duration_seconds"] = (total / count) if count else None
    return summary


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


def run_powershell(script, timeout, what):
    """Run one read-only PowerShell script and return its rows. The only impure path."""
    if os.name != "nt":
        raise RuntimeError("taskpulse reads Windows Task Scheduler; this is not Windows.")
    command = ["powershell", "-NoProfile", "-NonInteractive",
               "-ExecutionPolicy", "Bypass", "-Command", script]
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=timeout)
    stdout = result.stdout.decode("utf-8", "replace")
    if result.returncode != 0:
        raise RuntimeError("{} failed: ".format(what)
                           + result.stderr.decode("utf-8", "replace").strip())
    return rows_from_json(stdout)


def read_tasks(timeout=120):
    """Run the read-only PowerShell query and return raw task dicts."""
    return run_powershell(PS_QUERY, timeout, "Task Scheduler query")


def read_run_events(days_back=30, min_record_id=0, timeout=120):
    """Return raw 100/102/200/201 events from the Task Scheduler Operational log.

    Returns no events when that log is disabled, which is the Windows default: the query uses
    -ErrorAction SilentlyContinue, so an absent or empty log is an empty history rather than a
    failed audit. The substituted values are ints, never text, so nothing a caller types can
    reach the script as PowerShell.
    """
    script = (PS_HISTORY
              .replace("__DAYS_BACK__", str(int(days_back)))
              .replace("__MAX_EVENTS__", str(int(HISTORY_MAX_EVENTS)))
              .replace("__MIN_RECORD_ID__", str(int(min_record_id))))
    return run_powershell(script, timeout, "Task Scheduler history query")


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

    # --- run history: Operational-log events grouped into runs (--history) ---
    inventory = [dict(base, task_path="\\Jobs\\", task_name="etl")]

    def event(event_id, hour, instance="i1", task=r"\Jobs\etl", record_id=1, result_code=None):
        return {"event_id": event_id, "instance_id": instance, "task_full_name": task,
                "event_time_utc": "2026-07-28T{:02d}:00:00Z".format(hour),
                "event_record_id": record_id, "result_code": result_code}

    complete = build_run_rows([event(100, 1, record_id=10),
                               event(201, 3, record_id=11, result_code=0),
                               event(102, 3, record_id=12)], inventory)
    ok(len(complete) == 1, "three events sharing one instance id collapse to one run row")
    ok(complete[0]["duration_seconds"] == 7200.0, "events 100 and 102 bracket the duration")
    ok(complete[0]["start_time_estimated"] == 0, "a real 100 event is not an estimated start")
    ok(complete[0]["run_status"] == "Success", "event 201 carries the result code")
    ok(complete[0]["max_event_record_id"] == 12,
       "the watermark is the highest record id in the group, so it cannot go backwards")
    truncated = build_run_rows([event(201, 4, record_id=20, result_code=0),
                                event(102, 5, record_id=21)], inventory)
    ok(truncated[0]["start_time_estimated"] == 1,
       "a run whose 100 event fell outside the window is flagged, not given a null start"
       "  <-- pinned defect")
    ok(parse_dt(truncated[0]["start_time"]) == parse_dt("2026-07-28T04:00:00Z"),
       "an estimated start is the earliest event time observed for that run")
    undated = dict(event(100, 1, record_id=30))
    undated["event_time_utc"] = None
    ok(build_run_rows([undated], inventory) == [],
       "a run with nothing datable is dropped, not emitted with no start time")
    ok(build_run_rows([event(100, 1, task=r"\Jobs\other"),
                       event(102, 2, task=r"\Jobs\other")], inventory) == [],
       "an event naming a task absent from the inventory is skipped")
    ok(build_run_rows([event(100, 1, instance="")], inventory) == [],
       "an event with no instance id cannot be grouped and is skipped")
    running = build_run_rows([event(100, 1, record_id=40)], inventory)
    ok(running[0]["run_status"] == "Running" and running[0]["duration_seconds"] is None,
       "a run with no 102 event is still running and has no duration")
    ok(run_status("2026-07-28T03:00:00Z", None) == "Unknown",
       "a finished run that recorded no result is Unknown, never Success")
    ok(run_status("2026-07-28T03:00:00Z", -2147024894) == "Error",
       "a failing HRESULT on a finished run is an Error")
    ok(run_status("2026-07-28T03:00:00Z", TASK_TERMINATED) == "Warning",
       "a terminated run is a Warning, exactly as the snapshot path grades it")
    ok(len(build_run_rows([event(100, 1), event(100, 2, instance="i2")], inventory)) == 2,
       "two instance ids are two runs")
    repeated = build_run_rows([event(100, 2, record_id=50), event(100, 1, record_id=51),
                               event(102, 4, record_id=52), event(102, 6, record_id=53)],
                              inventory)
    ok(repeated[0]["duration_seconds"] == 18000.0,
       "a repeated 100 keeps the earliest start and a repeated 102 the latest end")
    in_order = build_run_rows([event(100, 1, record_id=60), event(100, 2, record_id=61),
                               event(102, 6, record_id=62), event(102, 4, record_id=63)],
                              inventory)
    ok(in_order[0]["duration_seconds"] == 18000.0,
       "the same duplicates in the other order give the same run, so a re-read cannot shrink it")
    no_code = build_run_rows([event(100, 1), event(201, 2), event(102, 3)], inventory)
    ok(no_code[0]["result_code"] is None and no_code[0]["run_status"] == "Unknown",
       "a 201 event carrying no result code leaves the run's result unknown")
    no_record = build_run_rows([event(100, 1, record_id=None)], inventory)
    ok(no_record[0]["max_event_record_id"] is None,
       "an event with no record id leaves the watermark unset rather than zeroing it")
    ok(to_int(None) is None and to_int("junk") is None,
       "a junk event id or record id is dropped, not raised")
    ok(to_int("102") == 102, "a numeric string event id is accepted")

    # --- the 7-day window is measured from an injected clock, never the wall clock ---
    def run(started, duration, status="Success"):
        return {"task": r"\Jobs\etl", "start_time": started, "duration_seconds": duration,
                "run_status": status}

    windowed = summarize_runs([run("2026-07-26T01:00:00Z", 10.0),
                               run("2026-06-28T01:00:00Z", 11.0)], now)[r"\Jobs\etl"]
    ok(windowed["runs_last_7_days"] == 1,
       "a 30-day-old run falls outside the window and a 2-day-old run does not, against the "
       "clock the caller passed  <-- pinned defect")
    ok(windowed["last_duration_seconds"] == 10.0,
       "the newest run's duration wins, whatever order the rows arrive in")
    ok(summarize_runs([], now) == {}, "no runs summarise to nothing")
    ok(summarize_runs([run("", 10.0)], now)[r"\Jobs\etl"]["runs_last_7_days"] == 0,
       "a run with an unparseable start counts towards no window")
    ok(summarize_runs([{"task": "", "start_time": "2026-07-26T01:00:00Z"}], now) == {},
       "a run with no task name is skipped, not filed under a blank key")
    failing = summarize_runs([run("2026-07-26T01:00:00Z", 10.0, "Error"),
                              run("2026-07-27T01:00:00Z", 10.0)], now)[r"\Jobs\etl"]
    ok(failing["failures_last_7_days"] == 1 and failing["runs_last_7_days"] == 2,
       "failures inside the window are counted apart from runs")
    unfinished = summarize_runs([run("2026-07-26T01:00:00Z", None)], now)[r"\Jobs\etl"]
    ok(unfinished["completed_run_count"] == 0 and unfinished["mean_duration_seconds"] is None,
       "a run still in flight counts towards the week but not towards the baseline")
    ok(duration_ratio({"completed_run_count": 9, "mean_duration_seconds": 0.0,
                       "last_duration_seconds": 5.0}) is None,
       "a zero mean yields no ratio rather than a division error")
    ok("last 7 days" in evaluate(inventory[0], now, failing)["reason"],
       "a task whose last run was green still reports the week's failures")

    # --- duration baseline: advisory, and gated so a new task cannot trip it ---
    four = [run("2026-07-2{}T01:00:00Z".format(day), 100.0) for day in (4, 5, 6, 7)]

    def history_row(last_duration):
        rows = four + [run("2026-07-28T01:00:00Z", last_duration)]
        return evaluate(inventory[0], now, summarize_runs(rows, now)[r"\Jobs\etl"])

    four_row = evaluate(inventory[0], now, summarize_runs(four, now)[r"\Jobs\etl"])
    ok(four_row["duration_ratio"] is None and four_row["is_duration_anomaly"] == 0,
       "four completed runs never set a baseline, however far apart their durations are")
    ok(history_row(300.0)["is_duration_anomaly"] == 1,
       "the fifth completed run sets the baseline, and 2.1x it flags")
    ok(history_row(250.0)["is_duration_anomaly"] == 0,
       "1.9x does not flag: the threshold is 2.0x, not 'slower than usual'")
    ok(history_row(20.0)["is_duration_anomaly"] == 1,
       "a run at a fraction of the baseline flags too: a job that stopped doing its work")
    ok(history_row(300.0)["status"] == "Success",
       "the duration baseline is advisory and never changes the health verdict")
    ok("baseline" in history_row(300.0)["reason"], "the anomaly reaches the reason column")
    ok(evaluate({})["runs_last_7_days"] == 0 and evaluate({})["duration_ratio"] is None,
       "a run without --history still emits the history columns, so the CSV header is stable")
    ok(full_task_name(dict(task_path="\\Jobs", task_name="etl")) == r"\Jobs\etl",
       "a task path with no trailing separator still joins to the event log's name")
    ok(evaluate(inventory[0])["task"] == full_task_name(inventory[0]),
       "both sides of the history join build the task name the same way")

    # --- rendering never explodes ---
    ok("STATUS" in render_table([row]), "table renders a header")
    ok(r"\Jobs\etl" in render_table([row]), "table renders the task name")
    ok(json.loads(json.dumps([row])) == [row], "rows are JSON-serialisable")
    csv_out = io.StringIO()
    write_output([history_row(300.0)], "csv", csv_out)
    ok("is_duration_anomaly" in csv_out.getvalue().splitlines()[0],
       "the CSV header carries the history columns")
    ok(len(csv_out.getvalue().splitlines()) == 2,
       "a history row writes as one CSV row: the header is built from the same row shape")
    json_out = io.StringIO()
    write_output([row], "json", json_out)
    ok(json.loads(json_out.getvalue()) == [row], "json output round-trips")
    table_out = io.StringIO()
    write_output([row], "table", table_out)
    ok(r"\Jobs\etl" in table_out.getvalue(), "the table format writes the report")
    empty_out = io.StringIO()
    write_output([], "table", empty_out)
    ok("No tasks need attention" in empty_out.getvalue(), "an empty report says so")

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
    parser.add_argument("--history", nargs="?", type=int, const=30, metavar="DAYS",
                        help="also read the Task Scheduler Operational log and report each "
                             "task's last 7 days of runs and its duration baseline "
                             "(default: 30 days of events)")
    parser.add_argument("--since-record-id", type=int, default=0, metavar="ID",
                        help="with --history, read only event records newer than ID. Pass the "
                             "watermark the previous run printed; the day window is ignored")
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
    run_summary = {}
    if args.history is not None:
        try:
            events = read_run_events(args.history, args.since_record_id, args.timeout)
        except Exception as error:
            sys.stderr.write("taskpulse: {}\n".format(error))
            return 1
        run_summary = summarize_runs(build_run_rows(events, tasks), now)
        # Report the watermark over every event fetched, not only the ones that joined to a
        # task: an event for an unmonitored task is still an event this run has read.
        watermark = max([to_int(raw.get("event_record_id")) or 0 for raw in events]
                        + [args.since_record_id])
        sys.stderr.write("taskpulse: read {} run event(s); next run can pass "
                         "--since-record-id {}\n".format(len(events), watermark))

    rows = [evaluate(task, now, run_summary.get(full_task_name(task))) for task in tasks]

    if args.match:
        pattern = re.compile(args.match, re.IGNORECASE)
        rows = [row for row in rows if pattern.search(row["task"])]
    if not args.show_ok:
        # A task that failed every night this week and succeeded tonight is exactly what
        # --history exists to surface, so a week's failures keep a row that status alone drops.
        rows = [row for row in rows
                if row["status"] in ("Warning", "Error") or row["failures_last_7_days"]]
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
