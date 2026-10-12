#!/usr/bin/env python3
"""taskpulse - audit Windows scheduled tasks and report which ones are silently failing.

Windows tells you a task's Last Run Result as a bare number and nothing else. It never
tells you that a Daily task has no next run time, that a task is overdue, or what
0x8007052E actually means. taskpulse joins those fields and prints a verdict.

Read-only by design. It shells out to `Get-ScheduledTask | Get-ScheduledTaskInfo`,
classifies the result in memory, and prints. With --history it also reads the Task Scheduler
Operational event log, which turns the one-slot snapshot into a week of runs and a duration
baseline. With --lint it judges each task's configuration instead of its last result: a
logon type that only runs while somebody is logged on, a Start In that is empty, quoted or
relative, a share the run-as account cannot reach, a program found only through PATH. Given
exported task XML (schtasks /query /xml, Export-ScheduledTask, or the files under
C:\\Windows\\System32\\Tasks), --lint needs no Task Scheduler and runs on any OS.

--history also reads what happened to a launch that never became a normal run: a start that
failed (events 101, 103, 203), a run the scheduler or a person ended (111, 329, 330) and a
launch that was refused (153, 322, 332). A run that never finishes is STUCK. A task whose latest
launch was refused is BLOCKED. --diff OLD NEW compares two exports of the same tasks and names
each field that changed, with the Task Scheduler schema defaults applied, so a setting that was
absent in one export and written at its default in the other is no change. It prints no
arguments unless --show-args is given, because they can hold secrets.

What it refuses to do:

  * never creates, edits, enables, disables, deletes, starts or stops a task
  * never opens a network connection, and never asks for or stores a credential
  * never reads or writes a config file - every knob is a command line flag
  * never writes anywhere except stdout, or the one path you pass to --out, and that only
    with --apply; --self-test also uses a temporary folder, which it removes

Exit codes: 0 = nothing in an Error state and taskpulse saw everything it reports on, 2 = at
least one task (or, with --lint, one finding) in an Error state, 1 = taskpulse itself failed
or could not see everything (a task it could not fully read, or a --history read that failed
or is incomplete), 64 = usage error. With --diff, 0 = the two exports match and 2 = they
differ. Suitable as a monitoring check.

Python 3.9+, standard library only.
"""

from __future__ import annotations

import argparse
import codecs
import csv
import importlib.util
import ctypes
import io
import json
import ntpath
import os
import re
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timedelta, timezone
from itertools import zip_longest

__version__ = "1.4.0"

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

# Interpreters by program name with any ".exe" removed. Task Scheduler runs `python`,
# `powershell` or ...\arcgispro-py3\python exactly as it runs the .exe spelling. A Python can
# also carry its version in its name, as python3.exe and python3.11.exe do.
PYTHON_NAME = re.compile(r"^(?:pythonw?(?:\d+(?:\.\d+)*)?|py)$")
POWERSHELL_EXES = frozenset(["powershell", "pwsh", "powershell_ise"])
CMD_EXES = frozenset(["cmd"])
SCRIPT_HOST_EXES = frozenset(["cscript", "wscript"])
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

# One fetch of the Operational log. See history_query for why the count matters.
HISTORY_MAX_EVENTS = 5000
HISTORY_EVENT_IDS = (100, 101, 102, 103, 111, 153, 200, 201, 203, 322, 329, 330, 332)

# Run-fate events. Every id and field below comes from the provider manifest of the log:
# Get-WinEvent -ListProvider Microsoft-Windows-TaskScheduler, read on Windows 11 build 26100.
# 101 "Task Start Failed" has no instance id, because it fires before an instance exists. 103
# "Action start failed" and 203 "Action failed to start" carry one, and a ResultCode.
LAUNCH_FAILED_IDS = frozenset([101, 103, 203])
# 111 "Task terminated", 329 "stopping due to timeout reached" and 330 "stopping due to user
# request". The scheduler or a person ended the instance. None carries a result code.
STOP_FATES = {111: "Terminated", 329: "TimedOut", 330: "Stopped"}
# A launch that was refused, not a run. 153 "Missed task start rejected" and 332 "user not
# logged-on" name only the task. 322 "instance already running" names the instance that was
# still running, not a new one.
BLOCK_KINDS = {153: "missed", 322: "overlap", 332: "no-session"}
BLOCK_TEXT = {
    "overlap": "the latest launch was ignored because an earlier run was still going (event 322)",
    "no-session": "the latest launch was refused because the run-as user was not logged on "
                  "(event 332)",
    "missed": "the latest scheduled start was missed and not made up (event 153; see the "
              "StartWhenAvailable setting)",
}
# The worst fate of an instance wins when it has several events.
FATE_RANK = {"": 0, "Stopped": 1, "Terminated": 2, "TimedOut": 3, "LaunchFailed": 4}
# A run with no end event after this many hours is STUCK (--stuck-hours changes it).
STUCK_HOURS = 24

# --lint vocabulary. The XML schema and the PowerShell enum spell the same logon types
# differently (InteractiveToken / Interactive), so both collapse to one word here.
LOGON_KINDS = {
    "interactivetoken": "interactive", "interactive": "interactive", "group": "interactive",
    "s4u": "s4u", "password": "password", "interactivetokenorpassword": "password",
    "interactiveorpassword": "password", "serviceaccount": "service",
}
# Built-in accounts, by SID and by name, with any "NT AUTHORITY\" and spaces removed.
SERVICE_ACCOUNTS = {
    "s-1-5-18": "SYSTEM", "system": "SYSTEM", "localsystem": "SYSTEM",
    "s-1-5-19": "LOCAL SERVICE", "localservice": "LOCAL SERVICE",
    "s-1-5-20": "NETWORK SERVICE", "networkservice": "NETWORK SERVICE",
}
# Triggers that fire whether or not anybody is at the console. An interactive-only task
# with one of these skips every run that happens while nobody is logged on.
UNATTENDED_TRIGGERS = frozenset(
    ["One Time", "Daily", "Weekly", "Monthly", "Calendar", "Startup", "Event"]
)
CALENDAR_KINDS = {"Day": "Daily", "Week": "Weekly", "Month": "Monthly",
                  "MonthDayOfWeek": "MonthlyDOW"}
# Programs in C:\Windows or System32, which is on every account's PATH. A bare name for one
# of these resolves the same way for every run-as account; any other bare name does not.
SYSTEM_PROGRAMS = frozenset(
    ["bitsadmin", "certutil", "cmd", "conhost", "cscript", "curl", "explorer", "forfiles",
     "icacls", "msiexec", "mshta", "net", "netsh", "notepad", "ping", "powershell", "reg",
     "regsvr32", "robocopy", "rundll32", "sc", "schtasks", "shutdown", "takeown", "tar",
     "taskkill", "timeout", "wevtutil", "wmic", "wscript", "xcopy"]
)
# Extensions that make an argument a file path even without a separator in it. A bare .exe is
# left out: run as a program, it resolves against PATH as well as Start In.
PATH_EXTS = frozenset(
    [".bat", ".cfg", ".cmd", ".csv", ".ini", ".jar", ".js", ".json", ".log",
     ".ps1", ".py", ".pyw", ".sql", ".toml", ".txt", ".vbs", ".xml", ".yaml", ".yml"]
)
# A command that changes its own directory first does not depend on Start In. Only the first
# command of the body that cmd /c or powershell -Command runs counts; see changes_directory().
DIR_CHANGERS = frozenset(["cd", "chdir", "pushd", "set-location", "push-location", "sl"])
# PowerShell takes any unique prefix of -Command: -com and -comm run their body (measured).
# -co is left out, because -ConfigurationName starts the same way.
PS_BODY = r"-c(?:om(?:m(?:a(?:nd?)?)?)?)?"
BODY_SWITCH = {"cmd": r"/[ck]", "powershell": PS_BODY, "pwsh": PS_BODY}
# Switch names whose value is a secret. That value is never judged as a path and never
# printed; only the share check reads it (see arg_values). "pass" covers --pass, password,
# passwd and passphrase; "pw" covers plink's -pw and pwd. A one-letter -P or -p is left out:
# it is a port or a path as often as a password. Only --diff's mask adds them (MASKED_LETTERS).
SECRET_SWITCH = re.compile(
    r"key|token|secret|pass|pw|pswd|cred|auth(?!or(?!iz))|bearer|signature|encodedcommand|"
    r"^(?:sas|sig|pat|rp)$",
    re.IGNORECASE)
# --diff prints command lines, so it also masks the value of a one-letter -P, -p or -k, which are
# sqlcmd's and mysql's password and a common name for a key. A port after -p is masked too: a
# changed port is reported as a change whose value is not printed, which costs nothing, where a
# printed password costs a lot. curl's -k takes no value, so the word after it is masked for
# nothing, which costs the same nothing.
MASKED_LETTERS = frozenset(["p", "P", "k"])
# The value of a JSON member whose name says it holds a secret, such as {"password":"x"}. The
# quotes may be backslash-escaped. The name part is bounded so a long word cannot make it slow.
JSON_SECRET = re.compile(
    r'(\\?"[^"\s:]{0,64}(?:key|token|secret|pass|pw|cred|auth(?!or(?!iz))|bearer|signature)'
    r'[^"\s:]{0,64}\\?"\s*:\s*)(?:\\?"[^"]*?\\?"|[^\s,}\]]+)', re.IGNORECASE)
# --diff also masks the credential that curl-style programs take after -u or --user as
# user:password. A value with no ':' is an account name or a python -u script, and prints.
CRED_SWITCH = frozenset(["u", "U", "user", "login", "proxy-user"])
CRED_VALUE = re.compile(r"[^\s:/]{2,}:")
# The attached form -pSECRET (7z, mysql) and -PSECRET (sqlcmd) is masked, except for these
# PowerShell parameters, which start the same way and take a path, a port or a name.
ATTACHED_PARAMS = frozenset(
    ["path", "pattern", "port", "property", "protocol", "process", "processname", "proxy",
     "parameter", "principal", "priority", "prefix"])
# A header such as `X-Api-Key: value` or `Authorization: Bearer value`: the name says it holds
# a secret, so everything after the colon is masked.
SECRET_HEADER = re.compile(
    r"^([\w-]*(?:key|token|secret|pass|auth(?!or(?!iz))|cookie|bearer|signature|session)[\w-]*:)"
    r"\s*\S.*$", re.IGNORECASE | re.DOTALL)
# Switch names whose value is an account, such as net use's /user:EXAMPLE\svc. An account is
# not a path, although DOMAIN\name has a separator. A one-letter -u is left out: to python it
# is a switch with no value, so the script after it would be lost.
USER_SWITCH = re.compile(r"^(?:user(?:name)?|login|ru)$", re.IGNORECASE)
# A relative path is printed in a finding only when it ends in one of these. A value with no
# known extension, such as Hunter2/Secret after a switch with a neutral name, may be a secret.
NAMED_EXTS = PATH_EXTS | {".exe"}
ROOTED = re.compile(r"^(?:[A-Za-z]:[\\/]|[\\/]|%)")
# The password in the user:password@host of a URL.
URL_AUTH = re.compile(r"(://[^/\s:@]*:)[^@/\s]*@")
# A share as \\server\share, //server/share or the long form \\?\UNC\server\share. It is
# matched against switch values (see arg_values), not the raw command line, so the share in
# /LOG:\\server\share is found. The lookbehind stops the // of a URL from reading as a share.
# The server must be a host name, which rules out a \\?\C:\ or \\.\ device path and the
# user:password@host of a URL.
UNC = re.compile(r"(?<![\\/\w:])(?:\\\\\?\\UNC\\|[\\/]{2})"
                 r"([\w$-][\w.$-]*)[\\/]([^\\/\s\"']+)", re.IGNORECASE)
# A drive root (Z:\, Z:) or a drive-relative path that holds a dot or a separator (Z:run.log).
# A drive-relative bare word such as Z:outbox is left out, because it reads the same as x:y.
DRIVE = re.compile(r"(?<![A-Za-z0-9_])([A-Za-z]):(?=[\\/\s\"']|$|[^\s\"':]*[.\\/])")
XML_DECL = re.compile(r"<\?xml[^>]*\?>")
SYSTEM32 = "C:\\Windows\\System32"
# What Task Scheduler assumes for a Settings element that an export leaves out. Every value is
# the default="..." of settingsType in the Task Scheduler schema, except two. ExecutionTimeLimit:
# the schema gives it none, and the ITaskSettings documentation says "By default, a task will be
# stopped 72 hours after it starts to run". DeleteExpiredTaskAfter is left out on purpose: its
# schema default is PT0S (delete at once), but its element page says "If no value is specified
# for this element, then the Task Scheduler service will not delete the task", so an absent
# element and PT0S are opposite behaviours and must diff as a change. Windows writes most of
# these explicitly, so an absent element mostly means a hand-written export. The principal's
# LogonType and RunLevel have no documented default, so they get none here.
SETTING_DEFAULTS = {
    "AllowStartOnDemand": "true", "MultipleInstancesPolicy": "IgnoreNew",
    "DisallowStartIfOnBatteries": "true", "StopIfGoingOnBatteries": "true",
    "AllowHardTerminate": "true", "StartWhenAvailable": "false",
    "RunOnlyIfNetworkAvailable": "false", "WakeToRun": "false", "Enabled": "true",
    "Hidden": "false", "Priority": "7",
    "RunOnlyIfIdle": "false", "UseUnifiedSchedulingEngine": "false",
    "DisallowStartOnRemoteAppSession": "false", "ExecutionTimeLimit": "PT72H",
}
# What a hung run does to the launches behind it, by MultipleInstancesPolicy.
HANG_EFFECT = {
    "ignorenew": "every later launch is dropped without an error (Task Scheduler logs each as "
                 "event 322, which --history reports)",
    "queue": "every later launch waits behind it",
    "parallel": "later launches pile up beside it",
}
# ArcGIS Pro's own Python: the folder Esri documents for propy and proenv, the default conda
# environment arcgispro-py3, and the propy launcher itself.
ARCGIS_PYTHON = re.compile(r"arcgis[\\/]pro[\\/]bin[\\/]python|arcgispro-py3|\bpropy\b",
                           re.IGNORECASE)
# Esri's four conditions are "Sign me in automatically", Pro open, Pro authorized to work
# offline, and "Remember my certificate" (the README lists them with their source).
LICENCE_NOTE = (
    "this task runs ArcGIS Pro's Python: arcpy raises RuntimeError: NotInitialized unless Esri's "
    "sign-in conditions hold for the account that runs it, and a task definition does not show "
    "them, so check them for the new account or logon type")
DIFF_FIELDS = ["change", "task", "field", "old", "new"]

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
    # A part that could not be read is named here. Left blank, a task with no result and no
    # trigger reads as one that has not run yet, and drops out of the report (see read_failures).
    $failed = @()
    $info = $null
    try {
        $info = Get-ScheduledTaskInfo -TaskName $task.TaskName -TaskPath $task.TaskPath
    } catch { $failed += "run details" }

    $exe = ""; $args = ""
    try {
        $a = @($task.Actions)
        if ($a.Count -gt 0) {
            $exe = [string]$a[0].Execute
            $args = [string]$a[0].Arguments
        }
    } catch { $failed += "actions" }

    # Every Exec action, for --lint. COM handler actions have no command line to judge.
    $actions = @()
    try {
        foreach ($x in @($task.Actions)) {
            if ([string]$x.CimClass.CimClassName -eq 'MSFT_TaskExecAction') {
                $actions += [pscustomobject]@{
                    executable        = [string]$x.Execute
                    arguments         = [string]$x.Arguments
                    working_directory = [string]$x.WorkingDirectory
                }
            }
        }
    } catch { $failed += "actions" }

    # A disabled trigger never fires, so it is left out, as the XML reader leaves it out.
    $triggerTypes = ""
    try {
        $triggerTypes = (@($task.Triggers) | Where-Object { $_.Enabled -ne $false } |
            ForEach-Object { Get-TriggerTypeName $_ } |
            Where-Object { $_ } | Select-Object -Unique) -join " | "
    } catch { $failed += "triggers" }

    # The settings --lint judges, under the schema's own names, and each trigger's end
    # boundary. Only what --lint reads is asked for; the XML reader keeps the rest for --diff.
    $settings = @{}
    try {
        $settings = @{
            MultipleInstancesPolicy   = [string]$task.Settings.MultipleInstances
            ExecutionTimeLimit        = [string]$task.Settings.ExecutionTimeLimit
            RunOnlyIfIdle             = [string]$task.Settings.RunOnlyIfIdle
            RunOnlyIfNetworkAvailable = [string]$task.Settings.RunOnlyIfNetworkAvailable
        }
    } catch { $failed += "settings" }
    $triggerDetails = @()
    try {
        foreach ($g in @($task.Triggers)) {
            $triggerDetails += [pscustomobject]@{
                kind         = Get-TriggerTypeName $g
                enabled      = ($g.Enabled -ne $false)
                end_boundary = [string]$g.EndBoundary
            }
        }
    } catch { $failed += "triggers" }

    [pscustomobject]@{
        task_name             = [string]$task.TaskName
        task_path             = [string]$task.TaskPath
        state                 = [string]$task.State
        enabled               = [bool]$task.Settings.Enabled
        author                = [string]$task.Author
        run_as_user           = [string]$task.Principal.UserId
        logon_type            = [string]$task.Principal.LogonType
        executable            = $exe
        arguments             = $args
        actions               = $actions
        trigger_types         = $triggerTypes
        trigger_details       = $triggerDetails
        settings              = $settings
        last_run_time         = if ($info) { Convert-ToIsoUtcOrNull $info.LastRunTime } else { $null }
        next_run_time         = if ($info) { Convert-ToIsoUtcOrNull $info.NextRunTime } else { $null }
        last_task_result      = if ($info) { [int64]$info.LastTaskResult } else { $null }
        number_of_missed_runs = if ($info) { [int64]$info.NumberOfMissedRuns } else { $null }
        read_errors           = $failed -join ","
    }
}

$rows | ConvertTo-Json -Depth 4 -Compress
"""

PS_HISTORY = r"""
$ErrorActionPreference = "Stop"

$LogName = "Microsoft-Windows-TaskScheduler/Operational"
$XPath = '__XPATH__'
$MaxEvents = __MAX_EVENTS__
$Oldest = __OLDEST__

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

# history_query() builds $XPath and $Oldest; see it for why each part is there.
#
# -LogName with -FilterXPath, never -FilterHashtable: unelevated, the hashtable form reports
# an access-denied log as NoMatchingEventsFound, which is a clean empty history (measured on
# the Security log). The XPath form raises UnauthorizedAccessException.
#
# No -ErrorAction SilentlyContinue: it turned every failed read into an empty history. Every
# failure is handed to Python with its error id, which treats only NoMatchingEventsFound as
# empty (see history_events).
#
# A disabled log also answers NoMatchingEventsFound, even to an invalid query (measured), so
# it is asked first whether it is on. Off is the Windows default, and an empty answer from it
# would be a clean week the log never recorded.
#
# The log's own oldest and newest record go to Python as the first row (see log_range_gap): a
# watermark above the newest record, records past it already overwritten, or a log younger than
# 7 days each read as a clean history otherwise.
$out = @()
try {
    $info = Get-WinEvent -ListLog $LogName -ErrorAction Stop
    if (-not $info.IsEnabled) {
        [pscustomobject]@{ read_error = 'LogDisabled'; message = 'the log is disabled, so it holds no run history; an administrator can enable it with: wevtutil sl Microsoft-Windows-TaskScheduler/Operational /e:true' } | ConvertTo-Json -Compress
        exit 0
    }
    $range = [pscustomobject]@{ log_oldest_record_id = $null; log_newest_record_id = $null; log_oldest_time_utc = $null }
    if ($info.RecordCount -gt 0) {
        $first = Get-WinEvent -LogName $LogName -MaxEvents 1 -Oldest -ErrorAction Stop
        $range.log_oldest_record_id = [int64]$first.RecordId
        $range.log_oldest_time_utc = Convert-ToIsoUtcOrNull $first.TimeCreated
        $range.log_newest_record_id = [int64](Get-WinEvent -LogName $LogName -MaxEvents 1 -ErrorAction Stop).RecordId
    }
    $out += $range
    $events = @(Get-WinEvent -LogName $LogName -FilterXPath $XPath -MaxEvents $MaxEvents -Oldest:$Oldest -ErrorAction Stop)
} catch {
    $out += [pscustomobject]@{ read_error = [string]$_.FullyQualifiedErrorId; message = [string]$_.Exception.Message }
    ConvertTo-Json -InputObject $out -Compress
    exit 0
}

$rows = @(foreach ($event in $events) {
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
})

ConvertTo-Json -InputObject ($out + $rows) -Depth 6 -Compress
"""

# The OS message table. Windows-only; None elsewhere, where every code reports as unmapped.
FORMAT_ERROR = getattr(ctypes, "FormatError", None)


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


def describe_result(code, formatter=FORMAT_ERROR):
    """Decode a task result code using the OS message table.

    A hand-maintained HRESULT table is both redundant and wrong: the OS knows
    0x8007052E is "the user name or password is incorrect", which is exactly the
    failure you want named. 0x8007xxxx is HRESULT-wrapped Win32 error xxxx; current
    Windows resolves either form, so unwrapping is belt-and-braces, not a fix.
    `formatter` is ctypes.FormatError on Windows and None elsewhere; the self-test
    passes a stub so the decode logic runs on every host.
    """
    unsigned = to_unsigned(code)
    if unsigned is None:
        return "no result recorded"
    if unsigned == 0:
        # Short-circuit: ctypes.FormatError(0) is stateful and returns the
        # "cannot find message text" placeholder after any failed lookup.
        return "success"
    win32 = (unsigned & 0xFFFF) if (unsigned & 0xFFFF0000) == 0x80070000 else unsigned
    message = ""
    if formatter is not None:
        try:
            message = formatter(ctypes.c_long(win32).value).strip()
        except Exception:
            message = ""
    if message and not message.startswith("<") and "message text for message number" not in message:
        return message
    return "unmapped result 0x%08X" % unsigned


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
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        # 9999-12-31T23:59:59-05:00 is past the last UTC instant a datetime holds.
        return parsed.astimezone(timezone.utc)
    except (ValueError, OverflowError):
        return None


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
    return not trigger_tokens(trigger_types).issubset(NO_NEXT_RUN_EXPECTED)


def unquote(value):
    """Strip one pair of matching quotes. PowerShell quotes a path with ' as often as with "."""
    text = text_of(value)
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "\"'":
        return text[1:-1].strip()
    return text


def program_name(executable):
    """The program's file name, lowercased, with any .exe removed."""
    return re.sub(r"\.exe$", "", ntpath.basename(unquote(executable)).lower())


def split_args(value):
    r"""The words of a command line, each keeping its quotes, as Windows' argv parser cuts them.

    A " opens or closes a quote anywhere in a word, so `--out="C:\my out\r.csv"` and
    `/LOG:"C:\my logs\x.txt"` are one word each. A ' opens a quote only at the start of a word
    or after = or :, because PowerShell quotes a path with ' but a name such as O'Brien is not
    quoted. An unclosed quote runs to the end of the line and the task still runs, so it is
    closed there. One whole-line word would skip the secret-switch rule and print a password in
    a finding. Backslashes escape nothing: a path ends in one.
    """
    words, word, quote = [], "", ""
    for char in text_of(value):
        if quote:
            word += char
            quote = "" if char == quote else quote
        elif char == '"' or (char == "'" and (not word or word[-1] in "=:")):
            word, quote = word + char, char
        elif char.isspace():
            words.append(word)
            word = ""
        else:
            word += char
    words.append(word + quote)
    return [part.strip() for part in words if part.strip()]


def extension_of(path_value):
    return os.path.splitext(unquote(path_value))[1].lower()


def script_words(tokens):
    r"""Each argument, with a quoted cmd /c or -Command body split into its own words.

    The target is printed in every report format. A body such as
    "set PGPASSWORD=x&& C:\jobs\refresh.bat" is one token, so only its script word may be
    reported. Each word is also cut after its last & | or ;, so a secret set earlier in the
    same word never becomes the target.
    """
    words = []
    for token in tokens:
        for word in (body_words(token) if re.search(r"\s", token) else [token]):
            words.append(re.split(r"[&|;]", unquote(word))[-1].strip())
    return words


def shown_program(exe):
    """The program field as it may be printed. A field that holds a command line is masked.

    Task Scheduler takes a whole command line in Command when Arguments is empty, so
    `sync.exe --password x` can be the program. mask_arguments() is for the arguments; a plain
    path is returned as it is.
    """
    return mask_arguments(exe) if re.search(r"\s", exe) else exe


def classify_command(executable, arguments):
    """Find the real script behind an interpreter invocation.

    Returns (target, kind). `python.exe C:\\jobs\\etl.py` reports etl.py, not
    python.exe - the interpreter is never the thing that broke. This is the one
    part of the report Windows genuinely does not give you.
    """
    exe = unquote(executable)
    shown = shown_program(exe)
    tokens = [unquote(token) for token in split_args(arguments)]
    lowered = [token.lower() for token in tokens]
    name = program_name(exe)
    ext = extension_of(exe)

    if PYTHON_NAME.match(name):
        for token in tokens:
            if token and not token.startswith("-") and extension_of(token) in (".py", ".pyw"):
                return token, "PythonScript"
        if "-c" in lowered:
            return shown, "PythonInline"
        if "-m" in lowered:
            index = lowered.index("-m")
            if index + 1 < len(tokens):
                return tokens[index + 1], "PythonModule"
        return shown, "Python"

    if name in POWERSHELL_EXES:
        for index, token in enumerate(lowered):
            if token in ("-file", "-f") and index + 1 < len(tokens):
                return unquote(tokens[index + 1]), "PowerShellScript"
        for token in script_words(tokens):
            if token and not token.startswith("-") and extension_of(token) == ".ps1":
                return token, "PowerShellScript"
        if "-command" in lowered or "-c" in lowered or "-encodedcommand" in lowered:
            return shown, "PowerShellInline"
        return shown, "PowerShell"

    if name in CMD_EXES:
        for token in script_words(tokens):
            if token and token[0] not in "/-" and extension_of(token) in (".bat", ".cmd"):
                return token, "BatchScript"
        return shown, "CommandShell"

    if name in SCRIPT_HOST_EXES:
        for token in tokens:
            token_ext = extension_of(token)
            if token and token[0] not in "/-" and token_ext in (".vbs", ".js"):
                return token, "VBScript" if token_ext == ".vbs" else "JavaScript"
        return shown, "ScriptHost"

    if ext in EXT_KIND:
        return shown, EXT_KIND[ext]
    return shown, "Executable" if exe else ""


def read_failures(task):
    """The parts of a live task the inventory read could not get, in order, without repeats.

    PS_QUERY names each part whose read threw. An exported XML task has none.
    """
    parts = []
    for part in text_of(task.get("read_errors")).split(","):
        if part.strip() and part.strip() not in parts:
            parts.append(part.strip())
    return parts


def health_status(task, now=None):
    """The verdict Windows never computes: join five fields into one word.

    `task` is a plain dict as produced by read_tasks(). `now` is an aware datetime
    used only for the overdue test, so this stays pure and testable.
    """
    if not task.get("enabled", True):
        return "Disabled"
    if read_failures(task):
        return "Warning"  # a task the read could not see is not a task that has not run

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

    failed = read_failures(task)
    if failed:
        reasons.append("the live read could not get its %s" % " or ".join(failed))
    if missed > 0:
        reasons.append("%d missed run(s)" % missed)
    if now and next_run and next_run < now:
        hours = (now - next_run).total_seconds() / 3600.0
        reasons.append("next run overdue by %.1f hour(s)" % hours)
    # Same two exemptions as health_status, or the reason contradicts the verdict.
    if next_run is None and code != TASK_NO_MORE_RUNS and expects_next_run(triggers):
        reasons.append("%s task has no next run time" % schedule_bucket(triggers).lower())
    if status == "Disabled":
        reasons.append("task is disabled")
    elif status == "Running":
        reasons.append("task is currently running")
    elif status == "NotYetRun" and not reasons:
        reasons.append("task has not yet run")
    else:
        reasons.append(result_text)  # describe_result() never returns an empty string
    return "; ".join(reasons)


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


def evaluate(task, now=None, stats=None, history="off", fate=None):
    """Enrich one raw task dict into a report row. Pure: dict in, dict out.

    `stats` is this task's entry from summarize_runs() when --history ran, else None. The
    history columns are emitted either way, so the CSV header does not change with the flag.
    `history` is how the run columns were read: "off" (no --history), "failed", "incomplete"
    (the counts are a lower bound) or "complete". Unread run counts are None, never 0: a saved
    report of a failed read must not match a clean read of an empty week.
    `fate` is this task's entry from judge_fates(). A STUCK or BLOCKED task is at least a
    Warning, so the default report keeps its row; the exit code still follows the snapshot
    alone, because a Warning never makes it non-zero.
    """
    target, kind = classify_command(task.get("executable"), task.get("arguments"))
    status = health_status(task, now)
    stats = stats or {}
    ratio = duration_ratio(stats)
    anomaly = 1 if ratio is not None and (
        ratio > DURATION_ANOMALY_HIGH_RATIO or ratio < DURATION_ANOMALY_LOW_RATIO) else 0
    read = history in ("complete", "incomplete")
    failures = int(stats.get("failures_last_7_days", 0) or 0) if read else None
    runs = int(stats.get("runs_last_7_days", 0) or 0) if read else None
    reasons = [attention_reason(task, status, now)]
    fate = (fate or {}) if read else {}
    if fate.get("fate"):
        reasons.insert(0, fate["detail"])  # first: the table cuts a cell at 60 characters
        if status in ("Success", "NotYetRun", "Running"):
            status = "Warning"
    if failures:
        # The whole point of --history: a task whose last run was green can have failed every
        # night for weeks, and the snapshot Task Scheduler keeps has one slot.
        reasons.append("%d of %d run(s) %s failed"
                       % (failures, runs, stats.get("window", "in the last 7 days")))
    if anomaly:
        reasons.append("last run took %.1fx its own baseline" % ratio)
    if history in ("failed", "incomplete"):
        reasons.append("run history %s" % ("unread" if history == "failed" else "incomplete"))
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
        "history": history,
        "runs_last_7_days": runs,
        "failures_last_7_days": failures,
        "last_duration_seconds": stats.get("last_duration_seconds"),
        "duration_ratio": round(ratio, 3) if ratio is not None else None,
        "is_duration_anomaly": anomaly,
        "fate": fate.get("fate", ""),
        "blocked_launches_last_7_days": int(fate.get("blocked_launches", 0)) if read else None,
    }


# --------------------------------------------------------------------------
# run history - the Operational log, grouped into runs (--history)
# --------------------------------------------------------------------------

def result_rank(code):
    """0 for a success code, 1 for a Task Scheduler warning code, 2 for any other code."""
    if code in NON_ERROR_CODES:
        return 0
    if code in WARNING_CODES:
        return 1
    return 2


def worse_fate(one, other):
    """The more serious of two fates (see FATE_RANK)."""
    return one if FATE_RANK[one] >= FATE_RANK[other] else other


def run_status(end_time, code, fate=""):
    """Verdict for one run in the event log, not for the task as a whole.

    A failed action is an Error at once, even before the run's 102: a watermark read that lands
    mid-run must count it, because the next read sees only the rest of the run. A run whose
    start failed, or that the scheduler stopped for exceeding its time limit, is an Error too,
    whatever codes it has. A run the scheduler terminated or a person stopped is a Warning, and
    it is over, whether or not a 102 followed. Otherwise a run with no 102 event has not
    finished, and a finished run with no 201 event recorded no result, which is Unknown rather
    than Success.
    """
    normalized = to_unsigned(code)
    rank = None if normalized is None else result_rank(normalized)
    if rank == 2 or fate in ("LaunchFailed", "TimedOut"):
        return "Error"
    if fate in ("Terminated", "Stopped"):
        return "Warning"
    if not text_of(end_time):
        return "Running"
    if rank is None:
        return "Unknown"
    return "Success" if rank == 0 else "Warning"


def task_names(tasks):
    """The full names of the inventory's tasks, which an event must name to join to one."""
    return set(full_task_name(task) for task in tasks if text_of(task.get("task_name")))


def build_run_rows(events, tasks):
    """Group Operational-log events into one row per run instance. Pure: events in, rows out.

    Events 100 and 102 bracket a run and 201 carries the result code. Events 103 and 203 (the
    action could not start) carry a result code too and make the run a failure. Events 111, 329
    and 330 say the scheduler or a person ended the instance; they set the row's fate but not
    its end time, so such a run gets no duration and never reaches the baseline. Event 101 (the
    task could not start at all) has no instance, so it is a row of its own, named after its
    record. Events 153, 322 and 332 are refused launches, not runs; build_block_rows() takes
    them. A run whose 100 event
    fell outside the fetch window used to emit a run with no start time at all, so the earliest
    observed event time is used instead and the row carries start_time_estimated, which stops
    an estimate reading as a measurement. Such a run gets no duration, so it never reaches the baseline. A group with
    nothing datable at all is dropped, not emitted with no start.

    An event naming a task that is not in `tasks` is skipped, so a filtered inventory yields a
    filtered history rather than rows nothing can be joined to.
    """
    known = task_names(tasks)
    grouped = {}

    for raw in events:
        event_id = to_int(raw.get("event_id"))
        if event_id in BLOCK_KINDS:
            continue
        instance_id = text_of(raw.get("instance_id"))
        task_name = text_of(raw.get("task_full_name"))
        if not instance_id and event_id == 101:
            instance_id = "launch-" + (text_of(raw.get("event_record_id"))
                                       or text_of(raw.get("event_time_utc")))
        if not instance_id or task_name not in known:
            continue
        group = grouped.setdefault(instance_id, {
            "task": task_name,
            "instance_id": instance_id,
            "start_time": None,
            "end_time": None,
            "first_event_time": None,
            "result_code": None,
            "fate": "",
        })

        event_time = text_of(raw.get("event_time_utc"))
        event_dt = parse_dt(event_time)

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
        if event_id in LAUNCH_FAILED_IDS:
            group["fate"] = worse_fate(group["fate"], "LaunchFailed")
        elif event_id in STOP_FATES:
            group["fate"] = worse_fate(group["fate"], STOP_FATES[event_id])
        if event_id == 201 or event_id in LAUNCH_FAILED_IDS:
            code = to_unsigned(raw.get("result_code"))
            # One 201 per action, read in either order: the worst code wins, so a failed
            # action is never hidden by another action's success or warning code.
            if code is not None and (group["result_code"] is None or
                                     result_rank(code) > result_rank(group["result_code"])):
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
        # An estimated start is the run's 201 or 102, seconds before its end, so it measures
        # nothing: such a run counts towards the week but never gets a duration, which would
        # read as a near-zero run and trip the baseline.
        duration = (round((end_dt - start_dt).total_seconds(), 2)
                    if start_dt and end_dt and end_dt >= start_dt and not start_estimated
                    else None)
        rows.append({
            "task": group["task"],
            "instance_id": group["instance_id"],
            "start_time": start_time,
            "start_time_estimated": start_estimated,
            "end_time": text_of(group["end_time"]),
            "duration_seconds": duration,
            "result_code": group["result_code"],
            "fate": group["fate"],
            "run_status": run_status(group["end_time"], group["result_code"], group["fate"]),
        })
    rows.sort(key=lambda row: (row["task"].lower(), row["start_time"]))
    return rows


def history_window(now, since_record_id=None):
    """(cutoff, label) of the runs the history columns count. The cutoff is None past a watermark."""
    cutoff = None if since_record_id is not None else now - timedelta(days=7)
    return cutoff, (("since record %d" % since_record_id) if cutoff is None
                    else "in the last 7 days")


def summarize_runs(run_rows, now, since_record_id=None):
    """Per-task run counts, last duration and completed-run mean. Pure, one dict per task.

    Without a watermark (None) the counts cover the 7 days before `now`. With one, even 0, the
    read holds only the runs since that watermark, and taskpulse keeps nothing between runs, so
    the counts cover exactly those runs, whatever their age, and each entry's "window" says so.
    A failure is then counted by the one run that read it, and a backlog older than 7 days is
    not dropped while the watermark moves past it.

    `now` is injected and never read from the clock. A cutoff that reads the wall clock
    itself makes every test written against a pinned clock pass on the day it was written and
    fail a week later.
    """
    cutoff, window = history_window(now, since_record_id)
    summary = {}

    for run in run_rows:
        key = text_of(run.get("task"))
        if not key:
            continue
        entry = summary.setdefault(key, {
            "runs_last_7_days": 0, "failures_last_7_days": 0,
            "completed_run_count": 0, "last_duration_seconds": None,
            "_last_start": None, "_duration_sum": 0.0, "window": window,
        })
        started = parse_dt(run.get("start_time"))
        duration = run.get("duration_seconds")
        if started is not None:
            if entry["_last_start"] is None or started > entry["_last_start"]:
                entry["_last_start"] = started
                entry["last_duration_seconds"] = duration
            if cutoff is None or started >= cutoff:
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


def build_block_rows(events, tasks):
    """The launches that Task Scheduler refused, one row each, oldest first. Pure.

    Events 153 (a missed start was not made up), 322 (the task was still running) and 332 (the
    run-as user was not logged on) say a launch was refused. None of them is a run, and none
    starts one. A 322 names the instance that was still running, which judge_fates() uses to
    tie the refusals to a run that never ends. An event for a task outside the inventory, or
    with no usable time, is skipped, as in build_run_rows().
    """
    known = task_names(tasks)
    rows = []
    for raw in events:
        kind = BLOCK_KINDS.get(to_int(raw.get("event_id")))
        when = text_of(raw.get("event_time_utc"))
        task_name = text_of(raw.get("task_full_name"))
        if kind is None or task_name not in known or parse_dt(when) is None:
            continue
        rows.append({"task": task_name, "kind": kind, "time": when,
                     "instance_id": text_of(raw.get("instance_id"))})
    rows.sort(key=lambda row: (row["task"].lower(), parse_dt(row["time"])))
    return rows


def judge_fates(run_rows, block_rows, tasks, now, since_record_id=None, stuck_hours=STUCK_HOURS):
    """STUCK, BLOCKED or neither for each task that has a run or a refused launch. Pure.

    STUCK: a run has no end event, and the task's own state does not say otherwise, and the run
    began `stuck_hours` or more ago. Later launches that were refused because it was still
    running (event 322) are counted in the detail, but they do not make a young run STUCK: a
    healthy job that runs longer than its repeat interval draws a 322 for every trigger. A task
    whose state is Running and whose last launch was `stuck_hours` or more ago is STUCK too,
    even when this read holds no start event for that run. A task whose state is Ready or Queued
    is not running, so a run with no end event is a lost end event, not a stuck run. A state
    that is missing, as in an XML export, does not rule a run out.

    BLOCKED: not stuck, and the latest launch refused inside the window came after the task's
    latest start in this read, so nothing has run since. The window is the one the run columns
    use (see history_window), and `blocked_launches` counts every refusal inside it.

    Each entry is {fate, detail, blocked_launches}; fate is "" for a task that is neither.
    """
    cutoff, _ = history_window(now, since_record_id)
    states = dict((full_task_name(task), text_of(task.get("state")).lower()) for task in tasks)
    launched = dict((full_task_name(task), parse_dt(task.get("last_run_time"))) for task in tasks)
    runs, blocks = {}, {}
    for row in run_rows:
        runs.setdefault(row["task"], []).append(row)
    for row in block_rows:
        blocks.setdefault(row["task"], []).append(row)
    verdicts = {}
    running = set(name for name, state in states.items() if state == "running")
    for name in sorted(set(runs) | set(blocks) | running):
        refused = blocks.get(name, [])
        counted = [row for row in refused
                   if cutoff is None or parse_dt(row["time"]) >= cutoff]
        stuck = []
        if states.get(name, "") not in ("ready", "queued"):
            for run in runs.get(name, []):
                started = parse_dt(run["start_time"])
                if run["run_status"] != "Running" or started is None:
                    continue
                waiting = len([row for row in refused if row["kind"] == "overlap"
                               and row["instance_id"] == run["instance_id"]])
                hours = (now - started).total_seconds() / 3600.0
                if hours >= stuck_hours:
                    stuck.append((hours, waiting))
            # The scheduler's own word: Running since a launch long ago, whether or not this
            # read holds that run's start event (the log may be shorter than --history).
            since_launch = launched.get(name)
            if not stuck and states.get(name) == "running" and since_launch is not None:
                hours = (now - since_launch).total_seconds() / 3600.0
                if hours >= stuck_hours:
                    stuck.append((hours, 0))
        starts = [parse_dt(run["start_time"]) for run in runs.get(name, [])]
        last_start = max([when for when in starts if when] or [None])
        late = [row for row in counted if last_start is None or parse_dt(row["time"]) > last_start]
        fate, detail = "", ""
        if stuck:
            hours, waiting = max(stuck)
            fate = "STUCK"
            detail = "STUCK: a run started %.1f hour(s) ago has not finished" % hours
            if waiting:
                detail += "; %d later launch(es) were ignored while it ran (event 322)" % waiting
        elif late:
            latest = max(late, key=lambda row: parse_dt(row["time"]))
            fate = "BLOCKED"
            detail = "BLOCKED: %s at %s" % (BLOCK_TEXT[latest["kind"]],
                                           parse_dt(latest["time"]).strftime("%Y-%m-%dT%H:%MZ"))
        verdicts[name] = {"fate": fate, "detail": detail, "blocked_launches": len(counted)}
    return verdicts


def is_microsoft_task(task):
    """Stock Windows ships ~200 of its own tasks; they drown out yours."""
    path = text_of(task.get("task_path")).replace("/", "\\").lower()
    return path.startswith("\\microsoft\\")


# --------------------------------------------------------------------------
# configuration lint (--lint) - pure: task dict in, findings out
# --------------------------------------------------------------------------

def body_words(body):
    r"""Split the quoted body of cmd /c or powershell -Command into its own words.

    A body that starts with a rooted path holding spaces, such as
    "C:\Program Files\ArcGIS\Pro\bin\Python\Scripts\propy.bat", keeps that path whole: the
    leading words join until they end in a known extension.
    """
    words = split_args(body)
    if words and ROOTED.match(words[0]):
        for end in range(1, len(words) + 1):
            head = " ".join(words[:end])
            if extension_of(head) in PATH_EXTS | {".exe"}:
                return ['"%s"' % head] + words[end:]
    return words


def arg_values(arguments, body=None, hidden=None):
    """The values a command line passes, with switch names cut off and secrets left out.

    `-in data.csv`, `--out=r.csv`, `/LOG:r.txt` and `-Path:C:\\x` each give their value. The
    value of a switch named like a secret (SECRET_SWITCH) goes to `hidden` instead, because
    only the share check may read it and no finding may print it. A switch with no value of
    its own, such as -PassThru, hands the next word to `hidden` too, so that word still meets
    the share check. The value of an account switch (USER_SWITCH) is dropped, and so is a
    value with '=' or '+' in it and no PATH_EXTS extension, which base64 keys, tokens and
    connection strings carry. A leading redirection (`>`, `2>`) is cut off. `body` is the
    switch that makes the program run a command line of its own (BODY_SWITCH). Everything after
    it is that command line, quoted or not. It is split again as one line, with the body
    switch of the program it starts, so `cmd /c powershell -Command "..."` splits both bodies.
    """
    hidden = [] if hidden is None else hidden
    tokens = split_args(arguments)
    values, secret_next, user_next = [], False, False
    for index, token in enumerate(tokens):
        value = unquote(token)
        if body and re.match(body + "$", value, re.IGNORECASE):
            rest = tokens[index + 1:]
            line = unquote(rest[0]) if len(rest) == 1 else " ".join(rest)
            if body == BODY_SWITCH["cmd"] and line[:1] == line[-1:] == '"' and line.count('"') > 2:
                line = line[1:-1]  # cmd /c strips the outer pair when the line holds more quotes
            words = body_words(line)
            inner = BODY_SWITCH.get(program_name(words[0])) if words else None
            return values + arg_values(" ".join(words), inner, hidden)
        secret, secret_next = secret_next, False
        user, user_next = user_next, False
        value = re.sub(r"^\d?[<>]+", "", value)
        if value[:1] in ("-", "/") and value[:2] != "//":
            name, value = re.match(r"[-/]*([^=:]*)[=:]?(.*)", value).groups()
            value = unquote(value)
            secret = bool(SECRET_SWITCH.search(name))
            user = bool(USER_SWITCH.match(name))
            secret_next, user_next = secret and not value, user and not value
        opaque = re.search(r"[=+]", value) and extension_of(value) not in PATH_EXTS
        if value and secret:
            hidden.append(value)
        elif value and not user and not opaque:
            values.append(value)
    return values


def relative_paths(executable, arguments):
    """File paths in a command line that are not rooted, so they resolve against Start In.

    The program and each value from arg_values() count as a path when they end in a PATH_EXTS
    extension, or when they hold a separator. A bare refresh.bat counts, because no PATH holds
    the user's own script; a bare python.exe does not, because PATH finds it. URLs and paths
    rooted at a drive, at a UNC share, at \\ or at a %VARIABLE% are not relative. Neither is a
    value with ':' after its second character, such as a URL, svc:Hunter2 or "Authorization:
    Basic x", because Windows allows ':' in a path only after a drive letter. net takes no file
    argument at all, so the password in `net use \\\\srv\\share <password>` is never judged.
    """
    name = program_name(executable)
    found = []
    for value in [unquote(executable)] + ([] if name == "net" else arg_values(
            arguments, BODY_SWITCH.get(name))):
        is_path = extension_of(value) in PATH_EXTS or re.search(r"[\\/]", value)
        if is_path and ":" not in value[2:] and not ROOTED.match(value):
            found.append(value)
    return found


def changes_directory(executable, arguments):
    """True when the body that cmd /c or powershell -Command runs changes directory first.

    False for any other program. Only the first command of the body counts, so in
    `cmd /c x.bat && cd C:\\logs` the cd comes too late. A cd with no folder changes nothing.
    cmd's cd without /d keeps the current drive, and with Start In empty that drive is the one
    System32 is on, so `cd D:\\jobs` from there leaves the task in System32 (measured). cmd's
    `cd C:` only prints C:'s current folder (measured). cmd cannot make \\\\server\\share its
    current folder, so that cd fails and the task stays in System32; only pushd maps a share.
    A relative folder, as in `cd scripts`, resolves against System32 itself, so it is no
    substitute for Start In. The folder must be rooted (ROOTED), or a $variable in PowerShell.
    """
    name = program_name(executable)
    switch = BODY_SWITCH.get(name)
    match = switch and re.search(r"(?:^|\s)%s\s+[\"']?([^&|;]*)" % switch,
                                 text_of(arguments), re.IGNORECASE)
    words = [word.strip("\"'").lower() for word in match.group(1).split()] if match else []
    if len(words) < 2 or words[0] not in DIR_CHANGERS:
        return False
    cmd_cd = name == "cmd" and words[0] in ("cd", "chdir")
    # `cd /d D:\jobs` changes drive as well. A /d after the folder is read as part of the
    # folder, and the cd fails (measured).
    switch_drive = cmd_cd and words[1] == "/d"
    named = switch_drive or words[1] in ("-path", "-literalpath")
    folder = ((words[2:] if named else words[1:]) or [""])[0]
    if not (ROOTED.match(folder) or (name != "cmd" and folder[:1] == "$")):
        return False
    if not cmd_cd:
        return True
    # Without /d, only a folder on the drive System32 is on, or rooted at \, is reached. A
    # %VARIABLE% may name another drive.
    return not re.match(r"[\\/]{2}", folder) and (
        switch_drive or folder[:1] in "\\/" or folder[0].upper() == SYSTEM32[0])


def as_list(value):
    """A list for a value that ConvertTo-Json may have unwrapped to one object, or left out."""
    value = value or []
    return [value] if isinstance(value, dict) else value


def effective_setting(task, name):
    """A task's setting, lowercased: the task's own value, else the schema default."""
    return text_of((task.get("settings") or {}).get(name) or SETTING_DEFAULTS[name]).lower()


def unlimited(duration):
    """True for an ISO 8601 duration of zero, such as PT0S: Task Scheduler's 'run indefinitely'."""
    return duration.upper().startswith("P") and re.search(r"[1-9]", duration) is None


def logon_minorities(tasks):
    """{task name: detail} for each enabled task whose logon type its neighbours do not share.

    Neighbours are the enabled tasks in the same folder that run as the same account. A logon
    type counts as the majority only when two or more neighbours share it and no other type
    has as many, so a tie names nobody. A heuristic, not a Task Scheduler rule: a task can
    differ on purpose, and the finding is a Warning for that reason. It is how a settings
    change that flips one nightly job to another logon type shows up beside the jobs it used
    to match.
    """
    groups = {}
    for task in tasks:
        kind = LOGON_KINDS.get(text_of(task.get("logon_type")).lower(), "")
        user = text_of(task.get("run_as_user"))
        if task.get("enabled", True) and kind and user:
            folder = (text_of(task.get("task_path")) or "\\").lower()
            groups.setdefault((folder, user.lower()), []).append((full_task_name(task), kind, user))
    found = {}
    for members in groups.values():
        counts = {}
        for _, kind, _ in members:
            counts[kind] = counts.get(kind, 0) + 1
        top = [kind for kind, count in counts.items() if count == max(counts.values())]
        if len(top) != 1 or counts[top[0]] < 2:
            continue
        for name, kind, user in members:
            if counts[kind] == 1:
                found[name] = (
                    "logon type %s differs from the %d other task(s) in this folder that run as "
                    "%s, which use %s: if this is not deliberate, a settings change flipped it"
                    % (kind, counts[top[0]], user, top[0]))
    return found


def lint_task(task, local_drives=("C",), now=None):
    """Configuration findings for one task. Pure: task dict in, list of finding dicts out.

    `task` is a read_tasks() row or a parse_task_xml() row: it needs logon_type,
    run_as_user, trigger_types and an `actions` list of {executable, arguments,
    working_directory}. Each finding is {task, severity, check, detail}; severity is Error
    when the next run cannot work as configured and Warning when it depends on something
    this tool cannot see offline, such as whether D: is a mapped drive.

    A task with a `settings` dict, as both readers give, is also judged for the ways it skips
    runs without an error, with the schema defaults applied to what it leaves out (see
    SETTING_DEFAULTS). `now` turns on the one check that needs a clock, an expired trigger.
    """
    name = full_task_name(task)
    findings = []

    def add(severity, check, detail):
        findings.append({"task": name, "severity": severity, "check": check, "detail": detail})

    logon = LOGON_KINDS.get(text_of(task.get("logon_type")).lower(), "")
    user = text_of(task.get("run_as_user"))
    account = SERVICE_ACCOUNTS.get(user.lower().replace("nt authority\\", "").replace(" ", ""), "")
    actions = task.get("actions") or []
    # ConvertTo-Json unwraps a one-element array to a bare object.
    actions = [actions] if isinstance(actions, dict) else actions
    kinds = [classify_command(a.get("executable"), a.get("arguments"))[1] for a in actions]
    scripted = [kind for kind in kinds if kind not in ("Executable", "")]
    unattended = sorted(trigger_tokens(task.get("trigger_types")) & UNATTENDED_TRIGGERS)
    local = set(drive.strip().rstrip(":").upper() for drive in local_drives)

    failed = read_failures(task)
    if failed:
        add("Warning", "read-failed",
            "the live read could not get this task's %s, so the lint may have missed a "
            "finding" % " or ".join(failed))
    if logon == "interactive" and unattended:
        # A settings change can flip a nightly job to "Run only when user is logged on".
        # Nothing then runs while nobody is logged on, and no run means no new result.
        add("Error" if scripted else "Warning", "interactive-only",
            "logon type is interactive: the task runs only while %s is logged on, so its %s "
            "trigger does nothing when nobody is" % (user or "its user", " and ".join(unattended)))

    for action in actions:
        exe = text_of(action.get("executable"))
        args = text_of(action.get("arguments"))
        start = text_of(action.get("working_directory"))
        # Values, not the raw line: a secret's value never reaches a finding, and a share
        # after /LOG: or -Path: starts a value of its own.
        hidden = []
        joined = " ".join([exe] + arg_values(args, BODY_SWITCH.get(program_name(exe)), hidden)
                          + [start])
        kind = classify_command(exe, args)[1]

        named = sorted(set("\\\\%s\\%s" % pair for pair in UNC.findall(joined)))
        # A hidden value is read only for the \\server\share form, which base64 never takes,
        # and the share is not named, in case the value is a secret after all.
        if any(re.match(r"\\\\", m.group(0)) for m in map(UNC.search, hidden) if m):
            named.append("a share in a secret switch's value (not printed)")
        shares = ", ".join(named)
        if shares and logon == "s4u":
            add("Error", "s4u-network",
                "logon type is S4U ('Do not store password'), which has no network credentials, "
                "so %s is unreachable" % shares)
        if shares and account == "LOCAL SERVICE":
            add("Error", "service-network",
                "LOCAL SERVICE reaches the network anonymously, so %s is unreachable" % shares)
        elif shares and account:
            add("Warning", "service-network",
                "%s reaches %s as the computer account (DOMAIN\\HOST$); the share must grant "
                "that account" % (account, shares))

        drives = sorted(set(letter.upper() for letter in DRIVE.findall(joined)) - local)
        if drives and logon != "interactive":
            add("Warning", "mapped-drive",
                "%s: is not a declared local drive (--local-drives); a mapped drive does not "
                "exist in a non-interactive logon, so use the UNC path" % ":, ".join(drives))

        if '"' in start:
            # A quote is never valid in a Windows path, at either end or half way.
            add("Error", "start-in-quoted",
                "Start In %s is quoted; Task Scheduler does not strip the quotes and the task "
                "fails to start with 0x8007010B (the directory name is invalid)" % start)
        elif start and not ROOTED.match(start):
            add("Error", "start-in-relative",
                "Start In %s is not an absolute path" % start)
        elif not start and not changes_directory(exe, args):
            relative = relative_paths(exe, args)
            # A value that only looks like a path, such as a password with a '/', can be a
            # secret, so only a value with a known extension is printed.
            shown = [value if extension_of(value) in NAMED_EXTS
                     else "(a value with no file extension, not printed)" for value in relative]
            if relative:
                add("Error", "start-in-missing",
                    "Start In is empty, so the relative path %s resolves against %s"
                    % (", ".join(shown), SYSTEM32))
            elif kind not in ("Executable", ""):
                add("Warning", "start-in-missing",
                    "Start In is empty, so the script runs in %s and any relative path it opens "
                    "resolves there" % SYSTEM32)

        bare = unquote(exe)
        stem = re.sub(r"\.exe$", "", bare.lower())
        if bare and not re.search(r"[\\/%]", bare) and stem not in SYSTEM_PROGRAMS:
            add("Warning", "bare-program",
                "%s has no folder, so it resolves against Start In and then the run-as "
                "account's PATH; which program runs, if any, depends on that account"
                % shown_program(bare))

    settings = task.get("settings")
    if settings is not None:
        policy = effective_setting(task, "MultipleInstancesPolicy")
        if unlimited(effective_setting(task, "ExecutionTimeLimit")) and policy != "stopexisting":
            # Event 322 is what Task Scheduler logs for each launch that IgnoreNew drops.
            add("Warning", "no-time-limit",
                "ExecutionTimeLimit is %s (run indefinitely), so a hung run never ends and %s"
                % (settings["ExecutionTimeLimit"],
                   HANG_EFFECT.get(policy, "later launches are affected")))
        waits = [label for name, label in (("RunOnlyIfIdle", "the computer is idle"),
                                           ("RunOnlyIfNetworkAvailable", "a network is available"))
                 if effective_setting(task, name) == "true"]
        if waits:
            add("Warning", "run-conditions",
                "the task is set to run only when %s: a trigger that fires while that is false "
                "can leave the run unstarted, and Last Run Result then still shows the previous "
                "run" % " and ".join(waits))

    live = [t for t in as_list(task.get("trigger_details")) if t.get("enabled", True)]
    ends = [parse_dt(t.get("end_boundary")) for t in live]
    # A time with no offset is the machine's local time, which an export does not say, so a
    # trigger counts as ended only a day after its EndBoundary: the zone cannot change that.
    if now and live and all(end and end < now - timedelta(days=1) for end in ends):
        add("Warning", "trigger-expired",
            "every enabled trigger ended (the latest EndBoundary is %s), so the task cannot start "
            "again; Task Scheduler reports 0x00041304 (no more runs), which the health report "
            "does not count as an error" % max(ends).strftime("%Y-%m-%dT%H:%MZ"))
    return findings


def lint_rows(tasks, local_drives=("C",), show_ok=False, now=None):
    """Findings for every enabled task, Errors first. show_ok adds one OK row per clean task."""
    rows = []
    # ponytail: a disabled task cannot fail a run, so it is not linted; re-enable, re-lint.
    tasks = [task for task in tasks if task.get("enabled", True)]
    minority = logon_minorities(tasks)
    for task in tasks:
        found = lint_task(task, local_drives, now)
        if full_task_name(task) in minority:
            found.append({"task": full_task_name(task), "severity": "Warning",
                          "check": "logon-minority", "detail": minority[full_task_name(task)]})
        clean = [{"task": full_task_name(task), "severity": "OK", "check": "",
                  "detail": "no findings"}] if show_ok else []
        rows.extend(found or clean)
    rows.sort(key=lambda row: (row["severity"] != "Error", row["severity"] != "Warning",
                               row["task"].lower()))
    return rows


# --------------------------------------------------------------------------
# exported task XML - pure parsing, then the one function that opens files
# --------------------------------------------------------------------------

def decode_task_xml(data):
    """Bytes of an exported task file to text, whatever wrote it.

    Files under System32\\Tasks and PowerShell 5 redirects are UTF-16 with a BOM; schtasks
    redirected by another shell is the console code page with no declaration; hand-saved
    exports are UTF-8. The XML declaration is not trusted: a UTF-8 file that still says
    encoding="UTF-16" is common, and expat refuses it outright.
    """
    if data.startswith(codecs.BOM_UTF16_LE) or data.startswith(codecs.BOM_UTF16_BE):
        return data.decode("utf-16")
    if data.startswith(codecs.BOM_UTF8):
        return data[len(codecs.BOM_UTF8):].decode("utf-8")
    if b"\x00" in data[:200]:
        return data.decode("utf-16-le")  # BOM-less UTF-16; Windows writes little-endian
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        # ponytail: a console code page is unknowable from the bytes; latin-1 keeps the
        # markup intact and only mis-spells non-ASCII task names.
        return data.decode("latin-1")


def local_name(tag):
    """Element tag without its namespace. Comments carry a function as their tag."""
    return tag.rsplit("}", 1)[-1] if isinstance(tag, str) else ""


def xml_children(node, name):
    return [child for child in (node if node is not None else []) if local_name(child.tag) == name]


def xml_first(node, *path):
    for name in path:
        found = xml_children(node, name)
        node = found[0] if found else None
    return node


def xml_text(node, *path):
    found = xml_first(node, *path)
    return text_of(found.text) if found is not None else ""


def xml_leaves(node, prefix=""):
    """Every element with text and no children below `node`, as sorted (dotted path, text) pairs.

    Used for what --diff compares and cannot name in advance: a trigger's schedule, a setting's
    sub-elements, an action's fields. A comment has no name, so it adds nothing.
    """
    pairs = []
    for child in (node if node is not None else []):
        name = local_name(child.tag)
        if not name:
            continue
        if len(child):
            pairs.extend(xml_leaves(child, prefix + name + "."))
        else:
            pairs.append((prefix + name, text_of(child.text)))
    return sorted(pairs)


def split_task_uri(uri):
    r"""\Folder\Name to (task_path, task_name), so full_task_name() gives the URI back."""
    uri = uri.replace("/", "\\")
    uri = uri if uri.startswith("\\") else "\\" + uri
    cut = uri.rfind("\\") + 1
    return uri[:cut], uri[cut:]


def trigger_name(trigger):
    """A Triggers child element to the trigger-type word trigger_tokens() understands."""
    tag = local_name(trigger.tag)
    if tag == "CalendarTrigger":
        kinds = [local_name(child.tag)[len("ScheduleBy"):] for child in trigger
                 if local_name(child.tag).startswith("ScheduleBy")]
        return CALENDAR_KINDS.get(kinds[0], "Calendar") if kinds else "Calendar"
    return re.sub(r"Trigger$", "", tag)


def task_from_xml(node, name):
    """One <Task> element to a task dict in read_tasks()'s shape, plus logon_type and actions."""
    uri = xml_text(node, "RegistrationInfo", "URI") or name
    actions = xml_first(node, "Actions")
    context = actions.get("Context", "") if actions is not None else ""
    principals = xml_children(xml_first(node, "Principals"), "Principal")
    # The principal the actions run as is the one Actions/@Context names, not the first.
    chosen = [p for p in principals if p.get("id") == context] + principals
    principal = chosen[0] if chosen else None
    user = xml_text(principal, "UserId")
    group = xml_text(principal, "GroupId")
    triggers = xml_first(node, "Triggers")
    task_path, task_name = split_task_uri(uri)
    return {
        "task_path": task_path,
        "task_name": task_name,
        "enabled": xml_text(node, "Settings", "Enabled").lower() != "false",
        "run_as_user": user or group,
        "run_level": xml_text(principal, "RunLevel"),
        # Only what the XML says; lint_task and diff_tasks apply the schema defaults.
        "settings": dict(xml_leaves(xml_first(node, "Settings"))),
        "trigger_details": [
            {"kind": trigger_name(t), "enabled": xml_text(t, "Enabled").lower() != "false",
             "end_boundary": xml_text(t, "EndBoundary"), "leaves": xml_leaves(t)}
            for t in (triggers if triggers is not None else []) if local_name(t.tag)],
        "action_details": [{"kind": local_name(a.tag), "leaves": xml_leaves(a)}
                           for a in (actions if actions is not None else [])
                           if local_name(a.tag)],
        # A group principal runs only in a member's session, whatever else is set.
        "logon_type": xml_text(principal, "LogonType") or ("Group" if group and not user else ""),
        # A disabled trigger never fires, so it is not one of the task's triggers.
        "trigger_types": " | ".join(
            trigger_name(t) for t in (triggers if triggers is not None else [])
            if xml_text(t, "Enabled").lower() != "false"),
        "actions": [{"executable": xml_text(e, "Command"),
                     "arguments": xml_text(e, "Arguments"),
                     "working_directory": xml_text(e, "WorkingDirectory")}
                    for e in xml_children(actions, "Exec")],
    }


def parse_task_xml(text, fallback_name=""):
    """Every <Task> in one exported file, as task dicts. Raises ValueError on anything else.

    Accepts a single task export, the <Tasks> wrapper that `schtasks /query /xml` prints
    (each task preceded by a <!-- \\Path\\Name --> comment and often with no URI), and
    several task documents pasted end to end. A file with no <Task> at all is an error,
    not an empty lint: a wrong file passed by mistake must not read as a clean one.

    The body is wrapped in one root element so that pasted documents parse together. That
    also puts any DOCTYPE inside an element, where it is malformed, so no entity can expand.
    """
    body = XML_DECL.sub("", text)
    parser = ET.XMLParser(target=ET.TreeBuilder(insert_comments=True))
    try:
        root = ET.fromstring("<taskpulse>%s</taskpulse>" % body, parser)
    except ET.ParseError as error:
        raise ValueError("not well-formed XML: %s" % error)
    tasks = []
    pending = ""
    for node in root.iter():
        if node.tag is ET.Comment:
            pending = text_of(node.text)
        elif local_name(node.tag) == "Task":
            tasks.append(task_from_xml(node, pending or fallback_name))
            pending = ""
    if not tasks:
        raise ValueError("no <Task> element found")
    return tasks


def raise_error(error):
    raise error


def read_task_files(paths, walk=os.walk, islink=os.path.islink):
    """Parse exported task XML from files and folders. Folders are walked, as System32\\Tasks is.

    A task with neither a URI nor a schtasks comment is named after its file, relative to
    the folder given, which is exactly the task's path when the folder is a copy of
    System32\\Tasks. Any unreadable file or subfolder, a subfolder that is a symbolic link, or
    a folder with no file in it, stops the run: a lint that read nothing there would pass.
    os.walk skips a subfolder it cannot list unless onerror raises, and it lists a linked
    subfolder without entering it. `walk` and `islink` exist for the self-test, which can
    neither lock a folder nor make a link on every OS.
    """
    tasks = []
    for path in paths:
        root = path if os.path.isdir(path) else os.path.dirname(path)
        files = [path]
        if os.path.isdir(path):
            files = []
            for folder, subfolders, names in walk(path, onerror=raise_error):
                linked = [os.path.join(folder, name) for name in subfolders
                          if islink(os.path.join(folder, name))]
                if linked:
                    raise ValueError("%s: a linked folder is not followed; lint its target"
                                     % linked[0])
                files.extend(os.path.join(folder, name) for name in names)
            files.sort()
        if not files:
            # An empty folder read as zero tasks would lint clean: the same false pass.
            raise ValueError("%s: no task file found" % path)
        for filename in files:
            fallback = "\\" + re.sub(r"\.xml$", "", os.path.relpath(filename, root),
                                     flags=re.IGNORECASE).replace(os.sep, "\\")
            with open(filename, "rb") as handle:
                data = handle.read()
            try:
                tasks.extend(parse_task_xml(decode_task_xml(data), fallback))
            except ValueError as error:
                raise ValueError("%s: %s" % (filename, error))
    return tasks


# --------------------------------------------------------------------------
# task definition diff (--diff) - pure: two lists of parsed tasks in, rows out
# --------------------------------------------------------------------------

def mask_word(value, state):
    """(shown text, state for the next word) of one word of a command line, for mask_arguments.

    `state` is "secret" when the word before was a secret switch with no value of its own, and
    "cred" when it was -u or --user, whose value is a secret only when it holds a ':'.
    """
    if not re.search(r"\s", value):
        value = URL_AUTH.sub(r"\1***@", value)
    head, secret, after = "", state == "secret", ""
    if value[:1] in ("-", "/") and value[:2] != "//" and (
            not re.search(r"\s", value) or re.match(r"[-/]+[^=:\s]*[=:]", value)):
        dashes, name, sep, value = re.match(r"([-/]*)([^=:\s]*)([=:]?)(.*)", value,
                                            re.DOTALL).groups()
        head = dashes + name + sep
        attached = (dashes == "-" and name[:1] in MASKED_LETTERS and len(name) > 1
                    and name.lower() not in ATTACHED_PARAMS
                    and not SECRET_SWITCH.match(name))
        if attached:
            return dashes + name[:1] + "***" + sep + ("***" if value else ""), ""
        secret = bool(SECRET_SWITCH.search(name)) or name in MASKED_LETTERS
        if secret and not value:
            after = "secret"
        if name in CRED_SWITCH:
            secret = bool(CRED_VALUE.match(unquote(value)))
            after = "" if value else "cred"
    elif state == "cred":
        secret = bool(CRED_VALUE.match(unquote(value)))
    inner = unquote(value) if head else value
    if re.search(r"\s", inner) and not head and split_args(inner) == [inner]:
        # NAME="a b" or x"y z" is one word: mask_arguments(inner) would split it into itself
        # and recurse for ever. Keep the name, then mask the value as its own line.
        name, equals, rest = inner.partition("=")
        if not equals or '"' in name or "'" in name:
            return '"***"', ""
        return name + "=" + ("***" if secret or SECRET_SWITCH.search(name) else
                             '"%s"' % mask_arguments(unquote(rest))), ""
    if re.search(r"\s", inner):
        header = SECRET_HEADER.match(inner)
        text = ('"%s ***"' % header.group(1) if header and not secret
                else '"***"' if secret else '"%s"' % mask_arguments(inner))
        return head + text, ""
    header = None if head else SECRET_HEADER.match(value)
    opaque = re.search(r"[=+]", value) and extension_of(value) not in PATH_EXTS
    if header:
        return header.group(1) + "***", after
    return head + ("***" if value and (secret or opaque) else value), after


def mask_arguments(arguments, program=""):
    r"""A command line with every value that could be a secret replaced by ***.

    The rules of arg_values(), kept to what a diff prints: the value of a secret switch
    (SECRET_SWITCH), the word after a secret switch that has no value of its own, a value
    with '=' or '+' in it and no known file extension, which base64 keys and connection
    strings have, the password in the user:password@host of a URL, the user:password after -u
    or --user (CRED_SWITCH), the value of a header whose name says it holds a secret
    (SECRET_HEADER) and the attached -pSECRET (ATTACHED_PARAMS). Every argument of `net` is
    masked, because `net use \srv\share <password>` takes its password by position, and so is
    every word of a `net` command inside a cmd /c or powershell -Command body, up to the next
    & | or ;. A word that holds spaces, such as a quoted body, is masked word by word. A value
    after a one-letter switch is not masked, except -P, -p and -k (MASKED_LETTERS). The value
    of a JSON member named like a secret is masked (JSON_SECRET).
    """
    if program == "net":
        return "***" if text_of(arguments) else ""
    arguments = JSON_SECRET.sub(lambda m: m.group(1) + '"***"', text_of(arguments))
    words, state, net_args = [], "", False
    for token in split_args(arguments):
        value = unquote(token)
        shown = ""
        for piece in ([value] if re.search(r"\s", value) else re.split(r"([&|;]+)", value)):
            if re.match(r"[&|;]+$", piece):
                net_args, shown = False, shown + piece
            elif net_args and piece:
                shown += "***"
            elif piece:
                text, state = mask_word(piece, state)
                net_args = program_name(piece) == "net"
                shown += text
        words.append(shown)
    return " ".join(words)


def describe_action(action, show_args=False):
    """(compare key, shown text) of one child of Actions.

    The arguments are compared always, but the text leaves them out unless `show_args` is set:
    a mask is a blacklist of known secret shapes, and a credential in a shape it does not know
    (a token in a URL path, a bare positional password) would print. With `show_args` the text
    holds the arguments with the mask applied, which is a second layer, not a guarantee.
    """
    fields = dict(action["leaves"])
    if action["kind"] != "Exec":
        return (action["kind"], tuple(action["leaves"])), (
            "%s %s" % (action["kind"], fields.get("ClassId", ""))).strip()
    command = fields.get("Command", "")
    args = fields.get("Arguments", "")
    start = fields.get("WorkingDirectory", "")
    if show_args:
        shown_args = mask_arguments(args, program_name(command))
    else:
        shown_args = "[arguments not shown]" if args else ""
    shown = "Exec " + " ".join(part for part in (mask_arguments(command), shown_args) if part)
    return (command.lower(), args, start.lower()), shown + (
        " [Start In %s]" % start if start else "")


def describe_trigger(trigger):
    """(compare key, shown text) of one trigger. Enabled is true when the export says nothing."""
    # A list, not a dict: a monthly trigger repeats <Day>, and a dict keeps only one of them.
    pairs = list(trigger["leaves"])
    if not any(name == "Enabled" for name, _ in pairs):
        pairs.append(("Enabled", "true"))
    pairs.sort()
    return (trigger["kind"].lower() + "|" + ";".join(
        "%s=%s" % (name.lower(), value.lower()) for name, value in pairs),
        trigger["kind"] + " " + ", ".join("%s=%s" % pair for pair in pairs))


def unmatched(old, new):
    """(old shown, new shown) pairs of the entries that two lists of (key, shown) do not share.

    Order does not matter, and a repeated entry is matched as often as it repeats. What is left
    is paired in key order; the shorter side is padded with blanks.
    """
    rest = sorted(new)
    gone = []
    for item in sorted(old):
        matches = [other for other in rest if other[0] == item[0]]
        if matches:
            rest.remove(matches[0])
        else:
            gone.append(item)
    return list(zip_longest([item[1] for item in gone], [item[1] for item in rest], fillvalue=""))


def compare_tasks(old, new, show_args=False):
    """(field, old shown, new shown) for each difference between two parses of one task.

    Compared: the account, its logon type and run level; each Settings element, with the schema
    default for one that only a side leaves out; the triggers, in any order; and the actions, in
    order. Not compared: RegistrationInfo (date, author, description), which changes on every
    re-registration and does not change what runs. Arguments are compared but not printed
    unless `show_args` is set (see describe_action); a change to a hidden one says so.
    """
    changes = []

    def pair(value, key=None):
        return (text_of(value).lower() if key is None else key, text_of(value))

    def differ(field, before, after):
        if before[0] != after[0]:
            note = " (a value changed that is not printed)" if before[1] == after[1] else ""
            changes.append((field, before[1], after[1] + note))

    def logon(task):
        kind = text_of(task.get("logon_type"))
        return pair(kind, LOGON_KINDS.get(kind.lower(), kind.lower()))

    differ("run as", pair(old.get("run_as_user")), pair(new.get("run_as_user")))
    differ("logon type", logon(old), logon(new))
    differ("run level", pair(old.get("run_level")), pair(new.get("run_level")))
    before, after = old.get("settings") or {}, new.get("settings") or {}
    for name in sorted(set(before) | set(after)):
        default = SETTING_DEFAULTS.get(name, "")
        differ("enabled" if name == "Enabled" else "setting " + name,
               pair(before.get(name) or default), pair(after.get(name) or default))
    for gone, added in unmatched([describe_trigger(t) for t in old.get("trigger_details") or []],
                                 [describe_trigger(t) for t in new.get("trigger_details") or []]):
        changes.append(("trigger", gone, added))
    was = [describe_action(a, show_args) for a in old.get("action_details") or []]
    now = [describe_action(a, show_args) for a in new.get("action_details") or []]
    for index in range(max(len(was), len(now))):
        differ("action %d" % (index + 1), was[index] if index < len(was) else ("", ""),
               now[index] if index < len(now) else ("", ""))
    runs_arcgis = any(ARCGIS_PYTHON.search("%s %s" % (a.get("executable", ""),
                                                      a.get("arguments", "")))
                      for a in (old.get("actions") or []) + (new.get("actions") or []))
    if runs_arcgis and set(c[0] for c in changes) & set(["run as", "logon type", "run level"]):
        changes.append(("arcpy-licence", "", LICENCE_NOTE))
    return changes


def diff_tasks(old_tasks, new_tasks, show_args=False):
    """One row per difference between two sets of parsed tasks, tasks in name order. Pure.

    A task is matched by its full name, ignoring case, as Windows does. A task in only one set
    is added or removed; a rename is both. Rows are {change, task, field, old, new}.
    """
    olds = dict((full_task_name(task).lower(), task) for task in old_tasks)
    news = dict((full_task_name(task).lower(), task) for task in new_tasks)
    rows = []
    for key in sorted(set(olds) | set(news)):
        if key not in news or key not in olds:
            rows.append({"change": "removed" if key not in news else "added",
                         "task": full_task_name(olds.get(key) or news[key]),
                         "field": "", "old": "", "new": ""})
            continue
        rows.extend({"change": "changed", "task": full_task_name(news[key]), "field": field,
                     "old": before, "new": after}
                    for field, before, after in compare_tasks(olds[key], news[key], show_args))
    return rows


# --------------------------------------------------------------------------
# the only impure functions: talk to Task Scheduler
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


def run_powershell(script, timeout, what, runner=subprocess.run, platform=os.name):
    """Run one read-only PowerShell script and return its rows. The only impure path.

    `runner` and `platform` exist for the self-test, which drives both failure branches
    without starting PowerShell.
    """
    if platform != "nt":
        raise RuntimeError("taskpulse reads Windows Task Scheduler; this is not Windows. "
                           "--lint FILE works on exported task XML anywhere.")
    command = ["powershell", "-NoProfile", "-NonInteractive",
               "-ExecutionPolicy", "Bypass", "-Command", script]
    try:
        result = runner(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    except subprocess.TimeoutExpired:
        # Its own message quotes the whole command line, which is the whole script.
        raise RuntimeError("%s timed out after %d second(s)" % (what, timeout))
    stdout = result.stdout.decode("utf-8", "replace")
    if result.returncode != 0:
        raise RuntimeError("%s failed: %s"
                           % (what, result.stderr.decode("utf-8", "replace").strip()))
    return rows_from_json(stdout)


def read_tasks(timeout=120):
    """Run the read-only PowerShell query and return raw task dicts."""
    return run_powershell(PS_QUERY, timeout, "Task Scheduler query")


def history_events(rows):
    """(events, log range) of one history read, or a RuntimeError when the read failed. Pure.

    The history script hands back the log's range row ({} when it has none) and then either its
    event rows or one {read_error, message} row with PowerShell's FullyQualifiedErrorId. Only
    NoMatchingEventsFound is an empty history: it is what an enabled log with no matching
    events gives. A disabled log (LogDisabled, which the script reports before it queries),
    access denied, a missing log or any other failure raises, because a history that could not
    be read is not a clean week.
    """
    log = ([row for row in rows if "log_newest_record_id" in row] or [{}])[0]
    events = [row for row in rows if "read_error" not in row and "log_newest_record_id" not in row]
    failed = [row for row in rows if "read_error" in row]
    if not failed:
        return events, log
    error_id = text_of(failed[0].get("read_error"))
    if error_id.split(",")[0] == "NoMatchingEventsFound":
        return [], log
    raise RuntimeError("the Task Scheduler Operational log could not be read (%s): %s"
                       % (error_id or "no error id", text_of(failed[0].get("message"))))


def log_range_gap(since, log, now):
    """Why the log itself leaves this read incomplete, or None. Raises past the log's end. Pure.

    `log` is the range row of history_events. A watermark above the newest record comes from a
    cleared log, a typo or another server: the read answers NoMatchingEventsFound on every run
    until the ids pass it, so it raises. A circular log that overwrote records past the
    watermark lost those runs unread. A cold start on a log whose oldest record is younger than
    7 days, because it was just enabled or rolled over, cannot fill the 7-day columns. Both are
    an incomplete report. A log with no record has no range, so it passes only a watermark of 0.
    """
    oldest = to_int(log.get("log_oldest_record_id"))
    newest = to_int(log.get("log_newest_record_id"))
    if since is not None:
        if since > (newest or 0):
            raise RuntimeError("--since-record-id %d is above the newest record of the log (%s), "
                               "so the log was cleared or the id came from another log; pass "
                               "--since-record-id 0 to read the whole log again"
                               % (since, "none" if newest is None else newest))
        if oldest and oldest > since + 1:
            return ("the log no longer holds records %d to %d past the watermark; they were "
                    "overwritten before this run read them, so their runs are missing from "
                    "this report" % (since + 1, oldest - 1))
        return None
    begins = parse_dt(log.get("log_oldest_time_utc"))
    if begins is None or begins > now - timedelta(days=7):
        return ("the log holds no record older than %s, so the 7-day columns miss any run "
                "before it and this report is incomplete"
                % (begins.strftime("%Y-%m-%dT%H:%MZ") if begins else "now"))
    return None


def history_query(days_back, min_record_id):
    """The XPath filter and the read order for one history read. Pure; both take ints only.

    The Operational log is busy: on one server it carried roughly a thousand events a day, so
    the HISTORY_MAX_EVENTS cap holds about five days. Which end of the match the cap keeps
    decides what is lost.

    Past a watermark the read is oldest first. Newest first, the cap keeps the newest events,
    and the next watermark passes every older record unread (measured), so a backlog larger
    than the cap would be skipped for good.

    A watermark of 0, which a read of an empty log prints, is a watermark too: the whole log, oldest
    first, so following the printed advice never skips a backlog. With no watermark (None)
    there is no backlog yet, so the cold start reads newest first inside the DAYS window.
    Oldest first, a capped cold read of a synthetic 30-day log of 17400 events held not one
    run of the current week, so every 7-day column read 0.
    """
    ids = " or ".join("EventID=%d" % event_id for event_id in HISTORY_EVENT_IDS)
    xpath = "*[System[(EventRecordID > %d) and (%s)" % (int(min_record_id or 0), ids)
    if min_record_id is not None:
        return xpath + "]]", True
    window_ms = int(days_back) * 86400000
    return xpath + " and TimeCreated[timediff(@SystemTime) <= %d]]]" % window_ms, False


def read_run_events(days_back=30, min_record_id=None, timeout=120):
    """Return (raw 100/102/200/201 events, log range) from the Task Scheduler Operational log.

    Oldest first past a watermark, newest first on a cold start (see history_query). It asks
    for one event more than HISTORY_MAX_EVENTS, so the caller can tell a read that filled the
    cap from one that ended there. An enabled log with no matching events is an empty
    history. A disabled log, which is the Windows default, and any other failed read raise
    (see history_events). The substituted values are built from ints, never text, so nothing a
    caller types can reach the script as PowerShell.
    """
    xpath, oldest = history_query(days_back, min_record_id)
    script = (PS_HISTORY
              .replace("__XPATH__", xpath)
              .replace("__MAX_EVENTS__", str(int(HISTORY_MAX_EVENTS) + 1))
              .replace("__OLDEST__", "$true" if oldest else "$false"))
    return history_events(run_powershell(script, timeout, "Task Scheduler history query"))


# --------------------------------------------------------------------------
# output
# --------------------------------------------------------------------------

COLUMNS = ["status", "task", "schedule", "last_result_text", "reason"]
TABLE_HEADER = ["STATUS", "TASK", "SCHEDULE", "LAST RESULT", "WHY"]
LINT_FIELDS = ["severity", "task", "check", "detail"]


def render_table(rows, columns=COLUMNS, header=TABLE_HEADER, cap=60):
    table = [header] + [[str(row.get(key, "")) for key in columns] for row in rows]
    widths = [min(cap, max(len(line[i]) for line in table)) for i in range(len(header))]
    out = []
    for index, line in enumerate(table):
        cells = [cell[:widths[i]].ljust(widths[i]) for i, cell in enumerate(line)]
        out.append("  ".join(cells).rstrip())
        if index == 0:
            out.append("  ".join("-" * width for width in widths))
    return "\n".join(out)


def write_output(rows, fmt, stream, lint=False, diff=False):
    """Write health rows, lint findings when `lint`, or diff rows when `diff`, in `fmt`."""
    if fmt == "json":
        json.dump(rows, stream, indent=2, sort_keys=True)
        stream.write("\n")
    elif fmt == "csv":
        fields = DIFF_FIELDS if diff else LINT_FIELDS if lint else list(evaluate({}).keys())
        writer = csv.DictWriter(stream, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        for row in rows:
            # A task's author, account and command are anybody's text. A spreadsheet runs a
            # cell that starts with = + - @ as a formula, so a quote makes it text again.
            writer.writerow(dict((key, "'" + value if isinstance(value, str)
                                  and value[:1] in ("=", "+", "-", "@", "\t", "\r") else value)
                                 for key, value in row.items()))
    elif diff:
        stream.write(render_table(rows, DIFF_FIELDS, [f.upper() for f in DIFF_FIELDS], 240)
                     + "\n" if rows else "No differences.\n")
    elif lint:
        # The detail is the point of a finding, so its column is allowed to run long.
        stream.write(render_table(rows, LINT_FIELDS, [f.upper() for f in LINT_FIELDS], 240)
                     + "\n" if rows else "No findings.\n")
    else:
        stream.write(render_table(rows) + "\n" if rows else "No tasks need attention.\n")


# --------------------------------------------------------------------------
# self-test - offline, no network, no credentials, no Task Scheduler
# --------------------------------------------------------------------------

def harness(stream):
    """check(), raises() and finish() for self_test, writing PASS/FAIL lines to `stream`."""
    passed = [0]
    failed = []

    def check(cond, label):
        if cond:
            passed[0] += 1
            stream.write("PASS  %s\n" % label)
        else:
            failed.append(label)
            stream.write("FAIL  %s\n" % label)

    def raises(fn, label, expected=ValueError):
        try:
            fn()
        except expected:
            check(True, label)
        except Exception as exc:
            check(False, "%s (wrong exception %r)" % (label, exc))
        else:
            check(False, "%s (no error raised)" % label)

    def finish():
        stream.write("-" * 68 + "\n")
        total = passed[0] + len(failed)
        if failed:
            stream.write("%d assertions, %d failed\n" % (total, len(failed)))
            for label in failed:
                stream.write("  FAILED: %s\n" % label)
            return 1
        stream.write("%d assertions, 0 failed\n" % total)
        return 0

    return check, raises, finish


def task_xml(uri="\\Jobs\\refresh", logon="Password", user="EXAMPLE\\svc-etl",
             trigger="<CalendarTrigger><ScheduleByDay><DaysInterval>1</DaysInterval>"
                     "</ScheduleByDay></CalendarTrigger>",
             command="C:\\Python39\\python.exe", arguments="C:\\jobs\\refresh.py",
             start="C:\\jobs", enabled="", namespace=True, limit="", settings=""):
    """A synthetic exported task for the self-test. Every account and share is made up.

    Like a real export, an enabled task has no <Enabled> element: Windows writes one only as
    <Enabled>false</Enabled>. It leaves out an <ExecutionTimeLimit> that equals the 72-hour
    default (measured on a development machine), so `limit` is empty here unless a case needs one.
    `settings` adds more Settings elements.
    """
    return (
        '<Task version="1.2"%s><RegistrationInfo>%s</RegistrationInfo>'
        '<Principals><Principal id="Author"><UserId>%s</UserId>%s</Principal></Principals>'
        '<Settings>%s</Settings><Triggers>%s</Triggers>'
        '<Actions Context="Author"><Exec><Command>%s</Command>%s%s</Exec></Actions></Task>'
        % (' xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"' if namespace else "",
           "<URI>%s</URI>" % uri if uri else "", user,
           "<LogonType>%s</LogonType>" % logon if logon else "",
           ("<Enabled>%s</Enabled>" % enabled if enabled else "")
           + ("<ExecutionTimeLimit>%s</ExecutionTimeLimit>" % limit if limit else "") + settings,
           trigger, command,
           "<Arguments>%s</Arguments>" % arguments if arguments else "",
           "<WorkingDirectory>%s</WorkingDirectory>" % start if start else ""))


def self_test():
    check, raises, finish = harness(sys.stdout)
    print("taskpulse self-test: offline, no Task Scheduler, no network, no credentials")
    print("-" * 68)

    windows = FORMAT_ERROR is not None
    now = datetime(2026, 7, 28, 12, 0, tzinfo=timezone.utc)

    # --- the harness itself: a failing check must fail the run ---
    probe_out = io.StringIO()
    p_check, p_raises, p_finish = harness(probe_out)
    p_check(False, "a false condition")
    p_raises(lambda: None, "nothing raised")
    p_raises(lambda: int([]), "the wrong exception")
    p_raises(lambda: int("x"), "the expected exception")
    check(p_finish() == 1 and "4 assertions, 3 failed" in probe_out.getvalue(),
          "the harness counts a failed check, a missing raise and a wrong exception")

    # --- result codes arrive both signed and unsigned; both must normalise ---
    check(to_unsigned(-2147024894) == 0x80070002, "signed form normalises to unsigned")
    check(to_unsigned(2147942402) == 0x80070002, "unsigned form passes through")
    check(to_unsigned(267011) == TASK_NOT_YET_RUN, "267011 is SCHED_S_TASK_HAS_NOT_RUN")
    check(to_unsigned(None) is None, "missing code stays None")
    check(to_unsigned("") is None, "empty code stays None")
    check(to_unsigned("267011") == 267011, "numeric string is accepted")
    check(to_unsigned("nonsense") is None, "junk code does not raise")
    check(describe_result(None) == "no result recorded", "none result is reported, not guessed")
    check(describe_result(0) == "success", "0 is success without touching the message table")
    check(describe_result(-2147024894) == describe_result(0x80070002),
          "signed and unsigned decode identically")

    # --- the decode logic, with a stub message table so it runs on every host ---
    asked = []

    def table(code):
        asked.append(code)
        return {5: "Access is denied.  ", 7: "<undefined>",
                8: "The system cannot find message text for message number 0x8."}.get(code, "")

    def broken_table(code):
        raise OSError("no message table")

    check(describe_result(0x80070005, table) == "Access is denied." and asked[-1] == 5,
          "0x8007xxxx is unwrapped to win32 xxxx before the lookup, and the text is stripped")
    check(describe_result(7, table) == "unmapped result 0x00000007",
          "a placeholder message in angle brackets reports as unmapped")
    check(describe_result(8, table) == "unmapped result 0x00000008",
          "the 'cannot find message text' placeholder reports as unmapped")
    check(describe_result(5, broken_table) == "unmapped result 0x00000005",
          "a message table that raises reports as unmapped, not a crash")
    check(describe_result(5, None) == "unmapped result 0x00000005",
          "with no message table at all every code reports as unmapped")

    # Real codes observed on a live box. The OS message table is the source of truth; a
    # hand-written table gets 0x8007052E and 0x8007007A wrong. Off Windows there is no
    # table, so the same assertions check the unmapped fallback and the count stays equal.
    def os_says(code, words):
        text = describe_result(code).lower()
        return (words in text) if windows else text.startswith("unmapped result 0x")

    check(os_says(0x80070002, "cannot find the file"),
          "0x80070002 unwraps to win32 2 (file not found)")
    check(os_says(0x8007052E, "user name or password"),
          "0x8007052E is a bad service-account password")
    check(os_says(0x8007007A, "data area"), "0x8007007A is not 'access denied'")
    check(os_says(267011, "has not yet run"), "scheduler status codes decode too")
    check(os_says(TASK_RUNNING, "currently running"), "task_running decodes")
    check(describe_result(0x40010004).startswith("unmapped result 0x"),
          "codes with no message text report as unmapped")
    check(describe_result(0) == "success",
          "formatError(0) statefulness cannot leak after a failed lookup")
    check((describe_result(0x80070002) == describe_result(2)) if windows
          else describe_result(2) == "unmapped result 0x00000002",
          "0x8007xxxx and bare xxxx decode to the same text")

    # --- trigger buckets ---
    check(schedule_bucket("Daily") == "Daily", "single daily trigger")
    check(schedule_bucket("MSFT_TaskDailyTrigger") == "Daily", "raw CIM class name maps")
    check(schedule_bucket("Logon") == "Logon", "logon bucket")
    check(schedule_bucket("") == "No Triggers", "no triggers")
    check(schedule_bucket("Daily | Weekly") == "Daily + Weekly", "two buckets combine sorted")
    check(schedule_bucket("Daily | Weekly | Logon") == "Multiple / Other",
          "three or more collapse")
    check(schedule_bucket("Boot") == "Startup", "boot maps to startup")
    check(expects_next_run("Daily") is True, "a daily task must have a next run")
    check(expects_next_run("Logon") is False, "a logon task legitimately has none")
    check(expects_next_run("Event") is False, "an event task legitimately has none")
    check(expects_next_run("") is False, "an untriggered task legitimately has none")
    check(expects_next_run("Daily | Logon") is True,
          "the Daily half of a mixed task still owes a next run")
    check(expects_next_run("Registration | Logon | Event") is False,
          "3+ triggers keep their exemption; the display label collapses, the check must not")
    check(schedule_bucket("Registration | Logon | Event") == "Multiple / Other",
          "the display label still collapses at 3+")
    check(expects_next_run("MSFT_TaskLogonTrigger | MSFT_TaskEventTrigger "
                           "| MSFT_TaskRegistrationTrigger") is False,
          "raw CIM class names normalise before the exemption check")
    check(trigger_tokens("Daily | Daily | MSFT_TaskDailyTrigger") == {"Daily"},
          "duplicate and raw spellings of one trigger collapse to one token")

    # --- wrapper unwrapping: report the script, not the interpreter ---
    check(classify_command(r"C:\Python313\python.exe", r"C:\jobs\etl.py --full")
          == (r"C:\jobs\etl.py", "PythonScript"), "python wrapper unwraps to the .py")
    check(classify_command(r"C:\Python313\python.exe", r'"C:\my jobs\etl.py"')
          == (r"C:\my jobs\etl.py", "PythonScript"), "quoted script path is unquoted")
    check(classify_command("python.exe", '-c "import x"')[1] == "PythonInline",
          "python -c has no script file and is labelled inline")
    check(classify_command("python.exe", "-m pip list") == ("pip", "PythonModule"),
          "python -m reports the module")
    check(classify_command("python.exe", "-m") == ("python.exe", "Python"),
          "a dangling -m with no module falls back to the interpreter")
    check(classify_command("powershell.exe", r'-NoProfile -File "C:\jobs\sync.ps1"')
          == (r"C:\jobs\sync.ps1", "PowerShellScript"), "-File wins over positional scan")
    check(classify_command("powershell.exe", r"C:\jobs\sync.ps1")[1] == "PowerShellScript",
          "positional .ps1 is found without -File")
    check(classify_command("powershell.exe", "-Command Get-Date")[1] == "PowerShellInline",
          "powershell -Command is inline, not a script")
    check(classify_command("pwsh.exe", "-NoLogo") == ("pwsh.exe", "PowerShell"),
          "powershell with neither a script nor a command is the bare shell")
    check(classify_command(r"C:\ArcGIS\Pro\bin\Python\envs\arcgispro-py3\python",
                           r"C:\jobs\etl.py") == (r"C:\jobs\etl.py", "PythonScript"),
          "an interpreter named with no .exe, as task scheduler accepts it, still unwraps"
          "  <-- pinned defect")
    check(classify_command("cmd.exe", r"/c C:\jobs\nightly.bat")
          == (r"C:\jobs\nightly.bat", "BatchScript"), "cmd /c switch is skipped")
    check(classify_command("cmd.exe", r'/c "set PGPASSWORD=Hunter2Zq&& C:\jobs\refresh.bat"')
          == (r"C:\jobs\refresh.bat", "BatchScript")
          and classify_command("powershell.exe", "-Command \"$env:API_TOKEN='Hunter2Zq';"
                               r' & C:\jobs\sync.ps1"')
          == (r"C:\jobs\sync.ps1", "PowerShellScript"),
          "a secret set in a quoted cmd /c or -Command body never reaches the target"
          "  <-- pinned defect")
    check(classify_command("cmd.exe", r'/c "C:\my jobs\refresh.bat"')
          == (r"C:\my jobs\refresh.bat", "BatchScript"),
          "a quoted body that is one rooted path with a space stays whole")
    check(classify_command("cmd.exe", "/c exit 0") == ("cmd.exe", "CommandShell"),
          "cmd with no batch file is the command shell itself")
    check(classify_command("cscript.exe", r"//B C:\jobs\legacy.vbs")
          == (r"C:\jobs\legacy.vbs", "VBScript"), "cscript switch is skipped")
    check(classify_command("wscript.exe", r"C:\jobs\legacy.js")
          == (r"C:\jobs\legacy.js", "JavaScript"), "wscript runs a .js as JavaScript")
    check(classify_command("wscript.exe", "//Nologo") == ("wscript.exe", "ScriptHost"),
          "a script host with no script is the host itself")
    check(classify_command(r"C:\tools\backup.exe", "")
          == (r"C:\tools\backup.exe", "Executable"), "a direct exe is its own target")
    check(classify_command(r"C:\jobs\nightly.cmd", "") == (r"C:\jobs\nightly.cmd", "BatchScript"),
          "a batch file run directly is classified by its extension")
    check(classify_command("", "") == ("", ""), "an actionless task classifies empty")
    check(split_args('"unterminated') == ['"unterminated"'],
          "an unbalanced quote runs to the end of the line, as windows reads it, never raises")
    check(split_args(r'--password Hunter2 --out "reports\daily.csv')
          == ["--password", "Hunter2", "--out", r'"reports\daily.csv"'],
          "an unclosed trailing quote still splits into words, never one whole-line token  "
          "<-- pinned defect")
    check(split_args("--log 'logs\\a \"b") == ["--log", "'logs\\a \"b'"],
          "an unclosed single quote is closed too, after a double quote fails")
    for exe, args in ((r"C:\tools\sync.exe", r'--password Hunter2 --out "reports\daily.csv'),
                      (r"C:\Python39\python.exe",
                       r'C:\jobs\etl.py --token Hunter2 --log "logs\etl.log')):
        said = lint_task({"task_name": "t", "task_path": "\\Jobs\\", "logon_type": "Password",
                          "run_as_user": r"EXAMPLE\svc", "trigger_types": "Daily",
                          "actions": [{"executable": exe, "arguments": args,
                                       "working_directory": ""}]})
        check("Hunter2" not in repr(said) and "Hunter2" not in repr(classify_command(exe, args))
              and any(row["check"] == "start-in-missing" and row["severity"] == "Error"
                      for row in said),
              "an unclosed quote never prints the secret and keeps the start-in-missing error "
              "(%s)  <-- pinned defect" % exe.split("\\")[-1])

    # --- health: the verdict Windows does not compute ---
    base = {"enabled": True, "state": "Ready", "trigger_types": "Daily",
            "last_task_result": 0, "number_of_missed_runs": 0,
            "next_run_time": "2026-07-29T02:00:00+00:00"}

    def variant(**kwargs):
        row = dict(base)
        row.update(kwargs)
        return row

    check(health_status(base, now) == "Success", "green task is Success")
    check(health_status(variant(enabled=False), now) == "Disabled", "disabled short-circuits")
    check(health_status(variant(state="Running", last_task_result=None), now) == "Running",
          "running state wins over a missing result")
    check(health_status(variant(last_task_result=TASK_QUEUED), now) == "Running",
          "queued counts as running")
    check(health_status(variant(last_task_result=-2147024894), now) == "Error",
          "a signed failure HRESULT is an Error")
    check(health_status(variant(last_task_result=TASK_NOT_YET_RUN), now) == "NotYetRun",
          "never-run is not a failure")
    check(health_status(variant(last_task_result=None), now) == "NotYetRun",
          "no result recorded is not a failure")
    check(health_status(variant(number_of_missed_runs=3), now) == "Warning",
          "missed runs are a Warning even with result 0")
    check(health_status(variant(number_of_missed_runs=1), now) == "Warning",
          "one missed run is already a Warning")
    check(health_status(variant(next_run_time="2026-07-27T02:00:00+00:00"), now) == "Warning",
          "next run in the past is overdue")
    check(health_status(variant(next_run_time="2026-07-27T02:00:00+00:00", state="Running"),
                        now) == "Running", "a long-running task is not overdue")
    check(health_status(variant(next_run_time=None), now) == "Warning",
          "a daily task with no next run is broken")
    check(health_status(variant(next_run_time=None, trigger_types="Logon"), now) == "Success",
          "a logon task with no next run is NOT a fault")
    check(health_status(variant(next_run_time=None, trigger_types="Event"), now) == "Success",
          "an event task with no next run is NOT a fault")
    check(health_status(variant(last_task_result=TASK_NO_VALID_TRIGGERS), now) == "Warning",
          "no-valid-triggers is a Warning, not an Error")
    check(health_status(variant(last_task_result=TASK_TERMINATED), now) == "Warning",
          "user-terminated is a Warning")
    check(health_status(variant(last_task_result=TASK_NO_MORE_RUNS, next_run_time=None,
                                trigger_types="One Time"), now) == "Success",
          "a spent one-time task is fine")
    spent_daily = variant(last_task_result=TASK_NO_MORE_RUNS, next_run_time=None,
                          trigger_types="Daily")
    check(health_status(spent_daily, now) == "Success",
          "a Daily task past its EndBoundary reports NO_MORE_RUNS, which is not a fault")
    check("no next run time" not in attention_reason(spent_daily, "Success", now),
          "the reason must not contradict the verdict on a spent recurring task")
    all_exempt = variant(next_run_time=None,
                         trigger_types="Registration | Logon | Event")
    check(health_status(all_exempt, now) == "Success",
          "3+ exempt triggers with no next run is not a fault (live \\Microsoft\\...\\UserTask)")
    check(health_status(variant(next_run_time=None, trigger_types="Daily | Logon"), now)
          == "Warning", "a Daily trigger in the mix still demands a next run")
    check(health_status(variant(last_task_result=0x800705B4), now) == "Error",
          "a timeout HRESULT is an Error")
    check(health_status(base, None) == "Success",
          "overdue detection is skipped when no clock is supplied")

    # --- timestamps ---
    check(parse_dt("2026-07-28T12:00:00Z") == now, "z suffix parses as UTC")
    check(parse_dt("2026-07-28T12:00:00") == now, "naive timestamps are assumed UTC")
    check(parse_dt("") is None and parse_dt(None) is None, "blank timestamps are None")
    check(parse_dt("not a date") is None, "unparseable timestamps do not raise")
    check(parse_dt("2026-07-28T12:00:00.0000000Z") == now,
          "powerShell's 7-digit fractional seconds parse (fromisoformat takes 6 pre-3.11)")
    check(parse_dt("2026-07-28T07:00:00-05:00") == now, "offsets convert to UTC")
    check(health_status(variant(next_run_time="2026-07-29T02:00:00.0000000Z"), now)
          == "Success", "a real PowerShell timestamp is not mistaken for a missing next run")

    # --- row assembly and filtering ---
    row = evaluate(dict(base, task_path="\\Jobs\\", task_name="etl",
                        executable="python.exe", arguments=r"C:\jobs\etl.py"), now)
    check(row["task"] == r"\Jobs\etl", "task path and name join")
    check(row["target"] == r"C:\jobs\etl.py" and row["target_kind"] == "PythonScript",
          "row carries the unwrapped target")
    check(row["status"] == "Success" and row["missed_runs"] == 0, "row carries the verdict")
    check(evaluate(dict(base, task_path="", task_name="orphan"))["task"] == "\\orphan",
          "an empty task path still yields a rooted name")
    check(set(COLUMNS).issubset(evaluate({}).keys()), "every rendered column exists on a row")
    check(evaluate({})["status"] in ("NotYetRun", "Warning"), "an empty dict does not crash")
    check(is_microsoft_task({"task_path": "\\Microsoft\\Windows\\Defrag\\"}) is True,
          "microsoft tasks are detected for exclusion")
    check(is_microsoft_task({"task_path": "\\Jobs\\"}) is False, "your own tasks are kept")

    # --- the PowerShell bridge always yields a list, never None ---
    check(rows_from_json("null") == [], "convertTo-Json emits 'null' for zero rows, not ''")
    check(rows_from_json("") == [] and rows_from_json("   ") == [], "empty output is no rows")
    check(rows_from_json('{"task_name": "solo"}') == [{"task_name": "solo"}],
          "convertTo-Json unwraps a single row to a bare object")
    check(rows_from_json('[{"task_name": "a"}, {"task_name": "b"}]')
          == [{"task_name": "a"}, {"task_name": "b"}], "many rows pass through")
    check(all(isinstance(rows_from_json(text), list) for text in ("null", "", "{}", "[]")),
          "read_tasks' caller can always iterate the result")

    class Finished(object):
        def __init__(self, returncode, stdout, stderr):
            self.returncode, self.stdout, self.stderr = returncode, stdout, stderr

    launched = []

    def fake_run(command, **kwargs):
        launched.append((command, kwargs))
        return Finished(0, b'{"task_name": "solo"}', b"")

    check(run_powershell("Get-Date", 9, "probe", fake_run, "nt") == [{"task_name": "solo"}],
          "the bridge decodes PowerShell's stdout into rows")
    check(launched[0][0][:3] == ["powershell", "-NoProfile", "-NonInteractive"]
          and launched[0][0][-1] == "Get-Date" and launched[0][1]["timeout"] == 9,
          "the bridge runs a non-interactive PowerShell with no profile and the caller's timeout")
    raises(lambda: run_powershell("x", 9, "probe",
                                  lambda command, **kw: Finished(1, b"", b"denied"), "nt"),
           "a non-zero PowerShell exit raises with its stderr", RuntimeError)

    def slow_run(command, **kwargs):
        raise subprocess.TimeoutExpired(command, kwargs["timeout"])

    said = ""
    try:
        run_powershell("$Secretish = 1", 9, "probe", slow_run, "nt")
    except RuntimeError as error:
        said = str(error)
    check(said == "probe timed out after 9 second(s)",
          "a timeout names the query and the limit, not the whole script")
    raises(lambda: run_powershell("x", 9, "probe", fake_run, "posix"),
           "off Windows the live query refuses before starting anything", RuntimeError)
    check(len(launched) == 1, "the off-Windows refusal never reached the runner")

    module = globals()
    scripts = []
    real_bridge = run_powershell
    try:
        module["run_powershell"] = lambda script, timeout, what: scripts.append(script) or []
        check(read_tasks(5) == [] and "logon_type" in scripts[0]
              and "working_directory" in scripts[0],
              "the live query asks for the logon type and every action's Start In")
        check("catch { }" not in scripts[0] and 'catch { $failed += "run details" }' in
              scripts[0] and 'read_errors           = $failed -join ","' in scripts[0],
              "the live query names each part it could not read, never swallows the error"
              "  <-- pinned defect")
        check("Where-Object { $_.Enabled -ne $false }" in scripts[0],
              "the live query leaves out a disabled trigger, as the XML reader does"
              "  <-- pinned defect")
        read_run_events(3, 99)
        check("(EventRecordID > 99)" in scripts[1] and "$Oldest = $true" in scripts[1]
              and "$MaxEvents = %d" % (HISTORY_MAX_EVENTS + 1) in scripts[1]
              and "__" not in scripts[1], "the history query receives integers for every slot, "
              "and one event more than the cap, so a capped read can be told apart")
        read_run_events(3)
        check("$Oldest = $false" in scripts[2] and "<= 259200000]" in scripts[2],
              "a cold start reads newest first inside the DAYS window")
        raises(lambda: read_run_events("3; Remove-Item C:\\"),
               "text that is not an integer never reaches the history script")
        raises(lambda: read_run_events(3, "1) or (1=1"),
               "a watermark that is not an integer never reaches the XPath")
        check("-MaxEvents $MaxEvents -Oldest:$Oldest" in scripts[1]
              and "-FilterXPath $XPath" in scripts[1],
              "the read takes its order and filter from history_query")
        # The script's comments name the flags it must not use; judge its code lines only.
        history_code = "\n".join(line for line in scripts[1].splitlines()
                                  if not line.lstrip().startswith("#"))
        check("SilentlyContinue" not in history_code and "-ErrorAction Stop" in history_code,
              "a failed history read is never silenced into an empty history  <-- pinned defect")
        check(history_code.lstrip().startswith('$ErrorActionPreference = "Stop"'),
              "the history script stops on any error, so a cast that fails in the event loop "
              "stops the read and never drops that event")
        # The Python half of the error rule is only as good as the script's catch: one that
        # printed nothing, or an empty list, would turn access denied into a clean week.
        caught = re.search(r"-ErrorAction Stop\)\n\} catch \{\n(.*?)\n\}\n", history_code,
                           re.DOTALL)
        check(caught is not None and [line.strip() for line in caught.group(1).splitlines()]
              == ["$out += [pscustomobject]@{ read_error = [string]$_.FullyQualifiedErrorId; "
                  "message = [string]$_.Exception.Message }",
                  "ConvertTo-Json -InputObject $out -Compress", "exit 0"],
              "the history script's catch hands every failed read to python with its error id,"
              " never an empty list  <-- pinned defect")
        ranged = history_code.find("$out += $range")
        check(history_code.find("$out = @()") < history_code.find("-MaxEvents 1 -Oldest")
              < ranged < history_code.find("-FilterXPath $XPath")
              and "-InputObject ($out + $rows)" in history_code,
              "the history script sends the log's oldest and newest record ahead of the events, "
              "and ahead of a failed read's error  <-- pinned defect")
        probe = history_code.find("$info = Get-WinEvent -ListLog $LogName -ErrorAction Stop")
        check(-1 < probe < history_code.find("if (-not $info.IsEnabled)")
              < history_code.find("-FilterXPath $XPath")
              and -1 < probe < history_code.find("read_error = 'LogDisabled'")
              < history_code.find("-ErrorAction Stop)\n} catch {"),
              "the history script asks whether the log is enabled before it queries, because a "
              "disabled log answers NoMatchingEventsFound  <-- pinned defect")
        check("-FilterHashtable" not in history_code and "-FilterXPath" in history_code,
              "the history read never uses -FilterHashtable, which reports access denied as no "
              "events  <-- pinned defect")
        module["run_powershell"] = lambda script, timeout, what: [
            {"read_error": "System.UnauthorizedAccessException,Microsoft.PowerShell.Commands."
                           "GetWinEventCommand", "message": "Attempted to perform an "
                                                            "unauthorized operation."}]
        raises(lambda: read_run_events(3), "the history reader applies the error rule to what "
               "the bridge returns", RuntimeError)
    finally:
        module["run_powershell"] = real_bridge

    # --- a history read that failed is a failure, never an empty week (--history) ---
    def read_error(error_id, message="x"):
        return [{"read_error": error_id, "message": message}]

    check(history_events(read_error(
        "NoMatchingEventsFound,Microsoft.PowerShell.Commands.GetWinEventCommand")) == ([], {}),
        "only NoMatchingEventsFound, what an enabled log with no matching events gives, is an "
        "empty history")
    raises(lambda: history_events(read_error("LogDisabled", "the log is disabled")),
           "a disabled log raises, never an empty history: off is the windows default  "
           "<-- pinned defect", RuntimeError)
    raises(lambda: history_events(read_error(
        "System.UnauthorizedAccessException,Microsoft.PowerShell.Commands.GetWinEventCommand")),
        "an access-denied read raises, never an empty history  <-- pinned defect", RuntimeError)
    raises(lambda: history_events(read_error(
        "NoMatchingLogsFound,Microsoft.PowerShell.Commands.GetWinEventCommand")),
        "a missing log raises too: NoMatchingLogsFound is not NoMatchingEventsFound",
        RuntimeError)
    said = ""
    try:
        history_events(read_error(None, "boom"))
    except RuntimeError as error:
        said = str(error)
    check("no error id" in said and "boom" in said,
          "a read error with no id still raises and keeps the message")
    events_in = [{"event_id": 100, "event_record_id": 7}]
    span = {"log_oldest_record_id": 5, "log_newest_record_id": 9, "log_oldest_time_utc": None}
    check(history_events(events_in) == (events_in, {})
          and history_events([span] + events_in) == (events_in, span)
          and history_events([span] + read_error("NoMatchingEventsFound")) == ([], span),
          "event rows pass through unchanged, and the log's range row is split off")
    raises(lambda: history_events([span] + read_error(
        "System.UnauthorizedAccessException,Microsoft.PowerShell.Commands.GetWinEventCommand")),
        "access denied after a good range probe, the shape the script sends, still raises  "
        "<-- pinned defect", RuntimeError)

    # --- a watermark or a cold start the log itself cannot answer (--history) ---
    def span_of(oldest, newest, days_old=30):
        begins = None if days_old is None else (now - timedelta(days=days_old)).isoformat()
        return {"log_oldest_record_id": oldest, "log_newest_record_id": newest,
                "log_oldest_time_utc": begins}

    said = ""
    try:
        log_range_gap(2000000, span_of(1, 9652), now)
    except RuntimeError as error:
        said = str(error)
    check("2000000 is above the newest record of the log (9652)" in said
          and "--since-record-id 0" in said,
          "a watermark above the log's newest record, as after a clear, raises, never an empty "
          "history  <-- pinned defect")
    raises(lambda: log_range_gap(5, span_of(None, None, None), now),
           "a watermark into a log with no record at all raises too", RuntimeError)
    raises(lambda: log_range_gap(1, span_of(None, None, None), now),
           "a watermark of 1 on an empty log raises: only 0 is a complete read of nothing",
           RuntimeError)
    check(log_range_gap(0, span_of(None, None, None), now) is None
          and log_range_gap(9652, span_of(1, 9652), now) is None
          and log_range_gap(100, span_of(101, 9652), now) is None,
          "a watermark of 0 on an empty log, at the newest record, or just below the oldest is "
          "complete")
    raises(lambda: log_range_gap(9653, span_of(1, 9652), now),
           "a watermark one past the newest record raises, so no record is skipped silently",
           RuntimeError)
    gap = log_range_gap(100, span_of(9001, 9652), now) or ""
    check("records 101 to 9000" in gap and "overwritten" in gap,
          "records past the watermark that the log overwrote make the read incomplete"
          "  <-- pinned defect")
    check("records 101 to 101" in (log_range_gap(100, span_of(102, 9652), now) or ""),
          "one overwritten record past the watermark makes the read incomplete too")
    gap = log_range_gap(None, span_of(1, 30, days_old=4.0 / 24), now) or ""
    check("no record older than" in gap and "incomplete" in gap,
          "a cold start on a log younger than 7 days is incomplete  <-- pinned defect")
    check("older than now" in (log_range_gap(None, span_of(None, None, None), now) or "")
          and log_range_gap(None, span_of(1, 30, days_old=7), now) is None,
          "a cold start on an empty log is incomplete, and on a log 7 days old is complete")
    check("incomplete" in (log_range_gap(None, span_of(1, 30, days_old=6.5), now) or ""),
          "a cold start on a log that holds 6.5 days, not 7, is incomplete too")

    # --- which end of the log the event cap keeps (--history) ---
    ids = ("(EventID=100 or EventID=101 or EventID=102 or EventID=103 or EventID=111 or "
           "EventID=153 or EventID=200 or EventID=201 or EventID=203 or EventID=322 or "
           "EventID=329 or EventID=330 or EventID=332)")
    check(history_query(30, 1) == ("*[System[(EventRecordID > 1) and %s]]" % ids, True),
          "past a watermark the read is oldest first, so a backlog is never skipped, and "
          "takes no time window  <-- pinned defect")
    check(history_query(7, None) == ("*[System[(EventRecordID > 0) and %s and TimeCreated["
                                     "timediff(@SystemTime) <= 604800000]]]" % ids, False),
          "a cold start reads the newest events of the DAYS window, so a capped read keeps "
          "the current week  <-- pinned defect")
    check(history_query(7, 0) == ("*[System[(EventRecordID > 0) and %s]]" % ids, True),
          "a watermark of 0, as an empty log prints, reads the whole log oldest first, so "
          "passing it back never skips a backlog  <-- pinned defect")

    # --- a part of a task the live read could not get (PS_QUERY read_errors) ---
    unread = variant(read_errors="run details", last_task_result=None, next_run_time=None,
                     number_of_missed_runs=None, trigger_types="Logon")
    check(health_status(unread, now) == "Warning"
          and "could not get its run details" in attention_reason(unread, "Warning", now),
          "a task whose run details could not be read is a Warning, not a task that has not "
          "run yet  <-- pinned defect")
    check(read_failures({"read_errors": "actions, actions,triggers,"}) == ["actions", "triggers"]
          and read_failures({}) == [] and read_failures({"read_errors": None}) == [],
          "read failures are listed once each, in order, and an XML task has none")
    check(health_status(variant(read_errors=""), now) == "Success",
          "a live task read in full is judged as before")

    # --- reasons name the actual problem ---
    check("2 missed run(s)" in attention_reason(variant(number_of_missed_runs=2), "Warning",
                                                now), "reason names the missed run count")
    check("overdue" in attention_reason(variant(next_run_time="2026-07-27T12:00:00+00:00"),
                                        "Warning", now), "reason names overdue")
    check("24.0 hour(s)" in attention_reason(variant(next_run_time="2026-07-27T12:00:00+00:00"),
                                             "Warning", now), "overdue is quantified in hours")
    check("no next run time" in attention_reason(variant(next_run_time=None), "Warning", now),
          "reason names the missing next run")
    check(attention_reason(variant(enabled=False), "Disabled", now) == "task is disabled",
          "disabled reason is plain")
    check(attention_reason(variant(state="Running"), "Running", now)
          == "task is currently running", "running reason is plain")
    check(attention_reason(variant(last_task_result=None), "NotYetRun", now)
          == "task has not yet run", "a task that never ran says so")
    check(attention_reason(variant(last_task_result=None, number_of_missed_runs=1), "NotYetRun",
                           now) == "1 missed run(s); no result recorded",
          "a never-run task with a real reason gives it, not 'has not yet run'")
    check(attention_reason({}, "Unknown") == "no result recorded",
          "a task with nothing to say still gets the decoded result")

    # --- run history: Operational-log events grouped into runs (--history) ---
    inventory = [dict(base, task_path="\\Jobs\\", task_name="etl")]

    def event(event_id, hour, instance="i1", task=r"\Jobs\etl", record_id=1, result_code=None):
        return {"event_id": event_id, "instance_id": instance, "task_full_name": task,
                "event_time_utc": "2026-07-28T%02d:00:00Z" % hour,
                "event_record_id": record_id, "result_code": result_code}

    complete = build_run_rows([event(100, 1, record_id=10),
                               event(201, 3, record_id=11, result_code=0),
                               event(102, 3, record_id=12)], inventory)
    check(len(complete) == 1, "three events sharing one instance id collapse to one run row")
    check(complete[0]["duration_seconds"] == 7200.0, "events 100 and 102 bracket the duration")
    check(complete[0]["start_time_estimated"] == 0, "a real 100 event is not an estimated start")
    check(complete[0]["run_status"] == "Success", "event 201 carries the result code")
    actions = [event(201, 2, record_id=20, result_code=1), event(201, 3, record_id=21,
                                                                 result_code=0)]
    check([build_run_rows(order + [event(102, 3, record_id=22)], inventory)[0]["run_status"]
           for order in (actions, actions[::-1])] == ["Error", "Error"],
          "a failed action is not hidden by a later action's success, in either read order"
          "  <-- pinned defect")
    warned = [event(201, 2, record_id=20, result_code=TASK_TERMINATED),
              event(201, 3, record_id=21, result_code=1)]
    check([build_run_rows(order + [event(102, 3, record_id=22)], inventory)[0]["run_status"]
           for order in (warned, warned[::-1])] == ["Error", "Error"],
          "a warning code from one action does not hide another action's failure, in either "
          "read order  <-- pinned defect")
    mid_run = build_run_rows([event(100, 1, record_id=30), event(200, 1, record_id=31),
                              event(201, 2, record_id=32, result_code=1),
                              event(200, 2, record_id=33)], inventory)
    check(mid_run[0]["run_status"] == "Error"
          and summarize_runs(mid_run, now, 29)[r"\Jobs\etl"]["failures_last_7_days"] == 1,
          "a read that lands mid-run counts a failed action at once, because the next read "
          "sees only the rest of the run  <-- pinned defect")
    truncated = build_run_rows([event(201, 4, record_id=20, result_code=0),
                                event(102, 5, record_id=21)], inventory)
    check(truncated[0]["start_time_estimated"] == 1,
          "a run whose 100 event fell outside the window is flagged, not given a null start"
          "  <-- pinned defect")
    check(parse_dt(truncated[0]["start_time"]) == parse_dt("2026-07-28T04:00:00Z"),
          "an estimated start is the earliest event time observed for that run")
    check(truncated[0]["duration_seconds"] is None,
          "a run with an estimated start gets no duration  <-- pinned defect")
    measured = []
    for hour in (1, 3, 5, 7, 9):  # five one-hour runs arm the baseline
        measured += [event(100, hour, instance="m%d" % hour, record_id=hour * 10),
                     event(102, hour + 1, instance="m%d" % hour, record_id=hour * 10 + 1)]
    split = build_run_rows(measured + [event(201, 11, instance="cut", record_id=200,
                                             result_code=0),
                                       event(102, 11, instance="cut", record_id=201)],
                           inventory)
    split_row = evaluate(inventory[0], now, summarize_runs(split, now)[r"\Jobs\etl"])
    check(len(split) == 6 and split_row["is_duration_anomaly"] == 0,
          "a run cut off from its 100 event by the read cap counts, but never reads as a "
          "zero-second run against the baseline  <-- pinned defect")
    undated = dict(event(100, 1, record_id=30))
    undated["event_time_utc"] = None
    check(build_run_rows([undated], inventory) == [],
          "a run with nothing datable is dropped, not emitted with no start time")
    check(build_run_rows([event(100, 1, task=r"\Jobs\other"),
                          event(102, 2, task=r"\Jobs\other")], inventory) == [],
          "an event naming a task absent from the inventory is skipped")
    check(build_run_rows([event(100, 1, instance="")], inventory) == [],
          "an event with no instance id cannot be grouped and is skipped")
    running = build_run_rows([event(100, 1, record_id=40)], inventory)
    check(running[0]["run_status"] == "Running" and running[0]["duration_seconds"] is None,
          "a run with no 102 event is still running and has no duration")
    check(run_status("2026-07-28T03:00:00Z", None) == "Unknown",
          "a finished run that recorded no result is Unknown, never Success")
    check(run_status("2026-07-28T03:00:00Z", -2147024894) == "Error",
          "a failing HRESULT on a finished run is an Error")
    check(run_status("2026-07-28T03:00:00Z", TASK_TERMINATED) == "Warning",
          "a terminated run is a Warning, exactly as the snapshot path grades it")
    check(len(build_run_rows([event(100, 1), event(100, 2, instance="i2")], inventory)) == 2,
          "two instance ids are two runs")
    repeated = build_run_rows([event(100, 2, record_id=50), event(100, 1, record_id=51),
                               event(102, 4, record_id=52), event(102, 6, record_id=53)],
                              inventory)
    check(repeated[0]["duration_seconds"] == 18000.0,
          "a repeated 100 keeps the earliest start and a repeated 102 the latest end")
    in_order = build_run_rows([event(100, 1, record_id=60), event(100, 2, record_id=61),
                               event(102, 6, record_id=62), event(102, 4, record_id=63)],
                              inventory)
    check(in_order[0]["duration_seconds"] == 18000.0,
          "the same duplicates in the other order give the same run, so a re-read cannot "
          "shrink it")
    no_code = build_run_rows([event(100, 1), event(201, 2), event(102, 3)], inventory)
    check(no_code[0]["result_code"] is None and no_code[0]["run_status"] == "Unknown",
          "a 201 event carrying no result code leaves the run's result unknown")
    check(to_int(None) is None and to_int("junk") is None,
          "a junk event id or record id is dropped, not raised")
    check(to_int("102") == 102, "a numeric string event id is accepted")
    backwards = build_run_rows([event(100, 5), event(102, 4)], inventory)
    check(backwards[0]["duration_seconds"] is None,
          "an end before the start yields no duration rather than a negative one")
    check(build_run_rows([event(100, 4), event(102, 4)], inventory)[0]["duration_seconds"]
          == 0.0, "an end at the start is a zero-second run, not a missing duration")
    check(build_run_rows([event(100, 1, record_id=None), event(102, 2, record_id=None),
                          event(999, 3, record_id=None)], inventory)[0]["duration_seconds"]
          == 3600.0, "an unknown event id dates the run but brackets nothing")

    # --- the 7-day window is measured from an injected clock, never the wall clock ---
    def run(started, duration, status="Success"):
        return {"task": r"\Jobs\etl", "start_time": started, "duration_seconds": duration,
                "run_status": status}

    windowed = summarize_runs([run("2026-07-26T01:00:00Z", 10.0),
                               run("2026-06-28T01:00:00Z", 11.0)], now)[r"\Jobs\etl"]
    check(windowed["runs_last_7_days"] == 1,
          "a 30-day-old run falls outside the window and a 2-day-old run does not, against "
          "the clock the caller passed  <-- pinned defect")
    still = summarize_runs([run("2026-07-26T01:00:00Z", None, "Running")], now)[r"\Jobs\etl"]
    check(still["runs_last_7_days"] == 1 and still["failures_last_7_days"] == 0,
          "a run still running counts as a run, never as a failure")
    check(windowed["last_duration_seconds"] == 10.0,
          "the newest run's duration wins, whatever order the rows arrive in")
    check(summarize_runs([run("2026-07-21T12:00:00Z", 10.0)], now)[r"\Jobs\etl"][
        "runs_last_7_days"] == 1, "a run exactly 7 days old is still inside the window")
    check(summarize_runs([], now) == {}, "no runs summarise to nothing")
    check(summarize_runs([run("", 10.0)], now)[r"\Jobs\etl"]["runs_last_7_days"] == 0,
          "a run with an unparseable start counts towards no window")
    check(summarize_runs([{"task": "", "start_time": "2026-07-26T01:00:00Z"}], now) == {},
          "a run with no task name is skipped, not filed under a blank key")
    failing = summarize_runs([run("2026-07-26T01:00:00Z", 10.0, "Error"),
                              run("2026-07-27T01:00:00Z", 10.0)], now)[r"\Jobs\etl"]
    check(failing["failures_last_7_days"] == 1 and failing["runs_last_7_days"] == 2,
          "failures inside the window are counted apart from runs")
    aged = summarize_runs([run("2026-07-21T11:00:00Z", 10.0, "Error"),  # 7 days 1 hour old
                           run("2026-06-28T01:00:00Z", 10.0, "Error"),
                           run("2026-07-26T01:00:00Z", 10.0, "Warning"),
                           run("2026-07-26T02:00:00Z", None, "Unknown"),
                           run("2026-07-27T01:00:00Z", 10.0)], now)[r"\Jobs\etl"]
    check(aged["runs_last_7_days"] == 3 and aged["failures_last_7_days"] == 0,
          "an Error older than 7 days counts as neither a run nor a failure of the week, and a "
          "Warning or Unknown run is a run but not a failure  <-- pinned defect")
    unfinished = summarize_runs([run("2026-07-26T01:00:00Z", None)], now)[r"\Jobs\etl"]
    check(unfinished["completed_run_count"] == 0 and unfinished["mean_duration_seconds"] is None,
          "a run still in flight counts towards the week but not towards the baseline")
    check(duration_ratio({"completed_run_count": 9, "mean_duration_seconds": 0.0,
                          "last_duration_seconds": 5.0}) is None,
          "a zero mean yields no ratio rather than a division error")
    check("last 7 days" in evaluate(inventory[0], now, failing, "complete")["reason"],
          "a task whose last run was green still reports the week's failures")
    sliced = summarize_runs([run("2026-06-28T01:00:00Z", 10.0, "Error"),
                             run("2026-07-27T01:00:00Z", 10.0)], now, 9)[r"\Jobs\etl"]
    check(sliced["runs_last_7_days"] == 2 and sliced["failures_last_7_days"] == 1
          and "1 of 2 run(s) since record 9 failed"
          in evaluate(inventory[0], now, sliced, "complete")["reason"],
          "past a watermark the columns count every run read, however old, and say they "
          "start at the watermark, not 'the last 7 days'  <-- pinned defect")
    zero = summarize_runs([run("2026-06-28T01:00:00Z", 10.0)], now, 0)[r"\Jobs\etl"]
    check(zero["runs_last_7_days"] == 1 and zero["window"] == "since record 0",
          "a watermark of 0 is a watermark too: its columns count every run read")

    # --- duration baseline: advisory, and gated so a new task cannot trip it ---
    four = [run("2026-07-2%dT01:00:00Z" % day, 100.0) for day in (4, 5, 6, 7)]

    def history_row(last_duration):
        rows = four + [run("2026-07-28T01:00:00Z", last_duration)]
        return evaluate(inventory[0], now, summarize_runs(rows, now)[r"\Jobs\etl"])

    edge = evaluate(inventory[0], now, {"completed_run_count": 5, "mean_duration_seconds": 100.0,
                                        "last_duration_seconds": 33.0})
    check(edge["duration_ratio"] == 0.33 and edge["is_duration_anomaly"] == 0,
          "a run at exactly the low ratio is not an anomaly; only a shorter one is")
    four_row = evaluate(inventory[0], now, summarize_runs(four, now)[r"\Jobs\etl"])
    check(four_row["duration_ratio"] is None and four_row["is_duration_anomaly"] == 0,
          "four completed runs never set a baseline, however far apart their durations are")
    check(history_row(300.0)["is_duration_anomaly"] == 1,
          "the fifth completed run sets the baseline, and 2.1x it flags")
    check(history_row(250.0)["is_duration_anomaly"] == 0,
          "1.9x does not flag: the threshold is 2.0x, not 'slower than usual'")
    exact = [run("2026-07-2%dT01:00:00Z" % day, 3.0) for day in (3, 4, 5, 6)]
    exact_row = evaluate(inventory[0], now, summarize_runs(
        exact + [run("2026-07-27T01:00:00Z", 8.0)], now)[r"\Jobs\etl"])
    check(exact_row["duration_ratio"] == 2.0 and exact_row["is_duration_anomaly"] == 0,
          "exactly 2.0x its baseline does not flag: the threshold is 'more than'")
    check(history_row(20.0)["is_duration_anomaly"] == 1,
          "a run at a fraction of the baseline flags too: a job that stopped doing its work")
    check(history_row(300.0)["status"] == "Success",
          "the duration baseline is advisory and never changes the health verdict")
    check("baseline" in history_row(300.0)["reason"], "the anomaly reaches the reason column")
    check(evaluate({})["runs_last_7_days"] is None and evaluate({})["history"] == "off"
          and evaluate({})["duration_ratio"] is None,
          "a run without --history still emits the history columns, so the CSV header is "
          "stable, and leaves its run counts empty, not 0")
    check(evaluate({}, None, None, "complete")["runs_last_7_days"] == 0
          and evaluate({}, None, None, "complete")["failures_last_7_days"] == 0,
          "a complete read of a task with no run in it counts 0 runs and 0 failures")
    unread = evaluate(inventory[0], now, None, "failed")
    check(unread["runs_last_7_days"] is None and unread["failures_last_7_days"] is None
          and "run history unread" in unread["reason"],
          "a failed history read leaves the run counts empty and says so, never a clean week "
          "with 0 runs  <-- pinned defect")
    partial = evaluate(inventory[0], now, failing, "incomplete")
    check(partial["failures_last_7_days"] == failing["failures_last_7_days"]
          and partial["history"] == "incomplete" and "run history incomplete" in partial["reason"],
          "an incomplete read keeps its counts and marks them incomplete  <-- pinned defect")
    check(full_task_name(dict(task_path="\\Jobs", task_name="etl")) == r"\Jobs\etl",
          "a task path with no trailing separator still joins to the event log's name")
    check(evaluate(inventory[0])["task"] == full_task_name(inventory[0]),
          "both sides of the history join build the task name the same way")

    # --- run fate: the ways a launch ends that are not a normal run (--history) ---
    check(HISTORY_EVENT_IDS == (100, 101, 102, 103, 111, 153, 200, 201, 203, 322, 329, 330, 332),
          "the history read asks for the nine run-fate events as well as the four lifecycle "
          "events")
    check(len(HISTORY_EVENT_IDS) <= 21 and sorted(HISTORY_EVENT_IDS) == list(HISTORY_EVENT_IDS),
          "the event filter stays under the XPath clause limit measured with the time window, "
          "which is 21")
    failed_start = build_run_rows([event(100, 1, record_id=80),
                                   event(103, 1, record_id=81, result_code=-2147024894)],
                                  inventory)
    check(len(failed_start) == 1 and failed_start[0]["fate"] == "LaunchFailed"
          and failed_start[0]["run_status"] == "Error" and failed_start[0]["result_code"]
          == 0x80070002 and failed_start[0]["duration_seconds"] is None,
          "event 103, the action could not start, makes the run an Error with its code, though "
          "no 102 or 201 followed  <-- pinned defect")
    check(build_run_rows([event(203, 2, record_id=82, result_code=-2147024894),
                          event(100, 1, record_id=83), event(102, 3, record_id=84)],
                         inventory)[0]["run_status"] == "Error",
          "event 203 on a run that still ended with a 102 is an Error too  <-- pinned defect")
    check(build_run_rows([event(100, 1), event(203, 2, result_code=0)],
                         inventory)[0]["run_status"] == "Error",
          "a launch failure with a success code is still a failure: the event says it did not "
          "start")
    lone = build_run_rows([event(101, 3, instance="", record_id=77, result_code=-2147024894),
                           event(101, 4, instance="", record_id=78, result_code=-2147024894)],
                          inventory)
    check(len(lone) == 2 and lone[0]["instance_id"] == "launch-77"
          and lone[0]["run_status"] == "Error" and lone[0]["fate"] == "LaunchFailed"
          and lone[0]["start_time_estimated"] == 1 and lone[0]["duration_seconds"] is None
          and lone[0]["result_code"] == 0x80070002,
          "event 101 has no instance id, because no instance existed: each is a run of its own, "
          "named after its record, and an Error  <-- pinned defect")
    check(build_run_rows([event(101, 3, instance="", record_id=None)],
                         inventory)[0]["instance_id"] == "launch-2026-07-28T03:00:00Z",
          "an event 101 with no record id is named after its time")
    check(build_run_rows([event(101, 3, instance="", record_id=77, task=r"\Jobs\other")],
                         inventory) == [],
          "an event 101 for a task outside the inventory is skipped")
    nameless = dict(event(101, 3, instance="", record_id=None), event_time_utc=None)
    check(build_run_rows([nameless], inventory) == [],
          "an event 101 with neither a record id nor a time is dropped, not filed as a run")
    check(build_run_rows([event(100, 1, record_id=85), event(102, 2, record_id=86)],
                         inventory)[0]["fate"] == "",
          "a normal run has no fate")
    stops = {}
    for stop_id, label in ((111, "Terminated"), (329, "TimedOut"), (330, "Stopped")):
        stops[stop_id] = build_run_rows([event(100, 1, record_id=90), event(stop_id, 2,
                                                                            record_id=91)],
                                        inventory)[0]
        check(stops[stop_id]["fate"] == label and stops[stop_id]["duration_seconds"] is None,
              "event %d sets the fate %s and, with no 102, no duration" % (stop_id, label))
    check([stops[i]["run_status"] for i in (111, 329, 330)] == ["Warning", "Error", "Warning"]
          and stops[111]["end_time"] == "",
          "a terminated or user-stopped run is a Warning and over, a run stopped for exceeding "
          "its time limit is an Error, and none of them is Running  <-- pinned defect")
    ended = build_run_rows([event(100, 1), event(111, 2), event(102, 3)], inventory)[0]
    check(ended["run_status"] == "Warning" and ended["duration_seconds"] == 7200.0,
          "a terminated run that also wrote a 102 keeps its duration and stays a Warning")
    check([build_run_rows(order, inventory)[0]["fate"] for order in (
        [event(330, 2), event(329, 3)], [event(329, 3), event(330, 2)],
        [event(329, 2), event(111, 3)], [event(111, 2), event(329, 3)],
        [event(111, 2), event(330, 3)], [event(330, 2), event(111, 3)])]
        == ["TimedOut"] * 4 + ["Terminated"] * 2,
        "the worst fate of an instance wins, whatever order its events are read in")
    check(worse_fate("", "Stopped") == "Stopped" and worse_fate("LaunchFailed", "TimedOut")
          == "LaunchFailed" and worse_fate("Stopped", "") == "Stopped",
          "worse_fate ranks launch failure above a timeout above termination above a stop")
    check(run_status(None, None, "LaunchFailed") == "Error"
          and run_status(None, None, "TimedOut") == "Error"
          and run_status(None, None, "Terminated") == "Warning"
          and run_status(None, None, "Stopped") == "Warning"
          and run_status(None, 0, "") == "Running" and run_status("x", 0) == "Success",
          "a fate decides the run's status, and no fate leaves run_status as it was")
    check(build_run_rows([event(322, 2), event(332, 3, instance=""), event(153, 4, instance="")],
                         inventory) == [],
          "a refused launch (153, 322, 332) is not a run and starts none")
    overlapped = build_run_rows([event(100, 1, record_id=92), event(322, 5, record_id=93)],
                                inventory)
    check(len(overlapped) == 1 and overlapped[0]["start_time"] == "2026-07-28T01:00:00Z"
          and overlapped[0]["run_status"] == "Running",
          "a 322 naming a running instance neither ends it nor moves its start  <-- pinned defect")

    refusals = build_block_rows([
        event(332, 6, instance="", record_id=1), event(322, 2, instance="i1", record_id=2),
        event(153, 4, instance="", record_id=3), event(100, 1, record_id=4),
        event(322, 3, task=r"\Jobs\other"), dict(event(332, 5), event_time_utc=None)], inventory)
    check([(row["kind"], row["instance_id"]) for row in refusals]
          == [("overlap", "i1"), ("missed", ""), ("no-session", "")]
          and refusals[0]["task"] == r"\Jobs\etl",
          "refused launches come out oldest first, each with its kind, and a 322 keeps the "
          "instance that was still running; a run event, an unknown task and an undated event "
          "are left out")

    stuck_now = datetime(2026, 7, 28, 12, 0, tzinfo=timezone.utc)

    def go(started, state="Running", blocks=(), status="Running", **options):
        """judge_fates over one run that began at `started` (hours ago) on a task in `state`."""
        started_at = (stuck_now - timedelta(hours=started)).isoformat() if started else ""
        runs = [{"task": r"\Jobs\etl", "instance_id": "r1", "start_time": started_at,
                 "run_status": status}]
        tasks = [dict(inventory[0], state=state)] if state else [
            {k: v for k, v in inventory[0].items() if k != "state"}]
        got = judge_fates(runs, list(blocks), tasks, stuck_now, **options)
        return got.get(r"\Jobs\etl", {})

    def refusal(kind, hours_ago, instance=""):
        return {"task": r"\Jobs\etl", "kind": kind, "instance_id": instance,
                "time": (stuck_now - timedelta(hours=hours_ago)).isoformat()}

    verdict = go(59)
    check(verdict["fate"] == "STUCK" and "59.0 hour(s) ago has not finished" in verdict["detail"]
          and verdict["blocked_launches"] == 0,
          "a run with no end event after 59 hours on a Running task is STUCK")
    check(go(23.9)["fate"] == "" and go(24)["fate"] == "STUCK",
          "the threshold is 24 hours, and a run of exactly 24 hours is stuck")
    check(go(59, stuck_hours=72)["fate"] == "" and go(59, stuck_hours=48)["fate"] == "STUCK",
          "--stuck-hours moves the threshold")
    check(go(59, state="Ready")["fate"] == "" and go(59, state="Queued")["fate"] == "",
          "a run with no end event on a task that is Ready or Queued is a lost end event, not a "
          "stuck run  <-- pinned defect")
    check(go(59, state="")["fate"] == "STUCK" and go(59, state="Disabled")["fate"] == "STUCK",
          "a task whose state is unknown, as in an export, or disabled with a run still going "
          "can be stuck")
    check(go(59, status="Success")["fate"] == "" and go(59, status="Error")["fate"] == "",
          "only a run with no end is stuck: a finished run is not, however old")
    check(go(0)["fate"] == "",
          "a run row with no usable start time is skipped, not a crash")
    healthy = go(2, blocks=[refusal("overlap", 1, "r1"), refusal("overlap", 0.5, "r1")])
    check(healthy["fate"] == "BLOCKED" and "event 322" in healthy["detail"]
          and "STUCK" not in healthy["detail"] and healthy["blocked_launches"] == 2,
          "a run that is only 2 hours old is not STUCK although later launches were ignored "
          "while it ran: a slow job on a short repeat interval is healthy  <-- pinned defect")
    waiting = go(30, blocks=[refusal("overlap", 1, "r1"), refusal("overlap", 0.5, "r1")])
    check(waiting["fate"] == "STUCK" and "2 later launch(es) were ignored while it ran (event 322)"
          in waiting["detail"] and "30.0 hour(s) ago" in waiting["detail"]
          and waiting["blocked_launches"] == 2,
          "a run past the threshold with ignored launches is STUCK, and the detail counts them")
    check("ignored" not in go(30)["detail"],
          "a stuck run that drew no 322 does not claim ignored launches")
    check(go(2, blocks=[refusal("overlap", 1, "other")])["fate"] == "BLOCKED",
          "a 322 that names another instance does not make this run stuck; it blocks the task")
    check(go(2, blocks=[refusal("no-session", 1)])["fate"] == "BLOCKED",
          "a refused launch after a young run's start does not make it stuck; it blocks the task")
    check(go(59, blocks=[refusal("no-session", 1)])["fate"] == "STUCK",
          "STUCK wins over BLOCKED")

    def running_since(hours, state="Running", launch=True):
        """judge_fates for a task with no run row at all, last launched `hours` ago."""
        when = (stuck_now - timedelta(hours=hours)).isoformat() if launch else ""
        return judge_fates([], [], [dict(inventory[0], state=state, last_run_time=when)],
                           stuck_now).get(r"\Jobs\etl", {})

    check(running_since(290)["fate"] == "STUCK"
          and "290.0 hour(s) ago has not finished" in running_since(290)["detail"]
          and running_since(23.9)["fate"] == "" and running_since(24)["fate"] == "STUCK"
          and running_since(290, state="Ready") == {} and running_since(290, state="Queued") == {}
          and running_since(290, launch=False)["fate"] == "",
          "a task the scheduler says is Running since a launch 24 hours or more ago is STUCK "
          "although this read holds no start event for the run; Ready, Queued and a missing "
          "launch time are not  <-- pinned defect")

    check(running_since(290)["detail"] == "STUCK: a run started 290.0 hour(s) ago has not finished",
          "a Running task with no run row claims no ignored launches")

    def finished(started, blocks, **options):
        """judge_fates for a task whose only run began `started` hours ago and ended."""
        return go(started, state="Ready", blocks=blocks, status="Success", **options)

    blocked = finished(10, [refusal("no-session", 5)])
    check(blocked["fate"] == "BLOCKED" and blocked["blocked_launches"] == 1
          and "BLOCKED: the latest launch was refused because the run-as user was not logged on "
          "(event 332) at 2026-07-28T07:00Z" == blocked["detail"],
          "a launch refused after the task's last start leaves it BLOCKED, with the time")
    check(finished(3, [refusal("no-session", 5)])["fate"] == ""
          and finished(3, [refusal("no-session", 5)])["blocked_launches"] == 1,
          "a refusal before the task's last start is counted but does not leave it BLOCKED")
    check("event 322" in finished(10, [refusal("overlap", 5, "gone")])["detail"]
          and "event 153" in finished(10, [refusal("missed", 5)])["detail"]
          and "StartWhenAvailable" in finished(10, [refusal("missed", 5)])["detail"],
          "each kind of refusal names its event, and a missed start names the setting")
    latest = [refusal("no-session", 6), refusal("overlap", 5, "g")]
    check("event 322" in finished(10, latest)["detail"]
          and "event 322" in finished(10, latest[::-1])["detail"]
          and "event 332" in finished(10, [refusal("overlap", 6, "g"),
                                           refusal("no-session", 5)])["detail"],
          "the latest refusal names the cause, whatever order the rows arrive in")
    check(finished(10, [refusal("no-session", 7 * 24)])["blocked_launches"] == 1
          and finished(10, [refusal("no-session", 7 * 24 + 0.01)])["blocked_launches"] == 0
          and finished(10, [refusal("no-session", 10)])["fate"] == ""
          and finished(10, [refusal("no-session", 9.99)])["fate"] == "BLOCKED",
          "a refusal exactly 7 days old is counted and one a moment older is not; a refusal at "
          "the very second of the last start is not BLOCKED and one just after is")
    only = judge_fates([], [refusal("missed", 5)], [inventory[0]], stuck_now)[r"\Jobs\etl"]
    check(only["fate"] == "BLOCKED" and only["blocked_launches"] == 1,
          "a task with a refused launch and no run at all is BLOCKED")
    old = [refusal("no-session", 9 * 24)]
    check(finished(10, old)["blocked_launches"] == 0 and finished(10, old)["fate"] == ""
          and finished(10, old, since_record_id=5)["blocked_launches"] == 1
          and judge_fates([], old, [inventory[0]], stuck_now, 5)[r"\Jobs\etl"]["fate"]
          == "BLOCKED",
          "a refusal older than the 7-day window is not counted on a cold start, and is past a "
          "watermark, whatever its age")
    clean = judge_fates([{"task": r"\Jobs\etl", "instance_id": "r1", "run_status": "Success",
                          "start_time": "2026-07-28T01:00:00Z"}], [], [inventory[0]], stuck_now)
    check(clean == {r"\Jobs\etl": {"fate": "", "detail": "", "blocked_launches": 0}}
          and judge_fates([], [], [], stuck_now) == {},
          "a task with only normal runs has no fate, and no events judge to nothing")

    fate_stats = {"completed_run_count": 0, "mean_duration_seconds": None}
    stuck_row = evaluate(inventory[0], now, fate_stats, "complete", verdict)
    check(stuck_row["fate"] == "STUCK" and stuck_row["status"] == "Warning"
          and "STUCK: a run started 59.0 hour(s) ago" in stuck_row["reason"]
          and stuck_row["blocked_launches_last_7_days"] == 0,
          "a STUCK task is a Warning, though its snapshot says success, and the reason says why")
    check(evaluate(dict(inventory[0], state="Running", last_task_result=TASK_RUNNING), now,
                   fate_stats, "complete", verdict)["status"] == "Warning"
          and evaluate(dict(inventory[0], last_task_result=None), now, fate_stats, "complete",
                       verdict)["status"] == "Warning",
          "a task that reads as Running or NotYetRun is a Warning once it is STUCK")
    check(evaluate(dict(inventory[0], last_task_result=1), now, fate_stats, "complete",
                   verdict)["status"] == "Error"
          and evaluate(dict(inventory[0], enabled=False), now, fate_stats, "complete",
                       verdict)["status"] == "Disabled",
          "a fate never lowers an Error or lifts a Disabled task")
    unread_fate = evaluate(inventory[0], now, None, "failed", verdict)
    check(unread_fate["fate"] == "" and unread_fate["blocked_launches_last_7_days"] is None
          and unread_fate["status"] == "Success" and "STUCK" not in unread_fate["reason"],
          "a history read that failed ignores any fate: nothing was read, so nothing is "
          "judged  <-- pinned defect")
    check(evaluate({})["fate"] == "" and evaluate({})["blocked_launches_last_7_days"] is None
          and evaluate({}, None, None, "complete")["blocked_launches_last_7_days"] == 0,
          "a run without --history leaves the fate columns empty, and a complete read of a "
          "quiet task counts 0 refused launches")

    # --- rendering never explodes ---
    check("STATUS" in render_table([row]), "table renders a header")
    check(r"\Jobs\etl" in render_table([row]), "table renders the task name")
    check(json.loads(json.dumps([row])) == [row], "rows are JSON-serialisable")
    csv_out = io.StringIO()
    write_output([history_row(300.0)], "csv", csv_out)
    check("is_duration_anomaly" in csv_out.getvalue().splitlines()[0],
          "the CSV header carries the history columns")
    check(len(csv_out.getvalue().splitlines()) == 2,
          "a history row writes as one CSV row: the header is built from the same row shape")
    formula_out = io.StringIO()
    write_output([dict(row, author='=HYPERLINK("http://example.test/","x")', run_as_user="-1",
                       reason="")], "csv", formula_out)
    cells = next(csv.DictReader(io.StringIO(formula_out.getvalue())))
    check(cells["author"].startswith("'=") and cells["run_as_user"] == "'-1"
          and cells["task"] == row["task"] and cells["reason"] == "",
          "a CSV cell a spreadsheet would run as a formula is written as text"
          "  <-- pinned defect")
    json_out = io.StringIO()
    write_output([row], "json", json_out)
    check(json.loads(json_out.getvalue()) == [row], "json output round-trips")
    table_out = io.StringIO()
    write_output([row], "table", table_out)
    check(r"\Jobs\etl" in table_out.getvalue(), "the table format writes the report")
    empty_out = io.StringIO()
    write_output([], "table", empty_out)
    check("No tasks need attention" in empty_out.getvalue(), "an empty report says so")

    # --- lint: the configuration that makes the NEXT run fail (--lint) ---
    def finding_checks(task, drives=("C",)):
        return [(f["severity"], f["check"]) for f in lint_task(task, drives)]

    def job(logon="Password", user="EXAMPLE\\svc-etl", triggers="Daily", command=None,
            arguments=r"C:\jobs\refresh.py", start=r"C:\jobs"):
        return {"task_path": "\\Jobs\\", "task_name": "refresh", "logon_type": logon,
                "run_as_user": user, "trigger_types": triggers,
                "actions": [{"executable": command or r"C:\Python39\python.exe",
                             "arguments": arguments, "working_directory": start}]}

    check(finding_checks(job()) == [],
          "a stored-password job with absolute paths and a Start In has no findings")
    flipped_job = job(logon="InteractiveToken")
    check(finding_checks(flipped_job) == [("Error", "interactive-only")]
          and health_status(dict(base, **flipped_job), now) == "Success",
          "a nightly python job switched to 'run only when logged on' is an Error, while its "
          "last result still reads success  <-- pinned defect")
    for interpreter in ("python3.exe", "python3.11.exe", "pythonw.exe", "py.exe"):
        check(finding_checks(job(logon="InteractiveToken", command="C:\\Py\\" + interpreter))
              == [("Error", "interactive-only")],
              "%s is a python interpreter, so an interactive-only job is an Error"
              "  <-- pinned defect" % interpreter)
    check(finding_checks(job(logon="Interactive")) == [("Error", "interactive-only")],
          "powerShell's spelling 'Interactive' is the same logon type as the XML's")
    for command, arguments in ((r"C:\Python39\python", r"C:\jobs\refresh.py"),
                               ("powershell", r"-File C:\jobs\refresh.ps1"),
                               ("cmd", r"/c C:\jobs\refresh.bat")):
        check(finding_checks(job(logon="InteractiveToken", command=command, arguments=arguments))
              == [("Error", "interactive-only")],
              "an interactive-only %s job named with no .exe is still a script, so an Error"
              "  <-- pinned defect" % ntpath.basename(command))
    check(finding_checks(job(logon="Group", user="")) == [("Error", "interactive-only")],
          "a group principal runs only in a member's session, so it is interactive too")
    check(finding_checks(job(logon="InteractiveToken", command=r"C:\vendor\update.exe",
                             arguments="/silent"))
          == [("Warning", "interactive-only")],
          "a vendor exe on an interactive schedule is a Warning: it is often meant that way")
    check(finding_checks(job(logon="InteractiveToken", triggers="Logon")) == [],
          "an interactive task with only a logon trigger runs exactly when it is meant to")
    check(finding_checks(job(logon="InteractiveTokenOrPassword")) == [],
          "interactive-or-password can run with nobody logged on")
    check(finding_checks(dict(job(), read_errors="actions", actions=[]))
          == [("Warning", "read-failed")],
          "a task whose actions could not be read is not a clean lint  <-- pinned defect")
    check("svc-etl is logged on" in lint_task(job(logon="InteractiveToken"))[0]["detail"]
          and "Daily trigger" in lint_task(job(logon="InteractiveToken"))[0]["detail"],
          "the finding names the account and the trigger that will be skipped")

    share_job = job(logon="S4U", arguments=r"C:\jobs\refresh.py \\fileserver\gis\out")
    check(finding_checks(share_job) == [("Error", "s4u-network")],
          "s4u ('do not store password') with a share in the arguments is an Error")
    check(r"\\fileserver\gis" in lint_task(share_job)[0]["detail"],
          "the finding names the share root that cannot be reached")
    check(finding_checks(job(logon="S4U")) == [],
          "s4u with only local paths is fine: it loses the network, not the disk")
    check(finding_checks(job(arguments=r"C:\jobs\refresh.py \\fileserver\gis")) == [],
          "a stored-password logon has network credentials, so a share is no finding"
          "  <-- pinned defect")
    check(finding_checks(job(logon="S4U", command=r"\\fileserver\gis\bin\run.exe",
                             arguments="")) == [("Error", "s4u-network")],
          "a share in the program path counts, not only in the arguments")
    check(finding_checks(job(logon="S4U", start=r"\\fileserver\gis\work"))
          == [("Error", "s4u-network")], "a share as Start In counts too")
    check(finding_checks(job(logon="", user="S-1-5-18", arguments=r"\\fileserver\gis\a.py"))
          == [("Warning", "service-network")],
          "system on a share is a Warning: it reaches it as the computer account")
    check(finding_checks(job(logon="ServiceAccount", user="NT AUTHORITY\\SYSTEM",
                             arguments=r"\\fileserver\gis\a.py"))
          == [("Warning", "service-network")],
          "the account is recognised by name as well as by SID")
    check(finding_checks(job(logon="", user="LOCAL SERVICE", arguments=r"\\fileserver\gis\a.py"))
          == [("Error", "service-network")],
          "local service reaches the network anonymously, so a share is an Error")
    check(finding_checks(job(logon="", user="S-1-5-20", arguments=r"\\fileserver\gis\a.py"))
          == [("Warning", "service-network")], "network service is the computer account too")
    check(finding_checks(job(logon="S4U", arguments=r"C:\jobs\a.py \\?\C:\jobs\long")) == []
          and finding_checks(job(logon="S4U", arguments=r"C:\jobs\a.py \\.\pipe\etl")) == [],
          "a \\\\?\\ or \\\\.\\ device path is not a share  <-- pinned defect")
    check(finding_checks(job(logon="S4U", arguments="https://portal.example.com/x.json")) == [],
          "a URL is neither a share, a drive nor a relative path")
    check(finding_checks(job(logon="S4U", arguments=r"C:\jobs\a.py //fileserver/gis/out"))
          == [("Error", "s4u-network")],
          "a share spelled with forward slashes is still a share  <-- pinned defect")
    long_unc = job(logon="S4U", arguments=r"C:\jobs\a.py \\?\UNC\fileserver\gis\out")
    check(finding_checks(long_unc) == [("Error", "s4u-network")]
          and r"\\fileserver\gis " in lint_task(long_unc)[0]["detail"] + " ",
          "the long \\\\?\\UNC\\ form is a share, named by its server and share  <-- pinned defect")
    check(finding_checks(job(logon="S4U", command="cscript.exe",
                             arguments=r"//B C:\jobs\legacy.vbs")) == [],
          "cscript's //B switch is not a share")
    check(finding_checks(job(logon="S4U", arguments=r"C:\jobs\a.py file:///C:/data/x.json")) == [],
          "the /// of a file URL is not a share")

    check(finding_checks(job(logon="", user="S-1-5-18", arguments=r"D:\jobs\a.py"))
          == [("Warning", "mapped-drive")],
          "d: under a non-interactive logon may be a mapped drive the task will not have")
    check(finding_checks(job(logon="", user="S-1-5-18", arguments=r"D:\jobs\a.py"), ("C", "D:"))
          == [], "declaring D as a local drive silences it")
    check(finding_checks(job(logon="", user="S-1-5-18", arguments=r"D:\jobs\a.py"), ("c", "d"))
          == [], "a local drive declared in lower case is the same drive")
    check(finding_checks(job(logon="InteractiveToken", triggers="Logon",
                             arguments=r"Z:\jobs\a.py")) == [],
          "an interactive session has the user's mapped drives")
    check(finding_checks(job(start="C:/jobs", arguments="C:/jobs/refresh.py")) == [],
          "forward slashes after a drive letter are an absolute path")
    robocopy = r"C:\Windows\System32\robocopy.exe"
    check(lint_task(job(logon="Password", arguments=r"--in=E:\a.csv --out=F:\b.csv"))[0][
        "detail"].startswith("E:, F: is not"), "every undeclared drive is named")
    for arguments in (r"C:\out Z:run.log", r"C:\out C:\copy /LOG:Z:run.log",
                      r"C:\out Z:outbox\daily"):
        check(finding_checks(job(command=robocopy, arguments=arguments))
              == [("Warning", "mapped-drive")],
              "a drive-relative path such as %s names a mapped drive  <-- pinned defect"
              % arguments.split()[-1])
    for word in ("x:y", "3D:"):
        check(finding_checks(job(logon="", user="S-1-5-18",
                                 arguments=r"C:\jobs\a.py -tag %s" % word)) == [],
              "the letter before the colon in %s is not a drive  <-- pinned defect" % word)

    check(finding_checks(job(start='"C:\\my jobs"')) == [("Error", "start-in-quoted")],
          "a quoted Start In is an Error: measured, it fails with 0x8007010B  <-- pinned defect")
    check(finding_checks(job(start='"C:\\my jobs')) == [("Error", "start-in-quoted")]
          and finding_checks(job(start='C:\\jobs"')) == [("Error", "start-in-quoted")],
          "a quote at only one end of Start In is still a quoted Start In")
    check(finding_checks(job(start="jobs")) == [("Error", "start-in-relative")],
          "a relative Start In is an Error")
    check(finding_checks(job(start="%USERPROFILE%\\jobs")) == [],
          "a Start In rooted at an environment variable is absolute once expanded")
    check(finding_checks(job(start="", arguments="refresh.py"))
          == [("Error", "start-in-missing")],
          "an empty Start In with a relative script is an Error: it resolves in System32")
    check(r"refresh.py resolves against C:\Windows\System32" in
          lint_task(job(start="", arguments="refresh.py"))[0]["detail"],
          "the finding names the relative path and where it actually resolves")
    check(finding_checks(job(start="")) == [("Warning", "start-in-missing")],
          "an empty Start In behind an absolute script is a Warning: the script may open "
          "relative paths")
    check(finding_checks(job(start="", command=r"C:\tools\backup.exe", arguments="/full"))
          == [], "an empty Start In for an exe with absolute paths is not a finding")
    check(finding_checks(job(start="", command="cmd.exe",
                             arguments=r"/c cd /d C:\jobs && python.exe refresh.py")) == [],
          "a command that changes its own directory first does not depend on Start In")
    check(finding_checks(job(start="", arguments=r"C:\jobs\refresh.py --out=report.csv"))
          == [("Error", "start-in-missing")], "the value of --out=report.csv is a path")
    check(finding_checks(job(start="", command="cmd.exe", arguments=r"/c scripts\nightly.bat"))
          == [("Error", "start-in-missing")], "a relative path with a separator is found")
    check(finding_checks(job(start="", command=r"tools\run.exe", arguments=""))
          == [("Error", "start-in-missing")], "a relative program path is found")
    check(finding_checks(job(start="", command="refresh.bat", arguments=""))
          == [("Error", "start-in-missing"), ("Warning", "bare-program")],
          "a bare script as the program is a relative path: no PATH holds it  <-- pinned defect")
    check(finding_checks(job(start="", arguments=r"C:\jobs\refresh.py data\a+b.csv"))
          == [("Error", "start-in-missing")],
          "a value with '+' and a known extension is still a path, so it is judged")
    check(finding_checks(job(logon="S4U", command=r"C:\PS7\pwsh.exe",
                             arguments=r"-WorkingDirectory \\fileserver\gis -Command Invoke-Sync"))
          == [("Error", "s4u-network")], "a share before the -Command body still counts")
    check(finding_checks(job(start="", arguments="C:refresh.py"))
          == [("Error", "start-in-missing")],
          "a drive-relative C:refresh.py resolves against the drive's current folder"
          "  <-- pinned defect")
    empty_exec = dict(job(logon="InteractiveToken", start=""), actions=[{"executable": ""}])
    check(finding_checks(empty_exec) == [("Warning", "interactive-only")],
          "an action with no command is not a script: a Warning, and no Start In finding")
    check(finding_checks(job(start="", arguments=r"C:\jobs\refresh.py /out=report.csv"))
          == [("Error", "start-in-missing")], "the value of /out=report.csv is a path too")
    check(finding_checks(job(start="", command=r"C:\tools\fetch.exe",
                             arguments="https://portal.example.com/x.json")) == [],
          "a URL argument is not a relative path")
    check(finding_checks(job(start="", command=r"C:\tools\sync.exe",
                             arguments=r"-in data\parcels.csv -user svc"))
          == [("Error", "start-in-missing")], "the value after an ordinary switch is judged")
    for why, secret in (("its padding", "-apikey Zm9vYmFy/c2VjcmV0K3Rva2Vu== -user svc"),
                        ("the switch before it", "-apikey Zm9vYmFy/c2VjcmV0 -user svc"),
                        ("its --token= switch", "--token=Zm9vYmFy/c2VjcmV0"),
                        ("its '+'", "-data Zm9vYmFy/c2Vj+cmV0")):
        check(finding_checks(job(start="", command=r"C:\tools\sync.exe", arguments=secret))
              == [], "a base64 secret, known by %s, is not a relative path, so no finding "
              "prints it  <-- pinned defect" % why)
    check(finding_checks(job(start="", arguments="refresh.py sl"))
          == [("Error", "start-in-missing")],
          "the word 'sl' among the arguments does not change directory  <-- pinned defect")
    check(finding_checks(job(start="", command="cmd.exe", arguments=r"/c nightly.bat && cd C:\x"))
          == [("Error", "start-in-missing")],
          "a cd after the relative script comes too late  <-- pinned defect")
    check(finding_checks(job(start="", command="cmd.exe",
                             arguments=r"/c python.exe rebuild.py & cd \logs"))
          == [("Error", "start-in-missing")], "a cd after '&' comes too late as well")
    check(finding_checks(job(start="", command="cmd.exe",
                             arguments=r'/c "cd /d C:\jobs && python.exe refresh.py"')) == [],
          "a quoted cmd /c body that runs cd first is exempt  <-- pinned defect")
    check(finding_checks(job(start="", command="powershell.exe",
                             arguments=r'-NoProfile -Command "Set-Location C:\jobs; .\sync.ps1"'))
          == [], "powershell -Command that runs Set-Location first is exempt  <-- pinned defect")
    check(finding_checks(job(start="", command="powershell", arguments=r"-File C:\jobs\sync.ps1"))
          == [("Warning", "start-in-missing")],
          "powershell named with no .exe still runs a script that may open relative paths")
    check(relative_paths("python.exe", "-m etl.nightly --verbose -") == [],
          "a module name, a switch and a lone dash are not file paths")

    # Switch values after a colon, quoted shell bodies, and what a finding may print.
    for form, command, arguments in (
            ("robocopy /LOG:", robocopy, r"C:\gis\out C:\gis\mirror /MIR /LOG:\\fileserver\gis\m.log"),
            ("powershell -Dest:", "powershell.exe", r"-File C:\jobs\x.ps1 -Dest:\\fileserver\gis")):
        check(finding_checks(job(logon="S4U", command=command, arguments=arguments))
              == [("Error", "s4u-network")],
              "a share after a %s switch is still a share  <-- pinned defect" % form)
    check(finding_checks(job(start="", command=robocopy, arguments=r"C:\a C:\b /LOG:logs\run.txt"))
          == [("Error", "start-in-missing")],
          "the value of /LOG:logs\\run.txt is a relative path  <-- pinned defect")
    colon_secret = lint_task(job(start="", command=r"C:\tools\sync.exe",
                                 arguments=r"-apikey:v data\x.csv"))
    check([(f["severity"], f["check"]) for f in colon_secret] == [("Error", "start-in-missing")]
          and "path data\\x.csv resolves" in colon_secret[0]["detail"],
          "-apikey:v carries its own value, so the path after it is still judged"
          "  <-- pinned defect")
    check(relative_paths(r"C:\t\x.exe", r'--out="C:\out\r.csv"') == [],
          "a quoted value after '=' is unquoted before it is judged")
    check(relative_paths("powershell.exe", r'-File C:\jobs\x.ps1 -config "my dir\a.json"')
          == ["my dir\\a.json"],
          "-config is not powershell's -c, so its quoted value stays one path  <-- pinned defect")
    for command, arguments in (("cmd.exe", r'/c "python.exe rebuild.py --full"'),
                               ("powershell.exe", r'-NoProfile -Command "python rebuild.py -v"')):
        check(finding_checks(job(start="", command=command, arguments=arguments))
              == [("Error", "start-in-missing")],
              "each word of a quoted %s body is judged on its own  <-- pinned defect"
              % ntpath.splitext(command)[0])
    for command, arguments in (
            ("cmd.exe", r"/c python.exe C:\jobs\etl.py > C:\logs\etl.log 2>&1"),
            ("cmd.exe", r"/c robocopy.exe C:\data C:\backup /MIR"),
            ("powershell.exe", r'-Command "python.exe C:\jobs\etl.py"'),
            ("cmd.exe", r"/c python.exe C:\jobs\etl.py >C:\logs\etl.log"),
            ("powershell.exe", r"-Command & 'C:\my jobs\sync.ps1'"),
            ("cmd.exe", r'/c "C:\Program Files\ArcGIS\Pro\bin\Python\Scripts\propy.bat" C:\j\x.py'),
            ("cmd.exe", r'/c "C:\tools\sync --all"'),
            ("cmd.exe", r'/c "C:\Program Files\Vendor\tool.exe" --full'),
            ("cmd.exe", r'/c "C:\Program Files\Vendor\tool.exe"'),
            ("cmd.exe", '/c ""')):
        check(finding_checks(job(start="", command=command, arguments=arguments))
              == [("Warning", "start-in-missing")],
              "no relative path in %s %s: a bare .exe is found on PATH, and a redirection, a "
              "quoted path with spaces and a rooted body are absolute  <-- pinned defect"
              % (command, arguments))
    check(finding_checks(job(start="", command=r"C:\t\x.exe", arguments=">>run.log"))
          == [("Error", "start-in-missing")], "a relative redirection target is still judged")
    # The secret-shaped values below never reach a label: a label says only what the case is.
    for form, command, arguments in (
            ("a quoted cmd /c body", "cmd.exe", '/c "sync.exe --password Hunter2/Secret"'),
            ("a quoted cmd /k body", "cmd.exe", '/k "sync.exe --password Hunter2/Secret"'),
            ("a quoted powershell -Command body", "powershell.exe",
             '-Command "Invoke-Sync -Token Hunter2/Secret"'),
            ("an unquoted cmd /c body", "cmd.exe", "/c sync.exe --password Hunter2/Secret"),
            ("an unquoted powershell -Command body", "powershell.exe",
             "-Command Invoke-Sync -Token Hunter2/Secret"),
            ("--pass", r"C:\tools\sync.exe", "--pass Hunter2/Secret"),
            ("plink's -pw", "plink.exe", "-batch -pw Hunter2/Secret svc@host"),
            ("--credential", r"C:\tools\sync.exe", "--credential Hunter2/Secret"),
            ("-apikey", r"C:\tools\sync.exe", "-apikey Hunter2/Secret"),
            ("a powershell -Command body inside a cmd /c body", "cmd.exe",
             '/c powershell -Command "Invoke-Sync -Token Hunter2/Secret"'),
            ("a powershell body after the abbreviation -comm", "powershell.exe",
             '-comm "Invoke-Sync -Password Hunter2/Secret"'),
            ("net use's password after the share", "net.exe",
             r"use \\fileserver\drop Hunter2/Secret /user:EXAMPLE\svc"),
            ("curl -u user:password", r"C:\Windows\System32\curl.exe",
             r"-u svc:Hunter2/Secret -o C:\x\out.csv https://example.test/x"),
            ("an Authorization header", r"C:\Windows\System32\curl.exe",
             r'-H "Authorization: Basic Hunter2/Secret" -o C:\x\out.csv https://example.test/x'),
            ("sqlcmd's one-letter -P", r"C:\tools\sqlcmd.exe",
             r"-U svc -P Hunter2/Secret -i C:\jobs\job.sql"),
            ("a quoted positional value", "powershell.exe",
             "-Command \"$p = ConvertTo-SecureString 'Hunter2/Secret' -AsPlainText\"")):
        check(all("Hunter2" not in f["detail"]
                  for f in lint_task(job(start="", command=command, arguments=arguments))),
              "the value of a secret switch in %s is never printed  <-- pinned defect" % form)
    for form, arguments in (
            ("a base64 value after -apikey", "-apikey //8AAAAc2VjcmV0/a2V5bWF0ZXJpYWw -user svc"),
            ("user:password@host after --src=", "--src=//svc:Hunter2@files/drop"),
            ("a base64 value with '+//' in it", "-data Zm9v+//YmFy/c2VjcmV0+dG9rZW4"),
            ("a connection string with '='", r"-conn Server=\\dbhost\gis;Password=Hunter2"),
            ("a share name ending in '='", r"--conn \\dbhost\Pa55+w0rd=")):
        check(finding_checks(job(logon="S4U", command=r"C:\tools\sync.exe",
                                 arguments=arguments)) == []
              and finding_checks(job(logon="", user="S-1-5-18", command=r"C:\tools\sync.exe",
                                     arguments=arguments)) == [],
              "%s never reaches the share check, so no finding prints it  <-- pinned defect"
              % form)
    # A body split with its own switch has no relative path left once the secret is dropped.
    for form, command, arguments in (
            ("a powershell body inside a cmd /c body", "cmd.exe",
             '/c powershell -Command "Invoke-Sync -Token Hunter2/Secret"'),
            ("a powershell -comm body", "powershell.exe",
             '-comm "Invoke-Sync -Password Hunter2/Secret"')):
        check(finding_checks(job(start="", command=command, arguments=arguments))
              == [("Warning", "start-in-missing")],
              "%s is split into its own words, so the secret in it is no relative path"
              "  <-- pinned defect" % form)
    for form, command, arguments in (
            ("net use with a password and a DOMAIN\\user", "net.exe",
             r"use \\fileserver\drop Hunter2/Secret /user:EXAMPLE\svc"),
            ("an account after --user", r"C:\tools\sync.exe", r"--user EXAMPLE\svc C:\jobs\a.csv"),
            ("curl -u user:password", r"C:\Windows\System32\curl.exe",
             r"-u svc:Hunter2/Secret -o C:\x\out.csv https://example.test/x")):
        check(finding_checks(job(start="", command=command, arguments=arguments)) == [],
              "%s names no relative path, so an empty Start In is no Error  <-- pinned defect"
              % form)
    unprinted = lint_task(job(start="", command=r"C:\tools\sync.exe", arguments="-data Zm9v/YmFy"))
    check([(f["severity"], f["check"]) for f in unprinted] == [("Error", "start-in-missing")]
          and "Zm9v" not in unprinted[0]["detail"] and "not printed" in unprinted[0]["detail"],
          "a path-like value with no file extension is judged but never printed, in case it is "
          "a secret  <-- pinned defect")
    for form, command, arguments in (
            ("-PassThru, which takes no value,", "powershell.exe",
             r'-NoProfile -Command "Start-Process -Wait -PassThru \\fileserver\gis\refresh.exe"'),
            ("--use-keyring, which takes no value,", r"C:\Python39\python.exe",
             r"C:\jobs\etl.py --use-keyring \\fileserver\gis\parcels.gdb"),
            ("--keyfile", r"C:\Python39\python.exe",
             r"C:\jobs\etl.py --keyfile \\fileserver\keys\x.pem")):
        found = lint_task(job(logon="S4U", command=command, arguments=arguments))
        check([(f["severity"], f["check"]) for f in found] == [("Error", "s4u-network")]
              and "fileserver" not in found[0]["detail"],
              "a share after %s still meets the S4U share check, and is not printed"
              "  <-- pinned defect" % form)
    check(finding_checks(job(logon="S4U", arguments=r"C:\jobs\a.py -apikey \\?\C:\keys\k"))
          == [], "a device path after a secret switch is not a share either")

    for why, command, arguments in (
            ("cmd's cd without /d keeps the drive", "cmd.exe",
             r"/c cd D:\gis && C:\Py\python.exe rebuild.py"),
            ("a /d after the folder is part of the folder", "cmd.exe",
             r"/c cd D:\gis /d && C:\Py\python.exe rebuild.py"),
            ("a cd with no folder changes nothing", "cmd.exe",
             r"/c cd && C:\Py\python.exe rebuild.py"),
            ("a cd with no folder before ';' changes nothing", "powershell.exe",
             r'-Command "cd ; C:\Py\python.exe rebuild.py"'),
            ("cmd's cd C: only prints the current folder", "cmd.exe",
             r"/c cd C: && C:\Py\python.exe rebuild.py"),
            ("cmd cannot cd to a share", "cmd.exe",
             r"/c cd \\fileserver\gis && C:\Py\python.exe rebuild.py"),
            ("cmd cannot cd /d to a share either", "cmd.exe",
             r"/c cd /d \\fileserver\gis && C:\Py\python.exe rebuild.py"),
            ("cd /d with no folder changes nothing", "cmd.exe",
             r"/c cd /d && C:\Py\python.exe rebuild.py"),
            ("a cd to a relative folder resolves against System32 itself", "cmd.exe",
             r'/c "cd scripts && rebuild.bat"'),
            ("a Set-Location to a relative folder resolves against System32 itself",
             "powershell.exe", r'-NoProfile -Command "Set-Location scripts; .\sync.ps1"'),
            ("cmd's cd without /d to a %VARIABLE% may leave the drive unchanged", "cmd.exe",
             r"/c cd %JOBS% && C:\Py\python.exe rebuild.py")):
        check(finding_checks(job(start="", command=command, arguments=arguments), ("C", "D"))
              == [("Error", "start-in-missing")], "%s  <-- pinned defect" % why)
    for command, arguments in (("cmd.exe", r"/c cd /d D:\gis && python.exe rebuild.py"),
                               ("cmd.exe", r"/c pushd D:\gis && python.exe rebuild.py"),
                               ("cmd.exe", r"/c pushd \\fileserver\gis && python.exe rebuild.py"),
                               ("cmd.exe", r"/c cd \gis && python.exe rebuild.py"),
                               ("cmd.exe", r"/c chdir C:\gis && python.exe rebuild.py"),
                               ("powershell.exe", r'-Command "cd D:\gis; python.exe rebuild.py"'),
                               ("cmd.exe", r"/c cd /d %JOBS% && python.exe rebuild.py"),
                               ("powershell.exe",
                                r'-Command "Set-Location -Path C:\gis; python.exe rebuild.py"'),
                               ("powershell.exe", r'-Command "cd $env:JOBS; python.exe rebuild.py"')):
        check(finding_checks(job(start="", command=command, arguments=arguments), ("C", "D"))
              == [], "%s %s changes directory first, so it is exempt" % (command, arguments))
    check(finding_checks(job(start="", command="powershell.exe",
                             arguments=r"-File run.ps1 -Tag dry-c cd C:\x"))
          == [("Error", "start-in-missing")],
          "a '-c' inside another word is not powershell's -c switch")
    check(split_args(r'--out="C:\my out\r.csv"') == [r'--out="C:\my out\r.csv"']
          and split_args(r'/LOG:"C:\my logs\x.txt" a') == [r'/LOG:"C:\my logs\x.txt"', "a"]
          and split_args(r"-Out='C:\my out\r.csv'") == [r"-Out='C:\my out\r.csv'"]
          and split_args("don't stop") == ["don't", "stop"]
          and split_args('a "b c') == ["a", '"b c"']
          and split_args('x "" y') == ["x", '""', "y"]
          and split_args("") == [],
          "a quote opens in the middle of a word, an apostrophe inside a name does not, and an "
          "unclosed quote is closed at the end of the line  <-- pinned defect")
    for why, command, arguments in (
            ("a quote attached to --out=", r"C:\Python39\python.exe",
             r'C:\jobs\etl.py --out="C:\my out\r.csv"'),
            ("a quote attached to /out:", r"C:\Python39\python.exe",
             r'C:\jobs\etl.py /out:"C:\my out\r.csv"'),
            ("a quote attached to /LOG:", "robocopy.exe",
             r'C:\a "C:\my b" /LOG:"C:\my logs\x.txt"'),
            ("cmd's doubled quote around a path with a space", "cmd.exe",
             r'/c ""C:\my jobs\x.bat""'),
            ("cmd's outer quote around a quoted program and a quoted redirect", "cmd.exe",
             r'/c ""C:\Program Files\app\run.bat" > "C:\my logs\o.txt" 2>&1"'),
            ("a single-quoted PowerShell value", "powershell.exe",
             r"-File C:\jobs\run.ps1 -Out='C:\my out\o.txt'")):
        check("Error" not in [severity for severity, _ in finding_checks(
            job(start="", command=command, arguments=arguments))],
              "%s is one value, not a relative path  <-- pinned defect" % why)
    check(finding_checks(job(start="", arguments=r'C:\jobs\refresh.py --out="reports\my out.csv"'))
          == [("Error", "start-in-missing")]
          and finding_checks(job(start="", command="cmd.exe",
                                 arguments=r'/c ""C:\jobs\x.bat" > "logs\my out.txt""'))
          == [("Error", "start-in-missing")],
          "a relative path inside a quote that holds a space is still judged")
    check(classify_command("powershell.exe", r"-File C:\jobs\run") == (
        r"C:\jobs\run", "PowerShellScript")
          and classify_command("powershell.exe", r"-f C:\jobs\run") == (
              r"C:\jobs\run", "PowerShellScript")
          and classify_command("powershell.exe", "-File") == ("powershell.exe", "PowerShell")
          and classify_command(r"C:\Python39\python.exe", "-m") == (
              r"C:\Python39\python.exe", "Python")
          and classify_command(r"C:\Python39\python.exe", "-m etl.run") == (
              "etl.run", "PythonModule"),
          "-File and -f name the script even without a .ps1, and a last -File or -m has no "
          "script to name")

    check(finding_checks(job(command="python.exe")) == [("Warning", "bare-program")],
          "a bare python.exe runs whichever python the account's PATH finds first")
    check(finding_checks(job(command='"python"')) == [("Warning", "bare-program")],
          "a quoted bare name is still bare")
    check(finding_checks(job(command="cmd.exe", arguments=r"/c C:\jobs\nightly.bat")) == [],
          "cmd.exe lives in System32, which is on every PATH")
    check(finding_checks(job(command="PowerShell", arguments=r"-File C:\jobs\sync.ps1")) == [],
          "a system program is recognised with no extension and in any case")
    check(finding_checks(job(command=r"%SystemRoot%\System32\cmd.exe",
                             arguments=r"/c C:\jobs\nightly.bat")) == [],
          "a program rooted at an environment variable is not bare")
    check(finding_checks(job(command="%PYTHON_EXE%")) == [],
          "a program given as one %VARIABLE% has a folder once expanded")
    check(finding_checks(job(command='"C:\\Program Files\\Vendor\\tool.exe"', arguments="")) == [],
          "a quoted absolute program path is fine: only Start In chokes on quotes")

    two = job()
    two["actions"] = two["actions"] + [{"executable": "python.exe", "arguments": "",
                                        "working_directory": r"C:\jobs"}]
    check(finding_checks(two) == [("Warning", "bare-program")],
          "every exec action is linted, not only the first")
    leaky = lint_task(job(command="sync.exe --password Hunter2x", arguments="", start=""))
    check(all("Hunter2x" not in f["detail"] for f in leaky)
          and any("sync.exe --password ***" in f["detail"] for f in leaky)
          and classify_command("sync.exe --password Hunter2x", "")
          == ("sync.exe --password ***", "Executable")
          and classify_command("python.exe", "-c x") == ("python.exe", "PythonInline")
          and classify_command(r"C:\Program Files\x\y.exe", "")
          == (r"C:\Program Files\x\y.exe", "Executable"),
          "a secret in the Command field is masked in the lint finding and in the target, and "
          "a path with spaces is not touched  <-- pinned defect")
    single = job(start="jobs")
    single["actions"] = single["actions"][0]
    check(finding_checks(single) == [("Error", "start-in-relative")],
          "a single action that ConvertTo-Json unwrapped to a bare object is still linted")
    check(lint_task({}) == [], "a task dict with nothing in it has nothing to find")

    # The interactive job has its own account: beside two stored-password jobs of one account
    # it would also be the logon-minority outlier, and this block is about the rows' order.
    lint_inventory = [job(logon="InteractiveToken", user="EXAMPLE\\svc-gis"),
                      dict(job(command="python.exe"), task_name="bare"),
                      dict(job(), task_name="clean"),
                      dict(job(start="jobs"), task_name="off", enabled=False)]
    linted = lint_rows(lint_inventory)
    check([(r["severity"], r["task"]) for r in linted]
          == [("Error", r"\Jobs\refresh"), ("Warning", r"\Jobs\bare")],
          "lint rows sort Errors first and leave clean tasks out")
    check(len(lint_rows(lint_inventory, show_ok=True)) == 3
          and lint_rows(lint_inventory, show_ok=True)[-1]["severity"] == "OK",
          "show_ok adds one OK row per clean task")
    check(all(r["task"] != r"\Jobs\off" for r in lint_rows(lint_inventory, show_ok=True)),
          "a disabled task is not linted: it cannot fail a run")
    lint_out = io.StringIO()
    write_output(linted, "table", lint_out, lint=True)
    check(lint_out.getvalue().startswith("SEVERITY") and "interactive-only" in
          lint_out.getvalue(), "the lint table has its own columns")
    check("does nothing when nobody is" in lint_out.getvalue(),
          "the lint table keeps a long detail whole")
    lint_csv = io.StringIO()
    write_output(linted, "csv", lint_csv, lint=True)
    check(lint_csv.getvalue().splitlines()[0] == "severity,task,check,detail"
          and len(lint_csv.getvalue().splitlines()) == 3, "lint csv has one row per finding")
    at_csv = io.StringIO()
    write_output(lint_rows([job(command="@SUM(1+1)*cmd")]), "csv", at_csv, lint=True)
    check(next(csv.DictReader(io.StringIO(at_csv.getvalue())))["detail"].startswith("'@SUM"),
          "a lint detail that starts with the task's own command cannot start a formula"
          "  <-- pinned defect")
    none_out = io.StringIO()
    write_output([], "table", none_out, lint=True)
    check(none_out.getvalue() == "No findings.\n", "an empty lint says so")

    # --- exported task XML: every shape Windows writes ---
    one = task_xml(logon="InteractiveToken")
    parsed = parse_task_xml(one)[0]
    check(parsed["task_path"] == "\\Jobs\\" and parsed["task_name"] == "refresh",
          "the URI splits into a task path and name that rejoin exactly")
    check(parsed["logon_type"] == "InteractiveToken" and parsed["run_as_user"] == "EXAMPLE\\svc-etl"
          and parsed["trigger_types"] == "Daily" and parsed["enabled"] is True,
          "logon type, account, calendar trigger and enabled flag are read")
    check(parsed["actions"] == [{"executable": r"C:\Python39\python.exe",
                                 "arguments": r"C:\jobs\refresh.py",
                                 "working_directory": r"C:\jobs"}],
          "the exec action carries its command, arguments and Start In")
    check(finding_checks(parsed) == [("Error", "interactive-only")],
          "an exported task lints exactly as a live one does")
    check(parse_task_xml(task_xml(namespace=False))[0]["task_name"] == "refresh",
          "a task with no namespace declaration parses the same")

    declared = '<?xml version="1.0" encoding="UTF-16"?>\r\n' + one
    check(decode_task_xml(declared.encode("utf-16")) == declared,
          "utf-16 with a BOM decodes, as System32\\Tasks and PowerShell 5 write it")
    check(parse_task_xml(decode_task_xml(declared.encode("utf-8")))[0]["task_name"] == "refresh",
          "utf-8 bytes whose declaration still says UTF-16 parse  <-- pinned defect")
    raises(lambda: ET.fromstring(declared.encode("utf-8")),
           "the stdlib parser alone refuses those same bytes", ET.ParseError)
    check(decode_task_xml(codecs.BOM_UTF8 + b"<Task/>") == "<Task/>",
          "a utf-8 BOM is dropped")
    check(decode_task_xml("<Task/>".encode("utf-16-le")) == "<Task/>",
          "utf-16 with no BOM is recognised by its zero bytes")
    check(decode_task_xml(codecs.BOM_UTF16_BE + one.encode("utf-16-be")) == one,
          "big-endian utf-16 with a BOM decodes")
    check(decode_task_xml(b"<Task><!-- caf\xe9 --></Task>") == u"<Task><!-- caf\xe9 --></Task>",
          "a console code page byte that is not utf-8 decodes rather than raising")

    schtasks = ("\r\n<Tasks>\r\n\r\n\r\n<!-- \\Jobs\\first -->\r\n\r\r\n%s\r\n"
                "<!-- \\Jobs\\second -->\r\n%s\r\n</Tasks>\r\n"
                % (task_xml(uri="").replace("><", ">\r\r\n<"),
                   task_xml(uri="", logon="S4U")))
    both = parse_task_xml(schtasks)
    check([full_task_name(t) for t in both] == [r"\Jobs\first", r"\Jobs\second"],
          "schtasks /query /xml names each task only in the comment before it")
    check(both[1]["logon_type"] == "S4U", "each task in the wrapper keeps its own principal")
    one_comment = "<Tasks><!-- \\Jobs\\first -->%s%s</Tasks>" % (task_xml(uri=""), task_xml(uri=""))
    check([full_task_name(t) for t in parse_task_xml(one_comment, "\\file")]
          == [r"\Jobs\first", r"\file"],
          "a comment names only the task after it, not every later task")
    pasted = "\n".join('<?xml version="1.0" encoding="UTF-16"?>\n' + task_xml(uri=u)
                       for u in ("\\a", "\\b"))
    check([t["task_name"] for t in parse_task_xml(pasted)] == ["a", "b"],
          "task documents pasted end to end, each with its own declaration, all parse")
    check(full_task_name(parse_task_xml(task_xml(uri=""), "\\Exports\\nightly")[0])
          == r"\Exports\nightly", "a task with no URI and no comment takes the file's name")
    check(split_task_uri("Jobs/refresh") == ("\\Jobs\\", "refresh"),
          "a URI with forward slashes and no leading separator is rooted")
    raises(lambda: parse_task_xml('<!DOCTYPE t [<!ENTITY a "a">]>' + one),
           "a DOCTYPE lands inside the wrapper element, where it is malformed, so no entity "
           "can expand")
    raises(lambda: parse_task_xml("<Task><Actions></Task>"), "malformed XML is a ValueError")
    raises(lambda: parse_task_xml("<Tasks></Tasks>"),
           "a file with no task in it is an error, not a clean lint")

    def triggers_of(inner):
        return parse_task_xml(task_xml(trigger=inner))[0]["trigger_types"]

    check(triggers_of("<CalendarTrigger><ScheduleByWeek/></CalendarTrigger>") == "Weekly",
          "a weekly calendar trigger reads as Weekly")
    check(schedule_bucket(triggers_of(
        "<CalendarTrigger><ScheduleByMonthDayOfWeek/></CalendarTrigger>")) == "Monthly",
        "a day-of-week monthly trigger buckets as Monthly")
    check(triggers_of("<CalendarTrigger><StartBoundary/></CalendarTrigger>") == "Calendar",
          "a calendar trigger with no schedule is still a calendar trigger")
    # The disaster check, once per unattended trigger kind, through the XML reader.
    for kind, inner in (("one time", "<TimeTrigger/>"),
                        ("weekly", "<CalendarTrigger><ScheduleByWeek/></CalendarTrigger>"),
                        ("monthly", "<CalendarTrigger><ScheduleByMonth/></CalendarTrigger>"),
                        ("monthly day-of-week",
                         "<CalendarTrigger><ScheduleByMonthDayOfWeek/></CalendarTrigger>"),
                        ("bare calendar", "<CalendarTrigger/>"), ("startup", "<BootTrigger/>"),
                        ("event", "<EventTrigger/>")):
        flipped = parse_task_xml(task_xml(logon="InteractiveToken", trigger=inner))[0]
        check(finding_checks(flipped) == [("Error", "interactive-only")],
              "an interactive-only script on a %s trigger is an Error" % kind)
    check(trigger_tokens(triggers_of("<TimeTrigger/><BootTrigger/><LogonTrigger/>"))
          == {"One Time", "Startup", "Logon"}, "time, boot and logon triggers map by name")
    check(triggers_of("<!-- none --><LogonTrigger/>") == " | Logon"
          and trigger_tokens(" | Logon") == {"Logon"},
          "a comment among the triggers adds nothing")
    check(parse_task_xml(task_xml(trigger=""))[0]["trigger_types"] == "",
          "a task with an empty Triggers element has no triggers")
    logon_now = parse_task_xml(task_xml(
        logon="InteractiveToken", trigger="<LogonTrigger><Enabled>true</Enabled></LogonTrigger>"
        "<CalendarTrigger><Enabled>false</Enabled><ScheduleByDay/></CalendarTrigger>"))[0]
    check(logon_now["trigger_types"] == "Logon" and finding_checks(logon_now) == [],
          "a disabled Daily trigger never fires, so a task left with a logon trigger is not "
          "interactive-only  <-- pinned defect")
    check(parse_task_xml(task_xml(enabled="false"))[0]["enabled"] is False,
          "a disabled export is read as disabled")
    check("<Enabled>" not in one and [r["check"] for r in lint_rows(parse_task_xml(one))]
          == ["interactive-only"] and parse_task_xml(task_xml(enabled="true"))[0]["enabled"],
          "an export with no <Enabled> element, as Windows writes every enabled task, is "
          "linted  <-- pinned defect")
    grouped = parse_task_xml(
        '<Task><Principals><Principal id="Users"><GroupId>S-1-5-32-545</GroupId></Principal>'
        '</Principals><Triggers><CalendarTrigger><ScheduleByDay/></CalendarTrigger></Triggers>'
        '<Actions Context="Users"><Exec><Command>C:\\jobs\\x.exe</Command></Exec>'
        '<ComHandler><ClassId>{0}</ClassId></ComHandler></Actions></Task>', "\\g")[0]
    check(grouped["logon_type"] == "Group" and grouped["run_as_user"] == "S-1-5-32-545",
          "a group principal with no logon type reads as a group logon")
    check(len(grouped["actions"]) == 1, "a COM handler action has no command line to lint")
    contexts = parse_task_xml(
        '<Task><Principals><Principal id="A"><UserId>EXAMPLE\\a</UserId>'
        '<LogonType>S4U</LogonType></Principal><Principal id="B"><UserId>EXAMPLE\\b</UserId>'
        '<LogonType>Password</LogonType></Principal></Principals>'
        '<Actions Context="B"/></Task>')[0]
    check(contexts["run_as_user"] == "EXAMPLE\\b" and contexts["logon_type"] == "Password",
          "the principal is the one Actions/@Context names, not the first listed")
    bare_task = parse_task_xml("<Task/>", "\\bare")[0]
    check(bare_task["actions"] == [] and bare_task["logon_type"] == ""
          and bare_task["run_as_user"] == "", "a task with no principal or actions parses empty")

    # --- exported XML: the settings, triggers and actions that --lint and --diff read ---
    detailed = parse_task_xml(task_xml(
        logon="InteractiveToken", limit="PT0S",
        settings="<MultipleInstancesPolicy>Parallel</MultipleInstancesPolicy><IdleSettings>"
                 "<Duration>PT10M</Duration></IdleSettings><!-- a note -->",
        trigger="<CalendarTrigger><!-- c --><StartBoundary>2026-01-01T02:00:00</StartBoundary>"
                "<EndBoundary>2026-06-01T00:00:00</EndBoundary><ScheduleByDay><DaysInterval>1"
                "</DaysInterval></ScheduleByDay></CalendarTrigger><LogonTrigger><Enabled>false"
                "</Enabled></LogonTrigger>").replace(
        "</Principal>", "<RunLevel>HighestAvailable</RunLevel></Principal>"))[0]
    check(detailed["settings"] == {"ExecutionTimeLimit": "PT0S",
                                   "MultipleInstancesPolicy": "Parallel",
                                   "IdleSettings.Duration": "PT10M"}
          and detailed["run_level"] == "HighestAvailable",
          "the XML reader keeps every Settings element as written, nested ones by dotted path, "
          "and the run level")
    check(detailed["trigger_details"] == [
        {"kind": "Daily", "enabled": True, "end_boundary": "2026-06-01T00:00:00",
         "leaves": [("EndBoundary", "2026-06-01T00:00:00"),
                    ("ScheduleByDay.DaysInterval", "1"),
                    ("StartBoundary", "2026-01-01T02:00:00")]},
        {"kind": "Logon", "enabled": False, "end_boundary": "", "leaves": [("Enabled", "false")]}],
        "each trigger keeps its kind, whether it is enabled, its end boundary and every field")
    check(detailed["action_details"] == [{"kind": "Exec", "leaves": [
        ("Arguments", r"C:\jobs\refresh.py"), ("Command", r"C:\Python39\python.exe"),
        ("WorkingDirectory", r"C:\jobs")]}],
        "each action keeps its kind and fields")
    empty_task = parse_task_xml("<Task/>", "\\bare")[0]
    check(empty_task["settings"] == {} and empty_task["trigger_details"] == []
          and empty_task["action_details"] == [] and empty_task["run_level"] == "",
          "a task with no Settings, triggers or actions parses empty")
    check(len(parse_task_xml(task_xml(trigger="<!-- none --><LogonTrigger/>"))[0][
        "trigger_details"]) == 1 and len(parse_task_xml(
            "<Task><Actions><!-- c --><Exec><Command>x</Command></Exec></Actions></Task>", "\\a")[
            0]["action_details"]) == 1,
        "a comment among the triggers or the actions is not one")

    # --- lint: the ways a task skips runs without an error ---
    def with_settings(**settings):
        return dict(job(), settings=settings)

    def check_names(task, **options):
        return [(f["severity"], f["check"]) for f in lint_task(task, **options)]

    unbounded = lint_task(with_settings(ExecutionTimeLimit="PT0S"))
    check([(f["severity"], f["check"]) for f in unbounded] == [("Warning", "no-time-limit")]
          and "every later launch is dropped without an error" in unbounded[0]["detail"]
          and "event 322" in unbounded[0]["detail"] and "PT0S (run indefinitely)"
          in unbounded[0]["detail"],
          "an unlimited run on a task with no MultipleInstancesPolicy is a Warning: the schema "
          "default, IgnoreNew, drops every later launch  <-- pinned defect")
    check("waits behind it" in lint_task(with_settings(
        ExecutionTimeLimit="PT0S", MultipleInstancesPolicy="Queue"))[0]["detail"]
        and "pile up beside it" in lint_task(with_settings(
            ExecutionTimeLimit="PT0S", MultipleInstancesPolicy="Parallel"))[0]["detail"]
        and "later launches are affected" in lint_task(with_settings(
            ExecutionTimeLimit="PT0S", MultipleInstancesPolicy="Weird"))[0]["detail"]
        and all("322" not in lint_task(with_settings(
            ExecutionTimeLimit="PT0S", MultipleInstancesPolicy=policy))[0]["detail"]
            for policy in ("Queue", "Parallel", "Weird")),
        "the finding says what the policy does to the launches behind a hung run, and names "
        "event 322 only where launches are dropped  <-- pinned defect")
    check(check_names(with_settings(ExecutionTimeLimit="PT0S",
                                    MultipleInstancesPolicy="StopExisting")) == []
          and check_names(with_settings(ExecutionTimeLimit="PT72H")) == []
          and check_names(with_settings(ExecutionTimeLimit="PT1H")) == []
          and check_names(with_settings()) == [] and check_names(job()) == [],
          "a hung run that the next launch stops, a limit, no setting at all and a task with "
          "no settings are no finding")
    check([unlimited(text) for text in ("PT0S", "pt0s", "P0D", "PT0H0M0S", "PT0.5S", "PT72H",
                                        "P1D", "abc", "")]
          == [True, True, True, True, False, False, False, False, False],
          "any ISO 8601 duration of zero is 'run indefinitely', and nothing else is")
    check(check_names(with_settings(ExecutionTimeLimit="PT0S", MultipleInstancesPolicy=""))
          == [("Warning", "no-time-limit")],
          "a live read that reports an empty policy gets the default policy too")
    check(effective_setting(with_settings(), "ExecutionTimeLimit") == "pt72h"
          and effective_setting(job(), "Priority") == "7"
          and effective_setting(with_settings(Priority="3"), "Priority") == "3",
          "an absent setting takes the documented default, 72 hours for the time limit")
    check([f["check"] for f in lint_task(with_settings(RunOnlyIfIdle="True"))]
          == ["run-conditions"]
          and "the computer is idle:" in lint_task(with_settings(RunOnlyIfIdle="True"))[0][
              "detail"]
          and "a network is available:" in lint_task(with_settings(
              RunOnlyIfNetworkAvailable="true"))[0]["detail"]
          and "the computer is idle and a network is available:" in lint_task(with_settings(
              RunOnlyIfIdle="true", RunOnlyIfNetworkAvailable="true"))[0]["detail"],
          "a task set to run only when idle or only with a network is a Warning, both are named")
    check(check_names(with_settings(RunOnlyIfIdle="False", RunOnlyIfNetworkAvailable="false"))
          == [], "the same settings switched off are no finding")

    def ending(*ends, enabled=True):
        return dict(job(), trigger_details=[{"kind": "Daily", "enabled": enabled,
                                             "end_boundary": end} for end in ends])

    expired = lint_task(ending("2026-06-01T00:00:00"), now=now)
    check([(f["severity"], f["check"]) for f in expired] == [("Warning", "trigger-expired")]
          and "2026-06-01T00:00Z" in expired[0]["detail"] and "0x00041304" in expired[0]["detail"],
          "a task whose every trigger has ended is a Warning that names the last end and the "
          "result code Task Scheduler gives it  <-- pinned defect")
    check(check_names(ending("2026-06-01T00:00:00")) == [],
          "no clock, no expiry check: lint_task without `now` never judges a trigger")
    check(check_names(ending("2026-07-27T13:00:00Z"), now=now) == []
          and check_names(ending("2026-07-27T11:00:00Z"), now=now) == [("Warning",
                                                                        "trigger-expired")],
          "a trigger counts as ended a day after its end, because a time with no zone is local")
    check(check_names(ending("2026-07-27T12:00:00Z"), now=now) == []
          and check_names(ending("2026-07-27T11:59:59Z"), now=now) == [("Warning",
                                                                        "trigger-expired")],
          "a trigger that ended exactly a day ago is not yet expired, one second more is")
    check(check_names(ending("2026-06-01T00:00:00", ""), now=now) == []
          and check_names(ending(""), now=now) == []
          and check_names(dict(job(), trigger_details=[]), now=now) == [],
          "one trigger with no end keeps the task alive, and a task with no triggers is no "
          "expiry")
    check(check_names(dict(job(), trigger_details=[
        {"kind": "Daily", "enabled": False, "end_boundary": "2026-06-01T00:00:00"},
        {"kind": "Logon", "enabled": True, "end_boundary": ""}]), now=now) == []
        and check_names(ending("2026-06-01T00:00:00", enabled=False), now=now) == [],
        "a disabled trigger does not count either way")
    check("2026-06-05T00:00Z" in lint_task(ending("2026-06-01T00:00:00+00:00",
                                                  "2026-06-05T00:00:00Z"), now=now)[0]["detail"],
          "the finding names the latest end among the triggers")
    check(check_names(dict(job(), trigger_details={"kind": "Daily", "enabled": True,
                                                   "end_boundary": "2026-06-01T00:00:00"}),
                      now=now) == [("Warning", "trigger-expired")],
          "a single trigger that ConvertTo-Json unwrapped to an object is still judged")
    ended_xml = parse_task_xml(task_xml(
        trigger="<TimeTrigger><StartBoundary>2026-01-01T02:00:00</StartBoundary><EndBoundary>"
                "2026-02-01T02:00:00</EndBoundary></TimeTrigger>"))
    check([row["check"] for row in lint_rows(ended_xml, now=now)] == ["trigger-expired"]
          and lint_rows(ended_xml) == [],
          "an exported task is judged the same way, and only when lint_rows has a clock")

    def named(name, logon, user="EXAMPLE\\svc-etl", folder="\\Jobs\\", **rest):
        return dict(job(logon=logon, user=user, triggers="Logon"), task_name=name,
                    task_path=folder, **rest)

    trio = [named("a", "Password"), named("b", "Password"), named("c", "InteractiveToken")]
    check(logon_minorities(trio) == {r"\Jobs\c": (
        "logon type interactive differs from the 2 other task(s) in this folder that run as "
        r"EXAMPLE\svc-etl, which use password: if this is not deliberate, a settings change "
        "flipped it")},
        "the one task whose logon type differs from two neighbours is named, with theirs")
    flagged = lint_rows(trio)
    check([(r["severity"], r["task"], r["check"]) for r in flagged]
          == [("Warning", r"\Jobs\c", "logon-minority")]
          and [r["severity"] for r in lint_rows(trio, show_ok=True)] == ["Warning", "OK", "OK"],
          "the lint reports it as a Warning, and a task with a finding gets no OK row")
    check(logon_minorities([named("a", "Password"), named("b", "InteractiveToken")]) == {}
          and logon_minorities([named("a", "Password")] * 1) == {}
          and logon_minorities([named("a", "Password"), named("b", "Password"),
                                named("c", "Password")]) == {},
          "two tasks differ with no majority, one task has no neighbour, and three that agree "
          "have no outlier")
    check(logon_minorities([named("a", "Password"), named("b", "Password"),
                            named("c", "InteractiveToken"), named("d", "InteractiveToken")])
          == {} and len(logon_minorities([named("a", "Password"), named("b", "Password"),
                                          named("c", "InteractiveToken"), named("d", "S4U")]))
          == 2,
          "a tie names nobody, and with two outliers against a pair both are named")
    check(logon_minorities([named("a", "Password"), named("b", "Password"),
                            named("c", "InteractiveToken", folder="\\Other\\")]) == {}
          and logon_minorities([named("a", "Password"), named("b", "Password"),
                                named("c", "InteractiveToken", user="EXAMPLE\\other")]) == {},
          "neighbours share a folder and an account")
    check(list(logon_minorities([named("a", "Password"), named("b", "Password"),
                                 named("c", "InteractiveToken", user="example\\SVC-ETL",
                                       folder="\\JOBS\\")])) == [r"\JOBS\c"],
          "folder and account are compared without regard to case")
    check(logon_minorities(trio[:2] + [named("c", "InteractiveToken", enabled=False)]) == {}
          and logon_minorities(trio[:2] + [named("c", "InteractiveToken", user="")]) == {}
          and logon_minorities(trio[:2] + [named("c", "Weird")]) == {}
          and logon_minorities(trio[:2] + [named("c", "S4U", folder="")]) == {}
          and list(logon_minorities([named("a", "Password", folder=""),
                                     named("b", "Password", folder=""),
                                     named("c", "S4U", folder="")])) == ["\\c"],
          "a disabled task, a task with no account, an unknown logon type and a task in another "
          "folder are no outlier, and a task with no folder is in the root folder")

    # --- diff: what changed between two exports of the same tasks ---
    def parsed(**kwargs):
        return parse_task_xml(task_xml(**kwargs))

    def changes(before, after, show_args=False):
        return [(r["change"], r["field"], r["old"], r["new"])
                for r in diff_tasks(before, after, show_args)]

    check(diff_tasks(parsed(), parsed()) == [] and diff_tasks([], []) == [],
          "two exports of one task differ in nothing")
    noisy = parse_task_xml(task_xml(namespace=False).replace(
        "<RegistrationInfo>", "<RegistrationInfo><Date>2026-01-01T00:00:00</Date><Author>x"
        "</Author><Description>d</Description>"))
    check(diff_tasks(parsed(), noisy) == [],
          "the namespace, the registration date, author and description are not a change")
    check(diff_tasks(parsed(), parsed(
        settings="<MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>"
                 "<DisallowStartIfOnBatteries>True</DisallowStartIfOnBatteries>"
                 "<Priority>7</Priority>", limit="PT72H")) == [],
          "a setting written out at its default, in any case, equals one left out  "
          "<-- pinned defect")
    check(changes(parsed(), parsed(settings="<DeleteExpiredTaskAfter>PT0S</DeleteExpiredTaskAfter>"))
          == [("changed", "setting DeleteExpiredTaskAfter", "", "PT0S")]
          and diff_tasks(parsed(settings="<DeleteExpiredTaskAfter>PT0S</DeleteExpiredTaskAfter>"),
                         parsed(settings="<DeleteExpiredTaskAfter>PT0S</DeleteExpiredTaskAfter>"))
          == [],
          "a task that gains DeleteExpiredTaskAfter PT0S is a change: Microsoft says an absent "
          "element means the task is never deleted, and PT0S deletes it at once  <-- pinned defect")
    check(diff_tasks(parsed(logon="Interactive", user="EXAMPLE\\SVC-ETL"),
                     parsed(logon="InteractiveToken")) == []
          and diff_tasks(parsed(logon="InteractiveTokenOrPassword"), parsed(logon="Password"))
          == [], "both spellings of a logon type, and an account in another case, are no change")
    task_name = r"\Jobs\refresh"
    check(diff_tasks(parsed(limit="PT1H"), parsed(limit="PT0S")) == [
        {"change": "changed", "task": task_name, "field": "setting ExecutionTimeLimit",
         "old": "PT1H", "new": "PT0S"}],
        "a changed setting is one row that names the field and both values")
    check(changes(parsed(), parsed(limit="PT0S")) == [
        ("changed", "setting ExecutionTimeLimit", "PT72H", "PT0S")]
        and changes(parsed(enabled="false"), parsed()) == [("changed", "enabled", "false", "true")],
        "a setting one export leaves out is shown at its default, and Enabled has its own name")
    check(changes(parsed(), parsed(logon="InteractiveToken")) == [
        ("changed", "logon type", "Password", "InteractiveToken")]
        and changes(parsed(), parsed(user="EXAMPLE\\svc-other")) == [
            ("changed", "run as", "EXAMPLE\\svc-etl", "EXAMPLE\\svc-other")],
        "a changed logon type or account is named, as the disaster in the README needs")
    check(changes(parsed(), parse_task_xml(task_xml().replace(
        "</Principal>", "<RunLevel>HighestAvailable</RunLevel></Principal>")))
        == [("changed", "run level", "", "HighestAvailable")],
        "a changed run level is named; an absent one has no documented default, so it shows "
        "as blank")
    daily_2 = ("<CalendarTrigger><StartBoundary>2026-01-01T02:00:00</StartBoundary>"
               "<ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay></CalendarTrigger>")
    daily_3 = daily_2.replace("02:00", "03:00")
    moved = changes(parsed(trigger=daily_2), parsed(trigger=daily_3))
    check(len(moved) == 1 and moved[0][:2] == ("changed", "trigger")
          and "StartBoundary=2026-01-01T02:00:00" in moved[0][2]
          and "StartBoundary=2026-01-01T03:00:00" in moved[0][3]
          and moved[0][2].startswith("Daily Enabled=true,"),
          "a moved trigger is one row with the old and the new schedule")
    boot = "<BootTrigger><Delay>PT1M</Delay></BootTrigger>"
    check(diff_tasks(parsed(trigger=daily_2 + boot), parsed(trigger=boot + daily_2)) == []
          and changes(parsed(trigger=daily_2), parsed(trigger=daily_2 + boot))
          == [("changed", "trigger", "", "Boot Delay=PT1M, Enabled=true")]
          and changes(parsed(trigger=daily_2 + boot), parsed(trigger=daily_2))
          == [("changed", "trigger", "Boot Delay=PT1M, Enabled=true", "")],
          "triggers are compared in any order, and an added or removed one is a row with a "
          "blank side")
    check(len(changes(parsed(trigger=boot), parsed(trigger=boot.replace(
        "<Delay>", "<Enabled>false</Enabled><Delay>")))) == 1,
        "a trigger that is switched off differs from one that is on")
    check(diff_tasks(parsed(trigger=boot + boot), parsed(trigger=boot)) != []
          and unmatched([("a", "A"), ("a", "A")], [("a", "A")]) == [("A", "")]
          and unmatched([], [("b", "B")]) == [("", "B")],
          "a trigger repeated twice is not matched by one")
    month = ("<CalendarTrigger><ScheduleByMonth><DaysOfMonth><Day>%d</Day><Day>28</Day>"
             "</DaysOfMonth><Months><January/></Months></ScheduleByMonth></CalendarTrigger>")
    weeks = ("<CalendarTrigger><ScheduleByMonthDayOfWeek><Weeks><Week>%s</Week><Week>4</Week>"
             "</Weeks><DaysOfWeek><Monday/></DaysOfWeek><Months><January/></Months>"
             "</ScheduleByMonthDayOfWeek></CalendarTrigger>")
    check(len(changes(parsed(trigger=month % 10), parsed(trigger=month % 15))) == 1
          and changes(parsed(trigger=month % 10), parsed(trigger=month % 10)) == []
          and len(changes(parsed(trigger=weeks % "1"), parsed(trigger=weeks % "2"))) == 1
          and "Day=10, ScheduleByMonth.DaysOfMonth.Day=28" in changes(
              parsed(trigger=month % 10), parsed(trigger=month % 15))[0][2],
          "a monthly trigger that moves one of its repeated Day or Week values is a change; "
          "the last value kept used to hide it  <-- pinned defect")
    check(parse_dt("9999-12-31T23:59:59-05:00") is None
          and parse_dt("9999-12-31T23:59:59Z") == datetime(9999, 12, 31, 23, 59, 59,
                                                            tzinfo=timezone.utc),
          "a timestamp past the last UTC instant is None, not an OverflowError  "
          "<-- pinned defect")
    check(changes(parsed(), parsed(command=r"C:\Python311\python.exe"), True) == [
        ("changed", "action 1", r"Exec C:\Python39\python.exe C:\jobs\refresh.py [Start In "
         r"C:\jobs]", r"Exec C:\Python311\python.exe C:\jobs\refresh.py [Start In C:\jobs]")]
        and changes(parsed(), parsed(arguments=r"C:\jobs\refresh.py --days 30"),
                    True)[0][3].endswith(r"refresh.py --days 30 [Start In C:\jobs]")
        and changes(parsed(start="C:\\jobs"), parsed(start="C:\\JOBS")) == [],
        "with --show-args, a changed program or argument is one row for that action, and a "
        "Start In in another case is no change")
    check(changes(parsed(), parsed(command=r"C:\Python311\python.exe")) == [
        ("changed", "action 1", r"Exec C:\Python39\python.exe [arguments not shown] [Start In "
         r"C:\jobs]", r"Exec C:\Python311\python.exe [arguments not shown] [Start In C:\jobs]")]
        and changes(parsed(), parsed(arguments=r"C:\jobs\refresh.py --days 30")) == [
            ("changed", "action 1", r"Exec C:\Python39\python.exe [arguments not shown] "
             r"[Start In C:\jobs]", r"Exec C:\Python39\python.exe [arguments not shown] "
             r"[Start In C:\jobs] (a value changed that is not printed)")],
        "by default the arguments are compared but not printed, and a changed one says so  "
        "<-- pinned defect")
    two = parse_task_xml(task_xml().replace(
        "</Exec></Actions>", "</Exec><Exec><Command>C:\\jobs\\after.bat</Command></Exec>"
                             "</Actions>"))
    check(changes(parsed(), two) == [("changed", "action 2", "", "Exec C:\\jobs\\after.bat")]
          and changes(two, parsed()) == [("changed", "action 2", "Exec C:\\jobs\\after.bat",
                                          "")],
          "an added or removed action is a row with a blank side, and a bare action has no "
          "Start In")
    handler = task_xml().replace("</Actions>", "<ComHandler><ClassId>{abc}</ClassId><Data>one"
                                               "</Data></ComHandler></Actions>")
    check(changes(parse_task_xml(handler), parse_task_xml(handler.replace("one", "two")))
          == [("changed", "action 2", "ComHandler {abc}",
               "ComHandler {abc} (a value changed that is not printed)")]
          and changes(parse_task_xml(handler), parse_task_xml(handler.replace(
              "<ClassId>{abc}</ClassId>", ""))) != []
          and describe_action({"kind": "ComHandler", "leaves": []}) == (("ComHandler", ()),
                                                                          "ComHandler"),
          "a COM handler is compared by every field and shown by its class id only")
    check(changes([], parsed()) == [("added", "", "", "")]
          and changes(parsed(), []) == [("removed", "", "", "")]
          and diff_tasks(parsed(uri="\\jobs\\REFRESH"), parsed()) == [],
          "a task in one export only is added or removed, and names match without regard to "
          "case")
    renamed = diff_tasks(parsed(uri="\\Jobs\\b"), parsed(uri="\\Jobs\\a"))
    check([(r["change"], r["task"]) for r in renamed] == [("added", r"\Jobs\a"),
                                                          ("removed", r"\Jobs\b")],
          "a rename is an added and a removed task, in name order")

    arcgis = r"C:\Program Files\ArcGIS\Pro\bin\Python\envs\arcgispro-py3\python.exe"
    flipped_arc = changes(parsed(command=arcgis), parsed(command=arcgis, logon="InteractiveToken"))
    check([row[1] for row in flipped_arc] == ["logon type", "arcpy-licence"]
          and "NotInitialized" in flipped_arc[1][3] and flipped_arc[1][3] == LICENCE_NOTE
          and len(LICENCE_NOTE) < 240,
          "a logon change on a task that runs ArcGIS Pro's Python also names the licence "
          "conditions  <-- pinned defect")
    check([row[1] for row in changes(parsed(command="cmd.exe", arguments='/c "C:\\Program Files'
                                           '\\ArcGIS\\Pro\\bin\\Python\\Scripts\\propy.bat" x.py'),
                                     parsed(command="cmd.exe", arguments='/c "C:\\Program Files'
                                            '\\ArcGIS\\Pro\\bin\\Python\\Scripts\\propy.bat" x.py',
                                            user="EXAMPLE\\other"))]
          == ["run as", "arcpy-licence"]
          and [row[1] for row in changes(parsed(arguments="-m arcgispro-py3"), parsed(
              arguments="-m arcgispro-py3", user="EXAMPLE\\other"))] == ["run as", "arcpy-licence"]
          and "arcpy-licence" in [row[1] for row in changes(
              parsed(command=arcgis), parse_task_xml(task_xml(command=arcgis).replace(
                  "</Principal>", "<RunLevel>HighestAvailable</RunLevel></Principal>")))],
          "propy, the arcgispro-py3 environment and a run level change all count")
    check([row[1] for row in changes(parsed(), parsed(logon="InteractiveToken"))]
          == ["logon type"]
          and changes(parsed(command=arcgis), parsed(command=arcgis, limit="PT0S"))
          == [("changed", "setting ExecutionTimeLimit", "PT72H", "PT0S")],
          "no licence note for another program, or for an ArcGIS task whose account and logon "
          "did not change")
    check([row[1] for row in changes(parsed(command=arcgis),
                                     parsed(command="cmd.exe", user="EXAMPLE\\other"))]
          == ["run as", "action 1", "arcpy-licence"]
          and [row[1] for row in changes(parsed(command="cmd.exe"),
                                         parsed(command=arcgis, user="EXAMPLE\\other"))]
          == ["run as", "action 1", "arcpy-licence"],
          "the licence note holds when ArcGIS Python is on only the old side or only the new")

    leaks = (
        ('-Password "correct horse battery"', ""),
        ("--passphrase 'correct horse battery'", ""),
        ('--password="correct horse battery"', ""),
        ('--api-key="abc def"', ""),
        (r"/c net use Z: \\srv\share Hunter2 /user:EX\svc && robocopy a b", "cmd"),
        (r'/c "net use Z: \\srv\share Hunter2 /user:EX\svc & robocopy a b"', "cmd"),
        ("-u svc:Hunter2 https://h/a", "curl"),
        ("--user svc:Hunter2 https://h/a", "curl"),
        ("--user=svc:Hunter2 https://h/a", "curl"),
        ('-H "X-Api-Key: Hunter2" https://h/a', "curl"),
        ('-H "Authorization: Bearer Hunter2" https://h/a', "curl"),
        ("-H X-Api-Key:Hunter2 https://h/a", "curl"),
        ("--authorization Hunter2", ""),
        ("a -pHunter2 out.7z", "7z"),
        ("-PHunter2 -S srv", "sqlcmd"),
        ("--pswd Hunter2", ""),
        ("--cred Hunter2", ""),
        ('-H "Cookie: sid=Hunter2"', "curl"),
        ("--proxy-user svc:Hunter2", "curl"),
        ("-U svc:Hunter2", "smbclient"),
        ("--sas Hunter2", ""),
        ("--sig Hunter2", ""),
        ("--pat Hunter2", ""),
        ("/RP Hunter2", ""),
        ("--login svc:Hunter2", ""),
        ("--signature Hunter2", ""),
        ("-EncodedCommand Hunter2", "powershell"),
        ("-k Hunter2", ""),
        ('--data {"password":"Hunter2"}', "curl"),
        ('--data {"user": "svc", "client_secret": "Hunter2", "n": 1}', ""),
        ("--data {\\\"api_key\\\":\\\"Hunter2\\\"}", ""),
        ("--data {\"token\":Hunter2}", ""))
    check(all("Hunter2" not in mask_arguments(line, program) and "***" in mask_arguments(
        line, program) for line, program in leaks),
          "a quoted or attached secret, a net command inside a cmd /c body, curl's -u and "
          "-H, -pSECRET, --pswd, --cred, --signature, -EncodedCommand, -k and a JSON password, secret, "
          "token or key member are all masked  <-- pinned defect")
    check(mask_arguments('--data {"author":"bob","n":5}') == '--data {"author":"bob","n":5}',
          "a JSON member whose name only looks like a secret, such as author, is left alone")
    spaced = mask_arguments('/i x.msi TARGETDIR="C:\\Program Files\\App" PASSWORD="a b" x"y z"')
    check(spaced == '/i x.msi TARGETDIR="C:\\Program Files\\App" PASSWORD=*** "***"'
          and mask_arguments('K="a b" tool') == 'K="a b" tool',
          "a word with a quoted space, such as msiexec's TARGETDIR=\"C:\\Program Files\\App\", "
          "does not recurse for ever, and a secret in one is still masked  <-- pinned defect")
    check(all("Hunter2" in mask_arguments(line) for line in (
        "-usvc:Hunter2", "-U svc%Hunter2", "--password -Hunter2", '-H "X-Custom: Hunter2"', "-uHunter2")),
          "the documented gaps: these forms still print in full, so the README lists them")
    check(mask_arguments(r"/c net use Z: \\srv\share Hunter2 && robocopy a b", "cmd")
          == "/c net *** *** *** *** && robocopy a b"
          and mask_arguments('-Password "correct horse battery" -Name x', "")
          == '-Password "***" -Name x'
          and mask_arguments("--user svc --out r.csv -u C:\\jobs\\a.py", "")
          == "--user svc --out r.csv -u C:\\jobs\\a.py"
          and mask_arguments(r"-Path C:\x -Port 80 --author Ann", "")
          == r"-Path C:\x -Port 80 --author Ann"
          and mask_arguments('--out="C:\\my out\\r.csv"', "") == '--out="C:\\my out\\r.csv"',
          "the masks leave the rest of the line as it was: a net command ends at the next "
          "&, a user with no password, a path, a port and --author print")
    check("Hunter2" not in shown_program(r'C:\tools\sync.exe -Password "a b" --token Hunter2')
          and "Hunter2" not in " ".join(
              f["detail"] for f in lint_task(job(command=r'sync.exe -Password "a b" --token Hunter2',
                                                 arguments=""))),
          "a command line in the Command field is masked in the health report's target and "
          "in the bare-program finding  <-- pinned defect")
    diffed = changes(parsed(command="cmd.exe", arguments=r"/c net use Z: \\srv\s Hunter2OLD"),
                     parsed(command="cmd.exe", arguments=r"/c net use Z: \\srv\s Hunter2NEW"))
    check(len(diffed) == 1 and "Hunter2" not in repr(diffed),
          "--diff of a net use inside cmd /c prints neither password  <-- pinned defect")
    secret_line = ("-password Hunter2 --token=abc123 /pw:Secret9 -apikey QUJD+RA== data.csv "
                   "-x 5")
    check(mask_arguments(secret_line) == "-password *** --token=*** /pw:*** -apikey *** "
          "data.csv -x 5", "the value of every secret switch is masked, and nothing else")
    check(mask_arguments(r'/c "set PGPASSWORD=Hunter2&& C:\jobs\run.bat"')
          == r'/c "set ***&& C:\jobs\run.bat"'
          and mask_arguments("--out=r.csv -Name=foo+bar //host/share /var/log")
          == "--out=r.csv -Name=*** //host/share /var/log"
          and mask_arguments(r'"C:\Program Files\x\y.exe"') == r'"C:\Program Files\x\y.exe"'
          and mask_arguments("") == "",
          "a secret in a cmd /c body is masked word by word, a base64-looking value is masked, "
          "and a path, a share and a plain switch are left alone")
    check(mask_arguments("https://svc:Hunter2@host/api --url=ftp://a:Pw9@h/")
          == "https://svc:***@host/api --url=ftp://a:***@h/"
          and mask_arguments("https://host/api@c") == "https://host/api@c",
          "the password in a URL is masked, wherever the URL sits, and a URL with no password is "
          "not touched  <-- pinned defect")
    check(mask_arguments(r"use \\srv\share Pa55word", "net") == "***"
          and mask_arguments("", "net") == "",
          "every argument of net is masked: it takes its password by position")
    check(mask_arguments("-S srv -U sa -P Hunter2x") == "-S srv -U sa -P ***"
          and mask_arguments("-p Hunter2y -x 5") == "-p *** -x 5"
          and mask_arguments("--auth Bearer_abc --author bob") == "--auth *** --author bob"
          and mask_arguments("-S srv -U sa") == "-S srv -U sa",
          "the value of -P, -p and --auth is masked, and --author and other letters are not  "
          "<-- pinned defect")

    def secretive(args, command="C:\\jobs\\tool.exe", show_args=True):
        return changes(parsed(command=command, arguments=args[0]),
                       parsed(command=command, arguments=args[1]), show_args)

    shown = []
    for pair_of_args, command in (
            ((secret_line, secret_line.replace("Hunter2", "Hunter3")), "C:\\jobs\\tool.exe"),
            ((r"use \\srv\share Pa55word", r"use \\srv\share Pa66word"), "net.exe"),
            ((r'/c "set PGPASSWORD=Hunter2&amp;&amp; C:\jobs\run.bat"',
              r'/c "set PGPASSWORD=Hunter3&amp;&amp; C:\jobs\run.bat"'), "cmd.exe"),
            (("--password Hunter2", "--password Hunter3"), "C:\\jobs\\sync.exe --apikey QUJD+RA=="),
            (("-S srv -U sa -P Hunter2x", "-S srv -U sa -P Hunter3x"), "sqlcmd.exe"),
            (("-p Hunter2y", "-p Hunter3y"), "mysql.exe"),
            (("--auth Bearer_abc123tok", "--auth Bearer_abc124tok"), "C:\\jobs\\sync.exe")):
        rows = secretive(pair_of_args, command)
        shown.append(rows)
        for fmt in ("table", "csv", "json"):
            out = io.StringIO()
            write_output(diff_tasks(parsed(command=command, arguments=pair_of_args[0]),
                                    parsed(command=command, arguments=pair_of_args[1]),
                                    show_args=True),
                         fmt, out, diff=True)
            leaked = [word for word in ("Hunter2", "Hunter3", "abc123", "abc124", "Secret9", "QUJD",
                                        "Pa55word", "Pa66word", "PGPASSWORD=Hunter")
                      if word in out.getvalue()]
            check(not leaked, "no secret reaches the %s diff of command line %d  "
                  "<-- pinned defect" % (fmt, len(shown)))
    check(all(len(rows) == 1 and rows[0][3].endswith("(a value changed that is not printed)")
              for rows in shown),
          "a change to a secret is reported as a change, with the value left out  "
          "<-- pinned defect")

    # Shapes the mask does not know. The default diff never prints arguments, so none can leak.
    unknown = (
        ("https://hooks.example.com/services/T0AAAAAAA/B0BBBBBBB/Zq9XvR2mLpW4sTn8", "curl.exe"),
        ("-c \"import svc; svc.login('Zq9XvR2mLpW4sTn8')\"", "python.exe"),
        ("etl.py Zq9XvR2mLpW4sTn8", "python.exe"),
        ("scott/Zq9XvR2mLpW4sTn8@db @run.sql", "sqlplus.exe"),
        ("--dsn Zq9XvR2mLpW4sTn8 --pin 4471", "etl.exe"),
        ("-Command \"$p = 'Zq9XvR2mLpW4sTn8'; Connect-Svc -Password (ConvertTo-SecureString "
         "'Zq9XvR2mLpW4sTn8' -AsPlainText)\"", "powershell.exe"),
        ("/c start /b run.bat Zq9XvR2mLpW4sTn8", "cmd.exe"))
    for index, (line, command) in enumerate(unknown):
        for fmt in ("table", "csv", "json"):
            out = io.StringIO()
            write_output(diff_tasks(parsed(command=command, arguments=line),
                                    parsed(command=command, arguments=line + "x")),
                         fmt, out, diff=True)
            check("Zq9X" not in out.getvalue() and "4471" not in out.getvalue()
                  and "(a value changed that is not printed)" in out.getvalue(),
                  "a secret in a shape the mask does not know, %d, stays out of the %s diff and "
                  "the change is still reported  <-- pinned defect" % (index + 1, fmt))

    diff_out = io.StringIO()
    write_output(diff_tasks(parsed(limit="PT1H"), parsed(limit="PT0S")), "table", diff_out,
                 diff=True)
    check(diff_out.getvalue().startswith("CHANGE") and "setting ExecutionTimeLimit"
          in diff_out.getvalue(), "the diff table has its own columns")
    empty_diff = io.StringIO()
    write_output([], "table", empty_diff, diff=True)
    check(empty_diff.getvalue() == "No differences.\n", "an empty diff says so")
    diff_csv = io.StringIO()
    write_output(diff_tasks(parsed(command="C:\\jobs\\a.exe"), parsed(command="C:\\jobs\\b.exe")),
                 "csv", diff_csv, diff=True)
    cells = next(csv.DictReader(io.StringIO(diff_csv.getvalue())))
    check(diff_csv.getvalue().splitlines()[0] == "change,task,field,old,new"
          and cells["field"] == "action 1" and cells["new"].startswith("Exec C:\\jobs\\b.exe"),
          "the diff csv has its own header")
    formula = io.StringIO()
    write_output([{"change": "changed", "task": "=x", "field": "f", "old": "-1", "new": "@y"}],
                 "csv", formula, diff=True)
    cells = next(csv.DictReader(io.StringIO(formula.getvalue())))
    check(cells["task"] == "'=x" and cells["old"] == "'-1" and cells["new"] == "'@y",
          "a diff cell a spreadsheet would run as a formula is written as text")

    # --- the live read asks for what the lint judges ---
    live_script = []
    module["run_powershell"] = lambda script, timeout, what: live_script.append(script) or []
    try:
        read_tasks()
    finally:
        module["run_powershell"] = real_bridge
    check("MultipleInstancesPolicy   = [string]$task.Settings.MultipleInstances" in live_script[0]
          and "ExecutionTimeLimit        = [string]$task.Settings.ExecutionTimeLimit"
          in live_script[0] and "RunOnlyIfIdle             = [string]$task.Settings.RunOnlyIfIdle"
          in live_script[0] and "end_boundary = [string]$g.EndBoundary" in live_script[0]
          and 'catch { $failed += "settings" }' in live_script[0]
          and "trigger_details       = $triggerDetails" in live_script[0]
          and "settings              = $settings" in live_script[0],
          "the live query asks for the policy, the time limit, the idle and network conditions "
          "and each trigger's end, under the schema's names, and names a settings read that "
          "failed")

    # --- files and folders, then the command line end to end ---
    scratch = tempfile.mkdtemp(prefix="taskpulse-selftest-")
    try:
        folder = os.path.join(scratch, "Tasks", "Jobs")
        os.makedirs(folder)
        with open(os.path.join(folder, "nightly"), "wb") as handle:
            handle.write(task_xml(uri="", logon="InteractiveToken").encode("utf-16"))
        loose = os.path.join(scratch, "export.XML")
        with open(loose, "wb") as handle:
            handle.write(task_xml(uri="", command="python.exe").encode("utf-8"))
        broken = os.path.join(scratch, "broken.xml")
        with open(broken, "wb") as handle:
            handle.write(b"<Tasks/>")
        from_files = read_task_files([os.path.join(scratch, "Tasks"), loose])
        check([full_task_name(t) for t in from_files] == [r"\Jobs\nightly", r"\export"],
              "a folder is walked like System32\\Tasks and names come from relative paths")
        raises(lambda: read_task_files([broken]), "a bad file stops the read")
        try:
            read_task_files([broken])
        except ValueError as error:
            check(str(error).startswith(broken), "the error names the file that failed")
        empty = os.path.join(scratch, "empty")
        os.makedirs(os.path.join(empty, "sub"))
        raises(lambda: read_task_files([empty]),
               "a folder with no task file in it is an error, not a clean lint  <-- pinned defect")

        def locked_walk(path, onerror):
            # What os.walk does with a subfolder it cannot list: hand the error to onerror.
            return onerror(PermissionError(13, "Permission denied", os.path.join(path, "locked")))

        raises(lambda: read_task_files([os.path.join(scratch, "Tasks")], walk=locked_walk),
               "a subfolder the walk cannot list stops the read, not a clean lint"
               "  <-- pinned defect", PermissionError)
        linked_walk = [(folder, ["kept", "linked"], ["nightly"])]
        raises(lambda: read_task_files([folder],
                                       walk=lambda path, onerror: linked_walk,
                                       islink=lambda path: path.endswith("linked")),
               "a subfolder that is a symbolic link, which the walk lists but never enters, "
               "stops the read  <-- pinned defect")
        check(same_file(os.path.join(scratch, "gone"), loose) is False,
              "the --out guard compares a name with nothing behind it as no match, not a "
              "traceback  <-- pinned defect")
        backwards = [(folder, [], ["zeta", "nightly"])]
        with open(os.path.join(folder, "zeta"), "wb") as handle:
            handle.write(task_xml(uri="").encode("utf-8"))
        check([t["task_name"] for t in read_task_files(
            [folder], walk=lambda path, onerror: backwards)] == ["nightly", "zeta"],
            "files are read in name order, whatever order the walk returns them in")
        os.remove(os.path.join(folder, "zeta"))
        cwd = os.getcwd()
        os.chdir(scratch)
        try:
            check(full_task_name(read_task_files(["export.XML"])[0]) == r"\export",
                  "a bare file name in the current folder names its task after the file")
        finally:
            os.chdir(cwd)

        stock = dict(base, task_path="\\Microsoft\\Windows\\X\\", task_name="stock",
                     last_task_result=0x80070002, logon_type="S4U",
                     actions=[{"executable": "tool.exe"}])
        later = dict(base, next_run_time="2999-01-01T02:00:00+00:00")  # main reads the clock
        live = [dict(later, task_path="\\Jobs\\", task_name="etl", logon_type="Password",
                     actions=[{"executable": r"C:\jobs\etl.exe", "working_directory": "C:\\"}]),
                dict(later, task_path="\\Jobs\\", task_name="broken", last_task_result=0x80070002,
                     logon_type="InteractiveToken",
                     actions=[{"executable": "python.exe", "arguments": "etl.py"}]),
                stock]
        history = [event(100, 1, task=r"\Jobs\etl", record_id=70),
                   event(102, 2, task=r"\Jobs\etl", record_id=71),
                   event(100, 1, task=r"\Elsewhere\x", record_id=90)]

        def cli(*argv):
            out, err = io.StringIO(), io.StringIO()
            with redirect_stdout(out), redirect_stderr(err):
                try:
                    code = main(list(argv))
                except SystemExit as stop:  # argparse's own exit, for usage and --version
                    code = stop.code
            return code, out.getvalue(), err.getvalue()

        def unavailable(*args, **kwargs):
            raise RuntimeError("Task Scheduler is not reachable")

        def serve(rows, **span):
            """A read_run_events stub: `rows` from a log of 30 days that ends at their newest."""
            log = dict(log_oldest_record_id=1, log_oldest_time_utc=(
                datetime.now(timezone.utc) - timedelta(days=30)).isoformat(),
                log_newest_record_id=max([row["event_record_id"] for row in rows] or [1]))
            log.update(span)
            return lambda days, since=None, timeout=120: (list(rows), dict(log))

        real_readers = read_tasks, read_run_events
        try:
            module["read_tasks"] = lambda timeout=120: [dict(t) for t in live]
            module["read_run_events"] = serve(history)
            code, out, err = cli()
            check(code == 2 and r"\Jobs\broken" in out and r"\Jobs\etl" not in out
                  and "stock" not in out,
                  "the health report shows the failing task, hides the healthy one and "
                  "microsoft's, and exits 2")
            code, out, err = cli("--all")
            check("stock" in out, "--all includes \\Microsoft\\ tasks")
            code, out, err = cli("--show-ok", "--format", "json")
            check(code == 2 and len(json.loads(out)) == 2, "--show-ok adds the healthy task")
            code, out, err = cli("--match", "etl$", "--show-ok")
            check(code == 0 and r"\Jobs\broken" not in out,
                  "--match scopes the report and the exit code with it")
            code, out, err = cli("--match", "nothing")
            check(code == 1 and out == "" and "matched no task" in err,
                  "the health report --match that matches no task is not 'No tasks need "
                  "attention'  <-- pinned defect")
            code, out, err = cli("--history", "--match", "nothing")
            check(code == 1 and out == "" and "matched no task" in err and "read " not in err,
                  "--history --match that matches no task stops before the log is read")
            check(cli("--history", "7")[0] != 64 and cli("--history", "--stuck-hours", "1")[0] != 64
                  and cli("--history", "--stuck-hours", "0")[0] == 64,
                  "--history 7 and --stuck-hours 1 are the smallest accepted values")
            code, out, err = cli("--history", "--since-record-id", "50")
            check("read 3 run event(s)" in err and "--since-record-id 90" in err,
                  "--history reports the watermark over every event read, joined or not")
            check("cap" not in err, "a read below the event cap says nothing about a cap")
            clock = datetime.now(timezone.utc)  # main reads the clock, so this week is real

            def ago(hours, event_id, run_id, record_id, result_code=None):
                return {"event_id": event_id, "instance_id": run_id,
                        "task_full_name": r"\Jobs\etl", "event_record_id": record_id,
                        "event_time_utc": (clock - timedelta(hours=hours)).isoformat(),
                        "result_code": result_code}

            week = []  # newest first, as a cold start reads: green tonight, two failed nights
            for night, code in enumerate((0, 1, 1)):
                hours, top = 2 + 24 * night, 1000 - 3 * night
                week += [ago(hours - 1, 102, "w%d" % night, top),
                         ago(hours - 1, 201, "w%d" % night, top - 1, code),
                         ago(hours, 100, "w%d" % night, top - 2)]
            real_cap = HISTORY_MAX_EVENTS  # read now, before the global is patched
            module["HISTORY_MAX_EVENTS"] = 3
            try:
                code, out, err = cli("--history", "--since-record-id", "50")
                check("read 3 run event(s)" in err and "cap" not in err,
                      "a read of exactly the cap left nothing unread, so it is not called "
                      "incomplete  <-- pinned defect")
                module["HISTORY_MAX_EVENTS"] = 2
                code, out, err = cli("--history", "--since-record-id", "50", "--match", "etl")
                check(code == 1 and "read 2 run event(s)" in err and "incomplete" in err
                      and "stopped at the 2-event cap" in err and "--since-record-id 71" in err,
                      "a watermark read that left events unread exits 1, never 0, and the next "
                      "run continues past the last event it kept  <-- pinned defect")
                code, out, err = cli("--history", "--since-record-id", "0", "--match", "etl")
                check(code == 1 and "newer events were not read" in err,
                      "a capped read past a watermark of 0 is incomplete too, not a cold start")
                code, out, err = cli("--history")
                check(code == 2 and "7-day columns are complete" in err,
                      "a capped cold read that still reaches back 7 days is complete, and says "
                      "its baseline is short")
                module["read_run_events"] = serve(week)
                code, out, err = cli("--history", "--match", "etl")
                check(code == 1 and "miss the older runs" in err and "incomplete" in err,
                      "a capped cold read that does not reach back 7 days exits 1, never a "
                      "clean report  <-- pinned defect")
                code, out, err = cli("--history", "--show-ok", "--format", "json", "--match",
                                     "etl")
                check(json.loads(out)[0]["history"] == "incomplete"
                      and "run history incomplete" in json.loads(out)[0]["reason"],
                      "a capped cold read marks its json rows incomplete  <-- pinned defect")
                module["read_run_events"] = serve([
                    ago(1, 102, "n", 30), ago(156, 100, "n", 20), ago(170, 100, "o", 10)])
                code, out, err = cli("--history", "--match", "etl")
                check(code == 1 and "miss the older runs" in err,
                      "a capped cold read that reaches back 6.5 days, not 7, is incomplete too")
                module["read_run_events"] = serve([
                    ago(1, 102, "n", 30), ago(170, 100, "n", 20), ago(180, 100, "o", 10)])
                code, out, err = cli("--history", "--match", "etl")
                check("7-day columns are complete" in err and "miss the older runs" not in err,
                      "a capped cold read of recent events whose oldest kept event is just over "
                      "7 days old is complete")
                module["read_run_events"] = serve(week)
            finally:
                module["HISTORY_MAX_EVENTS"] = real_cap
            code, out, err = cli("--history")
            check(code == 2 and r"\Jobs\etl" in out
                  and "2 of 3 run(s) in the last 7 days failed" in out,
                  "the default report keeps a task whose last run was green but whose week "
                  "was not  <-- pinned defect")
            module["read_run_events"] = serve(week[::-1])
            code, out, err = cli("--history", "--since-record-id", "500", "--match", "etl")
            check(code == 0 and "2 of 3 run(s) since record 500 failed" in out,
                  "a watermark run says its columns start at the watermark  <-- pinned defect")
            # --- run fate, end to end through the command line ---
            module["read_tasks"] = lambda timeout=120: [dict(t, state="Running") for t in live]
            module["read_run_events"] = serve([ago(40, 100, "hung", 2000),
                                               ago(39, 200, "hung", 2001)])
            code, out, err = cli("--history", "--match", "etl", "--format", "json")
            hung_row = json.loads(out)[0]
            check(code == 0 and hung_row["fate"] == "STUCK" and hung_row["status"] == "Warning"
                  and "STUCK: a run started 40.0 hour(s) ago has not finished"
                  in hung_row["reason"] and hung_row["blocked_launches_last_7_days"] == 0
                  and "read 2 run event(s)" in err,
                  "a run with no end event for 40 hours on a Running task is a STUCK Warning in "
                  "the default report, and a Warning never makes the exit code non-zero")
            code, out, err = cli("--history", "--match", "etl")
            check("STUCK" in out and out.startswith("STATUS"),
                  "the STUCK reason reaches the table too")
            code, out, err = cli("--history", "--match", "etl", "--stuck-hours", "48",
                                 "--show-ok", "--format", "json")
            check(json.loads(out)[0]["fate"] == "",
                  "--stuck-hours 48 leaves a 40-hour run alone")
            module["read_tasks"] = lambda timeout=120: [dict(t) for t in live]
            code, out, err = cli("--history", "--match", "etl", "--show-ok", "--format", "json")
            check(json.loads(out)[0]["fate"] == "" and json.loads(out)[0]["status"] == "Success",
                  "the same events on a task whose state is Ready are a lost end event, not a "
                  "stuck run  <-- pinned defect")
            bad_flags = [cli("--stuck-hours", "5")[0], cli("--history", "--stuck-hours", "0")[0],
                       cli("--history", "--stuck-hours", "x")[0], cli("--stuck-h", "5",
                                                                    "--history")[0]]
            code, out, err = cli("--stuck-hours", "5")
            check(bad_flags == [64] * 4 and "needs --history" in err
                  and "must be 1 or more" in cli("--history", "--stuck-hours", "0")[2],
                  "--stuck-hours without --history, below 1, not a number, or typed as a "
                  "prefix is a usage error  <-- pinned defect")
            module["read_run_events"] = serve([
                ago(30, 100, "late", 2998), ago(29, 102, "late", 2999),
                {"event_id": 332, "instance_id": "", "task_full_name": r"\Jobs\etl",
                 "event_record_id": 3000, "result_code": None,
                 "event_time_utc": (clock - timedelta(hours=5)).isoformat()}])
            code, out, err = cli("--history", "--match", "etl", "--format", "json")
            blocked_row = json.loads(out)[0]
            check(code == 0 and blocked_row["fate"] == "BLOCKED"
                  and blocked_row["blocked_launches_last_7_days"] == 1
                  and "event 332" in blocked_row["reason"] and "read 3 run event(s)" in err,
                  "a launch refused after the task's last run leaves it BLOCKED, and the report "
                  "counts the refusal")
            code, out, err = cli("--history", "--match", "etl")
            check("BLOCKED" in out, "BLOCKED shows in the table")
            code, out, err = cli("--history", "--show-ok", "--format", "csv", "--match", "etl")
            cells = list(csv.DictReader(io.StringIO(out)))[0]
            check(cells["fate"] == "BLOCKED" and cells["blocked_launches_last_7_days"] == "1",
                  "the CSV carries the fate columns")
            code, out, err = cli("--show-ok", "--format", "json", "--match", "etl")
            check(json.loads(out)[0]["fate"] == "",
                  "without --history there is no fate to report")

            module["read_run_events"] = real_readers[1]
            refused = read_error("System.UnauthorizedAccessException,Microsoft.PowerShell."
                                 "Commands.GetWinEventCommand",
                                 "Attempted to perform an unauthorized operation.")
            module["run_powershell"] = lambda script, timeout, what: [span_of(1, 50)] + refused
            code, out, err = cli("--history", "--since-record-id", "10", "--match", "etl")
            check(code == 1 and "UnauthorizedAccessException" in err
                  and "next run can pass" not in err,
                  "access denied after the range row exits 1 and never moves the watermark  "
                  "<-- pinned defect")
            module["run_powershell"] = lambda script, timeout, what: refused
            code, out, err = cli("--history")
            check(code == 2 and r"\Jobs\broken" in out and "UnauthorizedAccessException" in err
                  and "no run history" in err and "read 0" not in err,
                  "an access-denied history read names the error, still prints the snapshot "
                  "and keeps the Error task's exit 2  <-- pinned defect")
            code, out, err = cli("--history", "--match", "etl")
            check(code == 1 and "UnauthorizedAccessException" in err,
                  "an access-denied history read with no task in Error exits 1, never 0")
            code, out, err = cli("--history", "--show-ok", "--match", "etl")
            check("run history unread" in out,
                  "an access-denied history read says 'run history unread' in the table too")
            denied = cli("--history", "--show-ok", "--format", "json", "--match", "etl")[1]
            module["run_powershell"] = lambda script, timeout, what: read_error(
                "LogDisabled", "the log is disabled, so it holds no run history")
            code, out, err = cli("--history", "--since-record-id", "50", "--match", "etl")
            check(code == 1 and "(LogDisabled)" in err and "read 0" not in err,
                  "a disabled operational log exits 1 and says so, never a clean week with 0 "
                  "runs  <-- pinned defect")
            code, out, err = cli("--history", "--show-ok", "--format", "csv", "--match", "etl")
            cells = list(csv.DictReader(io.StringIO(out)))[0]
            check(cells["history"] == "failed" and cells["runs_last_7_days"] == ""
                  and cells["failures_last_7_days"] == "",
                  "a disabled log writes empty run cells to the CSV, never 0  <-- pinned defect")
            nothing = read_error("NoMatchingEventsFound,Microsoft.PowerShell.Commands."
                                 "GetWinEventCommand")
            module["run_powershell"] = lambda script, timeout, what: [span_of(1, 50)] + nothing
            code, out, err = cli("--history")
            check(code == 2 and r"\Jobs\broken" in out and "read 0 run event(s)" in err,
                  "a log with no matching events is zero events, and the report still runs")
            quiet = cli("--history", "--show-ok", "--format", "json", "--match", "etl")[1]
            gone, clean = json.loads(denied)[0], json.loads(quiet)[0]
            check(denied != quiet and gone["history"] == "failed"
                  and gone["runs_last_7_days"] is None and gone["failures_last_7_days"] is None
                  and clean["history"] == "complete" and clean["runs_last_7_days"] == 0
                  and clean["failures_last_7_days"] == 0,
                  "the json of an access-denied read differs from a clean read of an empty "
                  "log: null run counts, not 0  <-- pinned defect")
            code, out, err = cli("--show-ok", "--format", "json", "--match", "etl")
            check(json.loads(out)[0]["history"] == "off"
                  and json.loads(out)[0]["runs_last_7_days"] is None,
                  "without --history the json says history off and leaves the run counts null")
            code, out, err = cli("--history", "--since-record-id", "50", "--match", "etl")
            check(code == 0 and "read 0 run event(s); next run can pass --since-record-id 50"
                  in err, "a watermark read with nothing new hands the same watermark back, "
                  "not 0, and exits 0")
            module["run_powershell"] = lambda script, timeout, what: [span_of(9001, 9652)] + nothing
            code, out, err = cli("--history", "--since-record-id", "9000", "--match", "etl")
            check(code == 0 and "--since-record-id 9652" in err,
                  "an empty read moves the watermark to the log's newest record, so the next "
                  "read does not report records the log overwrote since  <-- pinned defect")
            code, out, err = cli("--history", "--since-record-id", "2000000", "--match", "etl")
            check(code == 1 and "above the newest record of the log (9652)" in err
                  and "next run can pass" not in err,
                  "a watermark above the log's newest record, as after a clear, exits 1, never "
                  "a clean empty history  <-- pinned defect")
            code, out, err = cli("--history", "--since-record-id", "100", "--match", "etl")
            check(code == 1 and "records 101 to 9000" in err and "--since-record-id 9652" in err,
                  "a log that rolled over past the watermark exits 1, never 0  <-- pinned defect")
            module["read_run_events"] = serve([ago(3, 100, "s", 2), ago(2, 102, "s", 3)],
                                              log_oldest_time_utc=ago(4, 100, "s", 1)[
                                                  "event_time_utc"])
            code, out, err = cli("--history", "--match", "etl")
            check(code == 1 and "no record older than" in err,
                  "a cold start on a log that holds only 4 hours exits 1, never a clean week"
                  "  <-- pinned defect")
            module["read_run_events"] = real_readers[1]
            sent = []
            module["run_powershell"] = lambda script, timeout, what: sent.append(script) or []
            code, out, err = cli("--history", "--since-record-id", "0")
            check("$Oldest = $true" in sent[0] and "timediff" not in sent[0]
                  and "--since-record-id 0" in err,
                  "the --since-record-id 0 an empty log prints, passed back, reads the whole "
                  "log oldest first, not a newest-first cold start  <-- pinned defect")
            module["run_powershell"] = real_bridge
            module["read_run_events"] = serve(history)
            code, out, err = cli("--lint")
            check(code == 2 and "interactive-only" in out and "start-in-missing" in out
                  and "stock" not in out, "--lint alone lints the live inventory")
            code, out, err = cli("--lint", "--all", "--format", "csv")
            check("s4u-network" not in out and "bare-program" in out and "stock" in out,
                  "--lint --all includes microsoft's tasks too")
            code, out, err = cli("--lint", "--show-ok", "--match", "etl")
            check(code == 0 and "no findings" in out, "--lint --show-ok confirms a clean task")
            code, out, err = cli("--lint", os.path.join(scratch, "Tasks"), loose)
            check(code == 2 and "interactive-only" in out and "bare-program" in out,
                  "--lint PATH lints exported files and exits 2 on an Error finding")
            target = os.path.join(scratch, "findings.json")
            code, out, err = cli("--lint", loose, "--format", "json", "--out", target)
            check(code == 0 and not os.path.exists(target) and "bare-program" in out
                  and "was not written" in err,
                  "--out without --apply writes nothing at all and prints the report"
                  "  <-- pinned defect")
            code, out, err = cli("--lint", loose, "--format", "json", "--out", target, "--apply")
            with open(target) as handle:
                written = json.load(handle)
            check(code == 0 and out == "" and "wrote 1 row(s)" in err
                  and written[0]["check"] == "bare-program",
                  "--out --apply writes the findings to the named file and a Warning exits 0")
            with open(loose, "rb") as handle:
                export = handle.read()
            for out_path in (loose, os.path.join(scratch, "Tasks", "findings.csv")):
                code, out, err = cli("--lint", os.path.join(scratch, "Tasks"), loose,
                                     "--out", out_path, "--apply")
                with open(loose, "rb") as handle:
                    kept = handle.read() == export
                check(code == 64 and kept and "this run lints" in err,
                      "--out on an export being linted, or inside a linted folder, is refused"
                      "  <-- pinned defect")
            check(not os.path.exists(os.path.join(scratch, "Tasks", "findings.csv")),
                  "the refused write inside the linted folder made no file")
            # Another spelling of the same file: the \\?\ long-path prefix on Windows. POSIX
            # has no such prefix, so there the spelling is a dot segment.
            alias = "\\\\?\\" + loose if windows else os.path.join(scratch, ".", "export.XML")
            linked = os.path.join(scratch, "linked.xml")
            os.link(loose, linked)
            inner = os.path.join(scratch, "inner-link.xml")
            os.link(os.path.join(folder, "nightly"), inner)
            with open(inner, "rb") as handle:
                nightly = handle.read()
            for why, lint_path, out_path in (
                    ("another spelling of the export", loose, alias),
                    ("a hard link to the export", loose, linked),
                    ("a hard link to a file in a linted folder", os.path.join(scratch, "Tasks"),
                     inner)):
                code, out, err = cli("--lint", lint_path, "--out", out_path, "--apply")
                with open(loose, "rb") as handle, open(inner, "rb") as other:
                    kept = handle.read() == export and other.read() == nightly
                check(code == 64 and kept and "this run lints" in err,
                      "--out as %s is refused  <-- pinned defect" % why)
            code, out, err = cli("--lint", loose, "--apply")
            check(code == 64 and "--apply needs --out" in err, "--apply without --out is refused")
            prefixed = os.path.join(scratch, "prefixed.json")
            codes = [cli("--lint", loose, "--out", prefixed, prefix)[0]
                     for prefix in ("--ap", "--app", "--appl")]
            check(codes == [64] * 3 and not os.path.exists(prefixed),
                  "a prefix of --apply, such as --ap, is refused and writes nothing"
                  "  <-- pinned defect")
            code, out, err = cli("--lint", loose, "--out",
                                 os.path.join(scratch, "nope", "x.csv"), "--apply")
            check(code == 1 and "cannot write" in err and "Traceback" not in err,
                  "--out into a missing folder exits 1 with a message  <-- pinned defect")
            # A task name in a script that cp1252 cannot encode, built from code points so
            # this file stays ASCII.
            wide_name = chr(0x5730) + chr(0x56FE)
            wide = os.path.join(scratch, "wide.xml")
            with open(wide, "wb") as handle:
                handle.write(task_xml(uri="\\GIS\\%s-nightly" % wide_name,
                                      logon="InteractiveToken").encode("utf-16"))
            raw = io.BytesIO()
            console = io.TextIOWrapper(raw, encoding="cp1252")
            with redirect_stdout(console), redirect_stderr(io.StringIO()):
                code = main(["--lint", wide])
            console.flush()
            check(code == 2 and wide_name.encode("ascii", "backslashreplace") in raw.getvalue(),
                  "a task name a cp1252 console cannot show prints as \\uXXXX, not a crash"
                  "  <-- pinned defect")
            code, out, err = cli("--lint", os.path.join(scratch, "missing.xml"))
            check(code == 1 and "missing.xml" in err, "a missing export exits 1 and says why")
            code, out, err = cli("--lint", os.path.join(scratch, "missing.xml"), "--out", target,
                                 "--apply")
            check(code == 1 and "missing.xml" in err and "Traceback" not in err,
                  "a missing export with --out exits 1 too: the --out guard has nothing to compare")
            code, out, err = cli("--lint", loose, "--local-drives", "C,D")
            check(code == 0, "--local-drives is accepted as a comma list")
            code, out, err = cli("--lint", empty)
            check(code == 1 and "no task file found" in err,
                  "--lint on an empty folder exits 1, not 0 with 'No findings.'  <-- pinned defect")
            code, out, err = cli("--lint", "--history")
            check(code == 64 and "not allowed with" in err,
                  "--lint and --history are refused together as a usage error")
            # --- --diff, end to end ---
            old_export = os.path.join(scratch, "old.xml")
            new_export = os.path.join(scratch, "new.xml")
            with open(old_export, "wb") as handle:
                handle.write(task_xml(uri="\\Jobs\\nightly", limit="PT1H").encode("utf-16"))
            with open(new_export, "wb") as handle:
                handle.write(task_xml(uri="\\Jobs\\nightly", limit="PT0S",
                                      logon="InteractiveToken").encode("utf-8"))
            code, out, err = cli("--diff", old_export, new_export)
            check(code == 2 and out.startswith("CHANGE") and "setting ExecutionTimeLimit" in out
                  and "logon type" in out and r"\Jobs\nightly" in out and err == "",
                  "--diff names each field that changed between two exports and exits 2")
            args_old = os.path.join(scratch, "args-old.xml")
            args_new = os.path.join(scratch, "args-new.xml")
            for path, secret in ((args_old, "Zq9XvR2mLpW4sTn8"), (args_new, "Nw3KdF8sQzP1vB6y")):
                with open(path, "wb") as handle:
                    handle.write(task_xml(uri="\\Jobs\\nightly", arguments="etl.py " + secret
                                          ).encode("utf-8"))
            code, out, err = cli("--diff", args_old, args_new, "--format", "json")
            check(code == 2 and "Zq9X" not in out + err and "Nw3K" not in out + err
                  and "arguments not shown" in out and "action 1" in out,
                  "--diff prints no arguments by default, and still exits 2 on a changed one"
                  "  <-- pinned defect")
            code, out, err = cli("--diff", args_old, args_new, "--show-args")
            check(code == 2 and "etl.py" in out and "[Start In" in out,
                  "--show-args prints the arguments of each action")
            code, out, err = cli("--lint", loose, "--show-args")
            check(code == 64 and "--show-args needs --diff" in err,
                  "--show-args without --diff is a usage error")
            code, out, err = cli("--diff", old_export, old_export)
            check(code == 0 and out == "No differences.\n",
                  "--diff of an export with itself says so and exits 0")
            code, out, err = cli("--diff", old_export, new_export, "--format", "json",
                                 "--match", "nightly")
            check(code == 2 and {row["field"] for row in json.loads(out)}
                  == {"setting ExecutionTimeLimit", "logon type"},
                  "--diff writes json, and --match scopes it")
            code, out, err = cli("--diff", old_export, old_export, "--match", "nightly")
            check(code == 0 and out == "No differences.\n" and err == "",
                  "--match that keeps a task with no difference is a clean diff")
            code, out, err = cli("--diff", old_export, new_export, "--match", "nothing")
            check(code == 1 and out == "" and "matched no task" in err,
                  "--diff --match that matches no task is not a clean diff  <-- pinned defect")
            code, out, err = cli("--lint", loose, "--match", "nothing")
            check(code == 1 and out == "" and "matched no task" in err,
                  "--lint --match that matches no task is not 'No findings'  <-- pinned defect")
            code, out, err = cli("--diff", os.path.join(scratch, "Tasks"), loose)
            check(code == 2 and "removed" in out and "added" in out and r"\export" in out
                  and r"\Jobs\nightly" in out,
                  "--diff reads a folder as it reads a file, and a task in one side is added or "
                  "removed")
            dup_folder = os.path.join(scratch, "dups")
            os.makedirs(dup_folder)
            for name, limit in (("a.xml", "PT0S"), ("b.xml", "PT1H")):
                with open(os.path.join(dup_folder, name), "wb") as handle:
                    handle.write(task_xml(uri="\\Jobs\\dup", limit=limit).encode("utf-8"))
            dup_one = os.path.join(scratch, "dup-one.xml")
            with open(dup_one, "wb") as handle:
                handle.write(task_xml(uri="\\Jobs\\dup", limit="PT1H").encode("utf-8"))
            code, out, err = cli("--diff", dup_one, dup_folder)
            swapped = cli("--diff", dup_folder, dup_one)
            check(code == 1 and out == "" and "dups" in err and "\\Jobs\\dup" in err
                  and swapped[0] == 1 and "dups" in swapped[2],
                  "two files that define one task on a side stop --diff, on either side: the "
                  "verdict never depends on file order  <-- pinned defect")
            off = os.path.join(scratch, "off.xml")
            with open(off, "wb") as handle:
                handle.write(task_xml(uri="\\Jobs\\off", enabled="false", start="",
                                      arguments="refresh.py").encode("utf-8"))
            code, out, err = cli("--lint", off)
            check(code == 0 and out == "No findings.\n",
                  "a disabled task is not linted, so an export of only disabled tasks is clean "
                  "(a README limit)")
            other = os.path.join(scratch, "other-file.txt")
            with open(other, "w") as handle:
                handle.write("keep me")
            code, out, err = cli("--lint", off, "--show-ok", "--out", other, "--apply")
            with open(other) as handle:
                replaced = handle.read()
            check(code == 0 and replaced == "No findings.\n",
                  "--apply replaces any other file it can write without asking (a README limit)")
            stock_old = os.path.join(scratch, "stock-old.xml")
            stock_new = os.path.join(scratch, "stock-new.xml")
            for stock_path, stock_limit in ((stock_old, "PT1H"), (stock_new, "PT0S")):
                with open(stock_path, "wb") as handle:
                    handle.write(task_xml(uri="\\Microsoft\\Windows\\X\\stock",
                                          limit=stock_limit).encode("utf-8"))
            code, out, err = cli("--diff", stock_old, stock_new)
            code_all, out_all, err_all = cli("--diff", stock_old, stock_new, "--all")
            check(code == 1 and out == "" and "2 task(s)" in err and "pass --all" in err
                  and "no result" in err and code_all == 2 and "stock" in out_all
                  and "not examined" not in err_all,
                  "--diff of two exports that hold only Microsoft's own tasks has no result: "
                  "exit 1 and a notice, never 'No differences'  <-- pinned defect")
            mixed = {}
            for side, stock_path in (("a", stock_old), ("b", stock_new)):
                mixed[side] = os.path.join(scratch, "mixed-" + side)
                os.makedirs(mixed[side])
                with open(os.path.join(mixed[side], "own.xml"), "wb") as handle:
                    handle.write(task_xml(uri="\\Jobs\\own").encode("utf-8"))
                shutil.copy(stock_path, os.path.join(mixed[side], "stock.xml"))
            code, out, err = cli("--diff", mixed["a"], mixed["b"])
            check(code == 0 and out == "No differences.\n" and "2 task(s)" in err
                  and "no result" not in err,
                  "--diff that skipped some of Microsoft's tasks says so on stderr and still "
                  "compares the rest  <-- pinned defect")
            code, out, err = cli("--lint", stock_old)
            code_all, out_all, err_all = cli("--lint", stock_old, "--all")
            code_mixed, out_mixed, err_mixed = cli("--lint", mixed["a"], "--show-ok")
            check(code == 1 and out == "" and "1 task(s)" in err and "no result" in err
                  and "not examined" not in err_all and "not examined" in err_mixed
                  and "no result" not in err_mixed and code_mixed == 0,
                  "--lint of an export that holds only Microsoft's own tasks has no result: "
                  "exit 1 and a notice, never 'No findings'  <-- pinned defect")
            diff_target = os.path.join(scratch, "diff.json")
            code, out, err = cli("--diff", old_export, new_export, "--format", "json", "--out",
                                 diff_target)
            check(code == 2 and not os.path.exists(diff_target) and "was not written" in err,
                  "--diff with --out and no --apply writes nothing")
            code, out, err = cli("--diff", old_export, new_export, "--format", "json", "--out",
                                 diff_target, "--apply")
            with open(diff_target) as handle:
                saved_diff = json.load(handle)
            check(code == 2 and out == "" and len(saved_diff) == 2 and "wrote 2 row(s)" in err,
                  "--diff --out --apply writes the rows and still exits 2")
            code, out, err = cli("--diff", old_export, new_export, "--out",
                                 os.path.join(scratch, "nope", "x.json"), "--apply")
            check(code == 1 and "cannot write" in err,
                  "--diff with an --out it cannot write exits 1, not 2")
            with open(old_export, "rb") as handle:
                before_bytes = handle.read()
            outcomes = [cli("--diff", old_export, new_export, "--out", path, "--apply")
                        for path in (old_export, new_export)]
            with open(old_export, "rb") as handle:
                kept_old = handle.read() == before_bytes
            check([code for code, _, _ in outcomes] == [64, 64] and kept_old
                  and all("this run lints or compares" in err for _, _, err in outcomes),
                  "--out on an export that --diff compares is refused and the export is "
                  "untouched  <-- pinned defect")
            code, out, err = cli("--diff", old_export, os.path.join(scratch, "missing.xml"))
            check(code == 1 and "missing.xml" in err and out == "",
                  "--diff of a missing export exits 1 and names it")
            code, out, err = cli("--diff", broken, old_export)
            check(code == 1 and "broken.xml" in err and "no <Task> element found" in err,
                  "--diff of a file with no task in it exits 1, not 'No differences'  "
                  "<-- pinned defect")
            refused = [cli(*argv)[0] for argv in (("--diff", old_export), ("--diff",),
                                                  ("--diff", old_export, new_export, "--lint"),
                                                  ("--diff", old_export, new_export,
                                                   "--history"),
                                                  ("--dif", old_export, new_export))]
            check(refused == [64] * 5,
                  "--diff takes exactly two paths, cannot be combined with --lint or "
                  "--history, and cannot be typed as a prefix  <-- pinned defect")

            usage = [cli(*argv)[0] for argv in (("--bogus",), ("--timeout", "abc"),
                                                ("--format", "xml"), ("--history", "x"))]
            check(usage == [64] * 4,
                  "a usage error exits 64, never 2, which means an Error finding  <-- pinned defect")
            refused = [cli(*argv) for argv in (("--history", "0"), ("--history", "-3"),
                                               ("--since-record-id", "5"),
                                               ("--history", "--since-record-id", "-1"))]
            check([code for code, out, err in refused] == [64] * 4
                  and "7 or more" in refused[0][2] and "needs --history" in refused[2][2]
                  and "0 or more" in refused[3][2],
                  "--history 0 or less, which matches no event, and --since-record-id without "
                  "--history or below 0 are usage errors, not an empty history  <-- pinned defect")
            code, out, err = cli("--history", "6")
            check(code == 64 and "7 or more" in err and out == "",
                  "--history below 7 days is a usage error: a shorter read would still label "
                  "its columns 'the last 7 days'  <-- pinned defect")
            code, out, err = cli("--lint", loose, "--match", "(")
            check(code == 64 and "not a valid regex" in err and "Traceback" not in err,
                  "a bad --match regex is a usage error, not a traceback  <-- pinned defect")
            code, out, err = cli("--version")
            check(code == 0 and __version__ in out, "--version still exits 0")
            module["read_run_events"] = unavailable
            code, out, err = cli("--history", "--match", "etl")
            check(code == 1 and "not reachable" in err and "No tasks need attention." in out,
                  "a failed history read exits 1, though its table reads like a clean run")
            saved = []
            for reader in (serve([]), unavailable):
                module["read_run_events"] = reader
                path = os.path.join(scratch, "history-%d.json" % len(saved))
                code = cli("--history", "--match", "etl", "--format", "json", "--out", path,
                           "--apply")[0]
                with open(path, "rb") as handle:
                    saved.append((code, handle.read()))
            check(saved == [(0, b"[]\n"), (1, b"[]\n")],
                  "with no row, the --out file of a failed history read matches a clean one, "
                  "so only the exit code tells them apart  <-- pinned defect")
            unread = dict(later, task_path="\\Jobs\\", task_name="unread", logon_type="Password",
                          read_errors="run details", last_task_result=None,
                          actions=[{"executable": r"C:\jobs\x.exe", "working_directory": "C:\\"}])
            module["read_tasks"] = lambda timeout=120: [dict(t) for t in live] + [dict(unread)]
            seen = [cli("--match", "unread")[0], cli("--lint", "--match", "unread")[0], cli()[0]]
            code, out, err = cli("--match", "unread")
            check(seen == [1, 1, 2] and r"\Jobs\unread" in out
                  and "could not fully read 1 task(s)" in err,
                  "a task the live read could not fully read exits 1, in the report and the "
                  "lint, unless a task is in Error  <-- pinned defect")
            module["read_tasks"] = lambda timeout=120: [dict(unread, enabled=False)]
            check(cli("--show-ok")[0] == 0,
                  "a disabled task whose run details could not be read is not a blind spot")
            # The stub behind the README's run-fate example. Hours are counted back from one
            # clock, so the "40.0 hour(s)" in the README is the value this run prints.
            clock = datetime.now(timezone.utc)
            folder = "\\GIS\\"

            def aged(hours, event_id, instance, record, name, code=None):
                return {"event_id": event_id, "instance_id": instance, "event_record_id": record,
                        "task_full_name": folder + name, "result_code": code,
                        "event_time_utc": (clock - timedelta(hours=hours)).isoformat()}

            def sample(name, state, result=0):
                return dict(later, task_path=folder, task_name=name, state=state,
                            last_task_result=result, last_run_time=None, actions=[],
                            next_run_time="2999-01-01T02:00:00+00:00", read_errors="")

            module["read_tasks"] = lambda timeout=120: [
                sample("nightly-parcel-refresh", "Running"), sample("report-mailer", "Running"),
                sample("tile-cache", "Ready"), sample("locator-rebuild", "Ready", 0x8007052E)]
            module["read_run_events"] = serve([
                aged(40, 100, "a", 1, "nightly-parcel-refresh"),
                aged(40, 200, "a", 2, "nightly-parcel-refresh"),
                aged(50, 100, "b", 3, "report-mailer"), aged(50, 200, "b", 4, "report-mailer"),
                aged(26, 322, "b", 5, "report-mailer"), aged(2, 322, "b", 6, "report-mailer"),
                aged(30, 100, "c", 7, "tile-cache"), aged(30, 200, "c", 8, "tile-cache"),
                aged(29.9, 201, "c", 9, "tile-cache", 0), aged(29.9, 102, "c", 10, "tile-cache"),
                aged(5, 332, "", 11, "tile-cache"),
                aged(20, 100, "d", 12, "locator-rebuild"),
                aged(20, 201, "d", 23, "locator-rebuild", 0x8007052E)])
            code, out, err = cli("--history")
            cells = [re.split(r"  +", line) for line in out.splitlines()[2:]]
            check(code == 2 and "read 13 run event(s)" in err and len(cells) == 4
                  and [(row[0], row[1]) for row in cells] == [
                      ("Error", folder + "locator-rebuild"),
                      ("Warning", folder + "nightly-parcel-refresh"),
                      ("Warning", folder + "report-mailer"), ("Warning", folder + "tile-cache")]
                  and "; 1 of 1 run(s)" in cells[0][-1]
                  and cells[1][-1] == "STUCK: a run started 40.0 hour(s) ago has not finished; task"
                  and cells[2][-1] == "STUCK: a run started 50.0 hour(s) ago has not finished; 2 la"
                  and cells[3][-1] == "BLOCKED: the latest launch was refused because the run-as us",
                  "the run-fate example in the README: two STUCK, one BLOCKED and one Error "
                  "row, exit 2, with the rows the README prints")
            module["read_tasks"] = unavailable
            code, out, err = cli()
            check(code == 1 and "not reachable" in err, "a failed inventory read exits 1")
        finally:
            module["read_tasks"], module["read_run_events"] = real_readers
            module["run_powershell"] = real_bridge
    finally:
        shutil.rmtree(scratch)

    # Imported rather than run, the file defines everything and executes nothing.
    spec = importlib.util.spec_from_file_location("taskpulse_import_probe", __file__)
    imported = importlib.util.module_from_spec(spec)
    quiet = io.StringIO()
    # The loader would otherwise leave __pycache__ beside the script: a write --self-test
    # has no business making.
    cached = importlib.util.cache_from_source(os.path.abspath(__file__))

    def stamp():
        return os.path.getmtime(cached) if os.path.exists(cached) else None

    before = stamp()
    no_pyc = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        with redirect_stdout(quiet), redirect_stderr(quiet):
            spec.loader.exec_module(imported)
    finally:
        sys.dont_write_bytecode = no_pyc
    check(callable(imported.main) and quiet.getvalue() == "",
          "importing taskpulse runs nothing and prints nothing")
    check(stamp() == before, "the import probe writes no .pyc beside the script  <-- pinned defect")

    print("os message table: %s" % ("present" if windows
                                     else "absent, so its assertions check the unmapped fallback"))
    return finish()


# --------------------------------------------------------------------------

USAGE_ERROR = 64


def inside(path, other):
    """True when `path` is `other`, or lies inside the folder `other`, however it is spelled.

    Compared by file identity, not by string: a \\\\?\\ prefix, an admin share or a hard link
    names the same file with a different string. `path` is `other` or inside it when it, or a
    folder above it, is the same file as `other`, or when it is a hard link to a file inside
    `other`.
    """
    if not os.path.exists(other):
        return False  # nothing there to replace; the read reports the missing path
    here = os.path.abspath(path)
    while True:
        if os.path.exists(here) and os.path.samefile(here, other):
            return True
        if os.path.dirname(here) == here:
            break
        here = os.path.dirname(here)
    return os.path.isdir(other) and os.path.isfile(path) and any(
        same_file(path, os.path.join(folder, name))
        for folder, _, names in os.walk(other) for name in names)


def same_file(one, other):
    """os.path.samefile, but False for a name with nothing behind it, such as a dangling link."""
    try:
        return os.path.samefile(one, other)
    except OSError:
        return False


class Parser(argparse.ArgumentParser):
    """argparse exits 2 on a usage error, and 2 here means an Error finding. Use 64 instead."""

    def error(self, message):
        self.print_usage(sys.stderr)
        self.exit(USAGE_ERROR, "%s: error: %s\n" % (self.prog, message))


def emit(rows, args, lint=False, diff=False):
    """Print the report, or with --apply write it to --out. 1 when the write failed, else 0."""
    report = io.StringIO()
    write_output(rows, args.format, report, lint, diff)
    if args.apply:
        try:
            with open(args.out, "w", encoding="utf-8", newline="") as handle:
                handle.write(report.getvalue())
        except OSError as error:
            sys.stderr.write("taskpulse: cannot write %s: %s\n" % (args.out, error))
            return 1
        sys.stderr.write("taskpulse: wrote %d row(s) to %s\n" % (len(rows), args.out))
    else:
        # A redirected Windows console encodes as cp1252; a task named in another script
        # would raise there and lose every finding. Print what cannot be encoded as \uXXXX.
        encoding = getattr(sys.stdout, "encoding", None) or "utf-8"
        sys.stdout.write(report.getvalue().encode(encoding, "backslashreplace").decode(encoding))
        if args.out:
            sys.stderr.write("taskpulse: check only, %s was not written; re-run with --apply\n"
                             % args.out)
    return 0


def skip_notice(skipped, sides):
    r"""Say on stderr that --all would add tasks. True when no task was left to examine.

    Without --all, tasks under \Microsoft\ are dropped from a file or folder the user named,
    and a result over zero tasks looks the same as a clean one, so that case is never clean.
    """
    if skipped:
        sys.stderr.write("taskpulse: %d task(s) under \\Microsoft\\ were not examined; pass "
                         "--all to include them\n" % skipped)
    if skipped and not any(sides):
        sys.stderr.write("taskpulse: no other task was left to examine, so there is no result\n")
        return True
    return False


def match_notice(args, pattern, tasks):
    r"""Say on stderr that --match found no task. True when it found none.

    A scoped check such as --match "^\\Jobs\\nightly" would stay green for ever after the task
    is renamed or deleted, or after a typo in the regex. Like an empty \Microsoft\ filter
    (skip_notice), a result over zero tasks is never a clean one. Only a --match that was given
    counts; an empty inventory with no --match keeps its old answer.
    """
    if args.match and not any(pattern.search(full_task_name(task)) for task in tasks):
        sys.stderr.write("taskpulse: --match matched no task, so there is no result\n")
        return True
    return False


def repeated_name(tasks):
    """The first full task name that two definitions share, or None. Pure.

    --diff matches tasks by name, so two definitions of one name on a side would hide one of
    them and the verdict would depend on file order.
    """
    seen = set()
    for task in tasks:
        key = full_task_name(task).lower()
        if key in seen:
            return full_task_name(task)
        seen.add(key)
    return None


def main(argv=None):
    parser = Parser(
        prog="taskpulse",
        # Without this, argparse reads --ap, --app and --appl as --apply: a typed prefix writes.
        allow_abbrev=False,
        description="Audit every Windows scheduled task and report which ones are silently "
                    "failing, or lint their configuration.",
        epilog="Read-only: taskpulse never modifies, starts, stops or deletes a task, "
               "never uses the network, and never needs credentials.",
    )
    parser.add_argument("--format", choices=["table", "json", "csv"], default="table",
                        help="output format (default: table)")
    parser.add_argument("--out", metavar="PATH",
                        help="with --apply, write to PATH instead of stdout")
    parser.add_argument("--apply", action="store_true",
                        help="write --out. Without it nothing is written, and the report goes "
                             "to stdout")
    parser.add_argument("--all", action="store_true",
                        help="include Microsoft's own tasks under \\Microsoft\\ (noisy)")
    parser.add_argument("--show-ok", action="store_true",
                        help="include healthy tasks, not just Warning/Error")
    parser.add_argument("--match", metavar="REGEX",
                        help="only tasks whose full path matches this regex")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--history", nargs="?", type=int, const=30, metavar="DAYS",
                      help="also read the Task Scheduler Operational log and report each "
                           "task's last 7 days of runs, its duration baseline, and whether it "
                           "is STUCK or BLOCKED "
                           "(default: 30 days of events, newest first; at least 7)")
    mode.add_argument("--lint", nargs="*", metavar="PATH",
                      help="report configuration findings instead of run health. With no "
                           "PATH, lint the live Task Scheduler; with PATHs, lint exported task "
                           "XML files or folders (works on any OS)")
    mode.add_argument("--diff", nargs=2, metavar=("OLD", "NEW"),
                      help="compare two exports of the same tasks (files or folders, any OS) "
                           "and name each field that changed. Exits 0 when they match, 2 "
                           "when they differ")
    parser.add_argument("--show-args", action="store_true",
                        help="with --diff, print each action's arguments. They can hold a "
                             "secret that the mask does not know, and a change shows both the "
                             "old and the new value, so do not paste or commit the output "
                             "(default: arguments are compared but not printed)")
    parser.add_argument("--local-drives", default="C", metavar="LETTERS",
                        help="with --lint, drive letters that are local disks, not mapped "
                             "drives (default: C)")
    parser.add_argument("--since-record-id", type=int, metavar="ID",
                        help="with --history, read only event records newer than ID, oldest "
                             "first. Pass the watermark the previous run printed, even 0. The "
                             "day window is ignored, and the run columns count only the runs "
                             "since ID")
    parser.add_argument("--stuck-hours", type=int, metavar="HOURS",
                        help="with --history, a run with no end event after this many hours is "
                             "STUCK (default: %d)" % STUCK_HOURS)
    parser.add_argument("--timeout", type=int, default=120, metavar="SECONDS",
                        help="Task Scheduler query timeout (default: 120)")
    parser.add_argument("--self-test", action="store_true",
                        help="run the offline assertion suite and exit")
    parser.add_argument("--version", action="version", version="taskpulse " + __version__)
    args = parser.parse_args(argv)
    try:
        pattern = re.compile(args.match or "", re.IGNORECASE)
    except re.error as error:
        parser.error("--match is not a valid regex: %s" % error)
    if args.apply and not args.out:
        parser.error("--apply needs --out")
    if args.show_args and args.diff is None:
        parser.error("--show-args needs --diff")
    if args.history is not None and args.history < 7:
        # The run columns cover 7 days. A shorter window would read fewer days and still label
        # them 'the last 7 days', so a failure 5 nights ago would vanish from a clean report.
        parser.error("--history DAYS must be 7 or more, because the run columns cover 7 days")
    if args.since_record_id is not None and args.history is None:
        parser.error("--since-record-id needs --history")
    if (args.since_record_id or 0) < 0:
        parser.error("--since-record-id must be 0 or more")
    since = args.since_record_id  # None is a cold start; 0, as an empty log prints, is not
    if args.stuck_hours is not None and args.history is None:
        parser.error("--stuck-hours needs --history")
    if args.stuck_hours is not None and args.stuck_hours < 1:
        parser.error("--stuck-hours must be 1 or more")
    stuck_hours = args.stuck_hours or STUCK_HOURS
    if args.out and any(inside(args.out, path) for path in (args.lint or []) + (args.diff or [])):
        # One mistyped path would replace the export being read with the report on it.
        parser.error("--out %s is an export this run lints or compares, or inside one" % args.out)

    if args.self_test:
        return self_test()

    lint = args.lint is not None
    diff = args.diff is not None
    try:
        if diff:
            before, after = [read_task_files([path]) for path in args.diff]
        else:
            tasks = read_task_files(args.lint) if args.lint else read_tasks(args.timeout)
    except Exception as error:
        sys.stderr.write("taskpulse: %s\n" % error)
        return 1

    now = datetime.now(timezone.utc)
    if diff:
        sides = [[task for task in side if args.all or not is_microsoft_task(task)]
                 for side in (before, after)]
        if skip_notice(len(before) + len(after) - len(sides[0]) - len(sides[1]), sides):
            return 1
        if match_notice(args, pattern, sides[0] + sides[1]):
            return 1
        for path, side in zip(args.diff, sides):
            name = repeated_name(side)
            if name:
                sys.stderr.write("taskpulse: %s holds more than one task named %s; compare one "
                                 "export of each task\n" % (path, name))
                return 1
        rows = diff_tasks(sides[0], sides[1], args.show_args)
        rows = [row for row in rows if pattern.search(row["task"])]
        return emit(rows, args, diff=True) or (2 if rows else 0)

    if not args.all:
        kept = [task for task in tasks if not is_microsoft_task(task)]
        # Only for tasks the user named by path: a silent filter there reads as a clean file.
        if args.lint and skip_notice(len(tasks) - len(kept), [kept]):
            return 1
        tasks = kept
    if not diff and match_notice(args, pattern, tasks):
        return 1

    run_summary, fates = {}, {}
    incomplete = False
    history = "off"
    if args.history is not None:
        try:
            events, log = read_run_events(args.history, since, args.timeout)
            gap = log_range_gap(since, log, now)
        except Exception as error:
            # The snapshot still prints and a task in Error still exits 2: on a stock box the
            # log is off, and a monitoring check must not lose its Error row to that.
            incomplete, history = True, "failed"
            sys.stderr.write("taskpulse: %s\ntaskpulse: the report has no run history, so it "
                             "is incomplete\n" % error)
        else:
            # The read asks for one event more than the cap, so only a read that left events
            # unread counts as capped. The events kept are the first ones in read order: the
            # oldest past a watermark, the newest on a cold start.
            capped = len(events) > HISTORY_MAX_EVENTS
            events = events[:HISTORY_MAX_EVENTS]
            runs = build_run_rows(events, tasks)
            run_summary = summarize_runs(runs, now, since)
            fates = judge_fates(runs, build_block_rows(events, tasks), tasks, now, since,
                                stuck_hours)
            # Report the watermark over every event fetched, not only the ones that joined to
            # a task: an event for an unmonitored task is still an event this run has read.
            # Past a watermark the read is oldest first, so every record below the new one has
            # been read. A read the cap did not stop has seen every record up to the log's
            # newest, so the watermark moves there, or an empty read would hand back a
            # watermark below records the log has since overwritten.
            newest = [] if capped else [to_int(log.get("log_newest_record_id")) or 0]
            watermark = max([to_int(raw.get("event_record_id")) or 0 for raw in events]
                            + [since or 0] + newest)
            sys.stderr.write("taskpulse: read %d run event(s); next run can pass "
                             "--since-record-id %d\n" % (len(events), watermark))
            times = [parse_dt(raw.get("event_time_utc")) for raw in events]
            reach = min([when for when in times if when] or [now])
            if capped and since is not None:
                incomplete = True
                sys.stderr.write("taskpulse: the read stopped at the %d-event cap, so newer "
                                 "events were not read and this report is incomplete; the next "
                                 "run continues from that watermark\n" % HISTORY_MAX_EVENTS)
            elif capped and reach > now - timedelta(days=7):
                # A clean report here would hide a task whose failures lie in the unread days.
                incomplete = True
                sys.stderr.write("taskpulse: the read stopped at the %d-event cap at %s, so the "
                                 "7-day columns miss the older runs and this report is "
                                 "incomplete; pass the watermark to later runs\n"
                                 % (HISTORY_MAX_EVENTS, reach.strftime("%Y-%m-%dT%H:%MZ")))
            elif capped:
                sys.stderr.write("taskpulse: the read stopped at the %d-event cap at %s; the "
                                 "7-day columns are complete, and the duration baseline covers "
                                 "less than %d day(s)\n" % (HISTORY_MAX_EVENTS,
                                                            reach.strftime("%Y-%m-%dT%H:%MZ"),
                                                            args.history))
            if gap:
                incomplete = True
                sys.stderr.write("taskpulse: %s\n" % gap)
            history = "incomplete" if incomplete else "complete"

    if lint:
        rows = lint_rows(tasks, args.local_drives.split(","), args.show_ok, now)
    else:
        rows = [evaluate(task, now, run_summary.get(full_task_name(task)), history,
                         fates.get(full_task_name(task))) for task in tasks]

    rows = [row for row in rows if pattern.search(row["task"])]
    if not lint and not args.show_ok:
        # A task that failed every night this week and succeeded tonight is exactly what
        # --history exists to surface, so a week's failures keep a row that status alone drops.
        rows = [row for row in rows
                if row["status"] in ("Warning", "Error") or row["failures_last_7_days"]]
    if not lint:
        rows.sort(key=lambda row: (row["status"] != "Error", row["task"].lower()))

    if emit(rows, args, lint):
        return 1

    failed = [row for row in rows if row.get("status", row.get("severity")) == "Error"]
    if failed:
        return 2
    # A task the live read could not fully see has an unknown result, so it is not a clean run.
    unread = set(full_task_name(task) for task in tasks if read_failures(task))
    blind = [row for row in rows if row["task"] in unread and row.get("status") != "Disabled"]
    if blind:
        sys.stderr.write("taskpulse: the live read could not fully read %d task(s), so their "
                         "result is unknown and this run is incomplete\n"
                         % len(set(row["task"] for row in blind)))
    return 1 if incomplete or blind else 0  # a run taskpulse could not finish is never clean


if __name__ == "__main__":
    sys.exit(main())
