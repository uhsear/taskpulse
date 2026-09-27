# taskpulse

Audits Windows scheduled tasks for silent failures and for the configuration that causes them,
from one read-only command.

A production GIS refresh ran every night as a scheduled task. Then a PowerShell settings change
switched the task's logon type, and nobody saw it happen. Under the new logon `arcpy` could not
see its licence, and the refresh broke. Task Scheduler's `Last Run Result` did not name the
cause. Until the next run, it still showed the previous night's success. The task carried a
configuration that broke its next run, and every field anyone looked at said it was fine.

taskpulse does two jobs. The health report joins the fields Task Scheduler keeps apart and
prints one verdict per task. The lint (`--lint`) reads each task's configuration and names what
will make the next run fail: a logon type that only runs while somebody is logged on, a
`Start In` that is empty, quoted or relative, a share the run-as account cannot reach, a
program that only `PATH` can find. The lint also reads exported task XML, so it runs on any OS.
Standard library only, no install, no config file, no credentials.

```console
$ python taskpulse.py --self-test
taskpulse self-test: offline, no Task Scheduler, no network, no credentials
--------------------------------------------------------------------
PASS  the harness counts a failed check, a missing raise and a wrong exception
PASS  signed form normalises to unsigned
...
PASS  a CSV cell a spreadsheet would run as a formula is written as text  <-- pinned defect
...
PASS  a nightly python job switched to 'run only when logged on' is an Error, while its last result still reads success  <-- pinned defect
PASS  python3.exe is a python interpreter, so an interactive-only job is an Error  <-- pinned defect
...
PASS  a drive-relative path such as Z:run.log names a mapped drive  <-- pinned defect
...
PASS  a quoted Start In is an Error: measured, it fails with 0x8007010B  <-- pinned defect
...
PASS  the value of a secret switch in an unquoted cmd /c body is never printed  <-- pinned defect
...
PASS  net use with a password and a DOMAIN\user names no relative path, so an empty Start In is no Error  <-- pinned defect
...
PASS  a path-like value with no file extension is judged but never printed, in case it is a secret  <-- pinned defect
PASS  a share after -PassThru, which takes no value, still meets the S4U share check, and is not printed  <-- pinned defect
...
PASS  cmd's cd without /d keeps the drive  <-- pinned defect
...
PASS  cmd cannot cd to a share  <-- pinned defect
...
PASS  a cd to a relative folder resolves against System32 itself  <-- pinned defect
PASS  a Set-Location to a relative folder resolves against System32 itself  <-- pinned defect
...
PASS  utf-8 bytes whose declaration still says UTF-16 parse  <-- pinned defect
...
PASS  a disabled Daily trigger never fires, so a task left with a logon trigger is not interactive-only  <-- pinned defect
...
PASS  an export with no <Enabled> element, as Windows writes every enabled task, is linted  <-- pinned defect
...
PASS  a subfolder the walk cannot list stops the read, not a clean lint  <-- pinned defect
PASS  a subfolder that is a symbolic link, which the walk lists but never enters, stops the read  <-- pinned defect
...
PASS  --out without --apply writes nothing at all and prints the report  <-- pinned defect
...
PASS  --out as a hard link to the export is refused  <-- pinned defect
...
PASS  importing taskpulse runs nothing and prints nothing
PASS  the import probe writes no .pyc beside the script  <-- pinned defect
os message table: present
--------------------------------------------------------------------
416 assertions, 0 failed
```

The same command prints `416 assertions, 0 failed` on Windows with Python 3.13 and on Ubuntu
with Python 3.12, and on Windows with Python 3.9. On Linux there is no OS message table, so
the line above the footer rule reads
`os message table: absent, so its assertions check the unmapped fallback`. Six assertions then
check the `unmapped result 0x...` text instead of the Windows wording, and the count stays equal.

The lint, run on Linux against a synthetic `schtasks /query /xml ONE` export (every name in it
is made up):

```console
$ python3 taskpulse.py --lint gis-tasks.xml
SEVERITY  TASK                         CHECK             DETAIL
--------  ---------------------------  ----------------  -------------------------------------------------------------------------------------------------------------------------------------------------------
Error     \GIS\export-to-share         s4u-network       logon type is S4U ('Do not store password'), which has no network credentials, so \\fileserver\gis is unreachable
Error     \GIS\locator-rebuild         start-in-missing  Start In is empty, so the relative path rebuild.py resolves against C:\Windows\System32
Error     \GIS\nightly-parcel-refresh  interactive-only  logon type is interactive: the task runs only while EXAMPLE\svc-etl is logged on, so its Daily trigger does nothing when nobody is
Error     \GIS\tile-cache              start-in-quoted   Start In "C:\tile work" is quoted; Task Scheduler does not strip the quotes and the task fails to start with 0x8007010B (the directory name is invalid)
Warning   \GIS\locator-rebuild         bare-program      python.exe has no folder, so it resolves against Start In and then the run-as account's PATH; which program runs, if any, depends on that account
Warning   \GIS\sync-to-mapped-drive    mapped-drive      Z: is not a declared local drive (--local-drives); a mapped drive does not exist in a non-interactive logon, so use the UNC path
$ echo $?
2
```

## What already exists

Task Scheduler itself shows every field, and shows it accurately. The Task Scheduler console,
`Get-ScheduledTask` and `schtasks /query /v` all expose the logon type, the account, the
`Start In` folder and the action. `schtasks /query /v /fo list` even prints
`Logon Mode: Interactive only`. Nothing is hidden. What they do not do is judge a field
against the others. An interactive logon is correct for a logon-triggered updater and wrong
for a nightly job. An empty `Start In` is harmless for `backup.exe /to C:\backups` and fatal
for `python rebuild.py`. taskpulse makes those judgements, and it makes them from the same
data those tools show.

## Requirements

Any Python 3.9 or later. The health report and the live lint need Windows, because they shell
out to the built-in `Get-ScheduledTask` / `Get-ScheduledTaskInfo` cmdlets, and to
`Get-WinEvent` when you pass `--history`. The lint on exported XML (`--lint PATH`) needs only
Python, on any OS. Nothing to install, nothing to configure, no credentials. Readers used to
Esri tooling should note that this needs no ArcGIS Pro, no `arcpy`, no `arcgis` package, and
no portal sign-in.

What it refuses to do:

* never creates, edits, enables, disables, deletes, starts or stops a task
* never opens a network connection, and never asks for or stores a credential
* never reads or writes a config file, because every knob is a command line flag
* never writes anywhere except stdout, or the single path you pass to `--out`, and only with
  `--apply`

The only write is `--out`, and it needs `--apply`. Without `--apply`, `--out` writes nothing.
The report goes to stdout, and stderr names the file that was not written. `--apply` without
`--out` is a usage error. So is an `--out` path that is an export the same run lints, or a
file inside a folder it lints, because one mistyped path would replace the export with its own
findings. The paths are compared as files, not as strings, so a `\\?\` spelling of the export
or a hard link to it is refused too. `--self-test` also writes its synthetic task files to a
temporary folder, which it removes. It writes no `__pycache__` beside the script, and an assertion checks that.

## Quick start

```console
git clone https://github.com/uhsear/taskpulse.git
cd taskpulse
python taskpulse.py --self-test
```

That is the whole setup. `--self-test` runs 416 assertions with no network, no credentials and
no Task Scheduler access, so it passes on a locked-down box and in CI. Then run
`python taskpulse.py` for the health report, or `python taskpulse.py --lint` for the lint.

## Usage

| Flag | Effect |
|---|---|
| `--format {table,json,csv}` | Output format. Default `table`. For the health report, `json` and `csv` carry all 20 fields per row and the table shows 5. Lint rows have 4 fields in every format. In `csv`, a cell that starts with `=`, `+`, `-`, `@`, a tab or a carriage return gets a leading `'`, because a spreadsheet runs such a cell as a formula and a task's author, account and command are text that anybody who registers a task can set. |
| `--out PATH` | With `--apply`, write to `PATH` in UTF-8 instead of stdout. The row count goes to stderr. Refused when `PATH` is an export this run lints, or inside a folder it lints, under any spelling or through a hard link. |
| `--apply` | Write `--out`. Without it nothing is written, and the report goes to stdout. |
| `--all` | Include Microsoft's own tasks under `\Microsoft\`. Excluded by default because there are roughly 200 of them. |
| `--show-ok` | Include healthy tasks. By default only `Warning` and `Error` rows print. With `--lint`, each task with no findings gets one `OK` row. |
| `--match REGEX` | Keep only tasks whose full path matches this regex, case insensitive. |
| `--history [DAYS]` | Also read the Task Scheduler Operational log and report each task's last 7 days of runs, its failures in that week, and its duration baseline. Default `30` days of events. Cannot be combined with `--lint`. |
| `--since-record-id ID` | With `--history`, read only event records newer than `ID`. Pass the watermark the previous run printed. The day window is then ignored. |
| `--lint [PATH ...]` | Report configuration findings instead of run health. With no `PATH`, lint the live Task Scheduler (Windows). With one or more `PATH`s, lint exported task XML files or folders (any OS). |
| `--local-drives LETTERS` | With `--lint`, the drive letters that are local disks, comma separated. Default `C`. Any other letter is reported as a possible mapped drive. |
| `--timeout SECONDS` | Task Scheduler query timeout. Default `120`. |
| `--self-test` | Run the offline assertion suite and exit. |
| `--version` | Print the version and exit. |
| `-h`, `--help` | Usage summary. |

Exit codes: `0` when nothing is in an `Error` state, `2` when at least one task is (or, with
`--lint`, when at least one finding is an `Error`), `1` when taskpulse itself failed, such as
an unreadable export, a subfolder of a linted folder that cannot be listed or is a symbolic
link, or an `--out` it
could not write, and `64` for a usage error, such as a
mistyped flag or an invalid `--match` regex. A usage error never
exits `2`, so a broken command line cannot read as a task in `Error`. That makes it usable as
a monitoring check. Run the health report and the lint as two checks. A task
can be healthy today and misconfigured for tomorrow, and the reverse. `--history` can add rows
to the report, because a task that failed every night this week and succeeded tonight is worth
printing, but it never changes the exit code: that still follows the current state alone.

A real health run on the development machine, scoped with `--match`:

```console
$ python taskpulse.py --match "ViGEm|Explorer"
STATUS  TASK                                SCHEDULE      LAST RESULT                 WHY
------  ----------------------------------  ------------  --------------------------  --------------------------
Error   \CreateExplorerShellUnelevatedTask  Registration  unmapped result 0x40010004  unmapped result 0x40010004
Error   \ViGEmBus_Updater                   Daily         unmapped result 0x00002EE7  unmapped result 0x00002EE7
```

## Configuration lint

`--lint` reads each enabled task's principal, triggers and every `Exec` action, and reports
these checks. A finding is an `Error` when the next run cannot work as configured. It is a
`Warning` when the result depends on something taskpulse cannot see offline.

| Check | Severity | Fires when |
|---|---|---|
| `interactive-only` | Error for a script, Warning for a plain program | The logon type is interactive ("Run only when user is logged on", or a group principal) and an enabled trigger fires unattended: one time, daily, weekly, monthly, at startup, or on an event. A disabled trigger never fires, so it does not count. |
| `s4u-network` | Error | The logon type is S4U ("Do not store password. The task will only have access to local computer resources.") and the action names a share: `\\server\share`, `//server/share` or `\\?\UNC\server\share`, alone or as a switch value such as `/LOG:\\server\share`. A `\\server\share` in the value of a secret switch counts too, but the finding does not name it. |
| `service-network` | Error for LOCAL SERVICE, Warning for SYSTEM and NETWORK SERVICE | A built-in account runs an action that names a share. LOCAL SERVICE reaches the network anonymously. The other two reach it as the computer account, which the share must grant. |
| `mapped-drive` | Warning | The action names a drive letter that is not in `--local-drives`, and the logon is not interactive. The letter counts as a drive root, such as `Z:\` or `Z:`, or in a drive-relative path with a dot or a separator after it, such as `Z:run.log` or `Z:out\daily`. A mapped drive exists only in the session that mapped it. |
| `start-in-quoted` | Error | `Start In` holds a quote, at one end or both. |
| `start-in-relative` | Error | `Start In` is not an absolute path. |
| `start-in-missing` | Error with a relative path, Warning for a script | `Start In` is empty. It is an Error when the action names a relative file path that the lint can see, and a Warning when it runs a script that might open one. A body run by `cmd /c` or `powershell -Command` that starts with `cd`, `pushd` or `Set-Location` and an absolute folder is exempt, quoted or not. An absolute folder starts with a drive and a separator, with `\`, or with a `%VARIABLE%`, or in PowerShell with a `$variable`. A relative folder, as in `cd scripts`, is not exempt, because it resolves against `C:\Windows\System32` too. A `cd` later in the body comes too late and is not exempt. In `cmd`, four more are not exempt: `cd %JOBS%` without `/d`, because the variable can name another drive; `cd D:\jobs` without `/d`, because it keeps the current drive; `cd C:`, which only prints that drive's current folder; and `cd \\server\share`, because `cmd` cannot make a share its current folder. `pushd \\server\share` maps the share and is exempt. |
| `bare-program` | Warning | The program has no folder, such as `python.exe`, and is not one of the Windows programs that are on every account's `PATH`. |

"A script" means the action runs an interpreter or a script file: Python, PowerShell, `cmd`,
a batch file, `cscript` or `wscript`. An interpreter counts with or without `.exe`, so
`powershell`, `cmd` and `...\envs\arcgispro-py3\python` are scripts too. A Python counts with
its version in its name, such as `python3.exe` or `python3.11.exe`, and so does the `py`
launcher, `py.exe`.

"A relative file path the lint can see" is a program or argument that is not rooted and that
holds a folder separator or ends in a known extension, such as `.py`, `.bat`, `.ps1` or
`.csv`. The value of a switch counts on its own, whether it follows a space, `=` or `:`, as in
`-in data.csv`, `--out=report.csv` or `/LOG:logs\run.txt`. Each word of a `cmd /c` or
`powershell -Command` body counts on its own too, whether the body is quoted or not.
PowerShell runs a body after any unique prefix of `-Command`, such as `-comm`, so the lint
splits those too. A body inside a body, such as `cmd /c powershell -Command "..."`, is split
with the switch of the program it starts. A program such as `refresh.bat` with no folder
counts, because no `PATH` holds your own script. A bare `.exe` such as `robocopy.exe` does not
count, because `PATH` finds it.

Some tokens never count as relative paths:

* A token with `:` after its second character, such as a URL, `svc:Hunter2` after `curl -u`,
  or `Authorization: Basic ...`. Windows allows `:` in a path only after a drive letter.
* The value of an account switch, `/user`, `--username`, `--login` or `schtasks /ru`, such as
  `/user:EXAMPLE\svc`. An account name is not a path.
* Every argument of `net`, which takes no file. So the password in
  `net use \\server\share <password> /user:EXAMPLE\svc` is never judged as a relative path,
  and cannot print as one.
* A token with `=` or `+` in it and no known extension, which is how base64 keys and
  connection strings look. Unless it is the value of a secret switch (below), no check
  reads it.
* The value of a switch whose name holds `key`, `token`, `secret`, `pass`, `pw` or `credential`.
  That covers `-apikey`, `-Token`, `--password`, `--pass`, plink's `-pw` and `--credential`,
  in a `cmd /c` or `powershell -Command` body too. Only the share check reads it, and only
  for the `\\server\share` form, which base64 never takes. The finding does not name that
  share. A switch such as `-PassThru` or `--use-keyring` takes no value, so the word after it
  is its "value". That word still meets the share check, so
  `Start-Process -PassThru \\fileserver\gis\refresh.exe` under S4U is an Error.

A finding prints a relative path only when it ends in a known extension or `.exe`. Any other
relative path prints as `(a value with no file extension, not printed)`, because a value
that only looks like a path, such as a password with a `/` in it, can be a secret.

The split between Error and Warning matters on a desktop. Vendor updaters routinely run
interactive on a daily trigger, and flagging each of them as an Error would bury the one
nightly Python job that matters. On the development machine, `--lint --all` gave 15
`interactive-only` findings. Every one ran a plain program, not a script, so each was a Warning
and the lint exited `0`. One more task there has an interactive logon and a disabled one-time
trigger beside its logon trigger. The lint does not report it, because that trigger never
fires.

These behaviours were measured on Windows 11 (build 26100), not taken from documentation. The
first four used throwaway tasks, and the last three used `cmd` started in `C:\Windows\System32`:

* A quoted `Start In` made the task fail with `0x8007010B`, "The directory name is invalid".
* With `Start In` empty, the action's working directory was `C:\Windows\System32`.
* `cmd /c tpprobe.cmd` with `Start In` empty ended with `Last Run Result` `0x1`, not "file not
  found". The script sat in another folder, and the result code did not say so.
* A bare program name ran when `Start In` held the program, and ended with `0x1` when
  `Start In` was empty. A bare name resolves against `Start In` first, and then against `PATH`.
* `cmd /c "cd D:\ && cd"` printed `C:\Windows\System32`. Without `/d`, `cd` does not change
  the drive. `cd /d D:\` printed `D:\`.
* `cmd /c "cd D:\ /d"` failed with "The system cannot find the path specified". A `/d` after
  the folder is read as part of the folder.
* `cmd /c "cd C: && cd"` printed `C:\Windows\System32` twice. `cd` with only a drive prints that
  drive's current folder and changes nothing.

`cd \\server\share` is not exempt because of documented `cmd` behaviour: `cmd` does not
support a share as its current folder. That case was not measured, because no share was
reachable from the test machine.

Exported XML comes in more shapes than one. `--lint PATH` reads all of these, and each shape
has an assertion in the self-test:

* One task per file, from `Export-ScheduledTask` or the Task Scheduler console.
* The `<Tasks>` wrapper that `schtasks /query /xml ONE` prints. Each task in it is named only by
  the `<!-- \Path\Name -->` comment before it.
* Several task documents pasted end to end, each with its own `<?xml ...?>` declaration.
* A folder, which is walked. A task file with no name inside it is named after its path
  relative to that folder, which is the task's path when the folder is a copy of
  `C:\Windows\System32\Tasks`. A subfolder that cannot be listed stops the run with exit `1`.
  On Ubuntu, a copy with one subfolder set to mode `000` exited `1` and named that subfolder.
  A subfolder that is a symbolic link stops the run with exit `1` too, because the walk lists
  it but does not enter it. On Ubuntu and on Windows, a linked subfolder exited `1` and named
  the link. A Windows junction is walked like a folder, and its tasks are linted.

With `--all`, a live `--lint` and a `--lint` of `schtasks /query /xml ONE` from the same
machine produced the same 20 findings, with the same task, check and severity in the same
order. Only the account named in 15 `interactive-only` details differs. The XML names the
principal by SID, and the live read names the user, or says "its user" for a group principal.

## Run history

The snapshot Task Scheduler keeps has one slot. It cannot tell you that a task has failed every
night for eight weeks, or that tonight's run took 175 times its usual duration, because the run
history lives in a separate event log that nothing joins to the task.

`--history` does that join. It reads events `100`, `102` and `201` from
`Microsoft-Windows-TaskScheduler/Operational`, groups them by instance id into one row per run,
and folds five columns onto each task: `runs_last_7_days`, `failures_last_7_days`,
`last_duration_seconds`, `duration_ratio` and `is_duration_anomaly`. A task whose last run was
green but whose week was not now prints, with the count in the `WHY` column.

Every history run prints, on stderr, how many events it read and the highest event record id it
saw. On a machine where the Operational log has never been enabled that line reads:

```console
$ python taskpulse.py --history
taskpulse: read 0 run event(s); next run can pass --since-record-id 0
```

That watermark is the point of the second flag. The Operational log is busy - on one server it
carried roughly 920 events a day, of which only about a quarter belonged to the monitored tasks -
so a flat 5000-event fetch reaches back about five days, not the thirty you asked for. Pass the
printed id back as `--since-record-id` and the next fetch reads only records newer than it, so
the event budget is never spent re-reading history you already have.

Two things to know before you trust the columns. The Operational log is **disabled by default on
Windows**; with it off, `--history` reports zero events and the audit falls back to the snapshot
rather than failing. And a run whose start event fell outside the window is not dropped: the
earliest event seen for that run is used as the start and the row carries
`start_time_estimated`, so an estimate cannot be read as a measurement.

The duration baseline is advisory. It never changes a task's health verdict, and it stays silent
until a task has five completed runs, so a new job cannot set a baseline off one sample.

## Configuration

There is none, deliberately. No config file is read, no environment variable is consulted, no
credential store is touched. Every behaviour is a flag, so what a run did is recoverable from the
command line that produced it.

Two things are worth knowing about the defaults. Microsoft's own tasks are hidden unless you pass
`--all`, so a stock box reports on your jobs rather than on the OS. The exit code is computed
after `--match` filtering, which means a scoped check like
`taskpulse.py --match "^\\Jobs\\"` exits `2` only for failures inside that scope.

## Why the obvious version is wrong

**HRESULT sign duality.** The same failure reaches you as `-2147024894` from one API and
`2147942402` from another. Compare either against a literal and half your matches vanish, so
every code is normalised with `& 0xFFFFFFFF` before anything looks at it. The decode then goes
through the OS message table rather than a hand-written dictionary, because a hand-written one
gets `0x8007052E` wrong, and that particular code is the one you most want named: it is a service
account whose password no longer works.

**Wrapper commands.** Most real tasks run `python.exe C:\jobs\etl.py` or
`powershell.exe -File C:\jobs\sync.ps1`. A report that prints the `Execute` field tells you
`python.exe` failed, which is true and useless. taskpulse walks the arguments, skips switches,
respects `-File`, `-Command`, `-c` and `-m`, and reports `etl.py` as the target. This is the one
column Task Scheduler genuinely cannot give you.

**Event log rescanning.** The tempting approach is to reconstruct the whole verdict from
`Microsoft-Windows-TaskScheduler/Operational`. That log is disabled by default on Windows, it
rolls over, and parsing it costs seconds per run for history you may not have. Current task state
is always present and always cheap, so the default report reads state alone and the event log is
opt-in, under `--history`. A tool that needs the log to say anything at all says nothing on a
stock box.

**Re-reading the same events.** The obvious incremental filter is a time window: fetch the last
thirty days each run. It does not hold, because the fetch is also capped by an event count. That
log carried roughly 920 events a day on one server, only about a quarter of them from the
monitored tasks, so a 5000-event window reached back about five days rather than thirty and the
rest of the month was silently absent. `--history` filters on `EventRecordID` above a watermark
instead, which is monotonic and costs nothing to store, and keeps the time window only for the
cold start when no watermark exists yet.

**Trusting the XML declaration.** Redirected from `cmd`, `schtasks /query /xml /tn <task>`
writes single-byte text under a declaration that says `encoding="UTF-16"`. Python's own XML
parser refuses that real output with "encoding specified in XML declaration is incorrect". So
taskpulse decodes the bytes itself, from the byte order mark or the byte pattern, and then
drops the declaration.

**Flagging every drive letter.** A check that warns on any `X:` in a command line warns on
`C:\Python39\python.exe`, which is every task. taskpulse treats `C:` as local and asks you to
name any other local disk with `--local-drives`. A letter it does not know is a Warning, not an
Error, because only the machine knows whether `D:` is a disk or a mapping.

## Limitations

* **The arcpy licence check is deferred.** The record of the incident above says that the
  logon type changed. It does not say which logon type the task landed on. The lint catches
  the logon changes that break a run as configured: an interactive-only logon on an unattended
  trigger, and an S4U or built-in account that must reach a share. It does not catch a logon
  that still runs the task but hides the licence from it. For example, an S4U job with only
  local paths lints clean. The lint does not check where an ArcGIS licence lives, or whether a
  given logon can read it. That needs `arcpy` and a live machine, and this tool has neither.
* **A relative path is found by its shape.** A token counts only when it has a folder
  separator or a known extension. `C:\R\bin\Rscript.exe job.R` with an empty `Start In` lints
  clean, because `.R` is not a known extension and `Rscript.exe` is not a known interpreter.
  A secret after a switch with a neutral name, such as `-data Zm9v/YmFy`, looks like a path.
  So does a secret after a one-letter switch, such as `sqlcmd -P`, and a password that `net use`
  takes inside a `cmd /c` body. With an empty `Start In`, each of these is a false
  `start-in-missing` Error, but the finding does not print the value, because it has no
  known extension. A one-letter `-P` or `-p` is a port or a path as often as a password, so it
  is not treated as a secret switch. A one-letter `-u` is not treated as an account switch,
  because to `python` it is a switch with no value. So `psexec -u EXAMPLE\svc` with an empty
  `Start In` is a false Error too. A share inside a token with `=` in it, such as
  `Server=\\dbhost\gis;Database=x`, is not seen by the share check, because that token is
  never read. The value of a secret switch meets only the share check, so a drive letter or a
  relative path in it is not reported. A quoted `cmd /c` body that starts with a rooted path
  holding a space keeps that path whole only when it ends in a known extension or `.exe`. So
  `cmd /c "C:\my tools\sync --all"` splits at the space and reports `tools\sync` as a relative
  path, which it does not print.
* **A drive-relative bare word is not a drive.** `Z:outbox`, with no dot or separator after
  the colon, reads the same as a tag such as `x:y`, so `mapped-drive` does not report it.
  `Z:\outbox`, `Z:outbox\daily` and `Z:run.log` are reported.
* **A console shows what its code page can.** Printed to a console or a pipe, a character
  that the console's code page cannot encode, such as a task name in Chinese on a cp1252
  console, prints as `\uXXXX`. `--out` with `--apply` writes UTF-8 and keeps it.
* **Offline, a path is text.** The lint never checks that a program, a script, a `Start In`
  folder or a share exists, or that an account holds permission on it. It judges only what the
  configuration says.
* **Disabled tasks are not linted.** A disabled task cannot fail a run. Re-enable it, then lint.
  A disabled trigger is left out in the same way, in the lint and in the health report.
* **`System32\Tasks` needs elevation.** Reading that folder needs an elevated shell. It was not
  read on the test machine, so the folder walk is exercised on a folder of real exports and on a
  synthetic tree in the self-test.
* **A code page cannot be recovered.** When exported bytes are neither UTF-16 nor valid UTF-8,
  they decode as Latin-1. The markup survives, but a non-ASCII task name can be misspelled.
* **Snapshot by default, history only on request.** Without `--history` the health report shows
  the last result and the next run, so a task that failed last week and has since succeeded looks
  clean. There is still no watch mode and no database: `--history` reads the event log once, in
  the same run, and keeps nothing between runs except the watermark you choose to pass back.
* **`--history` needs the Operational log enabled.** That log is off by default on Windows, and
  enabling it takes an administrator. With it off, `--history` reports zero events rather than
  failing, and every history column stays empty. A task's history also starts at the moment the
  log was enabled, not at the moment the task was created.
* **Elevation changes what you see.** Unelevated, tasks in protected folders and tasks owned by
  other users may be missing, or present with no `Get-ScheduledTaskInfo` detail. Rows with no
  detail still print, judged on triggers alone, but the audit is not complete.
* **Application exit codes are opaque.** The OS message table only knows OS codes. A task whose
  program exits `1` or `0x00002EE7` prints `unmapped result 0x...`, because inventing a meaning
  for an application's own code would be worse than admitting it is unknown.
* **Overdue is measured against the scheduler's own `NextRunTime`.** If the Task Scheduler
  service is stopped, that field goes stale and every recurring task looks overdue at once.
* **The live reads are Windows only.** On any other platform the health report and a live
  `--lint` exit `1` with a message rather than guessing. `--lint PATH` works everywhere.
* **XML with a DOCTYPE is refused.** taskpulse wraps each file in one root element, so that
  task documents pasted end to end parse together. That puts any DOCTYPE inside an element,
  where the parser rejects it as malformed. No entity can expand, and no third-party parser is
  needed. Task XML never carries a DOCTYPE.
* **There is no network path**, so there is nothing to test against a stub server.

## Contributing

Issues and pull requests are welcome. One request: any change to classification, decoding,
health or lint logic should arrive with assertions added to `self_test()` in `taskpulse.py`, and
`python taskpulse.py --self-test` should pass before and after. The suite is deliberately
dependency free and offline, so there is no framework to learn and no reason to skip it. It
reaches 100 percent branch coverage:

```console
python -m coverage run --branch taskpulse.py --self-test
python -m coverage report -m
```

## Author

Built by [Asir Khan](https://www.linkedin.com/in/asir-khan-310317264/).

## License

MIT.

## Related

Other single-file tools in this portfolio that pair with this one:

- [jobharness](https://github.com/uhsear/jobharness) - give the failing task logging, retry and resume
- [logsift](https://github.com/uhsear/logsift) - turn the logs those tasks write into a metric series
