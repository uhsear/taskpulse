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
PASS  a secret set in a quoted cmd /c or -Command body never reaches the target  <-- pinned defect
...
PASS  an unclosed trailing quote still splits into words, never one whole-line token  <-- pinned defect
PASS  an unclosed single quote is closed too, after a double quote fails
PASS  an unclosed quote never prints the secret and keeps the start-in-missing error (sync.exe)  <-- pinned defect
PASS  an unclosed quote never prints the secret and keeps the start-in-missing error (python.exe)  <-- pinned defect
...
PASS  the history script's catch hands every failed read to python with its error id, never an empty list  <-- pinned defect
PASS  the history script sends the log's oldest and newest record ahead of the events, and ahead of a failed read's error  <-- pinned defect
PASS  the history script asks whether the log is enabled before it queries, because a disabled log answers NoMatchingEventsFound  <-- pinned defect
...
PASS  access denied after a good range probe, the shape the script sends, still raises  <-- pinned defect
PASS  a watermark above the log's newest record, as after a clear, raises, never an empty history  <-- pinned defect
...
PASS  records past the watermark that the log overwrote make the read incomplete  <-- pinned defect
PASS  a cold start on a log younger than 7 days is incomplete  <-- pinned defect
...
PASS  past a watermark the read is oldest first, so a backlog is never skipped, and takes no time window  <-- pinned defect
PASS  a cold start reads the newest events of the DAYS window, so a capped read keeps the current week  <-- pinned defect
PASS  a watermark of 0, as an empty log prints, reads the whole log oldest first, so passing it back never skips a backlog  <-- pinned defect
PASS  a task whose run details could not be read is a Warning, not a task that has not run yet  <-- pinned defect
...
PASS  a failed action is not hidden by a later action's success, in either read order  <-- pinned defect
PASS  a warning code from one action does not hide another action's failure, in either read order  <-- pinned defect
PASS  a read that lands mid-run counts a failed action at once, because the next read sees only the rest of the run  <-- pinned defect
...
PASS  a run with an estimated start gets no duration  <-- pinned defect
...
PASS  an Error older than 7 days counts as neither a run nor a failure of the week, and a Warning or Unknown run is a run but not a failure  <-- pinned defect
...
PASS  past a watermark the columns count every run read, however old, and say they start at the watermark, not 'the last 7 days'  <-- pinned defect
...
PASS  a failed history read leaves the run counts empty and says so, never a clean week with 0 runs  <-- pinned defect
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
PASS  a capped cold read that does not reach back 7 days exits 1, never a clean report  <-- pinned defect
...
PASS  the default report keeps a task whose last run was green but whose week was not  <-- pinned defect
...
PASS  access denied after the range row exits 1 and never moves the watermark  <-- pinned defect
PASS  an access-denied history read names the error, still prints the snapshot and keeps the Error task's exit 2  <-- pinned defect
PASS  an access-denied history read with no task in Error exits 1, never 0
PASS  a disabled operational log exits 1 and says so, never a clean week with 0 runs  <-- pinned defect
...
PASS  the json of an access-denied read differs from a clean read of an empty log: null run counts, not 0  <-- pinned defect
...
PASS  an empty read moves the watermark to the log's newest record, so the next read does not report records the log overwrote since  <-- pinned defect
PASS  a watermark above the log's newest record, as after a clear, exits 1, never a clean empty history  <-- pinned defect
PASS  a log that rolled over past the watermark exits 1, never 0  <-- pinned defect
PASS  a cold start on a log that holds only 4 hours exits 1, never a clean week  <-- pinned defect
PASS  the --since-record-id 0 an empty log prints, passed back, reads the whole log oldest first, not a newest-first cold start  <-- pinned defect
...
PASS  --out without --apply writes nothing at all and prints the report  <-- pinned defect
...
PASS  --out as a hard link to the export is refused  <-- pinned defect
...
PASS  a prefix of --apply, such as --ap, is refused and writes nothing  <-- pinned defect
...
PASS  --history 0 or less, which matches no event, and --since-record-id without --history or below 0 are usage errors, not an empty history  <-- pinned defect
PASS  --history below 7 days is a usage error: a shorter read would still label its columns 'the last 7 days'  <-- pinned defect
...
PASS  a task the live read could not fully read exits 1, in the report and the lint, unless a task is in Error  <-- pinned defect
...
PASS  importing taskpulse runs nothing and prints nothing
PASS  the import probe writes no .pyc beside the script  <-- pinned defect
os message table: present
--------------------------------------------------------------------
497 assertions, 0 failed
```

The same command prints `497 assertions, 0 failed` on Windows with Python 3.13 and on Ubuntu
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

For run history, the console's per-task History tab is the existing alternative. It reads the
`Microsoft-Windows-TaskScheduler/Operational` log, filtered to the selected task, and its
Actions pane has `Enable All Tasks History`, which turns that log on. It shows every start,
action and result of one task, with no setup once the log is on. A one-line `Get-WinEvent`
XPath on the event's `TaskName` gives the same join from a script. What `--history` adds is
one pass over every task: the runs and failures of the week, a duration baseline, and an exit
code that a monitoring check can read.

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

That is the whole setup. `--self-test` runs 497 assertions with no network, no credentials and
no Task Scheduler access, so it passes on a locked-down box and in CI. Then run
`python taskpulse.py` for the health report, or `python taskpulse.py --lint` for the lint.

## Usage

| Flag | Effect |
|---|---|
| `--format {table,json,csv}` | Output format. Default `table`. For the health report, `json` and `csv` carry all 21 fields per row and the table shows 5. Lint rows have 4 fields in every format. In `csv`, a cell that starts with `=`, `+`, `-`, `@`, a tab or a carriage return gets a leading `'`, because a spreadsheet runs such a cell as a formula and a task's author, account and command are text that anybody who registers a task can set. |
| `--out PATH` | With `--apply`, write to `PATH` in UTF-8 instead of stdout. The row count goes to stderr. Refused when `PATH` is an export this run lints, or inside a folder it lints, under any spelling or through a hard link. |
| `--apply` | Write `--out`. Without it nothing is written, and the report goes to stdout. |
| `--all` | Include Microsoft's own tasks under `\Microsoft\`. Excluded by default because there are roughly 200 of them. |
| `--show-ok` | Include healthy tasks. By default only `Warning` and `Error` rows print. With `--lint`, each task with no findings gets one `OK` row. |
| `--match REGEX` | Keep only tasks whose full path matches this regex, case insensitive. |
| `--history [DAYS]` | Also read the Task Scheduler Operational log and report each task's last 7 days of runs, its failures in that week, and its duration baseline. `DAYS` is the window of events the read searches. The default is `30`, and it must be `7` or more, because the columns cover 7 days. With no watermark, a read takes at most 5000 events, newest first. A log that is disabled or cannot be read leaves the report without run history and makes the exit code `1`, or `2` when a task is in `Error`. Cannot be combined with `--lint`. |
| `--since-record-id ID` | With `--history`, read only event records newer than `ID`, oldest first. Pass the watermark the previous run printed, even `0`: `0` reads the whole log, oldest first. The day window is then ignored, and the run columns count the runs since `ID`, not the last 7 days (see [Run history](#run-history)). Without `--history`, or below `0`, it is a usage error. |
| `--lint [PATH ...]` | Report configuration findings instead of run health. With no `PATH`, lint the live Task Scheduler (Windows). With one or more `PATH`s, lint exported task XML files or folders (any OS). |
| `--local-drives LETTERS` | With `--lint`, the drive letters that are local disks, comma separated. Default `C`. Any other letter is reported as a possible mapped drive. |
| `--timeout SECONDS` | Task Scheduler query timeout. Default `120`. |
| `--self-test` | Run the offline assertion suite and exit. |
| `--version` | Print the version and exit. |
| `-h`, `--help` | Usage summary. |

Exit codes: `0` when nothing is in an `Error` state and taskpulse saw everything it reports
on. `2` when at least one task is in `Error` (or, with `--lint`, when at least one finding is
an `Error`). `64` for a usage error, such as a mistyped flag or an invalid `--match` regex.
`1` when taskpulse itself failed, or could not see everything:

* an unreadable export, a subfolder of a linted folder that cannot be listed or is a symbolic
  link, or a failed inventory read; no report prints then
* an `--out` it could not write
* a task whose run details, actions or triggers the live read could not get
* an Operational log that is disabled or that `--history` cannot read
* a `--history` read that the event cap stopped, before it reached back 7 days or past a
  watermark
* a watermark above the log's newest record, records past the watermark that the log
  overwrote, or a cold start on a log that holds less than 7 days

A flag must be typed in full: a prefix such as `--ap` is a usage error, not `--apply`, so a
typed prefix cannot write. A usage error never exits `2`, so a broken command line cannot read
as a task in `Error`. That makes it usable as a monitoring check. Run the health report and the
lint as two checks. A task can be healthy today and misconfigured for tomorrow, and the
reverse.

`--history` can add rows to the report, because a task that failed every night this week and
succeeded tonight is worth printing. It never makes the exit code `2`: that still follows the
current state alone. When the history read fails or is incomplete, the report still prints,
stderr says why, the `WHY` column says `run history unread` or `run history incomplete`, and
the exit code is `1`. When a task is in `Error`, the exit code is `2` all the same, so a
disabled log never hides a failing task from a check.

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
| `read-failed` | Warning | The live read could not get the task's actions, triggers or run details, so the other checks may have missed a finding. An exported XML task never gets it. |

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
night for weeks, or that tonight's run took over a hundred times its usual duration, because
the run history lives in a separate event log. The console's History tab joins that log to one
task at a time.

`--history` joins it to every task in one pass. It reads events `100` (task started), `102`
(task completed), `200` (action started) and `201` (action completed, with its result code)
from `Microsoft-Windows-TaskScheduler/Operational`. It groups them by instance id into one
row per run, and folds five columns onto each task: `runs_last_7_days`, `failures_last_7_days`,
`last_duration_seconds`, `duration_ratio` and `is_duration_anomaly`. A task whose last run was
green but whose week was not now prints, with the count in the `WHY` column. A task with
several actions writes one `201` per action, and a failed action makes the run fail, whatever
the other actions returned, warning codes included. A failed `201` counts at once, even
while the run's later actions still run.

Each row also has a `history` field, which says how its run columns were read:

* `off`: no `--history`. `runs_last_7_days` and `failures_last_7_days` are `null` in `json`
  and empty in `csv`.
* `failed`: the read failed, for example on a disabled log or access denied. The two counts
  are `null` or empty, and `WHY` says `run history unread`.
* `incomplete`: the event cap or the log's range left runs unread. The counts are a lower
  bound, and `WHY` says `run history incomplete`.
* `complete`: the counts are exact. A task with no run in the read counts `0`.

A failed read never writes `0` runs and `0` failures. So a saved `--out` file of a failed read
cannot match the file of a clean read of an empty log.

Every history read that succeeds prints, on stderr, how many events it read and the watermark
for the next run. A failed read prints its error instead, and the report prints without run
history. On the development machine the Operational log is disabled, which is the Windows
default. The two tasks in `Error` still print, and the run exits `2`, as it does without
`--history`. With a `--match` that keeps no task in `Error`, the same run prints
`No tasks need attention.` and exits `1`:

```console
$ python taskpulse.py --history --match "ViGEm|Explorer"
taskpulse: the Task Scheduler Operational log could not be read (LogDisabled): the log is disabled, so it holds no run history; an administrator can enable it with: wevtutil sl Microsoft-Windows-TaskScheduler/Operational /e:true
taskpulse: the report has no run history, so it is incomplete
STATUS  TASK                                SCHEDULE      LAST RESULT                 WHY
------  ----------------------------------  ------------  --------------------------  ----------------------------------------------
Error   \CreateExplorerShellUnelevatedTask  Registration  unmapped result 0x40010004  unmapped result 0x40010004; run history unread
Error   \ViGEmBus_Updater                   Daily         unmapped result 0x00002EE7  unmapped result 0x00002EE7; run history unread
$ echo $?
2
```

That watermark is the point of the second flag. The Operational log is busy. On one server it
carried roughly a thousand events a day, and only about a quarter of them belonged to the
monitored tasks. That figure was observed once, on one server, and was not reproduced here.
At that rate a 5000-event read reaches back about five days, not the thirty you asked for.
Pass the printed id back as `--since-record-id`, and the next read takes only the records
newer than it, oldest first. A read that the cap did not stop prints the log's newest record
id, even when it found no event, because it has seen every record up to that one. Only a log
with no record prints `0`, and `0` passed back reads the whole log oldest first.

Each read also asks the log for its oldest and newest record, and its oldest record's time.
Three answers then make the report incomplete, and the run exits `1`, or `2` when a task is
in `Error`:

* A watermark above the log's newest record. A cleared log restarts its record ids, and a
  typo or a watermark from another server does the same. The read would answer "no events"
  on every run until the ids pass it, so taskpulse says so and reads no history. Pass `0` to
  start again.
* An oldest record above the watermark plus one. The circular log overwrote records past the
  watermark before this run read them, and stderr names the lost range. The next watermark
  continues from what was read.
* A cold start on a log whose oldest record is younger than 7 days, because the log was just
  enabled, or rolled over. The 7-day columns cannot be complete then.

The same script, pointed at the Application log of the development machine with the cap set
to 3, was run with a watermark of `1000000000000`. It exited `1` with "is above the newest record of the log
(9652157)". A watermark of `100` exited `1` with "the log no longer holds records 101 to
9626824". A watermark at the newest record exited `0`.

The two modes answer different questions:

* **No watermark (a cold start).** The read takes the newest events in the `DAYS` window, and
  the columns cover the 7 days before now. If the cap stops the read before it reaches back 7
  days, stderr says the report is incomplete, and the run exits `1`, not `0`. If the read
  still reaches back 7 days, the columns are complete, and stderr says the duration baseline
  covers fewer days than asked.
* **With a watermark.** taskpulse keeps nothing between runs, so the columns count the runs
  read since the watermark, however old, and the `WHY` column says `since record ID`, not
  `in the last 7 days`. Run nightly, each failure is counted by the one run that first read
  it. A task that failed last night was already reported last night, so tonight it prints
  only if it is still failing, or failed again since. If the cap stops the read, the run exits
  `1`, and the next run continues from the printed watermark.

Things to know before you trust the columns:

* The Operational log is **disabled by default on Windows**. A disabled log answers "No
  events were found" (`NoMatchingEventsFound`), the same answer as an empty log, even to an
  invalid query. So the history script first asks the log whether it is enabled
  (`Get-WinEvent -ListLog`). A disabled log is a failed read with `LogDisabled`. Only
  `NoMatchingEventsFound` from an enabled log is an empty history: `--history` then reports
  zero events. Any other failed read names the error, and the report prints without run
  history, with exit `1`, or `2` when a task is in `Error`. On the development machine,
  unelevated, the script pointed at the Security log failed with `LogInfoUnavailable`
  ("Attempted to perform an unauthorized operation"). Pointed at the Application log, which
  is enabled, it read its events.
* Past a watermark, events are read oldest first, at most 5000 per run, so the printed
  watermark covers only records that were read. On the Application log with the cap set to 3,
  two runs in a row each read the 3 records just past the watermark they were given. The read
  asks for one event more than the cap, so a read of exactly 5000 events is not called
  incomplete.
* A run whose start event was not read is not dropped. Its start event can fall outside the
  window, or the cap can cut it off from the rest of the run. The earliest event seen for that
  run is used as its start, and the run is marked as estimated internally. No output format
  shows that mark, so the report does not say which runs had an estimated start. Such a run
  counts towards the week and its failures, but it gets no duration. Its 201 and 102 events land
  seconds apart, so an estimated duration would read as a near-zero run and trip the baseline.

The duration baseline is advisory. It never changes a task's health verdict, and it stays silent
until a task has five completed runs in one read, so a new job cannot set a baseline off one
sample. With a watermark, a nightly task polled nightly has one run per read, so its baseline
never arms. Run a cold `--history` now and then to see it.

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
log carried roughly a thousand events a day on one server, only about a quarter of them from the
monitored tasks, so a 5000-event window reached back about five days rather than thirty and the
rest of the month was silently absent. `--history` filters on `EventRecordID` above a watermark
instead, which is monotonic and costs nothing to store, and keeps the time window only for the
cold start when no watermark exists yet.

**Silencing the history read.** The obvious way to survive a disabled log is
`Get-WinEvent ... -ErrorAction SilentlyContinue`. That also hides access denied, a missing log
and every other failure. Each of them then reads as a quiet week with no failures. The second
trap is `-FilterHashtable`. Unelevated on Windows 11, a hashtable query of the Security log
answered `NoMatchingEventsFound`, the same answer as an empty log. The same query written as
`-LogName` with `-FilterXPath` answered `System.UnauthorizedAccessException`. So taskpulse uses
only the XPath form, and treats only `NoMatchingEventsFound` as an empty history. The third
trap is the disabled log itself: it answers `NoMatchingEventsFound` too. So taskpulse first
reads the log's `IsEnabled` flag, and a disabled log is a failed read.

**Reading from the wrong end.** `Get-WinEvent` returns the newest events first. Past a
watermark, that loses records: `-MaxEvents` keeps the newest 5000, and the next watermark passes
every older record unread. On the Application log, a read of 3 events past one record id
returned the 3 newest records. With `-Oldest`, the same read returned the 3 records just past
the watermark. So past a watermark, taskpulse reads with `-Oldest`. On a cold start the
opposite holds. No watermark exists yet, so there is no backlog to protect, and oldest first a
capped read keeps the oldest days of the window. A synthetic 30-day log of 17400 events had a
job that failed the 6 nights before tonight. Read oldest first, the 5000 events held no run of
the current week, so the job reported 0 runs, 0 failures and `success`, and the default report
hid it. Read newest first, the same log reported `6 of 7 run(s) in the last 7 days failed`.
So the cold start reads newest first.

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
  enabling it takes an administrator. With it off, `--history` names `LogDisabled`, prints the
  report without run history, and exits `1`, or `2` when a task is in `Error`. A task's
  history also starts at the moment the log was enabled, not at the moment the task was
  created. Any read that fails for another reason, such as access denied, is handled the same
  way. An access-denied read of the Operational log itself was not produced, because that log
  is disabled on the test machine. The Security log stood in for that case. Unelevated, it
  failed in the `-ListLog` call (`LogInfoUnavailable`) before the event read ran, so an
  `UnauthorizedAccessException` from the event read itself is covered only by a stub.
* **A busy log can hide part of the first week.** With no watermark, the read takes the newest
  5000 events. On a log with more than about 700 matching events a day, they do not reach back
  7 days. That run exits `1`, and its columns miss the older runs. Those older runs are never
  read, because the printed watermark starts after them.
* **The history exit code is 1, not 2.** A failed history read is a failure of taskpulse
  itself, so it exits `1`, as a failed inventory read does. Exit `2` means a task in `Error`,
  and a failed history read still exits `2` when a task is in `Error`. Then the `history`
  field, `failed`, tells the two runs apart. The original specification named exit `2` for a
  failed read, and taskpulse departs from it on purpose. Under Nagios-style checks, exit `1`
  means WARNING, not UNKNOWN. The specification also named exit `2`
  for a mistyped flag such as `--ap`. taskpulse exits `64` for every usage error, for the same
  reason.
* **Elevation changes what you see.** Unelevated, tasks in protected folders and tasks owned by
  other users may be missing, or present with no `Get-ScheduledTaskInfo` detail. A task whose
  run details, actions or triggers could not be read is a `Warning`, with "the live read could
  not get its ..." in the `WHY` column, and the lint reports it as `read-failed`. Either way
  the run exits `1`, or `2` when a task is in `Error`. On the development machine no task
  failed that read, even with `--all`, so this exit is covered by the self-test only. A
  missing task gets no row at all, so the audit is not complete.
* **Events of a task the inventory could not see still move the watermark.** An unelevated run
  reads the events of a protected task but has no row to join them to. A later elevated run
  with that watermark never counts those runs.
* **The log's range is read just before its events.** A record that the log overwrites
  between those two reads is lost without a warning. The gap is the time between two calls
  in one script, so it is short, but it was not measured.
* **A watermark can be wrong in a way the range cannot show.** After a clear, once the log
  refills and its new record ids pass a saved watermark, the records below it are skipped.
  This happens only when no run took place between the clear and that point.
* **One run can count in two watermark reads.** A read that sees a run's start but not its
  end counts it, and the read that sees the end counts it again, with an estimated start. The
  counts of each read are exact, but a total over several reads can count one run twice.
* **Only a `201` result marks a failed run.** A run whose action never launched writes no
  `201`, so it reads as `Unknown` and is not counted as a failure. taskpulse does not read the
  `101`, `103` and `203` launch-failure events.
* **The `--history` join is case sensitive.** If the event log spells a task's path in another
  case than the inventory, for example after a re-registration, those runs join to no task and
  are not counted.
* **A `--match` that matches no task is a clean run.** It prints `No tasks need attention.` and
  exits `0`, so a check scoped to a renamed, deleted or unreadable task stays green.
* **The event filter is near the XPath limit.** The limit counts clauses, so it depends on the
  query form. On the Application log of the development machine, the watermark form ran with
  22 event ids and failed with 23 ("The specified query is invalid"). The cold-start form,
  which adds the time window, ran with 21 and failed with 22. taskpulse names 4. A
  `HISTORY_EVENT_IDS` past the limit would make every `--history` read exit `1`.
* **An estimated start is late.** A run whose `100` event was not read takes its first event
  read as its start. That time is later than the real start, so a run that started just over
  7 days ago can still count towards the last 7 days.
* **An event whose XML cannot be parsed is dropped.** It loses its task name and instance id,
  so it joins to no task, and nothing reports that it was skipped. An event that names no task
  is dropped in the same way.
* **One unreadable event fails the whole read.** `-ErrorAction Stop` makes an error on a single
  event stop `Get-WinEvent`, so the run exits `1` rather than skipping that event. This was not
  measured.
* **The self-test does not pin a read that returns both events and an error**, because the
  history script cannot produce one.
* **Output from PowerShell that is neither a JSON object nor a JSON list stops the run.** A
  bare JSON string stops it with a traceback, and a bare JSON number with a one-line message.
  The exit code is then `1`, never `0`.
* **Empty output from a successful inventory read is taken as a box with no tasks.** If
  PowerShell exits `0` and prints nothing, the report is empty and exits `0`. A working
  PowerShell never does this.
* **With `--since-record-id`, the `*_last_7_days` fields count the runs since that record**,
  whatever their age. The field names do not change.
* **Non-ASCII task names can be misspelled.** Windows PowerShell 5.1 writes redirected output
  in the OEM code page, and taskpulse decodes it as UTF-8. Measured, the accented letter of a
  name arrived as byte `0x82` (code page 437) and decoded as a replacement character. The
  inventory and the event log are misspelled the same way, so the `--history` join still holds.
  A `--match` that spells the original name can miss such a task. Two tasks whose names differ
  only in such letters read as one name, so the `--history` join merges their runs.
* **The lint example's export is not in the repo.** `gis-tasks.xml` above is a synthetic file
  that is not one of the four files, so you cannot rerun that exact block.
* **The measured counts are point-in-time.** The 15 `interactive-only` findings and the 20
  findings above were measured once. A rerun on the same machine later gave 16 and 21, because
  its task set changed.
* **Branch coverage was measured on Windows only.** Coverage is not installed on the Linux
  host, so the Linux-only branches, such as a missing OS message table, are covered by stubs
  in the Windows run.
* **The quoted self-test run is an excerpt.** Each `...` stands for `PASS` lines left out. Every
  line shown appears in a real run, in that order, and the footer count is the full count.
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
* **`<Enabled>0</Enabled>` reads as enabled.** XML allows `0` for false, but the reader
  compares with `false`, which is what Windows writes. An export with `0` on the task or on a
  trigger then gets lint findings for a task or trigger that never runs.
* **A principal with two `<LogonType>` elements is judged by the first.** Such a file breaks
  the task schema, and its second logon type can hide an `interactive-only` Error.
* **An export with a NUL byte in it gets a confusing message.** It is refused with "'utf-16-le'
  codec can't decode ... truncated data". The exit code is still `1`.
* **A failed inventory read leaves `--out` as it was.** The run exits `1` and writes nothing,
  so a dashboard that reads only that file sees the previous run's report.
* **`--out` is written in place.** It is not written to a temporary file and renamed, so a
  crash or a full disk during the write leaves a truncated report at that path.
* **The table prints names as they are.** Task names, authors, accounts and `Start In` values
  are text that anyone who registers a task sets. A terminal control sequence in one of them
  reaches the console unchanged.
* **PowerShell is started by its bare name.** Windows looks in the current folder before
  System32, so a `powershell.exe` planted in the folder you run taskpulse from runs instead of
  the real one. Windows also searches the folder of the running `python.exe` first, so a
  `powershell.exe` planted in the Python install folder runs too. Run taskpulse from a folder
  that only you can write to, with a Python install that only administrators can change.
* **The table cuts a cell at 60 characters.** A long `WHY` can lose its `run history unread`
  or `run history incomplete` note in the table. `json` and `csv` keep the whole field.
* **The log-range read is checked as script text only.** The self-test cannot run PowerShell,
  so an inverted `RecordCount` test in the history script would go unnoticed offline.
* **Starting a watermark at 0 on a log that has rolled over reports a loss once.** The log no
  longer holds its first records, so that first run names them as overwritten and exits `1`.
* **A run is dated by its start.** On a cold start, a run that began more than 7 days ago and
  failed inside the last 7 days is left out of that week's failures.
* **An out-of-range `--since-record-id` or `DAYS` fails the history read.** A value such as
  `10**23` makes `Get-WinEvent` answer "The specified query is invalid", so the run exits `1`,
  or `2` when a task is in `Error`.
* **A PowerShell host that prints nothing reads as an empty log.** If the history script exits
  `0` with no output, a run with `--since-record-id 0` reports an empty history and exits `0`.
  The script always prints a range row or an error row, so only a broken host can cause this.
* **A log that was off for a while can look complete.** If the log is disabled, enabled again
  and keeps its old records, a cold start sees an old oldest record. It then calls the 7-day
  columns complete, although runs in the off period were never logged. Whether a disabled log
  keeps its records was not measured.
* **A log cleared during a read can look clean.** If the log is cleared after the script reads
  its range but before it reads the events, the empty answer reads as a clean history, and
  that run exits `0`. The next watermark run then exits `1`, because its watermark is above
  the new newest record. If the log is cleared before the range read, no range row comes
  back, so a run with `--since-record-id 0` reports an empty history and exits `0`.
* **A partly denied log was not seen to answer "no events".** On a log whose access list
  lets `-ListLog` report a record count but denies reading the records, the read raised
  `UnauthorizedAccessException` and failed loudly. A host that answers
  `NoMatchingEventsFound` there instead was not observed.
* **Check the exit code, not only the JSON.** A failed history read with `--format json` and
  no task needing attention prints `[]`, the same as a clean run, and exits `1`.
* **Python 3.9 reads only some timestamp precisions.** On 3.9 a timestamp with 1, 2, 4 or 5
  fractional digits is read as having no time. PowerShell's round-trip format always writes
  7, so real input is not affected.
* **The self-test needs hard links in its temporary folder.** On a FAT or exFAT temporary
  folder, `os.link` fails, and the self-test stops with an `OSError` instead of a count.
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
