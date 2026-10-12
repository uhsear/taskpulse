# taskpulse

Audits Windows scheduled tasks for silent failures and for the configuration that causes them,
from one read-only command.

A production GIS refresh ran every night as a scheduled task. Then a PowerShell settings change
switched the task's logon type, and nobody saw it happen. Under the new logon `arcpy` could not
see its licence, and the refresh broke. Task Scheduler's `Last Run Result` did not name the
cause. Until the next run, it still showed the previous night's success. The task carried a
configuration that broke its next run, and every field anyone looked at said it was fine.

taskpulse does four jobs. The health report joins the fields Task Scheduler keeps apart and
prints one verdict per task. With `--history` it also reads what became of each launch, so a run
that never ends is `STUCK` and a task whose latest launch was refused is `BLOCKED`. The lint
(`--lint`) reads each task's configuration and names what will make the next run fail or be
skipped: a logon type that only runs while somebody is logged on, a logon type that differs from
the tasks beside it, a `Start In` that is empty, quoted or relative, a share the run-as account
cannot reach, a program that only `PATH` can find, a run with no time limit, a trigger that has
ended. `--diff OLD NEW` compares two exports of the same tasks and names each field that changed,
so the logon type that flipped last night is a row, not a hunt. The lint and the diff read
exported task XML, so they run on any OS. Standard library only, no install, no config file, no
credentials.

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
...
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
PASS  event 103, the action could not start, makes the run an Error with its code, though no 102 or 201 followed  <-- pinned defect
...
PASS  event 101 has no instance id, because no instance existed: each is a run of its own, named after its record, and an Error  <-- pinned defect
...
PASS  a terminated or user-stopped run is a Warning and over, a run stopped for exceeding its time limit is an Error, and none of them is Running  <-- pinned defect
...
PASS  a 322 naming a running instance neither ends it nor moves its start  <-- pinned defect
...
PASS  a run with no end event on a task that is Ready or Queued is a lost end event, not a stuck run  <-- pinned defect
...
PASS  a run that is only 2 hours old is not STUCK although later launches were ignored while it ran: a slow job on a short repeat interval is healthy  <-- pinned defect
PASS  a task the scheduler says is Running since a launch 24 hours or more ago is STUCK although this read holds no start event for the run; Ready, Queued and a missing launch time are not  <-- pinned defect
...
PASS  a history read that failed ignores any fate: nothing was read, so nothing is judged  <-- pinned defect
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
PASS  a quote opens in the middle of a word, an apostrophe inside a name does not, and an unclosed quote is closed at the end of the line  <-- pinned defect
...
PASS  a secret in the Command field is masked in the lint finding and in the target, and a path with spaces is not touched  <-- pinned defect
...
PASS  utf-8 bytes whose declaration still says UTF-16 parse  <-- pinned defect
...
PASS  a disabled Daily trigger never fires, so a task left with a logon trigger is not interactive-only  <-- pinned defect
...
PASS  an export with no <Enabled> element, as Windows writes every enabled task, is linted  <-- pinned defect
...
PASS  an unlimited run on a task with no MultipleInstancesPolicy is a Warning: the schema default, IgnoreNew, drops every later launch  <-- pinned defect
...
PASS  a task whose every trigger has ended is a Warning that names the last end and the result code Task Scheduler gives it  <-- pinned defect
...
PASS  the one task whose logon type differs from two neighbours is named, with theirs
...
PASS  a setting written out at its default, in any case, equals one left out  <-- pinned defect
...
PASS  a task that gains DeleteExpiredTaskAfter PT0S is a change: Microsoft says an absent element means the task is never deleted, and PT0S deletes it at once  <-- pinned defect
...
PASS  a monthly trigger that moves one of its repeated Day or Week values is a change; the last value kept used to hide it  <-- pinned defect
PASS  a timestamp past the last UTC instant is None, not an OverflowError  <-- pinned defect
...
PASS  by default the arguments are compared but not printed, and a changed one says so  <-- pinned defect
...
PASS  a logon change on a task that runs ArcGIS Pro's Python also names the licence conditions  <-- pinned defect
...
PASS  a quoted or attached secret, a net command inside a cmd /c body, curl's -u and -H, -pSECRET, --pswd, --cred, --signature, -EncodedCommand, -k and a JSON password, secret, token or key member are all masked  <-- pinned defect
PASS  a word with a quoted space, such as msiexec's TARGETDIR="C:\Program Files\App", does not recurse for ever, and a secret in one is still masked  <-- pinned defect
...
PASS  --diff of a net use inside cmd /c prints neither password  <-- pinned defect
...
PASS  the password in a URL is masked, wherever the URL sits, and a URL with no password is not touched  <-- pinned defect
...
PASS  the value of -P, -p and --auth is masked, and --author and other letters are not  <-- pinned defect
...
PASS  no secret reaches the json diff of command line 7  <-- pinned defect
PASS  a change to a secret is reported as a change, with the value left out  <-- pinned defect
...
PASS  a secret in a shape the mask does not know, 1, stays out of the json diff and the change is still reported  <-- pinned defect
...
PASS  a subfolder the walk cannot list stops the read, not a clean lint  <-- pinned defect
PASS  a subfolder that is a symbolic link, which the walk lists but never enters, stops the read  <-- pinned defect
...
PASS  the health report --match that matches no task is not 'No tasks need attention'  <-- pinned defect
...
PASS  a capped cold read that does not reach back 7 days exits 1, never a clean report  <-- pinned defect
...
PASS  the default report keeps a task whose last run was green but whose week was not  <-- pinned defect
...
PASS  --stuck-hours without --history, below 1, not a number, or typed as a prefix is a usage error  <-- pinned defect
...
PASS  access denied after the range row exits 1 and never moves the watermark  <-- pinned defect
PASS  an access-denied history read names the error, still prints the snapshot and keeps the Error task's exit 2  <-- pinned defect
PASS  an access-denied history read with no task in Error exits 1, never 0
...
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
PASS  --diff prints no arguments by default, and still exits 2 on a changed one  <-- pinned defect
...
PASS  --diff --match that matches no task is not a clean diff  <-- pinned defect
PASS  two files that define one task on a side stop --diff, on either side: the verdict never depends on file order  <-- pinned defect
...
PASS  --diff of two exports that hold only Microsoft's own tasks has no result: exit 1 and a notice, never 'No differences'  <-- pinned defect
...
PASS  --lint of an export that holds only Microsoft's own tasks has no result: exit 1 and a notice, never 'No findings'  <-- pinned defect
...
PASS  --out on an export that --diff compares is refused and the export is untouched  <-- pinned defect
...
PASS  --diff takes exactly two paths, cannot be combined with --lint or --history, and cannot be typed as a prefix  <-- pinned defect
...
PASS  --history 0 or less, which matches no event, and --since-record-id without --history or below 0 are usage errors, not an empty history  <-- pinned defect
PASS  --history below 7 days is a usage error: a shorter read would still label its columns 'the last 7 days'  <-- pinned defect
...
PASS  with no row, the --out file of a failed history read matches a clean one, so only the exit code tells them apart  <-- pinned defect
PASS  a task the live read could not fully read exits 1, in the report and the lint, unless a task is in Error  <-- pinned defect
...
PASS  importing taskpulse runs nothing and prints nothing
PASS  the import probe writes no .pyc beside the script  <-- pinned defect
os message table: present
--------------------------------------------------------------------
711 assertions, 0 failed
```

The same command prints `711 assertions, 0 failed` on Windows with Python 3.13, 3.12 and 3.9, and
on Ubuntu with Python 3.12. On Linux there is no OS message table, so the line above the footer
rule reads `os message table: absent, so its assertions check the unmapped fallback`. Six
assertions then check the `unmapped result 0x...` text instead of the Windows wording, and the
count stays equal.

The lint, run on Linux against a synthetic `schtasks /query /xml ONE` export (every name in it
is made up). The two `logon-minority` rows are the incident in one view: two jobs of one account
use a logon type that differs from the one that the four others in their folder share:

```console
$ python3 taskpulse.py --lint gis-tasks.xml
SEVERITY  TASK                         CHECK             DETAIL
--------  ---------------------------  ----------------  -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Error     \GIS\export-to-share         s4u-network       logon type is S4U ('Do not store password'), which has no network credentials, so \\fileserver\gis is unreachable
Error     \GIS\locator-rebuild         start-in-missing  Start In is empty, so the relative path rebuild.py resolves against C:\Windows\System32
Error     \GIS\nightly-parcel-refresh  interactive-only  logon type is interactive: the task runs only while EXAMPLE\svc-etl is logged on, so its Daily trigger does nothing when nobody is
Error     \GIS\tile-cache              start-in-quoted   Start In "C:\tile work" is quoted; Task Scheduler does not strip the quotes and the task fails to start with 0x8007010B (the directory name is invalid)
Warning   \GIS\export-to-share         logon-minority    logon type s4u differs from the 4 other task(s) in this folder that run as EXAMPLE\svc-etl, which use password: if this is not deliberate, a settings change flipped it
Warning   \GIS\locator-rebuild         bare-program      python.exe has no folder, so it resolves against Start In and then the run-as account's PATH; which program runs, if any, depends on that account
Warning   \GIS\nightly-parcel-refresh  logon-minority    logon type interactive differs from the 4 other task(s) in this folder that run as EXAMPLE\svc-etl, which use password: if this is not deliberate, a settings change flipped it
Warning   \GIS\report-mailer           no-time-limit     ExecutionTimeLimit is PT0S (run indefinitely), so a hung run never ends and every later launch is dropped without an error (Task Scheduler logs each as event 322, which --history reports)
Warning   \GIS\sync-to-mapped-drive    mapped-drive      Z: is not a declared local drive (--local-drives); a mapped drive does not exist in a non-interactive logon, so use the UNC path
$ echo $?
2
```

The diff, run on Linux against two synthetic exports of the same tasks, taken a day apart. The
logon type of `nightly-parcel-refresh` flipped, and because that task runs ArcGIS Pro's Python
the diff adds the licence note. `report-mailer` lost its time limit. `tile-cache` moved its
trigger and changed an argument that the diff does not print, because it prints no
arguments unless `--show-args` is given. `unchanged` had its default settings
written out in the second export, and it is not a row:

```console
$ python3 taskpulse.py --diff monday.xml tuesday.xml
CHANGE   TASK                         FIELD                       OLD                                                                                  NEW
-------  ---------------------------  --------------------------  -----------------------------------------------------------------------------------  -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
removed  \GIS\export-to-share
added    \GIS\locator-rebuild
changed  \GIS\nightly-parcel-refresh  logon type                  Password                                                                             InteractiveToken
changed  \GIS\nightly-parcel-refresh  arcpy-licence                                                                                                    this task runs ArcGIS Pro's Python: arcpy raises RuntimeError: NotInitialized unless Esri's sign-in conditions hold for the account that runs it, and a task definition does not show them, so check them for the new account or logon type
changed  \GIS\report-mailer           setting ExecutionTimeLimit  PT1H                                                                                 PT0S
changed  \GIS\tile-cache              trigger                     Daily Enabled=true, ScheduleByDay.DaysInterval=1, StartBoundary=2026-01-01T02:00:00  Daily Enabled=true, ScheduleByDay.DaysInterval=1, StartBoundary=2026-01-01T03:30:00
changed  \GIS\tile-cache              action 1                    Exec C:\Python39\python.exe [arguments not shown] [Start In C:\jobs]                 Exec C:\Python39\python.exe [arguments not shown] [Start In C:\jobs] (a value changed that is not printed)
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

The same History tab already shows the run-fate events: a task that failed to start (`101`),
a run that was terminated (`111`) and a launch that was ignored because the task was still
running (`322`). Each is exact, and each has Microsoft's own message text. What the tab does not
do is rank them. It does not say that a run which began 40 hours ago and never ended is stuck,
or that the last launch of a task was refused and nothing has started since. taskpulse applies
those two rules to every task at once.

For the diff, the existing alternative is a text diff of two exports: `schtasks /query /xml ONE`
or `Export-ScheduledTask`, then `fc`, `diff` or `Compare-Object`. It shows every byte that
changed, and it needs nothing new. On the development machine, `Export-ScheduledTask` and
`schtasks` wrote the same XML for most tasks, once indentation and the XML declaration were
ignored, and the rest differed in one quote character of a description. So a text diff is
a good tool for two exports from one writer. It is not enough when the export changes shape
without the task changing: a setting written out at its default, triggers in another order, or
a new registration date. Those are text changes and not task changes. `--diff` does not report
them, and it names the field when something did change.

## Requirements

Any Python 3.9 or later. The health report and the live lint need Windows, because they shell
out to the built-in `Get-ScheduledTask` / `Get-ScheduledTaskInfo` cmdlets, and to
`Get-WinEvent` when you pass `--history`. The lint on exported XML (`--lint PATH`) and the diff
(`--diff OLD NEW`) need only Python, on any OS. Nothing to install, nothing to configure, no credentials. Readers used to
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
`--out` is a usage error. So is an `--out` path that is an export the same run lints or
compares, or a file inside a folder it reads, because one mistyped path would replace the
export with its own findings. The paths are compared as files, not as strings, so a `\\?\` spelling of the export
or a hard link to it is refused too. `--self-test` also writes its synthetic task files to a
temporary folder, which it removes. It writes no `__pycache__` beside the script, and an assertion checks that.

## Quick start

```console
git clone https://github.com/uhsear/taskpulse.git
cd taskpulse
python taskpulse.py --self-test
```

That is the whole setup. `--self-test` runs 711 assertions with no network, no credentials and
no Task Scheduler access, so it passes on a locked-down box. Then run
`python taskpulse.py` for the health report, `python taskpulse.py --lint` for the lint, or
`python taskpulse.py --diff old.xml new.xml` to compare two exports.

## Usage

| Flag | Effect |
|---|---|
| `--format {table,json,csv}` | Output format. Default `table`. For the health report, `json` and `csv` carry all 23 fields per row and the table shows 5. Lint rows have 4 fields in every format, and diff rows have 5 (`change`, `task`, `field`, `old`, `new`). In `csv`, a cell that starts with `=`, `+`, `-`, `@`, a tab or a carriage return gets a leading `'`, because a spreadsheet runs such a cell as a formula and a task's author, account and command are text that anybody who registers a task can set. |
| `--out PATH` | With `--apply`, write to `PATH` in UTF-8 instead of stdout. The row count goes to stderr. Refused when `PATH` is an export this run lints or compares, or inside a folder it reads, under any spelling or through a hard link. |
| `--apply` | Write `--out`. Without it nothing is written, and the report goes to stdout. |
| `--all` | Include Microsoft's own tasks under `\Microsoft\`. Excluded by default because there are so many. This holds for `--lint PATH` and `--diff` too: they skip those tasks in the files they read, print how many on stderr, and exit `1` when none was left. |
| `--show-ok` | Include healthy tasks. By default only `Warning` and `Error` rows print. With `--lint`, each task with no findings gets one `OK` row. |
| `--match REGEX` | Keep only tasks whose full path matches this regex, case insensitive. When it matches no task at all, nothing was examined: taskpulse says so on stderr and exits `1`, with no output, so a check scoped to a renamed or deleted task does not stay green. |
| `--history [DAYS]` | Also read the Task Scheduler Operational log and report each task's last 7 days of runs, its failures in that week, its duration baseline, and whether it is `STUCK` or `BLOCKED` (see [Run fate](#run-fate)). `DAYS` is the window of events the read searches. The default is `30`, and it must be `7` or more, because the columns cover 7 days. With no watermark, a read takes at most 5000 events, newest first. A log that is disabled or cannot be read leaves the report without run history and makes the exit code `1`, or `2` when a task is in `Error`. Cannot be combined with `--lint` or `--diff`. |
| `--stuck-hours HOURS` | With `--history`, a run with no end event after this many hours is `STUCK`. Default `24`. It must be `1` or more. Without `--history`, it is a usage error. |
| `--since-record-id ID` | With `--history`, read only event records newer than `ID`, oldest first. Pass the watermark the previous run printed, even `0`: `0` reads the whole log, oldest first. The day window is then ignored, and the run columns count the runs since `ID`, not the last 7 days (see [Run history](#run-history)). Without `--history`, or below `0`, it is a usage error. |
| `--lint [PATH ...]` | Report configuration findings instead of run health. With no `PATH`, lint the live Task Scheduler (Windows). With one or more `PATH`s, lint exported task XML files or folders (any OS). |
| `--diff OLD NEW` | Compare two exports of the same tasks (files or folders, any OS) and print one row for each field that changed, each task added and each task removed. Exits `0` when the tasks it compared match and `2` when they differ, and `1` when every task was under `\Microsoft\` and skipped (see [Task definition diff](#task-definition-diff)). Takes exactly two paths. Cannot be combined with `--lint` or `--history`. |
| `--show-args` | With `--diff`, print the arguments of each action. They can hold a secret that the mask does not know, and a change shows both the old and the new value, so do not paste or commit the output. By default the diff compares arguments but prints `[arguments not shown]`. Without `--diff`, it is a usage error. |
| `--local-drives LETTERS` | With `--lint`, the drive letters that are local disks, comma separated. Default `C`. Any other letter is reported as a possible mapped drive. |
| `--timeout SECONDS` | Task Scheduler query timeout. Default `120`. |
| `--self-test` | Run the offline assertion suite and exit. |
| `--version` | Print the version and exit. |
| `-h`, `--help` | Usage summary. |

Exit codes: `0` when nothing is in an `Error` state and taskpulse saw everything it reports
on. `2` when at least one task is in `Error` (or, with `--lint`, when at least one finding is
an `Error`). With `--diff`, `2` means the two exports differ in at least one row, and `0` means
they match. `64` for a usage error, such as a mistyped flag or an invalid `--match` regex.
`1` when taskpulse itself failed, or could not see everything:

* a `--lint PATH` or `--diff` whose tasks were all under `\Microsoft\` and skipped, so nothing
  was examined; pass `--all`
* a `--match` that matches no task, in the health report, `--history`, `--lint` and `--diff`
  (with `--diff`, no task on either side), so nothing was examined
* an unreadable export (with `--diff`, either of the two), a subfolder of a linted folder that
  cannot be listed or is a symbolic link, or a failed inventory read; no report prints then
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
disabled log never hides a failing task from a check. A `STUCK` or `BLOCKED` task is a
`Warning`. Like the other warnings, it prints in the default report and leaves the exit code
alone, so a check that must fail on one reads the `fate` field of the `json` or `csv` output.

A real health run on the development machine, scoped with `--match`:

```console
$ python taskpulse.py --match "ViGEm|Explorer"
STATUS  TASK                                SCHEDULE      LAST RESULT                 WHY
------  ----------------------------------  ------------  --------------------------  --------------------------
Error   \CreateExplorerShellUnelevatedTask  Registration  unmapped result 0x40010004  unmapped result 0x40010004
Error   \ViGEmBus_Updater                   Daily         unmapped result 0x00002EE7  unmapped result 0x00002EE7
```

## Configuration lint

`--lint` reads each enabled task's principal, triggers, settings and every `Exec` action, and reports
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
| `no-time-limit` | Warning | `ExecutionTimeLimit` is zero (`PT0S`, "run indefinitely") and `MultipleInstancesPolicy` is not `StopExisting`. A hung run never ends. Under the default policy, `IgnoreNew`, every later launch is dropped without an error, and under `Queue` they wait behind it. Under `Parallel` they pile up beside it. Only `IgnoreNew` drops launches, so only its finding names event `322` ("Launch request ignored, instance already running"), which `--history` reads. |
| `run-conditions` | Warning | `RunOnlyIfIdle` or `RunOnlyIfNetworkAvailable` is true. The task is set to run only while the computer is idle, or only while a network is available, so a trigger that fires while that is false can leave the run unstarted, and `Last Run Result` still shows the previous run. |
| `trigger-expired` | Warning | Every enabled trigger has an `EndBoundary` more than a day in the past, so no trigger can start the task again. Task Scheduler reports `0x00041304` ("no more runs"), which the health report counts as a non-error. A time with no zone is the machine's local time, which an export does not say, so a trigger counts as ended only a day after its end. |
| `logon-minority` | Warning | The task's logon type differs from its neighbours. Neighbours are the enabled tasks in the same folder that run as the same account. The type has to be shared by two or more of them, and by more than any other type, so a tie names nobody. A heuristic: a task can differ on purpose. |
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
nightly Python job that matters. On the development machine, `--lint --all` gave several
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
machine produced the same findings, with the same task, check and severity in the same
order, in five checks: `run-conditions`, `no-time-limit`, `interactive-only`, `start-in-missing`
and `bare-program`. Only the account named in the `interactive-only` details differs. The XML
names the principal by SID, and the live read names the user, or says "its user" for a group
principal. The new checks needed the live query to ask for more, so it now also reads each
task's `MultipleInstancesPolicy`, `ExecutionTimeLimit`, `RunOnlyIfIdle` and
`RunOnlyIfNetworkAvailable`, and each trigger's `EndBoundary`. Without `--all`, the live lint
of the development machine gave a short list of findings in four checks: `interactive-only`,
`start-in-missing`, `bare-program` and `run-conditions`.

### Silent skips, and the defaults that hide them

A run that is skipped leaves no failure. `Last Run Result` keeps the last run's code, so the
health report reads green. Three checks above (`no-time-limit`, `run-conditions`,
`trigger-expired`) look for the configuration that does this, and `logon-minority` looks for
the change that starts it. They apply the Task Scheduler schema's defaults to what an export
leaves out, because an absent element is a setting, not a gap. Every default below is from
Microsoft's documentation. `DeleteExpiredTaskAfter` is the one element that gets none, and it
is explained after the table:

| Setting | Default when the element is absent | Source |
|---|---|---|
| `MultipleInstancesPolicy` | `IgnoreNew`: "Does not start new instance if an existing instance of the task is running." | [multipleInstancesPolicyType](https://learn.microsoft.com/en-us/windows/win32/taskschd/taskschedulerschema-multipleinstancespolicytype-simpletype) |
| `ExecutionTimeLimit` | 72 hours: "By default, a task will be stopped 72 hours after it starts to run." `PT0S` runs indefinitely. | [ITaskSettings::ExecutionTimeLimit](https://learn.microsoft.com/en-us/windows/win32/api/taskschd/nf-taskschd-itasksettings-get_executiontimelimit) |
| `RunOnlyIfIdle`, `RunOnlyIfNetworkAvailable` | `false` | [settingsType](https://learn.microsoft.com/en-us/windows/win32/taskschd/taskschedulerschema-settingstype-complextype) |
| `Enabled`, `AllowStartOnDemand`, `AllowHardTerminate`, `DisallowStartIfOnBatteries`, `StopIfGoingOnBatteries` | `true` | settingsType |
| `StartWhenAvailable`, `WakeToRun`, `Hidden`, `UseUnifiedSchedulingEngine`, `DisallowStartOnRemoteAppSession` | `false` | settingsType |
| `Priority` | `7` | settingsType |

`ExecutionTimeLimit` is the one default that the schema does not give: its element has no
`default=` attribute, and the 72 hours come from the `ITaskSettings` page. The two agree in
practice. On the development machine, `schtasks /query /xml ONE` left the `ExecutionTimeLimit`
element out of many tasks, and the live read reported `PT72H` for every one of them. For the
others, the XML and the live read gave the same limit. The default is why the lint treats an
absent limit as 72 hours, not as unlimited, and why the two readers agree.

`DeleteExpiredTaskAfter` gets no default, although the schema's `default="PT0S"` attribute
suggests one. The prose on [its element page](https://learn.microsoft.com/en-us/windows/win32/taskschd/taskschedulerschema-deleteexpiredtaskafter-settingstype-element)
says "If no value is specified for this element, then the Task Scheduler service will not delete
the task". `PT0S` is the opposite: delete the task as soon as it expires. Treating an absent
element as `PT0S` would hide, from `--diff`, a change that makes a task delete itself. An absent
element compares as blank, so `--diff` reports the change to `PT0S` (the self-test pins it).

Two more defaults are not applied, because Microsoft documents none. The principal's `LogonType`
page lists `S4U`, `Password` and `InteractiveToken` and says nothing about an absent one, so an
absent `LogonType` is unknown and no logon check fires on it. The `RunLevel` page lists no
default either, so `--diff` shows an absent run level as blank.

`logon-minority` is the one check here that is not a Task Scheduler rule. The disaster in
this README was a logon type that changed on one task while its neighbours kept theirs. The
check compares each task with the tasks beside it, and it cannot know whether the change was
deliberate, so it is a Warning that names the type everyone else uses.

## Run history

The snapshot Task Scheduler keeps has one slot. It cannot tell you that a task has failed every
night for weeks, or that tonight's run took over a hundred times its usual duration, because
the run history lives in a separate event log. The console's History tab joins that log to one
task at a time.

`--history` joins it to every task in one pass. It reads events `100` (task started), `102`
(task completed), `200` (action started) and `201` (action completed, with its result code)
from `Microsoft-Windows-TaskScheduler/Operational`, and nine run-fate events that say a launch
ended some other way (see [Run fate](#run-fate)). It groups them by instance id into one
row per run, and folds five columns onto each task: `runs_last_7_days`, `failures_last_7_days`,
`last_duration_seconds`, `duration_ratio` and `is_duration_anomaly`. A task whose last run was
green but whose week was not now prints, with the count in the `WHY` column. A task with
several actions writes one `201` per action, and a failed action makes the run fail, whatever
the other actions returned, warning codes included. A failed `201` counts at once, even
while the run's later actions still run. Two more columns, `fate` and
`blocked_launches_last_7_days`, come from the run-fate events.

Each row also has a `history` field, which says how its run columns were read:

* `off`: no `--history`. `runs_last_7_days` and `failures_last_7_days` are `null` in `json`
  and empty in `csv`.
* `failed`: the read failed, for example on a disabled log or access denied. The two counts
  are `null` or empty, and `WHY` says `run history unread`.
* `incomplete`: the event cap or the log's range left runs unread. The counts are a lower
  bound, and `WHY` says `run history incomplete`.
* `complete`: the read covered the whole period that the counts describe. A task with no
  run in the read counts `0`. A run whose start failed (events `101`, `103`, `203`) counts as a
  failure. A launch that Task Scheduler refused (`153`, `322`, `332`) is not a run at all, and
  has its own count.

A failed read never writes `0` runs and `0` failures. So a saved `--out` file of a failed read
differs from the file of a clean read of an empty log only when it holds at least one row. When
no task needs attention, both files are the same: `[]` in `json`, a header in `csv`, and
`No tasks need attention.` in the table. Only the exit code tells them apart: `1` for the
failed read, `0` for the clean one.

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

That watermark is the point of the second flag. The Operational log is busy. On one server most
of its events belonged to tasks other than the monitored ones. That was observed once, on one
server, and was not reproduced here. On such a log a 5000-event read can reach back only a few
days, not the thirty you asked for.
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
(N)", where N was the log's newest record id. A watermark of `100` exited `1` with "the log no
longer holds records 101 to M", where M was one below its oldest record id. A watermark at the newest record exited `0`.

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

### Run fate

A launch can end in ways that no `201` event records, and that `Last Run Result` hides behind
the last good run. Windows lists them in the log's provider manifest. This table is from
`Get-WinEvent -ListProvider Microsoft-Windows-TaskScheduler`, reading its `Events`, on Windows
11 build 26100. The `Manifest name` column holds the `Name` of each event's task in that
manifest.

| Event | Manifest name | Fields it carries | What taskpulse makes of it |
|---|---|---|---|
| `101` | `TaskStartFail` | task, user, result code | A run of its own, because no instance existed. It is an `Error`, and counts as a failure. |
| `103` | `TaskFailure` | task, instance, user, result code | The run is an `Error`. |
| `203` | `ActionFailedToStart` | task, instance, action, result code | The run is an `Error`. |
| `111` | `TaskTerminated` | task, instance | The run is over and is a `Warning`. |
| `329` | `StoppingOnTimeout` | task, instance | The run is over and is an `Error`: the scheduler stopped it for exceeding its time limit. |
| `330` | `StoppingOnRequest` | task, instance, user | The run is over and is a `Warning`. |
| `153` | `MissedTaskRejected` | task | A refused launch of kind `missed`. |
| `322` | `NewInstanceIgnored` | task, the running instance | A refused launch of kind `overlap`. It names the instance that was still running. |
| `332` | `NoStartUserNotLogged` | task, user | A refused launch of kind `no-session`. |

A run that `111`, `329` or `330` ended gets no end time and no duration, so it never reaches
the duration baseline. That rule assumes Windows logs no `102` after the termination. If it
does, the run gets that `102`'s time as its end and a duration, and the duration can feed the
baseline. A refused launch is not a run, so `runs_last_7_days` does not count it.
The history script needed no change to read these events. The task name, the instance id (as
`InstanceId` or `TaskInstanceId`) and the result code have the same names in every one of them.

Two rules turn those events into a verdict for each task:

* **STUCK.** A run has no end event, and the task's own `state` is not `Ready` or `Queued`,
  and the run began `--stuck-hours` ago or more (default 24). A `322` that names the run's
  instance does not make a younger run stuck, because a healthy job that runs longer than its
  repeat interval draws a `322` for every trigger. The `322` count goes into the detail of a
  run that is stuck by age. A task whose state is `Ready` is not running, so a run
  with no end event there is a lost end event, and it is not called stuck. A state that is
  missing, as in an export, rules nothing out. A task whose live `state` is `Running` and whose
  last launch was `--stuck-hours` ago or more is also STUCK, even when the log holds no start
  event for that run, because the event is older than the log, than `--history` or than the
  5000-event cap.
* **BLOCKED.** The task is not stuck, and its latest refused launch inside the window is newer
  than its latest start in this read, so nothing has run since. The window is the one the run
  columns use: the last 7 days, or everything since the watermark.

Two columns carry the result. `fate` is `STUCK`, `BLOCKED` or empty. `blocked_launches_last_7_days`
counts the refused launches in the window, `0` for a quiet task, and is `null` when the
history was not read. A `STUCK` or `BLOCKED` task is at least a `Warning`, so the default report
keeps its row, and the `WHY` column starts with the reason. An `Error` stays an `Error` and a
disabled task stays disabled. The exit code does not change. A run against synthetic tasks and
events, because the Operational log of the development machine is disabled. The self-test builds
the same stub and checks that its table has these four rows (the check named "the run-fate
example in the README"), but it does not print the table:

```console
$ python taskpulse.py --history
taskpulse: read 13 run event(s); next run can pass --since-record-id 23
STATUS   TASK                         SCHEDULE  LAST RESULT                              WHY
-------  ---------------------------  --------  ---------------------------------------  ------------------------------------------------------------
Error    \GIS\locator-rebuild         Daily     The user name or password is incorrect.  The user name or password is incorrect.; 1 of 1 run(s) in th
Warning  \GIS\nightly-parcel-refresh  Daily     success                                  STUCK: a run started 40.0 hour(s) ago has not finished; task
Warning  \GIS\report-mailer           Daily     success                                  STUCK: a run started 50.0 hour(s) ago has not finished; 2 la
Warning  \GIS\tile-cache              Daily     success                                  BLOCKED: the latest launch was refused because the run-as us
$ echo $?
2
```

`report-mailer` is stuck by age, and two later launches were ignored while it ran. The
`json` row says so in full: `STUCK: a run started 50.0 hour(s) ago has not finished; 2 later
launch(es) were ignored while it ran (event 322); task is currently running`, with
`blocked_launches_last_7_days` at 2. `tile-cache` ran 30 hours ago, and a `332` came 5 hours
ago. The exit code is `2` because `locator-rebuild` is in `Error`; the two stuck tasks and the
blocked one are warnings.

`--stuck-hours` moves the threshold. A job that legitimately runs for 30 hours needs
`--stuck-hours 36`. A 90-minute job on an hourly trigger is not stuck: while it runs, each
ignored launch is a `322`, so the task reads `BLOCKED` until the run ends. Neither rule needs
the event log to be complete: a refused launch in the window blocks a task even when its last
run is out of the read.

## Task definition diff

`--diff OLD NEW` reads two exports of the same tasks, files or folders, in any of the shapes
`--lint` reads, and prints one row for each task that was added, each task that was removed,
and each field of a task that changed. A task is matched by its full name, without regard to
case, so a rename is one removed task and one added task. The question it answers is "what
changed", and the answer is a field name with the old and the new value.

What it compares, and how it makes two spellings of one thing equal:

* **The account, its logon type and its run level.** `Interactive` and `InteractiveToken` are
  one logon type, as are `InteractiveTokenOrPassword` and `Password`. An account is compared
  without regard to case.
* **Every `Settings` element, with the schema default applied** to a side that leaves it out
  (see [the defaults](#silent-skips-and-the-defaults-that-hide-them)). A setting written out
  at its default, in any case, equals one left out. An element with no documented default
  compares as blank when absent.
* **The triggers, in any order.** A trigger is its kind and every field below it, with
  `Enabled` taken as true when the export says nothing. Two identical triggers are two
  triggers: one of them is a row if the other export has only one.
* **The actions, in order.** A program, its arguments and its `Start In`. A COM handler is
  compared by every field but shown by its class id. The arguments are compared, but they are
  not printed unless `--show-args` is given (see below).

It leaves out `RegistrationInfo`: the date, the author and the description change when a
task is registered again, and they do not change what runs.

Like the health report, `--diff` and `--lint PATH` skip the tasks under `\Microsoft\` unless
`--all` is given. Each says on stderr how many tasks it skipped. When that leaves no task on
either side, there is nothing to compare, so the exit code is `1` and the output is empty. It
is never `No differences.` over zero tasks.

The arguments of an action can hold a secret, and a diff that changes one shows both the old
and the new value. A mask can only list the secret shapes it knows, and a token in a URL path,
a bare positional password or `sqlplus scott/X@db` has no name to match. So the diff does not
print arguments by default. A row for an action shows the program and the `Start In`, then
`[arguments not shown]`, and a change that only the arguments hold reads `(a value changed that
is not printed)` and exits `2`. `--show-args` prints the arguments. Their help says they can
hold a secret, so do not paste or commit that output. With `--show-args`, the arguments go
through `mask_arguments`, a second layer and not a guarantee. It replaces with `***`: the value of a switch whose name holds
`key`, `token`, `secret`, `pass`, `pw`, `pswd`, `cred`, `auth` (but not `author`), `bearer`,
`signature` or `encodedcommand`, or is `sas`, `sig`, `pat` or `rp`; the value of a one-letter
`-P`, `-p` or `-k`, which are the password of `sqlcmd` and `mysql` and a common name for a key, and the rest of an attached
`-pSECRET` or `-PSECRET` (but not a PowerShell parameter such as `-Path` or `-Port`); the value of a JSON member whose name holds `key`, `token`, `secret`, `pass`, `pw`, `cred`, `auth` (but not `author`), `bearer` or `signature`, as in `{"password":"X"}`; the word
after such a switch that has no value of its own; a value, quoted or not, that has spaces in it
and follows such a switch; a value with `=` or `+` in it and no file extension, which is how
base64 keys and connection strings look; the password in the `user:password@host` of a URL; the
`user:password` after `-u`, `-U`, `--user`, `--login` or `--proxy-user`; the value of a header
whose name holds `key`, `token`, `secret`, `pass`, `auth`, `cookie`, `bearer`, `signature` or
`session`, as in `-H "X-Api-Key: ..."` or `-H "Authorization: Bearer ..."`; and every argument
of `net`, which takes its password by position. That holds for a `net` command inside a `cmd /c`
or `-Command` body too, up to the next `&`, `|` or `;`. A `cmd /c` body is masked word by word.
When a secret changes and the mask makes both sides read the same, the row says `(a value
changed that is not printed)`, so the change is not lost. The self-test greps the table, the
`csv` and the `json` of seven such changes, printed with `--show-args`, for the secrets, and
finds none. It masks 32 more command-line shapes, from `-Password "a b"` to `curl -u
user:pass`, and checks each one. It also prints seven changes in shapes the mask does not know,
such as a token in a webhook URL path and `etl.py X`, without `--show-args`, and finds no secret
in any of the three formats. The program field is masked the same way when it holds a command
line, as in `sync.exe --password x`.

### The licence note

The README's disaster was a logon type that changed and took an `arcpy` licence with it.
When the account, the logon type or the run level of a task changed, and the task runs ArcGIS
Pro's Python, the diff adds a row named `arcpy-licence`. A task runs ArcGIS Pro's Python when
its command line holds the `ArcGIS\Pro\bin\Python` folder, the `arcgispro-py3` environment or
`propy`. Esri documents all three:
[the default environment is `arcgispro-py3`](https://doc.esri.com/en/arcgis-pro/latest/arcpy/get-started/what-is-conda.html)
and [`propy` starts Python](https://doc.esri.com/en/arcgis-pro/latest/arcpy/get-started/installing-python-for-arcgis-pro.html).

Esri's page on running Python outside the application says that one of four conditions must
hold, and that otherwise "a RuntimeError: NotInitialized exception appears when importing
arcpy or arcgisscripting". The four are that "Sign me in automatically" was checked when
signing in to ArcGIS Pro, that ArcGIS Pro is open, that it has been authorized to work
offline, and that "Remember my certificate" was checked for a PKI portal. For a Named User
licence, [the page on scheduling tools](https://doc.esri.com/en/arcgis-pro/latest/help/analysis/geoprocessing/basics/schedule-geoprocessing-tools.html)
adds that "Sign in automatically" is required, and that the token "has a maximum expiration
time set by the account administrator". None of this is in the task definition, and the diff
cannot read it. The note says which task to check, and for which account. It is not a probe
of the licence (see Limits).

On the development machine, the tasks outside `\Microsoft\` were exported twice, with
`Export-ScheduledTask` (one UTF-16 file per task, in a folder) and with `schtasks /query /xml ONE`
(one file for every task). `taskpulse.py --diff` of the folder against the file gave
`No differences.` and exit `0`. It also printed on stderr that the file's tasks under
`\Microsoft\` were not examined. With `--all` the same command printed one `added` row for each
of them, so the match holds only for the tasks outside `\Microsoft\`.

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
log held mostly events of other tasks on one server, so a 5000-event window reached back only a
few days rather than thirty and the rest of the month was silently absent. `--history` filters
on `EventRecordID` above a watermark instead, which is monotonic and costs nothing to store, and
keeps the time window only for the cold start when no watermark exists yet.

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

**Reading a 322 as a run.** Event `322` carries an instance id, so the obvious join files it
under that instance as one more event of the run. It is the opposite: it is a launch that did
not happen, and the id it carries is the run that was still going. Filed as an event of that run,
it would create a run out of nothing whenever the run's own events are outside the read, and
that run would have the refusal's time as its start. So taskpulse keeps the refused launches (`153`, `322`, `332`) out
of the run rows and reads a `322` only for what it says: this instance is holding up the task.

**Treating an absent element as a gap.** A lint that skips a setting the export leaves out
would pass a hand-written task, and a diff that compares the text would call the same task
different once Windows writes the default out. On the development machine, most tasks have
no `ExecutionTimeLimit` element, and every one runs under a 72-hour limit. So the lint and the
diff both put the documented default in its place before they judge. Where Microsoft documents
no default, as for `LogonType`, they put nothing in its place.

**Diffing the XML as text.** A text diff reports every change in the file, and some of those are
not changes in the task. A trigger list in another order, a setting written out at its default
and a new registration date all change the text and nothing else. A diff that cannot tell them
apart gets ignored the first night it reports one.

## Limits

* **There is no licence probe, only a licence note.** The record of the incident above says
  that the logon type changed. It does not say which logon type the task landed on. The lint
  catches the logon changes that break a run as configured: an interactive-only logon on an
  unattended trigger, and an S4U or built-in account that must reach a share. The diff names
  a changed account, logon type or run level on a task that runs ArcGIS Pro's Python, and
  quotes the four conditions Esri documents (see [the licence note](#the-licence-note)). It
  does not read whether those conditions hold, and a probe would need one of two things that
  this tool does not have. Esri documents the conditions, but not where an account's sign-in
  is kept, so a probe that reads a file or a registry key for it would rest on a claim that
  cannot be checked against the documentation. The other way is to import `arcpy` as the
  task's account, which needs that account, takes a licence, and is not read-only. An S4U job
  with only local paths still lints clean.
* **STUCK needs the run's start in the same read, or a live `Running` state.** taskpulse keeps
  nothing between runs. With a watermark, a run whose `100` event an earlier read took has no
  row in this read. A task that Task Scheduler still reports as `Running` since a launch
  `--stuck-hours` ago or more is STUCK all the same. A task that is not running now is not,
  and its next refused launch (`322`) leaves it `BLOCKED`. A
  cold `--history` sees the whole window and finds it. A task with no instance that Task
  Scheduler logged, such as one that hangs before its first event, has nothing to be stuck on.
* **The run-fate path was exercised with synthetic events.** The Operational log of the
  development machine is disabled, and enabling it needs an administrator. So no real
  `101`, `103`, `111`, `153`, `203`, `322`, `329`, `330` or `332` event was read. What was run
  for real: the provider manifest that names them, the history script's own event-to-row code
  on synthetic event XML shaped like that manifest (all nine events came out with the right
  task, instance and result code), and the 13-event filter against the Application log. The
  rest is the self-test's stub. The link between the `IgnoreNew` policy and event `322` rests
  on Microsoft's wording for both, which the README quotes, and not on a measured run.
* **Five events from the manifest are not read.** `202` (action failed to complete), `328`
  (stopped because the computer is no longer idle), `331` (failed to stop on timeout) and `333`
  and `334` (launch refused in a RemoteApp or worker session) are not in the filter. A run that
  one of them ends without a `201` reads as `Running` or `Unknown`.
* **Two more events from the manifest are not read, and one of them is a refused launch.**
  Event `135` (`NoStartWithoutIdle`, "could not start because the machine was not idle") is
  refused like `153` and `332`, and event `150` is a failed event-trigger subscription. A
  run-only-if-idle refusal therefore never makes a task `BLOCKED`.
* **A run that was refused is counted by the log, not by the task.** `blocked_launches_last_7_days`
  counts events. A task that fires every minute and is blocked all day has a large count, and one
  that is blocked once has `1`; neither number is a measure of how long the block lasted.
* **`--stuck-hours` is a guess.** The default of 24 hours suits a nightly job. A job that
  legitimately runs longer is reported `STUCK` until its threshold is raised.
* **A run slower than its repeat interval reads BLOCKED while it runs.** Each trigger that
  fires during the run draws a `322`, which is a refused launch, so a healthy 90-minute job on
  an hourly trigger is `BLOCKED` until it ends and a later launch starts. That is true: launches
  were dropped. It is not `STUCK`, because a `322` alone does not make a young run stuck.
* **BLOCKED does not check whether the run that caused it has finished.** A refusal that is
  newer than the latest start in the read keeps the task `BLOCKED` after a green run, while it
  is `Ready`, until its next launch starts. With a watermark, `BLOCKED` is judged only on the
  events of the current read.
* **A start with no end event can make a task STUCK later.** If the host rebooted mid-run, that
  start stays open. Whenever the task is `Running` again, the report names the old run's age,
  such as 240.0 hours, even beside a healthy 12-minute run.
* **A disabled task whose last run never logged an end event has the fate STUCK**, because only
  `Ready` and `Queued` rule `STUCK` out. Its status stays `Disabled`, so the default table
  hides the row in every format. It shows with `--show-ok`, and its `fate` field says `STUCK`
  in the `json` and `csv` output.
* **STUCK and BLOCKED never change the exit code.** A check that reads only the exit code stays
  green over a hung job. Read the `fate` field of the `json` or `csv` output if a hung or
  blocked job must fail a check.
* **Event `101` is filed as a run of its own.** If Windows also logs a `103` or `203` for the
  same failed launch, one failure counts twice. No real `101`, `103` or `203` event was read, so
  this is unchecked.
* **The health table cuts every cell at 60 characters.** Task names that differ only after
  character 60 look identical, and the `WHY` text of a `STUCK` row can stop mid-word. Use
  `--format json` for the full text.
* **A relative path is found by its shape.** A token counts only when it has a folder
  separator or a known extension. `C:\R\bin\Rscript.exe job.R` with an empty `Start In` lints
  clean, because `.R` is not a known extension and `Rscript.exe` is not a known interpreter.
  A secret after a switch with a neutral name, such as `-data Zm9v/YmFy`, looks like a path.
  So does a secret after a one-letter switch, such as `sqlcmd -P`, and a password that `net use`
  takes inside a `cmd /c` body. With an empty `Start In`, each of these is a false
  `start-in-missing` Error, but the finding does not print the value, because it has no
  known extension. A one-letter `-P` or `-p` is a port or a path as often as a password, so the
  lint does not treat it as a secret switch (the diff's mask does). A one-letter `-u` is not treated as an account switch,
  because to `python` it is a switch with no value. So `psexec -u EXAMPLE\svc` with an empty
  `Start In` is a false Error too. A share inside a token with `=` in it, such as
  `Server=\\dbhost\gis;Database=x`, is not seen by the share check, because that token is
  never read. The value of a secret switch meets only the share check, so a drive letter or a
  relative path in it is not reported. A quoted `cmd /c` body that starts with a rooted path
  holding a space keeps that path whole only when it ends in a known extension or `.exe`. So
  `cmd /c "C:\my tools\sync --all"` splits at the space and reports `tools\sync` as a relative
  path, which it does not print. A value that ends in a known file extension is printed as a
  path, even after a one-letter switch. With an empty `Start In`, `python etl.py -p Hunter2.txt`
  prints `Hunter2.txt` in the `start-in-missing` finding.
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
  field, `failed`, tells the two runs apart. Under Nagios-style checks, exit `1` means WARNING,
  not UNKNOWN. A mistyped flag, such as `--ap`, exits `64`, as every usage error does.
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
  This happens only when no run took place between the clear and that point. A watermark
  copied from another server, or saved before a clear, that falls inside this log's current
  record range is accepted too. The read then starts at the wrong record, and it can skip or
  re-read records without a warning.
* **One run can count in two watermark reads.** A read that sees a run's start but not its
  end counts it, and the read that sees the end counts it again, with an estimated start. The
  counts of each read are exact, but a total over several reads can count one run twice.
* **A launch that left no event is not counted.** A failed run needs a `201`, a `101`, a
  `103`, a `203` or a `329` in the read. A run that Task Scheduler never logged, or whose events
  the log overwrote, reads as nothing. A run that `111` or `330` ended is a `Warning`, and is
  not counted as a failure.
* **The `--history` join is case sensitive.** If the event log spells a task's path in another
  case than the inventory, for example after a re-registration, those runs join to no task and
  are not counted.
* **A `--match` that matches a task is judged on that task alone.** A task that matches but has
  no row to print is a clean run. Only a `--match` that matches no task at all exits `1`.
* **The event filter is near the XPath limit.** The limit counts clauses, so it depends on the
  query form. On the Application log of the development machine, the watermark form ran with
  22 event ids and failed with 23 ("The specified query is invalid"). The cold-start form,
  which adds the time window, ran with 21 and failed with 22. taskpulse now names 13, and
  both forms ran with all 13 against the same log. A `HISTORY_EVENT_IDS` past the limit would
  make every `--history` read exit `1`, and the self-test fails if the list grows past 21.
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
* **The example exports are not in the repo.** `gis-tasks.xml`, `monday.xml` and `tuesday.xml`
  above are synthetic files that are not among the four files, so you cannot rerun those exact
  blocks. A generator wrote them from the self-test's `task_xml()` helper, and every name in
  them is made up. The `--history` example in [Run fate](#run-fate) comes from a stub with those
  tasks and events. The self-test builds the same stub and checks the rows, but it does not
  print the table.
* **The measured results are point-in-time.** The live-versus-XML comparison of the lint, the
  findings without `--all`, the share of tasks with no time limit and the diff of the two
  exports were measured once on one machine. Its task set changes, so a rerun can give other
  numbers. This README gives those counts as words, not numbers.
* **Linux coverage used a virtualenv.** Branch coverage is 100 percent on Windows and on
  Linux. Coverage is not installed for the Linux host's system `python3`, so the Linux
  measurement ran in a virtualenv of that same Python 3.12.3.
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
  so an inverted `RecordCount` test in the history script would go unnoticed offline. The
  success path against an enabled Operational log was never run, because that log is disabled
  on the development machine. The script was run live with the Application log in its place.
  It read oldest first past a watermark and read an empty match as empty. It raised for the
  Security log, a missing log and a watermark above the newest record. The PowerShell lines
  that read the log's oldest and newest record are checked only by a live read, not by the
  self-test.
* **An empty record count hides the log's range.** If `Get-WinEvent -ListLog` reports no
  `RecordCount` for an enabled log that holds records, the range row has no record ids. Then
  every watermark above `0` exits `1` as above the newest record, and every cold start exits
  `1` as incomplete. The run is loud, never clean. This was not observed: `RecordCount` was
  empty only on the disabled log of the development machine.
* **Starting a watermark at 0 on a log that has rolled over reports a loss once.** The log no
  longer holds its first records, so that first run names them as overwritten and exits `1`.
* **The clock is read a few seconds before the log.** On a cold start, the 7-day columns count
  back from a clock read that `main` takes before the history script starts. The script's time
  window counts back from the moment its query runs, a few seconds later. So with
  `--history 7`, a short run that falls entirely in those first seconds of the week is not read.
* **An event with no usable time is ignored for timing.** It still joins its run and can carry
  a `201` result. No self-test case mixes such an event with dated events of the same run.
  Real events always carry `TimeCreated`.
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
  keeps its records was not measured. If the log is turned off and on again between two
  watermark runs, the runs in the off period were never logged, and the next watermark read
  still reports complete.
* **A log cleared during a read can look clean.** If the log is cleared after the script reads
  its range but before it reads the events, the empty answer reads as a clean history, and
  that run exits `0`. The next watermark run then exits `1`, because its watermark is above
  the new newest record. If the log is cleared before its record count is read, the range row
  has no record ids. If it is cleared between the record count and the range read, the range
  read answers `NoMatchingEventsFound`, so no range row comes back. In both cases a run with
  `--since-record-id 0` reports an empty history and exits `0`, and a cold read is incomplete.
* **A partly denied log is covered only by a stub.** No log on the test machine let `-ListLog`
  report a record count but denied reading the records, and changing a log's access list needs
  elevation. So an `UnauthorizedAccessException` from the event read is covered only by a
  stub. A host that answers `NoMatchingEventsFound` there instead was not tested.
* **Check the exit code, not only the JSON.** A failed history read with `--format json` and
  no task needing attention prints `[]`, the same as a clean run, and exits `1`. In the table
  format the same run prints `No tasks need attention.` on stdout and the failure on stderr.
  Its `--out` file is the same as the file of a clean run.
* **Python 3.9 reads only some timestamp shapes.** On 3.9 a timestamp with 1, 2, 4 or 5
  fractional digits, a `+HHMM` offset or a `+HH` offset is read as having no time. 3.12 and
  3.13 accept them, so a `trigger-expired` finding can differ by Python version on a hand-edited
  export. PowerShell's round-trip format always writes 7 digits, and Task Scheduler's own
  formats parse everywhere.
* **The self-test needs hard links in its temporary folder.** On a FAT or exFAT temporary
  folder, `os.link` fails, and the self-test stops with an `OSError` instead of a count.
* **Two encodings are refused.** An export in UTF-16 big-endian with no byte order mark, or in
  UTF-32, exits `1` with "no <Task> element found" or "not well-formed". Windows never writes
  these.
* **Task names are trimmed.** Two tasks whose names differ only by leading or trailing spaces
  share one row of run history.
* **The last duration can come from the wrong run.** When two runs of one task have the same
  start time, the last duration comes from the first one read. When runs of one task overlap,
  a run with an estimated, late start can outrank a run that really started later. The last
  duration and the duration ratio are then blank for that read. Both affect only the advisory
  baseline columns.
* **Two edges of a capped cold read are not pinned.** If every event read lacks a timestamp,
  the read counts as reaching back only to now, so it is called incomplete. Real events always
  carry `TimeCreated`. A read that reaches back exactly 7 days is not tested, because `main`
  reads the wall clock.
* **Some self-test assertions compare English text.** The OS message checks, such as "cannot
  find the file", expect English wording. The self-test is expected to fail on a Windows
  installation with another display language. This was not tested.
* **Put the path directly after `--lint`.** `taskpulse --lint --all file.xml` reads `file.xml`
  as an unrecognised argument and exits `64`. Write `taskpulse --lint file.xml --all`.
* **A program field with no space is printed as written.** A field that holds a command line,
  such as `sync.exe --password x`, is masked in the health report's `target` field and in the
  `bare-program` lint detail, by the rules of the diff's argument mask. The Task Scheduler
  console and `schtasks /tr` both put arguments in their own field.
* **Exported XML under `\Microsoft\` is skipped unless `--all` is given.** `--lint PATH` and
  `--diff` say on stderr how many tasks they skipped, and exit `1` when none was left. A file
  that holds other tasks too prints a clean result for those alone.
* **A task with no enabled trigger is not reported.** Disabled triggers are ignored by design,
  so a task whose only trigger is disabled lints clean.
* **The `no-time-limit` check reads only `Settings/ExecutionTimeLimit`.** A trigger-level
  `ExecutionTimeLimit` that bounds the run is not considered, so the Warning can be wrong.
* **A non-path argument that contains a slash reads as a relative path.** A date such as
  `2026/01/01` or a ratio such as `10/12`, on a task with an empty `Start In`, gives a false
  `start-in-missing` Error and exit `2`.
* **A PowerShell script block that changes folder is not seen.** The body
  `-Command "& { Set-Location C:\jobs; .\x.ps1 }"` gives a false `start-in-missing` Error.
* **`--diff` does not compare a principal's `RequiredPrivileges` or `ProcessTokenSidType`**, or
  anything under `RegistrationInfo`.
* **Printed text is not cleaned.** A newline inside a task's `Start In` or another printed field
  breaks the table layout and can forge an extra row, such as an `OK` line. Treat the table as
  untrusted text and use `--format json` or `csv` for automation.
* **Hostile XML ends in a plain error.** XML nested about 1500 levels deep ends with
  `maximum recursion depth exceeded` and exit `1`, with no file name in the message. A DOCTYPE
  with entities is refused as not well-formed, so entity expansion is not possible.
* **An export file has no size cap.** Each file is read whole into memory, so a very large file
  in a linted folder can exhaust memory. Symbolic-link subfolders are refused, but a symbolic
  link to a file inside a linted folder is read like any file.
* **The diff reads exports, not the live scheduler.** The live read does not return every trigger
  field, action field and setting, so `--diff` takes two paths. To compare today with a past
  day, export today (`schtasks /query /xml ONE > today.xml`) and keep the earlier file.
* **The diff matches names, and a rename is not a move.** A task renamed between exports is
  one removed and one added task, not a change. Two tasks with one name on one side stop the
  diff with exit `1`.
* **The diff does not normalise values it cannot prove equal.** `PT72H` and `P3D` are the same
  limit, and they are two values to the diff. Triggers compare without regard to case, so a
  trigger whose only change is the case of a text value is no change. A run level that one
  export writes out and the other leaves out reads as a change, because Microsoft documents
  no default for it. The same holds for any `Settings` element that has no default in the
  schema.
* **The argument mask is a set of patterns, and it only applies with `--show-args`.** It masks a secret by its switch name, by the
  letter of a one-letter `-P`, `-p` or `-k`, by `-u` or `--user` with a `:` in the value, and by the
  name of a header. These secrets still print in full: the attached `-uuser:X`, `-uX`,
  `-U user%X`, a header with another name such
  as `-H "X-Custom: X"`, and a secret switch whose value starts with `-` or `/`, such as
  `--password -X`, which is read as the next switch. The csv and json diff output and any
  `--out` file are redacted no further than the table. The self-test pins what the mask hides,
  and that these forms print, not what else it cannot see. Review a diff before it leaves the
  machine, as with the rest of the output.
* **`--diff` masks command lines only.** It prints the `Start In` folder, each trigger's fields
  and an event trigger's `Subscription` text as they are, so a secret placed there prints.
* **A quoted share with a space is named by its first part.** `/SRC:"\\srv\my share\data"` is one
  value, so it raises no false `start-in-missing` Error, but the share finding names
  `\\srv\my`, because the share pattern stops at a space.
* **The tokenizer follows Windows' quote rule, not its backslash rule.** A `"` opens or closes a
  quote anywhere in a word, and a `'` only at the start of a word or after `=` or `:`. A
  backslash escapes nothing, so a `\"` that Windows reads as a literal quote reads as a quote
  here.
* **The exit code ignores STUCK, BLOCKED and a week of failures.** A task that is STUCK or
  BLOCKED, or that failed in the last 7 days and succeeded on its last run, is a Warning, so a
  check that fails on them must read the `fate` or `failures_last_7_days` field of the `json`
  output.
* **A failed `--history` read still prints `No tasks need attention.`.** It goes to stdout, and
  to an `--out` file with `--apply`. Only the exit code `1` and stderr say the history was not
  read, so check the exit code, not the file.
* **`--apply` with `--out` overwrites the target without asking.** `--out` is refused only
  when it is a file or folder the same run lints or compares, so any other file taskpulse can
  write, such as a different export or the script itself, is replaced.
* **`--lint` skips disabled tasks.** A folder of only disabled tasks prints `No findings.` and
  exits `0`.
* **Keep one file per task in an export folder.** `--diff` keys a task by its full name, so two
  files that define one task on the same side stop it with exit `1` and a message that names the
  folder and the task. `--lint` does not check for this and judges both.
* **No check reads `DisallowStartIfOnBatteries` or `StopIfGoingOnBatteries`.** Both default to
  true, and on battery power they skip or stop runs without an error, as on a laptop or a
  host behind a UPS. The lint lists them among the defaults and never judges them.
* **`trigger-expired` does not know the time zone.** A time with no offset is the machine's
  local time, and an export does not say which. A trigger counts as ended a day after its end,
  so a zone cannot change the answer, and a trigger that ended an hour ago is not reported yet.
  The check also cannot see a task that deletes itself after it expires.
* **`run-conditions` and `logon-minority` are judgments.** The first reports a setting, not a
  skipped run: a machine that is idle at the trigger time is fine. The second compares a task
  with the tasks beside it, and a task that differs on purpose is reported. Both are Warnings
  for that reason. The idle and network conditions' own sub-settings (`IdleSettings`,
  `NetworkSettings`) are not read by the lint.
* **A `StartWhenAvailable` check is left out.** The setting is off by default on every task,
  so a lint on it would be a Warning on nearly every scheduled task. `--history` reports the
  consequence instead: a start that was missed and not made up is event `153`, and leaves the
  task `BLOCKED` if nothing has run since.
* **There is no network path**, so there is nothing to test against a stub server.
* **Mutation survivors are test gaps, not wrong output today.** A sweep of 1839 mutants of the
  non-test code (a flipped comparison, an `and`/`or` swap, a dropped branch, a constant moved by
  one, a swapped severity or state string) was run against the self-test at 680 assertions. It
  killed 1716, and 123 survived. Most survivors are equivalent mutants or unused constants. Six
  gaps were real, and none gave a wrong output. After the sweep the self-test pinned the detail
  text of the Running-state `STUCK` rule and three boundaries: a refusal at exactly the 7-day
  cutoff, a refusal at exactly the last start, and a watermark of 1 on an empty log. Four
  stay unpinned: that a complete or off history read leaves `run history incomplete` out of
  `WHY`, the severity of the `run-conditions` finding, the skipped-task count of `--diff` when
  only one side holds Microsoft tasks, and an event with a bad timestamp inside a `100` or `102`
  group. The sweep was not repeated at the current assertion count.
* **A name with a separator can look like a relative path.** The shape rule reads a registry
  key, a log channel or a task name as a path when it holds a separator and `Start In` is empty:
  `reg export HKLM\Software\Vendor C:\bk\v.reg`, `wevtutil cl
  Microsoft-Windows-TaskScheduler/Operational` and `schtasks /run /tn Folder\Task` each give a
  false `start-in-missing` Error and exit `2`. Fill `Start In` to clear it.
* **More credential forms print with `--show-args`.** `-Authorization Basic X` masks the word
  `Basic` and prints `X`. Curl's combined `-su user:X`, rar's attached `-hpX`, a positional
  password such as `smbclient //srv/share X` and `reg add ... /d X` print in full. Without
  `--show-args` the diff prints none of them.
* **A group principal reads as a user.** Windows writes an interactive principal for a group,
  such as `S-1-5-32-545`, as a `GroupId`. The interactive-only finding then says the task runs
  only while that SID is logged on, as if it were a user.
* **The lint table cuts every cell at 240 characters.** A long detail, such as a finding that
  names several shares, loses its tail in table format. Use `--format json` for the full text.
  The health table cuts at 60.
* **Overlapping exports count a task twice.** Pass the same task in a folder and in a
  `schtasks` file to `--lint`, and `logon-minority` counts it twice. A duplicate can make the
  majority that flags a differing neighbour.
* **The diff applies schema defaults to the direct children of `Settings` only.**
  `IdleSettings` and `NetworkSettings` children that one export writes at their defaults and the
  other leaves out show as changes. Windows always writes `IdleSettings`, so this appears only
  when one export is written by hand.
* **The diff compares an account as written.** `S-1-5-18` in one export and `SYSTEM` in the
  other is a `run as` change.
* **The diff does not report a change between two logon types it reads as one.**
  `InteractiveTokenOrPassword` and `Password` are one logon type to it.
* **The network run-condition is not measured.** An unmet idle condition left `Last Run Result`
  at the previous run, on a task that had never run (it stayed `267011`). A fake network
  profile name did not stop the task from running, so the network claim rests on Microsoft's
  wording alone.
* **A saved report is sensitive.** Task names on a real machine hold accounts, SIDs and
  e-mail-style names, and the report prints run-as accounts and authors. Treat a saved file
  that way.
* **A `.coverage` file may sit in the working tree.** It is git-ignored and not one of the four
  files. Copy the folder by hand and it travels along.
* **The `WHY` column quotes Windows for the last result.** A run that event `329` ended for
  exceeding its time limit shows the text `The last run of the task was terminated by the
  user.`, because the status comes from result code `0x41306`. The failure count and the run
  status are right.
* **A task meant to run for ever is STUCK.** A daemon that starts at logon or at startup is
  reported STUCK after `--stuck-hours` and stays STUCK. The only way to exclude one is a
  `--match` regex.
* **The busy-log numbers come from one observation.** The figures of about 700 to 1000 events
  a day come from a single server, were seen once and were not reproduced.
* **A bare positional secret prints in full in `--diff --show-args`.** In `x.py SECRET` nothing in the XML
  says that the word is a secret. The mask also leaves these forms: a value after a switch
  with a neutral name (`--cookie X`, `--session X`, `--jwt X`, `--pin X`, `--otp X`, `--dsn X`,
  `--connection-string X`, `-ArgumentList X`), a literal in a PowerShell `-Command` body such
  as `$p = 'X'`, a literal in parentheses after a secret switch such as
  `-Password (ConvertTo-SecureString 'X' -AsPlainText)`, the Oracle form `user/password@db`,
  the value of `-SecureString` and of any one-letter switch other than `-p`, `-P` and `-k`,
  and the abbreviations `-enc`, `-ec` and `-e` of `-EncodedCommand`. A one-character account
  in `-u a:X` is not masked, because the pattern needs two characters before the colon. A
  secret inside the `Command` field itself is masked when it follows a named switch, as in
  `sync.exe --password X`, and prints when it is an unmarked positional word. Windows puts
  arguments in `Arguments`.
* **The header mask is slow on one crafted word.** A word of 60000 characters that repeats
  `key` takes about 4 seconds in `--diff`, and an ordinary long word does not. Only a crafted
  export is slow.
* **A folder with a file that is not task XML stops the run.** `--lint` or `--diff` of a
  folder that holds `notes.txt` ends with exit `1` and `no <Task> element found`. The failure
  is loud, not a false pass.
* **`--diff --out` with `--apply` writes an alternate data stream of an input.** On NTFS,
  `--out old.xml:s1` is not refused. The input file stays as it was and only the stream is
  created.
* **The live read lists the tasks Task Scheduler returns to the calling account.** Whether an
  unelevated run misses a task whose access list denies it was not measured. Run the health
  report and the lint elevated for a full inventory.
* **`--local-drives` with an empty value or a path such as `C:\` matches no drive letter.**
  Every drive, `C:` included, is then reported as a mapped drive. Pass bare letters, as in
  `--local-drives C,D`.
* **The self-test writes task XML to a temporary folder.** It creates the folder with
  `tempfile.mkdtemp` and removes it in a `finally` block. It writes nowhere else. The files its
  own `--apply` tests produce go into that folder too.

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
