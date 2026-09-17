# taskpulse

Audits Windows scheduled tasks for silent failures, from one read-only command.

Task Scheduler shows a bare `Last Run Result` number and nothing else. It never says that a
Daily task has no next run time, that a task is overdue, or what `0x8007052E` means. taskpulse
joins those fields, decodes the code through the OS message table, unwraps interpreter
wrappers so the report names your script instead of `python.exe`, and prints one verdict per
task. With `--history` it also joins the run history the Task Scheduler snapshot throws away.
Standard library only, no install, no config file, no credentials.

```console
$ python taskpulse.py --self-test
self-test passed: 139 assertions, offline, no credentials.

$ python taskpulse.py          # real run on this development machine, 13 non-Microsoft tasks
STATUS  TASK                                SCHEDULE      LAST RESULT                                             WHY
------  ----------------------------------  ------------  ------------------------------------------------------  ------------------------------------------------------
Error   \CreateExplorerShellUnelevatedTask  Registration  unmapped result 0x40010004                              unmapped result 0x40010004
Error   \Launch Adobe CCXProcess            Daily         The operator or administrator has refused the request.  The operator or administrator has refused the request.
Error   \ViGEmBus_Updater                   Daily         unmapped result 0x00002EE7                              unmapped result 0x00002EE7
```

## Requirements

Windows, and any Python 3.8+ already on the box. Nothing to install, nothing to configure, no
credentials. Readers used to Esri tooling should note that this needs no ArcGIS Pro, no `arcpy`,
no `arcgis` package, and no portal sign-in. It imports only the standard library and shells out
to the built-in `Get-ScheduledTask` / `Get-ScheduledTaskInfo` cmdlets, and to `Get-WinEvent`
when you pass `--history`.

What it refuses to do:

* never creates, edits, enables, disables, deletes, starts or stops a task
* never opens a network connection, and never asks for or stores a credential
* never reads or writes a config file, because every knob is a command line flag
* never writes anywhere except stdout, or the single path you pass to `--out`

## Quick start

```console
git clone <this repo>
cd taskpulse
python taskpulse.py --self-test
```

That is the whole setup. `--self-test` runs 139 assertions with no network, no credentials and no
Task Scheduler access, so it passes on a locked-down box and in CI. Then run `python taskpulse.py`
for the audit.

## Usage

| Flag | Effect |
|---|---|
| `--format {table,json,csv}` | Output format. Default `table`. `json` and `csv` carry all 20 fields per row, the table shows 5. |
| `--out PATH` | Write to `PATH` instead of stdout. The row count goes to stderr. |
| `--all` | Include Microsoft's own tasks under `\Microsoft\`. Excluded by default because there are roughly 200 of them. |
| `--show-ok` | Include healthy tasks. By default only `Warning` and `Error` rows print. |
| `--match REGEX` | Keep only tasks whose full path matches this regex, case insensitive. |
| `--history [DAYS]` | Also read the Task Scheduler Operational log and report each task's last 7 days of runs, its failures in that week, and its duration baseline. Default `30` days of events. |
| `--since-record-id ID` | With `--history`, read only event records newer than `ID`. Pass the watermark the previous run printed. The day window is then ignored. |
| `--timeout SECONDS` | Task Scheduler query timeout. Default `120`. |
| `--self-test` | Run the offline assertion suite and exit. |
| `--version` | Print the version and exit. |
| `-h`, `--help` | Usage summary. |

Exit codes: `0` when nothing is in an `Error` state, `2` when at least one task is, `1` when
taskpulse itself failed. That makes it usable as a monitoring check. `--history` can add rows to
the report, because a task that failed every night this week and succeeded tonight is worth
printing, but it never changes the exit code: that still follows the current state alone.

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

## Limitations

* **Snapshot by default, history only on request.** Without `--history` it reports the last
  result and the next run, so a task that failed last week and has since succeeded looks clean.
  There is still no watch mode and no database: `--history` reads the event log once, in the same
  run, and keeps nothing between runs except the watermark you choose to pass back.
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
* **Windows only.** On any other platform it exits `1` with a message rather than guessing.

## Contributing

Issues and pull requests are welcome. One request: any change to classification, decoding or
health logic should arrive with assertions added to `self_test()` in `taskpulse.py`, and
`python taskpulse.py --self-test` should pass before and after. The suite is deliberately
dependency free and offline, so there is no framework to learn and no reason to skip it.

## Author

Built by [Asir Khan](https://www.linkedin.com/in/asir-khan-310317264/).

## License

MIT.

## Related

Other single-file tools in this portfolio that pair with this one:

- [jobharness](https://github.com/uhsear/jobharness) - give the failing task logging, retry and resume
- [logsift](https://github.com/uhsear/logsift) - turn the logs those tasks write into a metric series
