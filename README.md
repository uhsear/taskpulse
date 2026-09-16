# taskpulse

Audits Windows scheduled tasks for silent failures, from one read-only command.

Task Scheduler shows a bare `Last Run Result` number and nothing else. It never says that a
Daily task has no next run time, that a task is overdue, or what `0x8007052E` means. taskpulse
joins those fields, decodes the code through the OS message table, unwraps interpreter
wrappers so the report names your script instead of `python.exe`, and prints one verdict per
task. Standard library only, no install, no config file, no credentials.

```console
$ python taskpulse.py --self-test
self-test passed: 95 assertions, offline, no credentials.

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
to the built-in `Get-ScheduledTask` / `Get-ScheduledTaskInfo` cmdlets.

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

That is the whole setup. `--self-test` runs 95 assertions with no network, no credentials and no
Task Scheduler access, so it passes on a locked-down box and in CI. Then run `python taskpulse.py`
for the audit.

## Usage

| Flag | Effect |
|---|---|
| `--format {table,json,csv}` | Output format. Default `table`. `json` and `csv` carry all 15 fields per row, the table shows 5. |
| `--out PATH` | Write to `PATH` instead of stdout. The row count goes to stderr. |
| `--all` | Include Microsoft's own tasks under `\Microsoft\`. Excluded by default because there are roughly 200 of them. |
| `--show-ok` | Include healthy tasks. By default only `Warning` and `Error` rows print. |
| `--match REGEX` | Keep only tasks whose full path matches this regex, case insensitive. |
| `--timeout SECONDS` | Task Scheduler query timeout. Default `120`. |
| `--self-test` | Run the offline assertion suite and exit. |
| `--version` | Print the version and exit. |
| `-h`, `--help` | Usage summary. |

Exit codes: `0` when nothing is in an `Error` state, `2` when at least one task is, `1` when
taskpulse itself failed. That makes it usable as a monitoring check.

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

**Event log rescanning.** The tempting approach is to parse
`Microsoft-Windows-TaskScheduler/Operational` for failure events. That log is disabled by default
on Windows, it rolls over, and parsing it costs seconds per run for history you may not have.
Current task state is always present and always cheap, so taskpulse reads state and computes the
verdict, instead of reconstructing it from events that may never have been recorded.

## Limitations

* **Snapshot, not history.** It reports the last result and the next run, so a task that failed
  last week and has since succeeded looks clean. There is no trend, no watch mode, no database.
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
