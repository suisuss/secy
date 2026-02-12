# Plan: C2 Supervisory Agent + inotify Watch

## Context

secy currently runs 3 containers: `secy` (one-shot scans), `secy-watch` (polls Downloads every 5s), `secy-patrol` (scheduled sread module scans). Watch and patrol both invoke Claude independently but have no cross-service awareness — a suspicious download and a new listening port are analyzed in isolation. Adding a C2 (command and control) supervisory container creates a correlation layer that connects findings across services and directs targeted investigation.

Separately, watch's polling loop is replaced with inotify for event-driven file detection, with a polling fallback since inotify on Docker bind mounts is unreliable across kernel versions (documented in `docs/plans/watch-mode.md:125`).

## Architecture

```
state/ (shared volume)
├── findings/       ← watch, patrol, and C2 all write here
├── directives/     ← C2 writes; watch + patrol read, apply, and report
│   ├── active/     ← pending directives (C2 writes here)
│   └── applied/    ← processed directives + .report files (services write here)
├── issues/         ← C2 creates; user resolves by deleting
├── c2/             ← C2 progress memory, processed.db
├── patrol/         ← patrol runs, diffs, schedule
└── watch/          ← seen DB, queue

┌──────────┐    ┌───────────┐    ┌─────────┐
│  watch   │    │  patrol   │    │   C2    │
│ (sensor) │    │ (sensor)  │    │ (brain) │
│ inotify  │    │ scheduled │    │ event-  │
│ +claude  │    │ +claude   │    │ driven  │
└────┬─────┘    └─────┬─────┘    └────┬────┘
     │                │               │
     └── findings/ ───┴───────────────┘
              ↑                   │
              └── directives/ ←───┘
                  issues/ ←───────┘
```

- Watch + patrol **keep Claude** — they generate their own reports
- C2 monitors `state/findings/` for new reports (inotify or poll)
- C2 spawns fresh Claude (Ralph pattern) to correlate across services
- C2 writes directives; watch + patrol poll, apply, and report back
- C2 creates issues in `state/issues/` for human attention
- C2 reads application reports to verify directives were applied correctly

## Implementation

### 1. Dockerfile — add `inotify-tools`

**File**: `Dockerfile` (line 17-31)

Add `inotify-tools` to the `apt-get install` list. Add `chmod +x` for `c2.sh` on line 53.

### 2. Config — new variables

**File**: `agent/conf/agent.conf`

Append:
```bash
# ── C2 mode settings ────────────────────────────────────────────
C2_POLL_INTERVAL=30          # fallback poll if inotify fails (seconds)
C2_DEBOUNCE_INTERVAL=300     # min seconds between Claude invocations
C2_REVIEW_BUDGET_USD="0.75"  # budget per C2 invocation
C2_MAX_FINDINGS_PER_REVIEW=20
C2_CONTEXT_WINDOW=10         # historical findings for context

# ── Directive settings (all services) ───────────────────────────
DIRECTIVE_CHECK_INTERVAL=60  # how often services check for directives
```

### 3. Shared inotify utility

**New file**: `agent/lib/inotify-watch.sh`

Provides `watch_directory_loop()` used by both watch and C2:

- `probe_inotify(dir)` — creates a temp file in target dir, runs `inotifywait` with timeout, checks if it detected the create event. Returns 0 (inotify works) or 1 (fall back to poll).
- `watch_directory_loop(dir, callback, poll_interval, tag)` — probes once at startup. If inotify works: runs `inotifywait -t $poll_interval -r -e close_write,create,moved_to` in a loop, calling `callback(event, filename)` per event. If inotify fails: calls `callback("POLL", "")` every `poll_interval` seconds.
- Both paths check `$SECY_DAEMON_RUNNING` to honor signal-based shutdown (already defined in `secy-common.sh:110-129`).

### 4. Watch — inotify + directive reload

**Files**: `agent/watch.sh`, `agent/lib/watch-common.sh`

**watch.sh changes:**
- Source `inotify-watch.sh`
- Replace the `while` polling loop (lines 308-328) with a callback-based architecture:
  - Define `on_watch_event(event, filename)` that runs `scan_downloads()` + `analyze_batch()` (same logic, just triggered by callback instead of sleep loop)
  - Call `watch_directory_loop` with the Downloads directories
- For multiple Downloads dirs: pass all to `inotifywait -r` (inotify path), or scan all on each poll tick (poll path) — both work since `scan_downloads()` already iterates all dirs

**watch-common.sh changes:**
- Add `check_watch_directives()` — wrapper calling `_check_watch_config()` and `_process_watch_directive_files()`
- `_check_watch_config()` — checks `state/directives/watch-config.conf` mtime, reloads `WATCH_SCAN_DEPTH` and `WATCH_EXTRA_DIRS` if changed
- `_process_watch_directive_files()` — processes `*.watch-directive` files from `active/`, moves to `applied/`, writes `.report` files
- Add `WATCH_EXTRA_DIRS=""` as a new scannable dirs variable
- Modify `scan_downloads()` to also scan dirs in `$WATCH_EXTRA_DIRS` (if set by C2 directive)

### 5. Patrol — directive reload

**Files**: `agent/patrol.sh`, `agent/lib/patrol-common.sh`

**patrol-common.sh changes:**
- Add `check_directives()` — wrapper calling `_check_schedule_override()` and `_process_directive_files()`
- `_check_schedule_override()` — checks `state/directives/schedule-override.conf` mtime, parses `module.field=value` lines, updates `SCHED_INTERVALS[]` and `SCHED_PRIORITIES[]` arrays in place
- `_process_directive_files()` — processes `*.directive` files from `active/`, tracks old→new values per entry, moves to `applied/`, writes `.report` files with status (`applied`/`partial`), changes applied, and errors

**patrol.sh changes:**
- Add `check_directives` call in the main loop (after module execution, before review gate)

### 6. C2 common library

**New file**: `agent/lib/c2-common.sh`

Sources `secy-common.sh`. Provides:

- **State management**: `init_c2_state()` creates `state/c2/`, `state/directives/{active,applied}`, `state/issues/`
- **Processed tracking**: `state/c2/processed.db` (tab-delimited: filename, timestamp). Functions: `is_finding_processed()`, `mark_finding_processed()`, `scan_new_findings()`
- **Timestamp extraction**: `_extract_finding_timestamp(filename)` pulls `YYYY-MM-DD-HHMMSS` from filenames via regex, falls back to file mtime. `_format_timestamp()` converts to human-readable. `_extract_finding_source()` derives service name from filename prefix.
- **Chronological sorting**: `_sort_findings_by_time(array)` sorts filenames by embedded timestamps. New findings presented oldest→newest; historical newest→oldest.
- **Issue management**: `next_issue_id()` returns next sequential 4-digit zero-padded ID. `list_open_issues()`, `count_open_issues()` for context assembly.
- **Context assembly**: `assemble_c2_context(pending_array)` builds the prompt with 7 sections:
  1. New findings (full content, chronological, with `**Created**` and `**Source**` labels)
  2. Recent historical findings (summaries, reverse chronological, up to `C2_CONTEXT_WINDOW`)
  3. Current patrol schedule
  4. Active directives
  5. Directive application reports (from `applied/*.report`)
  6. Open issues
  7. C2 progress notes from `state/c2/progress.md`
- **Claude invocation**: `run_c2_analysis()` calls `invoke_claude` with C2.md as system prompt, assembled context as user prompt, writes to `state/findings/c2-TIMESTAMP.md`, marks findings processed, provides next issue ID and issues directory path

**Self-referencing loop prevention**: C2 writes `c2-*.md` to findings/. `mark_finding_processed()` is called immediately after writing, so the next scan skips them. `scan_new_findings()` also proactively marks any `c2-*` files it encounters.

### 7. C2 system prompt

**New file**: `agent/C2.md`

Role: correlation analyst and investigation commander. Key sections:
- **Cross-service correlation patterns** (e.g., suspicious download + new port = activation)
- **Temporal pattern analysis** (escalation, persistence, staging, resolution)
- **Directive mechanism** with exact file formats, paths, and service-specific extensions (`.directive` for patrol, `.watch-directive` for watch)
- **How services pick up directives** — polling on 60s interval, mtime-based reload, up to 60s latency
- **Verifying directive application** — check `.report` files in `applied/`, re-issue on errors, flag stale directives
- **Directive guidelines** — observe only/never remediate, be selective, revert when done, document why
- **Issues** — format, rules (one per concern, link findings, no remediation commands, 4-digit sequential IDs, user resolves by deleting)
- **Report format** (executive assessment, correlations, issues created, directives issued, investigation state)
- **Rules**: don't duplicate subordinate analysis, consider null hypothesis, directives have cost, maintain progress notes, be concise, time-bound directives, flag uncertainty, never remediate

### 8. C2 daemon

**New file**: `agent/c2.sh`

Structure mirrors `patrol.sh`:
- Flag parsing: `--no-claude`, `--poll-interval`, `--debounce`
- Preflight: `preflight_core` + claude check
- Event handler: `on_findings_event(event, filename)` — accumulates pending findings, checks debounce timer, triggers `run_c2_analysis()` when debounce expires and findings are pending
- Main: `init_c2_state`, `daemon_init`, `watch_directory_loop` on `state/findings/`

Debounce (default 300s) prevents rapid-fire invocations when patrol generates multiple findings simultaneously. Pending findings accumulate and are batched into one Claude call.

### 9. Entry point dispatch

**File**: `agent/secy.sh`

- Add `c2` to usage text (with options: `--no-claude`, `--poll-interval`, `--debounce`)
- Add dispatch block after patrol:
  ```bash
  if [[ "$1" == "c2" ]]; then
      exec "${AGENT_DIR}/c2.sh" "${@:2}"
  fi
  ```

### 10. Docker Compose

**File**: `docker-compose.yml`

Add `secy-c2` service after `secy-patrol`. Identical security posture (same image, same caps, same volumes, same tmpfs, same security_opt). Only differences: `command: ["c2"]`, `restart: unless-stopped`.

### 11. Consistent report timestamps

**Files**: `agent/AGENT.md`, `agent/PATROL.md`, `agent/WATCH.md`, `agent/C2.md`

All report formats standardized on `date -Iseconds` (ISO 8601: `2026-02-13T14:30:22+00:00`):
- AGENT.md: `**Date**` → `**Timestamp**` with explicit format
- PATROL.md: added report header (`**Timestamp**`, `**Diffs reviewed**`); per-finding `**Timestamp**` from diff header
- WATCH.md: added report header (`**Timestamp**`, `**Files analyzed**`)
- C2.md: report header and issue `**Created**` field use the same format

This enables C2's timestamp extraction to reliably parse and sort findings chronologically.

## Directive Format

### Persistent configs (mtime-polled)

**Schedule overrides** (`state/directives/schedule-override.conf`):
```
# module.field=value
ports.interval=60
ports.priority=high
netconn.interval=60
```

**Watch config** (`state/directives/watch-config.conf`):
```
scan_depth=2
extra_dirs=/host/tmp /host/dev/shm
```

### One-shot directives (processed and moved)

**Patrol** (`state/directives/active/<name>.directive`):
```
# module.field=value
ports.interval=30
ports.priority=high
```

**Watch** (`state/directives/active/<name>.watch-directive`):
```
scan_depth=3
extra_dirs=/host/tmp /host/dev/shm /host/var/tmp
```

### Application reports

When a service processes a one-shot directive, it writes:

`state/directives/applied/<name>.directive.report`:
```
# Directive Application Report

- **Directive**: <filename>
- **Service**: patrol | watch
- **Timestamp**: 2026-02-13T14:30:22+00:00
- **Status**: applied | partial

## Changes Applied

  ports.interval: 300 -> 30
  ports.priority: high -> high

## Errors

  badmodule.interval: unknown module
```

C2 reads these reports on each invocation to verify directives were applied correctly.

## Issue Format

Issues live in `state/issues/` with 4-digit sequential IDs:

`state/issues/0001-suspicious-binary-activation.md`:
```markdown
# Suspicious Binary Activation

- **Severity**: critical | warning | info
- **Created**: 2026-02-13T14:30:22+00:00
- **Related findings**: watch-triage-2026-02-13-142500.md, patrol-2026-02-13-143000.md

## What was detected

<Clear description of what happened>

## Evidence

<Specific signals from the findings>

## Recommended action

<What the user should investigate — no remediation commands>
```

Rules: one issue per concern, link to findings, no remediation commands (secy is a sensor), don't duplicate open issues, user resolves by deleting.

## Constraint: No Remediation

C2 and all directives are strictly **observe-only**. Directives adjust monitoring scope and frequency. They must never:
- Kill processes, delete files, modify configs
- Block traffic, quarantine downloads
- Alter firewall rules, remove packages
- Take any action that changes host system state

When C2 identifies a threat requiring action, it creates an issue for the human. Remediation is a human decision.

## File Summary

| Action | Path |
|--------|------|
| Modify | `Dockerfile` (add `inotify-tools`, chmod c2.sh) |
| Modify | `agent/conf/agent.conf` (C2 + directive config) |
| Create | `agent/lib/inotify-watch.sh` (shared inotify+poll utility) |
| Modify | `agent/watch.sh` (inotify loop, directive check) |
| Modify | `agent/lib/watch-common.sh` (directive reload, extra dirs, one-shot directives with reports) |
| Modify | `agent/patrol.sh` (directive check in main loop) |
| Modify | `agent/lib/patrol-common.sh` (schedule override reload, one-shot directives with reports) |
| Create | `agent/lib/c2-common.sh` (C2 state, timestamps, issues, context assembly, invocation) |
| Create | `agent/C2.md` (C2 system prompt) |
| Create | `agent/c2.sh` (C2 daemon entry point) |
| Modify | `agent/secy.sh` (add c2 dispatch + usage) |
| Modify | `docker-compose.yml` (add secy-c2 service) |
| Modify | `agent/AGENT.md` (standardize timestamp format) |
| Modify | `agent/PATROL.md` (add report header with timestamp) |
| Modify | `agent/WATCH.md` (add report header with timestamp) |

## Verification

1. **Build**: `docker compose build` — verify inotify-tools present
2. **inotify probe**: `docker compose run --rm secy watch --no-claude` — check log for "inotify probe succeeded" or "poll fallback"
3. **C2 startup**: `docker compose run --rm secy c2 --no-claude` — verify daemon starts, watches findings/
4. **Event flow**: start patrol + C2, wait for patrol finding, verify C2 detects and logs it
5. **Directive round-trip**: write `ports.interval=30` to `state/directives/schedule-override.conf`, verify patrol log shows reload within 60s
6. **One-shot directive + report**: write a `.directive` to `active/`, verify patrol moves to `applied/` and writes `.report`
7. **Watch directive + report**: write a `.watch-directive` to `active/`, verify watch moves to `applied/` and writes `.report`
8. **Self-reference prevention**: verify C2 doesn't re-process its own `c2-*.md` findings
9. **Issue creation**: trigger C2 with a critical finding, verify issue file created in `state/issues/` with 4-digit ID
10. **Timestamp consistency**: check that findings from all services use `date -Iseconds` format in report headers
