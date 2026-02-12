# Patrol Mode — Persistent Autonomous Security Monitoring

## Context

secy currently has three one-shot modes (baseline, audit, monitor) and one daemon (watch — Downloads only). The user wants a **patrol mode**: a long-lived daemon that continuously runs sread modules on a schedule, detects changes between runs, and periodically invokes Claude to review meaningful diffs. This makes the agent truly autonomous — it schedules, executes, compares, and reasons about host security state over time.

**Constraint**: The container is `read_only: true` with tmpfs at `/tmp` and `/root`. No cron package is installed and crontab would be lost on restart. The scheduler must be bash-native with state on the persistent volume (`/var/lib/secy/state`).

## Architecture

```
patrol.sh (daemon loop)
  ├── Phase 1: Init — run full audit on first start (if no prior state)
  ├── Phase 2: Module loop — check schedule.conf, run due modules, diff against previous
  └── Phase 3: Review gate — if meaningful diffs accumulated, invoke Claude to analyze
```

### State layout (`state/patrol/`)

```
state/patrol/
├── patrol.log              # Persistent log (rotated at 1MB, like watch)
├── schedule.conf           # Module schedules (editable, persists across restarts)
├── last-review.ts          # Unix timestamp of last Claude review
├── runs/
│   └── <module>/
│       ├── latest.out      # Most recent module output
│       └── previous.out    # Output from the run before latest
└── diffs/
    └── <module>-<timestamp>.diff  # Non-empty diffs waiting for review
```

### Schedule format (`schedule.conf`)

```bash
# module    interval_seconds    priority
ports       300                 high
services    600                 medium
spyproc     300                 high
kmod        600                 high
preload     600                 high
cron        600                 high
users       900                 medium
sysctl      900                 medium
firewall    900                 medium
setuid      900                 medium
world       1800                low
packages    3600                low
pkgverify   3600                low
tamper      3600                low
autostart   1800                medium
netconn     300                 high
desktop     1800                low
surveil     1800                low
```

### Review gate logic

Claude is invoked when ALL of:
1. At least one non-empty diff file exists in `diffs/`
2. Either: a high-priority module produced a diff, OR the review interval has elapsed (default 30 min)
3. Budget hasn't been exhausted

## Files to Create

### 1. `agent/patrol.sh` — Main daemon script

- **Source**: `agent/lib/patrol-common.sh` and `agent/conf/agent.conf`
- **Preflight**: Same as watch.sh (root check, /host check, claude check)
- **Init phase**: If `state/patrol/runs/` is empty, run `sread full` once to populate all `latest.out` files
- **Main loop** (mirrors watch.sh structure):
  ```
  while RUNNING; do
      for each module in schedule.conf:
          if time_since_last_run >= interval:
              run_module(module)     # sread <module> > latest.out, diff against previous

      if should_review():
          run_claude_review()        # Assemble diffs, invoke Claude, write findings

      interruptible_sleep(tick_interval)  # 10s tick
  done
  ```
- **Signal handling**: SIGTERM/SIGINT/SIGHUP → graceful shutdown (same as watch.sh)
- **Flag parsing**: `--no-claude`, `--tick-interval N`, `--review-interval N`

### 2. `agent/lib/patrol-common.sh` — Shared utilities

Functions:
- `patrol_log()` — Logging with rotation (reuse watch-common pattern)
- `init_patrol_state()` — Create dirs, write default schedule.conf if missing
- `load_schedule()` — Parse schedule.conf into arrays
- `get_last_run_time(module)` — Read mtime of `runs/<module>/latest.out`
- `run_module(module)` — Execute `sread <module>`, rotate previous↔latest, diff, save non-empty diffs
- `should_review()` — Check diff dir + priority + time since last review
- `run_claude_review()` — Assemble prompt from accumulated diffs, invoke Claude, clear reviewed diffs
- `mark_review_done()` — Write current timestamp to `last-review.ts`

### 3. `agent/PATROL.md` — Claude system prompt for patrol reviews

Concise prompt telling Claude:
- You are reviewing accumulated diffs from periodic security module scans
- For each diff: explain what changed, assess if it's benign or suspicious, assign severity
- Write findings to the specified path
- Output SECY_COMPLETE when done

## Files to Modify

### 4. `agent/secy.sh`

- Add `patrol` to the usage block
- Add delegation: `if [[ "$1" == "patrol" ]]; then exec "${AGENT_DIR}/patrol.sh" "${@:2}"; fi`

### 5. `agent/conf/agent.conf`

Add patrol-specific config:
```bash
# ── Patrol mode settings ─────────────────────────────────────────
PATROL_TICK_INTERVAL=10          # Main loop tick (seconds)
PATROL_REVIEW_INTERVAL=1800     # Claude review interval (seconds, 30 min)
PATROL_REVIEW_BUDGET_USD="0.50" # Budget per Claude review invocation
```

### 6. `docker-compose.yml`

Add a `secy-patrol` service (mirrors `secy-watch`):
```yaml
secy-patrol:
  build: .
  image: secy
  command: ["patrol"]
  restart: unless-stopped
  # ... same env, volumes, caps, security_opt as secy-watch
```

## Implementation Order (one commit each)

1. **`agent/lib/patrol-common.sh`** — State management, scheduling, module execution, diff logic
2. **`agent/PATROL.md`** — Claude review prompt
3. **`agent/patrol.sh`** — Main daemon script wiring it together
4. **`agent/conf/agent.conf` + `agent/secy.sh`** — Config additions and entry point routing
5. **`docker-compose.yml`** — Add secy-patrol service

## Verification

1. **Unit-level**: Run individual sread modules against `/host` to confirm they produce output: `sread ports`, `sread spyproc`, etc.
2. **Patrol dry run**: Start patrol.sh with `--no-claude` and a short tick interval, verify:
   - schedule.conf is created with defaults
   - Modules run on schedule and output is captured in `runs/<module>/latest.out`
   - Diffs are generated when output changes between runs
   - Diffs accumulate in `diffs/` directory
3. **Claude review**: Remove `--no-claude`, verify Claude is invoked when diffs exist, writes findings, and clears reviewed diffs
4. **Container integration**: `docker compose run secy patrol --no-claude --tick-interval 5` — confirm it runs, creates state, handles SIGTERM gracefully
