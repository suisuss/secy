# Plan: secy Watch Mode — Download Monitoring & Malware Triage

## Context

secy currently runs bounded audit sweeps (1-3 iterations, then exits). The user wants a new **long-lived daemon mode** that continuously watches the host's Downloads folder, checks file hashes against a malware database, and triggers Claude AI analysis for unknown files.

Key constraints: container can only reach `api.anthropic.com` (no VirusTotal/online lookups), host filesystem is read-only at `/host`.

## Architecture

```
watch.sh (daemon loop, runs indefinitely)
├── Poll /host/home/*/Downloads/ every 5s
├── For each new file:
│   ├── sha256sum → check seen.db (skip if already processed)
│   ├── look hash malware-sha256.txt (binary search)
│   │   ├── MATCH → write CRITICAL alert immediately
│   │   └── NO MATCH → classify file type
│   │       ├── Media (image/video/audio) → skip, mark seen
│   │       └── Analyzable (script/exe/pdf/office/archive) → queue
│   └── mark_file_seen
├── If queue non-empty: spawn ONE Claude instance for batch analysis
│   └── Claude reads files via sread fileinfo/hash, writes verdicts
└── sleep $POLL_INTERVAL, repeat
```

## Implementation (ordered by dependency)

### Phase 1: sread modules (pure bash, no Claude, no daemon)

**1. `sread/data/` directory** — new dir for baked-in hash DB

**2. `sread/lib/modules/hash.sh`** — Compute SHA256/MD5 of any file
- Intentionally skips MIME whitelist (must hash binaries)
- Still respects path blocklist (no hashing `/etc/shadow`)
- Pattern: `files.sh` (iterate args, validate each)

**3. `sread/lib/modules/fileinfo.sh`** — Extract metadata without reading content
- `file(1)` magic, `stat`, entropy estimate (unique bytes in first 8KB)
- ELF: `readelf -h` (if available)
- PDF: `pdfinfo` (if available)
- Archives: `zipinfo -1` / `tar tf` (first 50 entries)
- Text-like: first 20 `strings` lines
- Skips MIME whitelist, respects path blocklist

**4. `sread/lib/modules/hashlookup.sh`** — Check hash against local DB
- DB at `/usr/local/lib/sread/data/malware-sha256.txt` (sorted, baked at build)
- Uses `look` command for O(log n) binary search
- Supports `--file <path>` to hash-and-lookup in one step
- Output: `[MATCH]` or `[CLEAN]` per hash

**5. Update `sread/bin/sread`** — add new capabilities to `--capabilities` text

### Phase 2: Watch daemon scripts

**6. `agent/lib/watch-common.sh`** — Shared watch utilities
- `watch_log()` — timestamped logging to stderr + `state/watch/watch.log`
- `init_watch_state()` — create state dirs
- `is_file_seen()` / `mark_file_seen()` — seen.db operations (format: `hash size filepath timestamp`)
- `classify_file()` — returns SKIP_MEDIA / SKIP_TINY / ANALYZABLE based on MIME
- `enqueue_file()` / `dequeue_all()` — queue management in `state/watch/queue/`
- `write_alert()` — immediate finding for known-malware hash matches

**7. `agent/conf/agent.conf`** — Add watch settings
```bash
WATCH_POLL_INTERVAL=5
WATCH_BATCH_SIZE=10
WATCH_MAX_FILE_SIZE=52428800  # 50MB
WATCH_SCAN_DEPTH=1
```

**8. `agent/WATCH.md`** — System prompt for Claude malware triage
- Role: malware triage analyst
- Methodology by file type:
  - Scripts: obfuscation, eval/exec, network calls, privesc
  - ELF: entropy, suspicious strings, packing indicators
  - PDFs: /JavaScript, /OpenAction, /Launch, embedded files
  - Office: vbaProject.bin (macros), external rels, OLE objects
  - Archives: executables inside, path traversal, zip bombs
- Verdict format: CLEAN / SUSPICIOUS / MALICIOUS with confidence + reasoning

**9. `agent/watch.sh`** — The daemon loop
- Infinite `while true` with `sleep $POLL_INTERVAL`
- Scans `/host/home/*/Downloads/` (maxdepth 1) each cycle
- Skips files modified <2s ago (still being written) and files >50MB
- Stores hash+size in seen.db (re-hashes if size changed since last seen)
- Signal handling: `trap cleanup SIGTERM SIGINT` for graceful shutdown
- `analyze_batch()`: follows Ralph pattern — assembles prompt with file table, spawns `claude --dangerously-skip-permissions --print`, parses output, writes findings
- `--no-claude` flag for hash-check-only mode (no AI analysis)
- `--poll-interval N` override

### Phase 3: Docker build changes

**10. `Dockerfile`** — Add packages + hash DB
- Add to `apt-get install`: `binutils` (strings, readelf), `poppler-utils` (pdftotext, pdfinfo)
- New build step: download MalwareBazaar SHA256 full export, filter valid hashes, sort for `look`
  ```dockerfile
  RUN mkdir -p /usr/local/lib/sread/data \
      && curl -sSL https://bazaar.abuse.ch/export/txt/sha256/full/ \
      | grep -E '^[0-9a-f]{64}$' \
      | sort > /usr/local/lib/sread/data/malware-sha256.txt
  ```
- `chmod +x /opt/secy/watch.sh`

### Phase 4: Integration

**11. `agent/secy.sh`** — Add watch dispatch
- In usage: add `watch` mode description
- Early return: `if [[ "$mode" == "watch" ]]; then exec "${AGENT_DIR}/watch.sh" "${@:2}"; fi`

**12. `docker-compose.yml`** — Add `secy-watch` service
- Extends existing secy config (same volumes, caps, security)
- `command: ["watch"]`
- `restart: unless-stopped` for true daemon behavior

### Phase 5: Documentation

**13. `agent/AGENT.md`** — Add hash/fileinfo/hashlookup module reference
**14. `README.md`** — Document watch mode (usage, modes table, "what it checks")

## Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| **Polling not inotify** | inotify on bind mounts in Docker is unreliable across kernel versions. 5s polling on a single dir is negligible CPU. |
| **`look` for hash search** | O(log n) binary search on sorted file. 1.5M hashes searched in ~20 seeks. Zero dependency beyond util-linux. |
| **One Claude per poll cycle** | Batching controls costs. One invocation handles up to BATCH_SIZE files. |
| **Skip media files** | image/video/audio are near-zero risk as direct malware on Linux. Hash check still catches known-malicious media. |
| **Hash DB baked at build** | No runtime network needed. Rebuild image to refresh. Recommend daily rebuild cron for freshness. |
| **Separate watch.sh file** | Daemon lifecycle is fundamentally different from bounded modes. Clean separation via `exec` delegation. |
| **seen.db stores hash+size** | Detects partial downloads: if file size changes after initial hash, re-hash on next cycle. |

## Files Summary

| Action | Path |
|--------|------|
| Create | `sread/data/` (directory) |
| Create | `sread/lib/modules/hash.sh` |
| Create | `sread/lib/modules/fileinfo.sh` |
| Create | `sread/lib/modules/hashlookup.sh` |
| Create | `agent/lib/watch-common.sh` |
| Create | `agent/watch.sh` |
| Create | `agent/WATCH.md` |
| Modify | `sread/bin/sread` (capabilities text) |
| Modify | `agent/conf/agent.conf` (watch settings) |
| Modify | `agent/secy.sh` (watch dispatch) |
| Modify | `agent/entrypoint.sh` (no changes needed — already passes args through) |
| Modify | `Dockerfile` (packages + hash DB) |
| Modify | `docker-compose.yml` (secy-watch service) |
| Modify | `agent/AGENT.md` (hash module docs) |
| Modify | `README.md` (watch mode docs) |

## Verification

1. **sread modules standalone**: `sread hash /etc/hostname`, `sread fileinfo /bin/ls`, `sread hashlookup <known-hash>`
2. **Watch without Claude**: `docker compose run secy watch --no-claude` — drop file in Downloads, verify seen.db entry and watch.log
3. **Known malware alert**: Insert a test hash into DB, drop matching file, verify CRITICAL alert in `state/watch/findings/`
4. **Full integration**: `docker compose run secy watch` — drop a script in Downloads, verify Claude analysis finding
5. **Daemon mode**: `docker compose up -d secy-watch` — verify restart behavior, graceful shutdown via `docker compose down`
