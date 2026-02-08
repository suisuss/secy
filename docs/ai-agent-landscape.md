# AI Agent Landscape: Security Analysis

An analysis of current AI agent tools and their security models, written in the context of secy — a restricted sudo audit environment for AI agents.

These three projects represent two distinct patterns for autonomous AI agents: **loop-based coding agents** (Ralph) and **platform-bridging personal assistants** (OpenClaw). Both grant AI broad system access. Both have security implications worth understanding.

---

## Ralph

**Repo:** [snarktank/ralph](https://github.com/snarktank/ralph)
**What it is:** An autonomous coding loop that repeatedly spawns fresh Claude Code instances to work through a task list.

### How It Works

The entire runtime is a bash loop:

```bash
for i in $(seq 1 $MAX_ITERATIONS); do
    OUTPUT=$(claude --dangerously-skip-permissions --print < CLAUDE.md 2>&1 | tee /dev/stderr)
    echo "$OUTPUT" | grep -q '<promise>COMPLETE</promise>' && exit 0
    sleep 2
done
```

Each iteration:

1. Pipes `CLAUDE.md` (prompt instructions) into Claude Code in headless mode
2. Claude reads `prd.json` — a JSON task list with a `passes: boolean` per story
3. Picks the highest-priority incomplete story, implements it
4. Runs quality checks (typecheck, lint, tests)
5. Commits if checks pass, marks story as `passes: true`
6. Appends learnings to `progress.txt`
7. Exits. Loop restarts with a **completely fresh context window**.

### Architecture

| File | Role |
|------|------|
| `ralph.sh` | Outer bash loop (~100 lines). Start/stop/archive logic. |
| `prd.json` | Task list — the state machine. Each story has `passes: boolean`. |
| `progress.txt` | Append-only log. "Codebase Patterns" section accumulates learnings. |
| `CLAUDE.md` | Prompt template piped to Claude each iteration. |
| `.last-branch` | Tracks current branch. Branch change triggers archival of previous run. |

Memory is filesystem-based, not context-based. Each iteration is stateless from the LLM's perspective — it reads `prd.json`, `progress.txt`, and git history to reconstruct what happened before. This means context window degradation is impossible across the full project.

The completion signal is a literal string `<promise>COMPLETE</promise>` that the LLM emits when it determines all stories pass. The bash script greps for it.

### Security Model

**There is no security model.** The design is explicit about this:

- `--dangerously-skip-permissions` is **load-bearing**. Without it, Claude Code prompts for confirmation on every file edit and shell command, which halts the autonomous loop.
- The LLM has unrestricted filesystem, shell, and git access.
- The only protection against bad actions is the quality checks the LLM runs itself (tests, lint, typecheck) — and those depend on the project actually having them.
- No network restrictions. No file access restrictions. No command blocklist.

**The prescribed mitigation is environmental:** run Ralph inside a disposable sandbox (Docker container, cloud VM, Fly Sprites, E2B). The sandbox is the only security boundary.

**Blast radius without sandbox:** Full access to the host — credentials, browser cookies, SSH keys, API tokens, other repos. Ralph's docs acknowledge this: "It's not if it gets popped, it's when. And what is the blast radius?"

### Relevance to secy

Ralph represents the use case where an agent needs to **write** to the filesystem. secy is designed for **read-only** auditing, which is a fundamentally different trust model. However, the patterns overlap:

- Both need to run shell commands with elevated context
- Both face prompt injection risk (Ralph via malicious code in repos it's working on)
- Ralph's "backpressure" concept (tests/lints as guardrails) is analogous to secy's blocklist/redaction layers

A Ralph-style loop running `secy` modules instead of raw shell commands would be a significantly more constrained audit agent — able to investigate iteratively without the blast radius of raw `sudo`.

---

## Ralph Playbook

**Repo:** [ClaytonFarr/ralph-playbook](https://github.com/ClaytonFarr/ralph-playbook)
**What it is:** A methodology guide that formalizes the Ralph pattern into a structured three-phase workflow. By Clayton Farr, distilling Geoff Huntley's original "Ralph" methodology.

### The Three Phases

**Phase 1 — Define Requirements** (human + LLM conversation):
- Identify Jobs to Be Done (JTBD)
- Break each into "topics of concern" (each should pass the "one sentence without 'and'" test)
- Write one spec file per topic: `specs/FILENAME.md`
- Specs are the source of truth for what should be built

**Phase 2 — Planning** (automated loop with `PROMPT_plan.md`):
- Claude uses subagents to study all specs and existing source code
- Performs gap analysis: what specs require vs. what code exists
- Outputs `IMPLEMENTATION_PLAN.md` — a prioritized bullet-point TODO
- No implementation happens. No commits. Analysis only.

**Phase 3 — Building** (automated loop with `PROMPT_build.md`):
- Each iteration: read plan, pick most important task, implement, test, commit, update plan, exit
- Loop restarts with fresh context, reads updated plan, picks next task
- Continues until plan is exhausted or manually stopped

### Key Methodological Insights

**Context budget discipline:**
- Every iteration loads the same deterministic context: `PROMPT.md` + `AGENTS.md`
- The "smart zone" (40-60% of usable context, roughly 70-105K tokens) is where the LLM does its best work
- One task per iteration = 100% smart zone utilization
- `AGENTS.md` must stay under ~60 lines — it's loaded every iteration, and bloat degrades all future loops

**Steering mechanisms:**
- *Upstream (inputs):* Deterministic file setup, code patterns the agent discovers, `AGENTS.md` notes
- *Downstream (backpressure):* Tests, typechecks, lints that reject invalid work
- The agent can only commit if quality checks pass — this is the enforcement layer

**The plan is disposable:**
- Delete `IMPLEMENTATION_PLAN.md` and regenerate whenever trajectory goes wrong
- Cost: one planning loop iteration
- Regenerate when: going off track, too much clutter, significant spec changes

**Guardrail numbering convention:**
- Build prompts use escalating `9`-digit numbers for invariant rules
- `99999` — Capture the why in documentation
- `999999` — Single sources of truth
- `9999999999` — Update `AGENTS.md` with learnings
- `999999999999` — Implement completely, no placeholders
- More 9s = higher priority signal to the LLM

**"Let Ralph Ralph":**
- Trust the self-correction loop. Eventual consistency through iteration.
- When it fails, add guardrails ("signs") rather than prescribing everything upfront
- Start with empty `AGENTS.md` and add notes only as failures reveal gaps

### Security Additions Over Base Ralph

The playbook is more explicit about sandbox requirements:

- `--dangerously-skip-permissions` bypasses Claude's permission system entirely — sandbox is the only boundary
- Prescribes minimum viable access: only the API keys and deploy keys needed for the task
- Docker, Fly Sprites, E2B recommended
- Credential isolation: the sandbox should not have access to your main machine's secrets

The playbook also documents **non-deterministic backpressure** — using an LLM-as-judge to evaluate subjective criteria (aesthetics, UX, tone) with binary pass/fail. This extends the quality gate concept beyond static analysis.

### Relevance to secy

The playbook's structure of phases could apply to security auditing:

| Ralph Phase | Security Audit Equivalent |
|-------------|--------------------------|
| Phase 1: Define specs | Define audit scope and compliance requirements |
| Phase 2: Planning | Enumerate what to check, prioritize by risk |
| Phase 3: Building | Run audit modules, investigate findings, produce report |

The `IMPLEMENTATION_PLAN.md` pattern — a living document the agent updates as it works — could translate to an audit findings document that accumulates across secy module runs.

---

## OpenClaw (formerly Clawdbot, then Moltbot)

**Repo:** [openclaw/openclaw](https://github.com/clawdbot/clawdbot) (redirected from clawdbot/clawdbot)
**What it is:** A self-hosted Node.js agent that bridges messaging platforms (WhatsApp, Telegram, Discord, Slack, Signal, iMessage) to a local LLM-powered personal assistant.
**Scale:** 176k+ GitHub stars, ~29k forks. Created by Peter Steinberger.

### How It Works

```
User sends message on WhatsApp/Telegram/Discord/...
        │
        ▼
Channel Plugin (Baileys, grammY, discord.js, etc.)
        │
        ▼
Gateway (single Node.js process, WS+HTTP on :18789)
        │
        ▼
Pi Agent Runtime (embedded, in-process)
  - System prompt assembly (includes skills)
  - Model selection + auth profile rotation
  - Tool execution + streaming
        │
        ▼
LLM API (Anthropic, OpenAI, Google, Bedrock, Ollama)
```

Everything runs in one Node.js process. No cloud relay. The Gateway binds to `127.0.0.1:18789` and acts as the control plane. WebSocket is the internal bus — CLI, macOS app, iOS/Android nodes, and the web UI all connect via WS.

### Channel Integrations

| Channel | Library | Auth Method |
|---------|---------|-------------|
| WhatsApp | `@whiskeysockets/baileys` (unofficial) | QR code linking |
| Telegram | `grammy` | Bot token from @BotFather |
| Discord | `discord.js` / `@buape/carbon` | Bot token |
| Slack | `@slack/bolt` | Bot + app token (Socket Mode) |
| Signal | `signal-cli` (external process) | Linked device |
| iMessage | BlueBubbles | BlueBubbles server |
| Google Chat | Chat API | Service account credentials |
| MS Teams, Matrix, Zalo, etc. | Extension plugins | Various |

### Extension System

**Skills** — Markdown files (`SKILL.md`) injected into the system prompt. Teach the agent how to use tools. Loaded from:
1. Workspace: `<project>/skills/`
2. Managed: `~/.openclaw/skills/` (installed via ClawHub)
3. Bundled: shipped with OpenClaw (obsidian, github, spotify, weather, etc.)
4. Plugins: contributed by installed code extensions

**Plugins** — TypeScript packages that register tools, channels, providers, HTTP routes, hooks, services, and CLI commands. This is how new messaging platforms and capabilities get added.

### Authentication Layers

**Gateway access:**
- Shared token (`OPENCLAW_GATEWAY_TOKEN`) or password
- Tailscale identity headers (when behind Tailscale Serve)
- Device tokens for paired nodes (iOS/Android/macOS)
- Token comparison uses `crypto.timingSafeEqual()`

**LLM API:**
- OAuth profiles with rotation/failover (recommended)
- Raw API keys via config or env vars
- AWS credential chain for Bedrock
- GitHub Copilot token exchange

**Channel credentials:**
- Per-platform, stored in `~/.openclaw/credentials/` with `0o600` permissions

**DM pairing (default):**
- Unknown senders receive a pairing code
- Bot refuses to process their messages until approved
- This is the primary defense against unauthorized access
- Can be set to `dmPolicy="open"` which removes all verification (footgun)

### Security Model

**What exists:**

| Mechanism | What It Does |
|-----------|-------------|
| DM pairing | Blocks unknown senders by default |
| Security audit tool | `openclaw security audit --deep` — checks file permissions, secrets in config, DM policy, exposure matrix, skill code safety |
| Exec approval manager | Can require human approval before shell command execution |
| Tool policy system | Allowlist/blocklist for which tools the agent can use |
| Node command policy | Controls what commands companion devices can execute |
| Sandbox support | Docker-based sandboxing for the exec tool |
| detect-secrets CI | Automated secret detection in the codebase |

**What doesn't exist or is weak:**

| Gap | Risk |
|-----|------|
| Single-process trust boundary | A compromised plugin has full access to all credentials, all sessions, and can execute arbitrary code. No process-level isolation. |
| Prompt injection explicitly out of scope | SECURITY.md lists it as out of scope. Relies on LLM's native resistance + system prompt instruction to treat inputs as untrusted. |
| WhatsApp via Baileys | Unofficial reverse-engineered protocol. Can break at any time. May violate WhatsApp TOS. Session data security depends on Baileys implementation. |
| Plaintext session storage | Session transcripts stored as unencrypted JSONL on disk. Full conversation history readable by anyone with filesystem access. |
| Shared-secret gateway auth | One token for all clients. No per-client auth, no client certificates, no mTLS. Token leak = full gateway control. |
| Skill trust model | Skills from ClawHub are markdown instructions injected into the system prompt. A malicious skill is prompt injection by design. |
| Open DM policy option | `dmPolicy="open"` removes all sender verification. Documented but dangerous. |

### Security Audit Findings (from OpenClaw's own tooling)

OpenClaw ships a comprehensive `security audit` command that checks:
- File permissions on config/credentials/state directories
- Secrets exposed in config files
- DM policy configuration
- Attack surface summary and exposure matrix
- Hooks hardening
- Installed skills code safety
- Plugin trust assessment
- Model hygiene (flags risk of using smaller, more manipulable models)
- Synced folder exposure
- State directory deep filesystem scan

This is notable — it's one of the few AI agent projects that ships its own security audit tooling. The tool is honest about the gaps it finds.

### Relevance to secy

OpenClaw is the most relevant project to secy's mission because:

1. **It already has a security audit tool.** The patterns in `openclaw security audit` are worth studying — file permission checks, credential exposure scanning, attack surface enumeration. These could inform secy modules.

2. **It demonstrates the risks of broad agent access.** A single Node.js process with access to all messaging platforms, all LLM credentials, all session history, and shell execution capability is a high-value target. This is exactly the attack surface secy is designed to constrain.

3. **Its skill system is prompt injection by design.** Any SKILL.md loaded into the system prompt can influence agent behavior. This is the dual-use nature of extensibility — same mechanism enables both features and attacks.

4. **The DM pairing system is a good model for agent access control.** The default-deny posture (unknown senders blocked until approved) is analogous to secy's whitelist approach to MIME types and file paths.

---

## Comparative Security Analysis

| Property | Ralph | Ralph Playbook | OpenClaw |
|----------|-------|----------------|----------|
| **Primary function** | Autonomous coding loop | Methodology for Ralph | Personal assistant via messaging |
| **Permission model** | `--dangerously-skip-permissions` (all or nothing) | Same as Ralph | Exec approval manager (per-command, optional) |
| **Network access** | Unrestricted | Unrestricted | Unrestricted (channels require it) |
| **File access** | Unrestricted | Unrestricted | Unrestricted (but sandboxing available) |
| **Shell access** | Unrestricted | Unrestricted | Configurable (approval manager) |
| **Credential isolation** | None (sandbox is the boundary) | Prescribes minimum viable access | Per-platform credentials with file permissions |
| **Prompt injection defense** | None (trusts repo content) | None | Out of scope (per SECURITY.md) |
| **Quality gates** | Tests/lint/typecheck (project-dependent) | Same + LLM-as-judge | DM pairing, tool policy, exec approval |
| **Audit tooling** | None | None | Built-in `security audit --deep` |
| **Sandbox support** | External (Docker/VM recommended) | External (Docker/VM recommended) | Built-in Docker sandboxing for exec |
| **Session persistence** | `prd.json` + `progress.txt` (on disk) | Same | JSONL files (plaintext on disk) |
| **Memory across iterations** | Filesystem-based (git, progress.txt) | Same + `AGENTS.md` | In-process session history |
| **Completion detection** | `<promise>COMPLETE</promise>` string match | Same pattern | Continuous (always-on agent) |

---

## Implications for secy

### What secy could offer these projects

1. **For Ralph/Playbook:** A `secy`-gated audit phase before the build loop. Instead of jumping straight into coding, run `secy full` to understand the system's security posture, then incorporate findings into the implementation plan.

2. **For OpenClaw:** Replace the raw exec tool with secy-gated commands for audit use cases. Instead of `sudo cat /etc/sshd_config`, the agent calls `secy files /etc/ssh/sshd_config` — getting the content with redaction and blocklist enforcement.

3. **For all three:** A standardized way to grant read-only elevated access without the binary choice of "full sudo" or "no access." The four-layer defense (sudoers allowlist, argument validation, MIME type checking, output redaction) is a middle ground that doesn't exist in any of these projects today.

### What secy should learn from these projects

1. **Ralph's filesystem-as-memory pattern** could make secy sessions stateful — an audit findings file that accumulates across module runs, allowing the agent to build on previous discoveries.

2. **OpenClaw's security audit tool** demonstrates that agents can audit themselves. secy could include a self-check module that verifies its own installation integrity, blocklist completeness, and redaction coverage.

3. **The Playbook's backpressure concept** maps to secy's defense layers. Each layer (blocklist, MIME check, redaction) is a form of backpressure that rejects unsafe operations before they reach the output.

4. **All three projects confirm the core thesis:** AI agents need constrained access models. The current state of the art is either "full permissions" or "ask for approval on everything." secy's approach — structured, auditable, restricted access to specific capabilities — fills a gap none of these projects address.

---

## References

- [snarktank/ralph](https://github.com/snarktank/ralph)
- [ClaytonFarr/ralph-playbook](https://github.com/ClaytonFarr/ralph-playbook)
- [openclaw/openclaw](https://github.com/clawdbot/clawdbot)
- [OpenClaw rise and controversy — CNBC](https://www.cnbc.com/2026/02/02/openclaw-open-source-ai-agent-rise-controversy-clawdbot-moltbot-moltbook.html)
- [OpenClaw security concerns — Computerworld](https://www.computerworld.com/article/4125939/by-whatever-name-moltbolt-clawd-openclaw-this-uber-ai-assistant-is-a-security-nightmare.html)
- [OpenClaw — Scientific American](https://www.scientificamerican.com/article/moltbot-is-an-open-source-ai-agent-that-runs-your-computer/)
- [The Ralph Wiggum Approach — DEV Community](https://dev.to/sivarampg/the-ralph-wiggum-approach-running-ai-coding-agents-for-hours-not-minutes-57c1)
