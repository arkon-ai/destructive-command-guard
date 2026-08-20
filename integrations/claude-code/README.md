# Claude Code integrations

Adapters that bridge Claude Code's PreToolUse hook surface into `dcg`.

## `dcg-ctx-wrap`

Closes the **ctx_execute bypass**: Claude Code's stock `Bash` matcher does not
fire for context-mode's `ctx_execute` / `ctx_execute_file` / `ctx_batch_execute`,
which run shell / python / javascript code inside a sandboxed subprocess.
Without this adapter, every DCG rule that gates `Bash` is silently skipped when
the agent reaches for one of them.

The adapter:

1. Reads the Claude Code hook JSON from stdin.
2. If the tool name ends in one of `CTX_TOOL_SUFFIXES` (`context-mode__ctx_execute`,
   `…ctx_execute_file`, `…ctx_batch_execute`), extracts every code-bearing field
   and rewrites the payload as a synthetic
   `{tool_name: "Bash", tool_input: {command: <code>}}` shape.
3. Pipes the rewritten payload through `dcg-wrap` (which runs `dcg` + the
   Discord alert path).
4. Emits `dcg-wrap`'s decision back to Claude Code unchanged.

**Matching is by SUFFIX, never exact name** (transformate WI-2096). The harness renamed
these tools from `mcp__context-mode__ctx_execute` to
`mcp__plugin_context-mode_context-mode__ctx_execute`; the old exact-membership
set stopped matching and fell straight through to `fail_open()`, leaving the
primary code-execution channel unscanned. A suffix match survives the next
prefix change instead of failing open.

**Payload extraction is per-tool.** `ctx_execute` / `ctx_execute_file` carry a
single `tool_input.code`; `ctx_batch_execute` carries `tool_input.commands[]` of
`{label, command}` (older builds add a `processing` sibling) and **no** top-level
`code`. All of them are joined one-per-line into the synthetic command so a
single offending entry anywhere in a batch still matches.

For non-shell languages (javascript / python / ruby / etc.), DCG's regex
patterns still scan the raw source — substrings like `infisical secrets --plain`
will match whether they live in `bash` or in a JS `execSync(...)` string. This
is intentional: defends against the same emit vector in any wrapping language.

### Install

```
cp dcg-ctx-wrap ~/.local/bin/dcg-ctx-wrap
chmod +x ~/.local/bin/dcg-ctx-wrap
```

### Verify

```
python3 test-dcg-ctx-wrap.py     # routing + payload extraction; exit 0 = pass
```

Stubs `dcg-wrap`, so no network, no secrets, no real scan. It fails loudly if
the tool-name keying or the batch extraction regresses to the WI-2096 shape.

### Wire into Claude Code (`~/.claude/settings.json`)

Add alongside the existing `Bash` matcher. The matcher is a regex tested against
the tool name — keep it **loose**, matching the suffix only, so a harness rename
of the prefix keeps firing:

```json
{
  "matcher": "context-mode__ctx_(execute|execute_file|batch_execute)",
  "hooks": [
    { "type": "command", "command": "/home/<user>/.local/bin/dcg-ctx-wrap" }
  ]
}
```

On a fleet host, don't hand-edit: `~/.claude/settings.json` is the canonical
source the REPL-seat renderer fans out to every seat, so broken JSON propagates
on the next sync. Use the gated applier, which backs up, patches, canaries
against the coverage sweep, and auto-reverts if the sweep isn't green:

```
node apply-wi2096-matcher.mjs --dry-run   # show the change, touch nothing
node apply-wi2096-matcher.mjs             # backup → patch → canary → keep|revert
```

Idempotent. Manual rollback: `cp ~/.claude/settings.json.bak-wi2096 ~/.claude/settings.json`.

### Coverage sweep

`warden-memory/scripts/audit-hook-matchers.mjs` is the external check that this
adapter is actually reachable and actually denies: it feeds a synthetic,
never-executed trigger to the wrapper under each **live** tool name and asserts
`DENY`. A fail-open scores as a gap even when the static matcher looks right —
that asymmetry is what surfaced WI-2096. Exit 0 = full coverage.

### Wire into Claude Agent SDK programmatic hooks

`settings.json` is only read by the Claude Code TTY harness. Agent-SDK
processes register hooks via `options.hooks` and must spawn `dcg-ctx-wrap`
themselves — see `codesmith-bridge.mjs` for an example pattern (`dcgHook(bin, input)`
spawns the binary, pipes the hook JSON on stdin, parses stdout JSON).

### Fail-open guarantee

Any error in the adapter path (unparseable stdin, missing `dcg-wrap` binary,
subprocess crash) returns `{"continue": true}` so the host call proceeds.
The adapter must never block real work because of its own bugs — `dcg-wrap`
itself remains the load-bearing safety layer.

### Incident provenance

Added 2026-05-15 after a Warden session leaked 68 Infisical secrets through
`mcp__context-mode__ctx_execute` running `"$INF" secrets --plain`. The shape
matched a DCG rule, but the rule never ran because the hook matcher was
scoped to `Bash` only.

Re-opened 2026-07-19 (transformate WI-2037 sweep, RED; fixed under transformate WI-2096): the same
control had gone dark again, this time because the tool names changed
underneath it. No observed leak — a missing control, found by the sweep rather
than by an incident. The suffix matching and the sweep exist so the third
occurrence trips a red timer instead of a postmortem.
