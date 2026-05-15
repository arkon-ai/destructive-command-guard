# Claude Code integrations

Adapters that bridge Claude Code's PreToolUse hook surface into `dcg`.

## `dcg-ctx-wrap`

Closes the **ctx_execute bypass**: Claude Code's stock `Bash` matcher does not
fire for `mcp__context-mode__ctx_execute` / `_execute_file`, which run shell /
python / javascript code inside a sandboxed subprocess. Without this adapter,
every DCG rule that gates `Bash` is silently skipped when the agent reaches
for ctx_execute.

The adapter:

1. Reads the Claude Code hook JSON from stdin.
2. If `tool_name ∈ {mcp__context-mode__ctx_execute, mcp__context-mode__ctx_execute_file}`,
   extracts `tool_input.code` and rewrites the payload as a synthetic
   `{tool_name: "Bash", tool_input: {command: <code>}}` shape.
3. Pipes the rewritten payload through `dcg-wrap` (which runs `dcg` + the
   Discord alert path).
4. Emits `dcg-wrap`'s decision back to Claude Code unchanged.

For non-shell languages (javascript / python / ruby / etc.), DCG's regex
patterns still scan the raw source — substrings like `infisical secrets --plain`
will match whether they live in `bash` or in a JS `execSync(...)` string. This
is intentional: defends against the same emit vector in any wrapping language.

### Install

```
cp dcg-ctx-wrap ~/.local/bin/dcg-ctx-wrap
chmod +x ~/.local/bin/dcg-ctx-wrap
```

### Wire into Claude Code (`~/.claude/settings.json`)

Add alongside the existing `Bash` matcher:

```json
{
  "matcher": "mcp__context-mode__ctx_execute|mcp__context-mode__ctx_execute_file",
  "hooks": [
    { "type": "command", "command": "/home/<user>/.local/bin/dcg-ctx-wrap" }
  ]
}
```

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
