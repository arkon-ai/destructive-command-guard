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
2. If the tool name CONTAINS one of `CTX_TOOL_SUFFIXES` (`context-mode__ctx_execute`,
   `…ctx_execute_file`, `…ctx_batch_execute`), extracts every code-bearing field
   and rewrites the payload as a synthetic
   `{tool_name: "Bash", tool_input: {command: <code>}}` shape.
3. Pipes the rewritten payload through `dcg-wrap` (which runs `dcg` + the
   Discord alert path).
4. Emits `dcg-wrap`'s decision back to Claude Code unchanged.

**Matching is by SUBSTRING, never exact name** (transformate WI-2096). The harness renamed
these tools from `mcp__context-mode__ctx_execute` to
`mcp__plugin_context-mode_context-mode__ctx_execute`; the old exact-membership
set stopped matching and fell straight through to `fail_open()`, leaving the
primary code-execution channel unscanned. A substring match survives the next
prefix change instead of failing open.

It is deliberately not right-anchored, and `str.endswith` is **forbidden** here: the
`settings.json` matcher that routes calls to this adapter is unanchored, so the harness
really does deliver decorated names like `…__ctx_execute_v2`, and under `endswith` every
one of them reached `allow()` with the scanner never invoked. That remedy was applied
once and reverted; the suite now pins the decorated names as guarded.

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

### Decision contract — which way the adapter fails

**Once a call is identified as a guarded context-mode tool, it is never allowed
through because something failed.**

**And identification is part of that**, because every rule below is conditioned on the
call having been identified first — so defeating identification was a way past the
contract without ever engaging it. See "Identification fails closed too".

| situation | decision |
|---|---|
| stdin is not parseable JSON, and its raw bytes name no guarded tool | ALLOW — the call cannot be identified and nothing claims it should be. The harness writes this stdin; malformed input means the harness is broken. |
| stdin cannot be identified (unparseable, not an object, or `tool_name` missing/empty/not a string) **but its raw bytes name a guarded tool** | DENY |
| `tool_name` is a string naming something other than a context-mode exec tool | ALLOW — not this adapter's surface. |
| payload carried strings and all of them are blank | ALLOW — there is genuinely no code text to scan. |
| `tool_input` is not an object | DENY |
| payload carries no string fields at all | DENY — an unrecognized shape, which is what a schema rename looks like from inside the adapter. |
| payload nests deeper than `MAX_DEPTH` | DENY — scanning only the shallow part would report a verdict on a fraction of the payload. |
| `dcg-wrap` cannot be invoked, times out, or dies | DENY |
| `dcg-wrap` returns no parseable decision, at any exit status | DENY |
| any unexpected exception after the tool was identified as guarded | DENY |

A parseable decision from `dcg-wrap` is passed through untouched, exit status
included — it signals a block with exit 2, and rewriting that would mask its DENY.

**This replaces the previous blanket fail-open guarantee**, which read "the adapter
must never block real work because of its own bugs". That is a sound principle
applied to the wrong set. A missing scanner binary is not the adapter's own bug,
and once the tool is identified as guarded this adapter is the *only* path from
the ctx tools into dcg — the `Bash` matcher does not fire for them. So an
operational failure of the scanner silently reopened exactly the channel that
leaked on 2026-05-15. Measured, not argued: `DCG_WRAP_BIN=/nonexistent` used to
emit `{"continue": true}` and exit 0.

### Identification fails closed too

Every rule in that table starts "once the call is identified as guarded". So an attacker
never had to beat the contract — only to stop it applying. Two routes did exactly that,
each returning `{"continue": true}` with the scanner **never invoked**:

- **`json.loads` recurses.** Nesting any field deep enough raises `RecursionError`, which
  is an `Exception`, which the parse guard caught and turned into an allow. `MAX_DEPTH`
  does not help — it applies during extraction, *after* the parse. The depth needed is a
  C-stack limit that has moved across releases, measured on the parent commit at ~1100
  (3.11.15), ~10000 (3.12.3) and ~20000 (3.14.3). The interpreter sets the price, not
  whether the door is open.
- **A non-string `tool_name`** reached the same allow through the type check — on every
  interpreter, at any payload size, and reachable without any adversary at all.

The close: an identification failure counts as "not our surface" only while nothing in the
raw stdin says otherwise. The harness serialises `tool_name` with a standard JSON encoder,
so a guarded token is present verbatim in the bytes even when the document will not parse;
`\uXXXX`-escaped spellings are decoded before the check. If a guarded token is there, the
call is refused.

This is a tie-breaker for unidentifiable input, **not** a second opinion about a call that
was read correctly: it is consulted only after identification has already failed. A `Bash`
call whose command text merely mentions a ctx tool name parses fine, identifies as `Bash`,
and is allowed by the normal path. The suite pins that case.

Extraction is also shape-agnostic rather than field-keyed: it walks the whole
`tool_input` and scans every string it finds. Keying on `code` and
`commands[].command` had the same drift semantics one layer down as the
tool-name keying fixed in transformate WI-2096 — rename the field and a guarded
call extracts nothing and sails through, with the test suite still green.

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
