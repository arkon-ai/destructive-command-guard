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
2. If the tool name CONTAINS one of `CTX_TOOL_TOKENS` (`context-mode__ctx_execute`,
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

**Payload extraction is SHAPE-AGNOSTIC, not per-tool.** The known shapes are:
`ctx_execute` / `ctx_execute_file` carry a single `tool_input.code`;
`ctx_batch_execute` carries `tool_input.commands[]` of `{label, command}` (older
builds add a `processing` sibling) and **no** top-level `code`. But the adapter
does not key on any of that — it walks the whole `tool_input` and collects every
string **value** it finds, at any depth, then joins the non-blank ones one per
line into the synthetic command. Dict **keys** are not collected: a payload
shaped `{"commands": {"<command text>": {…}}}` is verdicted on the values alone.
That is a known, bounded gap in the drift-resistance claim rather than a live
bypass — no context-mode shape carries executable text in a key — and the
adapter documents why appending keys is not the fix. Keying on field names reproduced the transformate WI-2096
drift one layer down: rename the field and a guarded call extracts nothing and sails
through with the suite green.

The observable consequence, so it is not mistaken for a bug: a dangerous-looking
**label or path** can trigger a denial even when the executable code is benign.
That over-matching is the deliberate trade — dcg scans text, so a needless scan
costs nothing and a missed one is the incident.

Payload text (every string value under `tool_input`, including `path` and
`code`) still flows through `dcg-wrap` as a synthetic Bash command — that is the
original WI-2096 path and it is unchanged.

**transformate WI-3059 (closed):** for `ctx_execute_file` only, after a clean
payload-text verdict the adapter runs a **separate** `dcg scan --paths <path>
--format json --redact aggressive` on the referenced file. That report is parsed
for deny/error findings; the deny reason carries **rule id + path + line only**.
The matched snippet / file body is deliberately dropped and is **never** forwarded
to `dcg-wrap`, so it cannot reach the Discord alert path. Reading the file into
the synthetic command was considered and refused at merge authority on 2026-08-20
for exactly that exfil reason; this is the remedy that keeps contents off the
alert channel.

For non-shell languages (javascript / python / ruby / etc.), DCG's regex
patterns still scan the raw source — substrings like `infisical secrets --plain`
will match whether they live in `bash` or in a JS `execSync(...)` string. This
is intentional: defends against the same emit vector in any wrapping language.

### Install

**Prerequisite: `dcg-wrap` must already be installed and executable.** Since the
fail-closed flip, a scanner that cannot be run DENIES — so installing this
adapter on a host without `dcg-wrap` rejects every `ctx_execute`,
`ctx_execute_file` and `ctx_batch_execute` call.

```
test -x ~/.local/bin/dcg-wrap || echo "install dcg-wrap FIRST — ctx tools will be denied"
cp dcg-ctx-wrap ~/.local/bin/dcg-ctx-wrap
chmod +x ~/.local/bin/dcg-ctx-wrap
```

### Verify

```
python3 test-dcg-ctx-wrap.py         # adapter routing, extraction, decision contract
node test-apply-wi2096-matcher.mjs   # applier gating, canaries, publish ordering
```

Both exit 0 on pass. They stub `dcg-wrap`. The applier suite stubs the sweep for
every case except one optional extra: if `warden-memory/scripts/audit-hook-matchers.mjs`
is present on the machine, T7 also execs that script; if it is not, T7 prints SKIP
and is not a pass of the pin. No network, no secrets. They fail loudly if the
tool-name keying, the batch extraction, or the fail-closed contract regresses to
the transformate WI-2096 shape.

**Run them on Linux.** Git Bash on Windows cannot exec the POSIX-shebang stubs,
so every scanner verdict masks as a spurious DENY and the results are noise.

A green suite is not a working install. The suites prove behaviour against
stubs; only the applier's canary 3 proves that the real scanner is on the path.

### Wire into Claude Code (`~/.claude/settings.json`)

Add alongside the existing `Bash` matcher. The matcher is a regex tested against
the tool name — keep it **loose** and unanchored, so a harness rename
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
on the next sync. Use the gated applier, which writes the change as a
**candidate**, runs three canaries against it, and publishes only on green:

```
node apply-wi2096-matcher.mjs --dry-run   # show the change, touch nothing
node apply-wi2096-matcher.mjs             # candidate → canary ×3 → backup → publish
```

The applier will **refuse to certify** unless the settings document's `env` block
declares `PATH`, `PYTHONPATH`, `PYTHONHOME` and `PYTHONSTARTUP`. An empty string
counts as a declaration for the last three, where it means "unset" and still
dominates ambient. It does **not** count for `PATH`: an empty `PATH` resolves no
interpreter at all, and `dcg-ctx-wrap` starts `#!/usr/bin/env python3`, so the
control would be dark rather than certified. Every component of all four must be
an absolute path -- a trailing or doubled delimiter is an empty component and
means the current directory. A declared `DCG_WRAP_BIN` must be absolute too: it
names the file the green line calls the scanner. It does not invent a PATH floor
and does not inherit the calling shell. It also refuses if that block declares Node-runtime or native-preload
selectors (`NODE_OPTIONS`, `NODE_PATH`, `NODE_REPL_EXTERNAL_MODULE`, `LD_PRELOAD`,
`LD_LIBRARY_PATH`, `DYLD_*`): the harness would overlay those onto the live hook,
and a canary that stripped them would be certifying a different process. A green
line names the four pin values and states that ambient native preload was not
established.

| canary | asserts |
|---|---|
| 1 | the matcher **on disk** matches every live ctx tool name (read back, not asserted against this script's own constants) |
| 2 | the coverage sweep goes green against the candidate |
| 3 | a known-dangerous fixture is denied **by the scanner** — not by the adapter |

Canary 3 exists because the fail-closed flip made DENY ambiguous: a missing or
broken `dcg-wrap` also denies, so "something said DENY" stopped distinguishing a
live control from a dark one. Adapter-generated denials are recognisable — their
reason begins `dcg-ctx-wrap: ` — and canary 3 rejects them.

There is **no rollback path**, because nothing is published until the canaries
pass: on red, `settings.json` was never modified. A backup is still taken at
publish time. For manual rollback use the **exact timestamped path the applier
prints** — the fixed `.bak-wi2096` name is gone, because a second run overwrote
the only copy of the last known-good file and the documented rollback then
restored the already-broken state:

```
cp <the backup: path printed by the applier> ~/.claude/settings.json
```

Idempotent, but **not a no-op**: a re-run re-verifies that the control still
works and exits non-zero if it does not. "Already current" is a claim about
matcher text, and the matcher text is not the control.

| env | default | purpose |
|---|---|---|
| `HOOK_SETTINGS` | `~/.claude/settings.json` | canonical hook config to patch |
| `HOOK_SWEEP` | `~/dev/warden-memory/scripts/audit-hook-matchers.mjs` | coverage sweep |
| `CTX_WRAP` | `~/.local/bin/dcg-ctx-wrap` | wrapper basename the routing check uses |
| `HOOK_SWEEP_TIMEOUT_MS` | `120000` | ceiling on a hung sweep |

The sweep script reads `DCG_CTX_WRAP`, not `CTX_WRAP`. The applier sets both to the
wrapper path from the settings document when it spawns the sweep.

### Coverage sweep

`warden-memory/scripts/audit-hook-matchers.mjs` is the external check that this
adapter is actually reachable and actually denies: it feeds a synthetic,
never-executed trigger to the wrapper under each **live** tool name and asserts
`DENY`. A fail-open scores as a gap even when the static matcher looks right —
that asymmetry is what surfaced transformate WI-2096. Exit 0 = full coverage.

**That asymmetry no longer holds, and the sweep has not caught up.** Its
criterion is `covered = (dyn && dyn.decision === "DENY")`. Before the fail-closed
flip a missing `dcg-wrap` made the adapter ALLOW, so the sweep went red and the
gap surfaced. Now a missing, unexecutable, hung or crashed `dcg-wrap` produces
DENY, and the sweep scores that as **full coverage** — the check that exists to
tell "guarded" from "dark" can no longer do it.

Until the sweep is fixed in `warden-memory`, treat its green as necessary and not
sufficient; the applier's canary 3 is what actually distinguishes the two. The
sweep-side fix is one line, using the same discriminator:

```js
// An adapter self-denial (missing/hung/crashed dcg-wrap) is NOT coverage.
const adapterFault = /^dcg-ctx-wrap:/.test(dyn?.reason || "");
const covered = dyn && dyn.decision === "DENY" && !adapterFault;
```

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
| `dcg-wrap` exits 0 and says NOTHING | ALLOW — silence IS dcg's allow. **This is the one remaining fail-open in this control:** a stub, a `true`, or a wrapper whose exec failed silently is indistinguishable on the wire from a clean scan. It is closed at install time instead — `apply-wi2096-matcher.mjs` canary 3 sends a known-dangerous fixture and requires the DENY to have come from the scanner rather than from this adapter. |
| `dcg-wrap` exits NON-ZERO and says nothing | DENY — a clean scan and a crash are not the same thing. |
| `dcg-wrap` writes output that is not a recognisable decision, at any exit status | DENY |
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
