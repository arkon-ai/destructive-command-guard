#!/usr/bin/env node
// test-apply-wi2096-matcher.mjs — self-check for the WI-2096 matcher applier.
//
// The applier had NO test at all, which is how it came to report `already current` and
// exit 0 in two opposite states: every ctx matcher current, and NO ctx matcher present.
// The second is the "control gone dark" condition the applier exists to remediate, so the
// remediation tool green-ticked the vulnerability it was written to close.
//
// Everything is driven through HOOK_SETTINGS and HOOK_SWEEP against temp files, so no real
// settings.json is read or written and no real sweep runs.
//
// Run: node integrations/claude-code/test-apply-wi2096-matcher.mjs   (exit 0 = pass)

import { mkdtempSync, writeFileSync, readFileSync, chmodSync, rmSync, existsSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const APPLY = path.join(HERE, "apply-wi2096-matcher.mjs");
const LOOSE = "context-mode__ctx_(execute|execute_file|batch_execute)";

const tmp = mkdtempSync(path.join(tmpdir(), "wi2096-"));
const failures = [];
const check = (desc, cond) => { if (!cond) failures.push(desc); };

// A stub sweep whose exit status we control, so the canary can be driven both ways.
function sweep(exitCode) {
  const p = path.join(tmp, `sweep-${exitCode}.mjs`);
  writeFileSync(p, `console.log("stub sweep"); process.exit(${exitCode});\n`);
  return p;
}

function settings(entries) {
  const p = path.join(tmp, `settings-${Math.random().toString(36).slice(2)}.json`);
  writeFileSync(p, JSON.stringify({ hooks: { PreToolUse: entries } }, null, 2) + "\n");
  return p;
}

function run(settingsPath, sweepPath, extraArgs = []) {
  const r = spawnSync(process.execPath, [APPLY, ...extraArgs], {
    encoding: "utf8",
    env: { ...process.env, HOOK_SETTINGS: settingsPath, HOOK_SWEEP: sweepPath },
  });
  return { status: r.status, out: (r.stdout || "") + (r.stderr || "") };
}

const hook = [{ command: "~/.local/bin/dcg-ctx-wrap" }];
const staleEntry = () => ({ matcher: "mcp__context-mode__ctx_execute", hooks: hook });
const looseEntry = () => ({ matcher: LOOSE, hooks: hook });
const bashEntry = () => ({ matcher: "Bash", hooks: [{ command: "dcg-wrap" }] });

// 1. THE REGRESSION THIS FILE EXISTS FOR: no context-mode matcher anywhere. The control is
//    absent. This must NOT be reported as "already current", and must NOT exit 0.
{
  const s = settings([bashEntry()]);
  const r = run(s, sweep(0));
  check("absent control does not exit 0", r.status !== 0);
  // Anchored: the failure message legitimately contains the words "already current" while
  // explaining that this state is NOT that. Only the success line starts with them.
  check("absent control is not reported as already-current", !/^already current/m.test(r.out));
  check("absent control says the matcher is missing", /NO context-mode PreToolUse matcher/.test(r.out));
}

// 1b. A matcher-shaped hole: the entry exists and is already LOOSE, but runs NOTHING. That
//     used to report "already current" and exit 0, skipping both canaries — the same false
//     green as an absent control, just wearing a matcher.
for (const [label, hooks] of [
  ["empty hooks array", []],
  ["missing hooks key", undefined],
  ["blank command", [{ command: "   " }]],
]) {
  const entry = { matcher: LOOSE };
  if (hooks !== undefined) entry.hooks = hooks;
  const s = settings([bashEntry(), entry]);
  const r = run(s, sweep(0));
  check(`hollow matcher (${label}) does not exit 0`, r.status !== 0);
  check(`hollow matcher (${label}) is not called already-current`, !/^already current/m.test(r.out));
  check(`hollow matcher (${label}) says it runs nothing`, /runs NOTHING/.test(r.out));
}

// 1c. A run must not destroy the previous run's backup. A fixed backup name meant the second
//     invocation overwrote the only copy of the last known-good file, so the documented manual
//     rollback restored the already-broken state.
{
  const s = settings([bashEntry(), staleEntry()]);
  const r1 = run(s, sweep(0));
  const m1 = /backup: (\S+)/.exec(r1.out);
  check("first run names a backup", !!m1);
  // Make it stale again so a second run also writes.
  writeFileSync(s, JSON.stringify({ hooks: { PreToolUse: [bashEntry(), staleEntry()] } }, null, 2) + "\n");
  const r2 = run(s, sweep(0));
  const m2 = /backup: (\S+)/.exec(r2.out);
  check("second run names a backup", !!m2);
  check("the two runs use DIFFERENT backup paths", !!m1 && !!m2 && m1[1] !== m2[1]);
  check("the first run's backup still exists", !!m1 && existsSync(m1[1]));
}

// 2. Genuinely current: matcher present and already LOOSE.
{
  const s = settings([bashEntry(), looseEntry()]);
  const r = run(s, sweep(0));
  check("already-current exits 0", r.status === 0);
  check("already-current says so", /^already current/m.test(r.out));
}

// 3. Stale matcher, sweep green -> patched and kept.
{
  const s = settings([bashEntry(), staleEntry()]);
  const r = run(s, sweep(0));
  check("stale+green exits 0", r.status === 0);
  check("stale+green reports canary green", /canary green/.test(r.out));
  const after = JSON.parse(readFileSync(s, "utf8"));
  check("stale+green rewrote the matcher to LOOSE",
    after.hooks.PreToolUse.some((e) => e.matcher === LOOSE));
  check("stale+green left the unrelated Bash matcher alone",
    after.hooks.PreToolUse.some((e) => e.matcher === "Bash"));
}

// 4. Stale matcher, sweep RED -> rolled back, original restored, non-zero exit.
{
  const s = settings([bashEntry(), staleEntry()]);
  const before = readFileSync(s, "utf8");
  const r = run(s, sweep(3));
  check("stale+red exits non-zero", r.status !== 0);
  check("stale+red reports the sweep exit status", /sweep exit 3/.test(r.out));
  check("stale+red restored the original file", readFileSync(s, "utf8") === before);
}

// 5. A sweep that cannot be run at all must be a failure, not a pass.
{
  const s = settings([bashEntry(), staleEntry()]);
  const before = readFileSync(s, "utf8");
  const r = run(s, path.join(tmp, "no-such-sweep.mjs"));
  check("unrunnable sweep exits non-zero", r.status !== 0);
  check("unrunnable sweep restored the original file", readFileSync(s, "utf8") === before);
}

// 6. --dry-run touches nothing.
{
  const s = settings([bashEntry(), staleEntry()]);
  const before = readFileSync(s, "utf8");
  const r = run(s, sweep(0), ["--dry-run"]);
  check("dry-run exits 0", r.status === 0);
  check("dry-run did not modify the file", readFileSync(s, "utf8") === before);
}

// 7. The canary's own assertion: LOOSE must match every live ctx tool name. This is the
//    check the coverage sweep cannot make, because its ctx verdict comes from spawning
//    CTX_WRAP and ignores the static matcher entirely.
{
  const re = new RegExp(LOOSE);
  for (const t of [
    "mcp__plugin_context-mode_context-mode__ctx_execute",
    "mcp__plugin_context-mode_context-mode__ctx_execute_file",
    "mcp__plugin_context-mode_context-mode__ctx_batch_execute",
    "mcp__context-mode__ctx_execute",
    "mcp__someFuturePrefix__context-mode__ctx_batch_execute",
  ]) {
    check(`LOOSE matches ${t}`, re.test(t));
  }
  check("LOOSE does not match an unrelated tool", !re.test("Bash"));
  check("LOOSE does not match a non-exec ctx tool", !re.test("mcp__plugin_context-mode_context-mode__ctx_search"));
}

rmSync(tmp, { recursive: true, force: true });

if (failures.length) {
  for (const f of failures) console.log(`FAIL: ${f}`);
  process.exit(1);
}
console.log("ok — apply-wi2096-matcher assertions passed");
