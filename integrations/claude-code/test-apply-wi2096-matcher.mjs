#!/usr/bin/env node
// test-apply-wi2096-matcher.mjs — self-check for the WI-2096 matcher applier.
//
// The applier had NO test at all, which is how it came to report `already current` and
// exit 0 in two opposite states: every ctx matcher current, and NO ctx matcher present.
// The second is the "control gone dark" condition the applier exists to remediate, so the
// remediation tool green-ticked the vulnerability it was written to close.
//
// Everything is driven through HOOK_SETTINGS, HOOK_SWEEP and CTX_WRAP against temp files, so
// no real settings.json is read or written, no real sweep runs, and no real scanner is
// spawned.
//
// Run: node integrations/claude-code/test-apply-wi2096-matcher.mjs   (exit 0 = pass)

import {
  mkdtempSync, writeFileSync, readFileSync, copyFileSync, readdirSync,
  chmodSync, rmSync, existsSync, statSync,
} from "node:fs";
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

// A stub sweep whose exit status we control, so canary 2 can be driven both ways.
function sweep(exitCode) {
  const p = path.join(tmp, `sweep-${exitCode}.mjs`);
  writeFileSync(p, `console.log("stub sweep"); process.exit(${exitCode});\n`);
  return p;
}

// A stub wrapper for canary 3. The BASENAME must stay `dcg-ctx-wrap`, because the applier's
// routing check looks for it inside the hook command — a stub named anything else would fail
// an earlier gate and never reach the canary under test.
//
//   scanner -> denies with dcg's own text          (a live control)
//   adapter -> denies with a `dcg-ctx-wrap: ` reason (the control DARK, saying the right word)
//   allow   -> does not deny a known-dangerous fixture at all
function wrapper(kind) {
  const dir = mkdtempSync(path.join(tmp, `w-${kind}-`));
  const p = path.join(dir, "dcg-ctx-wrap");
  const bodies = {
    scanner: 'console.log(JSON.stringify({hookSpecificOutput:{hookEventName:"PreToolUse",' +
      'permissionDecision:"deny",permissionDecisionReason:"BLOCKED by dcg  Reason: git_reset_hard"}}));',
    adapter: 'console.log(JSON.stringify({hookSpecificOutput:{hookEventName:"PreToolUse",' +
      'permissionDecision:"deny",permissionDecisionReason:"dcg-ctx-wrap: scanner /nope could not be run"}}));',
    allow: 'console.log(JSON.stringify({continue:true}));',
  };
  writeFileSync(p, `#!/usr/bin/env node\n${bodies[kind]}\n`);
  chmodSync(p, 0o755);
  return p;
}

const SCANNER = wrapper("scanner");

function settings(entries) {
  const p = path.join(tmp, `settings-${Math.random().toString(36).slice(2)}.json`);
  writeFileSync(p, JSON.stringify({ hooks: { PreToolUse: entries } }, null, 2) + "\n");
  return p;
}

function run(settingsPath, sweepPath, extraArgs = [], wrapperPath = SCANNER) {
  const r = spawnSync(process.execPath, [APPLY, ...extraArgs], {
    encoding: "utf8",
    env: {
      ...process.env,
      HOOK_SETTINGS: settingsPath,
      HOOK_SWEEP: sweepPath,
      CTX_WRAP: wrapperPath,
    },
  });
  return { status: r.status, out: (r.stdout || "") + (r.stderr || "") };
}

// Every fixture now carries `type: "command"`, which the hook schema documents as REQUIRED and
// which every PreToolUse entry in the live canonical settings.json carries. EVERY fixture here
// used to omit it, which is exactly why the suite could not see that the applier accepted
// out-of-schema config as proof of a live control.
//
// The hook command is the STUB'S OWN ABSOLUTE PATH, not a literal `~/.local/bin/dcg-ctx-wrap`.
// The applier execs the binary the hook command names rather than the CTX_WRAP constant, so a
// fixture naming a path that does not exist is no longer a working control — which is the
// property these tests are here to hold.
const hookFor = (bin) => [{ type: "command", command: bin }];
const staleEntry = (bin = SCANNER) =>
  ({ matcher: "mcp__context-mode__ctx_execute", hooks: hookFor(bin) });
const looseEntry = (bin = SCANNER) => ({ matcher: LOOSE, hooks: hookFor(bin) });
const bashEntry = () => ({ matcher: "Bash", hooks: [{ type: "command", command: "dcg-wrap" }] });
const searchEntry = () => ({
  matcher: "mcp__plugin_context-mode_context-mode__ctx_search",
  hooks: [{ type: "command", command: "node audit-search.js" }],
});

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
  ["blank command", [{ type: "command", command: "   " }]],
  // The schema documents `type` as REQUIRED. An entry missing it, or carrying a type that
  // cannot exec a binary, is not a control this script may green-tick — and it cannot route
  // to the wrapper either. Every fixture in this file used to omit `type`, so nothing pinned it.
  ["hook with no `type`", [{ command: SCANNER }]],
  ["hook with a non-command `type`", [{ type: "http", command: SCANNER }]],
]) {
  const entry = { matcher: LOOSE };
  if (hooks !== undefined) entry.hooks = hooks;
  const s = settings([bashEntry(), entry]);
  const r = run(s, sweep(0));
  check(`hollow matcher (${label}) does not exit 0`, r.status !== 0);
  check(`hollow matcher (${label}) is not called already-current`, !/^already current/m.test(r.out));
  check(`hollow matcher (${label}) says it runs nothing`, /runs NOTHING/.test(r.out));
}

// 1b2. THE LAPTOP'S ACTUAL STATE: matcher at LOOSE, hooks present and runnable, but routed to
//      something other than the ctx wrapper. That reported "already current" while dcg was
//      nowhere on the path. A matcher string is not a control; the hook command is.
{
  const s = settings([bashEntry(), { matcher: LOOSE, hooks: [{ type: "command", command: "node ~/.claude/hooks/warden-bash-dispatcher.js" }] }]);
  const r = run(s, sweep(0));
  check("matcher routed away from the wrapper does not exit 0", r.status !== 0);
  check("matcher routed away from the wrapper is not called already-current",
    !/^already current/m.test(r.out));
  check("matcher routed away from the wrapper says so", /NONE execs/.test(r.out));
}
// ...and one that DOES route to the wrapper is accepted.
{
  const s = settings([bashEntry(), looseEntry()]);
  const r = run(s, sweep(0));
  check("matcher routed to the wrapper is accepted", r.status === 0);
}

// 1c. A run must not destroy the previous run's backup. A fixed backup name meant the second
//     invocation overwrote the only copy of the last known-good file, so the documented manual
//     rollback restored the already-broken state.
{
  const s = settings([bashEntry(), staleEntry()]);
  const r1 = run(s, sweep(0));
  const m1 = /Rollback: cp (\S+)/.exec(r1.out);
  check("first run names a backup", !!m1);
  // Make it stale again so a second run also writes.
  writeFileSync(s, JSON.stringify({ hooks: { PreToolUse: [bashEntry(), staleEntry()] } }, null, 2) + "\n");
  const r2 = run(s, sweep(0));
  const m2 = /Rollback: cp (\S+)/.exec(r2.out);
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

// 2b. "Already current" must still VERIFY. The branch used to exit 0 before any canary ran,
//     so on the ordinary steady-state host — the common case — the applier reported success
//     having verified nothing executable at all. A red sweep must now fail it.
{
  const s = settings([bashEntry(), looseEntry()]);
  const r = run(s, sweep(3));
  check("already-current + RED sweep exits non-zero", r.status !== 0);
  check("already-current + RED sweep is not reported as already-current",
    !/^already current/m.test(r.out));
}

// 2c. ...and the same branch must reject a control that is DARK. This is the case the
//      coverage sweep can no longer see: since the adapter went fail-closed, a missing or
//      broken dcg-wrap DENIES, so "something said DENY" is not evidence of a live control.
{
  const dark = wrapper("adapter");
  const s = settings([bashEntry(), looseEntry(dark)]);
  const r = run(s, sweep(0), [], dark);
  check("already-current + adapter-sourced DENY exits non-zero", r.status !== 0);
  check("already-current + adapter-sourced DENY says the control is dark",
    /came from the ADAPTER/.test(r.out));
}

// 2d. A wrapper that does not deny a known-dangerous fixture at all is not a control either.
{
  const permissive = wrapper("allow");
  const s = settings([bashEntry(), looseEntry(permissive)]);
  const r = run(s, sweep(0), [], permissive);
  check("a fixture that is not denied fails the canary", r.status !== 0);
  check("a fixture that is not denied says the surface is unscanned",
    /was NOT denied/.test(r.out));
}

// 3. Stale matcher, sweep green -> patched and published.
{
  const s = settings([bashEntry(), staleEntry()]);
  const r = run(s, sweep(0));
  check("stale+green exits 0", r.status === 0);
  check("stale+green reports the canaries green", /canaries green/.test(r.out));
  const after = JSON.parse(readFileSync(s, "utf8"));
  check("stale+green rewrote the matcher to LOOSE",
    after.hooks.PreToolUse.some((e) => e.matcher === LOOSE));
  check("stale+green left the unrelated Bash matcher alone",
    after.hooks.PreToolUse.some((e) => e.matcher === "Bash"));
}

// 3b. A NON-EXEC context-mode matcher must be left completely alone. A bare
//     /context-mode__ctx_/ pulled ctx_search, ctx_index and ctx_purge into the rewrite set and
//     replaced their matcher with the exec triple — breaking an unrelated guard two ways at
//     once: it stops matching its own tools, and its command starts firing on exec calls.
{
  const s = settings([bashEntry(), searchEntry(), staleEntry()]);
  const r = run(s, sweep(0));
  check("non-exec ctx matcher: run still succeeds", r.status === 0);
  const after = JSON.parse(readFileSync(s, "utf8"));
  const search = after.hooks.PreToolUse.find((e) => /ctx_search/.test(e.matcher || ""));
  check("a ctx_search matcher is left untouched",
    !!search && search.matcher === "mcp__plugin_context-mode_context-mode__ctx_search");
  check("a ctx_search hook command is left untouched",
    !!search && search.hooks[0].command === "node audit-search.js");
}

// 3c. THE CANARY MUST BIND TO THE BINARY THE HOOK ACTUALLY EXECS. Every command below
//     satisfied the old `command.includes("dcg-ctx-wrap")` routing test and published GREEN at
//     rc 0, because canary 3 spawned the CTX_WRAP constant instead of the hook command — a
//     working stub "proved" a control the harness would never reach. The .bak case is the
//     sharpest: the file is present AND executable, and only the NAME is wrong.
{
  const bak = path.join(path.dirname(SCANNER), "dcg-ctx-wrap.bak");
  copyFileSync(SCANNER, bak);
  chmodSync(bak, 0o755);
  for (const [label, command] of [
    ["a .bak copy that really runs", bak],
    ["an echo that prints the name", "echo dcg-ctx-wrap"],
    ["a comment mentioning the name", "true # dcg-ctx-wrap"],
    ["a bare PATH lookup", "dcg-ctx-wrap"],
  ]) {
    const s = settings([bashEntry(), { matcher: LOOSE, hooks: [{ type: "command", command }] }]);
    const before = readFileSync(s, "utf8");
    const r = run(s, sweep(0));
    check(`${label} is not accepted as routing to the wrapper`, r.status !== 0);
    check(`${label} is not called already-current`, !/^already current/m.test(r.out));
    check(`${label} leaves the settings file byte-identical`, readFileSync(s, "utf8") === before);
  }
}

// 3d. An absolute path with the RIGHT basename that does not exist passes the routing gate by
//     name and must then die at the canary — proving canary 3 execs the settings path rather
//     than the installed one. This published green before, with the live command still absent.
{
  const s = settings([bashEntry(), staleEntry("/opt/old/dcg-ctx-wrap")]);
  const before = readFileSync(s, "utf8");
  const r = run(s, sweep(0));
  check("a hook naming an absent wrapper fails", r.status !== 0);
  check("a hook naming an absent wrapper names the path it could not run",
    /\/opt\/old\/dcg-ctx-wrap/.test(r.out));
  check("a hook naming an absent wrapper publishes nothing",
    readFileSync(s, "utf8") === before);
}

// 3e. ANOTHER GUARD'S MATCHER IS NOT OURS TO REWRITE — the direction where a guard goes DARK.
//     The rewrite set used to be every exec-selecting ctx entry, so a MIXED matcher belonging
//     to a different hook was overwritten with the exec triple and stopped matching ctx_search
//     altogether, published under "all three canaries green". Test 3b pins the PURE ctx_search
//     case, which is exactly why the mixed one slipped through.
{
  const FOREIGN = "/usr/local/bin/other-guard";
  const mixed = {
    matcher: "context-mode__ctx_(execute|search)",
    hooks: [{ type: "command", command: FOREIGN }],
  };
  const s = settings([bashEntry(), mixed, staleEntry()]);
  const r = run(s, sweep(0));
  check("mixed foreign matcher: run still succeeds", r.status === 0);
  const after = JSON.parse(readFileSync(s, "utf8"));
  const foreign = after.hooks.PreToolUse.find(
    (e) => (e.hooks || []).some((h) => h.command === FOREIGN));
  check("a foreign guard's mixed matcher is left untouched",
    !!foreign && foreign.matcher === "context-mode__ctx_(execute|search)");
  check("a foreign guard still matches its own ctx_search after our publish",
    !!foreign && new RegExp(foreign.matcher)
      .test("mcp__plugin_context-mode_context-mode__ctx_search"));
  check("our own stale entry was still rewritten to LOOSE",
    after.hooks.PreToolUse.some(
      (e) => e.matcher === LOOSE && (e.hooks || []).some((h) => h.command === SCANNER)));
}

// 3f. ...and the over-firing direction: a NARROWER foreign exec entry must not be widened onto
//     tool names its hook never handled. Widened, `/usr/local/bin/file-policy-hook` would start
//     receiving ctx_batch_execute payloads, which carry no tool_input.command at all.
{
  const FOREIGN = "/usr/local/bin/file-policy-hook";
  const narrower = {
    matcher: "mcp__plugin_context-mode_context-mode__ctx_execute_file",
    hooks: [{ type: "command", command: FOREIGN }],
  };
  const s = settings([bashEntry(), narrower, staleEntry()]);
  const r = run(s, sweep(0));
  check("narrower foreign matcher: run still succeeds", r.status === 0);
  const after = JSON.parse(readFileSync(s, "utf8"));
  const foreign = after.hooks.PreToolUse.find(
    (e) => (e.hooks || []).some((h) => h.command === FOREIGN));
  check("a narrower foreign matcher is not widened to the exec triple",
    !!foreign && foreign.matcher === "mcp__plugin_context-mode_context-mode__ctx_execute_file");
  check("a narrower foreign matcher does not start selecting ctx_batch_execute",
    !!foreign && !new RegExp(foreign.matcher)
      .test("mcp__plugin_context-mode_context-mode__ctx_batch_execute"));
}

// 4. Stale matcher, canary RED -> the canonical file was NEVER MODIFIED.
//    Stronger than the old "restored from backup": publishing before verifying made the
//    change live fleet-wide inside the 15-minute renderer window, and the rollback was itself
//    a truncating in-place write on the failure path.
{
  const s = settings([bashEntry(), staleEntry()]);
  const before = readFileSync(s, "utf8");
  const r = run(s, sweep(3));
  check("stale+red exits non-zero", r.status !== 0);
  check("stale+red reports the sweep exit status", /sweep exit 3/.test(r.out));
  check("stale+red left the file untouched", readFileSync(s, "utf8") === before);
  check("stale+red says the file was not modified", /was NOT modified/.test(r.out));
  // GLOB the directory — do NOT build the path from the runner's pid. The applier runs as a
  // spawnSync CHILD with a different pid, so `${s}.tmp-wi2096-${process.pid}` named a path
  // that could never exist: the assertion passed unconditionally and could not fail. Measured
  // before the fix — with a real `.tmp-wi2096-999999` sitting in the directory, existsSync on
  // the runner-pid path still returned false. Four vendors filed this.
  const leaked = () => readdirSync(path.dirname(s))
    .filter((f) => f.startsWith(`${path.basename(s)}.tmp-wi2096-`));
  check("stale+red left no temp file behind", leaked().length === 0);

  // ...and the assertion must be CAPABLE of failing, which is the entire finding. Plant one
  // and confirm the glob sees it, or this check is the same vacuity wearing a new expression.
  const planted = `${s}.tmp-wi2096-999999`;
  writeFileSync(planted, "{}");
  const sawPlanted = leaked().length === 1;
  rmSync(planted, { force: true });
  check("the temp-leak assertion can actually fail", sawPlanted);
}

// 5. A sweep that cannot be run at all must be a failure, not a pass.
{
  const s = settings([bashEntry(), staleEntry()]);
  const before = readFileSync(s, "utf8");
  const r = run(s, path.join(tmp, "no-such-sweep.mjs"));
  check("unrunnable sweep exits non-zero", r.status !== 0);
  check("unrunnable sweep left the file untouched", readFileSync(s, "utf8") === before);
}

// 5b. The published file must keep the original's permissions. rename() replaces the inode,
//     so without an explicit chmod the temp file's umask-derived mode (0644 under a typical
//     022) is what goes live — and settings.json can carry an env block with tokens, so a
//     0600 file quietly becoming world-readable is a credential exposure.
if (process.platform !== "win32") {
  const s = settings([bashEntry(), staleEntry()]);
  chmodSync(s, 0o600);
  const r = run(s, sweep(0));
  check("restrictive-mode run exits 0", r.status === 0);
  check("published settings.json keeps mode 0600",
    (statSync(s).mode & 0o777) === 0o600);
  // A candidate surviving the SUCCESS path is the likelier exposure than one surviving an
  // abort, and it holds a complete copy of a 0600 document that can carry tokens.
  check("a successful publish leaves no candidate behind",
    readdirSync(path.dirname(s))
      .filter((f) => f.startsWith(`${path.basename(s)}.tmp-wi2096-`)).length === 0);
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
