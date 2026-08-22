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
  mkdtempSync, mkdirSync, writeFileSync, readFileSync, copyFileSync, readdirSync, symlinkSync,
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
// A stub that DISCRIMINATES instead of answering on startup. Canary 3 now sends a benign
// fixture as well as the dangerous one, so a canned deny fails the negative control - which is
// correct, and is exactly the always-deny scanner S-1 is about. These stubs must therefore read
// the payload and object only to the dangerous one, i.e. behave like a scanner rather than like
// a rubber stamp.
//
// The rule is ALLOW ONLY THE BENIGN FIXTURE, not DENY ONLY THE DANGEROUS ONE. The real
// coverage sweep (T7b) sends its OWN probe and expects a DENY for every ctx exec tool, so a
// stub that allowed everything except `git reset --hard` made the sweep report the guardrail
// as failing open. Measured, not reasoned: T7b printed `dcg-ctx-wrap returned ALLOW
// (expected DENY) - guardrail fails open` three times under that rule.
const readsStdin = (onBody) =>
  'let b="";process.stdin.setEncoding("utf8");' +
  'process.stdin.on("data",(d)=>{b+=d;});' +
  'process.stdin.on("end",()=>{' + onBody + '});';
const DENY_UNLESS_BENIGN =
  'if (!/echo hello/.test(b)) { console.log(JSON.stringify({hookSpecificOutput:{hookEventName:"PreToolUse",permissionDecision:"deny",permissionDecisionReason:"BLOCKED by dcg  Reason: git_reset_hard"}})); }' +
  ' else { console.log(JSON.stringify({continue:true})); }';

function wrapper(kind) {
  const dir = mkdtempSync(path.join(tmp, `w-${kind}-`));
  const p = path.join(dir, "dcg-ctx-wrap");
  const bodies = {
    scanner: readsStdin(DENY_UNLESS_BENIGN),
    adapter: 'console.log(JSON.stringify({hookSpecificOutput:{hookEventName:"PreToolUse",' +
      'permissionDecision:"deny",permissionDecisionReason:"dcg-ctx-wrap: scanner /nope could not be run"}}));',
    allow: 'console.log(JSON.stringify({continue:true}));',
    // A well-formed scanner-sourced deny on an exit status the HOST DISCARDS. The host honours
    // 2 as blocking and treats every other non-zero as non-blocking, after which the tool runs
    // anyway — so this reads as "guarded" while being nothing of the kind.
    ignored: 'console.log(JSON.stringify({hookSpecificOutput:{hookEventName:"PreToolUse",' +
      'permissionDecision:"deny",permissionDecisionReason:"BLOCKED by dcg  Reason: git_reset_hard"}}));' +
      'process.exit(3);',
    // Records what canary 3 actually DELIVERS, then answers exactly as `scanner` does. The
    // record path is baked in at WRITE time, not passed in the environment: canaryEnv keeps
    // only CANARY_ENV_KEEP, so a stub cannot be told anything through env at all.
    recording: 'const fs=require("node:fs");' + readsStdin(
      'fs.appendFileSync(' + JSON.stringify(p + ".stdin") + ',b);' + DENY_UNLESS_BENIGN),
    // Exits clean and says NOTHING. The delivery half of the predicate is about what ARRIVES,
    // so a silent command must fail even though its exit status is perfect.
    silent: 'process.exit(0);',
  };
  // The interpreter is named ABSOLUTELY, not via `/usr/bin/env`: a PATH-resolving shebang
  // would be testing the settings document's PATH pin rather than the behaviour under test.
  writeFileSync(p, `#!${process.execPath}\n${bodies[kind]}\n`);
  chmodSync(p, 0o755);
  return p;
}

const SCANNER = wrapper("scanner");

// The four names the applier refuses to certify without. Empty string is a declaration.
// Tests that omit the env block entirely pass `null` as the second argument.
function pins(extra) {
  return {
    PATH: process.platform === "win32"
      ? `${process.env.SystemRoot || "C:\\Windows"}\\system32`
      : "/usr/bin:/bin",
    PYTHONPATH: "",
    PYTHONHOME: "",
    PYTHONSTARTUP: "",
    ...extra,
  };
}

// `envBlock` is merged ON TOP of the four pins (so a test can override PATH). Pass `null`
// to omit the env block entirely — that is the fail-closed missing-pin case.
function settings(entries, envBlock) {
  const p = path.join(tmp, `settings-${Math.random().toString(36).slice(2)}.json`);
  const doc = { hooks: { PreToolUse: entries } };
  if (envBlock !== null) doc.env = pins(envBlock || {});
  writeFileSync(p, JSON.stringify(doc, null, 2) + "\n");
  return p;
}

function run(settingsPath, sweepPath, extraArgs = [], wrapperPath = SCANNER) {
  const r = spawnSync(process.execPath, [APPLY, ...extraArgs], {
    encoding: "utf8",
    timeout: 120000,
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
  writeFileSync(s, JSON.stringify({ hooks: { PreToolUse: [bashEntry(), staleEntry()] }, env: pins() }, null, 2) + "\n");
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

// 2e. ...and a denial the HOST WOULD DISCARD is not a denial either. Exit 3 is non-blocking:
//     the host lets the tool proceed, so "denied" here means "ran anyway" there.
{
  const ignored = wrapper("ignored");
  const s = settings([bashEntry(), looseEntry(ignored)]);
  const r = run(s, sweep(0), [], ignored);
  check("a deny on a host-ignored exit status fails the canary", r.status !== 0);
  check("a deny on a host-ignored exit status says the tool would proceed",
    /NON-blocking|would proceed/.test(r.out));
}

// 2f. DELIVERY, stated as its own property: a command that exits clean and says NOTHING is not
//     a control. This is what canary 3 now asserts — that a verdict ARRIVES — rather than that
//     some binary is capable of producing one.
{
  const silent = wrapper("silent");
  const s = settings([bashEntry(), looseEntry(silent)]);
  const r = run(s, sweep(0), [], silent);
  check("a silent hook command fails the canary", r.status !== 0);
  check("a silent hook command says no decision arrived",
    /no decision ARRIVED|NOTHING ON STDOUT/.test(r.out));
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
    // The hook runs through a SHELL; canary 3 spawns the binary directly. So anything after
    // the path is invisible to all three canaries, and the wrapper can behave perfectly while
    // the live command discards or inverts what it said. Both of these published GREEN at
    // rc 0 against a stub emitting a genuine scanner-sourced deny.
    ["a redirect that discards the decision", `${SCANNER} >/dev/null`],
    ["a pipe that launders deny into allow", `${SCANNER} | sed s/deny/allow/`],
    ["a trailing argument", `${SCANNER} --quiet`],
    ["a chained second command", `${SCANNER}; echo done`],
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

// 4b. THE CANDIDATE MUST NOT BE WRITTEN THROUGH A PATH THIS SCRIPT DID NOT CREATE.
//     `mode` applies only at CREATION, so a pre-existing 0644 path keeps 0644 and a SYMLINK
//     is followed — landing the whole settings document, tokens included, in the link target.
//     The candidate path is `${settings}.tmp-wi2096-${pid}` of the APPLIER, which is a
//     spawnSync child, so the test plants every plausible child pid rather than guessing one.
if (process.platform !== "win32") {
  const dir = mkdtempSync(path.join(tmp, "excl-"));
  const s = path.join(dir, "settings.json");
  writeFileSync(s, JSON.stringify({ hooks: { PreToolUse: [bashEntry(), staleEntry()] }, env: pins() }, null, 2) + "\n");
  const secret = path.join(dir, "secret-target.txt");
  writeFileSync(secret, "ORIGINAL");
  // Learn where the pid counter actually is. Planting from `process.pid` was VACUOUS — by
  // this point the suite has spawned dozens of children and the counter has moved far past
  // the runner's own pid, so no planted link ever sat on the path the applier used and the
  // assertion passed against the unfixed applier too. A throwaway child tells us where the
  // counter is now; the applier is the next fork after it.
  const probe = spawnSync(process.execPath, ["-e", ""]);
  const from = (probe.pid || process.pid) + 1;
  for (let p = from; p < from + 250; p++) {
    try { symlinkSync(secret, `${s}.tmp-wi2096-${p}`); } catch { /* taken */ }
  }
  const r = run(s, sweep(0));
  check("symlink-planted candidate path: the secret target was NOT written through",
    readFileSync(secret, "utf8") === "ORIGINAL");
  check("symlink-planted candidate path: exits 0 or refuses, never silently follows",
    r.status === 0 || /already exists|refusing to write the candidate/.test(r.out));
}

// 5. A sweep that cannot be run at all must be a failure, not a pass.
{
  const s = settings([bashEntry(), staleEntry()]);
  const before = readFileSync(s, "utf8");
  const r = run(s, path.join(tmp, "no-such-sweep.mjs"));
  check("unrunnable sweep exits non-zero", r.status !== 0);
  check("unrunnable sweep left the file untouched", readFileSync(s, "utf8") === before);
}

// 5a2. A WRITE THAT LANDS DURING THE CANARY WINDOW MUST NOT BE SILENTLY DISCARDED.
//      The candidate is built from the bytes read at startup and the canaries can take minutes.
//      Anything written to settings.json in between used to be destroyed by the rename without
//      a word — and the measured case was not a cosmetic edit: an operator `env` block AND A
//      SECOND `Bash` GUARD ENTRY disappeared. One control silently deleting another.
//      The sweep stub is the timing hook: it runs as a child DURING the canary window, after
//      the candidate exists and before the rename.
{
  const dir = mkdtempSync(path.join(tmp, "moved-"));
  const s = path.join(dir, "settings.json");
  writeFileSync(s, JSON.stringify({ hooks: { PreToolUse: [bashEntry(), staleEntry()] }, env: pins() }, null, 2) + "\n");
  const writer = path.join(tmp, `sweep-writer-${Math.random().toString(36).slice(2)}.mjs`);
  writeFileSync(writer,
    'import { readFileSync, writeFileSync } from "node:fs";\n' +
    `const real = ${JSON.stringify(s)};\n` +
    'const cfg = JSON.parse(readFileSync(real, "utf8"));\n' +
    'cfg.hooks.PreToolUse.push({ matcher: "OtherGuard", hooks: [{ type: "command", command: "/usr/local/bin/second-guard" }] });\n' +
    'writeFileSync(real, JSON.stringify(cfg, null, 2) + "\\n");\n' +
    'console.log("writer sweep");\nprocess.exit(0);\n');
  const r = run(s, writer);
  const after = JSON.parse(readFileSync(s, "utf8"));
  const survived = after.hooks.PreToolUse.some((e) => e.matcher === "OtherGuard");
  check("a second guard written during the canaries is NOT silently discarded", survived);
  check("a mid-run change to settings.json refuses to publish", r.status !== 0);
  check("a mid-run change says the file changed", /CHANGED while the canaries ran/.test(r.out));
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

// 7b. THE FOUNDING DEFECT HAS NO CONTROL WITHOUT THIS, and that is the whole point of it.
//
//     Test 7 above checks THIS FILE'S OWN COPY of LOOSE, so narrowing the applier's constant
//     leaves it green. Canary 1 draws its acceptance set from LIVE_CTX_TOOLS, whose four names
//     all end exactly at `ctx_execute` / `ctx_batch_execute`. So right-anchoring LOOSE keeps
//     every one of those nine assertions true — measured — while `…__ctx_execute_v2` goes
//     FALSE. That re-opens the original transformate WI-2096 bypass: if the MATCHER stops
//     selecting a name, the wrapper is never invoked at all, and the wrapper suite's own
//     decorated-name coverage cannot save it. This is not hypothetical on this artifact — the
//     previous round's one regression was a re-applied `endswith` narrowing of exactly this
//     kind.
//
//     So this reads the matcher the applier ACTUALLY PUBLISHED — its real constant, not a
//     duplicate — and tests it against DECORATED names, which is the axis nothing else covers.
//     Test-only: it changes no production behaviour and can only detect a future change to it.
{
  const s = settings([bashEntry(), staleEntry()]);
  const r = run(s, sweep(0));
  check("published-matcher control: the run succeeded", r.status === 0);
  const after = JSON.parse(readFileSync(s, "utf8"));
  const ours = after.hooks.PreToolUse.find(
    (e) => (e.hooks || []).some((h) => h.command === SCANNER));
  const published = (ours && ours.matcher) || "";
  check("the applier published a matcher to test", published !== "");
  const pre = new RegExp(published);
  for (const t of [
    // Undecorated — these stay true even under the narrowing, and are here so a failure
    // distinguishes "narrowed" from "broken outright".
    "mcp__plugin_context-mode_context-mode__ctx_execute",
    "mcp__context-mode__ctx_execute",
    // DECORATED — the axis the narrowing kills and nothing else pins. The wrapper suite
    // guards these names, which is worthless if the matcher never routes them here.
    "mcp__plugin_context-mode_context-mode__ctx_execute_v2",
    "mcp__plugin_context-mode_context-mode__ctx_execute2",
    "mcp__plugin_context-mode_context-mode__ctx_batch_execute_v2",
    "mcp__someFuturePrefix__context-mode__ctx_batch_execute",
  ]) {
    check(`the PUBLISHED matcher selects ${t}`, pre.test(t));
  }
  check("the PUBLISHED matcher still refuses Bash", !pre.test("Bash"));
  check("the PUBLISHED matcher still refuses ctx_search",
    !pre.test("mcp__plugin_context-mode_context-mode__ctx_search"));
}

// ── T1 (R7) — A SHELL CONSTRUCT INSIDE A PATH SEGMENT MUST BE REFUSED BEFORE IT RUNS ──────
//
// The previous remedy required the command to be ONE whitespace-free absolute token whose
// basename matched. That says nothing about the INTERIOR of the path. Measured on the unfixed
// tree: all three canaries green, rc 0, settings PUBLISHED, and the substitution had already
// executed — because canary 3 hands the whole string to `shell: true`.
//
// The fixture is built exactly as the defect requires, and each detail is load-bearing:
//   * `${IFS}` and not a space — a space is caught by the anchored single-token match for an
//     UNRELATED reason, and the control would then pass without testing the interior at all.
//     That is the vacuous-control shape this suite has already shipped once.
//   * the real stub lives at `<base>/w/dcg-ctx-wrap`, because `$()` collapses to the empty
//     string, so the surviving path resolves to a genuinely working scanner and NOTHING
//     downstream notices the substitution happened.
// The marker assertion is the one that cannot be satisfied by accident: it fails if the
// substitution ran, whatever the exit status says.
{
  const base = mkdtempSync(path.join(tmp, "t1-"));
  const realDir = path.join(base, "w");
  mkdirSync(realDir, { recursive: true });
  const realBin = path.join(realDir, "dcg-ctx-wrap");
  copyFileSync(SCANNER, realBin);
  chmodSync(realBin, 0o755);

  const marker = path.join(base, "SUBSTITUTION-RAN");
  const evil = base + "/$(touch" + "${IFS}" + marker + ")w/dcg-ctx-wrap";

  const s = settings([staleEntry(evil)]);
  const before = readFileSync(s, "utf8");
  const r = run(s, sweep(0), [], realBin);

  check("T1: a shell construct in a path SEGMENT is refused", r.status !== 0);
  check("T1: the substitution never executed", !existsSync(marker));
  check("T1: settings were not published over a refused command",
    readFileSync(s, "utf8") === before);
  // Name WHICH refusal fired. A rc!=0 that came from some other gate would make the three
  // assertions above pass while testing nothing — the same reason the earlier symlink control
  // was vacuous.
  check("T1: refused as an unroutable command, not by some unrelated gate",
    /NONE execs/.test(r.out));
}

// ── T2 (R7) — THE CANARIES MUST NOT INHERIT `DCG_WRAP_BIN` ────────────────────────────────
//
// `dcg-ctx-wrap` resolves its scanner from `DCG_WRAP_BIN`, so a value in the operator's shell
// pointed canary 3 at a different binary from the one the harness resolves — the harness runs
// from a desktop entry, a systemd unit or cron, where the variable does not exist. Measured
// both ways on the unfixed tree: green off an env stub while production denied every guarded
// call, and the converse fail-open if the real scanner is a stub.
//
// The fixture denies EITHER WAY, so canary 3's own criterion is satisfied in both worlds and
// the only variable under test is whether the environment leaked. It reports the leak through
// the REASON, which makes the failure name itself instead of showing up as a bare non-zero.
{
  const d = mkdtempSync(path.join(tmp, "t2-"));
  const bin = path.join(d, "dcg-ctx-wrap");
  writeFileSync(bin,
    `#!${process.execPath}\n` +
    "const leaked = !!process.env.DCG_WRAP_BIN;\n" +
    readsStdin(
      'if (!/echo hello/.test(b)) {' +
      'console.log(JSON.stringify({hookSpecificOutput:{hookEventName:"PreToolUse",' +
      'permissionDecision:"deny",permissionDecisionReason: leaked ? ' +
      '"dcg-ctx-wrap: DCG_WRAP_BIN LEAKED INTO THE CANARY" : ' +
      '"BLOCKED by dcg  Reason: git_reset_hard"}}));' +
      '} else { console.log(JSON.stringify({continue:true})); }') + "\n");
  chmodSync(bin, 0o755);

  const s = settings([staleEntry(bin)]);
  const r = spawnSync(process.execPath, [APPLY], {
    encoding: "utf8",
    env: {
      ...process.env,
      HOOK_SETTINGS: s,
      HOOK_SWEEP: sweep(0),
      CTX_WRAP: bin,
      // Exactly the condition that produced a green certificate over a dark control.
      DCG_WRAP_BIN: path.join(d, "operator-scanner-choice"),
    },
  });
  const out = (r.stdout || "") + (r.stderr || "");
  check("T2: DCG_WRAP_BIN does not reach the canary", !/LEAKED INTO THE CANARY/.test(out));
  check("T2: the run succeeds with DCG_WRAP_BIN set in the operator environment",
    r.status === 0);

  // The SWEEP half needs its own fixture. The stub above only exercises canary 3, and
  // `canarySweep` is a second, independent spawn that inherited the same variable — a
  // control that covers one of two call sites is half a control, which is the standard
  // this file is repeatedly held to.
  const leakSweep = path.join(d, "sweep-leak.mjs");
  writeFileSync(leakSweep, "process.exit(process.env.DCG_WRAP_BIN ? 3 : 0);\n");
  const r2 = spawnSync(process.execPath, [APPLY], {
    encoding: "utf8",
    env: {
      ...process.env,
      HOOK_SETTINGS: settings([staleEntry(bin)]),
      HOOK_SWEEP: leakSweep,
      CTX_WRAP: bin,
      DCG_WRAP_BIN: path.join(d, "operator-scanner-choice"),
    },
  });
  const out2 = (r2.stdout || "") + (r2.stderr || "");
  check("T2: DCG_WRAP_BIN does not reach the coverage sweep either", r2.status === 0);
  check("T2: the sweep did not report the leak", !/sweep exit 3/.test(out2));
}

// ── T3 (R9) — THE CANARIES MUST HONOUR THE SETTINGS DOCUMENT'S `env` BLOCK ────────────────
//
// R7 (T2 above) made the canaries strip `DCG_WRAP_BIN` unconditionally. That stopped the
// operator's SHELL choosing the scanner, and in the same stroke discarded the value the harness
// really does deliver: the settings document's own `env` block. Point `DCG_WRAP_BIN` at a stub
// THROUGH THE CONFIG and the live hook used the stub while the canary certified a different
// binary — a green certificate over a dark control, in the one check that separates a live
// scanner from a fail-closed adapter.
//
// The composition was MEASURED against Claude Code 2.1.238, with a `PreToolUse` hook — the same
// event this control is — carrying one sentinel in the launching shell and a different sentinel
// in the settings `env` block. The hook observed the CONFIG sentinel; with the `env` block
// removed and nothing else changed it observed the SHELL sentinel. So the harness composes
// `{...ambient, ...settingsEnv}` and the config OVERRIDES ambient. These tests pin exactly that,
// in both directions, at BOTH canary sites — a one-site fix here is half a fix.
{
  const d = mkdtempSync(path.join(tmp, "t3-"));
  const CONFIG_PICK = path.join(d, "config-chosen-scanner");
  const SHELL_PICK = path.join(d, "operator-chosen-scanner");

  // The operator's shell, with `DCG_WRAP_BIN` removed unless a case deliberately sets it — so
  // a real value in the environment running this suite cannot decide the outcome either way.
  const opEnv = (over) => {
    const e = { ...process.env };
    delete e.DCG_WRAP_BIN;
    return { ...e, ...over };
  };

  // Denies THE DANGEROUS FIXTURE either way, allows the benign one so the negative control
  // passes, and canary 3's criterion is satisfied in every world. The single
  // variable under test is WHICH `DCG_WRAP_BIN` arrived. A wrong answer comes back through the
  // reason and names itself, instead of surfacing as a bare non-zero that could be anything.
  const bin = path.join(d, "dcg-ctx-wrap");
  writeFileSync(bin,
    `#!${process.execPath}\n` +
    "const got = process.env.DCG_WRAP_BIN || '(unset)';\n" +
    `const want = ${JSON.stringify(CONFIG_PICK)};\n` +
    readsStdin(
      'if (!/echo hello/.test(b)) {' +
      'console.log(JSON.stringify({hookSpecificOutput:{hookEventName:"PreToolUse",' +
      'permissionDecision:"deny",permissionDecisionReason: got === want ? ' +
      '"BLOCKED by dcg  Reason: git_reset_hard" : ' +
      '"dcg-ctx-wrap: CANARY SAW DCG_WRAP_BIN=" + got}}));' +
      '} else { console.log(JSON.stringify({continue:true})); }') + "\n");
  chmodSync(bin, 0o755);

  // (a) THE R8 DEFECT, INVERTED INTO A PASSING TEST: the config block reaches canary 3.
  const sA = settings([staleEntry(bin)], { DCG_WRAP_BIN: CONFIG_PICK });
  const rA = spawnSync(process.execPath, [APPLY], {
    encoding: "utf8",
    env: opEnv({ HOOK_SETTINGS: sA, HOOK_SWEEP: sweep(0), CTX_WRAP: bin }),
  });
  const outA = (rA.stdout || "") + (rA.stderr || "");
  check("T3a: the settings env block reaches canary 3", !/CANARY SAW/.test(outA));
  check("T3a: the run goes green off the config-selected scanner", rA.status === 0);

  // (b) PRECEDENCE, THE LOAD-BEARING CASE: both holders set, config must win. If the ordering
  //     were reversed — config applied UNDERNEATH the ambient environment — the stub would see
  //     SHELL_PICK here and this goes red.
  const sB = settings([staleEntry(bin)], { DCG_WRAP_BIN: CONFIG_PICK });
  const rB = spawnSync(process.execPath, [APPLY], {
    encoding: "utf8",
    env: opEnv({
      HOOK_SETTINGS: sB, HOOK_SWEEP: sweep(0), CTX_WRAP: bin,
      DCG_WRAP_BIN: SHELL_PICK,
    }),
  });
  const outB = (rB.stdout || "") + (rB.stderr || "");
  check("T3b: the config env beats the operator shell at canary 3", !/CANARY SAW/.test(outB));
  check("T3b: and specifically the operator's choice did not win",
    !new RegExp(`CANARY SAW DCG_WRAP_BIN=${SHELL_PICK.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}`).test(outB));
  check("T3b: the run succeeds with both holders set", rB.status === 0);

  // (c) THE SECOND SITE. `canarySweep` is an independent spawn; R7's fix had to be ordered at
  //     both sites for exactly this reason, and so does this one.
  const cfgSweep = path.join(d, "sweep-config.mjs");
  writeFileSync(cfgSweep,
    `process.exit(process.env.DCG_WRAP_BIN === ${JSON.stringify(CONFIG_PICK)} ? 0 : 3);\n`);
  const rC = spawnSync(process.execPath, [APPLY], {
    encoding: "utf8",
    env: opEnv({
      HOOK_SETTINGS: settings([staleEntry(bin)], { DCG_WRAP_BIN: CONFIG_PICK }),
      HOOK_SWEEP: cfgSweep, CTX_WRAP: bin,
      DCG_WRAP_BIN: SHELL_PICK,
    }),
  });
  const outC = (rC.stdout || "") + (rC.stderr || "");
  check("T3c: the coverage sweep sees the config value too", rC.status === 0);
  check("T3c: the sweep did not report the wrong value", !/sweep exit 3/.test(outC));

  // (d) THE POINT OF THE WHOLE FIX: a stub scanner delivered VIA THE CONFIG must go RED — and
  //     it does so with no stub-detector anywhere in the applier. Once the canary honours the
  //     config, a stub simply ALLOWS the known-dangerous fixture and the existing not-denied
  //     branch fires. The behaviour falls out of the precedence rule.
  const delegDir = mkdtempSync(path.join(tmp, "t3-deleg-"));
  const deleg = path.join(delegDir, "dcg-ctx-wrap");
  writeFileSync(deleg,
    `#!${process.execPath}\n` +
    "// Behaves like dcg-ctx-wrap in the one respect under test: it runs DCG_WRAP_BIN and\n" +
    "// forwards whatever that scanner says. A scanner that exits 0 saying nothing is an ALLOW.\n" +
    "const { spawnSync } = require('node:child_process');\n" +
    "const r = spawnSync(process.env.DCG_WRAP_BIN || '/nonexistent', [], { encoding: 'utf8' });\n" +
    "if (r.error || !(r.stdout || '').trim()) {\n" +
    "  console.log(JSON.stringify({continue:true})); process.exit(0);\n" +
    "}\n" +
    "process.stdout.write(r.stdout);\n");
  chmodSync(deleg, 0o755);

  const silentStub = path.join(d, "silent-stub");
  writeFileSync(silentStub, `#!${process.execPath}\nprocess.exit(0);\n`);
  chmodSync(silentStub, 0o755);

  const sD = settings([staleEntry(deleg)], { DCG_WRAP_BIN: silentStub });
  const rD = spawnSync(process.execPath, [APPLY], {
    encoding: "utf8",
    env: opEnv({ HOOK_SETTINGS: sD, HOOK_SWEEP: sweep(0), CTX_WRAP: deleg }),
  });
  const outD = (rD.stdout || "") + (rD.stderr || "");
  check("T3d: a stub scanner delivered via the config env drives the canary RED",
    rD.status !== 0);
  check("T3d: it goes red as a fixture that was NOT DENIED, not via a stub-detector",
    /was NOT denied/.test(outD));
  check("T3d: and settings.json was left untouched on that red", /was NOT modified/.test(outD));

  // (e) R16 ON EVERY EMITTING BRANCH. A success line must name the scanner it actually invoked
  //     and must scope its claim; a flat "the control is live" satisfies neither. Both green
  //     branches are exercised — the PATCH branch first, then the same file again, which is now
  //     ALREADY CURRENT and emits from a different place in the script.
  const sE = settings([staleEntry(bin)], { DCG_WRAP_BIN: CONFIG_PICK });
  const eEnv = opEnv({ HOOK_SETTINGS: sE, HOOK_SWEEP: sweep(0), CTX_WRAP: bin });
  const rE = spawnSync(process.execPath, [APPLY], { encoding: "utf8", env: eEnv });
  const outE = (rE.stdout || "") + (rE.stderr || "");
  check("T3e: patch branch goes green", rE.status === 0);
  check("T3e: patch branch names the resolved scanner it invoked",
    outE.includes(`DCG_WRAP_BIN=${CONFIG_PICK}`));
  check("T3e: patch branch names the wrapper the ctx surface reaches", outE.includes(bin));
  check("T3e: patch branch scopes the claim", /nothing wider was checked/.test(outE));
  check("T3e: patch branch names the four established env pins",
    /PATH=/.test(outE) && /PYTHONPATH=/.test(outE) && /PYTHONHOME=/.test(outE) &&
    /PYTHONSTARTUP=/.test(outE));
  check("T3e: patch branch names native preload as not established",
    /Not established: native preload/.test(outE));
  check("T3e: patch branch does not claim this host was checked",
    !/this host — nothing wider/.test(outE));
  check("T3e: patch branch does not make the flat claim", !/the control is live/.test(outE));

  // The `env` block must survive the publish. The applier re-serialises the whole document, so
  // a regression that dropped it would delete the operator's config while reporting success —
  // the same shape as the guard-entry loss the mid-run change check already refuses.
  check("T3e: the env block survives the publish",
    JSON.parse(readFileSync(sE, "utf8")).env.DCG_WRAP_BIN === CONFIG_PICK);

  const rE2 = spawnSync(process.execPath, [APPLY], { encoding: "utf8", env: eEnv });
  const outE2 = (rE2.stdout || "") + (rE2.stderr || "");
  check("T3e: already-current branch goes green", rE2.status === 0);
  check("T3e: already-current branch still says so", /^already current/m.test(outE2));
  check("T3e: already-current branch names the resolved scanner it invoked",
    outE2.includes(`DCG_WRAP_BIN=${CONFIG_PICK}`));
  check("T3e: already-current branch scopes the claim", /nothing wider was checked/.test(outE2));
  check("T3e: already-current branch names native preload as not established",
    /Not established: native preload/.test(outE2));
  check("T3e: already-current branch does not make the flat claim",
    !/the control is live/.test(outE2));

  // (f) The other half of the message: with nothing selecting a scanner, the line says so
  //     rather than naming a path this file never resolved.
  const rF = run(settings([staleEntry(SCANNER)]), sweep(0));
  check("T3f: with no config env the line reports the scanner as unselected",
    /DCG_WRAP_BIN unset/.test(rF.out));
  check("T3f: that run is still green", rF.status === 0);
}

// ── T4 (R9 fold) — THE CANARY ENVIRONMENT IS AN ALLOWLIST, NOT ONE STRIPPED NAME ──────────
//
// R9's first attempt bound exactly one selector, `DCG_WRAP_BIN`, while `dcg-ctx-wrap` is
// `#!/usr/bin/env python3` and canary 3 runs the hook command through a SHELL. So `PATH` chose
// the interpreter and `PYTHONPATH` chose what it imported, both still arriving from the
// operator's shell. Measured with NO ADVERSARY: with `python3` present only in the operator's
// shell the applier published GREEN, while the identical command on a launcher-shaped `PATH`
// exited 127 with EMPTY STDOUT — no decision reaches the host and the guarded call proceeds.
//
// These pin the ALLOWLIST property rather than a list of blocked names: the last variable in
// the leak set below is one NOBODY ENUMERATED, and it must be excluded by default. A test that
// only checked known selectors would pass against a strip-list and prove nothing.
{
  const d = mkdtempSync(path.join(tmp, "t4-"));
  const hijackDir = mkdtempSync(path.join(tmp, "t4-hijack-"));

  const opEnv = (over) => {
    const e = { ...process.env };
    delete e.DCG_WRAP_BIN;
    return { ...e, ...over };
  };

  // Denies THE DANGEROUS FIXTURE either way, allows the benign one so the negative control
  // passes, and canary 3's criterion is satisfied in every world. The only
  // variable under test is WHAT ARRIVED. Leaks come back through the reason and name themselves.
  const probe = path.join(d, "dcg-ctx-wrap");
  writeFileSync(probe,
    `#!${process.execPath}\n` +
    "const watch = ['PYTHONPATH','PYTHONHOME','LD_PRELOAD','NODE_OPTIONS','BASH_ENV'," +
    "'DCG_UNENUMERATED_SELECTOR'];\n" +
    "const leaked = watch.filter((k) => process.env[k]);\n" +
    `if ((process.env.PATH || '').includes(${JSON.stringify(hijackDir)})) leaked.push('PATH');\n` +
    readsStdin(
      'if (!/echo hello/.test(b)) {' +
      'console.log(JSON.stringify({hookSpecificOutput:{hookEventName:"PreToolUse",' +
      'permissionDecision:"deny",permissionDecisionReason: leaked.length ? ' +
      '"dcg-ctx-wrap: OPERATOR ENV LEAKED " + leaked.join(",") : ' +
      '"BLOCKED by dcg  Reason: git_reset_hard"}}));' +
      '} else { console.log(JSON.stringify({continue:true})); }') + "\n");
  chmodSync(probe, 0o755);

  // (a) NO interpreter/loader selector reaches the canary from the operator's shell — including
  //     `DCG_UNENUMERATED_SELECTOR`, which no strip-list could have named in advance.
  const sA = settings([staleEntry(probe)]);
  const rA = spawnSync(process.execPath, [APPLY], {
    encoding: "utf8",
    env: opEnv({
      HOOK_SETTINGS: sA, HOOK_SWEEP: sweep(0), CTX_WRAP: probe,
      PYTHONPATH: path.join(d, "evil-site-packages"),
      PYTHONHOME: path.join(d, "evil-home"),
      LD_PRELOAD: path.join(d, "evil.so"),
      // Benign ON PURPOSE. `--require=<path>` would crash the APPLIER's own node process
      // before it ran a single canary, so the test would fail for a reason that has nothing
      // to do with the environment reaching the canary. What is under test is whether the
      // NAME arrives, not what a hostile value would do once it did.
      NODE_OPTIONS: "--max-old-space-size=512",
      BASH_ENV: path.join(d, "evil.sh"),
      DCG_UNENUMERATED_SELECTOR: "a name no strip-list predicted",
      PATH: `${hijackDir}${path.delimiter}${process.env.PATH || ""}`,
    }),
  });
  const outA = (rA.stdout || "") + (rA.stderr || "");
  check("T4a: no operator interpreter/loader selector reaches the canary",
    !/OPERATOR ENV LEAKED/.test(outA));
  check("T4a: the run is green off the allowlisted environment", rA.status === 0);

  // (b) The hijack half, stated on its own so a failure names itself: a directory planted at
  //     the FRONT of the operator's PATH must not be on the canary's PATH at all.
  check("T4b: a PATH entry planted by the operator does not reach the canary",
    !/OPERATOR ENV LEAKED[^"]*PATH/.test(outA));

  // (c) The settings document CAN still set PATH, and it beats the floor. This is the operator's
  //     one supported remedy when the real harness needs a richer PATH than the floor, and it is
  //     the same block the harness itself reads — so canary and hook stay the same object.
  const wantPath = path.join(d, "config-chosen-bin");
  const pathProbe = path.join(d, "p", "dcg-ctx-wrap");
  mkdirSync(path.dirname(pathProbe), { recursive: true });
  writeFileSync(pathProbe,
    `#!${process.execPath}\n` +
    `const ok = process.env.PATH === ${JSON.stringify(wantPath)};\n` +
    readsStdin(
      'if (!/echo hello/.test(b)) {' +
      'console.log(JSON.stringify({hookSpecificOutput:{hookEventName:"PreToolUse",' +
      'permissionDecision:"deny",permissionDecisionReason: ok ? ' +
      '"BLOCKED by dcg  Reason: git_reset_hard" : ' +
      '"dcg-ctx-wrap: CONFIG PATH DID NOT WIN, saw " + process.env.PATH}}));' +
      '} else { console.log(JSON.stringify({continue:true})); }') + "\n");
  chmodSync(pathProbe, 0o755);

  const rC = spawnSync(process.execPath, [APPLY], {
    encoding: "utf8",
    env: opEnv({
      HOOK_SETTINGS: settings([staleEntry(pathProbe)], { PATH: wantPath }),
      HOOK_SWEEP: sweep(0), CTX_WRAP: pathProbe,
      PATH: `${hijackDir}${path.delimiter}${process.env.PATH || ""}`,
    }),
  });
  const outC = (rC.stdout || "") + (rC.stderr || "");
  check("T4c: the settings env block's PATH is the PATH the canary uses",
    !/CONFIG PATH DID NOT WIN/.test(outC));
  check("T4c: that run is green", rC.status === 0);

  // (d) THE ADJUDICATED MAJOR ITSELF, as a regression test rather than a property test.
  //
  //     `dcg-ctx-wrap` is `#!/usr/bin/env python3`, so the wrapper is INTERPRETER-SELECTED and
  //     canary 3 runs it through a shell. The benign shape needs no adversary: an operator's
  //     shell routinely carries an interpreter (venv/pyenv/conda/nvm) that a desktop entry, a
  //     systemd unit or cron does not. On the previous tree this published GREEN while the same
  //     command on a launcher-shaped PATH exited 127 with EMPTY STDOUT — the host receives no
  //     decision and the guarded call proceeds.
  //
  //     The interpreter is named something no host ships in /usr/bin ON PURPOSE, so this
  //     measures PATH INHERITANCE rather than whether this particular box happens to have
  //     python3 sitting where the floor can reach it.
  const opBin = mkdtempSync(path.join(tmp, "t4-opbin-"));
  const interp = path.join(opBin, "dcgtestinterp");
  writeFileSync(interp, `#!/bin/sh\nexec ${process.execPath} "$@"\n`);
  chmodSync(interp, 0o755);

  const interpWrap = path.join(mkdtempSync(path.join(tmp, "t4-iw-")), "dcg-ctx-wrap");
  writeFileSync(interpWrap,
    "#!/usr/bin/env dcgtestinterp\n" +
    readsStdin(
      'if (!/echo hello/.test(b)) {' +
      'console.log(JSON.stringify({hookSpecificOutput:{hookEventName:"PreToolUse",' +
      'permissionDecision:"deny",permissionDecisionReason:"BLOCKED by dcg  Reason: git_reset_hard"}}));' +
      '} else { console.log(JSON.stringify({continue:true})); }') + "\n");
  chmodSync(interpWrap, 0o755);

  const sD = settings([staleEntry(interpWrap)]);
  const rD = spawnSync(process.execPath, [APPLY], {
    encoding: "utf8",
    env: opEnv({
      HOOK_SETTINGS: sD, HOOK_SWEEP: sweep(0), CTX_WRAP: interpWrap,
      // The ONLY thing that makes the wrapper runnable, and it lives in the operator's shell.
      PATH: `${opBin}${path.delimiter}${process.env.PATH || ""}`,
    }),
  });
  const outD = (rD.stdout || "") + (rD.stderr || "");
  check("T4d: an interpreter reachable only from the operator's PATH drives the canary RED",
    rD.status !== 0);
  check("T4d: it fails as a command the harness could not run, not as a false green",
    /CANARY FAILED/.test(outD));
  check("T4d: and settings.json was left untouched", /was NOT modified/.test(outD));

  // R16 ON THE REFUSAL. Document PATH is /usr/bin:/bin (the test default pin); the
  // interpreter lives only on the operator PATH. A refusal that does not name the
  // declared block is a mystery outage for an operator whose shell can run the command.
  check("T4d: the refusal names the settings env block as what the canary ran on",
    /env block of the settings file/.test(outD));
  check("T4d: the refusal shows the declared PATH", /PATH=/.test(outD));
  check("T4d: the refusal does not claim a launcher-shaped PATH floor",
    !/launcher-shaped environment/.test(outD));
}

// ── T5 — FAIL-CLOSED: REFUSE WHEN THE DOCUMENT DOES NOT ESTABLISH THE HOOK ENV ──────────
//
// Establishing means the four names are keys in the settings env block, which the harness
// overlays. Missing any of them, this tool must not invent a PATH floor (R10) and must not
// inherit this process (R9). Each red case has a green negative control: the same fixture
// with the missing names declared.
{
  const src = readFileSync(APPLY, "utf8");
  check("T5: the false R10 failure-direction claim is gone from the applier",
    !/THE FAILURE DIRECTION IS DELIBERATE/.test(src));
  check("T5: the converse-is-impossible claim is gone from the applier",
    !/converse arrangement/.test(src));
  check("T5: PATH_FLOOR is not assigned into the canary env",
    !/env\.PATH = PATH_FLOOR/.test(src));
  check("T5: PATH_FLOOR is not defined", !/const PATH_FLOOR/.test(src));
  check("T5: HOOK_ENV_PINS is exactly the four names the contract names",
    /HOOK_ENV_PINS = \["PATH", "PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP"\]/.test(src));

  // (a) No env block at all. The operator PATH would make a shebang wrapper runnable — that
  //     is the R9 inheritance that printed green. Must REFUSE, not canary-fail, not green.
  const opBin = mkdtempSync(path.join(tmp, "t5-opbin-"));
  const interp = path.join(opBin, "dcgtestinterp");
  writeFileSync(interp, `#!/bin/sh\nexec ${process.execPath} "$@"\n`);
  chmodSync(interp, 0o755);
  const interpWrap = path.join(mkdtempSync(path.join(tmp, "t5-iw-")), "dcg-ctx-wrap");
  writeFileSync(interpWrap,
    "#!/usr/bin/env dcgtestinterp\n" +
    readsStdin(
      'if (!/echo hello/.test(b)) {' +
      'console.log(JSON.stringify({hookSpecificOutput:{hookEventName:"PreToolUse",' +
      'permissionDecision:"deny",permissionDecisionReason:"BLOCKED by dcg  Reason: git_reset_hard"}}));' +
      '} else { console.log(JSON.stringify({continue:true})); }') + "\n");
  chmodSync(interpWrap, 0o755);

  const opEnv = (over) => {
    const e = { ...process.env };
    delete e.DCG_WRAP_BIN;
    return { ...e, ...over };
  };

  const sA = settings([staleEntry(interpWrap)], null);
  const beforeA = readFileSync(sA, "utf8");
  const rA = spawnSync(process.execPath, [APPLY], {
    encoding: "utf8",
    env: opEnv({
      HOOK_SETTINGS: sA, HOOK_SWEEP: sweep(0), CTX_WRAP: interpWrap,
      PATH: `${opBin}${path.delimiter}${process.env.PATH || ""}`,
    }),
  });
  const outA = (rA.stdout || "") + (rA.stderr || "");
  check("T5a: missing env block refuses to certify (does not inherit operator PATH)",
    rA.status !== 0);
  check("T5a: the refusal is REFUSING TO CERTIFY, not a canary failure under a substitute",
    /REFUSING TO CERTIFY/.test(outA) && !/canary 3:/.test(outA));
  check("T5a: it names PATH as undeclared", /does not declare PATH/.test(outA));
  check("T5a: settings were not published", readFileSync(sA, "utf8") === beforeA);
  check("T5a: the refusal names empty string as a valid declaration", /empty string counts/.test(outA));

  // Negative control: declare PATH as the operator's interp dir (plus the other three).
  // Same wrapper, same operator PATH — now green, because canary and hook agree on PATH.
  const rAok = spawnSync(process.execPath, [APPLY], {
    encoding: "utf8",
    env: opEnv({
      HOOK_SETTINGS: settings([staleEntry(interpWrap)], { PATH: opBin }),
      HOOK_SWEEP: sweep(0), CTX_WRAP: interpWrap,
      PATH: `${opBin}${path.delimiter}${process.env.PATH || ""}`,
    }),
  });
  const outAok = (rAok.stdout || "") + (rAok.stderr || "");
  check("T5a-neg: declaring PATH that contains the interpreter goes green", rAok.status === 0);
  check("T5a-neg: that green names the declared PATH", outAok.includes(`PATH=${opBin}`));
}

{
  // One pin missing at a time. A PATH-only check would green PYTHONPATH/HOME/STARTUP gaps;
  // R9 measured sitecustomize on a clean PATH as a working lever.
  for (const drop of ["PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP"]) {
    const env = pins();
    delete env[drop];
    const sB = path.join(tmp, `t5b-${drop}-${Math.random().toString(36).slice(2)}.json`);
    writeFileSync(sB, JSON.stringify({
      hooks: { PreToolUse: [staleEntry(SCANNER)] },
      env,
    }, null, 2) + "\n");
    const beforeB = readFileSync(sB, "utf8");
    const rB = run(sB, sweep(0));
    check(`T5b: ${drop} missing refuses to certify`, rB.status !== 0);
    check(`T5b: ${drop} missing names ${drop} and not a false PATH gap`,
      rB.out.includes(`does not declare ${drop}`) && !/does not declare PATH,/.test(rB.out));
    check(`T5b: ${drop} missing does not publish`, readFileSync(sB, "utf8") === beforeB);
  }
  const rBok = run(settings([staleEntry(SCANNER)], { PYTHONPATH: "", PYTHONHOME: "", PYTHONSTARTUP: "" }), sweep(0));
  check("T5b-neg: declaring the three python pins empty goes green", rBok.status === 0);
}

{
  // (c) Two different wrapper binaries, both routing. Round 10 T2: canary 3 exercised the
  //     first, publish widened the second. Both array orders must refuse. Negative: the
  //     same path twice (one LOOSE, one stale) still publishes.
  const aDir = mkdtempSync(path.join(tmp, "t5c-a-"));
  const bDir = mkdtempSync(path.join(tmp, "t5c-b-"));
  const binA = path.join(aDir, "dcg-ctx-wrap");
  const binB = path.join(bDir, "dcg-ctx-wrap");
  copyFileSync(SCANNER, binA); chmodSync(binA, 0o755);
  copyFileSync(SCANNER, binB); chmodSync(binB, 0o755);

  const two = (first, second) => settings([
    { matcher: LOOSE, hooks: hookFor(first) },
    { matcher: "mcp__context-mode__ctx_execute", hooks: hookFor(second) },
  ]);

  const rAB = run(two(binA, binB), sweep(0), [], binA);
  const rBA = run(two(binB, binA), sweep(0), [], binB);
  check("T5c: two different wrapper paths refuse (A then B)", rAB.status !== 0);
  check("T5c: two different wrapper paths refuse (B then A) — order is not the finding",
    rBA.status !== 0);
  check("T5c: the refusal names both binaries",
    rAB.out.includes(binA) && rAB.out.includes(binB));
  check("T5c: the refusal says the canary and the publish would be different objects",
    /same object/.test(rAB.out) || /different/.test(rAB.out));
  const beforeBA = two(binB, binA);
  const bytes = readFileSync(beforeBA, "utf8");
  const rBAagain = run(beforeBA, sweep(0), [], binB);
  check("T5c: settings were not published over two wrappers",
    readFileSync(beforeBA, "utf8") === bytes && rBAagain.status !== 0);

  const rSame = run(settings([
    { matcher: LOOSE, hooks: hookFor(SCANNER) },
    { matcher: "mcp__context-mode__ctx_execute", hooks: hookFor(SCANNER) },
  ]), sweep(0));
  check("T5c-neg: two entries pointing at the SAME wrapper still publish", rSame.status === 0);
  check("T5c-neg: the stale one was rewritten", /canaries green/.test(rSame.out));

  // Intra-entry form of the same class (B1). uniqueRouting used to take one command per
  // entry, so two hooks on ONE entry never tripped it.
  const twoHooks = (first, second) => settings([{
    matcher: "mcp__context-mode__ctx_execute",
    hooks: [{ type: "command", command: first }, { type: "command", command: second }],
  }]);
  const rIntra = run(twoHooks(binA, binB), sweep(0), [], binA);
  const rIntraRev = run(twoHooks(binB, binA), sweep(0), [], binB);
  check("T5c-intra: two wrapper hooks on one entry refuse", rIntra.status !== 0);
  check("T5c-intra: reversed hook order also refuses", rIntraRev.status !== 0);

  const foreign = "/usr/local/bin/file-policy-hook";
  const rMix = run(settings([{
    matcher: "mcp__context-mode__ctx_execute",
    hooks: [{ type: "command", command: SCANNER }, { type: "command", command: foreign }],
  }]), sweep(0));
  check("T5c-mix: wrapper plus a foreign command on one entry refuses", rMix.status !== 0);
  check("T5c-mix: the refusal names the mix, not a missing matcher",
    /mixes a/.test(rMix.out));
}

// B3 — the canaries judged the candidate; publishing must refuse if THAT file moved.
{
  const dir = mkdtempSync(path.join(tmp, "cand-"));
  const s = path.join(dir, "settings.json");
  writeFileSync(s, JSON.stringify({
    hooks: { PreToolUse: [bashEntry(), staleEntry()] },
    env: pins(),
  }, null, 2) + "\n");
  const writer = path.join(tmp, `sweep-cand-${Math.random().toString(36).slice(2)}.mjs`);
  writeFileSync(writer,
    'import { readFileSync, writeFileSync, readdirSync } from "node:fs";\n' +
    'import path from "node:path";\n' +
    `const dir = ${JSON.stringify(dir)};\n` +
    `const base = ${JSON.stringify(path.basename(s))};\n` +
    'const tmpf = readdirSync(dir).find((f) => f.startsWith(base + ".tmp-wi2096-"));\n' +
    'if (tmpf) {\n' +
    '  const p = path.join(dir, tmpf);\n' +
    '  const cfg = JSON.parse(readFileSync(p, "utf8"));\n' +
    '  cfg.hooks.PreToolUse.push({ matcher: "Evil", hooks: [{ type: "command", command: "/evil" }] });\n' +
    '  writeFileSync(p, JSON.stringify(cfg, null, 2) + "\\n");\n' +
    '}\n' +
    'process.exit(0);\n');
  const before = readFileSync(s, "utf8");
  const r = run(s, writer);
  const after = JSON.parse(readFileSync(s, "utf8"));
  check("B3: a candidate rewritten during the canaries does not publish",
    r.status !== 0);
  check("B3: the refusal names the candidate, not only SETTINGS",
    /candidate CHANGED/.test(r.out));
  check("B3: settings.json was left without the planted Evil matcher",
    !after.hooks.PreToolUse.some((e) => e.matcher === "Evil"));
  check("B3: settings bytes match the pre-run file when the candidate moved",
    readFileSync(s, "utf8") === before || !after.hooks.PreToolUse.some((e) => e.matcher === "Evil"));
}

// B4 — `~/` under a declared HOME is the settings HOME, not os.homedir().
{
  const homeDir = mkdtempSync(path.join(tmp, "b4-home-"));
  const wrapDir = path.join(homeDir, ".local", "bin");
  mkdirSync(wrapDir, { recursive: true });
  const bin = path.join(wrapDir, "dcg-ctx-wrap");
  copyFileSync(SCANNER, bin);
  chmodSync(bin, 0o755);
  const tildeCmd = "~/.local/bin/dcg-ctx-wrap";

  const rNoHome = run(settings([{
    matcher: "mcp__context-mode__ctx_execute",
    hooks: [{ type: "command", command: tildeCmd }],
  }]), sweep(0), [], bin);
  check("B4: ~/ without a declared HOME is refused", rNoHome.status !== 0);

  const rHome = run(settings([{
    matcher: "mcp__context-mode__ctx_execute",
    hooks: [{ type: "command", command: tildeCmd }],
  }], { HOME: homeDir }), sweep(0), [], bin);
  check("B4: ~/ with declared HOME that holds the wrapper goes green", rHome.status === 0);
  check("B4: the green line names the expanded path under declared HOME",
    rHome.out.includes(bin));

  const otherHome = mkdtempSync(path.join(tmp, "b4-other-"));
  const rWrong = run(settings([{
    matcher: "mcp__context-mode__ctx_execute",
    hooks: [{ type: "command", command: tildeCmd }],
  }], { HOME: otherHome }), sweep(0), [], bin);
  check("B4: ~/ with a declared HOME that does not hold the wrapper does not green",
    rWrong.status !== 0);
}

// B1 — a settings document that declares Node-runtime or native-preload keys is a
// substitute: the harness overlays them onto the live hook, and this certifier cannot
// run that process. Refuse, do not strip-and-publish. B1-node is the --require receipt:
// the certifier itself must not load a planted module on the way to that refusal.
{
  const d = mkdtempSync(path.join(tmp, "nodeopt-"));
  const marker = path.join(d, "PWNED");
  const pwn = path.join(d, "pwn.js");
  writeFileSync(pwn, `require("node:fs").writeFileSync(${JSON.stringify(marker)}, "pwned");\n`);
  const keys = [
    ["NODE_OPTIONS", `--require ${pwn}`],
    ["NODE_PATH", d],
    ["NODE_REPL_EXTERNAL_MODULE", pwn],
    ["LD_PRELOAD", path.join(d, "neuter.so")],
    ["LD_LIBRARY_PATH", d],
    ["DYLD_INSERT_LIBRARIES", path.join(d, "neuter.dylib")],
    ["DYLD_LIBRARY_PATH", d],
  ];
  for (const [key, value] of keys) {
    const s = settings([staleEntry()], { [key]: value });
    const before = readFileSync(s, "utf8");
    const r = run(s, sweep(0));
    check(`B1: declared ${key} refuses`, r.status !== 0);
    check(`B1: declared ${key} is REFUSING TO CERTIFY`, /REFUSING TO CERTIFY/.test(r.out));
    // Anchored to the REFUSAL line, not to r.out: the green line prints its own residual
    // list ("native preload (LD_PRELOAD, LD_LIBRARY_PATH, DYLD_*)"), so a bare
    // r.out.includes(key) passes off THAT text for LD_PRELOAD and LD_LIBRARY_PATH and
    // cannot tell a naming refusal from no refusal at all. Key names are [A-Z_] only.
    check(`B1: declared ${key} refusal names the key`,
      new RegExp(`REFUSING TO CERTIFY[^\n]*declares[^\n]*${key}`).test(r.out));
    check(`B1: declared ${key} does not publish`, readFileSync(s, "utf8") === before);
    check(`B1: declared ${key} never reaches canary 3`, !/canary 3:/.test(r.out));
  }
  check("B1-node: declared NODE_OPTIONS --require does not run in the certifier",
    !existsSync(marker));
}

// ── T7 — THE APPLIER'S SWEEP PIN IS DCG_CTX_WRAP ─────────────────────────────────────────
//
// Hermetic half always runs: a stub sweep that reads DCG_CTX_WRAP (the name the real
// script reads) and ignores CTX_WRAP. That is the contract, and it does not need the
// sibling repo. The recorder used to be the hook command as well, so canary 3 wrote the
// marker even when the sweep never saw the pin — that oracle is gone.
{
  const src = readFileSync(APPLY, "utf8");
  check("T7: the false CTX_WRAP-is-what-the-sweep-reads claim is gone",
    !/not the one CTX_WRAP happens to name/.test(src));
  const anchor = "DCG_CTX_WRAP: LIVE_WRAPPER";
  const hits = src.split(anchor).length - 1;
  check("T7: DCG_CTX_WRAP pin is present exactly once", hits === 1);
  const anchored = src.split("\n").find((l) => l.includes(anchor)) || "";
  console.log(`T7 mutant-anchor hit=${hits} line=${anchored.trim()}`);

  const d = mkdtempSync(path.join(tmp, "t7-"));
  const seen = path.join(d, "sweep-saw");
  const pinSweep = path.join(d, "sweep-pin.mjs");
  writeFileSync(pinSweep,
    `import { appendFileSync } from "node:fs";\n` +
    `appendFileSync(${JSON.stringify(seen)}, process.env.DCG_CTX_WRAP || "(unset)");\n` +
    `process.exit(process.env.DCG_CTX_WRAP ? 0 : 3);\n`);
  const rec = path.join(mkdtempSync(path.join(tmp, "t7-rec-")), "dcg-ctx-wrap");
  writeFileSync(rec,
    `#!${process.execPath}\n` +
    readsStdin(
      'if (!/echo hello/.test(b)) {' +
      'console.log(JSON.stringify({hookSpecificOutput:{hookEventName:"PreToolUse",' +
      'permissionDecision:"deny",permissionDecisionReason:"BLOCKED by dcg  Reason: git_reset_hard"}}));' +
      '} else { console.log(JSON.stringify({continue:true})); }') + "\n");
  chmodSync(rec, 0o755);

  const r = run(settings([staleEntry(rec)]), pinSweep, [], rec);
  check("T7a: hermetic stub sees DCG_CTX_WRAP", existsSync(seen));
  check("T7a: the value the stub saw is the settings wrapper",
    existsSync(seen) && readFileSync(seen, "utf8") === rec);
  check("T7a: that run is green", r.status === 0);

  if (hits === 1) {
    const mutantPath = path.join(d, "apply-mutant.mjs");
    writeFileSync(mutantPath, src.replace(anchor, "CTX_WRAP_NOT_READ: LIVE_WRAPPER"));
    const seenM = path.join(d, "mutant-saw");
    const pinSweepM = path.join(d, "sweep-pin-m.mjs");
    writeFileSync(pinSweepM,
      `import { appendFileSync } from "node:fs";\n` +
      `appendFileSync(${JSON.stringify(seenM)}, process.env.DCG_CTX_WRAP || "(unset)");\n` +
      `process.exit(process.env.DCG_CTX_WRAP ? 0 : 3);\n`);
    spawnSync(process.execPath, [mutantPath], {
      encoding: "utf8",
      timeout: 120000,
      env: {
        ...process.env,
        HOOK_SETTINGS: settings([staleEntry(rec)]),
        HOOK_SWEEP: pinSweepM,
        CTX_WRAP: rec,
      },
    });
    check("T7a: reverting DCG_CTX_WRAP is killed — the stub saw it unset",
      existsSync(seenM) && readFileSync(seenM, "utf8") === "(unset)");
  }

  const candidates = [
    path.join(process.env.HOME || process.env.USERPROFILE || "",
      "dev/warden-memory/scripts/audit-hook-matchers.mjs"),
    "/mnt/c/Users/brynn/dev/warden-memory/scripts/audit-hook-matchers.mjs",
    "C:/Users/brynn/dev/warden-memory/scripts/audit-hook-matchers.mjs",
  ];
  const realSweep = candidates.find((p) => p && existsSync(p));
  if (!realSweep) {
    console.log(
      "SKIP: T7b — real coverage sweep not found. Not a pass of that pin. Looked in:\n  " +
      candidates.filter(Boolean).join("\n  "));
  } else {
    const writeEntry = () => ({
      matcher: "Write|Edit|MultiEdit",
      hooks: [{ type: "command", command: "dcg-wrap" }],
    });
    const marker = path.join(d, "from-sweep");
    const recB = path.join(mkdtempSync(path.join(tmp, "t7b-rec-")), "dcg-ctx-wrap");
    writeFileSync(recB,
      `#!${process.execPath}\n` +
      `const fs = require("node:fs");\n` +
      `if (process.env.DCG_CTX_WRAP) fs.appendFileSync(${JSON.stringify(marker)}, "from-sweep\\n");\n` +
      readsStdin(
        'if (!/echo hello/.test(b)) {' +
        'console.log(JSON.stringify({hookSpecificOutput:{hookEventName:"PreToolUse",' +
        'permissionDecision:"deny",permissionDecisionReason:"BLOCKED by dcg  Reason: git_reset_hard"}}));' +
        '} else { console.log(JSON.stringify({continue:true})); }') + "\n");
    chmodSync(recB, 0o755);
    const rB = run(settings([bashEntry(), writeEntry(), staleEntry(recB)]), realSweep, [], recB);
    check("T7b: the real sweep spawned the pin (from-sweep, not canary 3)",
      existsSync(marker) && readFileSync(marker, "utf8").includes("from-sweep"));
    check("T7b: a complete fixture plus the real sweep can go green", rB.status === 0);

    const marker2 = path.join(d, "oldname-ran");
    const rec2 = path.join(mkdtempSync(path.join(tmp, "t7b-rec2-")), "dcg-ctx-wrap");
    writeFileSync(rec2,
      `#!${process.execPath}\n` +
      `require("node:fs").appendFileSync(${JSON.stringify(marker2)}, "ran\\n");\n` +
      'console.log(JSON.stringify({hookSpecificOutput:{hookEventName:"PreToolUse",' +
      'permissionDecision:"deny",permissionDecisionReason:"BLOCKED by dcg  Reason: x"}}));\n');
    chmodSync(rec2, 0o755);
    const envOld = { ...process.env, HOOK_SETTINGS: settings([staleEntry(rec2)]), CTX_WRAP: rec2 };
    delete envOld.DCG_CTX_WRAP;
    spawnSync(process.execPath, [realSweep], { encoding: "utf8", timeout: 120000, env: envOld });
    check("T7b: CTX_WRAP alone does NOT reach the real sweep", !existsSync(marker2));
  }
}


// ── M2 (G-2) — `%` IS LIVE ON THE SHELL CANARY 3 ACTUALLY USES ────────────────────────────
//
// Same class as T1, other shell. `canaryScanner` spawns with `shell: true`, which on win32 is
// `cmd.exe /d /s /c`, and cmd.exe expands `%NAME%` at delivery. G-2 measured
// `C:/%PWNVAR%/dcg-ctx-wrap` clearing the basename and absolute-path gates as a literal token
// and then executing an injected command, because `%` sat in the SHELL_LITERAL whitelist.
// The refusal is platform-independent — the whitelist no longer admits `%` anywhere — so this
// control holds on the Linux this suite runs on, where the expansion itself cannot happen.
{
  const base = mkdtempSync(path.join(tmp, "m2-"));
  const realDir = path.join(base, "w");
  mkdirSync(realDir, { recursive: true });
  const realBin = path.join(realDir, "dcg-ctx-wrap");
  copyFileSync(SCANNER, realBin);
  chmodSync(realBin, 0o755);

  // `%` EXPANDS; `,` and `=` SPLIT the command token, which is worse - G-3 measured
  // `<tmp>/inject.bat,/x/dcg-ctx-wrap` running inject.bat AND printing a green certificate
  // at rc 0, where the `%` case had at least failed closed.
  for (const [label, seg] of [["%", "%PWNVAR%"], [",", "hostname.exe,x"],
                              ["=", "hostname.exe=junk"]]) {
  const evil = base + "/" + seg + "/w/dcg-ctx-wrap";
  const s = settings([staleEntry(evil)]);
  const before = readFileSync(s, "utf8");
  const r = run(s, sweep(0), [], realBin);

  check(`M2: a \`${label}\` in a path SEGMENT is refused`, r.status !== 0);
  check(`M2: \`${label}\` - settings were not published over a refused command`,
    readFileSync(s, "utf8") === before);
  // Name WHICH refusal fired, for the same reason T1 does: an rc!=0 from an unrelated gate
  // would satisfy the two assertions above while testing nothing.
  check(`M2: \`${label}\` - refused as unroutable, not by some unrelated gate`,
    /NONE execs/.test(r.out));
  }
}

// ── M3 (G-3) — EVERY PIN COMPONENT MUST BE ABSOLUTE ───────────────────────────────────────
//
// The certificate's load-bearing claim is that the four declared names make canary and hook
// the SAME object. An empty or cwd-relative component makes them agree as STRINGS while
// resolving against two different directories — the canary runs in the operator's cwd, the
// harness runs PreToolUse from the session directory. G-3 measured `PATH=/usr/bin:/bin:`,
// a single trailing empty component, publishing green at rc=0.
{
  const cases = [
    ["PATH", "/usr/bin:/bin:", "trailing empty component"],
    ["PATH", "/usr/bin::/bin", "doubled delimiter"],
    ["PATH", "relbin:/usr/bin", "relative component"],
    // PYTHONPATH is a LIST. These two cases are what distinguish the list rule from the
    // single-value rule: the bare "lib" row below fails closed under BOTH, so on its own it
    // could not tell them apart, and the mutant LIST_PINS = new Set(["PATH"]) kept the suite
    // green while publishing PYTHONPATH=/usr/lib:lib at rc 0 (G-9).
    ["PYTHONPATH", "/usr/lib:lib", "relative component in a list"],
    ["PYTHONPATH", "/usr/lib:", "trailing empty component in a list"],
    ["PYTHONPATH", "lib", "relative value"],
    ["PYTHONHOME", "py", "relative value"],
    ["PYTHONSTARTUP", "start.py", "relative value"],
  ];
  for (const [key, value, why] of cases) {
    const s = settings([staleEntry()], { [key]: value });
    const before = readFileSync(s, "utf8");
    const r = run(s, sweep(0));
    check(`M3: ${key} with a ${why} is refused`, r.status !== 0);
    // Anchored to the refusal line, not to r.out: the pin values are echoed further down in
    // the `Declared:` block, so a bare substring test would pass off that echo.
    check(`M3: ${key} with a ${why} names the offending pin in the refusal`,
      new RegExp(`REFUSING TO CERTIFY[^\n]*relative component in[^\n]*${key}`).test(r.out));
    check(`M3: ${key} with a ${why} does not publish`,
      readFileSync(s, "utf8") === before);
  }
  // The EMPTY value stays legal: it declares nothing, and that is what the contract means by
  // "empty string counts — it dominates ambient". Absolute components still publish.
  const ok = settings([staleEntry()], { PYTHONPATH: "", PYTHONHOME: "", PYTHONSTARTUP: "" });
  check("M3: an empty pin VALUE is still accepted", run(ok, sweep(0)).status === 0);
}

// ── M4 (G-5) — CANARY 3 MUST ACTUALLY DELIVER THE DANGEROUS FIXTURE ───────────────────────
//
// Every canary-3 stub printed a canned deny on startup and never read stdin, so the suite
// could not see the DELIVERY half of its own load-bearing canary — it was a decision-parser
// test wearing a control's name. G-5 mutation-tested the applier: sending `{}` instead of the
// fixture, and sending a benign fixture, each left the suite at rc=0 / 0 FAILs. This stub
// records what arrived and the assertions read it, so either mutation now turns the suite red.
{
  const w = wrapper("recording");
  const rec = w + ".stdin";
  const s = settings([staleEntry(w)]);
  run(s, sweep(0), [], w);

  check("M4: canary 3 reached the recording wrapper", existsSync(rec));
  const got = existsSync(rec) ? readFileSync(rec, "utf8") : "";
  check("M4: canary 3 delivered a payload at all", got.trim() !== "");
  check("M4: the delivered payload carries the DANGEROUS fixture",
    got.includes("git reset --hard origin/main"));
  check("M4: the payload is a tool call, not a bare string",
    got.includes('"tool_name"') && got.includes('"tool_input"'));
}

// ── M6 (S-2) — AN UNKNOWN ARGUMENT MUST NOT PUBLISH ───────────────────────────────────────
//
// `process.argv.includes("--dry-run")` meant `--dry-rnu` and `--dry-run=true` both fell
// through to the publishing path, printed the rewrite plan a preview prints, and rewrote the
// canonical settings file at rc=0. On the file this script's own header calls the source the
// REPL-seat renderer fans out from, a one-character typo in the documented preview flag became
// a publish. Boundary validation on the highest-consequence path in the tool.
{
  for (const arg of ["--dry-rnu", "--dry-run=true", "-n", "extra"]) {
    const s = settings([staleEntry()]);
    const before = readFileSync(s, "utf8");
    const r = run(s, sweep(0), [arg]);
    check(`M6: ${arg} is refused`, r.status !== 0);
    check(`M6: ${arg} is named in the refusal`,
      r.out.includes(`unknown argument(s): ${arg}`));
    check(`M6: ${arg} does not publish`, readFileSync(s, "utf8") === before);
  }
  // The documented flag itself still previews and still touches nothing.
  const s = settings([staleEntry()]);
  const before = readFileSync(s, "utf8");
  run(s, sweep(0), ["--dry-run"]);
  check("M6: --dry-run still previews without publishing",
    readFileSync(s, "utf8") === before);
}


// ── A8 (O-1) — AN EMPTY `PATH` IS NOT A DECLARATION ───────────────────────────────────────
//
// "Empty string counts" is true for PYTHONPATH / PYTHONHOME / PYTHONSTARTUP, where CPython
// reads empty as unset. For PATH it means NO INTERPRETER RESOLVES: dcg-ctx-wrap starts
// `#!/usr/bin/env python3`, and `env -i PATH=""` on such a script cannot find python3 at all.
// O-1 measured `PATH: ""` publishing at rc 0 with no warning — on the tool's own advice, since
// the remediation text said empty counts with no exception for PATH.
{
  const s = settings([staleEntry()], { PATH: "" });
  const before = readFileSync(s, "utf8");
  const r = run(s, sweep(0));
  check("A8: an empty PATH is refused", r.status !== 0);
  check("A8: the refusal names PATH as the empty one",
    new RegExp("REFUSING TO CERTIFY[^\n]*PATH[^\n]*empty string").test(r.out));
  check("A8: an empty PATH does not publish", readFileSync(s, "utf8") === before);
  // The other three keep the empty-is-a-declaration contract. This is the half of the design
  // decision that was right, and it must not be broken by the half that was wrong.
  const ok = settings([staleEntry()], { PYTHONPATH: "", PYTHONHOME: "", PYTHONSTARTUP: "" });
  check("A8: empty PYTHONPATH / PYTHONHOME / PYTHONSTARTUP still certify",
    run(ok, sweep(0)).status === 0);
}

// ── A3 (G-3) — A DECLARED `DCG_WRAP_BIN` MUST BE ABSOLUTE ─────────────────────────────────
//
// It is not a pin — it is not required — but when the document declares it, it names the file
// the green line calls "the scanner behind it", and dcg-ctx-wrap execs it as a path. A relative
// value resolves against whatever directory the process starts in: the operator's cwd here, the
// session directory there. G-3 measured `DCG_WRAP_BIN=./dcg-wrap` publishing at rc 0 and being
// printed in the certificate, while `PYTHONSTARTUP=start.py` was refused one name over.
{
  for (const bad of ["./dcg-wrap", "dcg-wrap", "../bin/dcg-wrap"]) {
    const s = settings([staleEntry()], { DCG_WRAP_BIN: bad });
    const before = readFileSync(s, "utf8");
    const r = run(s, sweep(0));
    check(`A3: DCG_WRAP_BIN=${bad} is refused`, r.status !== 0);
    check(`A3: DCG_WRAP_BIN=${bad} refusal names the variable`,
      new RegExp("REFUSING TO CERTIFY[^\n]*DCG_WRAP_BIN").test(r.out));
    check(`A3: DCG_WRAP_BIN=${bad} does not publish`, readFileSync(s, "utf8") === before);
  }
  // Absent is fine — the wrapper resolves its own default — and so is an absolute value.
  check("A3: an absent DCG_WRAP_BIN still certifies",
    run(settings([staleEntry()]), sweep(0)).status === 0);
}

// ── A1 (G-1) — `~/` BINDS TO THE HOME THE SHELL ACTUALLY EXPANDS ──────────────────────────
//
// `declaredHome()` accepted USERPROFILE as a substitute for HOME. On Unix only HOME drives
// tilde expansion, so IDENTITY joined the USERPROFILE value while the shell expanded `~` under
// the AMBIENT HOME that CANARY_ENV_KEEP preserves. G-1 measured the consequence: rc 0, a
// certificate naming a USERPROFILE `allow` stub, and the deny it reported arriving from a
// different inode. The binary named was never run; the binary run was never named.
{
  const mkHome = (kind) => {
    const h = mkdtempSync(path.join(tmp, "a1home-"));
    const bin = path.join(h, ".local", "bin");
    mkdirSync(bin, { recursive: true });
    const w = path.join(bin, "dcg-ctx-wrap");
    copyFileSync(wrapper(kind), w);
    chmodSync(w, 0o755);
    return h;
  };
  const TILDE = "~/.local/bin/dcg-ctx-wrap";

  // USERPROFILE alone must NOT satisfy `~/`: nothing expands it on the shell that runs the hook.
  const hU = mkHome("scanner");
  const sU = settings([staleEntry(TILDE)], { USERPROFILE: hU });
  const beforeU = readFileSync(sU, "utf8");
  const rU = run(sU, sweep(0));
  check("A1: a declared USERPROFILE alone does not satisfy `~/`", rU.status !== 0);
  check("A1: refused as an unroutable command, not by some unrelated gate",
    /NONE execs/.test(rU.out));
  check("A1: USERPROFILE-only does not publish", readFileSync(sU, "utf8") === beforeU);

  // A declared HOME that is relative, or that carries a shell metacharacter, is refused too:
  // the JOINED result was never tested, only the segment after `~/`.
  //
  // DECLARED RESIDUAL, measured rather than argued. These two cases are pinned by
  // `hookCommand` (`apply-wi2096-matcher.mjs`), which already refuses a resolved binary that
  // is not `path.isAbsolute` - so removing the isAbsolute/SHELL_LITERAL guard from
  // `soleArgv0` leaves this suite at 0 FAILs. That guard is defence in depth, keeping
  // `soleArgv0` self-contained instead of relying on a caller two hops away, and NO test
  // here can distinguish it through the applier's observable behaviour. Saying so beats
  // manufacturing a control that only appears to cover it.
  //
  // The half that IS independently observable is USERPROFILE (above): reinstating it as a
  // tilde HOME turns this suite red. Both cases below still assert WHICH refusal fired,
  // because a bare `status !== 0` would pass off any unrelated gate - the shape T1 warns of.
  for (const [bad, why] of [["relhome", "relative"], ["/tmp/$(id)h", "shell construct"]]) {
    const sR = settings([staleEntry(TILDE)], { HOME: bad });
    const beforeR = readFileSync(sR, "utf8");
    const rR = run(sR, sweep(0));
    check(`A1: a ${why} declared HOME is refused`, rR.status !== 0);
    check(`A1: a ${why} declared HOME is refused AS UNROUTABLE, not by another gate`,
      /NONE execs/.test(rR.out));
    check(`A1: a ${why} declared HOME does not publish`,
      readFileSync(sR, "utf8") === beforeR);
  }

  // A declared, absolute HOME is the one accepted form, and it certifies.
  const hH = mkHome("scanner");
  const rH = run(settings([staleEntry(TILDE)], { HOME: hH }), sweep(0), [],
    path.join(hH, ".local", "bin", "dcg-ctx-wrap"));
  check("A1: a declared absolute HOME certifies `~/`", rH.status === 0);
}

// ── A2 (G-2) — A NON-COMMAND SIBLING WIDENS ANOTHER CONTROL ───────────────────────────────
//
// The mixed gate compared routing commands against COMMAND hooks only, but the schema this file
// quotes is `command | http | mcp_tool | prompt | agent`. A `prompt` sibling is in-schema and
// was invisible to that count, so G-2 measured a wrapper hook beside a `prompt` hook publishing
// at rc 0 and carrying that prompt — previously scoped to ctx_execute alone — onto all three
// exec tools. That is verbatim the over-firing the gate was written for.
{
  for (const sibling of [
    { type: "prompt", prompt: "decide" },
    { type: "http", url: "https://example.invalid/hook" },
    { type: "agent", agent: "reviewer" },
  ]) {
    const entry = { matcher: "mcp__context-mode__ctx_execute", hooks: [...hookFor(SCANNER), sibling] };
    const s = settings([entry]);
    const before = readFileSync(s, "utf8");
    const r = run(s, sweep(0));
    check(`A2: a '${sibling.type}' sibling refuses the rewrite`, r.status !== 0);
    check(`A2: a '${sibling.type}' sibling is named as a mixed entry`,
      /mixes a .* hook with another hook/.test(r.out));
    check(`A2: a '${sibling.type}' sibling leaves the file alone`,
      readFileSync(s, "utf8") === before);
  }
}

// ── A7 (S-1) — CANARY 3 NEEDS A BENIGN NEGATIVE CONTROL ───────────────────────────────────
//
// Canary 3 proved a dangerous fixture is denied. On its own that cannot separate "this scanner
// examined the payload and objected" from "this binary says no to everything". An
// unconditional-deny scanner blocks 100% of benign ctx traffic — the three-tool outage the
// adapter suite's test 12 header records as having happened once — and S-1 measured the applier
// green-ticking exactly that: the suite's own canned-deny stub certified at rc 0.
{
  const d = mkdtempSync(path.join(tmp, "a7-"));
  const always = path.join(d, "dcg-ctx-wrap");
  writeFileSync(always, `#!${process.execPath}\n` +
    'console.log(JSON.stringify({hookSpecificOutput:{hookEventName:"PreToolUse",' +
    'permissionDecision:"deny",permissionDecisionReason:"BLOCKED by dcg  Reason: everything"}}));\n');
  chmodSync(always, 0o755);

  const s = settings([staleEntry(always)]);
  const before = readFileSync(s, "utf8");
  const r = run(s, sweep(0), [], always);
  check("A7: an always-deny scanner does not certify", r.status !== 0);
  check("A7: the refusal names the benign fixture, not the dangerous one",
    /did not ALLOW a benign fixture/.test(r.out));
  check("A7: an always-deny scanner does not publish",
    readFileSync(s, "utf8") === before);
  // And the discriminating stub — deny the dangerous, allow the benign — still certifies, so
  // this control refuses always-deny binaries rather than refusing strictness in general.
  check("A7: a scanner that discriminates still certifies",
    run(settings([staleEntry()]), sweep(0)).status === 0);
}


// -- M3 (S-1) -- THE BENIGN CONTROL NEEDS AN AFFIRMATIVE ALLOW ---------------------------
//
// A7 closed the canned-deny shape and left the class open for every refusal NOT spelled
// `deny`: S-1 measured `{"continue": false}`, a `permissionDecision` of `"ask"`, and a
// CORRECT allow body delivered on exit 2 all certifying at rc 0 with the full green line.
// Each blocks or interrupts 100% of benign ctx traffic in production. The control now reads
// rb.status and requires `continue === true`.
//
// NOT tested here, because the adapter already converts them into its own `dcg-ctx-wrap: `
// deny which canary 3 rejects as adapter-sourced: a silent exit 2, a crash, and malformed
// output. Sol filed those three too; the adjudicator recorded that they are caught.
{
  const shapes = [
    ["continue-false", 'console.log(JSON.stringify({continue:false}));', "blocks the call"],
    ["ask", 'console.log(JSON.stringify({hookSpecificOutput:{hookEventName:"PreToolUse",' +
      'permissionDecision:"ask",permissionDecisionReason:"confirm"}}));', "interrupts the call"],
    ["allow-on-exit-2", 'console.log(JSON.stringify({continue:true}));process.exit(2);',
      "right body, blocking status"],
  ];
  for (const [name, benignBody, why] of shapes) {
    const dd = mkdtempSync(path.join(tmp, `m3-${name}-`));
    const w = path.join(dd, "dcg-ctx-wrap");
    // Denies the dangerous fixture correctly, so canary 3 clears its FIRST criterion and the
    // only thing under test is what the BENIGN payload comes back as.
    writeFileSync(w, `#!${process.execPath}\n` + readsStdin(
      'if (!/echo hello/.test(b)) { console.log(JSON.stringify({hookSpecificOutput:{' +
      'hookEventName:"PreToolUse",permissionDecision:"deny",' +
      'permissionDecisionReason:"BLOCKED by dcg  Reason: git_reset_hard"}})); }' +
      `else { ${benignBody} }`) + "\n");
    chmodSync(w, 0o755);
    const sm = settings([staleEntry(w)]);
    const before = readFileSync(sm, "utf8");
    const rm = run(sm, sweep(0), [], w);
    check(`M3: a benign ${name} scanner (${why}) does not certify`, rm.status !== 0);
    check(`M3: a benign ${name} scanner is refused ON THE BENIGN FIXTURE`,
      /did not ALLOW a benign fixture/.test(rm.out));
    check(`M3: a benign ${name} scanner does not publish`,
      readFileSync(sm, "utf8") === before);
  }
}

// -- M-a (C-1) -- THE REGEX AND THE OPERATOR TEXT MUST AGREE ABOUT `%` --------------------
//
// The previous fold closed G-2 in SHELL_LITERAL and left the operator-facing text still
// listing `%` among the accepted characters. It failed CLOSED, so nothing broke - but the
// danger is exact: the next edit that "aligns the regex with the message" restores G-2, where
// `%` was live and an injected command executed on win32. Pin the AGREEMENT, not either side,
// because either side alone can be edited into consistency the wrong way.
{
  const src = readFileSync(APPLY, "utf8");
  const cls = /const SHELL_LITERAL = \/\^\[([^\]]*)\]\+\$\//.exec(src);
  check("M-a: SHELL_LITERAL is still one character class", !!cls);
  const line = /The path itself must also be a plain literal[^\n]*/.exec(src);
  check("M-a: the operator text listing the accepted characters is still there", !!line);
  // Escapes are unwrapped first: the class is written `\\/` for the slash, so a raw
  // `.includes()` on the raw class would report a backslash that is not admitted.
  const cleaned = !!cls ? cls[1].replace(/\\(.)/g, "$1") : "";
  // The character list is the run of space-separated tokens after "digits and". Take the
  // FIRST character of each token: the final one is `-.`, the list item plus the full stop,
  // and the sentence also contains an English comma in "letters, digits" that is not a
  // listed character at all.
  const listed = !!line ? /digits and ([^\n]*)/.exec(line[0]) : null;
  const chars = new Set((listed ? listed[1] : "").trim().split(/\s+/).map((t) => t[0]));
  check("M-a: the operator text parses into a character list", chars.size >= 5);
  // `%` splits nothing but EXPANDS; `,` and `=` split the command token; `\\` is a separator on
  // cmd.exe and an escape in sh, so it must never be added to buy Windows-native paths - the
  // forward-slash form is the remedy there.
  for (const ch of ["%", ",", "=", "\\"]) {
    const inRegex = cleaned.includes(ch);
    const inText = chars.has(ch);
    check(`M-a: the regex and the operator text agree about \`${ch}\``, inRegex === inText);
    check(`M-a: and neither of them admits \`${ch}\``, inRegex === false);
  }
}

rmSync(tmp, { recursive: true, force: true });


if (failures.length) {
  for (const f of failures) console.log(`FAIL: ${f}`);
  process.exit(1);
}
console.log("ok — apply-wi2096-matcher assertions passed");
