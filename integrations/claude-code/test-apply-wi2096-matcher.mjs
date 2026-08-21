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
function wrapper(kind) {
  const dir = mkdtempSync(path.join(tmp, `w-${kind}-`));
  const p = path.join(dir, "dcg-ctx-wrap");
  const bodies = {
    scanner: 'console.log(JSON.stringify({hookSpecificOutput:{hookEventName:"PreToolUse",' +
      'permissionDecision:"deny",permissionDecisionReason:"BLOCKED by dcg  Reason: git_reset_hard"}}));',
    adapter: 'console.log(JSON.stringify({hookSpecificOutput:{hookEventName:"PreToolUse",' +
      'permissionDecision:"deny",permissionDecisionReason:"dcg-ctx-wrap: scanner /nope could not be run"}}));',
    allow: 'console.log(JSON.stringify({continue:true}));',
    // A well-formed scanner-sourced deny on an exit status the HOST DISCARDS. The host honours
    // 2 as blocking and treats every other non-zero as non-blocking, after which the tool runs
    // anyway — so this reads as "guarded" while being nothing of the kind.
    ignored: 'console.log(JSON.stringify({hookSpecificOutput:{hookEventName:"PreToolUse",' +
      'permissionDecision:"deny",permissionDecisionReason:"BLOCKED by dcg  Reason: git_reset_hard"}}));' +
      'process.exit(3);',
    // Exits clean and says NOTHING. The delivery half of the predicate is about what ARRIVES,
    // so a silent command must fail even though its exit status is perfect.
    silent: 'process.exit(0);',
  };
  // The interpreter is named ABSOLUTELY, not via `/usr/bin/env`: the canary environment now
  // carries a deterministic PATH floor, so a fixture that resolves its own interpreter through
  // PATH would be testing the floor rather than the behaviour under test.
  writeFileSync(p, `#!${process.execPath}\n${bodies[kind]}\n`);
  chmodSync(p, 0o755);
  return p;
}

const SCANNER = wrapper("scanner");

// `envBlock` is the settings document's own `env` — the block the harness delivers to every
// hook it spawns, and therefore part of the environment the canaries have to reproduce. Omitted
// by every fixture that predates T3, so the document is byte-identical to what it was.
function settings(entries, envBlock) {
  const p = path.join(tmp, `settings-${Math.random().toString(36).slice(2)}.json`);
  const doc = { hooks: { PreToolUse: entries } };
  if (envBlock) doc.env = envBlock;
  writeFileSync(p, JSON.stringify(doc, null, 2) + "\n");
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
  writeFileSync(s, JSON.stringify({ hooks: { PreToolUse: [bashEntry(), staleEntry()] } }, null, 2) + "\n");
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
  writeFileSync(s, JSON.stringify({ hooks: { PreToolUse: [bashEntry(), staleEntry()] } }, null, 2) + "\n");
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
    'console.log(JSON.stringify({hookSpecificOutput:{hookEventName:"PreToolUse",' +
    'permissionDecision:"deny",permissionDecisionReason: leaked ? ' +
    '"dcg-ctx-wrap: DCG_WRAP_BIN LEAKED INTO THE CANARY" : ' +
    '"BLOCKED by dcg  Reason: git_reset_hard"}}));\n');
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

  // Denies EITHER WAY, so canary 3's own criterion is satisfied in every world and the single
  // variable under test is WHICH `DCG_WRAP_BIN` arrived. A wrong answer comes back through the
  // reason and names itself, instead of surfacing as a bare non-zero that could be anything.
  const bin = path.join(d, "dcg-ctx-wrap");
  writeFileSync(bin,
    `#!${process.execPath}\n` +
    "const got = process.env.DCG_WRAP_BIN || '(unset)';\n" +
    `const want = ${JSON.stringify(CONFIG_PICK)};\n` +
    'console.log(JSON.stringify({hookSpecificOutput:{hookEventName:"PreToolUse",' +
    'permissionDecision:"deny",permissionDecisionReason: got === want ? ' +
    '"BLOCKED by dcg  Reason: git_reset_hard" : ' +
    '"dcg-ctx-wrap: CANARY SAW DCG_WRAP_BIN=" + got}}));\n');
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

  // Denies EITHER WAY, so canary 3's own criterion is satisfied in every world and the only
  // variable under test is WHAT ARRIVED. Leaks come back through the reason and name themselves.
  const probe = path.join(d, "dcg-ctx-wrap");
  writeFileSync(probe,
    `#!${process.execPath}\n` +
    "const watch = ['PYTHONPATH','PYTHONHOME','LD_PRELOAD','NODE_OPTIONS','BASH_ENV'," +
    "'DCG_UNENUMERATED_SELECTOR'];\n" +
    "const leaked = watch.filter((k) => process.env[k]);\n" +
    `if ((process.env.PATH || '').includes(${JSON.stringify(hijackDir)})) leaked.push('PATH');\n` +
    'console.log(JSON.stringify({hookSpecificOutput:{hookEventName:"PreToolUse",' +
    'permissionDecision:"deny",permissionDecisionReason: leaked.length ? ' +
    '"dcg-ctx-wrap: OPERATOR ENV LEAKED " + leaked.join(",") : ' +
    '"BLOCKED by dcg  Reason: git_reset_hard"}}));\n');
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
    'console.log(JSON.stringify({hookSpecificOutput:{hookEventName:"PreToolUse",' +
    'permissionDecision:"deny",permissionDecisionReason: ok ? ' +
    '"BLOCKED by dcg  Reason: git_reset_hard" : ' +
    '"dcg-ctx-wrap: CONFIG PATH DID NOT WIN, saw " + process.env.PATH}}));\n');
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
  check("T4c: the settings env block can still set PATH and beats the floor",
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
    'console.log(JSON.stringify({hookSpecificOutput:{hookEventName:"PreToolUse",' +
    'permissionDecision:"deny",permissionDecisionReason:"BLOCKED by dcg  Reason: git_reset_hard"}}));\n');
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

  // R16 ON THE REFUSAL. The false-refusal direction is chosen deliberately, so a refusal that
  // does not say how to fix it is a mystery outage for an operator who has not read our notes:
  // the command works when they type it and fails here, which reads as a bug in this tool.
  check("T4d: the refusal explains that the canary uses a launcher-shaped environment",
    /launcher-shaped environment/.test(outD));
  check("T4d: the refusal names the supported remedy — the settings env block",
    /"env" block of the settings file/.test(outD));
  check("T4d: the refusal shows the PATH it actually ran with", /PATH=/.test(outD));
}

rmSync(tmp, { recursive: true, force: true });

if (failures.length) {
  for (const f of failures) console.log(`FAIL: ${f}`);
  process.exit(1);
}
console.log("ok — apply-wi2096-matcher assertions passed");
