#!/usr/bin/env node
// apply-wi2096-matcher.mjs — gated, reversible fix for the stale context-mode
// PreToolUse matchers in the canonical ~/.claude/settings.json (transformate WI-2096).
//
// WHY A SCRIPT AND NOT A HAND EDIT: settings.json is the canonical source the
// REPL-seat renderer fans out to every seat (ops_seat_settings_generated,
// transformate WI-1818). A hot-patch that lands broken JSON breaks every seat on the
// next 15-minute sync. So the change is CANARIED AS A CANDIDATE and only published if all
// three canaries go green — there is no rollback path, because on red the canonical file was
// never touched.
//
//   node apply-wi2096-matcher.mjs --dry-run   # print the diff, touch nothing
//   node apply-wi2096-matcher.mjs             # write candidate → canary → backup → publish
//
// Manual rollback at any time: cp <printed backup path> ~/.claude/settings.json
// Idempotent, but NOT a no-op: a second run re-verifies that the control still works and
// exits non-zero if it does not. "Already current" is a claim about the matcher text, and
// the matcher text is not the control.

import {
  readFileSync, writeFileSync, copyFileSync, renameSync, unlinkSync,
  statSync, chmodSync, chownSync, constants,
} from "node:fs";
import { spawnSync } from "node:child_process";
import { homedir } from "node:os";
import path from "node:path";

const HOME = homedir();
const SETTINGS = process.env.HOOK_SETTINGS || path.join(HOME, ".claude/settings.json");
const SWEEP = process.env.HOOK_SWEEP || path.join(HOME, "dev/warden-memory/scripts/audit-hook-matchers.mjs");
const WRAPPER = process.env.CTX_WRAP || path.join(HOME, ".local/bin/dcg-ctx-wrap");
const DRY = process.argv.includes("--dry-run");

// The sweep spawns hooks, so it can hang. Unbounded, a hung sweep used to leave a patched
// but unverified settings.json live while this process waited forever.
const SWEEP_TIMEOUT_MS = Number(process.env.HOOK_SWEEP_TIMEOUT_MS || 120000);

// Loose UNANCHORED match: hits the legacy `mcp__context-mode__*` names, the live
// `mcp__plugin_context-mode_context-mode__*` names, and any future prefix.
const LOOSE = "context-mode__ctx_(execute|execute_file|batch_execute)";

const CTX_NAMESPACE = /context-mode__ctx_/;

// The live context-mode tool names this matcher has to cover. Used both to assert the
// patched matcher actually matches something (below) and to document what LOOSE is for.
const LIVE_CTX_TOOLS = [
  "mcp__plugin_context-mode_context-mode__ctx_execute",
  "mcp__plugin_context-mode_context-mode__ctx_execute_file",
  "mcp__plugin_context-mode_context-mode__ctx_batch_execute",
  "mcp__context-mode__ctx_execute",
];

// Is this entry one of OURS — a matcher that routes the context-mode EXEC surfaces?
//
// The test has to be SEMANTIC, not textual. A matcher is a regex, so the LOOSE string itself
// reads `context-mode__ctx_(execute|execute_file|batch_execute)` — a literal `ctx_execute`
// substring test does not match it, and narrowing the old `/context-mode__ctx_/` that way
// silently stopped recognising every already-current entry. Asking "does this matcher
// actually select an exec tool name?" is both the property we care about and immune to how
// the matcher happens to be spelled.
//
// It matters because a bare namespace test also swept in ctx_search / ctx_index / ctx_purge —
// which this fleet's context-mode plugin really does expose — and every match got its matcher
// REWRITTEN to the exec triple, breaking an unrelated guard two ways at once: it stops
// matching its own tools, and its hook command starts firing on exec calls it never handled.
const isExecCtxEntry = (e) => {
  const m = (e && e.matcher) || "";
  if (!CTX_NAMESPACE.test(m)) return false;
  try {
    const re = new RegExp(m);
    return LIVE_CTX_TOOLS.some((t) => re.test(t));
  } catch {
    // An unparseable matcher cannot be shown to belong to someone else's control, and it
    // sits in the context-mode namespace. Claim it so it gets repaired rather than skipped.
    return true;
  }
};

// Uncaught, a missing file / permission error / malformed JSON threw a bare Node stack
// trace before any of this script's structured messages could run.
let cfg;
try {
  cfg = JSON.parse(readFileSync(SETTINGS, "utf8"));
} catch (err) {
  console.error(`cannot read or parse ${SETTINGS}: ${err.message}`);
  process.exit(1);
}
const pre = cfg.hooks?.PreToolUse || [];

// Two DIFFERENT states used to collapse into one "already current — exit 0":
//   (a) every context-mode matcher is already LOOSE  -> genuinely nothing to do;
//   (b) there is NO context-mode matcher at all      -> the control is ABSENT.
// (b) is precisely the "control gone dark" condition this script exists to remediate, and
// reporting success on it means the remediation tool green-ticks the vulnerability it was
// written to close. Separate the two before deciding anything.
// An entry is only a FUNCTIONING control if it actually runs something. A matcher with
// `hooks: []`, a missing hooks array, or a blank command is a matcher-shaped hole: it matches
// the tool and then does nothing, and "already current" over one of those is the same false
// green as reporting success when no matcher exists at all.
// `type` is required because Claude Code's hook schema documents it as REQUIRED — one of
// command | http | mcp_tool | prompt | agent. The wiring snippet in this repo's README carries
// it, and every PreToolUse entry in the live canonical settings.json carries it, while every
// fixture in the suite omitted it — so the suite could not surface the gap. A tool whose sole
// purpose is to refuse to green-tick a control it has not proven live must not accept
// out-of-schema config as proof. Only a `command` hook can route to the wrapper anyway, so a
// non-command hook is not a functioning ctx control for anything this script decides.
const isCommandHook = (h) =>
  h && h.type === "command" && typeof h.command === "string" && h.command.trim() !== "";

const runs = (e) => Array.isArray(e.hooks) && e.hooks.some(isCommandHook);

// ── What the hook command ACTUALLY execs ─────────────────────────────────────────────────
//
// The old test was `h.command.includes(path.basename(WRAPPER))` — a substring anywhere in the
// command string — and canary 3 then spawned the CTX_WRAP constant rather than the command in
// settings.json. Nothing tied the binary that got exercised to the binary the harness will
// exec. Measured, four commands satisfied the old test while routing nowhere near the wrapper,
// and every one published green at rc 0: `/opt/old/dcg-ctx-wrap` (absent),
// `~/.local/bin/dcg-ctx-wrap.bak` (absent), `echo dcg-ctx-wrap` (a no-op that prints the name)
// and `true # dcg-ctx-wrap` (a comment mentioning it). That is the same
// validate-the-string-never-the-target false green the routing gate below exists to remove,
// one layer further out, and it voided the README's central claim that canary 3 is what proves
// the real scanner is on the path.
//
// So: take the FIRST argv token of the command, require its basename to EQUAL the wrapper's
// (not contain it), and require an absolute path. A bare `dcg-ctx-wrap` is refused for the
// same reason this script uses process.execPath instead of a PATH lookup for `node`: under a
// systemd unit, a cron entry or an nvm shell the lookup resolves to a different inode or to
// nothing at all, and Claude Code hooks inherit exactly that problem. The path this resolves
// is the one the canaries run — that binding is the whole point.
// The regex is ANCHORED AT BOTH ENDS: the command must be that one token and NOTHING else.
//
// Matching only the FIRST token left everything after it invisible, because the harness runs
// the hook THROUGH A SHELL while canary 3 spawns the binary directly. Measured, both published
// green at rc 0 with a stub that genuinely emitted a scanner-sourced deny — so canary 3's own
// criterion was satisfied by a binary whose output the live command then threw away or flipped:
//   `/abs/dcg-ctx-wrap >/dev/null`        the shell emits nothing; the harness sees no decision
//                                          and the guarded call proceeds. The control is DARK.
//   `/abs/dcg-ctx-wrap | sed s/deny/allow/` the shell emits permissionDecision "allow".
//                                          A deny laundered into an allow, certified green.
// So no redirect, no pipe, no argument, no `;` chain, no trailing comment. A tool that
// certifies a control must refuse anything it cannot execute end-to-end rather than green-tick
// it. Metacharacters spelled without a space (`/abs/dcg-ctx-wrap|sed`) fail the basename test
// below instead — the `;` neighbour was already refused that way, by accident rather than by
// design, which is exactly the sort of accident not to keep depending on.
//
// The tilde expansion is kept, and it is also the artifact's own admission that a shell is
// involved: nothing but a shell expands `~`.
const soleArgv0 = (command) => {
  const m = String(command).trim().match(/^"([^"]+)"$|^'([^']+)'$|^(\S+)$/);
  const tok = m ? (m[1] || m[2] || m[3] || "") : "";
  return tok.startsWith("~/") ? path.join(HOME, tok.slice(2)) : tok;
};

// ── THE ONE PREDICATE ────────────────────────────────────────────────────────────────────
//
// Three rounds produced three instances of ONE class: THE CHECK AND THE THING CHECKED WERE
// DIFFERENT OBJECTS.
//   R2  T5    validated the matcher STRING and never what it routed to.
//   R4/5 T-R1 validated one binary while canary 3 spawned a different one.
//   R6  T1    validated the first argv token while the rest of the command sent the verdict to
//             /dev/null, or piped it through `sed s/deny/allow/` and inverted it.
// Each was repaired at its own site, and each repair bought exactly one more variant. So the
// distinction is encoded ONCE, here, and every site that decides "does this entry deliver a
// scanner verdict?" consults it instead of re-deriving its own answer. Two halves, named for
// what they actually are:
//
//   hookCommand(h)     IDENTITY — the EXACT command string the harness will exec, or "".
//   deliversVerdict()  DELIVERY — run THAT string the way the harness runs it and see what
//                      arrives. Defined with the canaries below, because it must execute.
//
// Identity alone would have made the divergence moot rather than closed: constrain the command
// to a single absolute token and spawning the binary directly happens to be equivalent — until
// someone relaxes the constraint for a good reason (an `env VAR=x` prefix, an interpreter, a
// launcher) and the canary silently goes back to certifying something the harness never runs.
// Delivery tests the property we actually care about, so it survives that relaxation.
const wrapperName = path.basename(WRAPPER);

const hookCommand = (h) => {
  if (!isCommandHook(h)) return "";
  const bin = soleArgv0(h.command);
  if (!bin || path.basename(bin) !== wrapperName) return "";
  if (!path.isAbsolute(bin)) return "";
  return String(h.command).trim();
};
const entryCommand = (e) =>
  (Array.isArray(e.hooks) ? e.hooks : []).map(hookCommand).find(Boolean) || "";
const routesToWrapper = (e) => entryCommand(e) !== "";
// The resolved binary, for the one consumer that needs a PATH rather than a command: the
// coverage sweep takes CTX_WRAP as a binary. Derived FROM the predicate, never independently.
const entryWrapperPath = (e) => {
  const cmd = entryCommand(e);
  return cmd ? soleArgv0(cmd) : "";
};

const ctxEntries = pre.filter(isExecCtxEntry);
const hollow = ctxEntries.filter((e) => !runs(e));

// ONLY our own entry gets rewritten. The old `filter((e) => e.matcher !== LOOSE)` selected
// EVERY entry whose matcher happens to select an exec tool name and overwrote each one's
// matcher with LOOSE — while the routing gate below proves only that AT LEAST ONE entry
// reaches the wrapper. The rest are other people's controls. Measured both directions, with
// this script's own entry present and correct:
//   over-firing — a narrower `..._ctx_execute_file` entry owned by `/usr/local/bin/
//   file-policy-hook` was widened to the exec triple, so that hook began firing on
//   ctx_execute and ctx_batch_execute and no longer uniquely selected its own tool;
//   going DARK, the sharper half — a mixed `context-mode__ctx_(execute|search)` matcher owned
//   by another guard was rewritten to the exec triple, after which it no longer matched
//   ctx_search AT ALL. That guard's coverage vanished, published under "all three canaries
//   green" at rc 0.
// A tool whose entire purpose is to keep a control live must not silently remove a different
// control's coverage and report success. The shape is real on this fleet: TEAM-1 routes the
// same tools to the bash dispatcher as a second entry. A pure `ctx_search` entry already
// survived untouched — that is the case the suite pins, and precisely why the mixed one slipped.
const targets = ctxEntries.filter((e) => e.matcher !== LOOSE && routesToWrapper(e));

if (ctxEntries.length > 0 && hollow.length === ctxEntries.length) {
  console.error(
    `every context-mode matcher in ${SETTINGS} is present but runs NOTHING ` +
    `(${hollow.length} entr${hollow.length === 1 ? "y" : "ies"} with no usable hook command).\n` +
    "That is the control being absent wearing a matcher, not a stale matcher to rewrite.\n" +
    "Rewriting the matcher string would leave it just as inert, so this stops instead."
  );
  process.exit(1);
}
if (hollow.length > 0) {
  console.warn(
    `NOTE ${hollow.length} context-mode matcher(s) carry no usable hook command and will be ` +
    "rewritten but remain inert; fix their hooks separately."
  );
}

// A matcher string is not a control. It has to ROUTE somewhere, and specifically to the ctx
// wrapper this script exists to keep on the path.
//
// Found by an independent merge-authority probe, and it is not hypothetical: on the laptop
// seat the ctx matcher sits at LOOSE-equivalent and routes to `warden-bash-dispatcher.js`
// while `dcg-ctx-wrap` is absent from the machine entirely — so this tool reported the control
// "already current" with dcg nowhere on the path. Validating the string and never the target
// is the same false-green shape as the two states F4 collapsed.
//
// Only ONE ctx entry needs to reach the wrapper: a host may legitimately carry a second entry
// routing the same tools to another guard (TEAM-1 routes them to the bash dispatcher as well).
// This is the binary the LIVE hook execs — resolved FROM settings.json, not from CTX_WRAP.
// Everything downstream that claims to have exercised the scanner runs THIS path, so a host
// whose hook points somewhere other than the installed wrapper can no longer be green-ticked
// by testing the installed wrapper instead.
const LIVE_COMMAND = ctxEntries.map(entryCommand).find(Boolean) || "";
const LIVE_WRAPPER = LIVE_COMMAND ? soleArgv0(LIVE_COMMAND) : "";

if (ctxEntries.length > 0 && !LIVE_COMMAND) {
  console.error(
    `context-mode matcher(s) exist in ${SETTINGS} but NONE execs '${wrapperName}'.\n` +
    "The matcher string is not the control — the hook command is. Rewriting the matcher would\n" +
    "leave the ctx surfaces going somewhere else entirely, so this stops instead.\n" +
    "The command must BE the wrapper and nothing else — a single absolute path whose basename\n" +
    `is exactly '${wrapperName}'. A command that merely mentions the name (a .bak copy, an\n` +
    "`echo`, a trailing comment) routes nowhere, and a bare PATH lookup resolves differently\n" +
    "under systemd, cron and nvm than it does in your shell.\n" +
    "Anything AFTER that path is refused too, because the hook runs through a shell while the\n" +
    "canaries run the binary: `> /dev/null` would leave the harness with no decision at all,\n" +
    "and `| sed s/deny/allow/` would turn a denial into an approval, both while the wrapper\n" +
    "itself behaved perfectly. If you need a wrapper script, point the hook AT that script.\n" +
    "Point one context-mode entry's hook command at the wrapper, then re-run."
  );
  process.exit(1);
}

if (ctxEntries.length === 0) {
  console.error(
    `NO context-mode PreToolUse matcher exists in ${SETTINGS}.\n` +
    "This is NOT 'already current' — it is the control being absent entirely, which is the\n" +
    "condition this script exists to remediate. There is no stale matcher to rewrite, so a\n" +
    "matcher must be ADDED (with its hook command) before this script can do anything.\n" +
    `Expected a PreToolUse entry whose matcher covers: ${LIVE_CTX_TOOLS.join(", ")}`
  );
  process.exit(1);
}

// Text only. It is handed to the scanner as DATA and never executed; it is here because it
// is in dcg's default packs, so a working control must object to it.
const DANGEROUS_FIXTURE = "git reset --hard origin/main";

// ── The three canaries. Both the already-current and the patch path run all three. ──

// 1. The matcher that will be LIVE must match the live tool names. This reads the file BACK
//    rather than testing LOOSE against LIVE_CTX_TOOLS: both are constants in this file, so
//    that form was a tautology which could only fail if someone edited this source, and it
//    could not notice a skipped entry, a second still-stale entry, or a mangled write.
const canaryMatcher = (settingsPath, fail) => {
  let written;
  try {
    written = JSON.parse(readFileSync(settingsPath, "utf8")).hooks?.PreToolUse || [];
  } catch (err) {
    fail(`CANARY FAILED — cannot read back ${settingsPath} (${err.message})`);
  }
  const ctxWritten = written.filter(isExecCtxEntry);
  const unmatched = LIVE_CTX_TOOLS.filter(
    (t) => !ctxWritten.some((e) => {
      try { return new RegExp(e.matcher).test(t); } catch { return false; }
    })
  );
  if (!ctxWritten.length || unmatched.length) {
    fail(
      "CANARY FAILED — the matcher on disk does not match live context-mode tool names:\n  " +
      (unmatched.join("\n  ") || "(no context-mode entry survived the write)")
    );
  }
  console.log(`canary 1: matcher on disk matches all ${LIVE_CTX_TOOLS.length} known ctx tool names`);
};

// 2. The coverage sweep must go green against the file under test.
const canarySweep = (settingsPath, fail) => {
  const r = spawnSync(process.execPath, [SWEEP], {
    encoding: "utf8",
    timeout: SWEEP_TIMEOUT_MS,
    killSignal: "SIGTERM",
    // process.execPath, not a PATH lookup for "node": under a systemd unit, a cron entry or
    // an nvm shell the lookup picks a different runtime or fails outright, and a correct
    // patch then gets refused for an environment reason.
    // LIVE_WRAPPER, not WRAPPER: the sweep must exercise the binary the hook in this very
    // settings file execs, not the one CTX_WRAP happens to name.
    env: { ...process.env, HOOK_SETTINGS: settingsPath, CTX_WRAP: LIVE_WRAPPER },
  });
  process.stdout.write(r.stdout || "");
  // Diagnostics conventionally go to stderr. Swallowing it left the operator with
  // "CANARY FAILED (sweep exit 3)" and nothing about why, on the one path where that
  // information decides what to do next.
  process.stderr.write(r.stderr || "");
  if (r.error) {
    const how = r.error.code === "ETIMEDOUT"
      ? `timed out after ${SWEEP_TIMEOUT_MS}ms` : r.error.message;
    fail(`CANARY FAILED — coverage sweep ${SWEEP} ${how}`);
  }
  if (r.status !== 0) {
    const how = r.status === null ? `killed by ${r.signal}` : `exit ${r.status}`;
    fail(`CANARY FAILED (sweep ${how})`);
  }
  console.log("canary 2: coverage sweep green");
};

// 3. Prove the SCANNER produced the denial, not the adapter.
//
//    Since the adapter went fail-closed, a missing, unexecutable, hung or crashed dcg-wrap
//    DENIES — so "something said DENY" no longer separates a working control from a dark
//    one, and the sweep's own criterion is exactly `covered = (decision === "DENY")`. The
//    adapter cannot settle it from the inside either: a scanner that exits 0 having done
//    nothing is indistinguishable on the wire from a clean scan. It IS separable here,
//    because every adapter-generated denial's reason starts with the literal
//    `dcg-ctx-wrap: `, while a real verdict is forwarded untouched carrying dcg's own text.
//
//    This is the DELIVERY half of the predicate above. It runs LIVE_COMMAND — the WHOLE hook
//    command string out of settings.json — THROUGH A SHELL, exactly as the harness runs it,
//    and requires a scanner-sourced deny to actually ARRIVE ON STDOUT. It does not spawn a
//    resolved binary, because "the binary denies" and "the harness receives a denial" are
//    different claims, and every variant of this defect has lived in that gap.
//
//    Testing arrival rather than shape is what makes this robust to shapes nobody enumerated:
//    a command that redirects the verdict away fails because NOTHING arrives, and one that
//    pipes it through `sed s/deny/allow/` fails because an ALLOW arrives. Neither needs to be
//    on a list. The earlier version spawned the CTX_WRAP constant, which let four non-routing
//    commands publish green; the version after that spawned the resolved binary, which let a
//    redirect and a pipe publish green with the wrapper behaving perfectly.
const canaryScanner = (fail) => {
  const r = spawnSync(LIVE_COMMAND, {
    shell: true,
    input: JSON.stringify({
      tool_name: "mcp__plugin_context-mode_context-mode__ctx_execute",
      tool_input: { code: DANGEROUS_FIXTURE, language: "shell" },
    }),
    encoding: "utf8",
    timeout: 30000,
  });
  if (r.error) {
    fail(
      `CANARY FAILED — cannot run the hook command (${r.error.message}):\n  ${LIVE_COMMAND}\n` +
      "That is the command string read out of the settings file, run the way the harness runs\n" +
      "it — so the control this file describes does not work on this host."
    );
  }
  // A denial the host would discard is not a denial. The host treats 2 as blocking and every
  // other non-zero as NON-blocking, after which the tool proceeds — so a well-formed deny that
  // exits 3 reads as "guarded" here and runs anyway there. The wrapper this repo ships
  // normalises to 0 or 2 and cannot reach that state; a same-basename binary that the repo
  // neither ships nor describes can, and this canary exists to judge whatever is actually wired.
  if (r.status !== 0 && r.status !== 2) {
    fail(
      `CANARY FAILED — the hook command exited ${r.status === null ? `on ${r.signal}` : r.status},\n` +
      "which the host reads as NON-blocking: the tool would proceed despite the denial.\n" +
      "Only 0 and 2 are honoured."
    );
  }
  let out;
  try {
    out = JSON.parse(r.stdout || "");
  } catch {
    fail(
      "CANARY FAILED — no decision ARRIVED for a known-dangerous fixture. The hook command\n" +
      `produced ${r.stdout ? "unparseable output" : "NOTHING ON STDOUT"}:\n  ${LIVE_COMMAND}\n` +
      "The wrapper may well be denying; what matters is that the harness never receives it."
    );
  }
  const hso = (out && out.hookSpecificOutput) || {};
  if (hso.permissionDecision !== "deny") {
    fail(
      "CANARY FAILED — a known-dangerous fixture was NOT denied.\n" +
      "The ctx surface is not actually being scanned."
    );
  }
  const reason = String(hso.permissionDecisionReason || "");
  if (reason.startsWith("dcg-ctx-wrap:")) {
    fail(
      "CANARY FAILED — the DENY came from the ADAPTER, not the scanner:\n  " +
      reason.slice(0, 200) + "\n" +
      "That is the control being DARK while emitting the right word. Install/repair dcg-wrap."
    );
  }
  console.log("canary 3: a known-dangerous fixture was denied BY THE SCANNER");
};

const verify = (settingsPath, fail) => {
  canaryMatcher(settingsPath, fail);
  canarySweep(settingsPath, fail);
  canaryScanner(fail);
};

if (targets.length === 0) {
  // "Nothing to patch" is NOT "verified working". The matcher may name a wrapper that is
  // not installed, or route somewhere that never reaches the scanner. This branch used to
  // exit 0 before any canary ran, so on the ordinary steady-state host the remediation tool
  // reported success having verified nothing executable at all — the same false-green class
  // the routing check was added to remove.
  console.log(
    `matcher text already current — ${ctxEntries.length} context-mode matcher(s) at LOOSE; ` +
    "verifying the control actually works"
  );
  if (DRY) process.exit(0);
  verify(SETTINGS, (why) => {
    console.error(`\n${why}`);
    process.exit(1);
  });
  console.log("\nalready current — matchers at LOOSE and the control is live");
  process.exit(0);
}
for (const e of targets) {
  console.log(`  ${e.matcher}\n→ ${LOOSE}   [${(e.hooks || []).map((h) => h.command).join(", ")}]`);
  if (!DRY) e.matcher = LOOSE;
}
if (DRY) process.exit(0);

// CANARY THE CANDIDATE, THEN PUBLISH — in that order.
//
// Renaming first made the change live, and fanned out to every seat on the 15-minute
// renderer cycle, BEFORE anything had verified it. A Ctrl-C or a hung sweep inside that
// window left an unverified matcher in force with nothing to signal it, and the automatic
// rollback never ran. Worse, that rollback was itself a truncating in-place copyFileSync,
// running on the failure path where an interruption is likeliest — the very write the
// temp-and-rename exists to avoid.
//
// Verifying the candidate first deletes the whole rollback path: on red, settings.json was
// never touched at all, which is strictly stronger than modified-then-restored.
// Stat the SOURCE before the candidate exists — every mode decision below is derived from it.
const orig = statSync(SETTINGS);

const tmpPath = `${SETTINGS}.tmp-wi2096-${process.pid}`;

// The candidate is created at 0600 REGARDLESS of the source's mode, and only widened to the
// source's mode once the bytes are down. It used to be created at the umask default (0644
// under a typical 022) and chmod'd afterwards, so a COMPLETE copy of the settings document —
// which on this fleet is a 0600 file carrying an env block with tokens — sat world-readable
// for the length of the write. A mode passed at creation is still masked by umask, and umask
// can only REMOVE bits, so this is never wider than 0600 and never wider than the source.
// `flag: "wx"` — EXCLUSIVE create, and it is what makes the 0600 claim above actually true.
// Measured: `mode` applies ONLY at creation, so a path already present at 0644 stayed 0644
// straight through `writeFileSync(…, {mode: 0o600})`; worse, a SYMLINK at that path was
// FOLLOWED, landing the entire settings document — env block and tokens included — in whatever
// the link pointed at. Exclusive create refuses both with EEXIST. Reachability is narrow (a
// stale same-PID leftover, or a writable settings directory), but this was the one remaining
// path on which this file's own stated invariant did not hold.
try {
  writeFileSync(tmpPath, JSON.stringify(cfg, null, 2) + "\n", { mode: 0o600, flag: "wx" });
} catch (err) {
  if (err.code === "EEXIST") {
    console.error(
      `refusing to write the candidate: ${tmpPath} already exists.\n` +
      "It is a stale leftover or a planted symlink. This script will not write the settings\n" +
      "document through a path it did not create — remove it and re-run."
    );
  } else {
    console.error(`cannot write the candidate ${tmpPath}: ${err.message}`);
  }
  process.exit(1);
}

// An uncaught throw anywhere between the write and the rename left that candidate orphaned on
// disk, holding the whole document, outliving the process with nothing downstream to remove
// it. `abort()` covers the paths this script controls; this covers the ones it does not.
let tmpLive = true;
const dropTmp = () => {
  if (!tmpLive) return;
  tmpLive = false;
  try {
    unlinkSync(tmpPath);
  } catch {
    // Already gone — renamed into place, or removed by an earlier path.
  }
};
process.on("exit", dropTmp);

// rename() replaces the inode, so without this the published file inherits the temp file's
// mode and this process's ownership instead of the original's. A 0600 file silently becoming
// world-readable is a credential exposure; and a sudo run would flip ownership and cost the
// renderer its write access on the next sync.
chmodSync(tmpPath, orig.mode & 0o7777);
try {
  chownSync(tmpPath, orig.uid, orig.gid);
} catch {
  // Non-root run: the file is already ours, so there is nothing to restore.
}

const abort = (why) => {
  dropTmp();
  console.error(`\n${why}\n${SETTINGS} was NOT modified.`);
  process.exit(1);
};

verify(tmpPath, abort);

// Only now does anything become live, and the backup is taken against the file actually
// being replaced. COPYFILE_EXCL: a millisecond-resolution stamp can still collide in a loop,
// a parallel fan-out or a retry wrapper, and a silent overwrite destroys the last
// known-good copy — precisely the bug the timestamp was added to fix.
const stamp = new Date().toISOString().replace(/[:.]/g, "-");
const backup = `${SETTINGS}.bak-wi2096-${stamp}-${process.pid}`;
try {
  copyFileSync(SETTINGS, backup, constants.COPYFILE_EXCL);
} catch (err) {
  abort(`refusing to publish — could not take a backup at ${backup} (${err.message})`);
}
renameSync(tmpPath, SETTINGS);
tmpLive = false;  // published, not orphaned — the exit hook must not chase the old path
console.log(
  `\npatched ${targets.length} matcher(s) — all three canaries green BEFORE publish.` +
  `\nRollback: cp ${backup} ${SETTINGS}`
);
