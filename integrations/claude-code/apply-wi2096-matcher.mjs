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
import { createHash } from "node:crypto";
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
let srcBytes;
try {
  srcBytes = readFileSync(SETTINGS, "utf8");
  cfg = JSON.parse(srcBytes);
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
// it.
//
// ── WHAT IS CLOSED AND WHAT IS NOT — stated exactly, on purpose ──────────────────────────
// The previous version of this comment claimed more than the code enforced, and that is the
// mechanism by which this class survived four rounds: each remedy declared victory slightly
// wider than it had earned, and the next reader believed the declaration and stopped looking.
// It said metacharacters spelled without a space "fail the basename test below". That is true
// only for a metacharacter AFTER the last `/` — `/abs/dcg-ctx-wrap|sed` does fail it — and
// FALSE for every earlier path segment. `/opt/$(touch /tmp/pwn)w/dcg-ctx-wrap` is one
// whitespace-free token, its basename is exactly right, it is absolute, and the basename test
// never looks at its interior. Measured: all three canaries green, rc 0, settings PUBLISHED,
// and the substitution had already run — because canary 3 hands this string to `shell: true`.
//
// CLOSED BY THE CHECK BELOW: the first token must be a SHELL LITERAL — a whitelist of
// characters a shell passes through unchanged — applied to the WHOLE token, interior segments
// included, before the string ever reaches a shell.
// NOT CLOSED BY IT: everything after that first token is refused by the anchored match above,
// not by this whitelist. And a legitimate path carrying a character outside the whitelist (a
// space, a quote) is REFUSED, not escaped and not made to work — it fails closed and says so.
//
// A WHITELIST, not a blacklist of metacharacters. Each of the previous three remedies was
// beaten by a shape nobody had enumerated; a whitelist cannot be outflanked by a character no
// one thought of, which is the only property that makes this different from its predecessors.
//
// A leading `~/` is expanded by the shell under HOME. Module-load os.homedir() is not that
// HOME: the harness overlays the settings `env` block, which may set HOME to something else.
// Expanding with os.homedir() for identity while canary 3 / the harness expand under the
// overlay is two inodes for one command. So `~/` is accepted only when HOME (or USERPROFILE)
// is a key in this document's env block — the same establishment rule as PATH — and identity
// uses that declared value. Otherwise the token is refused: use an absolute path.
const SHELL_LITERAL = /^[A-Za-z0-9_@%+=:,.\/-]+$/;
const declaredHome = () => {
  const block = cfg && cfg.env;
  if (!block || typeof block !== "object" || Array.isArray(block)) return "";
  if (Object.prototype.hasOwnProperty.call(block, "HOME")) return String(block.HOME);
  if (Object.prototype.hasOwnProperty.call(block, "USERPROFILE")) return String(block.USERPROFILE);
  return "";
};
const soleArgv0 = (command) => {
  const m = String(command).trim().match(/^"([^"]+)"$|^'([^']+)'$|^(\S+)$/);
  const tok = m ? (m[1] || m[2] || m[3] || "") : "";
  if (!tok) return "";
  // Tested AS THE SHELL WILL SEE IT — before tilde expansion, because `~` is itself a shell
  // construct and the expanded form is not the string that gets executed. A quoted token is
  // tested on its CONTENTS: inside double quotes `$` and a backtick are still live, and
  // treating single quotes as safe would mean two rules where one fails closed.
  if (!SHELL_LITERAL.test(tok.startsWith("~/") ? tok.slice(2) : tok)) return "";
  if (tok.startsWith("~/")) {
    const h = declaredHome();
    if (!h) return "";
    return path.join(h, tok.slice(2));
  }
  return tok;
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
const commandHooksOf = (e) => (Array.isArray(e.hooks) ? e.hooks : []).filter(isCommandHook);
const entryRoutingCommands = (e) => commandHooksOf(e).map(hookCommand).filter(Boolean);
const entryCommand = (e) => entryRoutingCommands(e)[0] || "";
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
// routesToWrapper is a basename check. Collecting one command per ENTRY left a second
// hook on the SAME entry invisible: canary 3 ran the first, publish widened the matcher,
// and the sibling started firing on tools it never handled (another wrapper, or a foreign
// command). Walk every command hook. Mixed wrapper+other is a refuse — rewriting that
// matcher would drag the other command onto the exec triple.
const mixed = ctxEntries.filter((e) => {
  const nCmd = commandHooksOf(e).length;
  const nRoute = entryRoutingCommands(e).length;
  return nRoute > 0 && nRoute < nCmd;
});
if (mixed.length) {
  console.error(
    `a context-mode entry in ${SETTINGS} mixes a '${wrapperName}' hook with another command.\n` +
    "Rewriting its matcher would make the other command fire on tools it never handled.\n" +
    "Give that other command its own matcher, then re-run."
  );
  process.exit(1);
}

const routingCommands = ctxEntries.flatMap(entryRoutingCommands);
const uniqueRouting = [...new Set(routingCommands)];
const LIVE_COMMAND = uniqueRouting[0] || "";
const LIVE_WRAPPER = LIVE_COMMAND ? soleArgv0(LIVE_COMMAND) : "";

if (uniqueRouting.length > 1) {
  console.error(
    `context-mode entries in ${SETTINGS} route to ${uniqueRouting.length} different ` +
    `'${wrapperName}' binaries:\n` +
    uniqueRouting.map((c) => `  ${c}`).join("\n") + "\n" +
    "Canary 3 exercises one hook command; a publish rewrites every non-LOOSE routing entry.\n" +
    "Those have to be the same object, or a green certificate names one binary and widens another.\n" +
    "Point every routing entry at the same absolute path, then re-run."
  );
  process.exit(1);
}

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
    "The path itself must also be a plain literal — letters, digits and _ @ % + = : , . / -.\n" +
    "A leading `~/` is accepted only when HOME (or USERPROFILE) is declared in this file's\n" +
    "env block, because the shell expands it under that HOME; otherwise use an absolute path.\n" +
    "The whitelist covers the INTERIOR of the path, not just its last segment: a shell\n" +
    "construct in any earlier segment (for example\n" +
    "`/opt/$(...)/" + wrapperName + "`) is executed by the shell the moment this tool tests\n" +
    "the command, so it is refused before that can happen. A path containing anything outside\n" +
    "that set — a space, a quote — is refused rather than escaped; rename or symlink it.\n" +
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

// ── THE CANARY ENVIRONMENT ───────────────────────────────────────────────────────────────
//
// CONTRACT (fail-closed). The harness composes `{...ambient, ...settingsEnv}` — measured,
// with a negative control, against Claude Code 2.1.238 (probe below). This process's
// environment is not ambient. A desktop entry, a systemd unit and cron each supply a
// different one, and this tool cannot observe any of them. Round 9 inherited this process
// and printed green over a dark control. Round 10 invented PATH=/usr/bin:/bin and printed
// green the other way. Substituting an environment is the class. This tool refuses instead.
//
// Establishing the environment means: PATH, PYTHONPATH, PYTHONHOME and PYTHONSTARTUP are
// keys in the settings document's `env` block. Empty string is a declaration (it dominates
// ambient with empty). A missing key is not. The canary uses those declared values and
// nothing it invented; the harness overlays the same block; the four names therefore agree.
//
// When any of the four is missing, this tool REFUSES TO CERTIFY. It does not invent a PATH
// floor, it does not inherit this process's selectors, and it does not run a canary under a
// substitute and then print a narrower claim. settings.json is not touched.
//
// CLOSED: those four names, for this settings document. A bare DCG_WRAP_BIN is resolved
// against the declared PATH, so canary and hook agree on it too.
// NOT CLOSED, and a green line that omits this list is a lie: native preload (LD_PRELOAD,
// LD_LIBRARY_PATH, DYLD_INSERT_LIBRARIES, DYLD_LIBRARY_PATH); any env name not in the four;
// other settings scopes (enterprise, project, --settings); HOME, used only for the wrapper's
// default scanner path when DCG_WRAP_BIN is unset.
//
// THE COMPOSITION WAS MEASURED AGAINST THE HARNESS, NOT ASSUMED. A PreToolUse hook, the same
// event this control is, was spawned by Claude Code 2.1.238 with a probe variable set to one
// sentinel in the launching shell and a DIFFERENT sentinel in the settings `env` block. The
// hook observed the CONFIG sentinel. A variable present only in the shell still arrived, and
// one present only in the config also arrived. With the `env` block removed and nothing else
// changed, the same hook observed the SHELL sentinel — the negative control. Values are
// coerced by plain string conversion (`42`, `true`, `null`, `x,y`, `[object Object]`) —
// `String(v)` reproduces all five.
//
// BOUNDARY: this honours the `env` block of THE SETTINGS DOCUMENT UNDER TEST — the candidate
// on the patch path, the live file on the already-current path. An `env` that is not a JSON
// object is treated as absent, which fails the pin check rather than being filled in.
const configEnv = (settingsPath, fail) => {
  let block;
  try {
    // Read from the document under test rather than from the `cfg` parsed at the top: the
    // candidate is what gets published, and "the object we serialised" and "the file the
    // harness will read" being ASSUMED identical is precisely the class this file has spent
    // its rounds closing.
    block = JSON.parse(readFileSync(settingsPath, "utf8")).env;
  } catch (err) {
    fail(`CANARY FAILED — cannot read the env block from ${settingsPath} (${err.message})`);
    return {};
  }
  if (!block || typeof block !== "object" || Array.isArray(block)) return {};
  return Object.fromEntries(Object.entries(block).map(([k, v]) => [k, String(v)]));
};

// The ONLY names that survive from this process into a canary. Everything here is required to
// start an interpreter at all or to let it find the user's own files; nothing here selects
// WHICH interpreter or WHAT it loads. `DCG_WRAP_BIN` is absent, which is how the operator's
// scanner choice is refused — by construction now, rather than by a `delete` that had to name
// it.
const CANARY_ENV_KEEP = new Set([
  // The wrapper resolves `~` for its default scanner, so losing HOME changes which path it
  // resolves — a divergence of exactly the kind this function exists to prevent.
  "HOME", "USERPROFILE",
  // Decoding of the scanner's own output. A different locale can change how the verdict text
  // is read back, and the reason string is load-bearing here.
  "LANG", "LC_ALL", "LC_CTYPE",
  "TMPDIR", "TEMP", "TMP",
  // cmd.exe cannot start at all without these, so on win32 dropping them would make every
  // canary fail for a reason that has nothing to do with the control.
  "SystemRoot", "COMSPEC", "PATHEXT", "WINDIR", "SYSTEMDRIVE",
]);

// The four names the shipped adapter's process-start consults that ambient can set, and that
// the settings overlay can dominate. Not a claim that the selector set is closed — the green
// line names what is not established. A fifth name is a new pin, not a silent expansion of
// the certificate.
const HOOK_ENV_PINS = ["PATH", "PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP"];

// Recorded at the moment of use, quoted by the success line and by refusals. Recomputing
// it for the message would let the message and the run drift apart.
let declaredEnv = {};

const missingPins = (declared) =>
  HOOK_ENV_PINS.filter((k) => !Object.prototype.hasOwnProperty.call(declared, k));

const pinLines = (declared, missing) =>
  HOOK_ENV_PINS.map((k) => {
    if (missing.includes(k)) return `  ${k}  NOT DECLARED`;
    return `  ${k}=${declared[k]}`;
  }).join("\n");

const refuseUnestablished = (_settingsPath, missing) =>
  `REFUSING TO CERTIFY — ${SETTINGS} env block does not declare ${missing.join(", ")}.\n` +
  "dcg-ctx-wrap is #!/usr/bin/env python3, so PATH selects the interpreter and PYTHONPATH /\n" +
  "PYTHONHOME / PYTHONSTARTUP select what that interpreter imports before the adapter's first\n" +
  "line. This tool cannot observe the harness's ambient environment (a desktop entry, a\n" +
  "systemd unit or cron — not this process). Inventing PATH=/usr/bin:/bin printed green over\n" +
  "a dark control (WI-2096 R10). Inheriting this process printed green the other way (R9).\n" +
  "Declared:\n" + pinLines(declaredEnv, missing) + "\n" +
  "Add the missing names to the env block of the settings file (empty string counts — it\n" +
  "dominates ambient). The harness overlays that block onto every hook, so canary and hook\n" +
  "then read the same four names. Re-run after that. " + SETTINGS + " was NOT modified.";

const canaryEnv = (settingsPath, fail, extra) => {
  const declared = configEnv(settingsPath, fail);
  declaredEnv = declared;
  const missing = missingPins(declared);
  if (missing.length) fail(refuseUnestablished(settingsPath, missing));
  const env = {};
  for (const [k, v] of Object.entries(process.env)) {
    if (CANARY_ENV_KEEP.has(k)) env[k] = v;
  }
  Object.assign(env, declared);   // the settings document — including PATH. No floor.
  // This applier's own pins go LAST so the document under test cannot redirect the canary that
  // is judging it — the sweep must run against LIVE_WRAPPER and the file under test whatever
  // the `env` block says.
  const out = { ...env, ...extra };
  // Node-runtime / native-loader keys from the document must not reach ANY child this
  // certifier spawns. Canary 2 is process.execPath. Test fixtures are Node shebang
  // wrappers. A `--require` in declared NODE_OPTIONS would otherwise execute in the
  // certifier, which production's Python wrapper never starts.
  for (const k of [
    "NODE_OPTIONS", "NODE_PATH", "NODE_REPL_EXTERNAL_MODULE",
    "LD_PRELOAD", "LD_LIBRARY_PATH", "DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH",
  ]) {
    delete out[k];
  }
  return out;
};

const sweepEnv = (settingsPath, fail) => canaryEnv(settingsPath, fail, {
  HOOK_SETTINGS: settingsPath,
  DCG_CTX_WRAP: LIVE_WRAPPER,
  CTX_WRAP: LIVE_WRAPPER,
});

// What the canary environment SELECTED as the scanner, named exactly. When `DCG_WRAP_BIN` is
// set this IS the literal path `dcg-ctx-wrap` will exec; when it is not, the only true
// statement is that nothing selected one. It deliberately does not name the fallback path,
// because the wrapper expands that in ITS OWN process and this file did not resolve it.
const scannerSelection = (env) => env.DCG_WRAP_BIN
  ? `DCG_WRAP_BIN=${env.DCG_WRAP_BIN}`
  : "DCG_WRAP_BIN unset — dcg-ctx-wrap's own default scanner";

// Recorded BY canary 3, AT THE MOMENT OF USE, and quoted verbatim by the success lines.
// Recomputing it for the message would let the message and the run drift apart, which is the
// same two-objects mistake one more layer out.
let scannerUsed = "";

// 2. The coverage sweep must go green against the file under test.
const canarySweep = (settingsPath, fail) => {
  const r = spawnSync(process.execPath, [SWEEP], {
    encoding: "utf8",
    timeout: SWEEP_TIMEOUT_MS,
    killSignal: "SIGTERM",
    // process.execPath, not a PATH lookup for "node": under a systemd unit, a cron entry or
    // an nvm shell the lookup picks a different runtime or fails outright, and a correct
    // patch then gets refused for an environment reason.
    // THE SWEEP READS `DCG_CTX_WRAP`, NOT `CTX_WRAP`. Measured against
    // audit-hook-matchers.mjs:41 (`const CTX_WRAP = process.env.DCG_CTX_WRAP || <default>`).
    // The sweep's LOCAL CONSTANT is named `CTX_WRAP`, which is why a code read misses this —
    // the name matches and the source does not. With only `CTX_WRAP` exported, NEITHER a
    // binary named by it nor one named by `DCG_CTX_WRAP` ran; with both exported to different
    // binaries, `DCG_CTX_WRAP` won and `CTX_WRAP` was ignored. So a pin of only `CTX_WRAP`
    // made canary 2 sweep the sweep's OWN DEFAULT binary — one this applier never resolved.
    //
    // Both names are set. `DCG_CTX_WRAP` is the one the sweep obeys and is the fix; `CTX_WRAP`
    // is this repo's own convention and is kept so a consumer following it is not silently
    // dropped. The first is measured, the second is ours.
    //
    // LIVE_WRAPPER, not WRAPPER, is still the right VALUE: the binary the hook in this
    // settings file execs. Node-runtime selectors from the document are stripped in
    // sweepEnv — they must not reach process.execPath.
    env: sweepEnv(settingsPath, fail),
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

// R16 applies to a REFUSAL as much as to a success line: it is an operator-facing claim, and
// one that does not say how to fix it is a mystery outage. The canary runs on the declared
// env block, so the commonest TRUE refusal here is "the interpreter is on your shell PATH
// but not on the PATH you declared" — the command works when you type it and fails here.
// Naming the declared block keeps the canary and the hook the same object.
const ENV_REMEDY = () =>
  "\n\nIf that command works when you run it by hand, that difference IS the finding, not a bug\n" +
  "in this check. The canaries run on the env block of the settings file — the same block the\n" +
  "harness overlays onto every hook — not on this process and not on an invented PATH floor.\n" +
  "Declared:\n" + pinLines(declaredEnv, []) + "\n" +
  "Change that block, then re-run.";

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
const canaryScanner = (settingsPath, fail) => {
  // Without this the spawn inherits process.env wholesale, DCG_WRAP_BIN included, and this
  // canary — the ONE check that still separates a live scanner from a dark fail-closed
  // adapter — certifies a binary the harness will never resolve. See canaryEnv above.
  const env = canaryEnv(settingsPath, fail);
  scannerUsed = scannerSelection(env);
  const r = spawnSync(LIVE_COMMAND, {
    shell: true,
    input: JSON.stringify({
      tool_name: "mcp__plugin_context-mode_context-mode__ctx_execute",
      tool_input: { code: DANGEROUS_FIXTURE, language: "shell" },
    }),
    encoding: "utf8",
    timeout: 30000,
    env,
  });
  if (r.error) {
    fail(
      `CANARY FAILED — cannot run the hook command (${r.error.message}):\n  ${LIVE_COMMAND}\n` +
      "That is the command string read out of the settings file, run the way the harness runs\n" +
      "it — so the control this file describes does not work on this host." + ENV_REMEDY()
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
      `Only 0 and 2 are honoured.\n  ${LIVE_COMMAND}` + ENV_REMEDY()
    );
  }
  let out;
  try {
    out = JSON.parse(r.stdout || "");
  } catch {
    fail(
      "CANARY FAILED — no decision ARRIVED for a known-dangerous fixture. The hook command\n" +
      `produced ${r.stdout ? "unparseable output" : "NOTHING ON STDOUT"}:\n  ${LIVE_COMMAND}\n` +
      "The wrapper may well be denying; what matters is that the harness never receives it." +
      ENV_REMEDY()
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
  console.log(
    "canary 3: a known-dangerous fixture was denied BY THE SCANNER\n" +
    `          scanner the canary invoked: ${scannerUsed}`
  );
};

const verify = (settingsPath, fail) => {
  // Pin check FIRST, so a missing declaration never prints a canary-1 green and then refuses.
  // canaryEnv repeats it so a future caller that skips verify still cannot spawn a substitute.
  const declared = configEnv(settingsPath, fail);
  declaredEnv = declared;
  const missing = missingPins(declared);
  if (missing.length) fail(refuseUnestablished(settingsPath, missing));
  canaryMatcher(settingsPath, fail);
  canarySweep(settingsPath, fail);
  canaryScanner(settingsPath, fail);
};

// R16 — a success line may claim only what the canaries actually earned. Earned: for THIS
// settings document, the ctx exec matcher matches the live tool names, the sweep is green,
// the hook command — run through a shell exactly as the harness runs it — delivered a
// scanner-sourced DENY for ONE known-dangerous fixture, off the scanner named here, under
// the four env names declared in that document. NOT earned, and so not claimed: that this
// machine is protected, that ambient native preload agrees, that any other env name agrees,
// that any other tool surface is guarded, or that any other settings scope agrees.
const greenLine = () =>
  `ctx exec calls in ${SETTINGS} reach ${LIVE_WRAPPER}, and one known-dangerous fixture was ` +
  `denied by the scanner behind it (${scannerUsed}).\n` +
  `The canary used the env block of that file:\n${pinLines(declaredEnv, [])}\n` +
  "The harness overlays the same block, so those four names agree.\n" +
  "Not established: native preload (LD_PRELOAD, LD_LIBRARY_PATH, DYLD_*), any other env name, " +
  "other settings scopes (enterprise, project, --settings).\n" +
  "That surface, that fixture, those four names — nothing wider was checked.";

// Pin check at the door, not after printing a rewrite plan. The candidate's env block is
// this file's env block (this tool does not rewrite env). verify() reads the file it is
// handed again so a future split of those two objects cannot skip this.
{
  const declared = configEnv(SETTINGS, (why) => { console.error(why); process.exit(1); });
  declaredEnv = declared;
  const missing = missingPins(declared);
  if (missing.length) {
    console.error(refuseUnestablished(SETTINGS, missing));
    process.exit(1);
  }
}

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
  console.log(`\nalready current — matchers at LOOSE.\n${greenLine()}`);
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
const candidateBytes = JSON.stringify(cfg, null, 2) + "\n";

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
  writeFileSync(tmpPath, candidateBytes, { mode: 0o600, flag: "wx" });
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
// ABORT IF THE SOURCE MOVED UNDER US. The candidate was built from the bytes read at the top
// of this run, and the canaries can take minutes; anything written to settings.json in that
// window is destroyed by the rename below, silently. Measured in an earlier round: an operator
// `env` block AND A SECOND `Bash` GUARD ENTRY vanished that way. That is not a lost edit, it is
// one security control quietly deleting another, and this turns it into a loud refusal.
//
// Deliberately placed AFTER the backup and immediately BEFORE the rename, so the window it
// closes is the real one — checking earlier would leave exactly the gap it exists to close,
// which is the "checked a different object" shape this whole file has been repairing.
// A guard, not a reconciliation: it never merges, it only refuses.
const sha256 = (s) => createHash("sha256").update(s).digest("hex");
let nowBytes;
try {
  nowBytes = readFileSync(SETTINGS, "utf8");
} catch (err) {
  abort(`refusing to publish — ${SETTINGS} could not be re-read before the rename (${err.message})`);
}
if (sha256(nowBytes) !== sha256(srcBytes)) {
  abort(
    `refusing to publish — ${SETTINGS} CHANGED while the canaries ran.\n` +
    "The candidate was built from the earlier bytes, so publishing it would silently discard\n" +
    "whatever was written in between — which has previously included another guard's entry.\n" +
    `A backup of the current file is at ${backup}. Re-run to pick up the new contents.`
  );
}

// The canaries judged THIS file. Hashing SETTINGS (above) does not bind the inode we are
// about to rename. A writer that only replaces the candidate leaves SETTINGS untouched and
// would otherwise publish bytes no canary saw. Same class, one path over.
let nowCandidate;
try {
  nowCandidate = readFileSync(tmpPath, "utf8");
} catch (err) {
  abort(`refusing to publish — the candidate ${tmpPath} could not be re-read (${err.message})`);
}
if (sha256(nowCandidate) !== sha256(candidateBytes)) {
  abort(
    `refusing to publish — the candidate CHANGED while the canaries ran.\n` +
    "The canaries judged the earlier bytes; publishing would put something else live.\n" +
    `${SETTINGS} was not the file that moved — the candidate was.`
  );
}

renameSync(tmpPath, SETTINGS);
tmpLive = false;  // published, not orphaned — the exit hook must not chase the old path
console.log(
  `\npatched ${targets.length} matcher(s) — all three canaries green BEFORE publish.` +
  `\n${greenLine()}` +
  `\nRollback: cp ${backup} ${SETTINGS}`
);
