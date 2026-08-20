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
const runs = (e) =>
  Array.isArray(e.hooks) &&
  e.hooks.some((h) => h && typeof h.command === "string" && h.command.trim() !== "");

const ctxEntries = pre.filter(isExecCtxEntry);
const hollow = ctxEntries.filter((e) => !runs(e));
const targets = ctxEntries.filter((e) => e.matcher !== LOOSE);

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
const wrapperName = path.basename(WRAPPER);
const routesToWrapper = (e) =>
  Array.isArray(e.hooks) &&
  e.hooks.some((h) => h && typeof h.command === "string" && h.command.includes(wrapperName));

if (ctxEntries.length > 0 && !ctxEntries.some(routesToWrapper)) {
  console.error(
    `context-mode matcher(s) exist in ${SETTINGS} but NONE routes to '${wrapperName}'.\n` +
    "The matcher string is not the control — the hook command is. Rewriting the matcher would\n" +
    "leave the ctx surfaces going somewhere else entirely, so this stops instead.\n" +
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
    env: { ...process.env, HOOK_SETTINGS: settingsPath, CTX_WRAP: WRAPPER },
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
const canaryScanner = (fail) => {
  const r = spawnSync(WRAPPER, [], {
    input: JSON.stringify({
      tool_name: "mcp__plugin_context-mode_context-mode__ctx_execute",
      tool_input: { code: DANGEROUS_FIXTURE, language: "shell" },
    }),
    encoding: "utf8",
    timeout: 30000,
  });
  if (r.error) fail(`CANARY FAILED — cannot run the wrapper ${WRAPPER} (${r.error.message})`);
  let out;
  try {
    out = JSON.parse(r.stdout || "");
  } catch {
    fail(`CANARY FAILED — ${WRAPPER} returned no decision for a known-dangerous fixture`);
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
const tmpPath = `${SETTINGS}.tmp-wi2096-${process.pid}`;
writeFileSync(tmpPath, JSON.stringify(cfg, null, 2) + "\n");

// rename() replaces the inode, so without this the published file inherits the temp file's
// umask-derived mode (0644 under a typical 022) and this process's ownership instead of the
// original's. settings.json can carry an env block with tokens, so a 0600 file silently
// becoming world-readable is a credential exposure; and a sudo run would flip ownership and
// cost the renderer its write access on the next sync.
const orig = statSync(SETTINGS);
chmodSync(tmpPath, orig.mode & 0o7777);
try {
  chownSync(tmpPath, orig.uid, orig.gid);
} catch {
  // Non-root run: the file is already ours, so there is nothing to restore.
}

const abort = (why) => {
  try {
    unlinkSync(tmpPath);
  } catch {
    // Nothing to clean up.
  }
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
console.log(
  `\npatched ${targets.length} matcher(s) — all three canaries green BEFORE publish.` +
  `\nRollback: cp ${backup} ${SETTINGS}`
);
