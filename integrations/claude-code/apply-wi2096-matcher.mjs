#!/usr/bin/env node
// apply-wi2096-matcher.mjs — gated, reversible fix for the stale context-mode
// PreToolUse matchers in the canonical ~/.claude/settings.json (transformate WI-2096).
//
// WHY A SCRIPT AND NOT A HAND EDIT: settings.json is the canonical source the
// REPL-seat renderer fans out to every seat (ops_seat_settings_generated,
// transformate WI-1818). A hot-patch that lands broken JSON breaks every seat on the
// next 15-minute sync. This applies the change, CANARIES it against the
// coverage sweep, and ROLLS BACK automatically if the sweep does not go green.
//
//   node apply-wi2096-matcher.mjs --dry-run   # print the diff, touch nothing
//   node apply-wi2096-matcher.mjs             # backup → patch → canary → keep|revert
//
// Manual rollback at any time: cp <printed backup path> ~/.claude/settings.json
// Idempotent: a second run reports "already current" and exits 0.

import { readFileSync, writeFileSync, copyFileSync, renameSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { homedir } from "node:os";
import path from "node:path";

const HOME = homedir();
const SETTINGS = process.env.HOOK_SETTINGS || path.join(HOME, ".claude/settings.json");
const SWEEP = process.env.HOOK_SWEEP || path.join(HOME, "dev/warden-memory/scripts/audit-hook-matchers.mjs");
const DRY = process.argv.includes("--dry-run");

// Loose SUFFIX match: hits the legacy `mcp__context-mode__*` names, the live
// `mcp__plugin_context-mode_context-mode__*` names, and any future prefix.
const LOOSE = "context-mode__ctx_(execute|execute_file|batch_execute)";
const STALE = /context-mode__ctx_/;

// The live context-mode tool names this matcher has to cover. Used both to assert the
// patched matcher actually matches something (below) and to document what LOOSE is for.
const LIVE_CTX_TOOLS = [
  "mcp__plugin_context-mode_context-mode__ctx_execute",
  "mcp__plugin_context-mode_context-mode__ctx_execute_file",
  "mcp__plugin_context-mode_context-mode__ctx_batch_execute",
  "mcp__context-mode__ctx_execute",
];

const cfg = JSON.parse(readFileSync(SETTINGS, "utf8"));
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

const ctxEntries = pre.filter((e) => STALE.test(e.matcher || ""));
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

if (targets.length === 0) {
  console.log(`already current — ${ctxEntries.length} context-mode matcher(s) present, all at LOOSE`);
  process.exit(0);
}
for (const e of targets) {
  console.log(`  ${e.matcher}\n→ ${LOOSE}   [${(e.hooks || []).map((h) => h.command).join(", ")}]`);
  if (!DRY) e.matcher = LOOSE;
}
if (DRY) process.exit(0);

// The backup name carries a timestamp. A fixed `.bak-wi2096` was overwritten by the next run,
// so a second invocation destroyed the only copy of the last known-good file — and the
// documented manual rollback then restored the already-broken state.
const stamp = new Date().toISOString().replace(/[:.]/g, "-");
const backup = `${SETTINGS}.bak-wi2096-${stamp}`;
copyFileSync(SETTINGS, backup);

// Write via a temp file in the SAME directory + rename, which is atomic on POSIX.
// writeFileSync truncates in place: this file is the canonical source the REPL-seat renderer
// fans out to every seat on a 15-minute cycle, so a crash or a kill mid-write publishes a
// truncated settings.json fleet-wide — and an interruption after the write but before the
// canary leaves an unverified change in force with nothing to signal it.
const tmpPath = `${SETTINGS}.tmp-wi2096-${process.pid}`;
writeFileSync(tmpPath, JSON.stringify(cfg, null, 2) + "\n");
renameSync(tmpPath, SETTINGS);
console.log(`\npatched ${targets.length} matcher(s); backup: ${backup}`);

const rollback = (why) => {
  copyFileSync(backup, SETTINGS);
  console.error(`\n${why} — rolled back from ${backup}`);
  process.exit(1);
};

// ── Canary part 1: assert the matcher we just wrote MATCHES THE TOOLS IT IS FOR ──
//
// This exists because the coverage sweep cannot do it. For the three ctx surfaces the sweep
// computes `covered = (dyn && dyn.decision === "DENY")` and discards its static hit
// entirely; `dyn` comes from spawning CTX_WRAP, so the ctx portion of its verdict is
// independent of the matcher in this file. A patch that mangled the matcher into something
// matching nothing would still go green and be kept. So the one thing this script changes
// gets checked here, directly, before the sweep is consulted at all.
let re;
try {
  re = new RegExp(LOOSE);
} catch (err) {
  rollback(`CANARY FAILED — the patched matcher is not a valid regex (${err.message})`);
}
const unmatched = LIVE_CTX_TOOLS.filter((t) => !re.test(t));
if (unmatched.length) {
  rollback(
    "CANARY FAILED — the patched matcher does not match live context-mode tool names:\n  " +
    unmatched.join("\n  ")
  );
}
console.log(`canary: patched matcher matches all ${LIVE_CTX_TOOLS.length} known ctx tool names`);

// ── Canary part 2: the coverage sweep must go green against the patched file ──
//
// CTX_WRAP is passed explicitly. The sweep defaults it to ~/.local/bin/dcg-ctx-wrap and
// derives the ctx surfaces' verdict by spawning it, so leaving it unset made the result
// depend on whatever happened to be installed at that path rather than on this change.
const sweep = spawnSync("node", [SWEEP], {
  encoding: "utf8",
  env: {
    ...process.env,
    HOOK_SETTINGS: SETTINGS,
    CTX_WRAP: process.env.CTX_WRAP || path.join(HOME, ".local/bin/dcg-ctx-wrap"),
  },
});
process.stdout.write(sweep.stdout || "");
if (sweep.error) {
  rollback(`CANARY FAILED — could not run the coverage sweep ${SWEEP} (${sweep.error.message})`);
}
if (sweep.status !== 0) {
  // status is null when the child was killed by a signal; say which happened.
  const how = sweep.status === null ? `killed by ${sweep.signal}` : `exit ${sweep.status}`;
  rollback(`CANARY FAILED (sweep ${how})`);
}
console.log("\ncanary green — change kept. Rollback: cp " + backup + " " + SETTINGS);
