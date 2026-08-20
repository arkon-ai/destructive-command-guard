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

import { readFileSync, writeFileSync, copyFileSync } from "node:fs";
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

const cfg = JSON.parse(readFileSync(SETTINGS, "utf8"));
const pre = cfg.hooks?.PreToolUse || [];
const targets = pre.filter((e) => STALE.test(e.matcher || "") && e.matcher !== LOOSE);

if (targets.length === 0) {
  console.log("already current — no context-mode matcher needs updating");
  process.exit(0);
}
for (const e of targets) {
  console.log(`  ${e.matcher}\n→ ${LOOSE}   [${(e.hooks || []).map((h) => h.command).join(", ")}]`);
  if (!DRY) e.matcher = LOOSE;
}
if (DRY) process.exit(0);

const backup = `${SETTINGS}.bak-wi2096`;
copyFileSync(SETTINGS, backup);
writeFileSync(SETTINGS, JSON.stringify(cfg, null, 2) + "\n");
console.log(`\npatched ${targets.length} matcher(s); backup: ${backup}`);

// ── Canary: the coverage sweep must go green against the patched file ──
const sweep = spawnSync("node", [SWEEP], { encoding: "utf8", env: { ...process.env, HOOK_SETTINGS: SETTINGS } });
process.stdout.write(sweep.stdout || "");
if (sweep.status !== 0) {
  copyFileSync(backup, SETTINGS);
  console.error(`\nCANARY FAILED (sweep exit ${sweep.status}) — rolled back from ${backup}`);
  process.exit(1);
}
console.log("\ncanary green — change kept. Rollback: cp " + backup + " " + SETTINGS);
