# Arkon-AI fork — destructive_command_guard

Forked from [Dicklesworthstone/destructive_command_guard](https://github.com/Dicklesworthstone/destructive_command_guard).

**Pinned SHA:** `0bcbae83778e803b7d70350b38eb3cddb4e48c7c` (tag `arkon-pin/0bcbae8`)
**Date forked:** 2026-04-30
**Audit:** see [`AUDIT-2026-04-30.md`](AUDIT-2026-04-30.md)
**Tracked under:** transformate WI-117 Phase 1

## Why we fork

Arkon-AI policy: prefer org-owned binaries over upstream `curl | bash` dependencies. Pin to audited SHAs; bump deliberately, not on auto-update.

## Custom packs

In `packs-arkon/`. Currently:

- `transformate.secrets_emit.yaml` — blocks Bash patterns that emit secret VALUES to stdout (closes upstream's emission-class gap). 8 destructive + 6 safe patterns, schema-validated, 29/29 smoke tests pass.

To install on a host: copy YAML files into `~/.config/dcg/packs/`.

## Don't run `dcg update`

The upstream binary's `update` subcommand uses the `self_update` crate to fetch new releases over the network. We pin to known-good SHAs intentionally. Bumping the SHA happens via the monthly upstream review (last day of each month), not via the binary's self-update.

If you want to bump:
1. Diff upstream main vs `arkon-pin/<current>`
2. Re-run audit (see `AUDIT-*.md`)
3. Update tag → `arkon-pin/<new-sha-prefix>`

## Build

Same as upstream. Requires `cargo nightly` (see `rust-toolchain.toml`).

```bash
cargo build --release
```

Output binary at `target/release/dcg`. Install destinations and the Claude Code hook patch are managed separately under WI-117 Phase 1 install plan.
