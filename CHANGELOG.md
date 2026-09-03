# Changelog

All notable changes to **dcg** (Destructive Command Guard) are documented here.

Versions marked **[Release]** have published GitHub Releases with pre-built binaries.
Versions marked **[Tag]** are git tags only (no binaries published).

Repository: <https://github.com/Dicklesworthstone/destructive_command_guard>

---

## [Unreleased] (after v0.4.3)

Post-v0.4.3 work on `main` that has not yet been tagged.

### Security Hardening

- **Git-verb rules match only in executing positions** (`core.git`, transformate WI-3107): quoted argument content of a non-git command (an `orca … --body "…"` bus message, an `echo` string, a `git commit -m` message) is content and is masked out of the text the git-verb regexes scan, even in compound commands (`… && git status`). Executing positions stay visible: git itself, command substitutions and backticks, `-c`/`-e` inline code, deferred assignments (`X="…"; $X`, `eval`), process substitution, pipes into an executor, and every program that executes text handed to it as a quoted argument or on stdin. That executor class is closed as a class, not per instance: `sed`/`gsed` (`e`, `s///e`, `-f -`), `awk`, `m4` (`syscmd`), editors and pagers with `!cmd` escapes (`ed`/`ex`/`vi`/`vim`/`nvim`/`emacs`/`less`/`more`/`man -P`), archivers with exec hooks (`tar --to-command`, `cpio --rsh-command`, `zip -TT`), transports (`rsync -e`, `ssh`/`scp`, `nc -e`, `socat`), privilege and namespace wrappers (`sudo`/`su -c`/`runuser`/`unshare`/`nsenter`), containers (`docker`/`podman`/`kubectl … sh -c`), database and debugger shells (`psql \!`, `sqlite3`, `gdb -ex`), and interpreters. A script fed to such a program is denied even when it only mentions a git verb (`sed 's/git restore -W ./X/'`): the guard cannot parse sed or awk scripts, so it fails closed. The executor test is anchored to the segment's command word (an argument value such as `--to git` or `--subject publish` never unmasks a body), shells are an explicit list, and `eval` / `<(` / `>(` count only in executable spans. A `sed -f -` / `awk -f -` here-string or heredoc is a script, not data, for the heredoc masker.
- **Recursive-force-delete bypass family** (`core.filesystem`): closed seven sibling-bypass families an agent could use after `rm -rf` is blocked.
  - `find ... -delete` on sensitive paths (Critical/High) — closes the `find -delete` path-bypass plus compound, subshell, and path-prefix variants.
  - `unlink <sensitive>` (Critical/High) — POSIX unlink(2) primitive.
  - `truncate -s 0|--size=0|-s -N` on sensitive paths (Critical/High) — in-place zero/shrink.
  - `shred [-u|--remove|-fzu] <sensitive>` (Critical/High) — DoD-style overwrite + optional unlink.
  - `tar --remove-files` on sensitive sources (Critical/High) — archive-then-delete masquerading as an archive operation; order-agnostic flag/source placement; `tar --remove-files -cf /dev/null /etc` (delete-only) blocked.
  - `dd of=<sensitive>` (Critical/High) — file-level overwrite (truncate-equivalent at the dd layer); operand-order agnostic; `dd of=/dev/null` (read-discard) and `dd if=/etc/passwd of=/tmp/passwd.bak` (backup) preserved; device-level dd (`of=/dev/sda`) is `system.disk`'s scope.
  - `mv <sensitive>` (Critical) — closes the canonical cross-segment bypass `mv /etc /tmp/x && rm -rf /tmp/x` where each segment is allowed individually but together destroys `/etc`. Blocks any mv that mentions a sensitive path (source OR destination) including in-place renames within /etc; tmp-family moves remain allowed. The more general data-flow analyzer (covering `cp -al`, `ln -s`, etc.) is tracked as a follow-up epic.
  - `> <sensitive>` (Critical) — Bash output redirects (`>`, `>|`, `&>`, `1>`, `2>` with optional `|` force-overwrite) truncate the target file to zero bytes; bare `> /etc/passwd`, `: > /etc/passwd`, `echo > /etc/passwd`, and numbered-FD variants all destroy file content via shell syntax alone (no destructive binary involved). Append (`>>`) is correctly preserved via negative lookbehind. Per scope decision: only the Critical root-home tier ships — a `-general` rule would block legitimate `make > build.log` workflows. Two supporting changes: (a) the `should_fallback_to_full_normalized_keyword_scan` quick-reject helper now fires whenever a redirect operator is present (previously gated on path-prefix normalization), so redirect keywords match outside the executable span; (b) `sanitize_for_pattern_matching` now exits all-args-data masking on redirect operators so `echo > /etc/passwd` no longer hides the destructive target.
- **system.disk pack promoted to default-on** (`PacksConfig::enabled_pack_ids`) — first-time users with empty config now get `mkfs`/`dd-to-/dev`/`fdisk`/`parted`/`mdadm`/`lvm`/`wipefs` protection without manual enablement. Opt-out via `disabled = ["system.disk"]` (or `disabled = ["system"]`).
- **Strict git pack**: expanded dangerous-command detection for additional destructive git patterns ([6d950f3](https://github.com/Dicklesworthstone/destructive_command_guard/commit/6d950f3), [031e84a](https://github.com/Dicklesworthstone/destructive_command_guard/commit/031e84a))
- Removed safe patterns in strict git pack that created a compound-command bypass ([d6ce202](https://github.com/Dicklesworthstone/destructive_command_guard/commit/d6ce202))
- Podman `rm`/`rmi` combined-flag bypass (e.g. `podman rm -af`) ([d9d23b5](https://github.com/Dicklesworthstone/destructive_command_guard/commit/d9d23b5))

### Hook & Agent Detection

- **Codex CLI PreToolUse hook support**: Codex CLI 0.125.0+ is supported via stable `~/.codex/hooks.json` PreToolUse hooks. dcg detects Codex hook input from the `turn_id` field and uses the strict stderr-deny contract with exit code 2 required by Codex, not the Claude/Gemini JSON-deny payload. The Unix installer writes `~/.codex/hooks.json` when Codex CLI is detected; Windows installs document the manual hook path while PowerShell parity is tracked separately. Closes [#84](https://github.com/Dicklesworthstone/destructive_command_guard/issues/84).
- Hook system expansion with additional interception patterns and strict git pack hardening ([031e84a](https://github.com/Dicklesworthstone/destructive_command_guard/commit/031e84a))
- Disambiguate Claude Code from Gemini in `detect_protocol()` -- closes [#77](https://github.com/Dicklesworthstone/destructive_command_guard/issues/77) ([8815b54](https://github.com/Dicklesworthstone/destructive_command_guard/commit/8815b54))

### Maintenance

- Clippy and rustfmt cleanup across CLI, hook, and pack modules ([c26f22d](https://github.com/Dicklesworthstone/destructive_command_guard/commit/c26f22d))
- Test infrastructure: `large_dataset_insertion` test updated to use in-memory DB with manual seeding ([784e356](https://github.com/Dicklesworthstone/destructive_command_guard/commit/784e356))

---

## [v0.4.3](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.4.3) -- 2026-03-14 [Tag]

A large release adding new agent detections, new protection packs, self-healing settings monitoring, and a session-scoped interactive allowlist system.

### Self-Healing & Resilience

- **Real-time `settings.json` overwrite detection and self-healing** -- DCG now watches for external processes silently removing its hook registration and restores it automatically ([708d202](https://github.com/Dicklesworthstone/destructive_command_guard/commit/708d202))
- `dcg setup` command with shell startup hook-removal detection -- closes [#56](https://github.com/Dicklesworthstone/destructive_command_guard/issues/56) ([45db4b7](https://github.com/Dicklesworthstone/destructive_command_guard/commit/45db4b7))
- Shell startup check to detect silently removed DCG hook ([eb06112](https://github.com/Dicklesworthstone/destructive_command_guard/commit/eb06112))
- Prevent duplicate shell check injection on re-runs ([8b70cab](https://github.com/Dicklesworthstone/destructive_command_guard/commit/8b70cab))

### New Protection Packs

- **Supabase database protection pack** -- full CLI coverage including `db push`, `db reset`, `migration repair`, `functions delete`, `secrets unset`, `storage rm`, `projects delete`, and more; `--dry-run` whitelisted as safe ([003a429](https://github.com/Dicklesworthstone/destructive_command_guard/commit/003a429), [3e3ed19](https://github.com/Dicklesworthstone/destructive_command_guard/commit/3e3ed19))

### Agent Detection & Protocol Support

- **Gemini CLI hook protocol support** with improved detection for minimal payloads ([ac6e6ad](https://github.com/Dicklesworthstone/destructive_command_guard/commit/ac6e6ad), [0629a5d](https://github.com/Dicklesworthstone/destructive_command_guard/commit/0629a5d))
- **Augment Code** agent detection ([5917125](https://github.com/Dicklesworthstone/destructive_command_guard/commit/5917125))
- **GitHub Copilot CLI** agent detection ([84bb1a0](https://github.com/Dicklesworthstone/destructive_command_guard/commit/84bb1a0))

### Interactive Allowlist & Session Management

- **Session-scoped allowlist** binding with `session_id` and testable interactive checks ([3533533](https://github.com/Dicklesworthstone/destructive_command_guard/commit/3533533))
- **Interactive allowlist audit system** with collision-resistant backup naming and SQLite schema v6 migration ([c948240](https://github.com/Dicklesworthstone/destructive_command_guard/commit/c948240))
- Project-level hook install and `--no-configure` update flag ([1397a8b](https://github.com/Dicklesworthstone/destructive_command_guard/commit/1397a8b))

### Output & History

- **TOON output format** support, hardened history storage, and improved test infrastructure ([69f60c8](https://github.com/Dicklesworthstone/destructive_command_guard/commit/69f60c8))

### Bug Fixes

- Emit JSON `"ask"` decision for warn-severity matches in hook mode -- closes [#70](https://github.com/Dicklesworthstone/destructive_command_guard/issues/70) ([91f09db](https://github.com/Dicklesworthstone/destructive_command_guard/commit/91f09db))
- Display `custom_paths` packs in `dcg packs` listing -- closes [#57](https://github.com/Dicklesworthstone/destructive_command_guard/issues/57) ([045cfc0](https://github.com/Dicklesworthstone/destructive_command_guard/commit/045cfc0))
- Redis `maxmemory` regex no longer matches `maxmemory-policy` ([1c3c94a](https://github.com/Dicklesworthstone/destructive_command_guard/commit/1c3c94a))
- Missing Redis CONFIG SET rules for `maxmemory`, persistence, and rewrite ([4f0a21a](https://github.com/Dicklesworthstone/destructive_command_guard/commit/4f0a21a))
- ARM64 compilation fix for `uring-fs` (`*const i8` to `*const libc::c_char`) ([7b9bf96](https://github.com/Dicklesworthstone/destructive_command_guard/commit/7b9bf96))
- Installer and CI aligned on `gnu` targets to match existing release binaries ([5e81603](https://github.com/Dicklesworthstone/destructive_command_guard/commit/5e81603))

---

## [v0.4.2](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.4.2) -- 2026-02-23 [Tag]

Stabilization release that resolved 91+ pre-existing test failures.

### Test Suite

- Resolved 91+ pre-existing test failures across the entire test suite ([faf7e0e](https://github.com/Dicklesworthstone/destructive_command_guard/commit/faf7e0e))

### License

- License updated to MIT with OpenAI/Anthropic Rider ([c1200c7](https://github.com/Dicklesworthstone/destructive_command_guard/commit/c1200c7))

---

## [v0.4.1](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.4.1) -- 2026-02-22 [Tag]

First `musl`-based statically linked Linux binary release, plus dependency modernization and publish to crates.io.

### Distribution & Portability

- Switch Linux x86_64 distribution to **musl** for portable, statically linked binaries ([e066687](https://github.com/Dicklesworthstone/destructive_command_guard/commit/e066687))
- Static linking verification for musl builds in CI ([6cdbfc1](https://github.com/Dicklesworthstone/destructive_command_guard/commit/6cdbfc1), [0a6850c](https://github.com/Dicklesworthstone/destructive_command_guard/commit/0a6850c))
- `fsqlite` dependencies switched from local paths to crates.io v0.1.0 ([9dc695b](https://github.com/Dicklesworthstone/destructive_command_guard/commit/9dc695b))
- `rich_rust` dependency updated from pre-release/git ref to crates.io v0.2.0 ([83d4abf](https://github.com/Dicklesworthstone/destructive_command_guard/commit/83d4abf))
- crates.io keyword limit compliance (max 5) ([0a46ef7](https://github.com/Dicklesworthstone/destructive_command_guard/commit/0a46ef7))

### CLI Improvements

- `dcg pack-info` shows patterns by default; new `--json` and `--no-patterns` flags ([48e303e](https://github.com/Dicklesworthstone/destructive_command_guard/commit/48e303e))

### Bug Fixes

- Binary content detection for Unicode; FTS rowid sync; regex engine fallback ([acc2f2c](https://github.com/Dicklesworthstone/destructive_command_guard/commit/acc2f2c))
- macOS `CursorUIViewService` filtered from Cursor IDE detection ([970f62f](https://github.com/Dicklesworthstone/destructive_command_guard/commit/970f62f))
- Migrate all branch references from `master` to `main`; fix quote-stripping in normalizer ([920d785](https://github.com/Dicklesworthstone/destructive_command_guard/commit/920d785))
- History writer migrated to thread-local DB; updated `rand` API ([4d1b3c7](https://github.com/Dicklesworthstone/destructive_command_guard/commit/4d1b3c7))

### Testing

- Comprehensive unit tests for output modules ([b97f50a](https://github.com/Dicklesworthstone/destructive_command_guard/commit/b97f50a))

---

## [v0.4.0](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.4.0) -- 2026-02-10 [Release]

Major release adding GitHub Copilot CLI hook support, installer improvements, and automated packaging triggers.

### Agent Integration

- **GitHub Copilot CLI hook support** and installer integration ([7385931](https://github.com/Dicklesworthstone/destructive_command_guard/commit/7385931))
- Timeout protection and user feedback for agent scanning during install ([37c9123](https://github.com/Dicklesworthstone/destructive_command_guard/commit/37c9123))

### Distribution

- `repository_dispatch` triggers for homebrew-tap and scoop-bucket automated packaging ([b5482b4](https://github.com/Dicklesworthstone/destructive_command_guard/commit/b5482b4))

### Evaluator

- Evaluator refactored to consolidate external pack checking into core evaluation ([fea7d6a](https://github.com/Dicklesworthstone/destructive_command_guard/commit/fea7d6a))
- Build ordered pack list and keyword index after external packs are loaded ([314e591](https://github.com/Dicklesworthstone/destructive_command_guard/commit/314e591))

### Bug Fixes

- All available subcommands now appear in `dcg --help` output ([23f3301](https://github.com/Dicklesworthstone/destructive_command_guard/commit/23f3301))

---

## [v0.3.0](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.3.0) -- 2026-02-02 [Release]

Large feature release introducing robot mode, rich terminal output via `rich_rust`, golden testing, expanded packs, and agent-specific profiles.

### Robot Mode & Machine-Readable Output

- **Robot mode** with structured JSON output and machine-readable exit codes (`dcg test --robot`) ([e576883](https://github.com/Dicklesworthstone/destructive_command_guard/commit/e576883))
- Robot mode API documentation ([34506dd](https://github.com/Dicklesworthstone/destructive_command_guard/commit/34506dd))
- Schema versioning and metadata in `TestOutput` JSON ([b7a6d6d](https://github.com/Dicklesworthstone/destructive_command_guard/commit/b7a6d6d))

### Rich Terminal Output (`rich_rust` Integration)

- `rich_rust` dependency with DcgConsole wrapper and rich theme bridge ([ae39947](https://github.com/Dicklesworthstone/destructive_command_guard/commit/ae39947), [c881a75](https://github.com/Dicklesworthstone/destructive_command_guard/commit/c881a75))
- Tables migrated to `rich_rust` ([328107a](https://github.com/Dicklesworthstone/destructive_command_guard/commit/328107a))
- Enhanced `doctor`, `packs`, and `stats` commands with rich terminal output ([02b5086](https://github.com/Dicklesworthstone/destructive_command_guard/commit/02b5086), [ea39323](https://github.com/Dicklesworthstone/destructive_command_guard/commit/ea39323))
- Tree visualization for `dcg explain` ([e538399](https://github.com/Dicklesworthstone/destructive_command_guard/commit/e538399), [2b8780d](https://github.com/Dicklesworthstone/destructive_command_guard/commit/2b8780d))
- CLI output control flags for legacy and color modes ([fdda44f](https://github.com/Dicklesworthstone/destructive_command_guard/commit/fdda44f))

### Golden Testing

- Golden JSON tests framework for deterministic output validation ([0b0ca97](https://github.com/Dicklesworthstone/destructive_command_guard/commit/0b0ca97))
- Robot framework test fixtures ([cbf74da](https://github.com/Dicklesworthstone/destructive_command_guard/commit/cbf74da))

### Pack System Expansion

- Detailed explanations added to all destructive patterns ([e775c2b](https://github.com/Dicklesworthstone/destructive_command_guard/commit/e775c2b))
- Expanded allowlist rules for safe command patterns ([db272dc](https://github.com/Dicklesworthstone/destructive_command_guard/commit/db272dc))
- External pack loading from `custom_paths` wired into the evaluator ([bea17d0](https://github.com/Dicklesworthstone/destructive_command_guard/commit/bea17d0), [a2cabc5](https://github.com/Dicklesworthstone/destructive_command_guard/commit/a2cabc5))
- Expanded `system.disk` pack with mdadm, btrfs, LVM, and dmsetup patterns ([56df75a](https://github.com/Dicklesworthstone/destructive_command_guard/commit/56df75a))

### Agent Profiles

- **Agent-specific profiles and trust levels** (Epic 9) -- auto-detect AI coding agent and apply tailored settings ([77571ba](https://github.com/Dicklesworthstone/destructive_command_guard/commit/77571ba))

### Misc

- Configurable verification methods for interactive prompts ([23618ac](https://github.com/Dicklesworthstone/destructive_command_guard/commit/23618ac))
- OpenCode added to supported tools list ([4473419](https://github.com/Dicklesworthstone/destructive_command_guard/commit/4473419))

### Bug Fixes

- macOS config path: check XDG-style `~/.config/dcg` first ([ceffdf5](https://github.com/Dicklesworthstone/destructive_command_guard/commit/ceffdf5))
- External packs marked as always-enabled in listing ([7821773](https://github.com/Dicklesworthstone/destructive_command_guard/commit/7821773))
- Iteration limit added to prevent unbounded wrapper stripping in normalizer ([d342171](https://github.com/Dicklesworthstone/destructive_command_guard/commit/d342171))
- CI/TERM=dumb detection for plain text fallback output ([47b4ddd](https://github.com/Dicklesworthstone/destructive_command_guard/commit/47b4ddd))

---

## [v0.2.15](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.2.15) -- 2026-01-20 [Release]

CI fix release.

### Bug Fixes

- Run only lib tests in dist workflow to avoid missing binary errors ([6489d2b](https://github.com/Dicklesworthstone/destructive_command_guard/commit/6489d2b))

---

## [v0.2.14](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.2.14) -- 2026-01-20 [Tag]

Version bump and formatting for release pipeline.

### Maintenance

- Bump version to 0.2.14 and apply `cargo fmt` ([6d67502](https://github.com/Dicklesworthstone/destructive_command_guard/commit/6d67502))

---

## [v0.2.13](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.2.13) -- 2026-01-20 [Tag]

Massive feature batch covering the MCP server, CI scan extractors, self-update mechanism, SARIF output, rich TUI, custom packs, and dozens of new security pack enrichments.

### MCP Server & Agent Integration

- **MCP server mode** (`dcg mcp`) for direct agent integration via the Model Context Protocol ([b372d99](https://github.com/Dicklesworthstone/destructive_command_guard/commit/b372d99))
- Hook output enriched with `ruleId`, `severity`, and `remediation` fields ([b439cd4](https://github.com/Dicklesworthstone/destructive_command_guard/commit/b439cd4))
- Agent ergonomics test suite ([0ebc72f](https://github.com/Dicklesworthstone/destructive_command_guard/commit/0ebc72f))
- Machine-readable DCG documentation added to AGENTS.md ([871f929](https://github.com/Dicklesworthstone/destructive_command_guard/commit/871f929))

### Structured Output Formats

- **SARIF 2.1.0 output format** for security tool and CI integration ([4a4c09e](https://github.com/Dicklesworthstone/destructive_command_guard/commit/4a4c09e), [17f2040](https://github.com/Dicklesworthstone/destructive_command_guard/commit/17f2040))
- Standardized error code system (DCG-XXXX) ([4f87561](https://github.com/Dicklesworthstone/destructive_command_guard/commit/4f87561))
- JSON Schema (Draft 2020-12) for all DCG output formats ([8c7601c](https://github.com/Dicklesworthstone/destructive_command_guard/commit/8c7601c))
- `--format json` support for `test` and `packs` commands ([f9db962](https://github.com/Dicklesworthstone/destructive_command_guard/commit/f9db962))

### Rich Terminal Rendering

- **Rich terminal rendering** -- denial boxes, progress bars, tables, and TUI denial integration ([a0aaf42](https://github.com/Dicklesworthstone/destructive_command_guard/commit/a0aaf42), [f9986e0](https://github.com/Dicklesworthstone/destructive_command_guard/commit/f9986e0))
- Span highlighting with caret-style terminal formatter for denial output ([32aaa18](https://github.com/Dicklesworthstone/destructive_command_guard/commit/32aaa18), [ad2ac66](https://github.com/Dicklesworthstone/destructive_command_guard/commit/ad2ac66))

### Self-Update & Installer

- **Native Rust self-update mechanism** with version rollback and background notification ([f8a8a15](https://github.com/Dicklesworthstone/destructive_command_guard/commit/f8a8a15), [d0e1066](https://github.com/Dicklesworthstone/destructive_command_guard/commit/d0e1066))
- `--check` flag for version checking ([c4f4f64](https://github.com/Dicklesworthstone/destructive_command_guard/commit/c4f4f64))
- **Sigstore cosign signing** added to release workflow ([45c8109](https://github.com/Dicklesworthstone/destructive_command_guard/commit/45c8109))
- Installer: sigstore verification, Cursor detection, preflight checks, version-check idempotency ([2a597b6](https://github.com/Dicklesworthstone/destructive_command_guard/commit/2a597b6), [1ab0b5b](https://github.com/Dicklesworthstone/destructive_command_guard/commit/1ab0b5b))
- Installer: checksum verification with `--no-verify` flag ([616db4a](https://github.com/Dicklesworthstone/destructive_command_guard/commit/616db4a))
- Installer: `uninstall.sh` script with agent hook removal ([c3d3eff](https://github.com/Dicklesworthstone/destructive_command_guard/commit/c3d3eff))
- Installer: Aider auto-configuration, Continue detection (unsupported status), Codex CLI detection (unsupported status) ([0a06a82](https://github.com/Dicklesworthstone/destructive_command_guard/commit/0a06a82), [8d07940](https://github.com/Dicklesworthstone/destructive_command_guard/commit/8d07940), [067b28a](https://github.com/Dicklesworthstone/destructive_command_guard/commit/067b28a))

### Custom Pack System

- **Custom pack system** with external YAML loading (`custom_paths` in config) ([0e4bc64](https://github.com/Dicklesworthstone/destructive_command_guard/commit/0e4bc64), [f87aade](https://github.com/Dicklesworthstone/destructive_command_guard/commit/f87aade))
- Regex engine analysis and pack validation utilities ([fa9400f](https://github.com/Dicklesworthstone/destructive_command_guard/commit/fa9400f))

### Scan Mode Extractors

- CircleCI extractor (`.circleci/config.yml`) ([1a3b232](https://github.com/Dicklesworthstone/destructive_command_guard/commit/1a3b232))
- Azure Pipelines extractor ([80d4cda](https://github.com/Dicklesworthstone/destructive_command_guard/commit/80d4cda))
- Dockerfile extractor improvements ([302e35f](https://github.com/Dicklesworthstone/destructive_command_guard/commit/302e35f))
- GitLab CI extractor tests ([3316733](https://github.com/Dicklesworthstone/destructive_command_guard/commit/3316733))

### Pack Enrichment

- Comprehensive severity levels and extended explanations across all packs ([86b6b9a](https://github.com/Dicklesworthstone/destructive_command_guard/commit/86b6b9a), [8dafbe3](https://github.com/Dicklesworthstone/destructive_command_guard/commit/8dafbe3))
- Explanations added to DNS, Payment, database, infrastructure, Kubernetes, container, CI/CD, backup, and API gateway packs ([82064d4](https://github.com/Dicklesworthstone/destructive_command_guard/commit/82064d4), [42ed80b](https://github.com/Dicklesworthstone/destructive_command_guard/commit/42ed80b), [c07e4f9](https://github.com/Dicklesworthstone/destructive_command_guard/commit/c07e4f9))
- **MySQL pack** with comprehensive destructive patterns ([81b0ca8](https://github.com/Dicklesworthstone/destructive_command_guard/commit/81b0ca8))
- Suggestions added for Docker, Kubernetes, MySQL, and system permissions packs ([26dcc3b](https://github.com/Dicklesworthstone/destructive_command_guard/commit/26dcc3b), [1b16ef0](https://github.com/Dicklesworthstone/destructive_command_guard/commit/1b16ef0), [5f76ba0](https://github.com/Dicklesworthstone/destructive_command_guard/commit/5f76ba0))

### CLI Enhancements

- Verbosity controls, shell completions, and `DCG_FORMAT` env var ([f545d4d](https://github.com/Dicklesworthstone/destructive_command_guard/commit/f545d4d))
- Rule-level analytics queries and suggestion audit tracking ([0a1b7e5](https://github.com/Dicklesworthstone/destructive_command_guard/commit/0a1b7e5), [017a94b](https://github.com/Dicklesworthstone/destructive_command_guard/commit/017a94b))
- Git branch detection module ([6bb91f9](https://github.com/Dicklesworthstone/destructive_command_guard/commit/6bb91f9))
- `DetailedEvaluationResult` and `evaluate_detailed()` API ([bb93259](https://github.com/Dicklesworthstone/destructive_command_guard/commit/bb93259))
- Config parser for new allowlist schema ([876beff](https://github.com/Dicklesworthstone/destructive_command_guard/commit/876beff))

### Security

- Backslash and quote obfuscation bypass detection ([8eaeaaa](https://github.com/Dicklesworthstone/destructive_command_guard/commit/8eaeaaa))
- Safe pattern bypass prevention for compound commands ([e85a495](https://github.com/Dicklesworthstone/destructive_command_guard/commit/e85a495))
- Heredoc scanning: skip non-executing targets (cat, tee, etc.) ([4be0358](https://github.com/Dicklesworthstone/destructive_command_guard/commit/4be0358))
- Here-string (`<<<`) masking for non-executing commands ([831d637](https://github.com/Dicklesworthstone/destructive_command_guard/commit/831d637))

### Bug Fixes

- Docker-compose extractor quote handling for embedded commands ([90c01a0](https://github.com/Dicklesworthstone/destructive_command_guard/commit/90c01a0))
- UTF-8 safe string handling in update and denial modules ([c62ec3e](https://github.com/Dicklesworthstone/destructive_command_guard/commit/c62ec3e))
- History FTS rebuild wrapped in transaction for atomicity ([82ee415](https://github.com/Dicklesworthstone/destructive_command_guard/commit/82ee415))
- CI blockers resolved for release builds ([999b9b1](https://github.com/Dicklesworthstone/destructive_command_guard/commit/999b9b1))

---

## [v0.2.12](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.2.12) -- 2026-01-15 [Tag]

Internal rename of the `telemetry` module to `history`.

### Refactoring

- Complete `telemetry` to `history` module rename across the codebase ([ddfc15d](https://github.com/Dicklesworthstone/destructive_command_guard/commit/ddfc15d))

---

## [v0.2.11](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.2.11) -- 2026-01-15 [Tag]

Introduces the full command history system and auto-configuration of agent hooks.

### Command History System

- **Command history system** with stats, export, and per-pack analysis (`dcg history stats`, `dcg history export`) ([59a33b1](https://github.com/Dicklesworthstone/destructive_command_guard/commit/59a33b1))
- Comprehensive history module integration tests ([c7802cc](https://github.com/Dicklesworthstone/destructive_command_guard/commit/c7802cc))

### Installer & Agent Configuration

- Installer auto-configures Claude Code and Gemini CLI hooks with detailed feedback ([512c2d3](https://github.com/Dicklesworthstone/destructive_command_guard/commit/512c2d3))

### Performance

- Aho-Corasick quick-reject in `sanitize_for_pattern_matching` for faster false-positive elimination ([6c8afc6](https://github.com/Dicklesworthstone/destructive_command_guard/commit/6c8afc6))

### Testing

- Security regression tests for normalization, safe pattern, and Windows bypasses ([f7324e2](https://github.com/Dicklesworthstone/destructive_command_guard/commit/f7324e2))

---

## [v0.2.10](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.2.10) -- 2026-01-15 [Release]

Security hardening, performance improvements, and the history pruning command.

### Command History

- **History pruning** command ([06c6ea7](https://github.com/Dicklesworthstone/destructive_command_guard/commit/06c6ea7))
- `DCG_TELEMETRY_*` env vars renamed to `DCG_HISTORY_*` ([d44bde6](https://github.com/Dicklesworthstone/destructive_command_guard/commit/d44bde6))

### Security & Correctness

- Tier 1 bypass fixed for inline scripts with attached quotes (e.g. `bash -c"..."`) ([2890891](https://github.com/Dicklesworthstone/destructive_command_guard/commit/2890891))
- Inline interpreter detection improved to avoid false positives on echoed commands ([3b426b0](https://github.com/Dicklesworthstone/destructive_command_guard/commit/3b426b0))
- Potential stack overflow in recursive heredoc scanning limited to depth 50 ([a8f24b0](https://github.com/Dicklesworthstone/destructive_command_guard/commit/a8f24b0))
- Quoted secrets with spaces now handled in redaction ([a04f570](https://github.com/Dicklesworthstone/destructive_command_guard/commit/a04f570))

### Bug Fixes

- `xargs` regex robustness, simulated limits, and OOM protection ([77fa5fb](https://github.com/Dicklesworthstone/destructive_command_guard/commit/77fa5fb))
- Inline code detection improved for context module ([8d1ce05](https://github.com/Dicklesworthstone/destructive_command_guard/commit/8d1ce05))

---

## [v0.2.9](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.2.9) -- 2026-01-14 [Release]

Codebase-wide rename from `telemetry` to `history` and Redis secret redaction.

### Refactoring

- Complete `telemetry` to `history` rename throughout codebase ([d0b2976](https://github.com/Dicklesworthstone/destructive_command_guard/commit/d0b2976))

### Bug Fixes

- Redis `user:password` URL pattern added to secret redaction ([0d61117](https://github.com/Dicklesworthstone/destructive_command_guard/commit/0d61117))

---

## [v0.2.8](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.2.8) -- 2026-01-14 [Tag]

Introduces the telemetry/history subsystem with persistent SQLite storage, CLI subcommands, secret redaction, and extensive normalizer hardening.

### Telemetry / History Subsystem

- **Telemetry CLI** subcommands for querying persistent command history ([fc2a7a8](https://github.com/Dicklesworthstone/destructive_command_guard/commit/fc2a7a8), [2e4ea76](https://github.com/Dicklesworthstone/destructive_command_guard/commit/2e4ea76))
- **Secret redaction patterns** for telemetry storage ([dbe7159](https://github.com/Dicklesworthstone/destructive_command_guard/commit/dbe7159))
- Telemetry database migrations and config options ([15e3587](https://github.com/Dicklesworthstone/destructive_command_guard/commit/15e3587), [bb95341](https://github.com/Dicklesworthstone/destructive_command_guard/commit/bb95341))
- Comprehensive E2E test framework for telemetry ([13d1701](https://github.com/Dicklesworthstone/destructive_command_guard/commit/13d1701))

### Installer & Agent Configuration

- Claude Code `SKILL.md` for automatic capability discovery ([6f44dc7](https://github.com/Dicklesworthstone/destructive_command_guard/commit/6f44dc7))
- Installer auto-configures Claude Code and Gemini CLI idempotently ([3b8fc5f](https://github.com/Dicklesworthstone/destructive_command_guard/commit/3b8fc5f))

### Normalizer & Context Hardening

- Sanitize `git grep`/`ag`/`ack` search patterns to prevent false positives ([cf0565a](https://github.com/Dicklesworthstone/destructive_command_guard/commit/cf0565a), [299df4b](https://github.com/Dicklesworthstone/destructive_command_guard/commit/299df4b))
- Harden allowlist/pending exception parsing ([49fda98](https://github.com/Dicklesworthstone/destructive_command_guard/commit/49fda98))
- Avoid panics in production paths ([3e678b5](https://github.com/Dicklesworthstone/destructive_command_guard/commit/3e678b5))
- Apply scan globs after directory expansion ([82a7639](https://github.com/Dicklesworthstone/destructive_command_guard/commit/82a7639))
- Honor project pack overrides ([bcc9a20](https://github.com/Dicklesworthstone/destructive_command_guard/commit/bcc9a20))
- Handle path-prefixed wrappers, env quoted assignments, Dockerfile exec continuations, HCL block comments, inline YAML commas ([326ab3a](https://github.com/Dicklesworthstone/destructive_command_guard/commit/326ab3a), [81fcc2e](https://github.com/Dicklesworthstone/destructive_command_guard/commit/81fcc2e), [65d0fa6](https://github.com/Dicklesworthstone/destructive_command_guard/commit/65d0fa6), [3880cf3](https://github.com/Dicklesworthstone/destructive_command_guard/commit/3880cf3), [c4ba22f](https://github.com/Dicklesworthstone/destructive_command_guard/commit/c4ba22f))
- Skip GitHub Actions `env`/`with` blocks during scan extraction ([9f6eab9](https://github.com/Dicklesworthstone/destructive_command_guard/commit/9f6eab9))

### Bug Fixes

- TMPDIR shell default value syntax in safe path detection ([4a970b8](https://github.com/Dicklesworthstone/destructive_command_guard/commit/4a970b8))
- `is_expired` made fail-closed on invalid timestamps ([84e607c](https://github.com/Dicklesworthstone/destructive_command_guard/commit/84e607c))
- CI failures in E2E, scan-regression, and coverage jobs ([f7a4d53](https://github.com/Dicklesworthstone/destructive_command_guard/commit/f7a4d53), [dc82f6a](https://github.com/Dicklesworthstone/destructive_command_guard/commit/dc82f6a))

---

## [v0.2.7](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.2.7) -- 2026-01-12 [Release]

Memory leak fix and version alignment.

### Bug Fixes

- Full pipeline memory test constrained to core packs to prevent leaks ([d8b1376](https://github.com/Dicklesworthstone/destructive_command_guard/commit/d8b1376))

---

## [v0.2.6](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.2.6) -- 2026-01-12 [Release]

CI fix for macOS Intel builds.

### CI / Distribution

- macOS Intel builds moved to `macos-15-intel` runner (deprecation of `macos-13`) ([46c20d7](https://github.com/Dicklesworthstone/destructive_command_guard/commit/46c20d7))

---

## [v0.2.5](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.2.5) -- 2026-01-12 [Release]

Memory test stabilization.

### Bug Fixes

- Warm up pipeline before leak check to avoid false positives ([02c0169](https://github.com/Dicklesworthstone/destructive_command_guard/commit/02c0169))

---

## [v0.2.4](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.2.4) -- 2026-01-12 [Release]

Lockfile pin for CI stability.

### Bug Fixes

- Pin `ciborium` to 0.2.2 in lockfile ([9f454c6](https://github.com/Dicklesworthstone/destructive_command_guard/commit/9f454c6))

---

## [v0.2.3](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.2.3) -- 2026-01-12 [Release]

Default config fix.

### Bug Fixes

- Enable common packs on default config load ([23fd149](https://github.com/Dicklesworthstone/destructive_command_guard/commit/23fd149))

---

## [v0.2.2](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.2.2) -- 2026-01-12 [Release]

Formatting fix.

### Maintenance

- Align confidence tests with rustfmt ([534d1ef](https://github.com/Dicklesworthstone/destructive_command_guard/commit/534d1ef))

---

## [v0.2.1](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.2.1) -- 2026-01-12 [Release]

Installer improvements with Gemini CLI support, binary size reduction, and portability fixes.

### Installer & Agent Support

- **Gemini CLI** support in installer with proper tool name and error handling ([3769dab](https://github.com/Dicklesworthstone/destructive_command_guard/commit/3769dab))
- Auto-configure Claude Code/Codex and detect predecessor tools ([9929f7d](https://github.com/Dicklesworthstone/destructive_command_guard/commit/9929f7d))
- `--easy-mode` promoted as the recommended install method ([75de506](https://github.com/Dicklesworthstone/destructive_command_guard/commit/75de506))

### Performance

- Binary size reduced 69% by trimming tree-sitter parsers ([d11670e](https://github.com/Dicklesworthstone/destructive_command_guard/commit/d11670e))

### Scanning & Detection

- Confidence tiering for warn-by-default patterns ([b31b4010](https://github.com/Dicklesworthstone/destructive_command_guard/commit/b31b4010))
- Quote-aware heredoc operator detection ([4d20d9e](https://github.com/Dicklesworthstone/destructive_command_guard/commit/4d20d9e))
- Docker-compose extraction allowed without keywords ([c90a56b](https://github.com/Dicklesworthstone/destructive_command_guard/commit/c90a56b))
- Per-pack reference documentation generator ([56db566](https://github.com/Dicklesworthstone/destructive_command_guard/commit/56db566))

### Bug Fixes

- Installer portability improvements for BSD/macOS systems ([9f89544](https://github.com/Dicklesworthstone/destructive_command_guard/commit/9f89544))
- UTF-8 boundary panic prevented in confidence/operator detection ([44389a3](https://github.com/Dicklesworthstone/destructive_command_guard/commit/44389a3))
- Heredoc error message line numbers corrected ([d4b98b5](https://github.com/Dicklesworthstone/destructive_command_guard/commit/d4b98b5))
- Explain hint added to block messages ([156de92](https://github.com/Dicklesworthstone/destructive_command_guard/commit/156de92))
- Inline code context detection for attached `-c` flags ([b10c480](https://github.com/Dicklesworthstone/destructive_command_guard/commit/b10c480))

---

## [v0.2.0](https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v0.2.0) -- 2026-01-09 [Tag]

Foundational release representing the first tagged version of DCG with a mature feature set. Built over 300+ commits in two days of intensive multi-agent development.

### Core Detection Engine

- **Modular pack system** with 49+ security packs covering: core git/filesystem, databases (PostgreSQL, MySQL, Redis, MongoDB, SQLite), Kubernetes (kubectl, Helm, Kustomize), Docker/Podman/Compose, cloud providers (AWS, GCP, Azure), Terraform/Pulumi/Ansible, CI/CD (GitHub Actions, Jenkins, CircleCI, GitLab CI), CDN (CloudFront, Cloudflare Workers, Fastly), DNS (Route53, Cloudflare), backup tools (restic, rclone, borg, Velero), load balancers (ELB, nginx, HAProxy, Traefik), secrets management (Vault, AWS Secrets, Doppler, 1Password), monitoring (Datadog, Prometheus, Splunk, PagerDuty), email services (SES, SendGrid, Mailgun, Postmark), API gateways (Kong, Apigee, AWS API Gateway), search engines (Elasticsearch, Algolia, Meilisearch, OpenSearch), messaging (Kafka, RabbitMQ, NATS, SQS/SNS), storage (S3, GCS, MinIO, Azure Blob), feature flags (LaunchDarkly, Split, Unleash, Flipt), and payments (Stripe, Braintree, Square) ([f04ae36](https://github.com/Dicklesworthstone/destructive_command_guard/commit/f04ae36aaecc027b7666504cd5aa7e0c2d922dda))
- **Aho-Corasick keyword prefilter** + per-pack `RegexSet` fast path for O(n) matching
- **Lazy regex compilation** with `LazyFancyRegex` -- patterns compiled on first use only
- **Pack-aware quick reject** -- skip entire packs when no keywords match ([635bb97](https://github.com/Dicklesworthstone/destructive_command_guard/commit/635bb97))
- **CompiledOverrides** for precompiled config regexes in the evaluator hot path ([2f2a979](https://github.com/Dicklesworthstone/destructive_command_guard/commit/2f2a979))

### Heredoc & Inline Script Scanning

- **Two-tier heredoc detection** -- Tier 1 fast path for common patterns, Tier 2 AST-based content extraction ([1ca7745](https://github.com/Dicklesworthstone/destructive_command_guard/commit/1ca7745), [891722e](https://github.com/Dicklesworthstone/destructive_command_guard/commit/891722e))
- **AST pattern matching layer** for destructive operations in Python, Ruby, JavaScript, TypeScript, Perl, Go, Bash ([2ae7517](https://github.com/Dicklesworthstone/destructive_command_guard/commit/2ae7517))
- Language detection with priority-based signals ([f9f1228](https://github.com/Dicklesworthstone/destructive_command_guard/commit/f9f1228))
- Configurable heredoc scanning behavior ([81d9bde](https://github.com/Dicklesworthstone/destructive_command_guard/commit/81d9bde))
- Go language support for heredoc AST scanning ([a0a89bd](https://github.com/Dicklesworthstone/destructive_command_guard/commit/a0a89bd))

### Smart Context Detection

- **Execution-context classification** -- distinguishes data contexts (strings, comments, grep patterns) from execution contexts ([14cb23a](https://github.com/Dicklesworthstone/destructive_command_guard/commit/14cb23a), [e829144](https://github.com/Dicklesworthstone/destructive_command_guard/commit/e829144))
- **Safe String-Argument Registry** v1 for reducing false positives on non-executing patterns ([341f24b](https://github.com/Dicklesworthstone/destructive_command_guard/commit/341f24b))
- `sanitize_for_pattern_matching` integration for false-positive immunity ([55561a1](https://github.com/Dicklesworthstone/destructive_command_guard/commit/55561a1))

### CLI & User Interface

- **Explain mode** -- `dcg explain "command"` shows matching rules, packs, severity, and trace info ([4b01e6d](https://github.com/Dicklesworthstone/destructive_command_guard/commit/4b01e6d), [7d5a8fb](https://github.com/Dicklesworthstone/destructive_command_guard/commit/7d5a8fb))
- **Scan mode** for CI/CD -- extract and evaluate commands from GitHub Actions, Dockerfiles, Makefiles, shell scripts, docker-compose, and `package.json` ([1d915d5](https://github.com/Dicklesworthstone/destructive_command_guard/commit/1d915d5), [89ef9cd](https://github.com/Dicklesworthstone/destructive_command_guard/commit/89ef9cd))
- **Simulate mode** with output formats and redaction/truncation ([183862b](https://github.com/Dicklesworthstone/destructive_command_guard/commit/183862b))
- Pre-commit hook install/uninstall for scan mode ([c8174c9](https://github.com/Dicklesworthstone/destructive_command_guard/commit/c8174c9))
- Markdown output format for PR comments ([c3428ff](https://github.com/Dicklesworthstone/destructive_command_guard/commit/c3428ff))
- `--explain` and `--format` flags for the test command ([e032fd9](https://github.com/Dicklesworthstone/destructive_command_guard/commit/e032fd9))

### Policy & Allowlist System

- **Decision modes** (deny/warn/log) per rule ([d3e5499](https://github.com/Dicklesworthstone/destructive_command_guard/commit/d3e5499))
- **Severity tagging** for core pack rules ([aeacc38](https://github.com/Dicklesworthstone/destructive_command_guard/commit/aeacc38))
- **Allowlist system** with expiration, conditions, risk acknowledgement, and wildcard pack matching ([0eff234](https://github.com/Dicklesworthstone/destructive_command_guard/commit/0eff234), [58d683e](https://github.com/Dicklesworthstone/destructive_command_guard/commit/58d683e), [78d0eee](https://github.com/Dicklesworthstone/destructive_command_guard/commit/78d0eee))
- **Observe mode** with `observe_until` warn-first rollout window ([d67fe7b](https://github.com/Dicklesworthstone/destructive_command_guard/commit/d67fe7b))
- Allowlist CLI commands ([600549d](https://github.com/Dicklesworthstone/destructive_command_guard/commit/600549d))
- Allow-once audit logging ([d25f44f](https://github.com/Dicklesworthstone/destructive_command_guard/commit/d25f44f))

### Suggestions Engine

- **Suggestions engine** with safer alternative recommendations for all core patterns ([4948d6a](https://github.com/Dicklesworthstone/destructive_command_guard/commit/4948d6a), [53b48e7](https://github.com/Dicklesworthstone/destructive_command_guard/commit/53b48e7))
- Docker, Kubernetes, and database suggestions ([dd525d0](https://github.com/Dicklesworthstone/destructive_command_guard/commit/dd525d0))

### Performance & Resilience

- **Fail-open deadline enforcement** -- configurable timeout budget prevents DCG from blocking workflows ([ef9bb4a](https://github.com/Dicklesworthstone/destructive_command_guard/commit/ef9bb4a))
- **Performance benchmarks** for heredoc detection and core pipeline ([8456045](https://github.com/Dicklesworthstone/destructive_command_guard/commit/8456045), [4ac432e](https://github.com/Dicklesworthstone/destructive_command_guard/commit/4ac432e))
- Performance budget constants and CI enforcement ([2a2b3b1](https://github.com/Dicklesworthstone/destructive_command_guard/commit/2a2b3b1))
- Wrapper prefix stripping module for sudo/env/command normalization ([b2f02b8](https://github.com/Dicklesworthstone/destructive_command_guard/commit/b2f02b8))

### Testing

- **E2E test framework** with comprehensive coverage of CLI flows, hook mode, scan mode, and security regressions ([3d4c216](https://github.com/Dicklesworthstone/destructive_command_guard/commit/3d4c216), [39ee901](https://github.com/Dicklesworthstone/destructive_command_guard/commit/39ee901))
- **Cargo-fuzz harness** with 4 fuzz targets ([530e05f](https://github.com/Dicklesworthstone/destructive_command_guard/commit/530e05f))
- **Property-based tests** for evaluator invariants ([b3b33a4](https://github.com/Dicklesworthstone/destructive_command_guard/commit/b3b33a4))
- Layered allowlist E2E tests ([42c4adb](https://github.com/Dicklesworthstone/destructive_command_guard/commit/42c4adb))
- Hook/CLI evaluator parity tests ([d08105e](https://github.com/Dicklesworthstone/destructive_command_guard/commit/d08105e))
- Coverage threshold enforcement in CI ([d40217a](https://github.com/Dicklesworthstone/destructive_command_guard/commit/d40217a))

### Infrastructure

- **Release automation** and self-updater foundation ([cb9f6b4](https://github.com/Dicklesworthstone/destructive_command_guard/commit/cb9f6b4))
- Cross-platform CI: Linux (x86_64, aarch64), macOS (Intel, Apple Silicon), Windows
- Codecov integration for coverage tracking
- Dependabot configuration for automated dependency updates
- `install.sh` with `--easy-mode` flag, platform auto-detection, and predecessor tool migration

### Bug Fixes

- Regex backtracking panic in `normalize_command` ([4c5be16](https://github.com/Dicklesworthstone/destructive_command_guard/commit/4c5be16))
- Stdin hang on clap parse errors ([17889ce](https://github.com/Dicklesworthstone/destructive_command_guard/commit/17889ce))
- UTF-8 safe preview truncation in AST matcher ([961bc8f](https://github.com/Dicklesworthstone/destructive_command_guard/commit/961bc8f))
- Quoted command-word bypass ([1647112](https://github.com/Dicklesworthstone/destructive_command_guard/commit/1647112))
- Temp-dir path traversal treated as catastrophic in AST matcher ([893887a](https://github.com/Dicklesworthstone/destructive_command_guard/commit/893887a))
- Shell function declaration with spaced parens in scanner ([c19dc2a](https://github.com/Dicklesworthstone/destructive_command_guard/commit/c19dc2a))

---

## Initial Development -- 2026-01-07

The project began as `git_safety_guard`, a focused tool for blocking destructive git commands. It was renamed to **destructive_command_guard** (`dcg`) and expanded into a general-purpose destructive-command interceptor with the modular pack system.

- Initial commit ([1640612](https://github.com/Dicklesworthstone/destructive_command_guard/commit/16406128fc967a305b97f4cd8da1b537a4be7b6f))
- Comprehensive enhancements with colorful output, CI/CD, and tooling ([c686775](https://github.com/Dicklesworthstone/destructive_command_guard/commit/c686775b745b5b81644323eb35df3a8920136f74))
- Rename to `destructive_command_guard` with modular pack system ([f04ae36](https://github.com/Dicklesworthstone/destructive_command_guard/commit/f04ae36aaecc027b7666504cd5aa7e0c2d922dda))

---

## Release Matrix

| Version | Date | Type | Binaries |
|---------|------|------|----------|
| v0.4.3 | 2026-03-14 | Tag only | No |
| v0.4.2 | 2026-02-23 | Tag only | No |
| v0.4.1 | 2026-02-22 | Tag only | No |
| v0.4.0 | 2026-02-10 | **GitHub Release** | Yes |
| v0.3.0 | 2026-02-02 | **GitHub Release** | Yes |
| v0.2.15 | 2026-01-20 | **GitHub Release** | Yes |
| v0.2.14 | 2026-01-20 | Tag only | No |
| v0.2.13 | 2026-01-20 | Tag only | No |
| v0.2.12 | 2026-01-15 | Tag only | No |
| v0.2.11 | 2026-01-15 | Tag only | No |
| v0.2.10 | 2026-01-15 | **GitHub Release** | Yes |
| v0.2.9 | 2026-01-14 | **GitHub Release** | Yes |
| v0.2.8 | 2026-01-14 | Tag only | No |
| v0.2.7 | 2026-01-12 | **GitHub Release** | Yes |
| v0.2.6 | 2026-01-12 | **GitHub Release** | Yes |
| v0.2.5 | 2026-01-12 | **GitHub Release** | Yes |
| v0.2.4 | 2026-01-12 | **GitHub Release** | Yes |
| v0.2.3 | 2026-01-12 | **GitHub Release** | Yes |
| v0.2.2 | 2026-01-12 | **GitHub Release** | Yes |
| v0.2.1 | 2026-01-12 | **GitHub Release** | Yes |
| v0.2.0 | 2026-01-09 | Tag only | No |
