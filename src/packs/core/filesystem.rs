//! Core filesystem patterns - protections against destructive rm commands.
//!
//! This includes patterns for:
//! - rm -rf outside temp directories (blocked)
//! - rm -rf in /tmp, /var/tmp, $TMPDIR (allowed)

use crate::context::SpanKind;
use crate::packs::{DestructivePattern, Pack, PatternSuggestion, Platform, SafePattern, Severity};
use crate::{destructive_pattern, safe_pattern};

// ============================================================================
// Suggestion constants (must be 'static for the pattern struct)
// ============================================================================

/// Suggestions for `rm -rf` on root/home paths pattern.
const RM_RF_ROOT_HOME_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "find {path} -type f | head -20",
        "Preview what files would be deleted before running",
    ),
    PatternSuggestion::new(
        "ls -la {path}",
        "List directory contents to verify the path",
    ),
    PatternSuggestion::new(
        "rm -rf /path/to/specific/subdirectory",
        "Use explicit, specific paths instead of root or home",
    ),
];

/// Suggestions for general `rm -rf` pattern.
const RM_RF_GENERAL_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "rm -ri {path}",
        "Interactive mode: confirms each file before deletion",
    ),
    PatternSuggestion::with_platform(
        "trash-put {path}",
        "Move to trash instead of permanent deletion (requires trash-cli)",
        Platform::Linux,
    ),
    PatternSuggestion::with_platform(
        "gio trash {path}",
        "Move to trash via GNOME (requires gio)",
        Platform::Linux,
    ),
    PatternSuggestion::new(
        "mv {path} /tmp/delete-me-{timestamp}",
        "Move to a temp holding area instead of deleting immediately",
    ),
    PatternSuggestion::new(
        "rm -rf /tmp/{subdir}",
        "Safe temp directory deletion (allowed without confirmation)",
    ),
    PatternSuggestion::new(
        "find {path} -type f | wc -l",
        "Count files that would be deleted before proceeding",
    ),
    PatternSuggestion::new(
        "ls -la {path}",
        "List directory contents to verify the path",
    ),
];

/// Suggestions for `rm -r -f` (separate flags) pattern.
const RM_R_F_SEPARATE_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "rm -ri {path}",
        "Interactive mode: confirms each file before deletion",
    ),
    PatternSuggestion::new(
        "rm -r -f /tmp/{subdir}",
        "Safe temp directory deletion (allowed without confirmation)",
    ),
    PatternSuggestion::new(
        "rm -r -f $TMPDIR/{subdir}",
        "Use system temp directory (allowed without confirmation)",
    ),
    PatternSuggestion::new(
        "find {path} -type f | head -20",
        "Preview files before deletion",
    ),
];

/// Suggestions for `rm --recursive --force` (long flags) pattern.
const RM_RECURSIVE_FORCE_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "rm --interactive --recursive {path}",
        "Interactive mode: confirms each file before deletion",
    ),
    PatternSuggestion::new(
        "find {path} --maxdepth 2 -ls | head -30",
        "Preview directory structure before deletion",
    ),
    PatternSuggestion::new(
        "rm --recursive --force /tmp/{subdir}",
        "Safe temp directory deletion (allowed without confirmation)",
    ),
];

/// Suggestions for `find ... -delete` patterns. `find -delete` is
/// bytewise-equivalent to `rm -rf` on the matching tree, so the suggestions
/// mirror the rm-rf ones.
const FIND_DELETE_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "find {path} -type f | head -20",
        "Preview which files `-delete` would remove (drop the -delete flag)",
    ),
    PatternSuggestion::new(
        "find {path} -type f | wc -l",
        "Count files that would be deleted before proceeding",
    ),
    PatternSuggestion::new(
        "find /tmp/{subdir} -delete",
        "Safe temp directory deletion (allowed without confirmation)",
    ),
    PatternSuggestion::new(
        "find {path} -print -delete",
        "If you must proceed: use -print to log every deletion",
    ),
];

/// Suggestions for `unlink` patterns. `unlink <file>` is the raw POSIX
/// unlink(2) — semantically equivalent to `rm <file>` on a single file.
/// On sensitive targets (`/etc/passwd`, `~/.ssh/...`) it is one-shot
/// destruction with no recovery.
const UNLINK_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new("ls -la {path}", "Verify the path before unlinking"),
    PatternSuggestion::new(
        "cp {path} {path}.bak && unlink {path}",
        "Make a backup first if you really must remove the original",
    ),
    PatternSuggestion::new(
        "unlink /tmp/{subdir}/scratch",
        "Safe temp-directory unlink (allowed without confirmation)",
    ),
    PatternSuggestion::with_platform(
        "trash-put {path}",
        "Move to trash instead of permanent unlink (requires trash-cli)",
        Platform::Linux,
    ),
];

/// Suggestions for `truncate` patterns. `truncate -s 0 <file>` zeros the
/// file in place — equivalent to deleting all content. `truncate -s -<N>`
/// shrinks the file by N bytes (data loss). Both are recoverable only
/// from backups.
const TRUNCATE_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "cp {path} {path}.bak && truncate -s 0 {path}",
        "Make a backup before zeroing the file",
    ),
    PatternSuggestion::new("wc -c {path}", "Check current size before shrinking"),
    PatternSuggestion::new(
        "truncate -s 0 /tmp/{subdir}/scratch",
        "Safe temp-directory truncate (allowed without confirmation)",
    ),
    PatternSuggestion::new(
        "head -c <N> {path} > {path}.head && mv {path}.head {path}",
        "Keep the first N bytes instead of dropping data blindly",
    ),
];

/// Suggestions for `shred` patterns. `shred -u <file>` overwrites then
/// unlinks; `shred -fzu` is the most aggressive form (force, zero-pass,
/// remove). Without `-u`/`--remove` the file is overwritten in place —
/// data is destroyed but the file persists.
const SHRED_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "ls -la {path}",
        "Verify the path before shredding (no recovery)",
    ),
    PatternSuggestion::new(
        "cp {path} {path}.bak && shred -u {path}",
        "Make a backup first if you might need the data",
    ),
    PatternSuggestion::new(
        "shred -u /tmp/{subdir}/scratch",
        "Safe temp-directory shred (allowed without confirmation)",
    ),
    PatternSuggestion::new(
        "shred -n 1 -u {path}",
        "Single-pass shred is faster (and on SSDs, multi-pass adds little)",
    ),
];

/// Suggestions for `tar --remove-files` patterns. `tar --remove-files
/// -cf <archive> <source>` archives the source paths into <archive>,
/// then deletes the originals — bytewise-equivalent to `rm -rf <source>`
/// on the destination tree. The destruction trigger is the
/// `--remove-files` flag; without it tar only reads the source.
const TAR_REMOVE_FILES_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "tar -cf {path}.tar {path}",
        "Archive without --remove-files (sources are preserved)",
    ),
    PatternSuggestion::new(
        "tar -cf {path}.tar {path} && rm -ri {path}",
        "Archive first, then remove with confirmation prompts",
    ),
    PatternSuggestion::new(
        "tar --remove-files -cf out.tar /tmp/{subdir}",
        "Safe temp-directory archive + remove (allowed without confirmation)",
    ),
    PatternSuggestion::new(
        "ls -la {path}",
        "Verify the source path before archive+delete",
    ),
];

/// Suggestions for `dd` overwrite patterns. `dd if=/dev/zero of=<file>`
/// or `dd if=/dev/urandom of=<file>` overwrites the file's contents in
/// place — equivalent to `truncate -s 0` followed by writing zeros/
/// garbage. Device-level dd (`of=/dev/sda`) is system.disk's territory.
const DD_OVERWRITE_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "ls -la {path}",
        "Verify the path before overwriting (no recovery)",
    ),
    PatternSuggestion::new(
        "cp {path} {path}.bak && dd if=/dev/zero of={path} bs=1M count=10",
        "Make a backup first if you might need the data",
    ),
    PatternSuggestion::new(
        "dd if=/dev/zero of=/tmp/{subdir}/scratch bs=1M count=10",
        "Safe temp-directory dd (allowed without confirmation)",
    ),
    PatternSuggestion::new(
        "dd if={path} of=/dev/null",
        "Read-only dd: output discarded (useful for testing read speed)",
    ),
];

/// Suggestions for `mv` cross-segment bypass patterns. The bypass shape is
/// `mv /etc /tmp/x && rm -rf /tmp/x` — each segment is individually
/// allowed but together destroys `/etc`. Blocking on a sensitive source
/// (or destination) closes the first half of the chain.
const MV_SENSITIVE_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new("ls -la {path}", "Verify the source path before any move"),
    PatternSuggestion::new(
        "cp -a {path} {path}.bak",
        "Copy first (preserves the original) — verify the copy, then remove only after confirmation",
    ),
    PatternSuggestion::new(
        "mv {path} {path}.deleted-YYYYMMDD",
        "In-place rename for soft-delete (no cross-segment hop, easy to undo)",
    ),
    PatternSuggestion::new(
        "mv /tmp/{subdir}/foo /tmp/{subdir}/bar",
        "Safe temp-directory rename (allowed without confirmation)",
    ),
];

/// Suggestions for `redirect-truncate-*` patterns. Bash output redirects
/// (`>`, `>|`, `&>`, `1>`, `2>`) truncate the target file to zero bytes
/// before writing — the truncate-equivalent at the shell-syntax layer.
/// Append (`>>`) is non-destructive and not blocked.
const REDIRECT_TRUNCATE_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new("ls -la {path}", "Verify the path before any redirect"),
    PatternSuggestion::new(
        "cp {path} {path}.bak && echo data > {path}",
        "Make a backup first if you might need the previous content",
    ),
    PatternSuggestion::new(
        "echo data >> {path}",
        "Use append (>>) instead of truncate (>) to preserve existing content",
    ),
    PatternSuggestion::new(
        "echo data > /tmp/{subdir}/scratch",
        "Safe temp-directory redirect (allowed without confirmation)",
    ),
];
use crate::{normalize::NormalizeTokenKind, normalize::tokenize_for_normalization};
use std::ops::Range;

const RM_RF_ROOT_HOME_NAME: &str = "rm-rf-root-home";
const RM_RF_ROOT_HOME_REASON: &str = "rm -rf on root or home paths is EXTREMELY DANGEROUS. This command will NOT be executed. Ask the user to run it manually if truly needed.";
const RM_RF_GENERAL_NAME: &str = "rm-rf-general";
const RM_RF_GENERAL_REASON: &str = "rm -rf is destructive and requires human approval. Explain what you want to delete and why, then ask the user to run the command manually.";
const RM_R_F_SEPARATE_NAME: &str = "rm-r-f-separate";
const RM_R_F_SEPARATE_REASON: &str =
    "rm with separate -r -f flags is destructive and requires human approval.";
const RM_RECURSIVE_FORCE_NAME: &str = "rm-recursive-force-long";
const RM_RECURSIVE_FORCE_REASON: &str =
    "rm --recursive --force is destructive and requires human approval.";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QuoteKind {
    None,
    Single,
    Double,
}

#[derive(Debug, Clone)]
pub(crate) struct RmParseMatch {
    pub(crate) pattern_name: &'static str,
    pub(crate) reason: &'static str,
    pub(crate) severity: Severity,
    pub(crate) span: Option<Range<usize>>,
}

#[derive(Debug, Clone)]
pub(crate) enum RmParseDecision {
    Allow,
    Deny(RmParseMatch),
    NoMatch,
}

#[derive(Debug)]
struct PathToken<'a> {
    unquoted: &'a str,
    quote: QuoteKind,
    range: Range<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RmFlagStyle {
    Combined,
    Separate,
    Long,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RmFlagState {
    style: RmFlagStyle,
    span: Option<Range<usize>>,
    saw_terminator: bool,
}

#[derive(Debug, Default)]
#[allow(clippy::struct_excessive_bools)]
struct RmFlagTracker {
    combined_span: Option<Range<usize>>,
    seen_r: bool,
    r_span: Option<Range<usize>>,
    seen_f: bool,
    f_span: Option<Range<usize>>,
    seen_long_recursive: bool,
    recursive_span: Option<Range<usize>>,
    seen_long_force: bool,
    force_span: Option<Range<usize>>,
    saw_terminator: bool,
}

impl RmFlagTracker {
    fn resolve(self) -> Option<RmFlagState> {
        if let Some(span) = self.combined_span {
            return Some(RmFlagState {
                style: RmFlagStyle::Combined,
                span: Some(span),
                saw_terminator: self.saw_terminator,
            });
        }

        if self.seen_r && self.seen_f {
            return Some(RmFlagState {
                style: RmFlagStyle::Separate,
                span: self.r_span.or(self.f_span),
                saw_terminator: self.saw_terminator,
            });
        }

        if self.seen_long_recursive && self.seen_long_force {
            return Some(RmFlagState {
                style: RmFlagStyle::Long,
                span: self.recursive_span.or(self.force_span),
                saw_terminator: self.saw_terminator,
            });
        }

        None
    }
}

pub(crate) fn parse_rm_command(command: &str) -> RmParseDecision {
    let tokens = tokenize_for_normalization(command);
    if tokens.is_empty() {
        return RmParseDecision::NoMatch;
    }

    let mut i = 0;
    while i < tokens.len() {
        let current = &tokens[i];
        if current.kind == NormalizeTokenKind::Separator {
            i += 1;
            continue;
        }

        let Some(text) = current.text(command) else {
            i += 1;
            continue;
        };

        if text == "rm" {
            return parse_rm_segment(command, &tokens, i + 1);
        }

        // Skip to the next separator before scanning for another command word.
        i += 1;
        while i < tokens.len() && tokens[i].kind != NormalizeTokenKind::Separator {
            i += 1;
        }
    }

    RmParseDecision::NoMatch
}

#[allow(clippy::too_many_lines)]
fn parse_rm_segment(
    command: &str,
    tokens: &[crate::normalize::NormalizeToken],
    start_idx: usize,
) -> RmParseDecision {
    let mut options_ended = false;
    let mut flags = RmFlagTracker::default();

    let mut paths: Vec<PathToken<'_>> = Vec::new();

    for token in tokens.iter().skip(start_idx) {
        if token.kind == NormalizeTokenKind::Separator {
            break;
        }

        let Some(text) = token.text(command) else {
            continue;
        };

        if !options_ended {
            if text == "--" {
                options_ended = true;
                flags.saw_terminator = true;
                continue;
            }

            if text.starts_with('-') && text != "-" {
                if text.starts_with("--") {
                    if text.starts_with("--recursive") {
                        flags.seen_long_recursive = true;
                        if flags.recursive_span.is_none() {
                            flags.recursive_span = Some(token.byte_range.clone());
                        }
                    }
                    if text.starts_with("--force") {
                        flags.seen_long_force = true;
                        if flags.force_span.is_none() {
                            flags.force_span = Some(token.byte_range.clone());
                        }
                    }
                } else {
                    let flag_text = text.trim_start_matches('-');
                    if !flag_text.is_empty() {
                        let has_r = flag_text.chars().any(|c| c == 'r' || c == 'R');
                        let has_f = flag_text.chars().any(|c| c == 'f');
                        if has_r && has_f {
                            if flags.combined_span.is_none() {
                                flags.combined_span = Some(token.byte_range.clone());
                            }
                        } else {
                            if has_r && !flags.seen_r {
                                flags.seen_r = true;
                                flags.r_span = Some(token.byte_range.clone());
                            }
                            if has_f && !flags.seen_f {
                                flags.seen_f = true;
                                flags.f_span = Some(token.byte_range.clone());
                            }
                        }
                    }
                }

                continue;
            }
        }

        options_ended = true;
        let (quote, unquoted) = strip_outer_quotes(text);
        paths.push(PathToken {
            unquoted,
            quote,
            range: token.byte_range.clone(),
        });
    }

    let flag_state = flags.resolve();
    let Some(flag_state) = flag_state else {
        return RmParseDecision::NoMatch;
    };

    let safe_paths = !paths.is_empty()
        && !flag_state.saw_terminator
        && paths
            .iter()
            .all(|path| path_is_safe_for_style(path, flag_state.style));

    if safe_paths {
        return RmParseDecision::Allow;
    }

    let first_path = paths.first();
    let is_critical = flag_state.style == RmFlagStyle::Combined
        && !flag_state.saw_terminator
        && first_path.is_some_and(path_is_root_home);

    let (pattern_name, reason, severity) = if is_critical {
        (
            RM_RF_ROOT_HOME_NAME,
            RM_RF_ROOT_HOME_REASON,
            Severity::Critical,
        )
    } else {
        match flag_state.style {
            RmFlagStyle::Combined => (RM_RF_GENERAL_NAME, RM_RF_GENERAL_REASON, Severity::High),
            RmFlagStyle::Separate => (RM_R_F_SEPARATE_NAME, RM_R_F_SEPARATE_REASON, Severity::High),
            RmFlagStyle::Long => (
                RM_RECURSIVE_FORCE_NAME,
                RM_RECURSIVE_FORCE_REASON,
                Severity::High,
            ),
        }
    };

    let span = flag_state
        .span
        .or_else(|| paths.first().map(|path| path.range.clone()));

    RmParseDecision::Deny(RmParseMatch {
        pattern_name,
        reason,
        severity,
        span,
    })
}

fn strip_outer_quotes(token: &str) -> (QuoteKind, &str) {
    if token.len() >= 2 {
        if token.starts_with('"') && token.ends_with('"') {
            return (QuoteKind::Double, &token[1..token.len() - 1]);
        }
        if token.starts_with('\'') && token.ends_with('\'') {
            return (QuoteKind::Single, &token[1..token.len() - 1]);
        }
    }
    (QuoteKind::None, token)
}

fn path_is_safe_for_style(path: &PathToken<'_>, style: RmFlagStyle) -> bool {
    if path.quote == QuoteKind::Double && style != RmFlagStyle::Combined {
        return false;
    }

    match path.quote {
        QuoteKind::None => path_is_safe_unquoted(path.unquoted),
        QuoteKind::Double => path_is_safe_double_quoted(path.unquoted),
        QuoteKind::Single => false,
    }
}

fn path_is_safe_unquoted(path: &str) -> bool {
    if let Some(rest) = path.strip_prefix("/tmp/") {
        return !has_dotdot_segment(rest);
    }
    if let Some(rest) = path.strip_prefix("/var/tmp/") {
        return !has_dotdot_segment(rest);
    }
    if let Some(rest) = path.strip_prefix("$TMPDIR/") {
        return !has_dotdot_segment(rest);
    }
    if let Some(rest) = path.strip_prefix("${TMPDIR}/") {
        return !has_dotdot_segment(rest);
    }
    // Handle shell default value syntax: ${TMPDIR:-/tmp} and ${TMPDIR:-/var/tmp}
    // These always expand to a safe temp directory.
    if let Some(rest) = path.strip_prefix("${TMPDIR:-/tmp}/") {
        return !has_dotdot_segment(rest);
    }
    if let Some(rest) = path.strip_prefix("${TMPDIR:-/var/tmp}/") {
        return !has_dotdot_segment(rest);
    }
    false
}

fn path_is_safe_double_quoted(path: &str) -> bool {
    if let Some(rest) = path.strip_prefix("$TMPDIR/") {
        return !has_dotdot_segment(rest);
    }
    if let Some(rest) = path.strip_prefix("${TMPDIR}/") {
        return !has_dotdot_segment(rest);
    }
    // Handle shell default value syntax: ${TMPDIR:-/tmp} and ${TMPDIR:-/var/tmp}
    // These always expand to a safe temp directory.
    if let Some(rest) = path.strip_prefix("${TMPDIR:-/tmp}/") {
        return !has_dotdot_segment(rest);
    }
    if let Some(rest) = path.strip_prefix("${TMPDIR:-/var/tmp}/") {
        return !has_dotdot_segment(rest);
    }
    false
}

fn has_dotdot_segment(path: &str) -> bool {
    path.split('/')
        .filter(|segment| !segment.is_empty())
        .any(|segment| segment == "..")
}

fn path_is_root_home(path: &PathToken<'_>) -> bool {
    // Check if the path is root or home, ignoring quotes for absolute paths.
    // Tilde expansion only happens if UNQUOTED, but / is absolute regardless.

    let text = path.unquoted;

    // Absolute paths starting with / are dangerous regardless of quotes
    // e.g. rm -rf "/" is just as deadly as rm -rf /
    if text.starts_with('/') {
        return true;
    }

    // Tilde expansion (~/) only happens if unquoted
    if path.quote == QuoteKind::None && text.starts_with('~') {
        return true;
    }

    false
}

/// Create the core filesystem pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "core.filesystem".to_string(),
        name: "Core Filesystem",
        description: "Protects against dangerous rm -rf commands and equivalent destruction (find -delete, unlink) outside temp directories",
        // `find` is included so the quick-reject filter doesn't drop
        // commands like `find / -delete` — which is bytewise-equivalent
        // to `rm -rf /` and used to bypass dcg entirely (the agent learns
        // to swap `rm -rf` → `find -delete` when blocked).
        //
        // `unlink` is included so the quick-reject filter doesn't drop
        // single-file destruction via the POSIX unlink primitive.
        // `truncate` covers the in-place zero/shrink primitive that
        // destroys file content without removing the inode.
        // `shred` covers overwrite-and-unlink (or just overwrite) — DoD-
        // style data destruction with no recovery.
        // `tar` covers `tar --remove-files <sensitive-source>`, which
        // archives-then-deletes — i.e. recursive-force-delete masquerading
        // as an archive operation.
        // Mirror entries MUST also exist in src/packs/mod.rs::PACK_ENTRIES
        // (the duplicate-source-of-truth that gates execution).
        keywords: &[
            "rm", "find", "unlink", "truncate", "shred", "tar", "dd", "mv", ">/", "> /", ">~",
            "> ~", ">$", "> $", ">\"", "> \"", ">'", "> '", "&>", ">|", "1>", "2>",
        ],
        safe_patterns: create_safe_patterns(),
        destructive_patterns: create_destructive_patterns(),
        keyword_matcher: None,
        safe_regex_set: None,
        safe_regex_set_is_complete: false,
    }
}

#[allow(clippy::too_many_lines)]
fn create_safe_patterns() -> Vec<SafePattern> {
    vec![
        // rm -rf in /tmp (combined flags)
        safe_pattern!(
            "rm-rf-tmp",
            r"^rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f[a-zA-Z]*\s+(?:/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*(?:\s+|$))+$"
        ),
        safe_pattern!(
            "rm-fr-tmp",
            r"^rm\s+-[a-zA-Z]*f[a-zA-Z]*[rR][a-zA-Z]*\s+(?:/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*(?:\s+|$))+$"
        ),
        // rm -rf in /var/tmp (combined flags)
        safe_pattern!(
            "rm-rf-var-tmp",
            r"^rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f[a-zA-Z]*\s+(?:/var/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*(?:\s+|$))+$"
        ),
        safe_pattern!(
            "rm-fr-var-tmp",
            r"^rm\s+-[a-zA-Z]*f[a-zA-Z]*[rR][a-zA-Z]*\s+(?:/var/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*(?:\s+|$))+$"
        ),
        // rm -rf with $TMPDIR (combined flags)
        safe_pattern!(
            "rm-rf-tmpdir",
            r"^rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f[a-zA-Z]*\s+(?:\$TMPDIR/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*(?:\s+|$))+$"
        ),
        safe_pattern!(
            "rm-fr-tmpdir",
            r"^rm\s+-[a-zA-Z]*f[a-zA-Z]*[rR][a-zA-Z]*\s+(?:\$TMPDIR/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*(?:\s+|$))+$"
        ),
        // rm -rf with ${TMPDIR} (braced form)
        safe_pattern!(
            "rm-rf-tmpdir-brace",
            r"^rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f[a-zA-Z]*\s+(?:\$\{TMPDIR\}/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*(?:\s+|$))+$"
        ),
        safe_pattern!(
            "rm-fr-tmpdir-brace",
            r"^rm\s+-[a-zA-Z]*f[a-zA-Z]*[rR][a-zA-Z]*\s+(?:\$\{TMPDIR\}/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*(?:\s+|$))+$"
        ),
        // rm -rf with quoted $TMPDIR
        safe_pattern!(
            "rm-rf-tmpdir-quoted",
            r#"^rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f[a-zA-Z]*\s+(?:"\$TMPDIR/(?!(?:[^"]*/)?\.\.(?:/|"))[^"]*"(?:\s+|$))+$"#
        ),
        safe_pattern!(
            "rm-fr-tmpdir-quoted",
            r#"^rm\s+-[a-zA-Z]*f[a-zA-Z]*[rR][a-zA-Z]*\s+(?:"\$TMPDIR/(?!(?:[^"]*/)?\.\.(?:/|"))[^"]*"(?:\s+|$))+$"#
        ),
        // rm -rf with quoted ${TMPDIR}
        safe_pattern!(
            "rm-rf-tmpdir-brace-quoted",
            r#"^rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f[a-zA-Z]*\s+(?:"\$\{TMPDIR\}/(?!(?:[^"]*/)?\.\.(?:/|"))[^"]*"(?:\s+|$))+$"#
        ),
        safe_pattern!(
            "rm-fr-tmpdir-brace-quoted",
            r#"^rm\s+-[a-zA-Z]*f[a-zA-Z]*[rR][a-zA-Z]*\s+(?:"\$\{TMPDIR\}/(?!(?:[^"]*/)?\.\.(?:/|"))[^"]*"(?:\s+|$))+$"#
        ),
        // rm -r -f (separate flags) in /tmp
        safe_pattern!(
            "rm-r-f-tmp",
            r"^rm\s+(-[a-zA-Z]+\s+)*-[rR]\s+(-[a-zA-Z]+\s+)*-f\s+(?:/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*(?:\s+|$))+$"
        ),
        safe_pattern!(
            "rm-f-r-tmp",
            r"^rm\s+(-[a-zA-Z]+\s+)*-f\s+(-[a-zA-Z]+\s+)*-[rR]\s+(?:/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*(?:\s+|$))+$"
        ),
        // rm -r -f (separate flags) in /var/tmp
        safe_pattern!(
            "rm-r-f-var-tmp",
            r"^rm\s+(-[a-zA-Z]+\s+)*-[rR]\s+(-[a-zA-Z]+\s+)*-f\s+(?:/var/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*(?:\s+|$))+$"
        ),
        safe_pattern!(
            "rm-f-r-var-tmp",
            r"^rm\s+(-[a-zA-Z]+\s+)*-f\s+(-[a-zA-Z]+\s+)*-[rR]\s+(?:/var/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*(?:\s+|$))+$"
        ),
        // rm -r -f (separate flags) with $TMPDIR
        safe_pattern!(
            "rm-r-f-tmpdir",
            r"^rm\s+(-[a-zA-Z]+\s+)*-[rR]\s+(-[a-zA-Z]+\s+)*-f\s+(?:\$TMPDIR/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*(?:\s+|$))+$"
        ),
        safe_pattern!(
            "rm-f-r-tmpdir",
            r"^rm\s+(-[a-zA-Z]+\s+)*-f\s+(-[a-zA-Z]+\s+)*-[rR]\s+(?:\$TMPDIR/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*(?:\s+|$))+$"
        ),
        // rm -r -f (separate flags) with ${TMPDIR}
        safe_pattern!(
            "rm-r-f-tmpdir-brace",
            r"^rm\s+(-[a-zA-Z]+\s+)*-[rR]\s+(-[a-zA-Z]+\s+)*-f\s+(?:\$\{TMPDIR\}/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*(?:\s+|$))+$"
        ),
        safe_pattern!(
            "rm-f-r-tmpdir-brace",
            r"^rm\s+(-[a-zA-Z]+\s+)*-f\s+(-[a-zA-Z]+\s+)*-[rR]\s+(?:\$\{TMPDIR\}/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*(?:\s+|$))+$"
        ),
        // rm --recursive --force (long flags) in /tmp
        safe_pattern!(
            "rm-recursive-force-tmp",
            r"^rm\s+.*--recursive.*--force\s+(?:/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*(?:\s+|$))+$"
        ),
        safe_pattern!(
            "rm-force-recursive-tmp",
            r"^rm\s+.*--force.*--recursive\s+(?:/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*(?:\s+|$))+$"
        ),
        // rm --recursive --force (long flags) in /var/tmp
        safe_pattern!(
            "rm-recursive-force-var-tmp",
            r"^rm\s+.*--recursive.*--force\s+(?:/var/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*(?:\s+|$))+$"
        ),
        safe_pattern!(
            "rm-force-recursive-var-tmp",
            r"^rm\s+.*--force.*--recursive\s+(?:/var/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*(?:\s+|$))+$"
        ),
        // rm --recursive --force (long flags) with $TMPDIR
        safe_pattern!(
            "rm-recursive-force-tmpdir",
            r"^rm\s+.*--recursive.*--force\s+(?:\$TMPDIR/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*(?:\s+|$))+$"
        ),
        safe_pattern!(
            "rm-force-recursive-tmpdir",
            r"^rm\s+.*--force.*--recursive\s+(?:\$TMPDIR/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*(?:\s+|$))+$"
        ),
        // rm --recursive --force (long flags) with ${TMPDIR}
        safe_pattern!(
            "rm-recursive-force-tmpdir-brace",
            r"^rm\s+.*--recursive.*--force\s+(?:\$\{TMPDIR\}/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*(?:\s+|$))+$"
        ),
        safe_pattern!(
            "rm-force-recursive-tmpdir-brace",
            r"^rm\s+.*--force.*--recursive\s+(?:\$\{TMPDIR\}/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*(?:\s+|$))+$"
        ),
        // -----------------------------------------------------------------
        // `find ... -delete` safe whitelist for temp directories.
        //
        // WHOLE-COMMAND ANCHOR: `^...$`. The safe pattern only matches
        // when the ENTIRE command is a single `find /tmp ... -delete`
        // invocation. Compound forms (`find /tmp -delete; echo done`,
        // `echo done; find /tmp -delete`, `(find /tmp -delete)`) do NOT
        // short-circuit through the safe pattern.
        //
        // The reason for whole-command anchoring: dcg's destructive
        // evaluator (for non-rm patterns) matches against the whole
        // sanitized command, not per-segment. If any safe pattern in the
        // pack matches, ALL destructive patterns are skipped (see
        // `evaluator.rs` `matches_safe_with_deadline` shadowing). A
        // segment-aware safe pattern would create a real bypass:
        //   find /tmp -delete; find /etc -delete
        // — the first segment matches the safe pattern, the destructive
        // pattern for the second segment is skipped, /etc is deleted.
        //
        // The trade-off is false positives on legitimate compound forms
        // like `echo done; find /tmp -delete` (the destructive
        // `find-delete-general` rule fires). Users can resolve via
        // `dcg allow-once` for one-off cases or temporary allowlist for
        // recurring scripts. Proper fix is a `parse_find_command`
        // analogue to `parse_rm_command` that splits per-invocation —
        // see git_safety_guard followup beads.
        //
        // STRICT shape: after `find <tmp-path>`, only allow more <tmp-path>
        // tokens or `-flag [value]` pairs whose value is NOT path-like
        // (i.e. doesn't start with `/`, `~`, or `$HOME`). This prevents
        //   find /tmp/foo /etc -delete
        // from short-circuiting through (the `/etc` would also be deleted).
        //
        // `-delete` must terminate the command (followed by end-of-string
        // or only more non-path flags).
        // -----------------------------------------------------------------
        safe_pattern!(
            "find-delete-tmp",
            r"^find\s+/tmp(?:/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*)?(?:\s+(?:/tmp(?:/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*)?|-[a-zA-Z][\S]*(?:\s+[^/~$\-\s][^|;&\s]*)?))*\s+-delete(?:\s+-[a-zA-Z][\S]*(?:\s+[^/~$\-\s][^|;&\s]*)?)*\s*$"
        ),
        safe_pattern!(
            "find-delete-var-tmp",
            r"^find\s+/var/tmp(?:/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*)?(?:\s+(?:/var/tmp(?:/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*)?|-[a-zA-Z][\S]*(?:\s+[^/~$\-\s][^|;&\s]*)?))*\s+-delete(?:\s+-[a-zA-Z][\S]*(?:\s+[^/~$\-\s][^|;&\s]*)?)*\s*$"
        ),
        safe_pattern!(
            "find-delete-tmpdir",
            r"^find\s+\$TMPDIR(?:/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*)?(?:\s+(?:\$TMPDIR(?:/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*)?|-[a-zA-Z][\S]*(?:\s+[^/~$\-\s][^|;&\s]*)?))*\s+-delete(?:\s+-[a-zA-Z][\S]*(?:\s+[^/~$\-\s][^|;&\s]*)?)*\s*$"
        ),
        safe_pattern!(
            "find-delete-tmpdir-brace",
            r"^find\s+\$\{TMPDIR\}(?:/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*)?(?:\s+(?:\$\{TMPDIR\}(?:/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*)?|-[a-zA-Z][\S]*(?:\s+[^/~$\-\s][^|;&\s]*)?))*\s+-delete(?:\s+-[a-zA-Z][\S]*(?:\s+[^/~$\-\s][^|;&\s]*)?)*\s*$"
        ),
        // -----------------------------------------------------------------
        // `unlink <file>` safe whitelist for temp directories.
        //
        // WHOLE-COMMAND ANCHOR: `^...$`. Same rationale as the find-delete
        // safe patterns — segment-aware safes shadow the destructive rule
        // across compound segments and re-open the bypass class.
        //
        // Trade-off accepted: `echo done; unlink /tmp/scratch` blocks (false
        // positive). Resolve via `dcg allow-once` for one-offs.
        // -----------------------------------------------------------------
        safe_pattern!(
            "unlink-tmp",
            r"^unlink\s+/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S+\s*$"
        ),
        safe_pattern!(
            "unlink-var-tmp",
            r"^unlink\s+/var/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S+\s*$"
        ),
        safe_pattern!(
            "unlink-tmpdir",
            r"^unlink\s+\$TMPDIR/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S+\s*$"
        ),
        safe_pattern!(
            "unlink-tmpdir-brace",
            r"^unlink\s+\$\{TMPDIR\}/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S+\s*$"
        ),
        // unlink invoked with --help / --version is read-only.
        safe_pattern!("unlink-help", r"^unlink\s+(?:--help|--version)\s*$"),
        // -----------------------------------------------------------------
        // `truncate` safe whitelist.
        //
        // truncate has many flag forms:
        //   -s 0 <file>       --size=0 <file>      (zero out)
        //   -s -<N> <file>    --size=-N <file>     (shrink by N bytes — destructive)
        //   -s <N> <file>     --size=N <file>      (set absolute — could grow OR shrink)
        //   -s +<N> <file>    --size=+N <file>     (grow — non-destructive)
        //   -s <fmt><N> <file>                     (>, <, %, etc. — destructive variants exist)
        //
        // Approach: only allow truncate when the FIRST positional argument
        // looks like a +<N> grow operation OR the path is under /tmp etc.
        // Whole-command anchored. --help / --version are read-only.
        // -----------------------------------------------------------------
        safe_pattern!("truncate-help", r"^truncate\s+(?:--help|--version)\s*$"),
        // Growing operations: -s +<N>, --size=+<N> (pure growth — no
        // data destroyed). We only whitelist the explicit `+` form because
        // absolute sizes can shrink existing files. The `-s` short form
        // takes its value as a separate token (`-s +1G`); `--size=` packs
        // value into the same token (`--size=+1G`).
        safe_pattern!(
            "truncate-grow",
            r"^truncate\s+(?:-s\s+\+\S+|--size=\+\S+)\s+\S+\s*$"
        ),
        // Temp-directory truncate (any size).
        safe_pattern!(
            "truncate-tmp",
            r"^truncate\s+(?:-s\s+\S+|--size=\S+)\s+/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S+\s*$"
        ),
        safe_pattern!(
            "truncate-var-tmp",
            r"^truncate\s+(?:-s\s+\S+|--size=\S+)\s+/var/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S+\s*$"
        ),
        safe_pattern!(
            "truncate-tmpdir",
            r"^truncate\s+(?:-s\s+\S+|--size=\S+)\s+\$TMPDIR/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S+\s*$"
        ),
        safe_pattern!(
            "truncate-tmpdir-brace",
            r"^truncate\s+(?:-s\s+\S+|--size=\S+)\s+\$\{TMPDIR\}/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S+\s*$"
        ),
        // -r/--reference <ref-file> <file> uses the size of ref-file.
        // This is a copy-size, not a destruction primitive — allowed when
        // both args are paths. We don't whitelist explicitly because the
        // destructive pattern only fires on `-s 0` / `-s -N` / `--size=0`
        // / `--size=-N`, leaving --reference invocations to the
        // default-allow path.
        // -----------------------------------------------------------------
        // `shred` safe whitelist.
        //
        // shred forms (all destructive when path is sensitive):
        //   shred <file>          — overwrite (file persists, content gone)
        //   shred -u <file>       — overwrite + unlink
        //   shred -fzu <file>     — force + zero-pass + unlink (most aggressive)
        //   shred --remove <file> — long form for -u
        //
        // Whole-command anchored. Allow temp dirs and --help/--version.
        // -----------------------------------------------------------------
        safe_pattern!("shred-help", r"^shred\s+(?:--help|--version)\s*$"),
        safe_pattern!(
            "shred-tmp",
            r"^shred(?:\s+(?:-[a-zA-Z][a-zA-Z0-9_-]*(?:\s+[^/~$\-\s][^\s|;&]*)?|--[a-z\-]+(?:=\S+|\s+[^/~$\-\s][^\s|;&]*)?))*\s+/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S+(?:\s+(?:-[a-zA-Z][a-zA-Z0-9_-]*(?:\s+[^/~$\-\s][^\s|;&]*)?|--[a-z\-]+(?:=\S+|\s+[^/~$\-\s][^\s|;&]*)?))*\s*$"
        ),
        safe_pattern!(
            "shred-var-tmp",
            r"^shred(?:\s+(?:-[a-zA-Z][a-zA-Z0-9_-]*(?:\s+[^/~$\-\s][^\s|;&]*)?|--[a-z\-]+(?:=\S+|\s+[^/~$\-\s][^\s|;&]*)?))*\s+/var/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S+(?:\s+(?:-[a-zA-Z][a-zA-Z0-9_-]*(?:\s+[^/~$\-\s][^\s|;&]*)?|--[a-z\-]+(?:=\S+|\s+[^/~$\-\s][^\s|;&]*)?))*\s*$"
        ),
        safe_pattern!(
            "shred-tmpdir",
            r"^shred(?:\s+(?:-[a-zA-Z][a-zA-Z0-9_-]*(?:\s+[^/~$\-\s][^\s|;&]*)?|--[a-z\-]+(?:=\S+|\s+[^/~$\-\s][^\s|;&]*)?))*\s+\$TMPDIR/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S+(?:\s+(?:-[a-zA-Z][a-zA-Z0-9_-]*(?:\s+[^/~$\-\s][^\s|;&]*)?|--[a-z\-]+(?:=\S+|\s+[^/~$\-\s][^\s|;&]*)?))*\s*$"
        ),
        safe_pattern!(
            "shred-tmpdir-brace",
            r"^shred(?:\s+(?:-[a-zA-Z][a-zA-Z0-9_-]*(?:\s+[^/~$\-\s][^\s|;&]*)?|--[a-z\-]+(?:=\S+|\s+[^/~$\-\s][^\s|;&]*)?))*\s+\$\{TMPDIR\}/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S+(?:\s+(?:-[a-zA-Z][a-zA-Z0-9_-]*(?:\s+[^/~$\-\s][^\s|;&]*)?|--[a-z\-]+(?:=\S+|\s+[^/~$\-\s][^\s|;&]*)?))*\s*$"
        ),
        // -----------------------------------------------------------------
        // `tar --remove-files` safe whitelist.
        //
        // `tar --remove-files -cf <archive> <source>` archives sources
        // and then deletes them. The destructive pair is `--remove-files`
        // PLUS a sensitive source path; safe rescue requires the source
        // to be entirely under a temp directory.
        //
        // Pattern shape: anchored `^...$`, optional flags (each flag may
        // take a non-path-like value — that swallows the `-cf out.tar`
        // archive arg without falsely matching it as a sensitive path),
        // then the temp-dir source, then optional trailing flags. The
        // `(?=\s+[^|;&]*--remove-files\b)` lookahead requires the flag
        // to actually be present (otherwise the destructive rule wouldn't
        // fire and no rescue is needed).
        //
        // Trade-off accepted: a multi-source mixed command like
        // `tar --remove-files -cf out.tar /tmp/foo /etc/bar` will NOT
        // be rescued (there's a non-tmp positional after /tmp/foo, so
        // the trailing repetition fails to consume it) and the
        // destructive rule will fire correctly on the /etc/bar source.
        // -----------------------------------------------------------------
        safe_pattern!(
            "tar-remove-files-tmp",
            r"^tar(?=\s+[^|;&]*--remove-files\b)(?:\s+(?:-[a-zA-Z][a-zA-Z0-9_-]*(?:\s+[^/~$\-\s][^\s|;&]*)?|--[a-z\-]+(?:=\S+|\s+[^/~$\-\s][^\s|;&]*)?))*\s+/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S+(?:\s+(?:-[a-zA-Z][a-zA-Z0-9_-]*(?:\s+[^/~$\-\s][^\s|;&]*)?|--[a-z\-]+(?:=\S+|\s+[^/~$\-\s][^\s|;&]*)?))*\s*$"
        ),
        safe_pattern!(
            "tar-remove-files-var-tmp",
            r"^tar(?=\s+[^|;&]*--remove-files\b)(?:\s+(?:-[a-zA-Z][a-zA-Z0-9_-]*(?:\s+[^/~$\-\s][^\s|;&]*)?|--[a-z\-]+(?:=\S+|\s+[^/~$\-\s][^\s|;&]*)?))*\s+/var/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S+(?:\s+(?:-[a-zA-Z][a-zA-Z0-9_-]*(?:\s+[^/~$\-\s][^\s|;&]*)?|--[a-z\-]+(?:=\S+|\s+[^/~$\-\s][^\s|;&]*)?))*\s*$"
        ),
        safe_pattern!(
            "tar-remove-files-tmpdir",
            r"^tar(?=\s+[^|;&]*--remove-files\b)(?:\s+(?:-[a-zA-Z][a-zA-Z0-9_-]*(?:\s+[^/~$\-\s][^\s|;&]*)?|--[a-z\-]+(?:=\S+|\s+[^/~$\-\s][^\s|;&]*)?))*\s+\$TMPDIR/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S+(?:\s+(?:-[a-zA-Z][a-zA-Z0-9_-]*(?:\s+[^/~$\-\s][^\s|;&]*)?|--[a-z\-]+(?:=\S+|\s+[^/~$\-\s][^\s|;&]*)?))*\s*$"
        ),
        safe_pattern!(
            "tar-remove-files-tmpdir-brace",
            r"^tar(?=\s+[^|;&]*--remove-files\b)(?:\s+(?:-[a-zA-Z][a-zA-Z0-9_-]*(?:\s+[^/~$\-\s][^\s|;&]*)?|--[a-z\-]+(?:=\S+|\s+[^/~$\-\s][^\s|;&]*)?))*\s+\$\{TMPDIR\}/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S+(?:\s+(?:-[a-zA-Z][a-zA-Z0-9_-]*(?:\s+[^/~$\-\s][^\s|;&]*)?|--[a-z\-]+(?:=\S+|\s+[^/~$\-\s][^\s|;&]*)?))*\s*$"
        ),
        // -----------------------------------------------------------------
        // `dd` safe whitelist.
        //
        // `dd if=/dev/zero of=<file>` (or `if=/dev/urandom of=<file>`)
        // overwrites the file's content in place — the truncate-equivalent
        // for files. The destructive trigger is `of=` to a sensitive path
        // that is NOT under /dev (device-level dd is system.disk's
        // territory; this pack's dd rules exclude /dev entirely).
        //
        // Operand syntax: dd's positional arguments are all `key=value`
        // pairs (`if=`, `of=`, `bs=`, `count=`, `status=`, `conv=`, ...)
        // and can appear in any order. The flexible operand pattern below
        // matches any `letters=value` token plus optional --long-flags.
        //
        // Pattern shape: anchored `^...$`, optional operands/flags,
        // `of=/tmp/...`, optional trailing operands/flags. The
        // `(?=\s+[^|;&]*\bof=)` lookahead requires `of=` to actually be
        // present (otherwise no destruction trigger and no rescue needed).
        //
        // Trade-off accepted: a multi-of= command (extremely rare; dd
        // only reads the LAST of= operand per POSIX) is not specially
        // handled; the safe pattern fires if the LAST positional in the
        // command-line happens to be a tmp path.
        // -----------------------------------------------------------------
        safe_pattern!(
            "dd-tmp",
            r#"^dd(?=\s+[^|;&]*\bof=)(?:\s+(?:[a-zA-Z]+=\S+|--?[a-zA-Z][a-zA-Z0-9\-]*(?:=\S+)?))*\s+of=['"]?/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S+(?:\s+(?:[a-zA-Z]+=\S+|--?[a-zA-Z][a-zA-Z0-9\-]*(?:=\S+)?))*\s*$"#
        ),
        safe_pattern!(
            "dd-var-tmp",
            r#"^dd(?=\s+[^|;&]*\bof=)(?:\s+(?:[a-zA-Z]+=\S+|--?[a-zA-Z][a-zA-Z0-9\-]*(?:=\S+)?))*\s+of=['"]?/var/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S+(?:\s+(?:[a-zA-Z]+=\S+|--?[a-zA-Z][a-zA-Z0-9\-]*(?:=\S+)?))*\s*$"#
        ),
        safe_pattern!(
            "dd-tmpdir",
            r#"^dd(?=\s+[^|;&]*\bof=)(?:\s+(?:[a-zA-Z]+=\S+|--?[a-zA-Z][a-zA-Z0-9\-]*(?:=\S+)?))*\s+of=['"]?\$TMPDIR/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S+(?:\s+(?:[a-zA-Z]+=\S+|--?[a-zA-Z][a-zA-Z0-9\-]*(?:=\S+)?))*\s*$"#
        ),
        safe_pattern!(
            "dd-tmpdir-brace",
            r#"^dd(?=\s+[^|;&]*\bof=)(?:\s+(?:[a-zA-Z]+=\S+|--?[a-zA-Z][a-zA-Z0-9\-]*(?:=\S+)?))*\s+of=['"]?\$\{TMPDIR\}/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S+(?:\s+(?:[a-zA-Z]+=\S+|--?[a-zA-Z][a-zA-Z0-9\-]*(?:=\S+)?))*\s*$"#
        ),
        // dd invoked with --help / --version is read-only.
        safe_pattern!("dd-help", r"^dd\s+(?:--help|--version)\s*$"),
        // -----------------------------------------------------------------
        // `mv` safe whitelist.
        //
        // The destructive `mv-sensitive-source-root-home` rule fires on
        // any mv whose command line mentions a sensitive path (source OR
        // destination) — the regex doesn't position-parse args because
        // mv supports `-t target sources...`, multi-source moves, and
        // various flag interleavings. False positives only happen for
        // /var/tmp (which contains the sensitive `/var` prefix); these
        // safe patterns rescue when ALL positional paths are under the
        // matching tmp variant. Pure /tmp / $TMPDIR moves don't even
        // reach the destructive rule (those prefixes aren't sensitive)
        // but we whitelist them for symmetry and discoverability.
        //
        // Pattern shape: anchored `^...$`, optional flags (each may take
        // a non-path-like value to swallow `-t target`-style args), then
        // one or more tmp-family paths separated by whitespace, then
        // optional trailing flags.
        // -----------------------------------------------------------------
        safe_pattern!(
            "mv-tmp",
            r"^mv(?:\s+(?:-[a-zA-Z][a-zA-Z0-9_-]*(?:\s+[^/~$\-\s][^\s|;&]*)?|--[a-z\-]+(?:=\S+|\s+[^/~$\-\s][^\s|;&]*)?))*\s+(?:/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S+\s+)+/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S+\s*$"
        ),
        safe_pattern!(
            "mv-var-tmp",
            r"^mv(?:\s+(?:-[a-zA-Z][a-zA-Z0-9_-]*(?:\s+[^/~$\-\s][^\s|;&]*)?|--[a-z\-]+(?:=\S+|\s+[^/~$\-\s][^\s|;&]*)?))*\s+(?:/var/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S+\s+)+/var/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S+\s*$"
        ),
        safe_pattern!(
            "mv-tmpdir",
            r"^mv(?:\s+(?:-[a-zA-Z][a-zA-Z0-9_-]*(?:\s+[^/~$\-\s][^\s|;&]*)?|--[a-z\-]+(?:=\S+|\s+[^/~$\-\s][^\s|;&]*)?))*\s+(?:\$TMPDIR/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S+\s+)+\$TMPDIR/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S+\s*$"
        ),
        safe_pattern!(
            "mv-tmpdir-brace",
            r"^mv(?:\s+(?:-[a-zA-Z][a-zA-Z0-9_-]*(?:\s+[^/~$\-\s][^\s|;&]*)?|--[a-z\-]+(?:=\S+|\s+[^/~$\-\s][^\s|;&]*)?))*\s+(?:\$\{TMPDIR\}/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S+\s+)+\$\{TMPDIR\}/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S+\s*$"
        ),
        // mv invoked with --help / --version is read-only.
        safe_pattern!("mv-help", r"^mv\s+(?:--help|--version)\s*$"),
    ]
}

/// Command words whose QUOTED ARGUMENTS are content — data the program
/// carries somewhere else (a message body, a pattern, an HTTP payload, a
/// remote host's command line) and never runs as code on THIS machine.
///
/// This list is an ALLOWLIST and it is the whole security boundary of the
/// `redirect-truncate-root-home` scan view: **the default is fail CLOSED**.
/// If a segment's command word is not on this list — an unknown program, a
/// substitution (`$SHELL`, `${SHELL}`, `$(...)`), a quote- or
/// backslash-obfuscated name (`"sh"`, `s\h`), an interpreter
/// (`python3 run.py`), or a string-executing program (`git submodule
/// foreach`, `ansible -m shell`, `nix-shell --run`, `npx -c`, `gdb -ex`,
/// `sed …/e`) — the segment is left completely UNMASKED and the raw regex
/// decides exactly as it did before this rule grew a scan view, i.e. it
/// denies. Adding a name here is a security decision; leaving one out only
/// costs a conservative denial.
///
/// Membership is necessary but not sufficient: `git`, `gh`, `curl`, `wget`,
/// `sed`, `ssh`, `scp` and `sftp` carry extra conditions checked in
/// `content_command_carries_data` (a `git` subcommand must be a message
/// subcommand, an `ssh` destination must be a genuine remote host, and so
/// on). `cat`/`tee`/`less` bodies arrive here already heredoc-masked by
/// `crate::heredoc::mask_non_executing_heredocs`.
const REDIRECT_CONTENT_COMMANDS: &[&str] = &[
    // message/notification senders and printers: quoted args are prose
    "orca", "echo", "printf",
    // structured-text filters: quoted args are programs for a pure,
    // non-executing expression language
    "jq", // pattern matchers: quoted args are regexes over file content
    "grep", "egrep", "fgrep", "rg", "ripgrep",
    // sed: quoted args are a script — only when it cannot execute (no `e`)
    "sed", // non-executing sinks/pagers (heredoc bodies already masked upstream)
    "cat", "tee", "less",
    // VCS / forge clients: only their message-carrying subcommands
    "git", "gh", // HTTP clients: only their request-body payloads
    "curl", "wget", // remote shells: the payload runs on the DESTINATION host
    "ssh", "scp", "sftp",
];

/// `-o`/`-O` option keys an `ssh`/`scp`/`sftp` invocation may carry while its
/// quoted payload still counts as content. Anything else (`ProxyCommand`,
/// `LocalCommand`, `PermitLocalCommand`, `Match exec`, `ProxyJump` with a
/// command, or any key not listed) can run a command through a LOCAL shell,
/// so it makes the payload non-content. `Host`/`HostName` are listed but
/// their value is additionally checked for locality; `ForwardAgent` is only
/// safe as `no`.
const SSH_SAFE_OPTION_KEYS: &[&str] = &[
    "port",
    "user",
    "identityfile",
    "identitiesonly",
    "stricthostkeychecking",
    "userknownhostsfile",
    "connecttimeout",
    "serveraliveinterval",
    "batchmode",
    "loglevel",
    "forwardagent",
    "host",
    "hostname",
];

/// A wrapper that execs its ARGUMENT VECTOR directly (no shell), so the
/// INNER command word decides whether the quoted text is content:
/// `sudo echo "use > ~/file"` is content, `sudo sh -c '> /etc/passwd'` is
/// local execution. Each wrapper's own option scan stops at its first
/// operand, so a flag that belongs to the inner program is never read as the
/// wrapper's (`sudo grep -i "note: date > ~/stamp" file` is grep's `-i`, not
/// sudo's shell mode).
struct WrapperSpec {
    name: &'static str,
    /// Short option letters that consume the rest of the cluster, or the
    /// next word, as their value.
    arg_short: &'static [u8],
    /// Long option names (without `--`) that consume the next word.
    arg_long: &'static [&'static str],
    /// Short letters that put the wrapper itself into shell-string mode
    /// (`sudo -s`, `sudo -i`, `env -S`) — then the wrapper IS the executor.
    shell_short: &'static [u8],
    /// Long options that put the wrapper into shell-string mode.
    shell_long: &'static [&'static str],
    /// Non-option operands consumed before the inner command word
    /// (`timeout <duration> cmd`).
    pre_operands: usize,
}

const REDIRECT_TRANSPARENT_WRAPPERS: &[WrapperSpec] = &[
    WrapperSpec {
        name: "sudo",
        arg_short: b"ugpChDRTU",
        arg_long: &[
            "user",
            "group",
            "prompt",
            "chdir",
            "other-user",
            "host",
            "close-from",
            "command-timeout",
        ],
        shell_short: b"si",
        shell_long: &["shell", "login"],
        pre_operands: 0,
    },
    WrapperSpec {
        name: "doas",
        arg_short: b"CuL",
        arg_long: &[],
        shell_short: b"si",
        shell_long: &["shell", "login"],
        pre_operands: 0,
    },
    WrapperSpec {
        name: "env",
        arg_short: b"uC",
        arg_long: &["unset", "chdir"],
        shell_short: b"S",
        shell_long: &["split-string"],
        pre_operands: 0,
    },
    WrapperSpec {
        name: "timeout",
        arg_short: b"sk",
        arg_long: &["signal", "kill-after"],
        shell_short: b"",
        shell_long: &[],
        pre_operands: 1,
    },
    WrapperSpec {
        name: "nohup",
        arg_short: b"",
        arg_long: &[],
        shell_short: b"",
        shell_long: &[],
        pre_operands: 0,
    },
    WrapperSpec {
        name: "nice",
        arg_short: b"n",
        arg_long: &["adjustment"],
        shell_short: b"",
        shell_long: &[],
        pre_operands: 0,
    },
    WrapperSpec {
        name: "ionice",
        arg_short: b"cnpPu",
        arg_long: &["class", "classdata", "pid", "pgid", "uid"],
        shell_short: b"",
        shell_long: &[],
        pre_operands: 0,
    },
    WrapperSpec {
        name: "time",
        arg_short: b"fo",
        arg_long: &["format", "output"],
        shell_short: b"",
        shell_long: &[],
        pre_operands: 0,
    },
    WrapperSpec {
        name: "command",
        arg_short: b"",
        arg_long: &[],
        shell_short: b"",
        shell_long: &[],
        pre_operands: 0,
    },
    WrapperSpec {
        name: "setsid",
        arg_short: b"",
        arg_long: &[],
        shell_short: b"",
        shell_long: &[],
        pre_operands: 0,
    },
    WrapperSpec {
        name: "stdbuf",
        arg_short: b"ioe",
        arg_long: &["input", "output", "error"],
        shell_short: b"",
        shell_long: &[],
        pre_operands: 0,
    },
];

/// A whitespace/metacharacter-delimited word of a pipeline stage. `live` is
/// true when the word starts OUTSIDE quotes; a word that starts with a quote
/// character is quoted content and can never be a command word.
struct SegmentWord<'a> {
    text: &'a str,
    live: bool,
}

/// Index just past the `$(...)` or backtick substitution that starts at `at`.
/// Returns `bytes.len()` for an unterminated substitution.
fn skip_substitution(bytes: &[u8], at: usize) -> usize {
    if bytes[at] == b'`' {
        let mut i = at + 1;
        while i < bytes.len() {
            match bytes[i] {
                b'\\' => i += 2,
                b'`' => return i + 1,
                _ => i += 1,
            }
        }
        return bytes.len();
    }
    // `$(`
    let mut depth = 1usize;
    let mut i = at + 2;
    let (mut in_single, mut in_double) = (false, false);
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'\\' && !in_single {
            i += 2;
            continue;
        }
        match b {
            b'\'' if !in_double => in_single = !in_single,
            b'"' if !in_single => in_double = !in_double,
            b'(' if !in_single && !in_double => depth += 1,
            b')' if !in_single && !in_double => {
                depth -= 1;
                if depth == 0 {
                    return i + 1;
                }
            }
            _ => {}
        }
        i += 1;
    }
    bytes.len()
}

/// Split a segment into PIPELINE STAGES of words. A new stage starts at the
/// beginning of the segment and after every live `|`, `&`, `;`, `(`, `)`,
/// `{`, `}`, so `echo '> /etc/passwd' | "sh"`, `(sh -c …)` and
/// `{ sh -c …; }` each surface the shell as a stage of its own — the segment
/// only counts as content when EVERY stage is content.
///
/// A `$(...)`/backtick substitution is absorbed into the word it touches
/// rather than opened as a stage: the classifier emits the whole
/// substitution as one `InlineCode` span, which this scan view never masks
/// (so a redirect inside it is already visible to the raw regex), while a
/// word that merely CONTAINS a substitution (`user@$(uname -n)`, `$SHELL`)
/// must fail closed as a command word or host.
fn segment_stages(segment: &str) -> Vec<Vec<SegmentWord<'_>>> {
    fn end_word<'a>(
        segment: &'a str,
        start: &mut Option<(usize, bool)>,
        at: usize,
        words: &mut Vec<SegmentWord<'a>>,
    ) {
        if let Some((s, live)) = start.take()
            && at > s
        {
            words.push(SegmentWord {
                text: &segment[s..at],
                live,
            });
        }
    }

    let bytes = segment.as_bytes();
    let mut stages: Vec<Vec<SegmentWord<'_>>> = vec![Vec::new()];
    let (mut in_single, mut in_double) = (false, false);
    let mut word_start: Option<(usize, bool)> = None;
    let mut i = 0usize;
    while i < bytes.len() {
        let b = bytes[i];
        let quoted = in_single || in_double;
        if b == b'\\' && !in_single {
            if word_start.is_none() {
                word_start = Some((i, !quoted));
            }
            i += 2;
            continue;
        }
        if !in_single && ((b == b'$' && bytes.get(i + 1) == Some(&b'(')) || b == b'`') {
            if word_start.is_none() {
                word_start = Some((i, !quoted));
            }
            i = skip_substitution(bytes, i);
            continue;
        }
        if !quoted {
            match b {
                b' ' | b'\t' | b'\n' | b'\r' => {
                    end_word(
                        segment,
                        &mut word_start,
                        i,
                        stages.last_mut().expect("stages is never empty"),
                    );
                    i += 1;
                    continue;
                }
                b'|' | b'&' | b';' | b'(' | b')' | b'{' | b'}' => {
                    end_word(
                        segment,
                        &mut word_start,
                        i,
                        stages.last_mut().expect("stages is never empty"),
                    );
                    stages.push(Vec::new());
                    i += 1;
                    continue;
                }
                _ => {}
            }
        }
        if word_start.is_none() {
            word_start = Some((i, !quoted && b != b'\'' && b != b'"'));
        }
        match b {
            b'\'' if !in_double => in_single = !in_single,
            b'"' if !in_single => in_double = !in_double,
            _ => {}
        }
        i += 1;
    }
    end_word(
        segment,
        &mut word_start,
        bytes.len(),
        stages.last_mut().expect("stages is never empty"),
    );
    stages
}

/// Strip one layer of surrounding quotes.
fn unquote(text: &str) -> &str {
    text.trim_matches(|c| c == '"' || c == '\'')
}

/// `NAME=value` environment prefix (`FOO=1 sh -c …`, `env FOO=1 …`).
fn is_assignment(word: &str) -> bool {
    let Some((name, _)) = word.split_once('=') else {
        return false;
    };
    !name.is_empty()
        && name.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// Reduce a command word to the program name to look up in
/// `REDIRECT_CONTENT_COMMANDS`, or `None` when no literal name can be
/// resolved.
///
/// Two rules, both load-bearing:
/// 1. A word containing `$` or a backtick (`$SHELL`, `${SHELL}`,
///    `$(which sh)`) names a program that is UNKNOWN at scan time, and an
///    unknown program is never content — fail closed.
/// 2. Quotes and backslash escapes are DEQUOTED (`"sh"` → `sh`, `s'h'` →
///    `sh`, `s\h` → `sh`), mirroring `crate::normalize`'s
///    `dequote_segment_command_words`, which the shipped entry point applies
///    before pack evaluation. Dequoting rather than failing closed is what
///    makes the pack API and the production path give the SAME answer: the
///    dequoted name is then looked up in an allowlist of non-executing
///    programs, so an obfuscated `sh` still misses the list and denies while
///    an obfuscated `"orca"` is content at both layers.
fn content_command_word(word: &str) -> Option<std::borrow::Cow<'_, str>> {
    if word.is_empty() || word.bytes().any(|b| matches!(b, b'$' | b'`')) {
        return None;
    }
    let dequoted: std::borrow::Cow<'_, str> =
        if word.bytes().any(|b| matches!(b, b'\'' | b'"' | b'\\')) {
            let mut out = String::with_capacity(word.len());
            let mut chars = word.chars();
            while let Some(c) = chars.next() {
                match c {
                    '\'' | '"' => {}
                    '\\' => {
                        if let Some(next) = chars.next() {
                            out.push(next);
                        }
                    }
                    _ => out.push(c),
                }
            }
            std::borrow::Cow::Owned(out)
        } else {
            std::borrow::Cow::Borrowed(word)
        };
    let name = match dequoted {
        std::borrow::Cow::Borrowed(s) => {
            let s = s.trim_start_matches('!');
            std::borrow::Cow::Borrowed(s.rsplit('/').next().unwrap_or(s))
        }
        std::borrow::Cow::Owned(s) => {
            let trimmed = s.trim_start_matches('!');
            let base = trimmed.rsplit('/').next().unwrap_or(trimmed);
            std::borrow::Cow::Owned(base.to_string())
        }
    };
    (!name.is_empty()).then_some(name)
}

/// Index of the inner command word that a transparent wrapper will exec, or
/// `None` when the wrapper itself runs a shell string (`sudo -s`, `env -S`).
/// Only the option words BEFORE the wrapper's first operand are inspected.
fn wrapper_inner_start(
    spec: &WrapperSpec,
    words: &[SegmentWord<'_>],
    from: usize,
) -> Option<usize> {
    let mut pre = spec.pre_operands;
    let mut i = from;
    while let Some(word) = words.get(i) {
        if !word.live {
            return Some(i);
        }
        let text = word.text;
        if text == "--" {
            return Some(i + 1);
        }
        if let Some(long) = text.strip_prefix("--") {
            let key = long.split('=').next().unwrap_or(long);
            if spec.shell_long.contains(&key) {
                return None;
            }
            i += 1;
            if !long.contains('=') && spec.arg_long.contains(&key) {
                i += 1;
            }
            continue;
        }
        if text.len() > 1 && text.starts_with('-') {
            let cluster = &text[1..];
            if cluster.bytes().any(|b| spec.shell_short.contains(&b)) {
                return None;
            }
            i += 1;
            if let Some(pos) = cluster.bytes().position(|b| spec.arg_short.contains(&b))
                && pos + 1 == cluster.len()
            {
                i += 1;
            }
            continue;
        }
        if is_assignment(text) {
            i += 1;
            continue;
        }
        if pre > 0 {
            pre -= 1;
            i += 1;
            continue;
        }
        return Some(i);
    }
    Some(i)
}

/// Whether ONE pipeline stage's quoted text is content: its command word
/// (reached through any number of transparent wrappers) must be an
/// allowlisted content-bearing program and must satisfy that program's extra
/// conditions. A stage with nothing to run is vacuously content; a
/// substituted command word never is.
fn stage_is_content(words: &[SegmentWord<'_>], own_hostname: Option<&str>) -> bool {
    let mut idx = 0usize;
    loop {
        while words
            .get(idx)
            .is_some_and(|w| w.live && (w.text == "!" || is_assignment(w.text)))
        {
            idx += 1;
        }
        let Some(word) = words.get(idx) else {
            return true;
        };
        let Some(name) = content_command_word(word.text) else {
            return false;
        };
        let name = name.as_ref();
        if let Some(spec) = REDIRECT_TRANSPARENT_WRAPPERS
            .iter()
            .find(|s| s.name == name)
        {
            match wrapper_inner_start(spec, words, idx + 1) {
                Some(next) => {
                    idx = next;
                    continue;
                }
                None => return false,
            }
        }
        return REDIRECT_CONTENT_COMMANDS.contains(&name)
            && content_command_carries_data(name, &words[idx + 1..], own_hostname);
    }
}

/// The per-program conditions behind `REDIRECT_CONTENT_COMMANDS`.
fn content_command_carries_data(
    name: &str,
    rest: &[SegmentWord<'_>],
    own_hostname: Option<&str>,
) -> bool {
    match name {
        "orca" | "echo" | "printf" | "jq" | "grep" | "egrep" | "fgrep" | "rg" | "ripgrep"
        | "cat" | "tee" | "less" => true,
        "sed" => !rest.iter().any(|w| sed_arg_executes(w.text)),
        "git" => git_carries_message(rest),
        "gh" => gh_carries_body(rest),
        "curl" | "wget" => http_client_sends_payload(rest),
        "ssh" | "scp" | "sftp" => remote_shell_payload_is_content(name, rest, own_hostname),
        _ => false,
    }
}

/// A `sed` argument that can make sed run a shell command: the `e` command,
/// or an `s///e` substitution flag. `sed 's|x|…|e'` executes its result.
fn sed_arg_executes(word: &str) -> bool {
    let raw = unquote(word);
    if let Some(script) = raw.strip_prefix("--expression=") {
        return sed_script_executes(unquote(script));
    }
    if let Some(script) = raw.strip_prefix("-e") {
        return !script.is_empty() && sed_script_executes(unquote(script));
    }
    if raw.starts_with('-') {
        return false;
    }
    sed_script_executes(raw)
}

fn sed_script_executes(script: &str) -> bool {
    for piece in script.split([';', '\n']) {
        let bytes = piece
            .trim_start_matches(|c: char| c.is_whitespace() || matches!(c, '{' | '}' | '!'))
            .as_bytes();
        let mut i = 0usize;
        // Skip any line/regex address in front of the command letter.
        while i < bytes.len() {
            match bytes[i] {
                b'$' | b',' | b'+' | b'~' | b' ' | b'\t' => i += 1,
                d if d.is_ascii_digit() => i += 1,
                b'/' => {
                    i += 1;
                    while i < bytes.len() {
                        if bytes[i] == b'\\' {
                            i += 2;
                            continue;
                        }
                        let hit = bytes[i] == b'/';
                        i += 1;
                        if hit {
                            break;
                        }
                    }
                }
                b'\\' if i + 1 < bytes.len() => {
                    let delim = bytes[i + 1];
                    i += 2;
                    while i < bytes.len() {
                        if bytes[i] == b'\\' {
                            i += 2;
                            continue;
                        }
                        let hit = bytes[i] == delim;
                        i += 1;
                        if hit {
                            break;
                        }
                    }
                }
                _ => break,
            }
        }
        match bytes.get(i) {
            Some(b'e') => return true,
            Some(b's') if sed_substitution_has_e_flag(&bytes[i..]) => return true,
            _ => {}
        }
    }
    false
}

/// `s<delim>pattern<delim>replacement<delim>flags` with `e` among the flags.
fn sed_substitution_has_e_flag(bytes: &[u8]) -> bool {
    let Some(&delim) = bytes.get(1) else {
        return false;
    };
    if delim.is_ascii_alphanumeric() || delim == b'\\' || delim.is_ascii_whitespace() {
        return false;
    }
    let mut seen = 0usize;
    let mut i = 1usize;
    while i < bytes.len() && seen < 3 {
        if bytes[i] == b'\\' {
            i += 2;
            continue;
        }
        if bytes[i] == delim {
            seen += 1;
        }
        i += 1;
    }
    seen == 3
        && bytes[i..]
            .iter()
            .take_while(|b| b.is_ascii_alphanumeric())
            .any(|&b| b == b'e')
}

/// Global `git` options that consume the following word as their value.
const GIT_GLOBAL_ARG_OPTIONS: &[&str] = &[
    "-c",
    "-C",
    "--exec-path",
    "--git-dir",
    "--work-tree",
    "--namespace",
    "--config-env",
    "--super-prefix",
];

/// `git` is content only for its message-carrying subcommands carrying a
/// message payload: `git commit`/`tag`/`notes`/`stash` with `-m`/`--message`/
/// `-F`/`--file`. `git submodule foreach '…'`, `git config alias.x '!…'` and
/// every other subcommand are NOT content and keep denying.
///
/// Global options in front of the subcommand are SKIPPED, not fail-closed,
/// including `-c alias.x=!sh`: defining an alias does not run it, and the
/// invocation that WOULD run it (`git x`) has a subcommand that is not a
/// message subcommand and therefore denies. Failing closed here would also
/// contradict the shipped path, which treats a `git commit -m` payload as
/// data upstream of this rule (verified unchanged from base `0a38dee`).
fn git_carries_message(rest: &[SegmentWord<'_>]) -> bool {
    let live: Vec<&str> = rest.iter().filter(|w| w.live).map(|w| w.text).collect();
    let mut idx = 0usize;
    while let Some(&text) = live.get(idx) {
        if !text.starts_with('-') {
            break;
        }
        idx += 1;
        if !text.contains('=') && GIT_GLOBAL_ARG_OPTIONS.contains(&text) {
            idx += 1;
        }
    }
    let Some(&subcommand) = live.get(idx) else {
        return false;
    };
    if !matches!(subcommand, "commit" | "tag" | "notes" | "stash") {
        return false;
    }
    live[idx + 1..].iter().any(|text| {
        matches!(*text, "-m" | "--message" | "-F" | "--file")
            || text.starts_with("--message=")
            || text.starts_with("--file=")
    })
}

/// `gh` is content only for issue/PR/release text subcommands carrying a
/// `--body`/`--title` payload.
fn gh_carries_body(rest: &[SegmentWord<'_>]) -> bool {
    let mut subcommand: Option<&str> = None;
    let mut has_body = false;
    for word in rest.iter().filter(|w| w.live) {
        let text = word.text;
        if subcommand.is_none() {
            if text.starts_with('-') {
                return false;
            }
            subcommand = Some(text);
            continue;
        }
        let key = text.split('=').next().unwrap_or(text);
        if matches!(
            key,
            "-b" | "--body" | "--body-file" | "-F" | "-t" | "--title" | "--notes"
        ) {
            has_body = true;
        }
    }
    has_body && matches!(subcommand, Some("issue" | "pr" | "release" | "gist"))
}

/// `curl`/`wget` are content only when the quoted text is a request BODY.
/// An output option (`-o`, `-O`, `--output`) or a config/upload file makes
/// the invocation something other than a pure payload carrier.
fn http_client_sends_payload(rest: &[SegmentWord<'_>]) -> bool {
    let mut has_data = false;
    for word in rest.iter().filter(|w| w.live) {
        let key = word.text.split('=').next().unwrap_or(word.text);
        if matches!(
            key,
            "-d" | "--data"
                | "--data-raw"
                | "--data-binary"
                | "--data-ascii"
                | "--data-urlencode"
                | "--post-data"
                | "--body-data"
        ) {
            has_data = true;
            continue;
        }
        if matches!(
            key,
            "-o" | "-O"
                | "-K"
                | "-T"
                | "--output"
                | "--output-dir"
                | "--remote-name"
                | "--config"
                | "--upload-file"
        ) {
            return false;
        }
    }
    has_data
}

/// Whether an `ssh`/`scp`/`sftp` invocation's quoted payload runs on ANOTHER
/// machine. Content requires all three: a destination that names a genuine
/// remote host, no `-o`/`-O` option outside `SSH_SAFE_OPTION_KEYS`
/// (`ProxyCommand`/`LocalCommand` run through a LOCAL shell), and no
/// command-shaped `-J`/`-W`/`-L`/`-R`/`-D` value. Nothing proved remote =
/// not content.
fn remote_shell_payload_is_content(
    client: &str,
    rest: &[SegmentWord<'_>],
    own_hostname: Option<&str>,
) -> bool {
    let takes_arg: &[u8] = match client {
        "scp" => b"cFiJloPSD",
        "sftp" => b"BbcDFiJloPRSsX",
        _ => b"bcDEeFIiJLlmOopQRSWwB",
    };
    let mut found_remote = false;
    let mut idx = 0usize;
    while idx < rest.len() {
        let word = &rest[idx];
        idx += 1;
        if !word.live {
            continue;
        }
        let text = word.text;
        if text == "--" {
            continue;
        }
        if let Some(cluster) = text
            .strip_prefix('-')
            .filter(|c| !c.is_empty() && !c.starts_with('-'))
        {
            let mut value: Option<&str> = None;
            let mut taking: Option<u8> = None;
            for (pos, letter) in cluster.bytes().enumerate() {
                if takes_arg.contains(&letter) {
                    taking = Some(letter);
                    value = if pos + 1 < cluster.len() {
                        Some(&cluster[pos + 1..])
                    } else {
                        let next = rest.get(idx).map(|w| w.text);
                        idx += 1;
                        next
                    };
                    break;
                }
            }
            match taking {
                Some(b'o' | b'O') => {
                    let Some(value) = value else { return false };
                    if !ssh_option_is_safe(value, own_hostname) {
                        return false;
                    }
                }
                Some(b'J' | b'W' | b'L' | b'R' | b'D') => {
                    let Some(value) = value else { return false };
                    if ssh_value_is_command_shaped(value) {
                        return false;
                    }
                }
                _ => {}
            }
            continue;
        }
        if text.starts_with("--") {
            continue;
        }
        if client == "ssh" {
            // The first non-option operand is the destination; everything
            // after it is the remote command line.
            return !ssh_host_is_local_with(text, own_hostname);
        }
        // scp/sftp: every `host:path` operand must name a remote host.
        let unq = unquote(text);
        let host_part = if let Some(bracketed) = unq.strip_prefix('[') {
            bracketed.split(']').next()
        } else if unq.starts_with("ssh://") || unq.starts_with("sftp://") {
            Some(unq)
        } else {
            unq.split_once(':').map(|(host, _)| host)
        };
        if let Some(host) = host_part {
            if ssh_host_is_local_with(host, own_hostname) {
                return false;
            }
            found_remote = true;
        }
    }
    found_remote
}

/// One `-o Key=Value` (or `-oKey=Value`, or `-o "Key Value"`) is safe only
/// for a known non-executing key with a non-local, quote-free value.
fn ssh_option_is_safe(value: &str, own_hostname: Option<&str>) -> bool {
    let text = unquote(value);
    if text
        .bytes()
        .any(|b| matches!(b, b'\'' | b'"' | b'`' | b'$'))
    {
        return false;
    }
    let (key, val) = text
        .split_once('=')
        .or_else(|| text.split_once(char::is_whitespace))
        .unwrap_or((text, ""));
    let key = key.trim().to_ascii_lowercase();
    if !SSH_SAFE_OPTION_KEYS.contains(&key.as_str()) {
        return false;
    }
    let val = val.trim();
    if key == "forwardagent" {
        return val.eq_ignore_ascii_case("no");
    }
    if (key == "host" || key == "hostname") && ssh_host_is_local_with(val, own_hostname) {
        return false;
    }
    true
}

/// A `-J`/`-W`/`-L`/`-R`/`-D` value that looks like a command line rather
/// than a host/port spec.
fn ssh_value_is_command_shaped(value: &str) -> bool {
    let text = unquote(value);
    text.is_empty()
        || text.bytes().any(|b| {
            matches!(
                b,
                b' ' | b'\t' | b'$' | b'`' | b'\'' | b'"' | b';' | b'|' | b'&'
            )
        })
}

/// Loopback / self-referencing destination for ssh/scp/sftp. Any
/// substitution in the host position is treated as local (fail closed), and
/// so is every host when this machine's own name could not be resolved
/// (`own_hostname` is `None`) — an unknown own name must never let a
/// possibly-local destination pass as remote.
fn ssh_host_is_local_with(host: &str, own_hostname: Option<&str>) -> bool {
    let host = host.trim_matches(|c| c == '"' || c == '\'');
    let host = host
        .strip_prefix("ssh://")
        .or_else(|| host.strip_prefix("sftp://"))
        .unwrap_or(host);
    // user@host, [v6]:port, host:port (ssh:// form)
    let host = host.rsplit('@').next().unwrap_or(host);
    let host = if let Some(rest) = host.strip_prefix('[') {
        rest.split(']').next().unwrap_or(rest)
    } else if host.matches(':').count() == 1 {
        host.split(':').next().unwrap_or(host)
    } else {
        host
    };
    let host = host.trim_end_matches('.');
    if host.is_empty() {
        return false;
    }
    if host.starts_with('$') || host.starts_with('`') || host.contains("$(") || host.contains("${")
    {
        return true;
    }
    let lower = host.to_ascii_lowercase();
    if matches!(
        lower.as_str(),
        "localhost"
            | "localhost.localdomain"
            | "localhost4"
            | "localhost6"
            | "ip6-localhost"
            | "ip6-loopback"
            | "0.0.0.0"
            | "::"
            | "::1"
    ) || lower.starts_with("127.")
        || lower.starts_with("localhost.")
    {
        return true;
    }
    if let Ok(ip) = lower.parse::<std::net::IpAddr>() {
        let v4_mapped = match ip {
            std::net::IpAddr::V6(v6) => v6.to_ipv4_mapped(),
            std::net::IpAddr::V4(_) => None,
        };
        if ip.is_loopback()
            || ip.is_unspecified()
            || v4_mapped.is_some_and(|v4| v4.is_loopback() || v4.is_unspecified())
        {
            return true;
        }
    }
    // Numeric / octal / hex disguises of 127.0.0.1 (`2130706433`, `0x7f000001`,
    // `0177.0.0.1`): no real remote host looks like this.
    if lower.bytes().all(|b| b.is_ascii_digit())
        || (lower.starts_with('0')
            && lower
                .bytes()
                .all(|b| b.is_ascii_hexdigit() || b == b'x' || b == b'.'))
    {
        return true;
    }
    // Fail closed: without our own name we cannot prove the host is remote.
    let Some(own) = own_hostname.map(str::trim).filter(|s| !s.is_empty()) else {
        return true;
    };
    let own = own.to_ascii_lowercase();
    lower == own || lower.split('.').next() == own.split('.').next()
}

/// This host's name, resolved once. Portable across the shipped targets:
/// the Linux kernel files first, then `HOSTNAME`, then `uname -n` /
/// `hostname` (macOS and any host without `/etc/hostname`). `None` means
/// unresolvable, which `ssh_host_is_local_with` treats as LOCAL.
fn local_hostname() -> Option<&'static str> {
    static HOSTNAME: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();
    HOSTNAME
        .get_or_init(|| {
            ["/proc/sys/kernel/hostname", "/etc/hostname"]
                .iter()
                .find_map(|p| std::fs::read_to_string(p).ok())
                .or_else(|| std::env::var("HOSTNAME").ok())
                .or_else(|| hostname_from_command("uname", &["-n"]))
                .or_else(|| hostname_from_command("hostname", &[]))
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        })
        .as_deref()
}

/// Run a hostname-reporting command with a one-second budget. Any spawn
/// failure, non-zero exit or timeout yields `None`.
fn hostname_from_command(program: &str, args: &[&str]) -> Option<String> {
    use std::process::{Command, Stdio};
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                if !status.success() {
                    return None;
                }
                break;
            }
            Ok(None) => {
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return None;
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            Err(_) => return None,
        }
    }
    let output = child.wait_with_output().ok()?;
    String::from_utf8(output.stdout)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Whether a whole segment's quoted text is content: EVERY pipeline stage
/// must be content. One non-content stage (`… | "sh"`, `… | at now`) leaves
/// the segment unmasked.
fn segment_is_content(segment: &str, own_hostname: Option<&str>) -> bool {
    segment_stages(segment)
        .iter()
        .all(|stage| stage_is_content(stage, own_hostname))
}

/// Scan view for `redirect-truncate-root-home`: a redirect operator is only a
/// redirect when it is UNQUOTED on the local command line.
///
/// **The default is fail CLOSED.** A `>` byte is blanked to a space (so the
/// regex cannot match it) only when ALL of the following hold: it sits in a
/// quoted `Data`/`Argument` span, and every pipeline stage of its segment
/// has an allowlisted content-bearing command word
/// (`REDIRECT_CONTENT_COMMANDS`, reached through transparent wrappers such
/// as `sudo`/`env`/`timeout`), and that command word's own condition holds
/// (a `git` message subcommand, a `curl -d` payload, an `ssh` destination
/// that is a genuine remote host with no locally-executing `-o` option).
/// Anything else — an unknown program, `$SHELL`, `"sh"`, `s\h`, `$(…)` in
/// the command word, `python3 run.py`, `git submodule foreach`,
/// `ansible -m shell`, `nix-shell --run`, `gdb -ex`, `sed …/e`, a shell-mode
/// wrapper (`sudo -s`, `env -S`), a pipe into any of those, or ssh pointed
/// at this machine — is left completely unmasked and denies exactly as it
/// did before this rule grew a scan view.
///
/// Never masked regardless: unquoted operators, quoted TARGETS after an
/// unquoted operator, and `InlineCode` spans (`bash -c '…'`, `$(…)`,
/// backticks). Byte length is preserved so match spans still index the
/// original text.
fn redirect_unquoted_scan_view(cmd: &str) -> std::borrow::Cow<'_, str> {
    redirect_unquoted_scan_view_with(cmd, local_hostname())
}

/// `redirect_unquoted_scan_view` with this host's name injected, so both
/// arms of the loopback rule (own name resolvable / unresolvable) are
/// testable without depending on the build host.
fn redirect_unquoted_scan_view_with<'a>(
    cmd: &'a str,
    own_hostname: Option<&str>,
) -> std::borrow::Cow<'a, str> {
    if !cmd.bytes().any(|b| matches!(b, b'\'' | b'"')) {
        return std::borrow::Cow::Borrowed(cmd);
    }
    let spans = crate::context::classify_command(cmd);
    let mut out: Option<Vec<u8>> = None;
    for range in crate::packs::split_command_segment_ranges(cmd) {
        if !segment_is_content(&cmd[range.clone()], own_hostname) {
            continue;
        }
        for span in spans.spans() {
            if !matches!(span.kind, SpanKind::Data | SpanKind::Argument) {
                continue;
            }
            let start = span.byte_range.start.max(range.start);
            let end = span.byte_range.end.min(range.end);
            for idx in start..end {
                if cmd.as_bytes()[idx] == b'>' {
                    out.get_or_insert_with(|| cmd.as_bytes().to_vec())[idx] = b' ';
                }
            }
        }
    }
    match out {
        // Only ASCII `>` bytes were replaced by ASCII spaces, so the buffer is
        // still valid UTF-8; fall back to the raw text (conservative: the
        // regex sees everything) if that ever fails.
        Some(bytes) => String::from_utf8(bytes)
            .map_or(std::borrow::Cow::Borrowed(cmd), std::borrow::Cow::Owned),
        None => std::borrow::Cow::Borrowed(cmd),
    }
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    // Severity levels:
    // - Critical: Most dangerous, irreversible, high-confidence detections
    // - High: Dangerous but more context-dependent (default)
    // - Medium: Warn by default
    // - Low: Log only

    vec![
        // rm -rf on root or home paths (CRITICAL - catastrophic, never allow)
        // Target set covers:
        //   - literal `/` or `~` (optionally quoted/backslash-escaped)
        //   - `$HOME` and `${HOME}` (optionally quoted), which the shell
        //     expands to the user's home directory before rm sees it
        destructive_pattern!(
            "rm-rf-root-home",
            r#"rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f[a-zA-Z]*\s+['"\\]?(?:[/~]|\$\{?HOME\b)|rm\s+-[a-zA-Z]*f[a-zA-Z]*[rR][a-zA-Z]*\s+['"\\]?(?:[/~]|\$\{?HOME\b)"#,
            "rm -rf on root or home paths is EXTREMELY DANGEROUS. This command will NOT be executed. Ask the user to run it manually if truly needed.",
            Critical,
            "This command would recursively delete files starting from the root filesystem (/) \
             or home directory (~). This is catastrophic and will destroy:\n\n\
             - Your entire operating system\n\
             - All installed applications and libraries\n\
             - All user data, documents, and configurations\n\
             - Boot files, making the system unbootable\n\n\
             There is NO recovery without backups. Even with backups, full restoration \
             takes hours to days.\n\n\
             If you need to delete specific files, use explicit paths:\n  \
             rm -rf /path/to/specific/directory\n\n\
             Always preview what would be deleted first:\n  \
             find /path/to/directory -type f | head -20",
            RM_RF_ROOT_HOME_SUGGESTIONS
        ),
        // Same root/home catastrophe but with SEPARATE flags (`rm -r -f /`,
        // `rm -f -r /`). The previous pattern only caught the combined `-rf`
        // form. Without this, `rm -r -f /` fell through to the general
        // `rm-r-f-separate` rule (High) instead of being attributed as
        // Critical root deletion.
        destructive_pattern!(
            "rm-r-f-separate-root-home",
            r#"rm\s+(-[a-zA-Z]+\s+)*-[rR]\s+(-[a-zA-Z]+\s+)*-f\s+['"\\]?(?:[/~]|\$\{?HOME\b)|rm\s+(-[a-zA-Z]+\s+)*-f\s+(-[a-zA-Z]+\s+)*-[rR]\s+['"\\]?(?:[/~]|\$\{?HOME\b)"#,
            "rm with separate -r -f flags targeting root or home is EXTREMELY DANGEROUS.",
            Critical,
            "Separate `-r -f` flags on `/` or `~` have identical effect to `rm -rf /`: \
             recursive, forced, silent deletion of the entire filesystem or home directory.\n\n\
             There is NO recovery without backups. Run only if truly intended.",
            RM_RF_ROOT_HOME_SUGGESTIONS
        ),
        // Same root/home catastrophe but with LONG flags
        // (`rm --recursive --force /`, `rm --force --recursive /`).
        destructive_pattern!(
            "rm-recursive-force-root-home",
            r#"rm\s+.*--recursive.*--force\s+['"\\]?(?:[/~]|\$\{?HOME\b)|rm\s+.*--force.*--recursive\s+['"\\]?(?:[/~]|\$\{?HOME\b)"#,
            "rm --recursive --force targeting root or home is EXTREMELY DANGEROUS.",
            Critical,
            "The long-flag form has identical effect to `rm -rf /`: recursive, forced, \
             silent deletion. Run only if truly intended.",
            RM_RF_ROOT_HOME_SUGGESTIONS
        ),
        // General rm -rf (caught after safe patterns) - High because temp paths are allowed
        destructive_pattern!(
            "rm-rf-general",
            r"rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f|rm\s+-[a-zA-Z]*f[a-zA-Z]*[rR]",
            "rm -rf is destructive and requires human approval. Explain what you want to delete and why, then ask the user to run the command manually.",
            High,
            "rm -rf recursively removes files and directories without confirmation prompts. \
             The -f (force) flag suppresses all warnings, making accidental deletions \
             silent and immediate.\n\n\
             Why this is dangerous:\n\
             - Deleted files bypass the trash - they're gone immediately\n\
             - Typos in paths can delete unintended directories\n\
             - Wildcards can expand to match more than expected\n\
             - No undo mechanism exists\n\n\
             Safe alternatives:\n\
             - rm -ri: Interactive mode, confirms each file\n\
             - trash-cli: Moves files to trash instead of deleting\n\
             - rm -rf in /tmp, /var/tmp, $TMPDIR: Allowed (safe temp directories)\n\n\
             Preview what would be deleted:\n  \
             find /path/to/delete -type f | wc -l  # Count files\n  \
             ls -la /path/to/delete               # List contents",
            RM_RF_GENERAL_SUGGESTIONS
        ),
        // rm -r -f (separate flags)
        destructive_pattern!(
            "rm-r-f-separate",
            r"rm\s+(-[a-zA-Z]+\s+)*-[rR]\s+(-[a-zA-Z]+\s+)*-f|rm\s+(-[a-zA-Z]+\s+)*-f\s+(-[a-zA-Z]+\s+)*-[rR]",
            "rm with separate -r -f flags is destructive and requires human approval.",
            High,
            "rm with separate -r and -f flags has the same effect as rm -rf: recursive \
             forced deletion without confirmation.\n\n\
             Common variations that are all equivalent:\n\
             - rm -r -f path\n\
             - rm -f -r path\n\
             - rm -r -f -v path (verbose but still forced)\n\n\
             All carry the same risks as rm -rf: immediate, silent, irreversible deletion.\n\n\
             Safer approach for temporary directories:\n\
             - rm -r -f /tmp/mydir    # Allowed - temp directories are safe\n\
             - rm -r -f $TMPDIR/mydir # Allowed - uses system temp dir\n\n\
             For other paths, prefer:\n  \
             rm -ri /path  # Interactive confirmation",
            RM_R_F_SEPARATE_SUGGESTIONS
        ),
        // rm --recursive --force (long flags)
        destructive_pattern!(
            "rm-recursive-force-long",
            r"rm\s+.*--recursive.*--force|rm\s+.*--force.*--recursive",
            "rm --recursive --force is destructive and requires human approval.",
            High,
            "rm --recursive --force is the long-form equivalent of rm -rf. While more \
             readable, it carries identical risks: silent, recursive, irreversible deletion.\n\n\
             The long flags may appear in:\n\
             - Scripts aiming for clarity\n\
             - Generated code from build tools\n\
             - Cross-platform compatibility scenarios\n\n\
             All standard rm -rf precautions apply:\n\
             - Verify the path before running\n\
             - Use absolute paths to avoid ambiguity\n\
             - Consider using trash-cli for recoverable deletion\n\n\
             Preview command:\n  \
             find /path --maxdepth 2 -ls | head -30",
            RM_RECURSIVE_FORCE_SUGGESTIONS
        ),
        // ----- `find ... -delete` (Critical: root/home target) -----
        //
        // `find <sensitive-path> -delete` recursively removes everything
        // under the path — bytewise-equivalent to `rm -rf <sensitive-path>`.
        // This rule exists to close the most common dcg-bypass pattern in
        // the wild: agents that learn `rm -rf` is blocked simply swap it
        // for `find -delete`. Without this rule, dcg's protection against
        // catastrophic root/home deletion is one Google search away from
        // useless.
        //
        // The regex matches `find` at any word boundary (so it fires
        // inside compound commands like `echo foo; find /etc -delete`,
        // and on path-prefixed binaries like `/usr/bin/find / -delete`),
        // then somewhere later a sensitive path token (root, common
        // system dirs, or home-like prefixes) preceded by whitespace or
        // `=`, then a `-delete` action flag terminated by whitespace,
        // end-of-string, or a shell separator (`;`, `&`, `|`). The
        // `(?:\s|$|[;&|])` end anchor — instead of `\b` — ensures
        // `-delete-this-not-a-flag` does NOT false-positive (the `-`
        // after `-delete` is not in our terminator set even though `\b`
        // would happily allow it).
        destructive_pattern!(
            "find-delete-root-home",
            // End anchor `(?:\s|$|[;&|)\n])` accepts shell separators,
            // newlines, and a subshell-close `)` after `-delete` so
            // `(find /etc -delete)` and `find /etc -delete | tee log`
            // both fire. Without `)` in the set, subshell forms
            // silently bypass.
            r#"\bfind\b[^|;&]*?(?:\s|=)['"\\]?(?:/(?:etc|usr|bin|sbin|root|boot|lib|lib64|var|home|sys|proc|dev|opt)(?:/|(?=\s|$|['"]))|/(?=\s|$|['"])|~(?=\s|$|/)|\$\{?HOME\b)[^|;&]*?\s-delete(?:\s|$|[;&|)\n])"#,
            "find <sensitive-path> -delete is bytewise-equivalent to rm -rf on root/home and is EXTREMELY DANGEROUS. This command will NOT be executed.",
            Critical,
            "`find <path> -delete` is the bytewise-equivalent of `rm -rf <path>`: \
             it recursively removes every file and (when -depth is implied) every \
             directory matched by the predicate. Targeting `/`, `~`, `$HOME`, or any \
             top-level system directory (`/etc`, `/usr`, `/var`, `/home`, `/boot`, \
             `/dev`, `/proc`, `/sys`, `/lib`, `/lib64`, `/opt`, `/root`) destroys \
             the operating system or user data the same way `rm -rf` would.\n\n\
             There is NO recovery without backups.\n\n\
             If you only need to delete files matching a pattern, use a much more \
             specific path:\n  \
             find /path/to/specific/subdir -name '*.tmp' -delete\n\n\
             Always preview first:\n  \
             find /path -type f | head -20",
            FIND_DELETE_SUGGESTIONS
        ),
        // ----- `find ... -delete` (High: any other target) -----
        //
        // The general rule fires after the safe-pattern whitelist (which
        // allows `find /tmp/...`, `/var/tmp/...`, `$TMPDIR/...`, and
        // `${TMPDIR}/...`). Any other `find ... -delete` is an
        // unscoped destructive operation that should require human
        // approval, exactly like the parallel `rm-rf-general` rule.
        destructive_pattern!(
            "find-delete-general",
            // `\bfind\b` (not `^\s*find\b`) so the rule fires in compound
            // forms (`echo foo; find . -delete`, `(find . -delete)`) and
            // on path-prefixed binaries. `-delete(?:\s|$|[;&|)\n])` (not
            // `\b`) so `-delete-this-not-a-flag` — where `\b` happily
            // allows the following `-` — does NOT false-positive, while
            // shell separators and subshell-close are still accepted.
            r"\bfind\b[^|;&]*\s-delete(?:\s|$|[;&|)\n])",
            "find ... -delete is destructive (bytewise-equivalent to rm -rf on the matched tree) and requires human approval.",
            High,
            "`find ... -delete` recursively deletes every path matched by the find \
             expression. The action flag `-delete` implies `-depth` (so directories \
             are deleted after their contents). With no path predicate it deletes \
             the entire starting tree. Common pitfalls:\n\n\
             - `find . -delete` deletes the current working directory's contents.\n\
             - `find <path> -delete` with a wide -name glob matches more than expected.\n\
             - `-delete` errors are silent by default — failures don't stop the walk.\n\n\
             Safer alternatives:\n\
             - Drop -delete to preview: `find <path> ...` (just lists matches)\n\
             - Add -print -delete to log each deletion as it happens\n\
             - Use `find /tmp/<subdir> ... -delete` (allowed under temp dirs)\n\
             - For a few files: `find ... | xargs -t -p rm -i` for confirmation",
            FIND_DELETE_SUGGESTIONS
        ),
        // ----- `unlink <file>` (Critical: root/home/system target) -----
        //
        // `unlink <file>` is the raw POSIX unlink(2) primitive — semantic
        // equivalent of `rm <file>` (single file, no recursion). On a
        // sensitive target (`/etc/passwd`, `~/.ssh/id_*`, `$HOME/...`) it
        // is one-shot data destruction with no recovery and no recursion
        // budget to slow it down.
        //
        // The regex matches `unlink` at any word boundary (so it fires in
        // compound forms and after `sudo`/`env` wrappers, and on
        // path-prefixed binaries via PATH_NORMALIZER), then a sensitive
        // path token. Single argument only — multi-arg unlink isn't
        // standard.
        destructive_pattern!(
            "unlink-root-home",
            r#"\bunlink\s+['"\\]?(?:/(?:etc|usr|bin|sbin|root|boot|lib|lib64|var|home|sys|proc|dev|opt)(?:/|(?=\s|$|['"]))|/(?=\s|$|['"])|~(?=\s|$|/)|\$\{?HOME\b)"#,
            "unlink on a sensitive system or home path is one-shot data destruction with no recovery. EXTREMELY DANGEROUS.",
            Critical,
            "`unlink <file>` is the raw POSIX unlink(2) primitive: it removes a single \
             directory entry without prompting, without trash, without backup. On a \
             sensitive system file (`/etc/passwd`, `/etc/shadow`, `/etc/sudoers`) or \
             a home-directory key (`~/.ssh/id_ed25519`, `$HOME/.gnupg/...`) the result \
             is irrecoverable.\n\n\
             There is NO recovery without backups.\n\n\
             Safer alternatives:\n\
             - `mv <file> <file>.deleted-YYYYMMDD` then verify nothing breaks, then\n\
               `unlink <file>.deleted-...` after a few days.\n\
             - `cp <file> <file>.bak && unlink <file>` to keep an explicit backup.\n\
             - `unlink /tmp/<subdir>/scratch` is allowed (temp dirs).",
            UNLINK_SUGGESTIONS
        ),
        // ----- `unlink <file>` (High: any other target) -----
        //
        // The general rule fires after the `unlink-tmp` safe whitelist.
        // Any unlink not under a temp dir requires human approval.
        destructive_pattern!(
            "unlink-general",
            r"\bunlink\s+\S",
            "unlink is destructive (POSIX equivalent of rm on a single file) and requires human approval.",
            High,
            "`unlink <file>` removes a single directory entry without confirmation, \
             without trash, without backup. While not as broad as `rm -rf`, a typo in \
             the target path destroys an unintended file.\n\n\
             Safer alternatives:\n\
             - Verify the path with `ls -la <file>` first.\n\
             - Make a backup: `cp <file> <file>.bak`.\n\
             - For temp scratch: `unlink /tmp/<subdir>/scratch` is allowed.\n\
             - Use `mv <file> /tmp/quarantine-<file>` if you want a delayed delete.",
            UNLINK_SUGGESTIONS
        ),
        // ----- `truncate -s 0|--size=0|-s -N` (Critical: root/home/system) -----
        //
        // `truncate -s 0 <file>` zeros the file in place — equivalent to
        // deleting all content. With a sensitive target (`/etc/passwd`,
        // `/etc/shadow`, `/etc/sudoers`, `~/.ssh/...`, `$HOME/.aws/...`)
        // this is irrecoverable data destruction.
        //
        // Variants caught by the regex (size operand may have leading `=`):
        //   -s 0
        //   -s -<N>      (shrink by N bytes — destructive)
        //   --size=0
        //   --size=-<N>
        //
        // Variants NOT caught (intentionally — non-destructive):
        //   -s +<N>      (grow — pure append of zeros, no data loss)
        //   -s <N>       (absolute size; could shrink, but the safe path
        //                  is to whitelist via temp dir or restructure)
        //
        // The destructive size operand is `0`, `-<digits>...` (with unit
        // suffix), or `--size=0`/`--size=-...`.
        destructive_pattern!(
            "truncate-zero-root-home",
            r#"\btruncate\b[^|;&]*?(?:\s-s\s+(?:0\b|-\d+)|\s--size=(?:0\b|-\d+))[^|;&]*?\s+['"\\]?(?:/(?:etc|usr|bin|sbin|root|boot|lib|lib64|var|home|sys|proc|dev|opt)(?:/|(?=\s|$|['"]))|/(?=\s|$|['"])|~(?=\s|$|/)|\$\{?HOME\b)"#,
            "truncate -s 0|-N on a sensitive system or home path destroys data. EXTREMELY DANGEROUS.",
            Critical,
            "`truncate -s 0 <file>` zeros a file in place. `truncate -s -<N> <file>` \
             shrinks a file by N bytes (destroying the trailing data). On a sensitive \
             system file (`/etc/passwd`, `/etc/shadow`, `/etc/sudoers`) or a home-\
             directory key/credential the result is irrecoverable.\n\n\
             There is NO recovery without backups.\n\n\
             Safer alternatives:\n\
             - Make a backup first: `cp <file> <file>.bak && truncate -s 0 <file>`.\n\
             - For growth (NOT shrink): `truncate -s +<N>` is allowed (no data loss).\n\
             - For temp scratch: `truncate -s 0 /tmp/<subdir>/scratch` is allowed.",
            TRUNCATE_SUGGESTIONS
        ),
        // ----- `truncate -s 0|--size=0|-s -N` (High: any other target) -----
        destructive_pattern!(
            "truncate-zero-general",
            r"\btruncate\b[^|;&]*?(?:\s-s\s+(?:0\b|-\d+)|\s--size=(?:0\b|-\d+))",
            "truncate -s 0|-N is destructive (zeroes or shrinks file content) and requires human approval.",
            High,
            "`truncate -s 0 <file>` zeros a file in place; `truncate -s -<N> <file>` \
             shrinks it by N bytes. Both destroy data without confirmation, without \
             trash, without backup. While not as broad as `rm`, a typo in the target \
             path destroys an unintended file.\n\n\
             Safer alternatives:\n\
             - Verify the size first: `wc -c <file>`.\n\
             - Make a backup: `cp <file> <file>.bak && truncate -s 0 <file>`.\n\
             - For growth: `truncate -s +<N>` (allowed; non-destructive).\n\
             - For temp scratch: `truncate -s 0 /tmp/<subdir>/scratch` is allowed.",
            TRUNCATE_SUGGESTIONS
        ),
        // ----- `shred ...` (Critical: root/home/system) -----
        //
        // `shred` overwrites file content; `shred -u`/`--remove`/`-fzu`
        // additionally unlinks the file. On a sensitive target this is
        // beyond-recovery destruction (the very design intent of shred).
        //
        // Whether or not `-u` is present, a sensitive-path shred is
        // Critical: the file content is destroyed even if the inode
        // remains. The general (High-tier) rule below handles non-
        // sensitive paths.
        destructive_pattern!(
            "shred-root-home",
            r#"\bshred\b[^|;&]*?\s+['"\\]?(?:/(?:etc|usr|bin|sbin|root|boot|lib|lib64|var|home|sys|proc|dev|opt)(?:/|(?=\s|$|['"]))|/(?=\s|$|['"])|~(?=\s|$|/)|\$\{?HOME\b)"#,
            "shred on a sensitive system or home path destroys data beyond forensic recovery. EXTREMELY DANGEROUS.",
            Critical,
            "`shred` overwrites file content with random data (DoD-style multi-pass by \
             default). With `-u`/`--remove`/`-fzu` the file is also unlinked. On a \
             sensitive system file (`/etc/passwd`, `/etc/shadow`, `/etc/sudoers`) or a \
             home-directory key/credential the result is unrecoverable even with \
             specialised forensics — that is shred's entire design intent.\n\n\
             There is NO recovery without backups.\n\n\
             Safer alternatives:\n\
             - Verify the path with `ls -la <file>` first.\n\
             - Make a backup: `cp <file> <file>.bak && shred -u <file>`.\n\
             - For temp scratch: `shred -u /tmp/<subdir>/scratch` is allowed.\n\
             - For modern SSDs, single-pass is sufficient: `shred -n 1 -u <file>`.",
            SHRED_SUGGESTIONS
        ),
        // ----- `shred ...` (High: any other target) -----
        destructive_pattern!(
            "shred-general",
            r"\bshred\s+(?:-[a-zA-Z]+\s+|--[a-z\-]+\s+|--[a-z\-]+=\S+\s+)*\S",
            "shred destroys file content beyond recovery and requires human approval.",
            High,
            "`shred` overwrites file content with random data; `-u`/`--remove` adds an \
             unlink step. The whole point is that the data cannot be recovered. While \
             not as broad as `rm -rf`, a typo in the target path destroys an unintended \
             file with no possibility of undo.\n\n\
             Safer alternatives:\n\
             - Verify the path with `ls -la <file>` first.\n\
             - Make a backup: `cp <file> <file>.bak`.\n\
             - For temp scratch: `shred -u /tmp/<subdir>/scratch` is allowed.\n\
             - On modern SSDs `shred` may not actually overwrite the underlying flash \
               cells; use `cryptsetup erase` or vendor secure-erase utilities instead.",
            SHRED_SUGGESTIONS
        ),
        // ----- `tar --remove-files <sensitive>` (Critical: root/home) -----
        //
        // `tar --remove-files -cf <archive> <source>` archives the source
        // tree into <archive>, then deletes the originals — bytewise-
        // equivalent to `rm -rf <source>` once the archive is written.
        // With `-cf /dev/null` the archive is discarded entirely, making
        // it a pure delete. This is the sibling-bypass of the rm-rf-root-
        // home and find-delete-root-home rules: agents that learn `rm -rf`
        // and `find -delete` are blocked simply switch to
        // `tar --remove-files`.
        //
        // Order-agnostic match: `--remove-files` and the sensitive source
        // path can appear in either order (alternation arms below). Both
        // tokens must live inside the SAME shell command segment
        // (`[^|;&]*?`) so a benign tar elsewhere in a compound chain
        // does not taint a separate sensitive-path mention later.
        //
        // Known limitation: `tar --remove-files -cf /etc/foo.tar /tmp/x`
        // (writing the ARCHIVE into /etc, not deleting from it) trips
        // this rule because the regex doesn't position-parse `-cf`'s
        // argument. Accepted: writing tar archives to /etc is itself
        // suspicious and `dcg allow-once` covers the rare legitimate case.
        // Path-tail terminator set includes `)` (in addition to the
        // standard `\s|$|['"]`) so a subshell form like
        // `(tar --remove-files -cf out.tar /etc)` — where /etc is the
        // last token before the closing paren — still classifies as
        // Critical (root-home) rather than falling through to the
        // High-tier general rule. The other sibling rules (rm-rf,
        // find-delete, unlink, truncate-zero, shred) have the same
        // latent gap; closing it pack-wide is tracked separately.
        destructive_pattern!(
            "tar-remove-files-root-home",
            r#"\btar\b[^|;&]*?\s--remove-files\b[^|;&]*?(?:\s|=)['"\\]?(?:/(?:etc|usr|bin|sbin|root|boot|lib|lib64|var|home|sys|proc|dev|opt)(?:/|(?=[\s\)'"]|$))|/(?=[\s\)'"]|$)|~(?=\s|$|/|\))|\$\{?HOME\b)|\btar\b[^|;&]*?(?:\s|=)['"\\]?(?:/(?:etc|usr|bin|sbin|root|boot|lib|lib64|var|home|sys|proc|dev|opt)(?:/|(?=[\s\)'"]|$))|/(?=[\s\)'"]|$)|~(?=\s|$|/|\))|\$\{?HOME\b)[^|;&]*?\s--remove-files\b"#,
            "tar --remove-files on a sensitive system or home path is recursive deletion masquerading as an archive operation. EXTREMELY DANGEROUS.",
            Critical,
            "`tar --remove-files -cf <archive> <source>` first archives the source paths \
             into <archive>, then deletes the originals. With a sensitive source \
             (`/etc`, `/usr`, `/var`, `/home/<user>`, `~`, `$HOME`, ...) the result is \
             bytewise-equivalent to `rm -rf <source>`. With `-cf /dev/null` the archive \
             is discarded entirely, making this a pure recursive delete with no audit \
             trail.\n\n\
             There is NO recovery without backups.\n\n\
             Safer alternatives:\n\
             - Drop `--remove-files`: `tar -cf out.tar <source>` (sources preserved).\n\
             - Two-step with confirmation: `tar -cf out.tar <source> && rm -ri <source>`.\n\
             - Verify the source first: `ls -la <source>`.\n\
             - Allowed for temp dirs: `tar --remove-files -cf out.tar /tmp/<subdir>`.",
            TAR_REMOVE_FILES_SUGGESTIONS
        ),
        // ----- `tar --remove-files ...` (High: any other target) -----
        //
        // Fires after the safe-pattern whitelist (which allows the temp-
        // directory variants). Any other tar-with-remove-files invocation
        // is unscoped destruction that should require human approval, by
        // exact analogy with the parallel `rm-rf-general` /
        // `find-delete-general` rules.
        destructive_pattern!(
            "tar-remove-files-general",
            r"\btar\b[^|;&]*?\s--remove-files\b",
            "tar --remove-files deletes source paths after archiving and requires human approval.",
            High,
            "`tar --remove-files <source>` deletes the source paths once they have been \
             archived. While not as broad as `rm -rf`, a typo or wide glob in the source \
             list destroys files the agent did not intend to remove. With `-cf /dev/null` \
             the archive itself is discarded — the operation becomes a pure delete.\n\n\
             Safer alternatives:\n\
             - Drop `--remove-files` to preserve sources after archiving.\n\
             - Verify the source list with `ls -la` before running.\n\
             - For temp scratch: `tar --remove-files -cf out.tar /tmp/<subdir>` is allowed.",
            TAR_REMOVE_FILES_SUGGESTIONS
        ),
        // ----- `dd of=<sensitive>` (Critical: root/home/system) -----
        //
        // `dd if=/dev/zero of=<file>` (or `if=/dev/urandom of=<file>`)
        // overwrites the file's contents in place — the truncate-equivalent
        // for files. The destruction trigger is the `of=` operand pointing
        // at a sensitive non-/dev path. The `if=` operand is the SOURCE
        // (read-only); only `of=` matters for destruction.
        //
        // Scope: FILES only. Device-level dd (`of=/dev/sda`) is
        // system.disk's territory — `(?!/dev/)` excludes the entire
        // /dev path family from this rule, including /dev/null (which
        // is correctly read-as-discard, never destruction). When
        // system.disk is enabled, it owns device writes; nqhi.8 will
        // promote it to default-enabled.
        //
        // Path-tail terminator set includes `)` so subshell forms like
        // `(dd if=/dev/zero of=/etc/passwd)` still classify as Critical.
        destructive_pattern!(
            "dd-overwrite-root-home",
            r#"\bdd\b[^|;&]*?\bof=['"\\]?(?!/dev/)(?:/(?:etc|usr|bin|sbin|root|boot|lib|lib64|var|home|sys|proc|opt)(?:/|(?=[\s\)'"]|$))|/(?=[\s\)'"]|$)|~(?=\s|$|/|\))|\$\{?HOME\b)"#,
            "dd of=<sensitive-path> overwrites file contents in place. EXTREMELY DANGEROUS on a system or home file.",
            Critical,
            "`dd if=/dev/zero of=<file>` and `dd if=/dev/urandom of=<file>` overwrite the \
             file's contents in place — the `truncate -s 0` equivalent at the dd layer. \
             On a sensitive system file (`/etc/passwd`, `/etc/shadow`, `/etc/sudoers`) or \
             a home-directory key/credential the result is irrecoverable. Even without an \
             explicit input source (`dd of=<file>` reads from stdin), the file's content \
             is destroyed.\n\n\
             There is NO recovery without backups.\n\n\
             Safer alternatives:\n\
             - Make a backup first: `cp <file> <file>.bak && dd if=/dev/zero of=<file>`.\n\
             - For read-only verification: `dd if=<file> of=/dev/null` (output discarded).\n\
             - For temp scratch: `dd if=/dev/zero of=/tmp/<subdir>/scratch` is allowed.\n\n\
             Device-level dd (`dd of=/dev/sda`) is governed by the `system.disk` pack \
             — enable it for partition-table protection.",
            DD_OVERWRITE_SUGGESTIONS
        ),
        // ----- `dd of=<any-non-tmp>` (High: any other target) -----
        //
        // Fires after the safe-pattern whitelist (which allows the temp-
        // directory variants). `(?!/dev/)` excludes the entire /dev path
        // family (system.disk's scope). Any other dd-with-of= invocation
        // is unscoped destruction that should require human approval, by
        // analogy with `truncate-zero-general` and `shred-general`.
        destructive_pattern!(
            "dd-overwrite-general",
            r#"\bdd\b[^|;&]*?\bof=['"\\]?(?!/dev/)\S"#,
            "dd with of=<file> overwrites file contents and requires human approval.",
            High,
            "`dd of=<file>` overwrites the file's contents (with the input from `if=` \
             or stdin if no input source is given). While not as broad as `rm -rf`, a \
             typo in the target path destroys an unintended file with no possibility of \
             undo.\n\n\
             Safer alternatives:\n\
             - Verify the path first: `ls -la <file>`.\n\
             - Make a backup: `cp <file> <file>.bak && dd if=/dev/zero of=<file>`.\n\
             - Read-only verification: `dd if=<file> of=/dev/null`.\n\
             - For temp scratch: `dd if=/dev/zero of=/tmp/<subdir>/scratch` is allowed.\n\
             - For device writes: enable the `system.disk` pack.",
            DD_OVERWRITE_SUGGESTIONS
        ),
        // ----- `mv <sensitive>` (Critical: cross-segment bypass) -----
        //
        // Closes the canonical cross-segment recursive-force-delete
        // bypass: `mv /etc /tmp/x && rm -rf /tmp/x`. Each segment is
        // individually allowed (mv-to-tmp is benign on its own; rm-rf-
        // in-tmp is safe-pattern-rescued) but the pair destroys /etc.
        // The same shape applies to `mv /etc /dev/null`,
        // `mv /home/user /tmp/$$ && find /tmp/$$ -delete`, and any
        // future "move sensitive away from its semantic location, then
        // delete elsewhere" chain.
        //
        // Approach A from the bead's design: block ANY mv that mentions
        // a sensitive path (source OR destination). Position-parsing
        // mv's args is brittle (`-t target sources...`, multi-source,
        // mixed flags) so we taint the whole command on any sensitive
        // mention. Two consequences worth noting:
        //
        //   1. `mv /etc/hosts /etc/hosts.bak` (in-place rename inside
        //      /etc) blocks. Per the bead's v1 decision: rename within
        //      /etc is rare; allow-once covers legitimate cases.
        //   2. `mv ./build/foo /etc/local-config.bak` (write INTO /etc)
        //      blocks. Modifying /etc from a non-system source is
        //      itself a system change; conservative-block is correct.
        //
        // Out of scope (filed separately as Approach B): the more
        // general data-flow / taint-propagation analyzer that would
        // also catch `cp -al /etc /tmp/x && rm -rf /tmp/x`,
        // `ln -s /etc /tmp/x && rm -rf /tmp/x/.`, etc.
        //
        // /var/tmp false-positive trap: `/var` is in the sensitive set
        // so `mv /var/tmp/foo /var/tmp/bar` matches the destructive
        // regex. The `mv-var-tmp` safe pattern rescues. Same defense
        // applies to /tmp / $TMPDIR moves (those don't even trip the
        // destructive regex but are whitelisted for symmetry).
        // The optional-quote group `(?:['"\\]|\$['"])?` extends the
        // historical single-char quote prefix to accept Bash's
        // ANSI-C-quoted (`$'...'`) and locale-translated (`$"..."`)
        // path forms. Without these, `mv $'/etc' /tmp/x` slipped
        // through as a HIGH-impact bypass since mv has no general
        // tier to fall back on.
        destructive_pattern!(
            "mv-sensitive-source-root-home",
            r#"\bmv\b[^|;&]*?(?:\s|=)(?:['"\\]|\$['"])?(?:/(?:etc|usr|bin|sbin|root|boot|lib|lib64|var|home|sys|proc|dev|opt)(?:/|(?=[\s\)'"]|$))|/(?=[\s\)'"]|$)|~(?=\s|$|/|\))|\$\{?HOME\b)"#,
            "mv touching a sensitive system or home path is the cross-segment recursive-force-delete bypass. EXTREMELY DANGEROUS.",
            Critical,
            "`mv /etc /tmp/x && rm -rf /tmp/x` is the canonical cross-segment bypass: \
             each segment is individually allowed (mv-to-tmp is benign; rm-rf-in-tmp \
             is safe) but the pair destroys `/etc`. The same shape closes via \
             `mv /etc /dev/null`, `mv $HOME /tmp/x`, or any \"relocate then delete\" chain.\n\n\
             Any mv that mentions a sensitive path (source OR destination — `/etc`, \
             `/usr`, `/var`, `/home`, `~`, `$HOME`, ...) blocks here, including \
             in-place renames within /etc.\n\n\
             Safer alternatives:\n\
             - Backup with copy + verify + delete:\n  \
               `cp -a <source> <source>.bak && diff -r <source> <source>.bak && rm -rf <source>`\n\
             - Soft-delete via in-place rename: `mv <file> <file>.deleted-YYYYMMDD` \
               (use `dcg allow-once` for the rename, then a follow-up `rm` after a soak period).\n\
             - Pure tmp-to-tmp moves: `mv /tmp/<a> /tmp/<b>` is allowed.",
            MV_SENSITIVE_SUGGESTIONS
        ),
        // ----- `> <sensitive>` (Critical: shell redirect truncate) -----
        //
        // Bash output redirection truncates the target file to zero
        // bytes before writing. `> /etc/passwd` (with no command) opens
        // /etc/passwd for write, immediately closes — net effect: file
        // contents destroyed. Same shape:
        //
        //   `> /etc/passwd`                — bare redirect
        //   `: > /etc/passwd`              — null builtin + redirect
        //   `echo > /etc/passwd`           — any command's stdout > path
        //   `cat /dev/null > /etc/passwd`  — pipe /dev/null
        //   `>| /etc/passwd`               — force-overwrite (ignores noclobber)
        //   `&> /etc/passwd`               — stdout+stderr to file
        //   `1>| /etc/passwd`              — fd1 force-overwrite
        //   `2> /etc/passwd`               — fd2 to file
        //
        // None of these touch any binary keyword the rest of dcg
        // recognises, so they bypass dcg entirely without this rule.
        // The negative lookbehind `(?<![<>])` excludes append-mode
        // (`>>`) which is non-destructive (only adds content) — the
        // bead's explicit allow-list. The lookbehind is fixed-width 1,
        // safe under fancy-regex.
        //
        // Per the bead's design recommendation (option a): only ship
        // the Critical root-home tier. A `-general` rule would block
        // legitimate workflows like `make > build.log` and `cargo test
        // > test.log`; that tension is not worth the false-positive
        // pain. File-level redirects to non-sensitive paths fall
        // through to default-allow.
        //
        // /tmp / /var/tmp / $TMPDIR redirects: /tmp isn't in the
        // sensitive set so they don't fire the regex at all; /var/tmp
        // would match /var but we don't bother with a safe rescue
        // because the bead's allow-list is explicit (`> /tmp/scratch`,
        // `: > /tmp/cache`) — those naturally fall through. /var/tmp
        // redirects ARE caught by the regex; if that becomes a real
        // pain we can add a safe pattern later.
        // Two carve-outs in the regex below worth understanding:
        //
        //   1. `(?!/dev/(?:null|zero|full)\b)` — never fire on the
        //      universal "discard output" sinks. `cmd > /dev/null` and
        //      `cmd 2>&1 > /dev/null` are the most common shell idioms
        //      in existence; without this carve-out the `dev` element
        //      of the sensitive set would block essentially every
        //      script that suppresses output.
        //
        //   2. `(?:['"\\]|\$['"])?` — extends the historical optional
        //      single-char quote prefix to also accept the two-byte
        //      Bash quoting introducers `$'` (ANSI-C) and `$"`
        //      (locale-translated). Without this, an attacker could
        //      bypass with `> $'/etc/passwd'` or `> $"/etc/passwd"`.
        //
        // Scan view (WI-3135): the regex runs on
        // `redirect_unquoted_scan_view`, which blanks `>` bytes that sit
        // inside quoted, non-executing text. A redirect is only a redirect
        // when the OPERATOR is unquoted on the local command line;
        // `ssh host 'date > ~/stamp'` and
        // `send --body "wrote date > ~/stamp"` are content, not a local
        // truncate. Local executors (`bash -c`, `eval`, `xargs`, `script -c`,
        // `su -c`, `sudo -s`, `(sh -c ...)`, `... | sh`) and ssh/scp/sftp
        // pointed at THIS host (loopback, own hostname, substituted host)
        // keep the full text visible (fold r2, strict r1 Majors 1-3).
        DestructivePattern {
            scan_view: Some(redirect_unquoted_scan_view),
            ..destructive_pattern!(
                "redirect-truncate-root-home",
                r#"(?<![<>])(?:[12]?>\|?|&>)\s*(?:['"\\]|\$['"])?(?!/dev/(?:null|zero|full)\b)(?:/(?:etc|usr|bin|sbin|root|boot|lib|lib64|var|home|sys|proc|dev|opt)(?:/|(?=[\s\)'"]|$))|/(?=[\s\)'"]|$)|~(?=\s|$|/|\))|\$\{?HOME\b)"#,
                "shell redirect (>, >|, &>, 1>, 2>) to a sensitive system or home path truncates the file to zero bytes. EXTREMELY DANGEROUS.",
                Critical,
                "`> /etc/passwd` (or `: > /etc/passwd`, `echo > /etc/passwd`, etc.) opens \
             the target file with O_WRONLY|O_CREAT|O_TRUNC — the contents are destroyed \
             before any write happens. This applies equally to `>|` (force-overwrite), \
             `&>` (stdout+stderr to file), and numbered FD forms (`1>`, `2>`, `1>|`, \
             `2>|`). All of these are silent, immediate, irrecoverable.\n\n\
             There is NO recovery without backups.\n\n\
             Safer alternatives:\n\
             - Use append (`>>`) to preserve existing content: `echo line >> <file>`.\n\
             - Make a backup: `cp <file> <file>.bak && echo data > <file>`.\n\
             - For temp scratch: `> /tmp/<subdir>/scratch` is allowed.\n\
             - Read redirects (`< <file>`) are not affected — they don't truncate.",
                REDIRECT_TRUNCATE_SUGGESTIONS
            )
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packs::Severity;
    use crate::packs::test_helpers::*;

    #[test]
    fn test_pack_creation() {
        let pack = create_pack();
        assert_eq!(pack.id, "core.filesystem");
        assert_eq!(pack.name, "Core Filesystem");
        assert!(pack.keywords.contains(&"rm"));
        // Required for the find -delete bypass family — see
        // `find-delete-root-home` / `find-delete-general` patterns.
        assert!(pack.keywords.contains(&"find"));
    }

    // ---------- find -delete: closes the rm -rf bypass ----------

    #[test]
    fn find_delete_blocks_root_critical() {
        let pack = create_pack();
        // The historical bypass: agent learns rm -rf is blocked, swaps
        // for the bytewise-equivalent `find -delete`.
        for cmd in [
            "find / -delete",
            "find /etc -delete",
            "find /usr -delete",
            "find /home -delete",
            "find /var -delete",
            "find /boot -delete",
            "find /lib -delete",
            "find /lib64 -delete",
            "find /root -delete",
            "find /sys -delete",
            "find /proc -delete",
            "find /dev -delete",
            "find /opt -delete",
            "find ~ -delete",
            "find $HOME -delete",
            "find ${HOME} -delete",
            // With predicates / extra flags before -delete:
            "find / -depth -delete",
            "find / -type f -delete",
            "find /etc -name '*.conf' -delete",
            "find /home -mindepth 1 -delete",
            // Quoted paths
            "find \"/\" -delete",
            "find '/etc' -delete",
        ] {
            assert_blocks_with_severity(&pack, cmd, Severity::Critical);
        }
    }

    #[test]
    fn find_delete_blocks_general_high() {
        let pack = create_pack();
        // Anything that's not under a temp dir and not root/home should
        // still be blocked (High severity, mirrors rm-rf-general).
        for cmd in [
            "find . -delete",
            "find ./node_modules -delete",
            "find . -name '*.pyc' -delete",
            "find /data -delete",
            "find /workspace/build -delete",
            "find ./target -type f -delete",
        ] {
            assert_blocks_with_severity(&pack, cmd, Severity::High);
        }
    }

    #[test]
    fn find_delete_under_tmp_is_allowed() {
        let pack = create_pack();
        // Mirrors the rm -rf temp whitelist. Critical: only the FIRST
        // path argument matters; safe pattern must NOT short-circuit if
        // a second argument is sensitive (test below).
        for cmd in [
            "find /tmp -delete",
            "find /tmp/foo -delete",
            "find /tmp/foo -name '*.log' -delete",
            "find /var/tmp -delete",
            "find /var/tmp/dir -type f -delete",
            "find $TMPDIR -delete",
            "find $TMPDIR/work -name '*.tmp' -delete",
            "find ${TMPDIR} -delete",
            "find ${TMPDIR}/work -delete",
        ] {
            assert_safe_pattern_matches(&pack, cmd);
        }
    }

    #[test]
    fn find_delete_with_secondary_sensitive_path_still_blocks() {
        let pack = create_pack();
        // Important: the safe-temp pattern must require EVERY path to be
        // temp-rooted. Without that, an attacker could write
        //   find /tmp/foo /etc -delete
        // and short-circuit through the safe pattern even though /etc
        // would also be deleted. The current safe regex tightly restricts
        // post-find tokens to more temp paths or `-flag [non-path-value]`
        // pairs, so the secondary `/etc` argument fails the safe match
        // and the destructive root-home rule fires. We assert Critical
        // because /etc is in the sensitive-path list.
        let cases = [
            "find /tmp/foo /etc -delete",
            "find /tmp /usr -delete",
            "find /var/tmp/foo /home/user -delete",
            "find $TMPDIR / -delete",
        ];
        for cmd in cases {
            assert_blocks_with_severity(&pack, cmd, Severity::Critical);
        }
    }

    #[test]
    fn find_without_delete_is_not_blocked() {
        let pack = create_pack();
        // Plain find without the -delete action is read-only.
        for cmd in [
            "find . -name '*.rs'",
            "find / -type f -name passwd",
            "find /etc -ls",
            "find . -print",
            // -exec without rm is not destructive
            "find . -exec cat {} +",
            // -delete is a SUBSTRING of -delete-this-arg; the explicit
            // `(?:\s|$|[;&|])` terminator (instead of `\b`) prevents a
            // false positive here.
            "find . -name -delete-this-not-a-flag",
        ] {
            assert_no_match(&pack, cmd);
        }
    }

    #[test]
    fn find_delete_blocks_in_compound_commands() {
        let pack = create_pack();
        // Regression: the original `^\s*find\b` anchor only matched at the
        // start of the whole sanitized command. Compound forms like
        //   echo foo; find /etc -delete
        //   true && find / -delete
        //   ; find /etc -delete
        // dropped through entirely. Fixed by switching to `\bfind\b` so
        // the destructive rule fires on the embedded `find` invocation.
        for cmd in [
            "true; find / -delete",
            "echo done; find /etc -delete",
            "true && find /etc -delete",
            "false || find /etc -delete",
            "(find /etc -delete)",
            "find /tmp -delete; find /etc -delete", // 2nd segment dangerous
        ] {
            assert_blocks(&pack, cmd, "find");
        }
    }

    #[test]
    fn find_delete_blocks_with_terminating_separator() {
        let pack = create_pack();
        // `-delete;` and `-delete &&` and `-delete |` must terminate the
        // -delete flag. The `(?:\s|$|[;&|])` end set allows shell
        // separators, not just whitespace and end-of-string.
        for cmd in [
            "find /etc -delete; echo done",
            "find /etc -delete && echo done",
            "find /etc -delete | tee log",
            "find /etc -delete&& echo done", // no space before &&
        ] {
            assert_blocks(&pack, cmd, "find");
        }
    }

    #[test]
    fn find_delete_path_prefixed_normalizes_to_bare_find() {
        // PATH_NORMALIZER's capture group includes `find` so
        // `/usr/bin/find / -delete` is normalized to `find / -delete`
        // before the destructive regex runs. This test pins the
        // normalizer contract — if `find` is dropped from the
        // capture, this will fail and downstream pack matching will
        // miss path-prefixed bypasses.
        use crate::normalize::normalize_command;
        for (input, expected_substring) in [
            ("/usr/bin/find / -delete", "find / -delete"),
            ("/usr/local/bin/find /etc -delete", "find /etc -delete"),
            ("/bin/find /home -delete", "find /home -delete"),
            ("/sbin/find /etc -delete", "find /etc -delete"),
        ] {
            let normalized = normalize_command(input);
            assert!(
                normalized.contains(expected_substring),
                "PATH_NORMALIZER did not strip `{input}` to expected form `{expected_substring}` (got `{normalized}`)"
            );
        }
    }

    #[test]
    fn find_temp_compound_blocks_conservatively() {
        let pack = create_pack();
        // The safe pattern is whole-command anchored (`^...$`), NOT
        // segment-aware. Compound forms with a temp `find -delete` are
        // BLOCKED rather than allowed — this is a deliberate
        // false-positive trade-off to prevent the bypass:
        //   find /tmp -delete; find /etc -delete
        // (a segment-aware safe would shadow the whole pack's destructive
        // rules for the second segment, allowing /etc deletion).
        //
        // Users hitting this can `dcg allow-once <code>` for one-offs
        // or add a temporary allowlist entry for recurring scripts.
        for cmd in [
            "echo done; find /tmp -delete",
            "true && find /tmp -delete",
            "echo done; find /tmp/foo -delete",
            "echo done; find $TMPDIR -delete",
        ] {
            assert_blocks(&pack, cmd, "find");
        }
    }

    #[test]
    fn find_temp_safe_only_when_whole_command() {
        let pack = create_pack();
        // The safe pattern fires only on a clean, single-command
        // invocation. This is the intended trade-off (see
        // find_temp_compound_blocks_conservatively for rationale).
        for cmd in [
            "find /tmp -delete",
            "find /tmp/foo -delete",
            "find /tmp -name '*.log' -delete",
            "find /tmp/foo -name '*.tmp' -delete",
            "find /var/tmp -delete",
            "find $TMPDIR -delete",
            "find ${TMPDIR} -delete",
        ] {
            assert_safe_pattern_matches(&pack, cmd);
        }
    }

    // ---------- unlink (nqhi.3) ----------

    #[test]
    fn unlink_blocks_root_critical() {
        let pack = create_pack();
        for cmd in [
            "unlink /etc/passwd",
            "unlink /etc/shadow",
            "unlink /etc/sudoers",
            "unlink /usr/bin/sudo",
            "unlink /boot/vmlinuz",
            "unlink ~/.bashrc",
            "unlink ~/.ssh/id_ed25519",
            "unlink $HOME/.gnupg/secring.gpg",
            "unlink ${HOME}/.aws/credentials",
            "unlink \"/etc/passwd\"",
            "unlink '/etc/shadow'",
            // Compound forms.
            "echo done; unlink /etc/passwd",
            "true && unlink /etc/passwd",
            "(unlink /etc/passwd)",
            // Wrappers.
            "sudo unlink /etc/passwd",
            "env FOO=bar unlink /etc/passwd",
            // Path-prefixed (PATH_NORMALIZER strips it).
            "/usr/bin/unlink /etc/passwd",
            "/bin/unlink /etc/shadow",
        ] {
            assert_blocks_with_severity(&pack, cmd, Severity::Critical);
        }
    }

    #[test]
    fn unlink_blocks_general_high() {
        let pack = create_pack();
        // Anything outside temp dirs — High severity, mirrors rm-rf-general.
        for cmd in [
            "unlink ./important.db",
            "unlink ./build/output.bin",
            "unlink secrets.txt",
            "unlink /data/important",
            "unlink /workspace/build/critical.bin",
        ] {
            assert_blocks_with_severity(&pack, cmd, Severity::High);
        }
    }

    #[test]
    fn unlink_under_tmp_is_allowed() {
        let pack = create_pack();
        // Whole-command anchor — single invocation only.
        for cmd in [
            "unlink /tmp/scratch",
            "unlink /tmp/foo/bar",
            "unlink /var/tmp/cache",
            "unlink $TMPDIR/file",
            "unlink ${TMPDIR}/file",
        ] {
            assert_safe_pattern_matches(&pack, cmd);
        }
    }

    #[test]
    fn unlink_help_is_allowed() {
        let pack = create_pack();
        // unlink --help / --version are read-only.
        for cmd in ["unlink --help", "unlink --version"] {
            assert_safe_pattern_matches(&pack, cmd);
        }
    }

    #[test]
    fn unlink_path_traversal_in_tmp_is_blocked() {
        let pack = create_pack();
        // The safe regex's negative lookahead rejects `..` traversal.
        for cmd in [
            "unlink /tmp/../etc/passwd",
            "unlink /tmp/foo/../../etc/shadow",
            "unlink $TMPDIR/../etc/passwd",
        ] {
            // Path-traversal should NOT match the safe pattern. The
            // command falls through to destructive evaluation. Whether
            // it lands on root-home or general depends on the literal
            // sensitive substring; we only assert it blocks SOMEHOW.
            assert_blocks(&pack, cmd, "unlink");
        }
    }

    #[test]
    fn unlink_compound_with_temp_blocks_conservatively() {
        let pack = create_pack();
        // Same trade-off as find-delete: compound forms block even when
        // the unlink target is /tmp. Users `dcg allow-once` for the
        // legitimate cases.
        for cmd in [
            "echo done; unlink /tmp/scratch",
            "true && unlink /tmp/scratch",
        ] {
            assert_blocks(&pack, cmd, "unlink");
        }
    }

    #[test]
    fn unlink_no_false_positive_substring_traps() {
        let pack = create_pack();
        // `unlink` substring inside other paths/commands must NOT trip.
        for cmd in [
            "cat /etc/unlink-script.sh",
            "ls unlink-foo.txt",
            "echo unlink",
            // unlink without an argument doesn't match (regex requires \S).
            "unlink",
            "unlink ",
        ] {
            assert_no_match(&pack, cmd);
        }
    }

    #[test]
    fn unlink_path_prefixed_normalizes_to_bare() {
        // PATH_NORMALIZER strips `/usr/bin/unlink` to bare `unlink`.
        // Pin the contract — if `unlink` is dropped from the capture,
        // path-prefixed bypasses re-open.
        use crate::normalize::normalize_command;
        for (input, expected) in [
            ("/usr/bin/unlink /etc/passwd", "unlink /etc/passwd"),
            ("/bin/unlink /etc/shadow", "unlink /etc/shadow"),
            ("/usr/local/bin/unlink /etc/sudoers", "unlink /etc/sudoers"),
        ] {
            let normalized = normalize_command(input);
            assert!(
                normalized.contains(expected),
                "PATH_NORMALIZER did not strip `{input}` to `{expected}` (got `{normalized}`)"
            );
        }
    }

    // ---------- truncate (nqhi.1) ----------

    #[test]
    fn truncate_blocks_zero_root_critical() {
        let pack = create_pack();
        for cmd in [
            "truncate -s 0 /etc/passwd",
            "truncate -s 0 /etc/shadow",
            "truncate -s 0 /etc/sudoers",
            "truncate -s 0 /usr/bin/sudo",
            "truncate -s 0 /boot/vmlinuz",
            "truncate -s 0 ~/.bashrc",
            "truncate -s 0 $HOME/.aws/credentials",
            "truncate -s 0 ${HOME}/.gnupg/secring.gpg",
            "truncate --size=0 /etc/passwd",
            // shrink form
            "truncate -s -100 /etc/passwd",
            "truncate -s -1024 /etc/hosts",
            "truncate --size=-100 /etc/passwd",
            // compound forms
            "echo done; truncate -s 0 /etc/passwd",
            "true && truncate -s 0 /etc/passwd",
            "(truncate -s 0 /etc/passwd)",
            // wrappers
            "sudo truncate -s 0 /etc/passwd",
            "env FOO=bar truncate -s 0 /etc/passwd",
            // path-prefixed
            "/usr/bin/truncate -s 0 /etc/passwd",
            "/bin/truncate --size=0 /etc/shadow",
        ] {
            assert_blocks_with_severity(&pack, cmd, Severity::Critical);
        }
    }

    #[test]
    fn truncate_blocks_zero_general_high() {
        let pack = create_pack();
        for cmd in [
            "truncate -s 0 ./important.db",
            "truncate -s 0 build/output.bin",
            "truncate --size=0 secrets.txt",
            "truncate -s -100 ./large.log",
            "truncate -s 0 /data/important",
        ] {
            assert_blocks_with_severity(&pack, cmd, Severity::High);
        }
    }

    #[test]
    fn truncate_under_tmp_is_allowed() {
        let pack = create_pack();
        for cmd in [
            "truncate -s 0 /tmp/scratch.bin",
            "truncate -s 1G /tmp/sparse-file.bin",
            "truncate -s 0 /var/tmp/cache.bin",
            "truncate -s 100M /var/tmp/test.img",
            "truncate -s 0 $TMPDIR/cache.bin",
            "truncate --size=0 ${TMPDIR}/scratch",
            "truncate -s -100 /tmp/log.txt",
        ] {
            assert_safe_pattern_matches(&pack, cmd);
        }
    }

    #[test]
    fn truncate_grow_is_allowed_anywhere() {
        let pack = create_pack();
        // Pure-growth `+N` does not destroy data — allowed everywhere.
        for cmd in [
            "truncate -s +1024 ./output.bin",
            "truncate -s +1G /var/log/sparse",
            "truncate --size=+100M ./preallocated",
        ] {
            assert_safe_pattern_matches(&pack, cmd);
        }
    }

    #[test]
    fn truncate_help_is_allowed() {
        let pack = create_pack();
        for cmd in ["truncate --help", "truncate --version"] {
            assert_safe_pattern_matches(&pack, cmd);
        }
    }

    #[test]
    fn truncate_no_false_positive_substring_traps() {
        let pack = create_pack();
        for cmd in [
            "cat /etc/truncate-readme.txt",
            "ls truncate-script.sh",
            "echo truncate",
            // no -s 0 / shrink → no destructive match. truncate WITHOUT
            // a destructive size operand falls through to default-allow.
            "truncate -r ref.bin out.bin",
            "truncate --reference=ref.bin out.bin",
        ] {
            assert_no_match(&pack, cmd);
        }
    }

    #[test]
    fn truncate_path_prefixed_normalizes_to_bare() {
        use crate::normalize::normalize_command;
        for (input, expected) in [
            (
                "/usr/bin/truncate -s 0 /etc/passwd",
                "truncate -s 0 /etc/passwd",
            ),
            (
                "/bin/truncate --size=0 /etc/shadow",
                "truncate --size=0 /etc/shadow",
            ),
        ] {
            let normalized = normalize_command(input);
            assert!(
                normalized.contains(expected),
                "PATH_NORMALIZER did not strip `{input}` to `{expected}` (got `{normalized}`)"
            );
        }
    }

    // ---------- shred (nqhi.2) ----------

    #[test]
    fn shred_blocks_root_critical() {
        let pack = create_pack();
        for cmd in [
            "shred /etc/passwd",
            "shred -u /etc/passwd",
            "shred -fzu /etc/shadow",
            "shred --remove /etc/hosts",
            "shred -n 3 -u /etc/passwd",
            "shred -u ~/.ssh/id_ed25519",
            "shred -u $HOME/.aws/credentials",
            "shred -u ${HOME}/.gnupg/secring.gpg",
            "shred -fzu /usr/bin/sudo",
            "shred -u /boot/vmlinuz",
            // compound forms
            "echo done; shred -u /etc/passwd",
            "true && shred -u /etc/passwd",
            "(shred -u /etc/passwd)",
            // wrappers
            "sudo shred -u /etc/passwd",
            "env FOO=bar shred -u /etc/passwd",
            // path-prefixed
            "/usr/bin/shred -fzu /etc/passwd",
            "/bin/shred -u /etc/shadow",
        ] {
            assert_blocks_with_severity(&pack, cmd, Severity::Critical);
        }
    }

    #[test]
    fn shred_blocks_general_high() {
        let pack = create_pack();
        for cmd in [
            "shred ./important.db",
            "shred -u ./secrets.txt",
            "shred -fzu build/output.bin",
            "shred -u /data/private",
            "shred --remove /workspace/build/critical.bin",
        ] {
            assert_blocks_with_severity(&pack, cmd, Severity::High);
        }
    }

    #[test]
    fn shred_under_tmp_is_allowed() {
        let pack = create_pack();
        for cmd in [
            "shred -u /tmp/scratch.bin",
            "shred -fzu /tmp/foo/cache",
            "shred -u /var/tmp/cache.bin",
            "shred -u $TMPDIR/file",
            "shred -u ${TMPDIR}/file",
            "shred -n 1 -u /tmp/scratch",
            "shred /tmp/foo/output",
        ] {
            assert_safe_pattern_matches(&pack, cmd);
        }
    }

    #[test]
    fn shred_help_is_allowed() {
        let pack = create_pack();
        for cmd in ["shred --help", "shred --version"] {
            assert_safe_pattern_matches(&pack, cmd);
        }
    }

    #[test]
    fn shred_no_false_positive_substring_traps() {
        let pack = create_pack();
        for cmd in [
            "cat /etc/shred-readme.txt",
            "ls shred-script.sh",
            "echo shred",
        ] {
            assert_no_match(&pack, cmd);
        }
    }

    #[test]
    fn shred_path_prefixed_normalizes_to_bare() {
        use crate::normalize::normalize_command;
        for (input, expected) in [
            ("/usr/bin/shred -u /etc/passwd", "shred -u /etc/passwd"),
            ("/bin/shred -fzu /etc/shadow", "shred -fzu /etc/shadow"),
        ] {
            let normalized = normalize_command(input);
            assert!(
                normalized.contains(expected),
                "PATH_NORMALIZER did not strip `{input}` to `{expected}` (got `{normalized}`)"
            );
        }
    }

    // ---------- tar --remove-files: archive-then-delete bypass family ----------

    #[test]
    fn tar_remove_files_blocks_root_critical() {
        let pack = create_pack();
        for cmd in [
            // Flag before source.
            "tar --remove-files -cf out.tar /etc",
            "tar --remove-files -czf out.tar.gz /home/user",
            "tar --remove-files -cf out.tar /usr/local",
            // Source before flag.
            "tar -cf out.tar --remove-files /etc",
            "tar -cf out.tar /etc --remove-files",
            // Delete-only (discarded archive).
            "tar --remove-files -cf /dev/null /etc",
            // Quoted sensitive paths.
            "tar --remove-files -cf out.tar \"/etc\"",
            "tar --remove-files -cf out.tar '/etc'",
            // Home variants.
            "tar --remove-files -cf out.tar ~/.ssh",
            "tar --remove-files -cf out.tar $HOME/.aws",
            "tar --remove-files -cf out.tar ${HOME}/.gnupg",
            // Compound forms (\btar\b matches at any boundary).
            "echo done; tar --remove-files -cf out.tar /etc",
            "true && tar --remove-files -cf out.tar /etc",
            "(tar --remove-files -cf out.tar /etc)",
            // Wrappers.
            "sudo tar --remove-files -cf out.tar /etc",
            "env FOO=bar tar --remove-files -cf out.tar /etc",
            // Path-prefixed (PATH_NORMALIZER).
            "/usr/bin/tar --remove-files -cf out.tar /etc",
            "/bin/tar --remove-files -cf out.tar /etc",
        ] {
            assert_blocks_with_severity(&pack, cmd, Severity::Critical);
            assert_blocks_with_pattern(&pack, cmd, "tar-remove-files-root-home");
        }
    }

    #[test]
    fn tar_remove_files_blocks_general_high() {
        let pack = create_pack();
        for cmd in [
            "tar --remove-files -cf out.tar ./build",
            "tar --remove-files -cf out.tar important.db",
            "tar --remove-files -cf out.tar ./workspace",
            "tar -cf out.tar --remove-files data.json",
        ] {
            assert_blocks_with_severity(&pack, cmd, Severity::High);
            assert_blocks_with_pattern(&pack, cmd, "tar-remove-files-general");
        }
    }

    #[test]
    fn tar_remove_files_under_tmp_is_allowed() {
        let pack = create_pack();
        for cmd in [
            "tar --remove-files -cf out.tar /tmp/scratch",
            "tar -cf out.tar --remove-files /tmp/foo",
            "tar --remove-files -czf out.tar.gz /var/tmp/cache",
            "tar --remove-files -cf out.tar $TMPDIR/scratch",
            "tar --remove-files -cf out.tar ${TMPDIR}/scratch",
        ] {
            assert_safe_pattern_matches(&pack, cmd);
        }
    }

    #[test]
    fn tar_without_remove_files_is_allowed() {
        let pack = create_pack();
        // No --remove-files = pure archive/extract/list — destructive
        // pattern requires the flag, so these fall through to default-allow.
        for cmd in [
            "tar -cf out.tar /etc",
            "tar -czf out.tar.gz /home/user",
            "tar -xf in.tar",
            "tar -xzf in.tar.gz -C /tmp",
            "tar -tf in.tar",
            "tar --help",
            "tar --version",
        ] {
            assert_no_match(&pack, cmd);
        }
    }

    #[test]
    fn tar_no_false_positive_substring_traps() {
        let pack = create_pack();
        for cmd in [
            "cat tar-readme.md",
            "ls /etc/tar-config",
            "echo --remove-files",
            // Bare --remove-files appears (e.g. as a documented flag),
            // but no `tar` invocation: must not match.
            "grep --remove-files docs/",
        ] {
            assert_no_match(&pack, cmd);
        }
    }

    #[test]
    fn tar_remove_files_mixed_sources_blocks_via_general() {
        // `tar --remove-files -cf out.tar /tmp/foo /etc/bar` — the safe
        // /tmp/foo source does NOT rescue because /etc/bar is a sensitive
        // co-source. The root-home rule must fire.
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "tar --remove-files -cf out.tar /tmp/foo /etc/bar",
            "tar-remove-files-root-home",
        );
    }

    #[test]
    fn tar_remove_files_path_prefixed_normalizes_to_bare() {
        use crate::normalize::normalize_command;
        for (input, expected) in [
            (
                "/usr/bin/tar --remove-files -cf out.tar /etc",
                "tar --remove-files -cf out.tar /etc",
            ),
            (
                "/bin/tar --remove-files -cf out.tar /home/user",
                "tar --remove-files -cf out.tar /home/user",
            ),
        ] {
            let normalized = normalize_command(input);
            assert!(
                normalized.contains(expected),
                "PATH_NORMALIZER did not strip `{input}` to `{expected}` (got `{normalized}`)"
            );
        }
    }

    // ---------- dd of=: file-level overwrite (truncate-equivalent) ----------

    #[test]
    fn dd_overwrite_blocks_root_critical() {
        let pack = create_pack();
        for cmd in [
            // Canonical form.
            "dd if=/dev/zero of=/etc/passwd",
            "dd if=/dev/urandom of=/etc/shadow",
            "dd if=/dev/zero of=/etc/sudoers",
            // With bs/count operands.
            "dd if=/dev/zero of=/etc/passwd bs=1M count=10",
            "dd if=/dev/urandom of=/etc/shadow bs=4096 count=1",
            // Operand order swapped (of= first).
            "dd of=/etc/passwd if=/dev/zero",
            "dd of=/etc/passwd if=/dev/zero bs=1M",
            // No if= operand (reads from stdin — still destroys content).
            "dd of=/etc/passwd",
            // Quoted paths.
            "dd if=/dev/zero of=\"/etc/passwd\"",
            "dd if=/dev/zero of='/etc/shadow'",
            // Home variants.
            "dd if=/dev/zero of=~/.ssh/id_ed25519",
            "dd if=/dev/zero of=$HOME/.aws/credentials",
            "dd if=/dev/zero of=${HOME}/.gnupg/secring.gpg",
            // Other system roots.
            "dd if=/dev/zero of=/usr/bin/sudo",
            "dd if=/dev/zero of=/boot/vmlinuz",
            // Compound forms.
            "echo done; dd if=/dev/zero of=/etc/passwd",
            "true && dd if=/dev/zero of=/etc/passwd",
            "(dd if=/dev/zero of=/etc/passwd)",
            // Wrappers.
            "sudo dd if=/dev/zero of=/etc/passwd",
            "env FOO=bar dd if=/dev/zero of=/etc/passwd",
            // Path-prefixed.
            "/usr/bin/dd if=/dev/zero of=/etc/passwd",
            "/bin/dd if=/dev/zero of=/etc/shadow",
        ] {
            assert_blocks_with_severity(&pack, cmd, Severity::Critical);
            assert_blocks_with_pattern(&pack, cmd, "dd-overwrite-root-home");
        }
    }

    #[test]
    fn dd_overwrite_blocks_general_high() {
        let pack = create_pack();
        for cmd in [
            "dd if=/dev/zero of=./important.db",
            "dd if=/dev/urandom of=secrets.txt",
            "dd if=/dev/zero of=build/output.bin bs=1M count=10",
            "dd of=workspace/critical.bin",
            "dd if=/dev/zero of=/data/important",
        ] {
            assert_blocks_with_severity(&pack, cmd, Severity::High);
            assert_blocks_with_pattern(&pack, cmd, "dd-overwrite-general");
        }
    }

    #[test]
    fn dd_to_dev_null_is_allowed() {
        // Read-only dd with output discarded — this is the canonical
        // way to test read speed of a sensitive file. Must NOT block.
        // The pack's destructive regex excludes /dev/ entirely, so
        // these fall through to default-allow without needing a safe
        // pattern.
        let pack = create_pack();
        for cmd in [
            "dd if=/etc/passwd of=/dev/null",
            "dd if=/etc/shadow of=/dev/null bs=1M",
            "dd if=/dev/sda of=/dev/null count=1024",
            "dd if=/etc/sudoers of=/dev/zero",
            "dd if=/etc/passwd of=/dev/full",
        ] {
            assert_no_match(&pack, cmd);
        }
    }

    #[test]
    fn dd_to_device_falls_through_to_system_disk() {
        // Out of scope per bead: device-level dd (`of=/dev/sda`) is
        // governed by the system.disk pack, not core.filesystem. The
        // `(?!/dev/)` lookahead in our regex excludes /dev entirely.
        let pack = create_pack();
        for cmd in [
            "dd if=/dev/zero of=/dev/sda",
            "dd if=/dev/urandom of=/dev/sdb1",
            "dd of=/dev/loop0 if=/tmp/img",
        ] {
            assert_no_match(&pack, cmd);
        }
    }

    #[test]
    fn dd_backup_to_tmp_from_sensitive_is_allowed() {
        // `dd if=/etc/passwd of=/tmp/passwd.bak` — backup (READ from
        // sensitive, WRITE to tmp). The destructive trigger is `of=`,
        // not `if=`; since `of=/tmp/...` matches the safe whitelist,
        // this is NOT destruction.
        let pack = create_pack();
        for cmd in [
            "dd if=/etc/passwd of=/tmp/passwd.bak",
            "dd if=/etc/shadow of=/tmp/shadow.backup",
            "dd if=/home/user/.ssh/id_ed25519 of=/tmp/keybackup",
        ] {
            assert_safe_pattern_matches(&pack, cmd);
        }
    }

    #[test]
    fn dd_under_tmp_is_allowed() {
        let pack = create_pack();
        for cmd in [
            "dd if=/dev/zero of=/tmp/scratch.bin bs=1M count=10",
            "dd if=/dev/urandom of=/tmp/random.bin bs=4096 count=1",
            "dd if=/dev/zero of=/var/tmp/cache.bin",
            "dd if=/dev/zero of=$TMPDIR/cache.bin",
            "dd if=/dev/zero of=${TMPDIR}/scratch",
            "dd of=/tmp/out.bin",
            "dd of=/tmp/out.bin if=/dev/zero",
        ] {
            assert_safe_pattern_matches(&pack, cmd);
        }
    }

    #[test]
    fn dd_help_is_allowed() {
        let pack = create_pack();
        for cmd in ["dd --help", "dd --version"] {
            assert_safe_pattern_matches(&pack, cmd);
        }
    }

    #[test]
    fn dd_no_false_positive_substring_traps() {
        let pack = create_pack();
        for cmd in [
            // `dd` is a 2-char common substring. Word-boundary `\bdd\b`
            // must reject these.
            "echo address",
            "ls add-ons.txt",
            "cat odd.log",
            "echo dd-script",
            "ls dd-readme.md",
            // `dd` alone (no `of=` operand).
            "dd",
            "dd if=/dev/zero",
            "dd if=/etc/passwd",
        ] {
            assert_no_match(&pack, cmd);
        }
    }

    #[test]
    fn dd_path_prefixed_normalizes_to_bare() {
        use crate::normalize::normalize_command;
        for (input, expected) in [
            (
                "/usr/bin/dd if=/dev/zero of=/etc/passwd",
                "dd if=/dev/zero of=/etc/passwd",
            ),
            (
                "/bin/dd if=/dev/urandom of=/etc/shadow",
                "dd if=/dev/urandom of=/etc/shadow",
            ),
        ] {
            let normalized = normalize_command(input);
            assert!(
                normalized.contains(expected),
                "PATH_NORMALIZER did not strip `{input}` to `{expected}` (got `{normalized}`)"
            );
        }
    }

    // ---------- mv: cross-segment recursive-force-delete bypass ----------

    #[test]
    fn mv_sensitive_source_blocks_critical() {
        let pack = create_pack();
        for cmd in [
            // Canonical bypass shape (only the mv portion is asserted;
            // the && rm -rf /tmp/x second segment is independently
            // safe-rescued by rm-rf-tmp).
            "mv /etc /tmp/x",
            "mv /etc/passwd /tmp/passwd-deleted",
            "mv /home/user /tmp/relocated",
            "mv $HOME /tmp/x",
            "mv ${HOME} /tmp/x",
            "mv ~/.ssh /tmp/keys",
            "mv /usr/local /tmp/x",
            "mv /var/log /tmp/log-relocated",
            // /dev/null silent destruction.
            "mv /etc /dev/null",
            "mv /home/user /dev/null",
            // Destination is sensitive (writing INTO /etc).
            "mv ./build/foo /etc/local-config.bak",
            "mv ./key.pem /home/user/.ssh/id_rsa",
            // In-place rename within /etc — bead's v1 decision: BLOCK.
            "mv /etc/hosts /etc/hosts.bak",
            "mv /etc/passwd /etc/passwd.old",
            // With flags.
            "mv -v /etc /tmp/x",
            "mv -f /etc /tmp/x",
            "mv -t /tmp/x /etc",
            "mv --backup=numbered /etc /tmp/x",
            // Quoted paths.
            "mv \"/etc\" /tmp/x",
            "mv '/etc' /tmp/x",
            // Compound forms.
            "echo done; mv /etc /tmp/x",
            "true && mv /etc /tmp/x",
            "(mv /etc /tmp/x)",
            // Wrappers.
            "sudo mv /etc /tmp/x",
            "env FOO=bar mv /etc /tmp/x",
            // Path-prefixed.
            "/usr/bin/mv /etc /tmp/x",
            "/bin/mv /etc /tmp/x",
        ] {
            assert_blocks_with_severity(&pack, cmd, Severity::Critical);
            assert_blocks_with_pattern(&pack, cmd, "mv-sensitive-source-root-home");
        }
    }

    #[test]
    fn mv_no_sensitive_path_is_allowed() {
        let pack = create_pack();
        // No sensitive path in source OR dest → destructive rule doesn't
        // fire → default-allow.
        for cmd in [
            "mv ./old.txt ./new.txt",
            "mv build/output.bin dist/",
            "mv foo.log foo.log.1",
            "mv ./src/a.rs ./src/b.rs",
        ] {
            assert_no_match(&pack, cmd);
        }
    }

    #[test]
    fn mv_under_tmp_is_allowed() {
        let pack = create_pack();
        // All tmp-family moves are rescued by the explicit safe patterns
        // (mv-tmp / mv-var-tmp / mv-tmpdir / mv-tmpdir-brace). For /var/tmp
        // the safe pattern is load-bearing because /var is sensitive and
        // would otherwise trip the destructive rule; for /tmp / $TMPDIR
        // the safe pattern is whitelisted for symmetry/discoverability —
        // those prefixes aren't sensitive so the destructive rule
        // wouldn't fire either way, but the explicit allow makes the
        // intent clearer to anyone reading explain output.
        for cmd in [
            "mv /tmp/foo /tmp/bar",
            "mv /tmp/foo /tmp/sub/bar",
            "mv -v /tmp/foo /tmp/bar",
            "mv /var/tmp/foo /var/tmp/bar",
            "mv /var/tmp/dir1 /var/tmp/dir2",
            "mv $TMPDIR/foo $TMPDIR/bar",
            "mv ${TMPDIR}/foo ${TMPDIR}/bar",
        ] {
            assert_safe_pattern_matches(&pack, cmd);
        }
    }

    #[test]
    fn mv_help_is_allowed() {
        let pack = create_pack();
        for cmd in ["mv --help", "mv --version"] {
            assert_safe_pattern_matches(&pack, cmd);
        }
    }

    #[test]
    fn mv_no_false_positive_substring_traps() {
        let pack = create_pack();
        for cmd in [
            "cat mv-script.sh",
            "ls mv-readme.md",
            "echo mv",
            "echo amv-tools",
            // No `mv` invocation at all — sensitive paths in unrelated
            // commands must not falsely match.
            "ls /etc",
            "cat /etc/passwd",
        ] {
            assert_no_match(&pack, cmd);
        }
    }

    #[test]
    fn mv_path_prefixed_normalizes_to_bare() {
        use crate::normalize::normalize_command;
        for (input, expected) in [
            ("/usr/bin/mv /etc /tmp/x", "mv /etc /tmp/x"),
            ("/bin/mv /home/user /tmp/x", "mv /home/user /tmp/x"),
        ] {
            let normalized = normalize_command(input);
            assert!(
                normalized.contains(expected),
                "PATH_NORMALIZER did not strip `{input}` to `{expected}` (got `{normalized}`)"
            );
        }
    }

    // ---------- redirect-truncate: shell-syntax truncate-equivalent ----------

    #[test]
    fn redirect_truncate_blocks_critical() {
        let pack = create_pack();
        for cmd in [
            // Bare redirect (no command).
            "> /etc/passwd",
            ">/etc/passwd",
            // Null builtin + redirect (common idiom).
            ": > /etc/passwd",
            ": >/etc/shadow",
            // Any command stdout > sensitive.
            "echo > /etc/passwd",
            "echo \"x\" > /etc/passwd",
            "cat /dev/null > /etc/passwd",
            "printf foo > /etc/sudoers",
            // Force-overwrite (>|).
            ">| /etc/passwd",
            "echo x >| /etc/passwd",
            // stdout+stderr (&>).
            "&> /etc/passwd",
            "make &> /etc/log",
            // Numbered FDs.
            "echo x 1> /etc/passwd",
            "echo x 2> /etc/passwd",
            "echo x 1>| /etc/passwd",
            "echo x 2>| /etc/passwd",
            // Home variants.
            "echo x > ~/.ssh/id_ed25519",
            "echo x > $HOME/.aws/credentials",
            "echo x > ${HOME}/.gnupg/secring.gpg",
            // Other system roots.
            "echo x > /usr/bin/sudo",
            "echo x > /boot/vmlinuz",
            // Quoted sensitive paths.
            "echo x > \"/etc/passwd\"",
            "echo x > '/etc/shadow'",
            // Compound forms.
            "echo done; > /etc/passwd",
            "true && > /etc/passwd",
            "(> /etc/passwd)",
            // Wrappers.
            "sudo bash -c '> /etc/passwd'",
            // Leading whitespace (script formatting / heredoc bodies).
            "  > /etc/passwd",
            "\t> /etc/passwd",
        ] {
            assert_blocks_with_severity(&pack, cmd, Severity::Critical);
            assert_blocks_with_pattern(&pack, cmd, "redirect-truncate-root-home");
        }
    }

    #[test]
    fn redirect_append_is_allowed() {
        // `>>` is append (non-destructive); the destructive regex's
        // negative lookbehind `(?<![<>])` excludes it. Even on
        // sensitive paths, append must NOT block.
        let pack = create_pack();
        for cmd in [
            "echo line >> /etc/syslog",
            "echo line >> ~/.bashrc",
            "make >> build.log",
            "echo line >> /etc/passwd",
            "echo line >> /etc/shadow",
            "command >> /usr/local/log",
            "echo x &>> /etc/log",
            "echo x 1>> /etc/passwd",
            "echo x 2>> /etc/passwd",
        ] {
            assert_no_match(&pack, cmd);
        }
    }

    // ---------- WI-3135: quoted redirect text is content, not a redirect ----------
    //
    // The 14-case suite (SPEC-WI-3135-r2). D1-D7 are real shell redirects on
    // the local command line (operator unquoted, or inside a quoted payload
    // that some LOCAL program will execute) and must keep denying with the
    // same rule id and severity. A1-A7 carry the same text inside quoted data
    // of an allowlisted content-bearing command (ssh remote payloads,
    // --body/--subject/-m message arguments, quoted echo prose) or use
    // append, and must allow.
    //
    // Every fixture below is asserted at BOTH layers: the pack API
    // (`create_pack()` / `Pack::check`, which sees the raw string) and the
    // SHIPPED path (`crate::evaluator::evaluate_detailed`, which sees
    // `normalize_command(strip_wrapper_prefixes(cmd))` with heredocs masked).
    // See `redirect_truncate_suite_holds_on_production_path_wi3135_fold3`.

    /// D1-D7 of the 14-case suite.
    const WI3135_SUITE_DENY: &[&str] = &[
        // D1: bare redirect to home.
        "> ~/x",
        // D2: unquoted redirect to a home secret.
        "echo x > ~/.ssh/id_ed25519",
        // D3: the incident's remote payload, run LOCALLY unquoted.
        "date -u +%FT%TZ > ~/offload/wi112/WI112-R8-BUNDLE-STAMP",
        // D4: unquoted redirect to /etc.
        "echo x > /etc/passwd",
        // D5: quoted TARGET, unquoted operator.
        "echo x > \"/etc/passwd\"",
        // D6: compound.
        "true && > /etc/passwd",
        // D7: LOCAL executor with a quoted payload.
        "sudo bash -c '> /etc/passwd'",
    ];

    /// A1-A7 of the 14-case suite.
    const WI3135_SUITE_ALLOW: &[&str] = &[
        // A1: incident I1 verbatim — ssh single-quoted remote payload.
        "scp /home/brynn-bendixen/dev/_deck/wi112-b5feeaf.bundle /home/brynn-bendixen/dev/_deck/LAUNCH-BRIEF-wi112-r8.md orca@100.117.246.48:offload/wi112/ && ssh orca@100.117.246.48 'sha256sum ~/offload/wi112/wi112-b5feeaf.bundle && cp ~/offload/wi112/R7-EXCLUDED-FILES.txt ~/offload/wi112/R8-EXCLUDED-FILES.txt && wc -l ~/offload/wi112/R8-EXCLUDED-FILES.txt && date -u +%FT%TZ > ~/offload/wi112/WI112-R8-BUNDLE-STAMP'",
        // A2: double-quoted remote payload.
        "ssh orca@100.117.246.48 \"date -u +%FT%TZ > ~/offload/wi112/stamp\"",
        // A3: incident I2 verbatim — prose message body.
        "orca orchestration send --type status --subject \"deploy-wi2096 report\" --body \"Denial to report: at 10:04 dcg BLOCKED a compound scp+ssh command whose remote payload wrote date -u > ~/offload/wi112/stamp; worked around by splitting\"",
        // A4: compound with a prose body.
        "orca orchestration send --subject \"receipt\" --body \"remote wrote date > ~/offload/stamp\" && git status",
        // A5: prose in a quoted echo argument.
        "echo \"use > ~/file to truncate\"",
        // A6: commit message.
        "git commit -m \"fix: log redirect > ~/log was wrong\"",
        // A7: append (existing carve-out).
        "echo x >> ~/.bashrc",
    ];

    /// The quoted-text shield must not extend to local shell-string
    /// executors: these run the quoted text on THIS host.
    const WI3135_LOCAL_EXECUTOR_DENY: &[&str] = &[
        "bash -c \"> ~/x\"",
        "sh -c '> /etc/passwd'",
        "eval '> ~/.bashrc'",
        "timeout 5 bash -c '> /etc/passwd'",
        "env FOO=1 sh -c '> ~/x'",
        "xargs -0 sh -c '> /etc/passwd'",
        "echo \"> ~/x\" | bash",
        "echo '> /etc/passwd' | sudo sh",
    ];

    /// fold r2 / strict r1 Major 1: shell sugar in front of the executor
    /// word must not hide it (`(sh`, `{ sh`, `! bash`, `$(sh`, backticks).
    const WI3135_SUGAR_DENY: &[&str] = &[
        "(sh -c '> /etc/passwd')",
        "{ sh -c '> /etc/passwd'; }",
        "! bash -c '> /etc/passwd'",
        "$(sh -c '> /etc/passwd')",
        "echo `sh -c '> /etc/passwd'`",
        "echo \"$(sh -c '> /etc/passwd')\"",
        "true && (sh -c '> ~/.bashrc')",
        "echo '> /etc/passwd' | (sh)",
        "echo \"> ~/x\"|bash",
        "FOO=1 sh -c '> /etc/passwd'",
        "!sh -c '> /etc/passwd'",
    ];

    /// fold r2 / strict r1 Major 2: programs that run a string (or stdin)
    /// through a local shell or interpreter outside the classifier's `-c`
    /// InlineCode route. None of these is an allowlisted content command.
    const WI3135_STRING_RUNNER_DENY: &[&str] = &[
        "script -qc '> /etc/passwd' /dev/null",
        "script -c '> /etc/passwd' /dev/null",
        "script -ec \"> ~/x\" /dev/null",
        "su -c '> /etc/passwd'",
        "su root -c '> /etc/passwd'",
        "runuser -u x -c '> /etc/passwd'",
        "doas -s '> /etc/passwd'",
        "sudo -s '> /etc/passwd'",
        "sudo -i '> /etc/passwd'",
        "sudo -u root -Es '> /etc/passwd'",
        "expect -c 'spawn sh -c \"> /etc/passwd\"'",
        "tclsh run.tcl '> /etc/passwd'",
        "osascript -e 'do shell script \"> /etc/passwd\"'",
        "screen -X stuff '> /etc/passwd'",
        // tmux types the text into a live local shell; Enter runs it.
        "tmux send-keys '> /etc/passwd' Enter",
        "tmux run-shell '> /etc/passwd'",
        "nsenter -t 1 -m -- '> /etc/passwd'",
        "unshare -r '> /etc/passwd'",
        "chroot /mnt '> /etc/passwd'",
        "parallel '> /etc/passwd' ::: x",
        "env -S '> /etc/passwd'",
        "echo '> /etc/passwd' | at now",
        "echo '> /etc/passwd' | batch",
        "systemd-run --shell '> /etc/passwd'",
        "xargs -I {} sh -c '> /etc/passwd'",
        "find . -exec sh -c '> /etc/passwd' \\;",
        "find . -execdir '> /etc/passwd' \\;",
        "flock /tmp/l -c '> /etc/passwd'",
        "watch '> ~/x'",
        "awk 'BEGIN { print \"x\" > \"/etc/passwd\" }'",
        "python3 run.py '> /etc/passwd'",
        "busybox sh -c '> /etc/passwd'",
        "sudo /bin/sh -c '> /etc/passwd'",
    ];

    /// fold r2 / strict r1 Major 3: ssh/scp/sftp whose destination is THIS
    /// host run the payload locally; the quoted `>` is a real truncate.
    const WI3135_LOOPBACK_DENY: &[&str] = &[
        "ssh localhost 'date > ~/.ssh/authorized_keys'",
        "ssh 127.0.0.1 \"date > ~/.ssh/authorized_keys\"",
        "ssh ::1 \"date > ~/.ssh/authorized_keys\"",
        "ssh -p 2222 root@localhost 'date > ~/x'",
        "ssh -p2222 -l root localhost 'date > ~/x'",
        "ssh -vp 2222 localhost 'date > ~/x'",
        "ssh root@[::1] 'date > ~/x'",
        "ssh ssh://root@localhost:22 'date > ~/x'",
        "ssh localhost.localdomain 'date > ~/x'",
        "ssh ip6-localhost 'date > ~/x'",
        "ssh 127.1 'date > ~/x'",
        "ssh 0.0.0.0 'date > ~/x'",
        "ssh ::ffff:127.0.0.1 'date > ~/x'",
        "ssh 2130706433 'date > ~/x'",
        "ssh 0x7f000001 'date > ~/x'",
        "ssh -o Host=localhost bogus 'date > ~/x'",
        "ssh -oHostName=127.0.0.1 bogus 'date > ~/x'",
        "ssh -o \"HostName localhost\" bogus 'date > ~/x'",
        "ssh $(hostname) 'date > ~/x'",
        "ssh \"$(hostname -f)\" 'date > ~/x'",
        "ssh user@$(uname -n) 'date > ~/x'",
        "ssh `hostname -s` 'date > ~/x'",
        "ssh \"$HOSTNAME\" 'date > ~/x'",
        "ssh $HOSTNAME 'date > ~/x'",
        "ssh ${HOSTNAME} 'date > ~/x'",
        "timeout 30 ssh localhost 'date -u > ~/offload/stamp'",
        "sudo ssh -i key localhost 'date > ~/x'",
        "scp localhost:x /tmp && ssh localhost 'date > ~/x'",
    ];

    /// fold r2: a real remote host keeps the quoted payload as content,
    /// including when wrapped or named through `-o Host`.
    const WI3135_REMOTE_ALLOW: &[&str] = &[
        "ssh orca@100.117.246.48 'date -u > ~/offload/stamp'",
        "ssh user@host.example \"date > ~/stamp\"",
        "ssh -p 2222 -l root 100.117.246.48 'date > ~/x'",
        "ssh -o Host=100.117.246.48 deploy-box 'date > ~/x'",
        "ssh -J jump.example user@host.example 'date > ~/x'",
        "ssh root@[2001:db8::10] 'date > ~/x'",
        "ssh -4 host.example 'date > ~/x'",
        "ssh -- host.example 'date > ~/x'",
        "timeout 30 ssh orca@100.117.246.48 'date -u > ~/offload/stamp'",
        "scp file orca@100.117.246.48:~/x && ssh orca@100.117.246.48 'date > ~/x'",
        "ssh host.example 'date > ~/stamp' | tee log",
        "ssh host.example \"date > ~/stamp-$(date +%F)\"",
    ];

    /// fold r2 (sol Minor): an argv-exec wrapper in front of a
    /// content-bearing command is that inner command.
    const WI3135_WRAPPER_ALLOW: &[&str] = &[
        "sudo echo \"use > ~/file to truncate\"",
        "env echo \"use > ~/file to truncate\"",
        "timeout 5 echo \"use > ~/file to truncate\"",
        "nohup orca send --body \"wrote date > ~/x\"",
        "nice -n 10 printf \"%s\" \"> ~/x\"",
        "sudo -u deploy orca send --body \"wrote date > ~/x\"",
    ];

    /// fold r2: a wrapper in front of a real executor still denies.
    const WI3135_WRAPPER_DENY: &[&str] = &[
        "sudo sh -c '> /etc/passwd'",
        "sudo -u root sh -c '> /etc/passwd'",
        "env FOO=1 bash -c '> /etc/passwd'",
        "timeout 5 eval '> /etc/passwd'",
        "sudo echo '> /etc/passwd' | sh",
        "nohup script -c '> /etc/passwd' /dev/null",
    ];

    /// fold r2 (opus): quote tricks around an UNQUOTED operator never mask it.
    const WI3135_ADVERSARIAL_DENY: &[&str] = &[
        "echo \"x\" >\"/etc/passwd\"",
        "echo \"it's fine\" > /etc/passwd",
        "echo \\' > /etc/passwd",
        "echo a\\\"b > /etc/passwd",
        "echo x 2> /etc/passwd",
        "echo x &> /etc/passwd",
        "echo \"done\" >| /etc/passwd",
        "orca send --body \"wrote date > ~/x\" > ~/realfile",
    ];

    // ---------- WI-3135 fold r3: the shield is an ALLOWLIST (fail closed) ----------

    /// strict r2 Critical + Major (`filesystem.rs:1468`, `:1071`): the
    /// command word must be an allowlisted CONTENT-BEARING program. A
    /// substitution, an unlisted program, an interpreter or a
    /// string-executing subcommand leaves the segment unmasked, so the raw
    /// regex denies exactly as it did on base `0a38dee`.
    const WI3135_UNLISTED_COMMAND_DENY: &[&str] = &[
        // Critical: substituted command words.
        "$SHELL -c '> /etc/passwd'",
        "${SHELL} -c '> /etc/passwd'",
        "$(which sh) -c '> /etc/passwd'",
        "\"$SHELL\" -c '> /etc/passwd'",
        // Critical: quote/backslash-obfuscated names — dequoted to `sh`,
        // which is not a content command, at BOTH layers.
        "\"sh\" -c '> /etc/passwd'",
        "s'h' -c '> /etc/passwd'",
        "s\\h -c '> /etc/passwd'",
        "echo '> /etc/passwd' | \"sh\"",
        "echo '> /etc/passwd' | s\\h",
        // Major: string-executing programs the r2 denylist missed.
        "git submodule foreach '> ~/.ssh/authorized_keys'",
        "git config alias.wipe '> /etc/passwd'",
        "git commit '> /etc/passwd'",
        "ansible localhost -m shell -a '> /etc/passwd'",
        "ansible-playbook -e 'cmd=> /etc/passwd' p.yml",
        "nix-shell --run '> /etc/passwd'",
        "npx -c '> /etc/passwd'",
        "gdb -ex 'shell > /etc/passwd'",
        "make '> /etc/passwd'",
        "just '> /etc/passwd'",
        // sed with an executing script (`s///e` runs the result).
        "sed 's|x|> /etc/passwd|e' file",
        "sed -e 's@y@> ~/.bashrc@e' file",
        "sed '1,$e cat > /etc/passwd' file",
        // Interpreters (strict r2 Minor `:1112`): answered by the allowlist
        // model — an interpreter is simply not a content command. Recorded
        // as a deliberately CONSERVATIVE denial, not a false positive the
        // WI must fix.
        "python3 run.py '> /etc/passwd'",
        "python3 tools/send.py --body \"wrote date > ~/stamp\"",
        "perl -e '> /etc/passwd'",
        "node -e '> /etc/passwd'",
        // Shell-mode wrappers.
        "sudo -s '> /etc/passwd'",
        "env -S 'sh -c \"> /etc/passwd\"'",
        // curl/wget are content only for a pure request BODY.
        "curl -o out '> /etc/passwd' https://h.example/",
        "curl \"date > ~/x\" | sh",
        "wget -O - '> /etc/passwd' https://h.example/",
    ];

    /// strict r2 Major (`filesystem.rs:1391`): an `ssh` option that runs a
    /// command through a LOCAL shell makes the payload non-content, whatever
    /// the destination.
    const WI3135_SSH_OPTION_DENY: &[&str] = &[
        "ssh -oProxyCommand=\"sh -c '> /etc/passwd'\" host.example",
        "ssh -o ProxyCommand=\"sh -c '> /etc/passwd'\" host.example",
        "ssh -o LocalCommand=\"date > ~/x\" -o PermitLocalCommand=yes host.example",
        "ssh -o ProxyJump=\"sh -c '> ~/x'\" host.example",
        "ssh -o \"Match exec date > ~/x\" host.example",
        "ssh -o PermitLocalCommand=yes host.example 'date > ~/x'",
        "ssh -o UnknownKey=x host.example 'date > ~/x'",
        "ssh -o ForwardAgent=yes host.example 'date > ~/x'",
        "ssh -J \"x;date > ~/x\" host.example 'true'",
        "scp -o ProxyCommand=\"date > ~/x\" file host.example:/tmp/f",
    ];

    /// strict r2 Major (`filesystem.rs:1468`): the allowlist test applies to
    /// the COMMAND WORD only. A listed name in argument position is
    /// irrelevant, and the extra per-program conditions hold.
    const WI3135_CONTENT_ALLOW: &[&str] = &[
        // Command position only: `python`/`sh` as a --subject value.
        "orca send --subject python --body \"use > ~/file\"",
        "orca send --subject sh --body \"date > ~/x\"",
        "orca send --subject \"bash -c\" --body \"date > ~/x\"",
        // Dequoted command word agrees with the shipped normalization.
        "\"orca\" send --body \"date > ~/x\"",
        // Wrapper option scan stops at its first operand: `-i` is grep's.
        "sudo grep -i \"note: date > ~/stamp\" file",
        "grep -rn \"date > ~/x\" src",
        // git/gh message payloads.
        "git commit -m \"log > ~/x\"",
        "git notes add -m \"log > ~/x\"",
        // Global options in front of a message subcommand are skipped, not
        // fail-closed: defining an alias does not run it, and both layers
        // agree here (the shipped path treats the `-m` payload as data).
        "git -c alias.x='!sh' commit -m \"log > ~/x\"",
        "gh pr comment 5 --body \"wrote date > ~/stamp\"",
        "gh issue create --title \"date > ~/x\" --body \"date > ~/x\"",
        // curl request body only.
        "curl -d \"date > ~/x\" https://h.example/",
        // sed script that cannot execute (no `e` flag).
        "sed 's|x|> /etc/passwd|' file",
        // ssh with only safe -o options and a genuine remote destination.
        "ssh -o StrictHostKeyChecking=no -p 2222 orca@100.117.246.48 'date -u > ~/offload/stamp'",
        "ssh -o BatchMode=yes -o ConnectTimeout=5 host.example 'date > ~/x'",
        "ssh -o ForwardAgent=no host.example 'date > ~/x'",
        "timeout 30 ssh orca@100.117.246.48 'date -u > ~/offload/stamp'",
        // The substitution is InlineCode (never masked); the `>` sits in the
        // surrounding plain double-quoted Argument span of a content command.
        "echo \"$(date) > ~/x\"",
    ];

    fn assert_pack_denies_redirect(pack: &Pack, cmd: &str) {
        assert_blocks_with_severity(pack, cmd, Severity::Critical);
        assert_blocks_with_pattern(pack, cmd, "redirect-truncate-root-home");
    }

    #[test]
    fn redirect_truncate_unquoted_operator_still_blocks_wi3135() {
        let pack = create_pack();
        for cmd in WI3135_SUITE_DENY {
            assert_pack_denies_redirect(&pack, cmd);
        }
    }

    #[test]
    fn redirect_truncate_quoted_payload_or_message_body_is_allowed_wi3135() {
        let pack = create_pack();
        for cmd in WI3135_SUITE_ALLOW {
            assert_no_match(&pack, cmd);
        }
    }

    #[test]
    fn redirect_truncate_quoted_text_fed_to_local_executor_still_blocks_wi3135() {
        let pack = create_pack();
        for cmd in WI3135_LOCAL_EXECUTOR_DENY {
            assert_blocks_with_pattern(&pack, cmd, "redirect-truncate-root-home");
        }
    }

    // ---------- WI-3135 fold r2: strict r1 Majors 1-3 + follow-ups ----------

    #[test]
    fn redirect_truncate_paren_or_sugar_prefixed_local_shell_still_blocks_wi3135_fold() {
        let pack = create_pack();
        for cmd in WI3135_SUGAR_DENY {
            assert_pack_denies_redirect(&pack, cmd);
        }
    }

    #[test]
    fn redirect_truncate_string_running_wrappers_still_block_wi3135_fold() {
        let pack = create_pack();
        for cmd in WI3135_STRING_RUNNER_DENY {
            assert_pack_denies_redirect(&pack, cmd);
        }
    }

    #[test]
    fn redirect_truncate_loopback_ssh_is_local_wi3135_fold() {
        let pack = create_pack();
        for cmd in WI3135_LOOPBACK_DENY {
            assert_pack_denies_redirect(&pack, cmd);
        }
        // The machine's own name is local too. `local_hostname` must answer on
        // every shipped target (strict r2 Major `filesystem.rs:1328`): this
        // assertion is what stops the arm below from silently self-skipping.
        let own = local_hostname().expect("local_hostname must resolve on a shipped target");
        for cmd in [
            format!("ssh {own} 'date > ~/x'"),
            format!("ssh admin@{own} 'date > ~/x'"),
        ] {
            assert_pack_denies_redirect(&pack, &cmd);
        }
        if let Some(short) = own.split('.').next() {
            assert_pack_denies_redirect(
                &pack,
                &format!("ssh {short}.example.internal 'date > ~/x'"),
            );
        }
        // Loopback without a redirect: no rule, no panic.
        for cmd in [
            "scp file localhost:~/.ssh/x",
            "ssh localhost",
            "ssh",
            "ssh -p",
            "sftp -P 22 localhost",
            "ssh -o",
            "ssh -o Host=",
        ] {
            assert_no_match(&pack, cmd);
        }
    }

    #[test]
    fn redirect_truncate_genuine_remote_payload_stays_content_wi3135_fold() {
        let pack = create_pack();
        for cmd in WI3135_REMOTE_ALLOW {
            assert_no_match(&pack, cmd);
        }
    }

    #[test]
    fn redirect_truncate_transparent_wrapper_prose_is_content_wi3135_fold() {
        let pack = create_pack();
        for cmd in WI3135_WRAPPER_ALLOW {
            assert_no_match(&pack, cmd);
        }
        for cmd in WI3135_WRAPPER_DENY {
            assert_blocks_with_pattern(&pack, cmd, "redirect-truncate-root-home");
        }
    }

    #[test]
    fn redirect_truncate_adversarial_quoting_still_blocks_wi3135_fold() {
        let pack = create_pack();
        for cmd in WI3135_ADVERSARIAL_DENY {
            assert_pack_denies_redirect(&pack, cmd);
        }
    }

    // ---------- WI-3135 fold r3: allowlist inversion, ssh options, hostname ----------

    #[test]
    fn redirect_truncate_unlisted_command_word_still_blocks_wi3135_fold3() {
        let pack = create_pack();
        for cmd in WI3135_UNLISTED_COMMAND_DENY {
            assert_pack_denies_redirect(&pack, cmd);
        }
    }

    #[test]
    fn redirect_truncate_locally_executing_ssh_options_still_block_wi3135_fold3() {
        let pack = create_pack();
        for cmd in WI3135_SSH_OPTION_DENY {
            assert_pack_denies_redirect(&pack, cmd);
        }
    }

    #[test]
    fn redirect_truncate_content_command_word_is_allowed_wi3135_fold3() {
        let pack = create_pack();
        for cmd in WI3135_CONTENT_ALLOW {
            assert_no_match(&pack, cmd);
        }
    }

    /// strict r2 Major (`filesystem.rs:1328`): both arms of the own-hostname
    /// rule, injected through the `Option<&str>` seam so neither can
    /// self-skip on a host where the name is unresolvable.
    #[test]
    fn redirect_truncate_hostname_resolution_is_fail_closed_wi3135_fold3() {
        let cmd = "ssh build-box.example 'date > ~/.ssh/authorized_keys'";
        // Resolvable and equal (fully qualified or short) => LOCAL => the
        // segment stays unmasked, so the raw regex denies.
        assert!(redirect_unquoted_scan_view_with(cmd, Some("build-box.example")).contains('>'));
        assert!(redirect_unquoted_scan_view_with(cmd, Some("build-box")).contains('>'));
        // Unresolvable => fail closed to LOCAL => still unmasked.
        assert!(redirect_unquoted_scan_view_with(cmd, None).contains('>'));
        // A genuinely different host => remote => content => masked.
        assert!(!redirect_unquoted_scan_view_with(cmd, Some("laptop-42")).contains('>'));

        assert!(ssh_host_is_local_with(
            "build-box.example",
            Some("build-box.example")
        ));
        assert!(ssh_host_is_local_with(
            "build-box",
            Some("build-box.example")
        ));
        assert!(ssh_host_is_local_with("host.example", None));
        assert!(ssh_host_is_local_with("localhost", None));
        assert!(!ssh_host_is_local_with("host.example", Some("build-box")));
        // An empty host is not a host at all, resolvable or not.
        assert!(!ssh_host_is_local_with("", None));
    }

    #[test]
    fn redirect_scan_view_helpers_wi3135_fold() {
        // Stages: a live `|`, `(`, `{` or `)` starts a new one; a quoted run
        // stays one word; a `$(...)` is absorbed into the word it touches.
        let stage_texts = |segment: &str| -> Vec<Vec<String>> {
            segment_stages(segment)
                .into_iter()
                .map(|stage| stage.into_iter().map(|w| w.text.to_string()).collect())
                .filter(|stage: &Vec<String>| !stage.is_empty())
                .collect()
        };
        assert_eq!(
            stage_texts("(sh -c '> /etc/passwd')"),
            [["sh", "-c", "'> /etc/passwd'"]]
        );
        assert_eq!(
            stage_texts("echo '> /etc/passwd' | \"sh\""),
            [
                vec!["echo".to_string(), "'> /etc/passwd'".to_string()],
                vec!["\"sh\"".to_string()]
            ]
        );
        assert_eq!(
            stage_texts("ssh user@$(uname -n) 'x'"),
            [["ssh", "user@$(uname -n)", "'x'"]]
        );

        // Command-word resolution: dequote, but never guess a substitution.
        assert_eq!(content_command_word("\"sh\"").as_deref(), Some("sh"));
        assert_eq!(content_command_word("s'h'").as_deref(), Some("sh"));
        assert_eq!(content_command_word("s\\h").as_deref(), Some("sh"));
        assert_eq!(content_command_word("/bin/sh").as_deref(), Some("sh"));
        assert_eq!(content_command_word("!sh").as_deref(), Some("sh"));
        assert_eq!(content_command_word("$SHELL"), None);
        assert_eq!(content_command_word("${SHELL}"), None);
        assert_eq!(content_command_word("$(which sh)"), None);

        // The inverted default: content only for an allowlisted command word.
        assert!(segment_is_content(
            "orca send --body '> x'",
            Some("build-box")
        ));
        assert!(segment_is_content("sudo echo '> x'", Some("build-box")));
        assert!(segment_is_content(
            "sudo grep -i '> x' f",
            Some("build-box")
        ));
        assert!(!segment_is_content("sudo -s '> x'", Some("build-box")));
        assert!(!segment_is_content("mystery-tool '> x'", Some("build-box")));
        assert!(!segment_is_content("$SHELL -c '> x'", Some("build-box")));
        assert!(!segment_is_content(
            "echo '> x' | mystery-tool",
            Some("build-box")
        ));
        assert!(segment_is_content(
            "ssh host.example 'x'",
            Some("build-box")
        ));
        assert!(!segment_is_content("ssh localhost 'x'", Some("build-box")));
        assert!(!segment_is_content(
            "ssh -o ProxyCommand=x host.example 'y'",
            Some("build-box")
        ));

        // sed executes only with an `e` flag / `e` command.
        assert!(sed_arg_executes("'s|x|y|e'"));
        assert!(sed_arg_executes("'1,$e cat'"));
        assert!(!sed_arg_executes("'s|x|y|g'"));
        assert!(!sed_arg_executes("'/here/d'"));
        assert!(!sed_arg_executes("-n"));

        // Nit (`packs/mod.rs:305`): the view preserves byte length.
        for cmd in WI3135_SUITE_DENY
            .iter()
            .chain(WI3135_SUITE_ALLOW)
            .chain(WI3135_UNLISTED_COMMAND_DENY)
            .chain(WI3135_SSH_OPTION_DENY)
            .chain(WI3135_CONTENT_ALLOW)
        {
            assert_eq!(
                redirect_unquoted_scan_view(cmd).len(),
                cmd.len(),
                "scan view changed byte length for `{cmd}`"
            );
        }
    }

    /// strict r2 Major (`filesystem.rs:3285`): every WI-3135 fixture is
    /// asserted on the SHIPPED decision path — `evaluate_detailed`, which
    /// applies `strip_wrapper_prefixes` + `normalize_command` (including the
    /// command-word dequoting at `normalize.rs:1453`) and heredoc masking
    /// before pack evaluation — not only against `create_pack()`. Where the
    /// two layers could disagree (quote-obfuscated command words), the code
    /// was changed so they agree; see `content_command_word`.
    #[test]
    fn redirect_truncate_suite_holds_on_production_path_wi3135_fold3() {
        for cmd in WI3135_SUITE_DENY
            .iter()
            .chain(WI3135_LOCAL_EXECUTOR_DENY)
            .chain(WI3135_SUGAR_DENY)
            .chain(WI3135_STRING_RUNNER_DENY)
            .chain(WI3135_LOOPBACK_DENY)
            .chain(WI3135_WRAPPER_DENY)
            .chain(WI3135_ADVERSARIAL_DENY)
            .chain(WI3135_UNLISTED_COMMAND_DENY)
            .chain(WI3135_SSH_OPTION_DENY)
        {
            assert_production_denies_redirect(cmd);
        }
        for cmd in WI3135_SUITE_ALLOW
            .iter()
            .chain(WI3135_REMOTE_ALLOW)
            .chain(WI3135_WRAPPER_ALLOW)
            .chain(WI3135_CONTENT_ALLOW)
        {
            assert_production_allows_redirect(cmd);
        }
    }

    /// Run a fixture through the shipped entry point.
    fn production_result(cmd: &str) -> crate::evaluator::EvaluationResult {
        crate::evaluator::evaluate_detailed(cmd, &crate::config::Config::default()).result
    }

    fn assert_production_denies_redirect(cmd: &str) {
        let result = production_result(cmd);
        let info = result.pattern_info.as_ref().unwrap_or_else(|| {
            panic!(
                "production path allowed `{cmd}`; expected \
                 core.filesystem:redirect-truncate-root-home at Critical"
            )
        });
        assert_eq!(
            info.pattern_name.as_deref(),
            Some("redirect-truncate-root-home"),
            "production path denied `{cmd}` by {:?} in pack {:?}, not redirect-truncate-root-home",
            info.pattern_name,
            info.pack_id
        );
        assert_eq!(
            info.pack_id.as_deref(),
            Some("core.filesystem"),
            "production path denied `{cmd}` from the wrong pack"
        );
        assert_eq!(
            info.severity,
            Some(Severity::Critical),
            "production path denied `{cmd}` at the wrong severity"
        );
        assert!(
            result.is_denied(),
            "production path matched but did not deny `{cmd}`"
        );
    }

    fn assert_production_allows_redirect(cmd: &str) {
        let result = production_result(cmd);
        if let Some(info) = &result.pattern_info {
            assert_ne!(
                info.pattern_name.as_deref(),
                Some("redirect-truncate-root-home"),
                "production path denied `{cmd}` by redirect-truncate-root-home; expected content"
            );
        }
        assert!(
            result.is_allowed(),
            "production path denied `{cmd}` by {:?} in pack {:?}",
            result
                .pattern_info
                .as_ref()
                .and_then(|i| i.pattern_name.clone()),
            result.pattern_info.as_ref().and_then(|i| i.pack_id.clone())
        );
    }

    #[test]
    fn redirect_truncate_to_non_sensitive_is_allowed() {
        // No `-general` tier (per bead's option-a recommendation):
        // these legitimate workflows must NOT block.
        let pack = create_pack();
        for cmd in [
            "make > build.log",
            "cargo test > test.log",
            "echo x > ./output.txt",
            "echo x > foo.log",
            "ls > files.txt",
            "command > /tmp/scratch",
            "command > $TMPDIR/scratch",
            "command > ${TMPDIR}/scratch",
            "echo x >| build.log",
            "echo x &> build.log",
            "echo x 2> err.log",
        ] {
            assert_no_match(&pack, cmd);
        }
    }

    #[test]
    fn redirect_read_is_allowed() {
        // Read redirects (`<`, `<<`, `<<<`) don't truncate anything.
        let pack = create_pack();
        for cmd in [
            "cat < /etc/passwd",
            "wc -l < /etc/hosts",
            "sort < /etc/passwd > /tmp/sorted",
            "while read line; do echo $line; done < /etc/hosts",
        ] {
            assert_no_match(&pack, cmd);
        }
    }

    #[test]
    fn redirect_to_fd_is_allowed() {
        // `1>&2` and `2>&1` redirect FD-to-FD, not file truncation.
        // The regex's `\s*['"]?<sensitive>` clause requires `/`/`~`/
        // `$HOME` next, which `&` doesn't satisfy.
        let pack = create_pack();
        for cmd in [
            "echo x 1>&2",
            "echo x 2>&1",
            "command 2>&1 | tee log.txt",
            "echo x >&2",
        ] {
            assert_no_match(&pack, cmd);
        }
    }

    #[test]
    fn redirect_no_false_positive_substring_traps() {
        let pack = create_pack();
        for cmd in [
            // Comparison operators in unrelated commands.
            "test 5 > 3",
            "[ \"a\" \\> \"b\" ]",
            // No redirect at all.
            "ls /etc",
            "cat /etc/passwd",
            // Not a `>` redirect (heredoc indicator, not output redirect).
            "cat <<EOF",
            "cat <<<\"input\"",
        ] {
            assert_no_match(&pack, cmd);
        }
    }

    #[test]
    fn redirect_to_dev_null_zero_full_is_allowed_universally() {
        // Regression guard for the most common shell idiom: discarding
        // output to /dev/null. The `(?!/dev/(?:null|zero|full)\b)`
        // lookahead in `redirect-truncate-root-home` exempts these
        // sinks; without it, every script that suppresses output (which
        // is essentially every script) would be blocked.
        let pack = create_pack();
        for cmd in [
            "command > /dev/null",
            "command >/dev/null",
            "command 2>&1 > /dev/null",
            "command > /dev/null 2>&1",
            "command 2> /dev/null",
            "command &> /dev/null",
            "cat /etc/passwd > /dev/null",
            "find . > /dev/null 2>&1",
            "make > /dev/zero",
            "echo test > /dev/full",
        ] {
            assert_no_match(&pack, cmd);
        }
    }

    #[test]
    fn redirect_to_dev_devices_still_blocks() {
        // The /dev/{null,zero,full} carve-out must NOT relax actual
        // device destruction (`> /dev/sda` etc.) — only the safe sinks.
        let pack = create_pack();
        for cmd in [
            "> /dev/sda",
            "echo zero > /dev/sda1",
            "command > /dev/sdb",
            "echo > /dev/nvme0n1",
        ] {
            assert_blocks_with_pattern(&pack, cmd, "redirect-truncate-root-home");
        }
    }

    #[test]
    fn redirect_glued_operator_blocks_destructive() {
        // Bypass attempt: glue the operator to the path with no space.
        // The dcg tokenizer keeps `data>/etc/passwd` as a single token,
        // and previously the args-data masking would erase the whole
        // thing. The `glued_redirect_split_position` helper now masks
        // only the prefix and leaves operator+target visible.
        let pack = create_pack();
        for cmd in [
            "echo data>/etc/passwd",
            "printf data>/etc/passwd",
            "echo data>~/.ssh/id_rsa",
            "echo data>$HOME/.aws/credentials",
            "echo \"data\">/etc/passwd",
            "echo data>'/etc/passwd'",
            "echo data>\"/etc/passwd\"",
            "echo x 2>/etc/passwd",
            "echo x 1>/etc/passwd",
            "echo x &>/etc/passwd",
            "echo x >|/etc/passwd",
        ] {
            assert_blocks_with_pattern(&pack, cmd, "redirect-truncate-root-home");
        }
    }

    #[test]
    fn redirect_glued_operator_to_non_sensitive_is_allowed() {
        // The glued-redirect-split heuristic must NOT cause new false
        // positives on tokens where `>` is followed by a path-like char
        // but the path itself isn't sensitive.
        let pack = create_pack();
        for cmd in [
            "echo data>./local.txt",
            "echo data>build.log",
            "echo data>/tmp/scratch",
            "echo data>/dev/null",
            "echo data>$LOG_FILE",
        ] {
            assert_no_match(&pack, cmd);
        }
    }

    #[test]
    fn redirect_ansi_c_and_locale_quoted_paths_block() {
        // Bash ANSI-C (`$'...'`) and locale (`$"..."`) quoting forms
        // must not bypass. The optional-quote group in the regex now
        // accepts both `\$'` and `\$"` as quote prefixes.
        let pack = create_pack();
        for cmd in [
            "> $'/etc/passwd'",
            "> $\"/etc/passwd\"",
            ": > $'/etc/shadow'",
            "echo > $'/etc/passwd'",
            "echo > $\"/etc/passwd\"",
        ] {
            assert_blocks_with_pattern(&pack, cmd, "redirect-truncate-root-home");
        }
    }

    #[test]
    fn mv_ansi_c_and_locale_quoted_sources_block() {
        // Same ANSI-C / locale quoting bypass for the mv rule. Without
        // the fix, `mv $'/etc' /tmp/x` slipped past as a HIGH-impact
        // gap (mv has no general tier to fall back on).
        let pack = create_pack();
        for cmd in [
            "mv $'/etc' /tmp/x",
            "mv $\"/etc\" /tmp/x",
            "mv $'/etc/passwd' /tmp/passwd",
            "mv $\"/home/user\" /tmp/relocated",
        ] {
            assert_blocks_with_pattern(&pack, cmd, "mv-sensitive-source-root-home");
        }
    }

    #[test]
    fn echo_quoted_data_args_with_arrow_no_path_dont_falsely_match() {
        // Plain-data quoted args where `>` is followed by a non-path
        // character must NOT trigger the
        // `glued_redirect_split_position` heuristic, so they stay
        // masked through the full sanitize. (Tokens whose `>` is
        // followed by `/`, `~`, `$`, or a quote DO get split — that's
        // the bypass-fix path tested separately via the e2e harness
        // since `assert_no_match` operates on the raw command and
        // can't observe sanitize behavior.)
        let pack = create_pack();
        for cmd in [
            "echo \"5 > 3\"",
            "echo \"user>admin\"",
            "echo \"<html><body>\"",
        ] {
            assert_no_match(&pack, cmd);
        }
    }

    #[test]
    fn test_rm_rf_root_critical() {
        let pack = create_pack();
        assert_blocks_with_severity(&pack, "rm -rf /", Severity::Critical);
        assert_blocks_with_severity(&pack, "rm -rf /etc", Severity::Critical);
        assert_blocks_with_severity(&pack, "rm -rf /home", Severity::Critical);
        assert_blocks_with_severity(&pack, "rm -rf ~/", Severity::Critical);
        assert_blocks_with_pattern(&pack, "rm -rf /", "rm-rf-root-home");
        // Quoted / or ~ — shell evaluates to / or ~; must still block.
        assert_blocks_with_severity(&pack, "rm -rf \"/\"", Severity::Critical);
        assert_blocks_with_severity(&pack, "rm -rf '/'", Severity::Critical);
        assert_blocks_with_severity(&pack, "rm -rf \"~/\"", Severity::Critical);
        assert_blocks_with_severity(&pack, "rm -rf '/etc'", Severity::Critical);
    }

    #[test]
    fn test_rm_separate_and_long_flag_root_is_critical() {
        // Previously only the combined `-rf` form produced Critical severity
        // on root/home targets. `-r -f /` and `--recursive --force /` were
        // attributed to the general High-severity rules, understating the
        // catastrophic nature of wiping the root filesystem.
        let pack = create_pack();
        assert_blocks_with_severity(&pack, "rm -r -f /", Severity::Critical);
        assert_blocks_with_severity(&pack, "rm -f -r /", Severity::Critical);
        assert_blocks_with_severity(&pack, "rm -r -f /etc", Severity::Critical);
        assert_blocks_with_severity(&pack, "rm -r -f ~/", Severity::Critical);
        assert_blocks_with_pattern(&pack, "rm -r -f /", "rm-r-f-separate-root-home");

        assert_blocks_with_severity(&pack, "rm --recursive --force /", Severity::Critical);
        assert_blocks_with_severity(&pack, "rm --force --recursive /", Severity::Critical);
        assert_blocks_with_severity(&pack, "rm --recursive --force /etc", Severity::Critical);
        assert_blocks_with_pattern(
            &pack,
            "rm --recursive --force /",
            "rm-recursive-force-root-home",
        );

        // Quoted forms too
        assert_blocks_with_severity(&pack, "rm -r -f \"/\"", Severity::Critical);
        assert_blocks_with_severity(&pack, "rm --recursive --force '/'", Severity::Critical);
        // Backslash-escaped root: shell unescapes \/ to / and \~ to ~.
        assert_blocks_with_severity(&pack, "rm -rf \\/", Severity::Critical);
        assert_blocks_with_severity(&pack, "rm -rf \\~", Severity::Critical);
        assert_blocks_with_severity(&pack, "rm -r -f \\/", Severity::Critical);
        assert_blocks_with_severity(&pack, "rm --recursive --force \\/", Severity::Critical);
        // $HOME variants: shell expands to the user's home directory.
        assert_blocks_with_severity(&pack, "rm -rf $HOME", Severity::Critical);
        assert_blocks_with_severity(&pack, "rm -rf \"$HOME\"", Severity::Critical);
        assert_blocks_with_severity(&pack, "rm -rf ${HOME}", Severity::Critical);
        assert_blocks_with_severity(&pack, "rm -rf \"${HOME}\"", Severity::Critical);
        assert_blocks_with_severity(&pack, "rm -r -f $HOME", Severity::Critical);
        assert_blocks_with_severity(&pack, "rm --recursive --force $HOME", Severity::Critical);

        // Non-root targets retain their existing (High) severity, so we don't
        // accidentally upgrade innocuous cleanup commands.
        assert_blocks_with_severity(&pack, "rm -r -f ./build", Severity::High);
        assert_blocks_with_severity(&pack, "rm --recursive --force ./build", Severity::High);
    }

    #[test]
    fn test_rm_rf_general_high() {
        let pack = create_pack();
        // Outside safe dirs, general rule catches it
        assert_blocks_with_severity(&pack, "rm -rf ./build", Severity::High);
        assert_blocks_with_pattern(&pack, "rm -rf ./build", "rm-rf-general");
    }

    #[test]
    fn test_rm_flags_ordering() {
        let pack = create_pack();
        assert_blocks(&pack, "rm -r -f ./build", "separate -r -f flags");
        assert_blocks(&pack, "rm -f -r ./build", "separate -r -f flags");
        assert_blocks(
            &pack,
            "rm --recursive --force ./build",
            "rm --recursive --force is destructive",
        );
        assert_blocks(
            &pack,
            "rm --force --recursive ./build",
            "rm --recursive --force is destructive",
        );
    }

    #[test]
    fn test_safe_rm_tmp() {
        let pack = create_pack();
        assert_safe_pattern_matches(&pack, "rm -rf /tmp/test");
        assert_safe_pattern_matches(&pack, "rm -rf /var/tmp/stuff");
        assert_safe_pattern_matches(&pack, "rm -rf $TMPDIR/junk");
        assert_safe_pattern_matches(&pack, "rm -rf ${TMPDIR}/junk");
    }

    #[test]
    fn test_tmpdir_brace_requires_exact_var_name() {
        let pack = create_pack();
        assert!(!pack.matches_safe("rm -rf ${TMPDIR_NOT}/junk"));
        assert_rm_parser_denies(
            "rm -rf ${TMPDIR_NOT}/junk",
            RM_RF_GENERAL_NAME,
            Severity::High,
        );
    }

    #[test]
    fn test_safe_rm_variants() {
        let pack = create_pack();
        assert_safe_pattern_matches(&pack, "rm -fr /tmp/test");
        assert_safe_pattern_matches(&pack, "rm -r -f /tmp/test");
        assert_safe_pattern_matches(&pack, "rm --recursive --force /tmp/test");
    }

    #[test]
    fn test_path_traversal_blocked() {
        let pack = create_pack();
        // Should NOT match safe patterns (so it falls through to destructive)
        assert!(!pack.matches_safe("rm -rf /tmp/../etc"));
        assert!(!pack.matches_safe("rm -rf /var/tmp/../etc"));

        // And should be blocked by destructive rules
        assert_blocks(&pack, "rm -rf /tmp/../etc", "rm -rf on root or home paths");
    }

    fn assert_rm_parser_allows(command: &str) {
        let decision = parse_rm_command(command);
        assert!(
            matches!(decision, RmParseDecision::Allow),
            "Expected rm parser to allow '{command}', got {decision:?}",
        );
    }

    fn assert_rm_parser_denies(command: &str, expected_rule: &str, expected_severity: Severity) {
        match parse_rm_command(command) {
            RmParseDecision::Deny(hit) => {
                assert_eq!(
                    hit.pattern_name, expected_rule,
                    "Unexpected rule for '{command}'"
                );
                assert_eq!(
                    hit.severity, expected_severity,
                    "Unexpected severity for '{command}'"
                );
            }
            other => unreachable!("Expected rm parser to deny '{command}', got {other:?}"),
        }
    }

    fn assert_rm_parser_no_match(command: &str) {
        match parse_rm_command(command) {
            RmParseDecision::NoMatch => {}
            other => {
                unreachable!("Expected rm parser to return NoMatch for '{command}', got {other:?}")
            }
        }
    }

    #[test]
    fn test_rm_parser_allows_tmpdir_quotes() {
        assert_rm_parser_allows(r#"rm -rf "$TMPDIR/foo""#);
        assert_rm_parser_allows(r#"rm -rf "${TMPDIR}/foo""#);
        assert_rm_parser_denies(r"rm -rf '$TMPDIR/foo'", RM_RF_GENERAL_NAME, Severity::High);
        assert_rm_parser_denies(
            r#"rm -r -f "$TMPDIR/foo""#,
            RM_R_F_SEPARATE_NAME,
            Severity::High,
        );
        assert_rm_parser_denies(
            r#"rm -r -f "${TMPDIR}/foo""#,
            RM_R_F_SEPARATE_NAME,
            Severity::High,
        );
        assert_rm_parser_denies(
            r#"rm --recursive --force "$TMPDIR/foo""#,
            RM_RECURSIVE_FORCE_NAME,
            Severity::High,
        );
        assert_rm_parser_denies(
            r#"rm --recursive --force "${TMPDIR}/foo""#,
            RM_RECURSIVE_FORCE_NAME,
            Severity::High,
        );
        assert_rm_parser_denies(
            r#"rm --force --recursive "$TMPDIR/foo""#,
            RM_RECURSIVE_FORCE_NAME,
            Severity::High,
        );
        assert_rm_parser_denies(
            r#"rm --force --recursive "${TMPDIR}/foo""#,
            RM_RECURSIVE_FORCE_NAME,
            Severity::High,
        );
    }

    #[test]
    fn test_rm_parser_traversal_blocked() {
        assert_rm_parser_denies(
            "rm -rf /tmp/../etc",
            RM_RF_ROOT_HOME_NAME,
            Severity::Critical,
        );
    }

    #[test]
    fn test_rm_parser_option_terminator() {
        assert_rm_parser_no_match("rm -- -rf /tmp/safe");
    }
}
