#!/bin/bash
#
# Pack E2E Tests — transformate.secrets_emit
#
# Tests blocking/allowing behavior for the secret-emission guard pack.
# Pack covers v1.0.0 (8 patterns) + v1.1.0 (at-c-job-env-dump, proc-environ-read)
# + v1.3.0 (proc-cmdline-bulk, ps-argv-env-dump, pgrep-list-full — argv/env leak class,
#   transformate WI-750; each carries a --no-secrets-near legit-use escape).
#
# Usage:
#   ./scripts/test_pack_secrets_emit.sh [--verbose] [--binary PATH]

set -euo pipefail

PACK_NAME="transformate.secrets_emit"
PACK_KEYWORD="infisical"

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

VERBOSE=false
BINARY=""
TESTS_PASSED=0
TESTS_FAILED=0

while [[ $# -gt 0 ]]; do
    case $1 in
        --verbose|-v) VERBOSE=true; shift ;;
        --binary|-b) BINARY="$2"; shift 2 ;;
        *) echo "Unknown: $1"; exit 1 ;;
    esac
done

if [[ -z "$BINARY" ]]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    PROJECT_ROOT="$SCRIPT_DIR"
    while [[ "$PROJECT_ROOT" != "/" && ! -f "$PROJECT_ROOT/Cargo.toml" ]]; do
        PROJECT_ROOT="$(dirname "$PROJECT_ROOT")"
    done
    if [[ ! -f "$PROJECT_ROOT/Cargo.toml" ]]; then
        echo "Error: Could not locate project root (Cargo.toml not found)."
        exit 1
    fi
    if [[ -f "$PROJECT_ROOT/target/release/dcg" ]]; then
        BINARY="$PROJECT_ROOT/target/release/dcg"
    elif [[ -f "$PROJECT_ROOT/target/debug/dcg" ]]; then
        BINARY="$PROJECT_ROOT/target/debug/dcg"
    elif command -v dcg &>/dev/null; then
        BINARY="dcg"
    else
        echo "Error: dcg binary not found. Build with 'cargo build --release' or use --binary"
        exit 1
    fi
fi

if [[ -f "$BINARY" && "$BINARY" != /* ]]; then
    BINARY="$(cd "$(dirname "$BINARY")" && pwd)/$(basename "$BINARY")"
fi

json_escape() {
    local s="$1"
    s=${s//\\/\\\\}
    s=${s//\"/\\\"}
    s=${s//$'\n'/\\n}
    s=${s//$'\r'/\\r}
    s=${s//$'\t'/\\t}
    echo -n "$s"
}

test_cmd() {
    local cmd="$1"
    local expected="$2"
    local desc="$3"

    local escaped_cmd
    escaped_cmd=$(json_escape "$cmd")
    local json="{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"$escaped_cmd\"}}"

    local out
    out=$(echo -n "$json" | DCG_PACKS="$PACK_NAME" "$BINARY" 2>&1 || true)

    if [[ "$expected" == "block" ]]; then
        if echo "$out" | grep -q '"permissionDecision"' && echo "$out" | grep -q '"deny"'; then
            [[ "$VERBOSE" == "true" ]] && echo -e "${GREEN}PASS${NC} [BLOCK] $desc"
            TESTS_PASSED=$((TESTS_PASSED+1))
        else
            echo -e "${RED}FAIL${NC} [BLOCK] $desc"
            echo "  Expected block, got: $out"
            TESTS_FAILED=$((TESTS_FAILED+1))
        fi
    else
        if [[ -z "$out" ]] || ! echo "$out" | grep -q '"permissionDecision"'; then
            [[ "$VERBOSE" == "true" ]] && echo -e "${GREEN}PASS${NC} [ALLOW] $desc"
            TESTS_PASSED=$((TESTS_PASSED+1))
        else
            echo -e "${RED}FAIL${NC} [ALLOW] $desc"
            echo "  Expected allow, got: $out"
            TESTS_FAILED=$((TESTS_FAILED+1))
        fi
    fi
}

echo "Testing pack: $PACK_NAME"
echo "Binary: $BINARY"
echo "----------------------------------------"

# --- v1.0.0 patterns (regression coverage) ---

# infisical-secrets-bulk-print
test_cmd "infisical secrets" "block" "infisical bulk list (no args)"
test_cmd "infisical secrets --plain" "block" "infisical bulk --plain"
test_cmd "infisical secrets get FOO" "allow" "infisical single-key get"
test_cmd "infisical secrets get FOO --plain" "allow" "infisical single-key get --plain"
test_cmd "infisical run -- env" "allow" "infisical runtime injection"

# docker-inspect-config-env
test_cmd "docker inspect --format '{{.Config.Env}}' c" "block" "docker inspect Config.Env"
test_cmd "docker container inspect --format '{{.Config.Env}}' c" "block" "docker container inspect Config.Env"
test_cmd "docker exec my-c printenv FOO" "allow" "docker exec single var"

# printenv-bulk
test_cmd "printenv" "block" "bare printenv"
test_cmd "printenv | grep AWS" "block" "printenv piped to grep"
test_cmd "printenv VAR_NAME" "allow" "printenv single var"

# env-bulk-or-grep
test_cmd "env" "block" "bare env"
test_cmd "env|grep AWS" "block" "env|grep no-spaces"

# set-bulk-or-grep
test_cmd "set" "block" "bare set"
test_cmd "set | grep AWS" "block" "set | grep"

# cat-secret-file-extension
test_cmd "cat .env.local" "block" "cat .env.local"
test_cmd "cat foo.pem" "block" "cat .pem"

# cat-credential-file-path
test_cmd "cat ~/.aws/credentials" "block" "cat aws credentials"
test_cmd "cat ~/.netrc" "block" "cat netrc"

# safe doc files
test_cmd "cat README.md" "allow" "cat README is fine"
test_cmd "cat CHANGELOG.md" "allow" "cat CHANGELOG is fine"

# --- v1.1.0 patterns (new) ---

# at-c-job-env-dump (DENY)
test_cmd "at -c 1" "block" "at -c 1 (env dump)"
test_cmd "at -c 99" "block" "at -c 99"
test_cmd "at -c abc" "block" "at -c with non-numeric jobid"
test_cmd "/usr/bin/at -c 5" "block" "absolute-path at -c"

# at safe cases (ALLOW)
test_cmd "atq" "allow" "atq (list jobs)"
test_cmd "at -l" "allow" "at -l (alias of atq)"
test_cmd "at now + 5 min" "allow" "schedule at"
test_cmd "at -d 1" "allow" "at -d 1 (delete job)"

# proc-environ-read (DENY)
test_cmd "cat /proc/123/environ" "block" "cat /proc/<pid>/environ"
test_cmd "less /proc/9999/environ" "block" "less /proc/<pid>/environ"
test_cmd "head -c 4096 /proc/123/environ" "block" "head /proc/<pid>/environ"
test_cmd "tail /proc/123/environ" "block" "tail /proc/<pid>/environ"
test_cmd "xxd /proc/123/environ" "block" "xxd /proc/<pid>/environ"
test_cmd "od -c /proc/123/environ" "block" "od /proc/<pid>/environ"
test_cmd "hexdump /proc/123/environ" "block" "hexdump /proc/<pid>/environ"
test_cmd "strings /proc/123/environ" "block" "strings /proc/<pid>/environ"

# /proc safe cases (ALLOW)
test_cmd "cat /proc/cpuinfo" "allow" "cat /proc/cpuinfo"
test_cmd "cat /proc/version" "allow" "cat /proc/version"
test_cmd "cat /proc/meminfo" "allow" "cat /proc/meminfo"
test_cmd "cat /proc/loadavg" "allow" "cat /proc/loadavg"
test_cmd "head /proc/123/status" "allow" "head /proc/<pid>/status (not environ)"

# --- v1.3.0 patterns (new: proc-cmdline-bulk, ps-argv-env-dump, pgrep-list-full) ---

# proc-cmdline-bulk (DENY)
test_cmd "cat /proc/123/cmdline" "block" "cat /proc/<pid>/cmdline"
test_cmd "cat /proc/*/cmdline" "block" "cat /proc/*/cmdline glob"
test_cmd "head -c 200 /proc/456/cmdline" "block" "head /proc/<pid>/cmdline"
test_cmd "xxd /proc/1/cmdline" "block" "xxd /proc/<pid>/cmdline"
test_cmd "strings /proc/999/cmdline" "block" "strings /proc/<pid>/cmdline"
test_cmd "cat < /proc/999/cmdline" "block" "redirect read of /proc cmdline"
test_cmd "for p in /proc/*/cmdline; do cat \$p; done" "block" "glob loop over /proc/*/cmdline"
test_cmd "find /proc -maxdepth 2 -name cmdline -exec cat {} +" "block" "find /proc sweep for cmdline"
test_cmd "cat /proc/\$(pidof bash)/cmdline" "block" "command-subst pid /proc cmdline"
test_cmd "cat /proc/1/task/1/cmdline" "block" "thread task path cmdline"
test_cmd "cat /proc/self/task/2/cmdline" "block" "self task path cmdline"
test_cmd "cat /proc/./1/cmdline" "block" "dot-segment /proc cmdline"
test_cmd "cat /proc//1/cmdline" "block" "double-slash /proc cmdline"

# proc-cmdline safe cases (ALLOW)
test_cmd "cat /proc/123/status" "allow" "cat /proc/<pid>/status (not cmdline)"
test_cmd "cat /proc/self/comm" "allow" "cat /proc/self/comm"
test_cmd "cat /proc/cmdline" "allow" "kernel /proc/cmdline (boot args, no per-proc segment)"
test_cmd "find /proc -maxdepth 1 -name loadavg" "allow" "find /proc not-cmdline"
test_cmd "NO_SECRETS_NEAR=1 cat /proc/123/cmdline" "allow" "proc cmdline with NO_SECRETS_NEAR escape"

# ps-argv-env-dump (DENY)
test_cmd "ps e" "block" "ps e (env)"
test_cmd "ps ef" "block" "ps ef (env+forest)"
test_cmd "ps eww" "block" "ps eww (env wide)"
test_cmd "ps auxe" "block" "ps auxe (env)"
test_cmd "ps -ef" "block" "ps -ef (full listing)"
test_cmd "ps auxf" "block" "ps auxf (forest)"
test_cmd "ps auxww" "block" "ps auxww (wide)"
test_cmd "ps -A -o cmd" "block" "ps -A -o cmd (full argv)"
test_cmd "ps -p 1234 -o cmd=" "block" "ps -p PID -o cmd= (full argv)"
test_cmd "ps -eo args" "block" "ps -eo args (full argv)"
test_cmd "ps -o command" "block" "ps -o command (full argv)"
test_cmd "ps aux" "block" "ps aux (non-tty full argv)"
test_cmd "ps au" "block" "ps au (BSD full argv)"
test_cmd "ps ax" "block" "ps ax (BSD full argv)"
test_cmd "ps -f" "block" "ps -f (full-format argv)"
test_cmd "ps -F" "block" "ps -F (extra-full argv)"
test_cmd "ps -fww" "block" "ps -fww (full wide argv)"
test_cmd "ps --format=args" "block" "ps --format=args (long-opt argv)"
test_cmd "ps --format command" "block" "ps --format command (long-opt argv)"
test_cmd "ps -o CMD" "block" "ps -o CMD (case-fold argv)"
test_cmd "ps -eo ARGS" "block" "ps -eo ARGS (case-fold argv)"

# ps safe cases (ALLOW) — comm-column / process-selection forms
test_cmd "ps -e" "allow" "ps -e (all procs, comm column)"
test_cmd "ps -A" "allow" "ps -A (all procs, comm column)"
test_cmd "ps -p 1234" "allow" "ps -p PID (default cols)"
test_cmd "ps -o pid,comm" "allow" "ps -o pid,comm (short name)"
test_cmd "ps -ef --no-secrets-near" "allow" "ps -ef with --no-secrets-near escape"
test_cmd "NO_SECRETS_NEAR=1 ps aux" "allow" "ps aux with NO_SECRETS_NEAR escape"

# pgrep-list-full (DENY)
test_cmd "pgrep -af nginx" "block" "pgrep -af (full argv)"
test_cmd "pgrep -f nginx -a" "block" "pgrep -f ... -a (full argv)"
test_cmd "pgrep --list-full nginx" "block" "pgrep --list-full"

# pgrep safe cases (ALLOW)
test_cmd "pgrep -f nginx" "allow" "pgrep -f (PIDs only)"
test_cmd "pgrep nginx" "allow" "pgrep bare (PIDs only)"
test_cmd "pgrep -c nginx" "allow" "pgrep -c (count only)"
test_cmd "NO_SECRETS_NEAR=1 pgrep -af nginx" "allow" "pgrep -af with NO_SECRETS_NEAR escape"

# escape must be a token (env-assign at cmd start / bounded flag), NOT a bare substring
# (panel R1 critical: `pgrep -af NO_SECRETS_NEAR` must still BLOCK)
test_cmd "pgrep -af NO_SECRETS_NEAR" "block" "escape token as search arg still blocks"
test_cmd "cat /proc/1/cmdline /tmp/NO_SECRETS_NEAR/x" "block" "escape token in decoy path still blocks"
test_cmd "pgrep -af NO_SECRETS_NEAR=1" "block" "escape= in arg position still blocks"
test_cmd "foo; NO_SECRETS_NEAR=1 pgrep -af nginx" "allow" "escape env-assign after ; allows"

echo "----------------------------------------"
echo "Tests Passed: $TESTS_PASSED"
echo "Tests Failed: $TESTS_FAILED"

if [[ $TESTS_FAILED -gt 0 ]]; then
    exit 1
else
    exit 0
fi
