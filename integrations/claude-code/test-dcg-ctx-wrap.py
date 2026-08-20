#!/usr/bin/env python3
"""Self-check for dcg-ctx-wrap's routing + payload extraction (transformate WI-2096).

The bug this pins: dcg-ctx-wrap keyed its guarded set to the LEGACY tool names,
so the live plugin-prefixed names fell through to fail_open() — an unguarded
shell channel. These assertions FAIL if that regresses.

No network, no secrets, no real dcg: DCG_WRAP_BIN points at a stub that records
the synthetic Bash payload it was handed and returns a DENY decision.

Run: python3 integrations/claude-code/test-dcg-ctx-wrap.py   (exit 0 = pass)
"""

import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
WRAP = os.path.join(HERE, "dcg-ctx-wrap")

STUB = """#!/usr/bin/env python3
import json, os, sys
payload = sys.stdin.read()
open(os.environ["STUB_RECORD"], "w").write(payload)
print(json.dumps({"hookSpecificOutput": {"permissionDecision": "deny"}}))
"""

PLUGIN = "mcp__plugin_context-mode_context-mode__"
LEGACY = "mcp__context-mode__"


def run(tool_name, tool_input, tmp):
    """Invoke the wrapper; return (decision_json, payload_seen_by_dcg_or_None)."""
    record = os.path.join(tmp, "record.json")
    env = dict(os.environ, DCG_WRAP_BIN=os.path.join(tmp, "stub"), STUB_RECORD=record)
    proc = subprocess.run(
        [sys.executable, WRAP],
        input=json.dumps({"tool_name": tool_name, "tool_input": tool_input}),
        capture_output=True, text=True, env=env, timeout=20,
    )
    seen = open(record).read() if os.path.exists(record) else None
    if os.path.exists(record):
        os.remove(record)
    return json.loads(proc.stdout), seen


def main():
    failures = []

    def check(desc, cond):
        if not cond:
            failures.append(desc)

    with tempfile.TemporaryDirectory() as tmp:
        stub = os.path.join(tmp, "stub")
        with open(stub, "w") as fh:
            fh.write(STUB)
        os.chmod(stub, 0o755)

        # 1. Every live plugin-prefixed exec tool must reach dcg and DENY.
        #    This is the WI-2096 gap: these used to fail_open().
        for tool in ("ctx_execute", "ctx_execute_file"):
            out, seen = run(PLUGIN + tool, {"code": "cat /tmp/probe.env", "language": "shell"}, tmp)
            check(f"{tool}: plugin-prefixed name is guarded",
                  out.get("hookSpecificOutput", {}).get("permissionDecision") == "deny")
            check(f"{tool}: code text reached dcg",
                  seen is not None and "cat /tmp/probe.env" in seen)

        # 2. ctx_batch_execute carries commands[].command, not `code` — every
        #    command must be scanned, including one buried mid-array.
        batch = {"commands": [
            {"label": "benign", "command": "echo hello"},
            {"label": "trigger", "command": "cat /tmp/probe.env"},
        ]}
        out, seen = run(PLUGIN + "ctx_batch_execute", batch, tmp)
        check("batch: guarded", out.get("hookSpecificOutput", {}).get("permissionDecision") == "deny")
        check("batch: non-first command reached dcg", seen and "cat /tmp/probe.env" in seen)
        check("batch: first command reached dcg too", seen and "echo hello" in seen)

        # 3. The legacy names still work — a stale caller must not go unguarded.
        out, _ = run(LEGACY + "ctx_execute", {"code": "cat /tmp/probe.env"}, tmp)
        check("legacy name still guarded",
              out.get("hookSpecificOutput", {}).get("permissionDecision") == "deny")

        # 4. A future rename must fail CLOSED on the suffix, not open.
        out, _ = run("mcp__someNewPrefix__context-mode__ctx_batch_execute", batch, tmp)
        check("unknown prefix + known suffix still guarded",
              out.get("hookSpecificOutput", {}).get("permissionDecision") == "deny")

        # 5. Unrelated tools and empty payloads pass through untouched.
        out, seen = run("Read", {"file_path": "/etc/hosts"}, tmp)
        check("unrelated tool passes through", out.get("continue") is True and seen is None)
        out, seen = run(PLUGIN + "ctx_execute", {"code": "   "}, tmp)
        check("empty code passes through", out.get("continue") is True and seen is None)

    if failures:
        for f in failures:
            print(f"FAIL: {f}")
        sys.exit(1)
    print("ok — dcg-ctx-wrap routing + extraction assertions passed")


if __name__ == "__main__":
    main()
