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
        check("blank code passes through", out.get("continue") is True and seen is None)
        # An EMPTY payload on a guarded tool is a truncated or malformed invocation, not a
        # deliberate no-op, and the README decision table denies it. It used to be allowed.
        out, seen = run(PLUGIN + "ctx_execute", {}, tmp)
        check("empty tool_input is denied",
              out.get("hookSpecificOutput", {}).get("permissionDecision") == "deny")
        check("empty tool_input never reached dcg", seen is None)

        # 5b. Suffix matching is a SUFFIX match. A name that merely CONTAINS a guarded token
        #     but carries trailing characters is a different tool and must pass through.
        out, seen = run(PLUGIN + "ctx_execute_status", {"code": "cat /tmp/probe.env"}, tmp)
        check("a guarded token with trailing characters is NOT treated as guarded",
              out.get("continue") is True and seen is None)

        # 5c. Depth overflow must DENY, not silently scan the shallow part. The shallow value
        #     here is benign; the dangerous one is buried below the extraction ceiling.
        deep = {"label": "benign"}
        node = deep
        for _ in range(20):
            node["next"] = {}
            node = node["next"]
        node["code"] = "cat /tmp/probe.env"
        out, seen = run(PLUGIN + "ctx_execute", deep, tmp)
        check("a payload nested past the extraction ceiling is denied",
              out.get("hookSpecificOutput", {}).get("permissionDecision") == "deny")
        check("an over-deep payload is never scanned in part", seen is None)

        # 5d. Valid JSON is not a decision. A diagnostic envelope carries no verdict, so
        #     forwarding it reads to the host as no objection.
        for label, body in (
            ("an error envelope", "print(json.dumps({'error': {'msg': 'boom'}}))"),
            ("a bare empty object", "print(json.dumps({}))"),
            ("an unrelated object", "print(json.dumps({'ok': True}))"),
            ("a JSON array", "print(json.dumps([1, 2, 3]))"),
        ):
            envelope = os.path.join(tmp, "envelope")
            with open(envelope, "w") as fh:
                fh.write("#!/usr/bin/env python3\nimport json\n" + body + "\n")
            os.chmod(envelope, 0o755)
            proc = subprocess.run(
                [sys.executable, WRAP],
                input=json.dumps({"tool_name": PLUGIN + "ctx_execute",
                                  "tool_input": {"code": "cat /tmp/probe.env"}}),
                capture_output=True, text=True,
                env=dict(os.environ, DCG_WRAP_BIN=envelope), timeout=20,
            )
            try:
                out = json.loads(proc.stdout)
            except ValueError:
                out = {}
            check(f"scanner returning {label} DENIES",
                  out.get("hookSpecificOutput", {}).get("permissionDecision") == "deny")

        # 5e. A genuine `{"continue": true}` allow from the scanner still passes through.
        allower = os.path.join(tmp, "allower")
        with open(allower, "w") as fh:
            fh.write("#!/usr/bin/env python3\nimport json\nprint(json.dumps({'continue': True}))\n")
        os.chmod(allower, 0o755)
        proc = subprocess.run(
            [sys.executable, WRAP],
            input=json.dumps({"tool_name": PLUGIN + "ctx_execute",
                              "tool_input": {"code": "echo hello"}}),
            capture_output=True, text=True,
            env=dict(os.environ, DCG_WRAP_BIN=allower), timeout=20,
        )
        check("a genuine continue:true allow is passed through",
              json.loads(proc.stdout).get("continue") is True)

        # ── Fail-CLOSED paths. Without these the suite stays green through exactly the
        # regressions the fail-open contract used to permit. ──

        # 6. SHAPE DRIFT. The harness renamed the tools once already (WI-2096); the next
        #    rename may be of the FIELD. A guarded call whose code sits under an unknown
        #    key must still be scanned, not silently extracted to nothing.
        out, seen = run(PLUGIN + "ctx_execute", {"script": "cat /tmp/probe.env"}, tmp)
        check("renamed code field is still scanned",
              seen is not None and "cat /tmp/probe.env" in seen)
        check("renamed code field is guarded",
              out.get("hookSpecificOutput", {}).get("permissionDecision") == "deny")

        # 7. A guarded payload with NO strings anywhere is a shape we do not understand.
        out, seen = run(PLUGIN + "ctx_execute", {"timeout": 30}, tmp)
        check("guarded call with no string fields is denied",
              out.get("hookSpecificOutput", {}).get("permissionDecision") == "deny")
        check("guarded call with no string fields never reached dcg", seen is None)

        # 8. A guarded call with a non-object tool_input is denied.
        out, _ = run(PLUGIN + "ctx_execute", ["cat /tmp/probe.env"], tmp)
        check("guarded call with non-object tool_input is denied",
              out.get("hookSpecificOutput", {}).get("permissionDecision") == "deny")

        # 9. SCANNER UNAVAILABLE. This is the one that mattered most: dcg-ctx-wrap is the
        #    only path from the ctx tools into dcg, so allowing here reopens the 2026-05-15
        #    channel. Probed live in adjudication: this used to emit continue:true, exit 0.
        env = dict(os.environ, DCG_WRAP_BIN=os.path.join(tmp, "does-not-exist"))
        proc = subprocess.run(
            [sys.executable, WRAP],
            input=json.dumps({"tool_name": PLUGIN + "ctx_execute",
                              "tool_input": {"code": "cat /tmp/probe.env"}}),
            capture_output=True, text=True, env=env, timeout=20,
        )
        out = json.loads(proc.stdout)
        check("missing scanner binary DENIES (does not fail open)",
              out.get("hookSpecificOutput", {}).get("permissionDecision") == "deny")

        # 10. SCANNER PRODUCES NO DECISION. subprocess.run does not raise on a non-zero
        #     child exit, so a crash used to be forwarded as whatever was on stdout.
        for label, body, mode in (
            ("crashes with empty stdout", "import sys; sys.exit(3)", 0o755),
            ("exits 0 with unparseable stdout", "print('not json')", 0o755),
            ("exits non-zero with unparseable stdout",
             "import sys; print('boom'); sys.exit(1)", 0o755),
        ):
            broken = os.path.join(tmp, "broken")
            with open(broken, "w") as fh:
                fh.write("#!/usr/bin/env python3\n" + body + "\n")
            os.chmod(broken, mode)
            proc = subprocess.run(
                [sys.executable, WRAP],
                input=json.dumps({"tool_name": PLUGIN + "ctx_execute",
                                  "tool_input": {"code": "cat /tmp/probe.env"}}),
                capture_output=True, text=True,
                env=dict(os.environ, DCG_WRAP_BIN=broken), timeout=20,
            )
            try:
                out = json.loads(proc.stdout)
            except ValueError:
                out = {}
            check(f"scanner that {label} DENIES",
                  out.get("hookSpecificOutput", {}).get("permissionDecision") == "deny")

        # 11. A parseable decision passes through with its exit status intact — dcg-wrap
        #     signals a block with exit 2 and rewriting that would mask its DENY.
        deny2 = os.path.join(tmp, "deny2")
        with open(deny2, "w") as fh:
            fh.write("#!/usr/bin/env python3\n"
                     "import json,sys\n"
                     "print(json.dumps({'hookSpecificOutput':{'permissionDecision':'deny'}}))\n"
                     "sys.exit(2)\n")
        os.chmod(deny2, 0o755)
        proc = subprocess.run(
            [sys.executable, WRAP],
            input=json.dumps({"tool_name": PLUGIN + "ctx_execute",
                              "tool_input": {"code": "cat /tmp/probe.env"}}),
            capture_output=True, text=True,
            env=dict(os.environ, DCG_WRAP_BIN=deny2), timeout=20,
        )
        check("exit-2 deny is passed through unchanged", proc.returncode == 2)
        check("exit-2 deny keeps its decision",
              json.loads(proc.stdout).get(
                  "hookSpecificOutput", {}).get("permissionDecision") == "deny")

    if failures:
        for f in failures:
            print(f"FAIL: {f}")
        sys.exit(1)
    print("ok — dcg-ctx-wrap routing + extraction assertions passed")


if __name__ == "__main__":
    main()
