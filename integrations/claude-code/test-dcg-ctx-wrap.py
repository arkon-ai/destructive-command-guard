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
print(json.dumps({"hookSpecificOutput": {
    "hookEventName": "PreToolUse", "permissionDecision": "deny"}}))
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
    return _with_exit(json.loads(proc.stdout), proc.returncode), seen


def run_raw(raw, tmp):
    """Invoke the wrapper with EXACT stdin bytes; return (decision, payload_seen_or_None).

    The identification probes need documents `run()` cannot express: malformed JSON, and
    payloads nested past the parser's ceiling — which json.dumps cannot build either,
    because the encoder recurses on the same structure the decoder does.
    """
    record = os.path.join(tmp, "record.json")
    if os.path.exists(record):
        os.remove(record)
    env = dict(os.environ, DCG_WRAP_BIN=os.path.join(tmp, "stub"), STUB_RECORD=record)
    proc = subprocess.run([sys.executable, WRAP], input=raw, capture_output=True,
                          text=True, env=env, timeout=180)
    seen = open(record).read() if os.path.exists(record) else None
    if os.path.exists(record):
        os.remove(record)
    try:
        return _with_exit(json.loads(proc.stdout), proc.returncode), seen
    except ValueError:
        return _with_exit({}, proc.returncode), seen


def run_raw_bytes(raw_bytes, tmp, extra_env=None):
    """Invoke the wrapper with EXACT stdin BYTES, plus an optional env overlay.

    `run` and `run_raw` both use text=True, so neither can express a payload that is not
    decodable under the child's stdin codec — which is precisely the input that used to walk
    straight past identification into `except Exception: allow()`.
    """
    record = os.path.join(tmp, "record.json")
    if os.path.exists(record):
        os.remove(record)
    env = dict(os.environ, DCG_WRAP_BIN=os.path.join(tmp, "stub"), STUB_RECORD=record)
    env.update(extra_env or {})
    proc = subprocess.run([sys.executable, WRAP], input=raw_bytes,
                          capture_output=True, env=env, timeout=60)
    seen = open(record).read() if os.path.exists(record) else None
    if os.path.exists(record):
        os.remove(record)
    try:
        return _with_exit(json.loads(proc.stdout.decode("utf-8", "replace")),
                          proc.returncode), seen
    except ValueError:
        return _with_exit({}, proc.returncode), seen


def seen_command(seen):
    """The command dcg actually received — NOT a substring of the raw stdin blob.

    `trigger in seen` passes if the trigger lands in ANY field, including one dcg-wrap
    never reads (`_dcg_source_tool`, a sibling key, a second copy beside an empty
    `command`). That is the transformate WI-2096 failure one layer down: suite green, the
    command field empty, channel open. So parse it and read the field that is scanned.
    """
    if not seen:
        return ""
    try:
        payload = json.loads(seen)
    except ValueError:
        return ""
    if payload.get("tool_name") != "Bash":
        return ""
    ti = payload.get("tool_input")
    return ti.get("command", "") if isinstance(ti, dict) else ""


def _with_exit(out, code):
    """Carry the process EXIT STATUS on the parsed decision.

    The host acts on the status as well as the document: it honours 2 as a blocking error,
    and treats every OTHER non-zero as non-blocking and runs the guarded call anyway. Every
    assertion in this file used to read the document alone, so two one-line mutations of the
    adapter left the suite at 0 FAILs: deny() exiting 3 (the denial is printed and the call
    proceeds, reopening the 2026-05-15 channel) and allow() exiting 2 (every BENIGN guarded
    call is blocked and all three ctx tools go offline, which test 12's own header records
    as having already happened once). Carried on a private key so no call site has to thread
    an extra tuple element.
    """
    if isinstance(out, dict):
        out["__exit"] = code
    return out


# The adapter exits 0 for both allow() and deny(), and normalises a pass-through to 2 only
# when the scanner itself exited 2. {0, 2} is the whole legal set, and it is the same set
# the applier's canary 3 refuses to certify outside of.
HOST_HONOURED_EXITS = (0, 2)


def denied(out):
    # A denial the host DISCARDS is not a denial.
    return (out.get("hookSpecificOutput", {}).get("permissionDecision") == "deny"
            and out.get("__exit") in HOST_HONOURED_EXITS)


def allowed(out):
    # Not symmetric decoration: an allow delivered on exit 2 blocks the call it just allowed.
    return out.get("continue") is True and out.get("__exit") == 0


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
                  denied(out))
            check(f"{tool}: code reached dcg as tool_input.command",
                  "cat /tmp/probe.env" in seen_command(seen))

        # 2. ctx_batch_execute carries commands[].command, not `code` — every
        #    command must be scanned, including one buried mid-array.
        batch = {"commands": [
            {"label": "benign", "command": "echo hello"},
            {"label": "trigger", "command": "cat /tmp/probe.env"},
        ]}
        out, seen = run(PLUGIN + "ctx_batch_execute", batch, tmp)
        check("batch: guarded", denied(out))
        check("batch: non-first command reached dcg",
              "cat /tmp/probe.env" in seen_command(seen))
        check("batch: first command reached dcg too", "echo hello" in seen_command(seen))

        # 3. The legacy names still work — a stale caller must not go unguarded.
        out, _ = run(LEGACY + "ctx_execute", {"code": "cat /tmp/probe.env"}, tmp)
        check("legacy name still guarded",
              denied(out))

        # 4. A future rename must fail CLOSED on the suffix, not open.
        out, _ = run("mcp__someNewPrefix__context-mode__ctx_batch_execute", batch, tmp)
        check("unknown prefix + known suffix still guarded",
              denied(out))

        # 5. Unrelated tools and empty payloads pass through untouched.
        out, seen = run("Read", {"file_path": "/etc/hosts"}, tmp)
        check("unrelated tool passes through", allowed(out) and seen is None)
        out, seen = run(PLUGIN + "ctx_execute", {"code": "   "}, tmp)
        check("blank code passes through", allowed(out) and seen is None)

        # 5a. A BLANK KNOWN FIELD COMPOSED WITH A DANGEROUS SIBLING.
        #
        # Test 5 above pins a blank `code` with NO sibling; test 6 below pins an unknown
        # `script` field when `code` is ABSENT. Nothing composed the two, and that gap admits
        # an ALLOW on a guarded call: a one-line short-circuit
        #
        #     if isinstance(ti.get("code"), str) and not ti["code"].strip(): allow()
        #
        # inserted before collect_strings left this suite at rc 0 / 0 FAILs while the payload
        # below returned {"continue": true} and dcg saw NOTHING. The shipped adapter is correct
        # - collect_strings walks every value and joins the non-blank ones - but nothing here
        # held it to that, which is the whole point of the pin.
        #
        # Both orderings, because a field-keyed short-circuit can key on either name, and the
        # sibling assertion reads what dcg ACTUALLY RECEIVED rather than the decision alone.
        for blank_key, sibling_key in (("code", "script"), ("command", "code"),
                                       ("code", "commands")):
            out, seen = run(PLUGIN + "ctx_execute",
                            {blank_key: "   ",
                             sibling_key: "git reset --hard origin/main"}, tmp)
            check(f"blank {blank_key} beside a dangerous {sibling_key} is DENIED", denied(out))
            check(f"blank {blank_key} beside a dangerous {sibling_key} reached dcg",
                  seen is not None and "git reset --hard origin/main" in seen_command(seen))
        # An EMPTY payload on a guarded tool is a truncated or malformed invocation, not a
        # deliberate no-op, and the README decision table denies it. It used to be allowed.
        out, seen = run(PLUGIN + "ctx_execute", {}, tmp)
        check("empty tool_input is denied",
              denied(out))
        check("empty tool_input never reached dcg", seen is None)

        # 5b. A name carrying a guarded token plus TRAILING characters must still be guarded.
        #     This pins the reverted `endswith` remedy as forbidden: the settings matcher is
        #     unanchored, so the harness really does route these here, and right-anchoring the
        #     check let them through with the scanner never invoked while the host believed the
        #     surface was covered — the WI-2096 fail-open, reintroduced by its own "fix".
        for variant in ("ctx_execute_v2", "ctx_execute2", "ctx_batch_execute_v2"):
            out, seen = run(PLUGIN + variant, {"code": "cat /tmp/probe.env"}, tmp)
            check(f"{variant}: a decorated guarded name is still guarded",
                  denied(out))
            check(f"{variant}: its code reached dcg",
                  "cat /tmp/probe.env" in seen_command(seen))

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
              denied(out))
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
                out = _with_exit(json.loads(proc.stdout), proc.returncode)
            except ValueError:
                out = {}
            # denied(), not a bare document read: tests 5d, 9 and 10 built their own
            # subprocess call and asserted the envelope alone, so a deny emitted on an exit
            # status the host DISCARDS certified green. G-15 measured it on the branch that
            # test 9 calls "the one that mattered most": deny envelope + sys.exit(1) -> 0 FAILs.
            check(f"scanner returning {label} DENIES", denied(out))

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
              allowed(_with_exit(json.loads(proc.stdout), proc.returncode)))

        # 5f. IDENTIFICATION IS PART OF THE FAIL-CLOSED CONTRACT.
        #     Every rule below is conditioned on the call having been IDENTIFIED as
        #     guarded first, so an attacker never had to beat the contract — only to stop
        #     it applying. Each case here returned continue:true with the scanner NEVER
        #     invoked, reopening the 2026-05-15 channel through the one path the contract
        #     blesses as ALLOW. `seen is None` is load-bearing in every one: it is what
        #     distinguishes "refused" from "scanned and happened to deny".
        def guarded_deep(n):
            """A guarded ctx_execute call with a sibling field nested n levels deep."""
            return ('{"tool_name": "' + PLUGIN + 'ctx_execute", "tool_input": '
                    '{"code": "cat /tmp/probe.env", "pad": ' + "[" * n + "]" * n + "}}")

        # json.loads RECURSES, so deep nesting ANYWHERE raises RecursionError — an
        # Exception, which the parse guard caught and turned into allow(). MAX_DEPTH does
        # not help; it applies inside collect_strings, AFTER the parse.
        #
        # READ THIS BEFORE TRUSTING A GREEN RUN: the depth at which the parser gives up is
        # INTERPRETER-DEPENDENT — measured on the parent commit at ~1100 (3.11.15), ~10000
        # (3.12.3, TEAM-1's) and ~20000 (3.14.3). So on a newer interpreter the 1200/2000
        # cases pass on the OLD code too, via the depth ceiling, and only the last one is a
        # negative control everywhere. Do not read 1200/2000 passing as proof the recursion
        # hole is shut; 200000 is the case that proves it on any interpreter.
        for depth in (1200, 2000, 200000):
            out, seen = run_raw(guarded_deep(depth), tmp)
            check(f"depth {depth}: a guarded call the parser cannot read is denied",
                  denied(out))
            check(f"depth {depth}: it never reached dcg", seen is None)

        # SELF-CHECK ON THAT CONTROL. It only exercises the identification arm while its
        # depth actually defeats this interpreter's parser — so assert the mechanism, not
        # just the outcome, or the day a CPython parses 200000 levels this quietly stops
        # being a control and the suite stays green over the hole.
        #
        # It cannot be made interpreter-independent by lowering sys.setrecursionlimit: the
        # json C scanner's ceiling is a C-STACK limit that setrecursionlimit does not
        # govern. Measured on 3.12.3 — with the limit at 150 a 400-level document still
        # parsed fine. If this check fails, RAISE THE DEPTH; do not delete the control.
        out, _ = run_raw(guarded_deep(200000), tmp)
        check("the deep control still reaches the PARSE-failure arm on this interpreter",
              "did not parse" in out.get(
                  "hookSpecificOutput", {}).get("permissionDecisionReason", ""))

        # A NON-STRING tool_name took the same exit, on every interpreter and at any
        # payload size — no adversarial construction needed at all.
        for label, name in (("list", [PLUGIN + "ctx_execute"]),
                            ("dict", {"n": PLUGIN + "ctx_execute"}),
                            ("int", 12345)):
            out, seen = run_raw(json.dumps(
                {"tool_name": name, "tool_input": {"code": "cat /tmp/probe.env"}}), tmp)
            if label == "int":
                # Nothing in these bytes names a guarded tool, so this one is genuinely
                # unattributable and MUST still allow — the pin that the refusal keys on
                # evidence, not merely on tool_name being the wrong type.
                check("non-string tool_name with no guarded token in stdin still allows",
                      allowed(out) and seen is None)
            else:
                check(f"tool_name as a {label} is denied, not allowed", denied(out))
                check(f"tool_name as a {label} never reached dcg", seen is None)

        # `toolName` is a fallback for an ABSENT tool_name only. If a corrupt-typed
        # tool_name could be overridden by a benign `toolName`, a guarded call would park
        # the real name in one field and a decoy in the other.
        out, seen = run_raw(json.dumps({"tool_name": [PLUGIN + "ctx_execute"],
                                        "toolName": "Read",
                                        "tool_input": {"code": "cat /tmp/probe.env"}}), tmp)
        check("a benign toolName cannot launder a corrupt-typed tool_name", denied(out))

        # Truncated JSON that still names a guarded tool.
        out, seen = run_raw('{"tool_name": "' + PLUGIN + 'ctx_execute", "tool_input": '
                            '{"code": "cat /tmp/probe.env"', tmp)
        check("unparseable stdin naming a guarded tool is denied", denied(out))

        # The token \u-escaped so it is not literally in the bytes, in a document deep
        # enough that the parse never resolves the escape.
        # THREE different \\u spellings of the same token, not one. A single case can be
        # satisfied by a rewrite of that exact escape: G-14 measured the mutant
        #     decoded = raw.replace("\\\\u0065", "e")
        # keeping this suite at 0 FAILs while every OTHER encoding of the token became
        # unattributable and fell through to allow() - the identification bypass reopened on
        # the raw-bytes path this block exists to close, with no signal. Escaping the FIRST
        # character is what kills that mutant.
        for spelling in ('ctx_ex\\u0065cute', '\\u0063tx_execute', 'ctx_execut\\u0065'):
            out, seen = run_raw('{"tool_name": "' + PLUGIN + spelling + '", "tool_input": '
                                '{"pad": ' + "[" * 200000 + "]" * 200000 + "}}", tmp)
            check("a "+spelling+" guarded token in unparseable stdin is denied", denied(out))

        # ---- and the ALLOW side, which the refusal above must not swallow ----
        # These are why the check reads the RAW BYTES rather than simply denying whatever
        # it cannot parse: genuine "cannot attribute" input must still pass.
        out, seen = run_raw('{"tool_name": "Read", "tool_input": {"file_path": "/etc/hosts"',
                            tmp)
        check("unparseable stdin naming NO guarded tool still allows",
              allowed(out) and seen is None)
        out, seen = run_raw('{"tool_name": "Read", "tool_input": {"pad": '
                            + "[" * 200000 + "]" * 200000 + "}}", tmp)
        check("an over-deep NON-ctx payload still allows",
              allowed(out) and seen is None)
        # The decisive false-positive pin: identification SUCCEEDS here (it is Bash), so
        # the raw-bytes check must never be consulted. If it were an override rather than a
        # tie-breaker, every Bash call discussing these tools would be blocked.
        out, seen = run_raw(json.dumps(
            {"tool_name": "Bash",
             "tool_input": {"command": "echo " + PLUGIN + "ctx_execute"}}), tmp)
        check("a Bash call whose TEXT names a ctx tool is still allowed",
              allowed(out) and seen is None)

        # ── Fail-CLOSED paths. Without these the suite stays green through exactly the
        # regressions the fail-open contract used to permit. ──

        # 6. SHAPE DRIFT. The harness renamed the tools once already (WI-2096); the next
        #    rename may be of the FIELD. A guarded call whose code sits under an unknown
        #    key must still be scanned, not silently extracted to nothing.
        out, seen = run(PLUGIN + "ctx_execute", {"script": "cat /tmp/probe.env"}, tmp)
        check("renamed code field is still scanned",
              "cat /tmp/probe.env" in seen_command(seen))
        check("renamed code field is guarded",
              denied(out))

        # 7. A guarded payload with NO strings anywhere is a shape we do not understand.
        out, seen = run(PLUGIN + "ctx_execute", {"timeout": 30}, tmp)
        check("guarded call with no string fields is denied",
              denied(out))
        check("guarded call with no string fields never reached dcg", seen is None)

        # 8. A guarded call with a non-object tool_input is denied.
        out, _ = run(PLUGIN + "ctx_execute", ["cat /tmp/probe.env"], tmp)
        check("guarded call with non-object tool_input is denied",
              denied(out))

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
        out = _with_exit(json.loads(proc.stdout), proc.returncode)
        check("missing scanner binary DENIES (does not fail open)", denied(out))

        # 10. SCANNER PRODUCES NO DECISION. subprocess.run does not raise on a non-zero
        #     child exit, so a crash used to be forwarded as whatever was on stdout.
        for label, body, mode in (
            ("crashes with empty stdout", "import sys; sys.exit(3)", 0o755),
            ("exits 0 with unparseable stdout", "print('not json')", 0o755),
            ("exits non-zero with unparseable stdout",
             "import sys; print('boom'); sys.exit(1)", 0o755),
            # THE MODE AXIS. Every fixture above is 0o755, and test 9 pins only the MISSING
            # binary, so the scanner-failure handler was exercised on exactly one exception
            # type. Splitting its single `except Exception` into
            #     except FileNotFoundError: deny(...)   /   except Exception: allow()
            # left this suite at rc 0 / 0 FAILs while a scanner that EXISTS at mode 0644 -
            # a bad cp, a mode drift, a package shipping 0644 - turned every guarded ctx
            # call into an ALLOW. This row is the difference between "the handler denies"
            # and "the handler denies for the one reason anyone tested".
            ("exists but is not executable", "print('never runs')", 0o644),
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
                out = _with_exit(json.loads(proc.stdout), proc.returncode)
            except ValueError:
                out = {}
            check(f"scanner that {label} DENIES", denied(out))

        # 10a. THE SAME HANDLER, THE OTHER SHAPE THAT IS NOT FileNotFoundError: a scanner
        #      path that resolves to a DIRECTORY. Raises IsADirectoryError (or
        #      PermissionError, platform and mode dependent), never FileNotFoundError, so a
        #      handler narrowed to the missing-binary case walks past it into allow().
        scanner_dir = os.path.join(tmp, "scanner-is-a-directory")
        os.makedirs(scanner_dir, exist_ok=True)
        proc = subprocess.run(
            [sys.executable, WRAP],
            input=json.dumps({"tool_name": PLUGIN + "ctx_execute",
                              "tool_input": {"code": "cat /tmp/probe.env"}}),
            capture_output=True, text=True,
            env=dict(os.environ, DCG_WRAP_BIN=scanner_dir), timeout=20,
        )
        try:
            out = _with_exit(json.loads(proc.stdout), proc.returncode)
        except ValueError:
            out = {}
        check("a scanner path that is a DIRECTORY denies", denied(out))
        check("a scanner path that is a DIRECTORY is not quietly allowed",
              out.get("continue") is not True)

        # 11. A parseable decision passes through with its exit status intact — dcg-wrap
        #     signals a block with exit 2 and rewriting that would mask its DENY.
        deny2 = os.path.join(tmp, "deny2")
        with open(deny2, "w") as fh:
            fh.write("#!/usr/bin/env python3\n"
                     "import json,sys\n"
                     "print(json.dumps({'hookSpecificOutput':{'hookEventName':'PreToolUse',"
                     "'permissionDecision':'deny'}}))\n"
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
              denied(_with_exit(json.loads(proc.stdout), proc.returncode)))


        # 12. HOW THE REAL SCANNER SPEAKS — pinned against dcg's measured behaviour, not
        #     against the stub's. dcg emits an envelope ONLY when it objects: a benign
        #     command returns exit 0 and ZERO bytes. Reading that as "no decision" denied
        #     every benign guarded call, i.e. took all three ctx tools offline on any host
        #     with the real scanner — and this suite stayed green through it, because every
        #     stub above always prints something. That is a test oracle that never modelled
        #     the thing it stands in for.
        def with_scanner(body, payload=None, mode=0o755):
            """Run a guarded call against a scanner stub with the given body."""
            binp = os.path.join(tmp, "shaped")
            with open(binp, "w") as fh:
                fh.write("#!/usr/bin/env python3\n" + body + "\n")
            os.chmod(binp, mode)
            proc = subprocess.run(
                [sys.executable, WRAP],
                input=json.dumps(payload or {"tool_name": PLUGIN + "ctx_execute",
                                             "tool_input": {"code": "echo hello"}}),
                capture_output=True, text=True,
                env=dict(os.environ, DCG_WRAP_BIN=binp), timeout=60)
            try:
                return _with_exit(json.loads(proc.stdout), proc.returncode), proc.returncode
            except ValueError:
                return _with_exit({}, proc.returncode), proc.returncode

        out, _ = with_scanner("import sys; sys.exit(0)")
        check("a scanner that exits 0 saying NOTHING is an ALLOW (this is dcg's allow)",
              allowed(out))

        out, _ = with_scanner("import sys; sys.exit(3)")
        check("a scanner that exits NON-ZERO saying nothing is a DENY, not an allow",
              denied(out))

        # sol: the host keys on hookEventName, so an envelope without it may be ignored —
        # and an ignored decision is no decision. The real dcg always sends it.
        #
        # Asserting only `denied(out)` here would NOT discriminate: a forwarded malformed
        # deny and an adapter-generated deny both read as "deny". The question is WHOSE
        # envelope reaches the host, so assert the adapter replaced it with a well-formed
        # one — and use an ALLOW envelope for the sharp case, where forwarding versus
        # replacing changes the verdict itself rather than only its provenance.
        def adapter_sourced(o):
            hso = o.get("hookSpecificOutput", {})
            return (hso.get("hookEventName") == "PreToolUse"
                    and str(hso.get("permissionDecisionReason", "")).startswith("dcg-ctx-wrap:"))

        for label, envelope in (
            ("missing hookEventName", "{'permissionDecision':'deny'}"),
            ("a different hook event", "{'hookEventName':'Other','permissionDecision':'deny'}"),
        ):
            out, _ = with_scanner(
                "import json; print(json.dumps({'hookSpecificOutput':" + envelope + "}))")
            check(f"a decision envelope with {label} is replaced, not forwarded",
                  denied(out) and adapter_sourced(out))

        # The sharp one: a malformed ALLOW. Forwarding it lets the call run on an envelope
        # the host may not honour; replacing it refuses.
        out, _ = with_scanner(
            "import json; print(json.dumps({'hookSpecificOutput':"
            "{'permissionDecision':'allow'}}))")
        check("a malformed ALLOW envelope is refused, not passed through",
              denied(out) and adapter_sourced(out))

        # opus: the host reads 2 as blocking and every OTHER non-zero as NON-blocking,
        # after which the tool proceeds — so a deny forwarded with exit 3 is a deny the
        # host discards. Normalise, never pass an arbitrary child status through.
        out, rc = with_scanner(
            "import json,sys; print(json.dumps({'hookSpecificOutput':"
            "{'hookEventName':'PreToolUse','permissionDecision':'deny'}})); sys.exit(3)")
        check("a deny that exited 3 is re-emitted on an exit the host honours",
              denied(out) and rc in (0, 2))
        check("a deny that exited 3 does not leak that status", rc != 3)

        # ── A FAILED stdin read is not an EMPTY one ────────────────────────────────────
        #
        # `sys.stdin.read()` sat inside a bare `except Exception: allow()`. Under a strict
        # stdin codec a single non-ASCII byte raised UnicodeDecodeError and the adapter
        # allowed a call the settings matcher had already selected as guarded, scanner never
        # invoked; a large payload under a memory cap did the same via MemoryError. The read
        # now happens on the BYTE stream with surrogateescape, so decoding cannot raise and
        # the bytes still reach identification. ensure_ascii=False is load-bearing here — the
        # default would escape the very byte under test out of existence.
        guarded_raw = json.dumps({
            "tool_name": PLUGIN + "ctx_execute",
            "tool_input": {"code": "git reset --hard origin/main # café",
                           "language": "shell"},
        }, ensure_ascii=False).encode("utf-8")
        check("the non-ASCII probe really carries the byte it is testing",
              b"\xc3" in guarded_raw)
        out, seen = run_raw_bytes(guarded_raw, tmp,
                                  {"PYTHONUTF8": "0", "PYTHONIOENCODING": "ascii"})
        check("a guarded call with a non-ASCII byte under a strict stdin codec is not allowed",
              out.get("continue") is not True)
        check("...and that call is either scanned or denied, never silently passed",
              seen is not None or denied(out))

        # No over-refusal: a genuinely EMPTY stdin still means "no call to attribute".
        # An empty read SUCCEEDS and returns b"" — only a read that RAISES is refused.
        out, _ = run_raw_bytes(b"", tmp)
        check("empty stdin still allows (the legitimate cannot-attribute path survives)",
              allowed(out))

        # ── `tool_name: null` must not launder a guarded call through `toolName` ───────
        #
        # `.get("tool_name")` returns None for an ABSENT key and for an explicit JSON null
        # alike, so a present-but-null tool_name fell through to the alias and identified as
        # Bash. With a guarded token sitting in the payload text it STILL allowed, because
        # the raw-bytes tie-breaker is deliberately skipped once identification "succeeds".
        # The suite pinned the LIST-typed case and passed, so the invariant read as covered
        # while null walked through it.
        out, _ = run_raw(json.dumps({
            "tool_name": None,
            "toolName": "Bash",
            "tool_input": {"command": PLUGIN + "ctx_execute git reset --hard origin/main"},
        }), tmp)
        check("tool_name:null carrying a guarded token in the payload is DENIED", denied(out))
        check("tool_name:null carrying a guarded token is not quietly allowed",
              out.get("continue") is not True)

        # ── EVERY falsy tool_name, not just null ──────────────────────────────────────
        #
        # The guard is `if not isinstance(tool, str) or not tool:`. The TYPE half was pinned
        # by the list/dict/int cases above and the null case here; the EMPTINESS half was
        # pinned by nothing. Deleting `or not tool` - a one-token edit - left this suite at
        # rc 0 / 0 FAILs while `{"tool_name": "", "toolName": "Bash"}` carrying a guarded
        # token returned {"continue": true}. `""` is a str, so the type half cannot see it.
        # False and 0 are caught by the type half and are pinned here too, so an edit to
        # EITHER half of the guard is caught by this block rather than by neither.
        for label, falsy in (("empty string", ""), ("False", False), ("zero", 0)):
            out, _ = run_raw(json.dumps({
                "tool_name": falsy,
                "toolName": "Bash",
                "tool_input": {"command": PLUGIN + "ctx_execute git reset --hard origin/main"},
            }), tmp)
            check(f"tool_name:{label} carrying a guarded token is DENIED", denied(out))
            check(f"tool_name:{label} carrying a guarded token is not quietly allowed",
                  out.get("continue") is not True)

        # Control: the camelCase alias must still work when tool_name is GENUINELY absent,
        # or this fix would have closed the hole by breaking the feature.
        out, seen = run_raw(json.dumps({
            "toolName": PLUGIN + "ctx_execute",
            "tool_input": {"code": "echo hello", "language": "shell"},
        }), tmp)
        check("the camelCase alias still resolves when tool_name is truly absent",
              seen is not None)

        # Control: a null tool_name naming nothing guarded anywhere stays ALLOWED. The
        # cannot-attribute path is legitimate and must not become an over-refusal.
        out, _ = run_raw(json.dumps({
            "tool_name": None, "toolName": "Bash",
            "tool_input": {"command": "ls -la"},
        }), tmp)
        check("a null tool_name naming nothing guarded is still allowed",
              allowed(out))

        # ── T4 (R7) is DEFERRED, and this pins WHY, so the next seat does not "fix" it ──
        #
        # T4 is real: dict KEYS are not collected, so a dangerous string in a key is
        # verdicted on its siblings. The obvious three-line remedy — append `key` in the
        # dict branch — was written, run, and REVERTED, because it converts a fail-CLOSED
        # path into a fail-OPEN one. Test 7 above denies `{"timeout": 30}` precisely
        # because NO string exists anywhere and the shape is unintelligible; every dict
        # carries its own key names, so with keys collected that payload is scanned as the
        # benign text "timeout" and ALLOWED. Measured: test 7 flipped deny -> allow.
        #
        # So this assertion pins the CURRENT, DOCUMENTED behaviour — values scanned, keys
        # not — rather than pretending the gap is closed. It fails loudly if someone
        # appends keys without also solving the intelligibility question, which is the
        # design decision the deferral exists for.
        out, seen = run(PLUGIN + "ctx_execute",
                        {"commands": {"git reset --hard origin/main": {"label": "x"}}}, tmp)
        cmd = seen_command(seen)
        check("values are still scanned under an unknown key", "x" in cmd)
        check("dict keys are NOT scanned (documented residual, deferred to transformate WI-3067)",
              "git reset --hard origin/main" not in cmd)

    if failures:
        for f in failures:
            print(f"FAIL: {f}")
        sys.exit(1)
    print("ok — dcg-ctx-wrap routing + extraction assertions passed")


if __name__ == "__main__":
    main()
