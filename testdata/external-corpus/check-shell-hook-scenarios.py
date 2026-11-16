#!/usr/bin/env python3
"""Replay pinned hook launch scenarios in a restricted native Bash process."""

import argparse
import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
from collections import defaultdict
from pathlib import Path


CORPUS_SHA256 = "f3799769e8c7f851a2f59db2e8769ef64ee52139b47fdd1a8121d67ef97b40e3"
CASES = {
    "hook-09": "hooks/stop-hook.sh",
    "hook-10": "hooks/sg-python.sh",
    "hook-12": "hooks/session-recap.sh",
}
TOOLS = ("awk", "basename", "cat", "date", "dirname", "grep", "head", "jq", "mkdir", "mv", "rm", "sed", "tail", "tr")
TRACE = re.compile(r"^\++SCOUT\|([^|]*)\|(\d+)\|\s*(.+)$")
SANDBOX = Path("/usr/bin/sandbox-exec")


def require(condition, description):
    if not condition:
        raise ValueError(description)


def load_corpus(path):
    with path.open("rb") as source:
        raw = source.read((8 << 20) + 1)
    require(hashlib.sha256(raw).hexdigest() == CORPUS_SHA256, "unexpected scenario corpus SHA-256")
    return {case["id"]: case for case in json.loads(raw)["cases"] if case["id"] in CASES}


def registrations(case, root):
    files = {entry["path"]: entry["content"] for entry in case["files"]}
    hooks = json.loads(files["hooks/hooks.json"])["hooks"]
    expected = str(root / CASES[case["id"]])
    commands = defaultdict(set)
    for event, groups in hooks.items():
        for group in groups:
            for hook in group["hooks"]:
                command = hook["command"]
                argv = shlex.split(command.replace("$"+"{CLAUDE_PLUGIN_ROOT}", str(root)))
                require(hook["type"] == "command" and "args" not in hook, "unsupported handler format")
                require(argv[:2] == ["bash", expected], "unexpected handler path")
                commands[command].add(event)
    return files, commands


def materialize(case, root):
    plugin = root / "plugin"
    files, commands = registrations(case, plugin)
    for name, body in files.items():
        dest = plugin / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(body.encode())
    return plugin, commands


def platform_tools(bash):
    require(sys.platform == "darwin" and SANDBOX.is_file(), "the scenario runner requires macOS sandbox-exec")
    require(bash.is_file(), "Bash executable not found")
    version = subprocess.run([str(bash), "--version"], capture_output=True, check=True, text=True, timeout=3)
    require("version 5." in version.stdout or "version 6." in version.stdout, "Bash with inherited xtrace FD is required")
    require(not re.search(r"\s", str(bash)), "Bash executable path contains whitespace")
    paths = {"bash": bash}
    for name in TOOLS:
        path = next((p for base in ("/bin", "/usr/bin") if (p := Path(base, name)).is_file()), None)
        require(path is not None, f"system tool {name} is unavailable")
        paths[name] = path.resolve()
    return paths, version.stdout.splitlines()[0]


def linked_libraries(paths):
    libraries = set()
    pending = list(paths)
    while pending:
        binary = pending.pop()
        result = subprocess.run(
            ["/usr/bin/otool", "-L", str(binary)], check=True, capture_output=True, text=True, timeout=3,
        )
        for row in result.stdout.splitlines()[1:]:
            library = Path(row.strip().split(" (compatibility version", 1)[0])
            if library.is_absolute() and library.is_file() and library not in libraries:
                libraries.update((library, library.resolve()))
                pending.append(library)
    return sorted(libraries)


STUBS = {
    "python3.13": r'''
[[ "$PYTHONUTF8" == 1 ]] || exit 81
if [[ $# == 3 && "$1" == -c && "$3" == "$SCOUT_TARGET" && -r "$3" ]]; then
    [[ "$PYTHONSAFEPATH" == 1 && "$2" == *"sys.version_info"* ]] || exit 82
    printf '%s\n' probe >> "$SCOUT_BOUNDARY"
    printf '%s\n' 3.13
elif [[ $# == 1 && "$1" == "$SCOUT_TARGET" && -r "$1" ]]; then
    printf 'dispatch:%s\n' "$1" >> "$SCOUT_BOUNDARY"
else
    exit 83
fi
''',
    "git": r'''
[[ $# == 4 && "$1" == -C && "$2" == "$SCOUT_PROJECT" && "$3" == rev-parse && "$4" == --git-dir ]] || exit 84
printf '%s\n' .git
''',
    "claude": r'''
[[ $# == 11 && "$1" == -p && "$2" == --model && "$3" == claude-sonnet-4-6 &&
   "$4" == --allowed-tools && "$5" == Read,Write,Edit,Glob &&
   "$6" == --permission-mode && "$7" == acceptEdits &&
   "$8" == --no-session-persistence && "$9" == --max-budget-usd && "${10}" == 1.00 &&
   "${11}" == *"$SCOUT_PROJECT/transcript.jsonl"* && "${11}" == *scenario-session* &&
   "$CLAUDE_RECAP_RUNNING" == 1 ]] || exit 85
printf '%s\n' ingest >> "$SCOUT_BOUNDARY"
printf '%s\n' 'scenario response'
exit "$SCOUT_CLAUDE_STATUS"
''',
    "mktemp": r'''
[[ $# == 2 && "$1" == -t && "$2" == claude-recap.XXXXXX ]] || exit 86
output="$TMPDIR/scout-recap-output"
: > "$output"
printf '%s\n' "$output"
''',
}


def sandbox_policy(root, paths, libraries, stub_paths, writable):
    def filters(kind, values):
        return " ".join(f"({kind} {json.dumps(str(value))})" for value in values)

    read = filters("subpath", (root, "/System/Library", "/usr/lib"))
    maps = filters("subpath", ("/System/Library", "/usr/lib"))
    libs = filters("literal", libraries)
    execs = filters("literal", [*paths.values(), *stub_paths])
    write = filters("subpath", writable)
    return (
        '(version 1)(deny default)(import "/System/Library/Sandbox/Profiles/dyld-support.sb")'
        "(allow process-fork)(allow sysctl-read)"
        "(allow file-read-metadata)"
        f"(allow file-read-data {read} {libs} {execs} (literal \"/dev/null\") (literal \"/dev/urandom\"))"
        f"(allow file-map-executable {maps} {execs} {libs})"
        f"(allow process-exec {execs})(allow file-write* {write} (literal \"/dev/null\"))(deny network*)"
    )


def run_profile(case, profile, runtime, command_index=0):
    paths, libraries = runtime
    with tempfile.TemporaryDirectory(prefix="scout-hook-", dir="/private/tmp") as directory:
        root = Path(directory).resolve()
        plugin, commands = materialize(case, root)
        work, home, temp, bin_dir = (root / name for name in ("work", "home", "tmp", "bin"))
        for path in (work, home, temp, bin_dir):
            path.mkdir()
        require(not re.search(r"[\s*?\[\]]", str(plugin)), "plugin root is not shell-safe")
        for name, path in paths.items():
            (bin_dir / name).symlink_to(path)

        command, events = list(commands.items())[command_index]
        env = {
            "PATH": str(bin_dir), "HOME": str(home), "TMPDIR": str(temp), "LC_ALL": "C",
            "CLAUDE_PLUGIN_ROOT": str(plugin), "SCOUT_PROJECT": str(work), "SHELLOPTS": "xtrace",
            "SCOUT_BOUNDARY": str(temp / "boundary"), "SCOUT_CLAUDE_STATUS": str(profile.get("claude_status", 0)),
        }
        transcript = work / "transcript.jsonl"
        fixture(case["id"], profile, work, transcript, env)
        if case["id"] == "hook-10":
            target = shlex.split(command.replace("$"+"{CLAUDE_PLUGIN_ROOT}", str(plugin)))[2]
            require(target in [str(plugin / "hooks" / name) for name in ("ensure_agent_sdk.py", "security_reminder_hook.py")], "unexpected Python target")
            env["SCOUT_TARGET"] = target

        stub_names = {
            "hook-09": (), "hook-10": ("python3.13",), "hook-12": ("git", "claude", "mktemp"),
        }[case["id"]]
        stub_paths = []
        for name in stub_names:
            stub = bin_dir / name
            stub.write_text(f"#!{paths['bash']}\n" + STUBS[name], encoding="utf-8")
            stub.chmod(0o700)
            stub_paths.append(stub)

        setup = root / "trace.bash"
        setup.write_text("PS4='+SCOUT|"+'$'+"{BASH_SOURCE[0]:-registration}|"+'$'+"{LINENO}| '\n", encoding="utf-8")
        env["BASH_ENV"] = str(setup)
        policy = sandbox_policy(root, paths, libraries, stub_paths, (work, home, temp))
        payload = json.dumps({"session_id": "scenario-session", "transcript_path": str(transcript), "cwd": str(work)})
        with (temp / "trace").open("w+b") as trace:
            env["BASH_XTRACEFD"] = str(trace.fileno())
            run = subprocess.run(
                [str(SANDBOX), "-p", policy, str(paths["bash"]), "-c", command],
                cwd=work, env=env, pass_fds=(trace.fileno(),),
                input=payload.encode(), capture_output=True, timeout=10,
            )
            require(run.returncode == 0 and not run.stderr, f"{profile['name']} failed ({run.returncode}): {run.stderr.decode(errors='replace')}")
            trace.seek(0)
            evidence = parse_trace(trace.read().decode(), plugin / CASES[case["id"]], setup, stub_paths)

        verify(case["id"], profile, work, temp, evidence, run.stdout, env)
        return {
            "case_id": case["id"], "scenario": profile["name"], "events": sorted(events),
            "assumptions": profile, "exit_code": run.returncode, "replay_complete": True,
            "stubbed_commands": list(stub_names),
            "traced_handler_commands": sum(evidence.values()), "reached_handler_lines": sorted(evidence),
            "handler_sha256": hashlib.sha256((plugin / CASES[case["id"]]).read_bytes()).hexdigest(),
        }


def parse_trace(trace, script, setup, stubs):
    reached = defaultdict(int)
    saw_registration = False
    for row in trace.splitlines():
        match = TRACE.match(row)
        if match is None:
            continue
        origin, line, command = match.groups()
        if origin == "registration":
            require(command.startswith(f"bash {script}"), "unexpected command in hook registration")
            saw_registration = True
        elif origin == str(script):
            reached[int(line)] += 1
        else:
            require(origin == str(setup) or Path(origin) in stubs, f"unexpected shell origin: {origin}")
    require(saw_registration and reached, "native Bash trace is missing the registration or handler")
    return reached


def fixture(case_id, profile, work, transcript, env):
    if case_id == "hook-09":
        (work / ".claude").mkdir()
        (work / ".claude/ralph-loop.local.md").write_text(
            f"---\niteration: {profile['iteration']}\nmax_iterations: {profile['max_iterations']}\n"
            "completion_promise: null\nsession_id: scenario-session\n---\nVerify example.\n", encoding="utf-8",
        )
        transcript.write_text('{"role":"assistant","message":{"content":[{"type":"text","text":"still working"}]}}\n', encoding="utf-8")
    elif case_id == "hook-12":
        lines = ['{"type":"user"}\n'] * profile["user_messages"] + ['{"type":"tool_use"}\n']
        transcript.write_text("".join(lines), encoding="utf-8")
        (work / ".claude/knowledge").mkdir(parents=True)
        env["CLAUDE_RECAP_RUNNING"] = ""


def verify(case_id, profile, work, temp, evidence, stdout, env):
    boundary = temp / "boundary"
    if case_id == "hook-09":
        state = work / ".claude/ralph-loop.local.md"
        if profile["name"] == "continue-loop":
            result = json.loads(stdout)
            require(result["decision"] == "block" and result["reason"] == "Verify example.", "Ralph Loop did not emit its stop response")
            require("iteration: 2\n" in state.read_text() and {145, 170, 191} <= evidence.keys(), "Ralph Loop did not increment and replace state")
        else:
            require(not state.exists() and b"Max iterations (1) reached" in stdout and 64 in evidence, "Ralph Loop did not clean up at the iteration limit")
    elif case_id == "hook-10":
        require(boundary.read_text().splitlines() == ["probe", "dispatch:" + env["SCOUT_TARGET"]], "wrong Python probe or dispatch")
        require(111 in evidence and 339 in evidence, "Python probe and exec are missing in the launcher trace")
    else:
        log = (work / ".claude/knowledge/log.md").read_text()
        name = profile["name"]
        if name == "short-session":
            require("skipped (below threshold: 1 user msgs, 1 tool calls" in log and not boundary.exists(), "Luca failed the short-session guard")
        elif name == "ingest-success":
            require("recap written" in log and boundary.read_text() == "ingest\n" and {101, 111, 117} <= evidence.keys(), "Luca did not complete the ingest scenario")
        else:
            errors = (Path(env["HOME"]) / ".claude/knowledge/_errors.log").read_text()
            require("claude -p failed" in errors and boundary.read_text() == "ingest\n" and {101, 114, 117} <= evidence.keys(), "Luca did not record the failed ingest")
        require(not (temp / "scout-recap-output").exists(), "Luca left a temporary output file")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--bash", type=Path, required=True)
    args = parser.parse_args()
    try:
        cases = load_corpus(args.corpus)
        paths, version = platform_tools(args.bash.resolve())
        runtime = paths, linked_libraries(set(paths.values()))
        reports = [
            run_profile(cases["hook-09"], {"name": "continue-loop", "iteration": 1, "max_iterations": 10, "locale": "C"}, runtime),
            run_profile(cases["hook-09"], {"name": "iteration-limit", "iteration": 1, "max_iterations": 1, "locale": "C"}, runtime),
            run_profile(cases["hook-10"], {"name": "posix-python-sdk", "cygpath": False, "python_stub_version": "3.13"}, runtime, 0),
            run_profile(cases["hook-10"], {"name": "posix-python-guidance", "cygpath": False, "python_stub_version": "3.13"}, runtime, 1),
            run_profile(cases["hook-12"], {"name": "short-session", "user_messages": 1, "claude_status": 0}, runtime),
            run_profile(cases["hook-12"], {"name": "ingest-success", "user_messages": 5, "claude_status": 0}, runtime),
            run_profile(cases["hook-12"], {"name": "ingest-failure", "user_messages": 5, "claude_status": 17}, runtime),
        ]
    except (ValueError, OSError, KeyError, subprocess.SubprocessError) as exc:
        parser.error(str(exc))
    print(json.dumps({
        "scope": "native Bash runtime replay of selected paths with pinned input and stubbed app boundaries",
        "environment": {"platform": sys.platform, "locale": "C", "scratch_plugin_root": "absolute, without whitespace or glob characters", "network": "denied"},
        "corpus_sha256": CORPUS_SHA256, "bash_version": version, "scenarios": reports,
    }, indent=2))


if __name__ == "__main__":
    main()
