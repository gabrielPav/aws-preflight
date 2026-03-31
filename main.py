#!/usr/bin/env python3
VERSION = "1.0.0"

import argparse
import shlex
import shutil
import subprocess
import sys
import time

try:
    import readline
except ImportError:
    pass

from cli_parser import parse_command
from engine import analyze
from formatter import (
    format_result,
    format_result_json,
    format_parse_error,
    format_parse_error_json,
    exit_code_for_findings,
)

HELP_TEXT = """
Commands:
  aws <service> <operation> [flags]   Lint an AWS CLI command (not executed)
  run <aws command>                   Bypass aws-preflight and execute against AWS
  !<aws command>                      Shorthand for run
  help                                Show this help
  exit / quit                         Leave aws-preflight
"""

_output_json = False
_min_severity = "MEDIUM"


def process(command: str, all_findings: list[dict]) -> list[dict]:
    parsed = parse_command(command)
    if not parsed:
        print(format_parse_error_json(command) if _output_json else format_parse_error(command))
        return []
    findings = analyze(parsed)
    all_findings.extend(findings)
    print(format_result_json(parsed, findings) if _output_json else format_result(parsed, findings))
    return findings


def execute(command: str):
    if not sys.stdin.isatty():
        print("\n⚠️  'run' / '!' commands are disabled in pipe/batch mode")
        return
    print(f"\n▶  Executing: {command}\n")
    try:
        parts = shlex.split(command)
    except ValueError as e:
        print(f"\n⚠️  Invalid command: {e}")
        return
    if not parts or parts[0] != "aws":
        print("\n⚠️  Only AWS CLI commands can be executed. Use: run aws <command>")
        return
    # Resolve to the real aws binary to prevent executing a rogue "aws" wrapper
    aws_path = shutil.which("aws")
    if not aws_path:
        print("\n⚠️  AWS CLI not found in PATH")
        return
    parts[0] = aws_path
    try:
        result = subprocess.run(parts, timeout=30)
    except FileNotFoundError:
        print(f"\n⚠️  Command not found: {parts[0]}")
        return
    except subprocess.TimeoutExpired:
        print("\n⚠️  Command timed out after 30 seconds")
        return
    except OSError as e:
        print(f"\n⚠️  Failed to execute command: {e}")
        return
    if result.returncode != 0:
        print(f"\n⚠️  Command exited with code {result.returncode}")


def interactive():
    all_findings: list[dict] = []
    print("\033[2J\033[H", end="", flush=True)
    sys.stdout.flush()
    time.sleep(0.05)
    print("")
    print("\033[36m  ░▒▓█\033[0m \033[1maws-preflight\033[0m \033[36m█▓▒░\033[0m")
    print("\033[2m  Security Linter for AWS CLI\033[0m")
    print("")
    print("\033[2m  Commands are linted, not executed against AWS.\033[0m")
    print("\033[2m  Type 'help' for options. Ctrl+C or 'quit' to exit.\033[0m")
    print("")

    while True:
        try:
            cmd = input("aws-preflight> ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nBye.")
            break

        if not cmd:
            continue

        if cmd in ("exit", "quit"):
            print("Bye.")
            break
        elif cmd == "help":
            print(HELP_TEXT)
        elif cmd.startswith("run "):
            execute(cmd[4:].strip())
        elif cmd.startswith("!"):
            execute(cmd[1:].strip())
        else:
            process(cmd, all_findings)
            print()


def main():
    global _output_json, _min_severity

    ap = argparse.ArgumentParser(
        prog="aws-preflight",
        description="Security pre-execution checker for AWS CLI commands",
    )
    ap.add_argument("-v", "--version", action="version", version=f"aws-preflight {VERSION}")
    ap.add_argument("command", nargs="?", help="AWS CLI command to lint")
    ap.add_argument(
        "--json", action="store_true", dest="json_output",
        help="Output results as JSON (for CI/CD pipelines)",
    )
    ap.add_argument(
        "--min-severity", choices=["HIGH", "MEDIUM", "LOW", "INFO"],
        default="MEDIUM", metavar="LEVEL",
        help="Minimum severity level that triggers a non-zero exit code (default: MEDIUM). All findings are always displayed regardless of this setting.",
    )
    args = ap.parse_args()

    _output_json = args.json_output
    _min_severity = args.min_severity
    all_findings: list[dict] = []

    if args.command:
        process(args.command, all_findings)
        sys.exit(exit_code_for_findings(all_findings, _min_severity))
    elif not sys.stdin.isatty():
        for line in sys.stdin:
            line = line.strip()
            if line:
                process(line, all_findings)
        sys.exit(exit_code_for_findings(all_findings, _min_severity))
    else:
        interactive()


if __name__ == "__main__":
    main()
