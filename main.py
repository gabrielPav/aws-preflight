#!/usr/bin/env python3
VERSION = "1.0.0"

import argparse
import shlex
import subprocess
import sys

try:
    import readline
except ImportError:
    pass

from parser import parse_command
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
_all_findings: list[dict] = []


def process(command: str):
    parsed = parse_command(command)
    if not parsed:
        print(format_parse_error_json(command) if _output_json else format_parse_error(command))
        return
    findings = analyze(parsed)
    _all_findings.extend(findings)
    print(format_result_json(parsed, findings) if _output_json else format_result(parsed, findings))


def execute(command: str):
    print(f"\n▶  Executing: {command}\n")
    try:
        parts = shlex.split(command)
    except ValueError as e:
        print(f"\n⚠️  Invalid command: {e}")
        return
    result = subprocess.run(parts)
    if result.returncode != 0:
        print(f"\n⚠️  Command exited with code {result.returncode}")


def interactive():
    print("┌─────────────────────────────────────────────────────┐")
    print("│  aws-preflight  -  Security Linter for AWS CLI      │")
    print("│  Commands are linted, NOT executed against AWS.     │")
    print("│  Type 'help' for options. Ctrl+C or 'exit' to quit. │")
    print("└─────────────────────────────────────────────────────┘\n")

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
            process(cmd)
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
        help="Minimum severity to trigger non-zero exit code (default: MEDIUM)",
    )
    args = ap.parse_args()

    _output_json = args.json_output
    _min_severity = args.min_severity

    if args.command:
        process(args.command)
        sys.exit(exit_code_for_findings(_all_findings, _min_severity))
    elif not sys.stdin.isatty():
        for line in sys.stdin:
            line = line.strip()
            if line:
                process(line)
        sys.exit(exit_code_for_findings(_all_findings, _min_severity))
    else:
        interactive()


if __name__ == "__main__":
    main()
