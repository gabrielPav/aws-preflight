import json

SEVERITY_ICON = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "ℹ️ "}
SEVERITY_EXIT = {"HIGH": 2, "MEDIUM": 1, "LOW": 0, "INFO": 0}


def _build_suggested(parsed: dict, findings: list[dict]) -> str:
    parts = ["aws", parsed["service"], parsed["operation"]]
    for flag, val in parsed["flags"].items():
        parts.append(flag)
        if val is not True:
            parts.append(val)

    existing_flags = set(parsed["flags"].keys())
    for f in findings:
        suggestion = f.get("suggestion", "")
        if not suggestion:
            continue
        flag = suggestion.split()[0]
        if flag not in existing_flags:
            parts.append(suggestion)
            existing_flags.add(flag)

    # Pair flags with their values into single tokens for display
    display = []
    i = 3
    while i < len(parts):
        token = parts[i]
        if token.startswith("-") and i + 1 < len(parts) and not parts[i + 1].startswith("-"):
            display.append(f"{token} {parts[i + 1]}")
            i += 2
        else:
            display.append(token)
            i += 1

    base = " ".join(parts[:3])
    if not display:
        return base
    lines = [base + " \\"] + [f"  {r} \\" for r in display[:-1]] + [f"  {display[-1]}"]
    return "\n".join(lines)


def format_result(parsed: dict, findings: list[dict]) -> str:
    cmd_label = f"aws {parsed['service']} {parsed['operation']}"
    lines = [f"\n{'─'*60}", f"Command: {cmd_label}"]

    if not findings:
        lines.append("✅  No obvious security issues detected")
        return "\n".join(lines)

    lines.append("⚠️   Issues detected:\n")
    for f in findings:
        icon = SEVERITY_ICON.get(f["severity"], "•")
        lines.append(f"  [{f['severity']}] {icon} {f['message']}")
        if f.get("context"):
            lines.append(f"  ℹ  {f['context']}")
        if f.get("suggestion"):
            lines.append(f"  → Add: {f['suggestion']}\n")

    lines.append("💡  Suggested command:\n")
    lines.append(_build_suggested(parsed, findings))
    return "\n".join(lines)


def format_result_json(parsed: dict, findings: list[dict]) -> str:
    result = {
        "command": f"aws {parsed['service']} {parsed['operation']}",
        "service": parsed["service"],
        "operation": parsed["operation"],
        "passed": len(findings) == 0,
        "findings": findings,
        "summary": {
            "total": len(findings),
            "high": sum(1 for f in findings if f["severity"] == "HIGH"),
            "medium": sum(1 for f in findings if f["severity"] == "MEDIUM"),
            "low": sum(1 for f in findings if f["severity"] == "LOW"),
            "info": sum(1 for f in findings if f["severity"] == "INFO"),
        },
    }
    if findings:
        result["suggested_command"] = _build_suggested(parsed, findings)
    return json.dumps(result, indent=2)


def format_parse_error(raw: str) -> str:
    return f"\n{'─'*60}\n⚠️   Skipped (not a valid AWS command): {raw[:80]}"


def format_parse_error_json(raw: str) -> str:
    return json.dumps({
        "command": raw[:200],
        "error": "not a valid AWS command",
        "passed": False,
        "findings": [],
        "summary": {"total": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
    }, indent=2)


def exit_code_for_findings(findings: list[dict], min_severity: str) -> int:
    threshold = {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    min_level = threshold.get(min_severity, 2)
    for f in findings:
        if threshold.get(f["severity"], 0) >= min_level:
            return 1
    return 0
