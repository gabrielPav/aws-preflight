import json
import os
import sys

RULES_DIR = os.path.join(os.path.dirname(__file__), "rules")

_rules_cache: dict = {}


def _load_rules() -> dict:
    if _rules_cache:
        return _rules_cache
    try:
        filenames = sorted(os.listdir(RULES_DIR))
    except (FileNotFoundError, PermissionError) as e:
        print(f"Error: cannot read rules directory {RULES_DIR}: {e}", file=sys.stderr)
        return _rules_cache
    for fname in filenames:
        if fname.endswith(".json"):
            try:
                with open(os.path.join(RULES_DIR, fname)) as f:
                    for rule in json.load(f):
                        key = rule["command"]
                        if key in _rules_cache:
                            _rules_cache[key].extend(rule["checks"])
                        else:
                            _rules_cache[key] = rule["checks"]
            except (json.JSONDecodeError, KeyError, IOError) as e:
                print(f"Warning: skipping malformed rule file {fname}: {e}", file=sys.stderr)
    return _rules_cache


def _flag_present(flags: dict, flag: str) -> bool:
    return flag in flags


def _flag_value_contains(flags: dict, flag: str, value: str) -> bool:
    v = flags.get(flag, "")
    return isinstance(v, str) and value.lower() in v.lower()


def analyze(parsed: dict) -> list[dict]:
    rules = _load_rules()
    key = f"{parsed['service']} {parsed['operation']}"
    checks = rules.get(key, [])
    findings = []
    flags = parsed["flags"]

    for check in checks:
        ctype = check["type"]
        finding = None

        if ctype == "missing_flag":
            if not _flag_present(flags, check["flag"]):
                finding = check
            elif "expected_value" in check:
                if not _flag_value_contains(flags, check["flag"], check["expected_value"]):
                    finding = check

        elif ctype == "forbidden_value":
            if _flag_present(flags, check["flag"]):
                val = flags.get(check["flag"], "")
                if val is True:
                    finding = check
                elif isinstance(val, str):
                    forbidden = check["forbidden_value"].lower()
                    val_lower = val.lower()
                    if val_lower == forbidden or val_lower.endswith("/" + forbidden):
                        finding = check

        elif ctype == "always_warn":
            finding = check

        if finding:
            entry = {
                "severity": finding["severity"],
                "message": finding["message"],
                "context": finding.get("context", ""),
                "suggestion": finding.get("suggestion", ""),
            }
            if ctype == "forbidden_value":
                entry["_forbidden_flag"] = check["flag"]
            findings.append(entry)

    return findings
