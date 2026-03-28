import json
import os
import sys

RULES_DIR = os.path.join(os.path.dirname(__file__), "rules")

_rules_cache: dict = {}
_rules_loaded: bool = False


_FLAG_REQUIRED_TYPES = {"missing_flag", "forbidden_value"}
_REQUIRED_CHECK_FIELDS = {"type", "severity", "message"}


def _validate_check(check: dict, fname: str) -> str | None:
    """Return an error string if the check is malformed, else None."""
    missing = _REQUIRED_CHECK_FIELDS - check.keys()
    if missing:
        return f"check missing fields {missing}"
    if check["type"] in _FLAG_REQUIRED_TYPES and "flag" not in check:
        return f"check of type '{check['type']}' missing 'flag'"
    if check["type"] == "forbidden_value" and "forbidden_value" not in check:
        return f"check of type 'forbidden_value' missing 'forbidden_value'"
    return None


def _load_rules() -> dict:
    global _rules_loaded
    if _rules_loaded:
        return _rules_cache
    try:
        filenames = sorted(os.listdir(RULES_DIR))
    except (FileNotFoundError, PermissionError) as e:
        print(f"Error: cannot read rules directory {RULES_DIR}: {e}", file=sys.stderr)
        return _rules_cache
    for fname in filenames:
        if fname.endswith(".json"):
            try:
                with open(os.path.join(RULES_DIR, fname), encoding="utf-8") as f:
                    for rule in json.load(f):
                        key = rule["command"]
                        valid_checks = []
                        for check in rule["checks"]:
                            err = _validate_check(check, fname)
                            if err:
                                print(f"Warning: skipping invalid check in {fname} ({key}): {err}", file=sys.stderr)
                            else:
                                valid_checks.append(check)
                        if valid_checks:
                            if key in _rules_cache:
                                _rules_cache[key].extend(valid_checks)
                            else:
                                _rules_cache[key] = valid_checks
            except (json.JSONDecodeError, KeyError, IOError) as e:
                print(f"Warning: skipping malformed rule file {fname}: {e}", file=sys.stderr)
    _rules_loaded = True
    return _rules_cache


def _flag_present(flags: dict, flag: str) -> bool:
    """Check whether *flag* (or its --no- / positive counterpart) is present.

    IMPORTANT: This treats --X and --no-X as equivalent for *presence* only.
    A missing_flag check for --no-X will report "present" when --X exists.
    This is correct ONLY when paired with a forbidden_value check that catches
    the dangerous positive form (e.g. --publicly-accessible true).  If you add
    a missing_flag rule for --no-X, always add a matching forbidden_value rule
    for --X to avoid silent false negatives.
    """
    if flag in flags:
        return True
    if flag.startswith("--no-"):
        base = flag[5:]  # e.g. "--no-publicly-accessible" -> "publicly-accessible"
        return bool(base) and ("--" + base) in flags
    return ("--no-" + flag[2:]) in flags


def _flag_value_contains(flags: dict, flag: str, value: str) -> bool:
    v = flags.get(flag, "")
    return isinstance(v, str) and value.lower() in v.lower()


def analyze(parsed: dict) -> list[dict]:
    rules = _load_rules()
    flags = parsed["flags"]

    # Warn when flags are passed via JSON file (bypasses all flag checks)
    if "--cli-input-json" in flags or "--cli-input-yaml" in flags:
        return [{
            "severity": "INFO",
            "message": "Parameters passed via JSON/YAML file, flag-based checks cannot inspect the contents",
            "context": "Manually verify the input file against security best practices.",
            "suggestion": "",
        }]

    key = f"{parsed['service']} {parsed['operation']}"
    checks = rules.get(key, [])
    findings = []

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
                # Boolean flags (parsed as Python True) always match forbidden_value
                # checks, regardless of the forbidden_value string. This is intentional:
                # --associate-public-ip-address (no value) is treated as "true".
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
