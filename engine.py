import json
import os
import sys

RULES_DIR = os.path.join(os.path.dirname(__file__), "rules")

_rules_cache: dict = {}
_rules_loaded: bool = False


_FLAG_REQUIRED_TYPES = {"missing_flag", "forbidden_value"}
_REQUIRED_CHECK_FIELDS = {"type", "severity", "message"}


_VALID_SEVERITIES = {"HIGH", "MEDIUM", "LOW", "INFO"}
_VALID_TYPES = {"missing_flag", "forbidden_value", "always_warn"}

# Global checks — applied to every command before per-command rules.
# These are CLI-level flags, not service parameters, so they fire even
# when --cli-input-json is used (the flag is on the CLI, not in the file).
_GLOBAL_CHECKS = [
    {
        "flag": "--no-verify-ssl",
        "severity": "HIGH",
        "message": "SSL certificate verification disabled",
        "context": "The AWS CLI will not verify SSL certificates for this request. Your credentials and data are exposed to man-in-the-middle attacks. Remove --no-verify-ssl and fix the certificate trust chain instead.",
        "suggestion": "",
    },
]


def _validate_check(check: dict, fname: str) -> str | None:
    """Return an error string if the check is malformed, else None."""
    missing = _REQUIRED_CHECK_FIELDS - check.keys()
    if missing:
        return f"check missing fields {missing}"
    if check["type"] not in _VALID_TYPES:
        return f"invalid type '{check['type']}'"
    if check["severity"] not in _VALID_SEVERITIES:
        return f"invalid severity '{check['severity']}'"
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
    # Warn about missing_flag checks for --no-X without a paired forbidden_value for --X
    for cmd, checks in _rules_cache.items():
        no_flags = [c["flag"] for c in checks if c["type"] == "missing_flag" and c["flag"].startswith("--no-")]
        for nf in no_flags:
            positive = "--" + nf[5:]  # --no-publicly-accessible -> --publicly-accessible
            has_pair = any(
                c["type"] == "forbidden_value" and c["flag"] == positive
                for c in checks
            )
            if not has_pair:
                print(f"Warning: {cmd} has missing_flag for {nf} without a paired forbidden_value for {positive}", file=sys.stderr)

    _rules_loaded = True
    return _rules_cache


def _flag_present(flags: dict, flag: str) -> bool:
    """Check whether *flag* (or its --no- counterpart) is present.

    For --no-X checks: returns True if --X is present (the positive form
    satisfies presence, paired forbidden_value catches the dangerous case).
    For --X checks: returns True ONLY if --X itself is present. --no-X does
    NOT satisfy a check for --X, because --no-X is the user explicitly
    disabling the control — the missing_flag check must still fire.
    """
    if flag in flags:
        return True
    if flag.startswith("--no-"):
        base = flag[5:]  # e.g. "--no-publicly-accessible" -> "publicly-accessible"
        return bool(base) and ("--" + base) in flags
    return False


def _flag_value_contains(flags: dict, flag: str, value: str) -> bool:
    v = flags.get(flag, "")
    return isinstance(v, str) and value.lower() in v.lower()


def analyze(parsed: dict) -> list[dict]:
    rules = _load_rules()
    flags = parsed["flags"]

    cli_input_bypass = "--cli-input-json" in flags or "--cli-input-yaml" in flags

    key = f"{parsed['service']} {parsed['operation']}"
    checks = rules.get(key, [])
    findings = []

    # Global checks — CLI-level flags that are dangerous on any command
    for g in _GLOBAL_CHECKS:
        if g["flag"] in flags:
            findings.append({
                "severity": g["severity"],
                "message": g["message"],
                "context": g["context"],
                "suggestion": g["suggestion"],
                "_forbidden_flag": g["flag"],
            })

    # Warn when flags are passed via JSON file (bypasses flag-based checks)
    if cli_input_bypass:
        findings.append({
            "severity": "INFO",
            "message": "Parameters passed via JSON/YAML file, flag-based checks cannot inspect the contents",
            "context": "Manually verify the input file against security best practices.",
            "suggestion": "",
        })

    for check in checks:
        ctype = check["type"]
        finding = None

        if cli_input_bypass and ctype != "always_warn":
            continue

        if ctype == "missing_flag":
            if "suppress_if_flag" in check and _flag_present(flags, check["suppress_if_flag"]):
                pass
            elif not _flag_present(flags, check["flag"]):
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
