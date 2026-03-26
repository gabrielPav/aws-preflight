import shlex


def parse_command(raw: str) -> dict | None:
    raw = raw.strip()
    if not raw.startswith("aws "):
        return None
    try:
        parts = shlex.split(raw)
    except ValueError:
        return None

    if len(parts) < 3:
        return None

    service = parts[1]
    operation = parts[2]
    flags = {}
    i = 3
    while i < len(parts):
        token = parts[i]
        if token.startswith("-"):
            if "=" in token:
                key, val = token.split("=", 1)
                flags[key] = val
                i += 1
            elif i + 1 < len(parts) and not parts[i + 1].startswith("-"):
                flags[token] = parts[i + 1]
                i += 2
            else:
                flags[token] = True
                i += 1
        else:
            i += 1

    return {
        "service": service,
        "operation": operation,
        "flags": flags,
        "raw": raw,
    }
