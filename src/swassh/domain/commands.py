"""A bounded opaque command; only the remote shell interprets its content."""
MAX_COMMAND_BYTES = 16_384


def validate_command(value: str) -> str:
    if not isinstance(value, str) or not value.strip() or "\x00" in value:
        raise ValueError("command must be a nonempty string without NUL")
    if len(value.encode("utf-8")) > MAX_COMMAND_BYTES:
        raise ValueError("command exceeds the portable 16 KiB limit; transfer a script first")
    return value
