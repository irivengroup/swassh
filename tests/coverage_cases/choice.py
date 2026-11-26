"""Independent oracle: two elementary short-circuit conditions, four outcomes."""


def choice(first, second):
    """Return 1 when either input is truthy, otherwise 0."""
    if first or second:
        return 1
    return 0
