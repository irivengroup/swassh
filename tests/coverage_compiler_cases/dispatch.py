"""No user boolean condition in pack; choose only tests its supplied values."""


def pack(values):
    return tuple(item for item in values)


def choose(values):
    return any(item for item in values)
