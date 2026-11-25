"""Independent statement oracle: semicolons and early exceptions on one line."""


def interrupted(operation):
    first=1; operation(); second=2
    return first+second


def nested():
    def inner():
        return 9
    return inner
