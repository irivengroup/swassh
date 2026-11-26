"""An explicit source identity test must always retain both outcomes."""


def identity(value):
    if value is tuple:
        return True
    return False
