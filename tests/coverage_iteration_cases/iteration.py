"""Independent iteration oracle: one loop and one elementary truth test."""


def count_true(values):
    """Return the number of truthy inputs, visiting each input once."""
    total = 0
    for value in values:
        if value:
            total += 1
    return total
