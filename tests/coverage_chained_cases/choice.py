"""Two elementary comparisons which can share one compiler source position."""
def between(low,value,high):
    if low < value < high:
        return 1
    return 0
