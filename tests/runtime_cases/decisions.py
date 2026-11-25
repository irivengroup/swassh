"""Independent loop effects keep inner completion distinct from outer break."""


def first(values, events):
    for item in {value for value in values}:
        events.append(item)
        break
    return events


def complete(values, events):
    for item in {value for value in values}:
        events.append(item)
    return events
