"""Separate return sites retain cleanup and never credit skipped alternatives."""


def finish(choice, events):
    try:
        if choice == 'first':
            return 11
        if choice == 'second':
            return 22
        return 33
    finally:
        events.append('cleaned')


def same_line(choice, events):
    try:
        if choice: return 44
        return 55
    finally:
        events.append('cleaned')


def stopped_before_return(events):
    try:
        raise ValueError('stopped')
        return 66
    finally:
        events.append('cleaned')
