"""Control-transfer source obligations, including paths never executed."""

def iterate(values, events):
    for value in values:
        if value == 0:
            continue
        if value < 0:
            break
        events.append(value)
    return events

def raise_again(fail, events):
    try:
        if fail:
            raise ValueError('synthetic oracle')
        return 'normal'
    except ValueError:
        events.append('caught')
        raise

def guarded_raise(fail):
    if fail: raise ValueError('guarded')
    return 17
