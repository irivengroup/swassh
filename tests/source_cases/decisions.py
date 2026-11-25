"""Independent, hand-enumerated source decision and refusal witnesses."""


def choose(first, second):
    if first and second:
        return 'yes'
    return 'no'


def between(low, value, high):
    if low < value < high:
        return 'inside'
    return 'outside'


def advance(value, limit):
    while 0 < value < limit:
        value += 1
    return value


def optional(value):
    if value is None:
        return 'missing'
    if value is not None:
        return 'present'
    return 'unreachable'


def count(values):
    total = 0
    for value in values:
        if value:
            total += 1
    return total


def recover(call):
    try:
        return call()
    except ValueError:
        return 'recovered'


def managed(manager):
    with manager:
        return 17


def constant():
    if True:
        return 7
    return 9


def filtered(values):
    return [value for value in values if value]


def packed(values):
    return tuple(value for value in values)


def any_value(values):
    if any(value for value in values):
        return 'some'
    return 'none'


async def asynchronous(values):
    output = []
    async for value in values:
        output.append(value)
    return output


async def asynchronous_break(values):
    output = []
    async for value in values:
        output.append(value)
        break
    return output


async def asynchronous_recover(values):
    output = []
    try:
        async for value in values:
            output.append(value)
    except LookupError:
        return 'failed'
    return output


def inverted(value):
    if not value:
        return 'false'
    return 'true'


def never_called(flag):
    if flag:
        return 1
    return 0


def value_boolean(first, second):
    return first or second


def filtered_optional(values):
    return [value for value in values if value is not None]


def assignment_test(first, second):
    if selected := first or second:
        return selected
    return None


def nested_generator(values):
    return {key: value for key, value in ((item, item) for item in values)}


def fused_value(first, second):
    return first, second or 17


def nested_iteration(values):
    return [(outer, inner) for outer in values for inner in outer]


def generator_with_inlined_comprehension(values):
    return tuple({key: key for key in row} for row in values)


def loop_over_comprehension(values):
    for value in {item for item in values}:
        break
    return 17


def preserving_not(value, alternative):
    return not value or alternative


def invalid_members(values):
    return any(not isinstance(value, dict) or len(value) != 1 for value in values)


def preserving_double_not(value, alternative):
    return not not value or alternative


def invalid_range(values):
    return any(not 0 <= value <= 9 for value in values)
