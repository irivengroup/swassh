"""Strict JSON hooks shared by untrusted data readers."""

from ..domain.errors import InventoryError

def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise InventoryError("duplicate JSON field")
        result[key] = value
    return result


def _invalid_constant(value):
    raise InventoryError("non-finite JSON numbers are forbidden")


