"""Compound value tests require path correlations; refuse to invent them."""


def negated_chain_value(low, value, high, alternative):
    return not (low < value < high) or alternative
