"""Reference properties for the PAIN Security Requirements ceiling.

This module is intentionally small. It makes the paper's per-objective
aggregation and the adopted PAIN calibration executable for reproducibility.
"""

from itertools import product

LEVELS = ("L", "M", "H")
LEVEL_RANK = {"L": 1, "M": 2, "H": 3}
IMPACT_WEIGHT = {"N": 0.0, "L": 0.22, "H": 0.56}
REQUIREMENT_WEIGHT = {"L": 0.5, "M": 1.0, "H": 1.5}
NORMALIZATION_DENOMINATOR = 0.995904
DEBILITATING_THRESHOLD = 0.933


def objective_max(*levels):
    """Return the greatest L/M/H objective."""
    if not levels:
        raise ValueError("at least one objective is required")
    return max(levels, key=LEVEL_RANK.__getitem__)


def objective_min(left, right):
    """Return the lesser L/M/H objective."""
    return min((left, right), key=LEVEL_RANK.__getitem__)


def aggregate_profiles(profiles):
    """Take the per-objective maximum of C/I/A profiles."""
    profiles = tuple(profiles)
    if not profiles:
        raise ValueError("at least one profile is required")
    return tuple(objective_max(*(profile[index] for profile in profiles)) for index in range(3))


def effective_requirements(archetype, ceiling):
    """Cap an archetype C/I/A vector by a ceiling."""
    return tuple(objective_min(value, limit) for value, limit in zip(archetype, ceiling))


def severity(impact, requirements):
    """Compute the adopted high-centered PAIN severity scalar."""
    products = (
        IMPACT_WEIGHT[value] * REQUIREMENT_WEIGHT[requirement]
        for value, requirement in zip(impact, requirements)
    )
    intact = 1.0
    for weighted_impact in products:
        intact *= 1.0 - weighted_impact
    return (1.0 - intact) / NORMALIZATION_DENOMINATOR


def debilitating(impact, requirements):
    return severity(impact, requirements) >= DEBILITATING_THRESHOLD


def all_profiles(values=LEVELS):
    return product(values, repeat=3)
