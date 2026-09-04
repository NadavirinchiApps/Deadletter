"""Rule pack. Rules self-register on import."""

from .base import Rule, all_rules, get_rule, register, run
from . import (  # noqa: F401  (registration)
    eda001,
    eda002,
    eda003,
    eda004,
    eda005,
    eda006,
    eda007,
    eda008,
    eda009,
    eda010,
    eda011,
    eda012,
)

__all__ = ["Rule", "all_rules", "get_rule", "register", "run"]
