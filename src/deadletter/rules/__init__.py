"""Rule pack. Rules self-register on import."""

from .base import Rule, all_rules, get_rule, register, run
from . import eda001, eda002, eda003, eda004, eda005  # noqa: F401  (registration)

__all__ = ["Rule", "all_rules", "get_rule", "register", "run"]
