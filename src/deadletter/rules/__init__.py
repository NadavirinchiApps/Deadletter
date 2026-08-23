"""Rule pack. Rules self-register on import; A2 adds EDA001-005 here."""

from .base import Rule, all_rules, get_rule, register, run

__all__ = ["Rule", "all_rules", "get_rule", "register", "run"]
