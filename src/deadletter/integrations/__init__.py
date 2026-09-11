"""Deadletter's engine, running inside tools people already have installed.

Nothing in here adds a rule. Each module is an adapter that hands the same
graph and the same twelve rules to another program's plugin interface, so the
cross-resource analysis rides an install path that already exists instead of
asking for a new one.
"""
