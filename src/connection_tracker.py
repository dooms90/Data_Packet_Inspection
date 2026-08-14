"""
connection_tracker.py
----------------------
Equivalent of include/connection_tracker.h.

Purpose: Maintain the flow table -- a mapping from FiveTuple to Flow -- so
that all packets belonging to the same connection share the same SNI/app
classification and blocked status.
"""

from .types import FiveTuple, Flow


class ConnectionTracker:
    def __init__(self):
        self.flows = {}  # FiveTuple -> Flow

    def get_or_create(self, tuple_key: FiveTuple) -> Flow:
        if tuple_key not in self.flows:
            self.flows[tuple_key] = Flow()
        return self.flows[tuple_key]

    def all_flows(self):
        return self.flows.values()

    def __len__(self):
        return len(self.flows)
