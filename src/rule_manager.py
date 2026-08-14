"""
rule_manager.py
----------------
Equivalent of include/rule_manager.h.

Purpose: Store blocking rules (by source IP, app type, or domain substring)
and decide whether a given flow should be blocked.
"""


class RuleManager:
    def __init__(self):
        self.blocked_ips = set()
        self.blocked_apps = set()
        self.blocked_domains = []

    def block_ip(self, ip: str):
        self.blocked_ips.add(ip)

    def block_app(self, app: str):
        self.blocked_apps.add(app)

    def block_domain(self, domain: str):
        self.blocked_domains.append(domain)

    def is_blocked(self, src_ip: str, app_type: str, sni: str) -> bool:
        # Check IP blacklist
        if src_ip in self.blocked_ips:
            return True
        # Check app blacklist
        if app_type in self.blocked_apps:
            return True
        # Check domain blacklist (substring match)
        if sni:
            sni_lower = sni.lower()
            for dom in self.blocked_domains:
                if dom.lower() in sni_lower:
                    return True
        return False
