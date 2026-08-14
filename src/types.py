"""
types.py
--------
Equivalent of include/types.h + src/types.cpp in the original C++ project.

Defines the core data structures used throughout the DPI engine:
- FiveTuple: uniquely identifies a network connection ("flow")
- Flow: tracks state for one connection (SNI, app type, blocked status)
- App signatures: maps a domain name (SNI) to a friendly app name
"""

from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# FiveTuple  (src_ip, dst_ip, src_port, dst_port, protocol)
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class FiveTuple:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str  # "TCP" or "UDP"


# ---------------------------------------------------------------------------
# Flow  (per-connection state)
# ---------------------------------------------------------------------------
@dataclass
class Flow:
    sni: Optional[str] = None
    app_type: str = "Unknown"
    blocked: bool = False


# ---------------------------------------------------------------------------
# App signatures (equivalent of sniToAppType in types.cpp)
# ---------------------------------------------------------------------------
APP_SIGNATURES = {
    "youtube": "YouTube",
    "facebook": "Facebook",
    "google": "Google",
    "github": "GitHub",
    "tiktok": "TikTok",
    "netflix": "Netflix",
    "twitter": "Twitter",
    "instagram": "Instagram",
    "amazon": "Amazon",
}


def sni_to_app_type(sni: str) -> str:
    """Map a domain name (from SNI or HTTP Host header) to a friendly app name."""
    sni_lower = sni.lower()
    for keyword, app in APP_SIGNATURES.items():
        if keyword in sni_lower:
            return app
    return "Unknown"
