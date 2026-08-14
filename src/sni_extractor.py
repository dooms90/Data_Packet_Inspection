"""
sni_extractor.py
-----------------
Equivalent of include/sni_extractor.h + src/sni_extractor.cpp.

Purpose: Extract the domain name a connection is heading to, even though
HTTPS traffic is encrypted -- the destination hostname (SNI) is sent in
plaintext inside the first TLS packet (Client Hello). We also handle plain
HTTP "Host:" headers the same way the C++ HTTPHostExtractor did.
"""

from typing import Optional


class SNIExtractor:
    """Extracts the Server Name Indication (SNI) from a TLS Client Hello."""

    @staticmethod
    def extract(payload: bytes) -> Optional[str]:
        try:
            if len(payload) < 6:
                return None
            if payload[0] != 0x16:      # Content Type: Handshake
                return None
            if payload[5] != 0x01:      # Handshake Type: Client Hello
                return None

            offset = 43  # skip: record header(5) + handshake header(4) + version(2) + random(32)

            session_len = payload[offset]
            offset += 1 + session_len

            cipher_len = int.from_bytes(payload[offset:offset + 2], "big")
            offset += 2 + cipher_len

            comp_len = payload[offset]
            offset += 1 + comp_len

            ext_total_len = int.from_bytes(payload[offset:offset + 2], "big")
            offset += 2
            ext_end = offset + ext_total_len

            while offset + 4 <= ext_end:
                ext_type = int.from_bytes(payload[offset:offset + 2], "big")
                ext_len = int.from_bytes(payload[offset + 2:offset + 4], "big")
                offset += 4

                if ext_type == 0x0000:  # SNI extension
                    sni_len = int.from_bytes(payload[offset + 3:offset + 5], "big")
                    sni_bytes = payload[offset + 5:offset + 5 + sni_len]
                    return sni_bytes.decode("utf-8", errors="ignore")

                offset += ext_len

            return None
        except (IndexError, ValueError):
            return None


class HTTPHostExtractor:
    """Extracts the "Host:" header value from a plain HTTP request."""

    @staticmethod
    def extract(payload: bytes) -> Optional[str]:
        try:
            text = payload.decode("utf-8", errors="ignore")
            if not any(text.startswith(m) for m in ("GET ", "POST ", "HEAD ", "PUT ")):
                return None
            for line in text.split("\r\n"):
                if line.lower().startswith("host:"):
                    return line.split(":", 1)[1].strip()
            return None
        except Exception:
            return None
