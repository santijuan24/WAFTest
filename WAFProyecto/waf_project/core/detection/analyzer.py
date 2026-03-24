"""
RequestAnalyzer – extracts and normalizes request data for the scoring engine.

Normalization steps:
  1. Collect path, query string, POST body, and security-relevant headers
  2. Apply double URL-decode to catch encoding evasion
  3. Decode hex entities (\\xNN)
  4. Normalize whitespace and case for consistent pattern matching
"""

import re
import html
import urllib.parse
from fastapi import Request


def _deep_decode(text: str) -> str:
    """Apply multiple decode passes to defeat encoding evasion."""
    if not text:
        return ""
    result = text
    # Double URL-decode (catches %2527 -> %27 -> ')
    for _ in range(2):
        decoded = urllib.parse.unquote(result)
        if decoded == result:
            break
        result = decoded
    # Decode + as space (form-urlencoded)
    result = result.replace("+", " ")
    # Decode HTML entities (&lt; &gt; &amp; &#x27; &#39; etc.)
    result = html.unescape(result)
    # Decode \xNN hex sequences (e.g., \x3c = <)
    result = re.sub(
        r"\\x([0-9a-fA-F]{2})",
        lambda m: chr(int(m.group(1), 16)),
        result,
    )
    # Decode \uNNNN unicode sequences
    result = re.sub(
        r"\\u([0-9a-fA-F]{4})",
        lambda m: chr(int(m.group(1), 16)),
        result,
    )
    # Remove null bytes
    result = result.replace("\x00", "")
    return result


def _extract_header_values(request: Request) -> str:
    """Extract security-relevant header values for inspection."""
    suspicious_headers = [
        "referer", "origin", "cookie",
        "x-forwarded-for", "x-forwarded-host",
        "x-original-url", "x-rewrite-url",
        "content-type",
    ]
    parts = []
    for hdr in suspicious_headers:
        val = request.headers.get(hdr, "")
        if val:
            parts.append(val)
    return " ".join(parts)


class RequestAnalyzer:
    @staticmethod
    async def extract(request: Request) -> dict:
        """
        Returns a dict with log fields + a normalized 'payload' string
        that the scoring engine scans for malicious patterns.
        """
        path = request.url.path
        query = str(request.url.query)
        user_agent = request.headers.get("user-agent", "")
        method = request.method
        client_ip = (
            request.headers.get("x-forwarded-for", "").split(",")[0].strip()
            or (request.client.host if request.client else "unknown")
        )

        # Read body safely (limit 64 KB)
        try:
            body = await request.body()
            body_str = body.decode("utf-8", errors="replace")[:65_536]
        except Exception:
            body_str = ""

        # Collect header values that could contain attack payloads
        header_values = _extract_header_values(request)

        # Build raw combined string
        raw_parts = [path, query, body_str, user_agent, header_values]
        combined_raw = " ".join(filter(None, raw_parts))

        # Apply deep decode normalization
        combined_decoded = _deep_decode(combined_raw)

        return {
            "ip_address": client_ip,
            "method": method,
            "path": path,
            "user_agent": user_agent,
            "payload": combined_decoded,
            "body": body_str,
        }
