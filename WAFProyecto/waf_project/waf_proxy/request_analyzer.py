"""
RequestAnalyzer – extracts a flat string representation of a request
that the scoring engine can search for malicious patterns.
"""

import urllib.parse
from fastapi import Request


class RequestAnalyzer:
    @staticmethod
    async def extract(request: Request) -> dict:
        """
        Returns a dict with the fields we log + a combined 'payload' string
        that will be fed into the scoring engine.
        """
        path       = request.url.path
        query      = str(request.url.query)
        user_agent = request.headers.get("user-agent", "")
        method     = request.method
        client_ip  = (
            request.headers.get("x-forwarded-for", "").split(",")[0].strip()
            or (request.client.host if request.client else "unknown")
        )

        # Try to read the body (limited to 64 KB to avoid memory issues)
        try:
            body = await request.body()
            body_str = body.decode("utf-8", errors="replace")[:65_536]
        except Exception:
            body_str = ""

        # Combine everything into one searchable string (URL Decode it!)
        combined = " ".join(filter(None, [path, query, body_str, user_agent]))
        combined_decoded = urllib.parse.unquote(combined)
        # Also decode + as space for form-urlencoded payloads
        combined_decoded = combined_decoded.replace('+', ' ')

        return {
            "ip_address": client_ip,
            "method":     method,
            "path":       path,
            "user_agent": user_agent,
            "payload":    combined_decoded,
            "body":       body_str,
        }
