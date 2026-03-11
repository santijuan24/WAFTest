"""
ProxyHandler – forwards an allowed request to the backend test server
and returns its response.

Uses httpx for async HTTP forwarding.
"""

import httpx
from fastapi import Request, Response
from fastapi.responses import JSONResponse
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from config import BACKEND_URL

# Shared async client (connection-pooled)
_client = httpx.AsyncClient(base_url=BACKEND_URL, timeout=10.0)


async def forward(request: Request, body: bytes) -> Response:
    """
    Forward the request to the backend and return a FastAPI-compatible Response.
    Strips hop-by-hop headers that must not be forwarded.
    """
    _HOP_BY_HOP = {
        "connection", "keep-alive", "proxy-authenticate",
        "proxy-authorization", "te", "trailers",
        "transfer-encoding", "upgrade", "host",
    }

    forward_headers = {
        k: v for k, v in request.headers.items()
        if k.lower() not in _HOP_BY_HOP
    }

    url = str(request.url.path)
    if request.url.query:
        url = f"{url}?{request.url.query}"

    try:
        backend_resp = await _client.request(
            method=request.method,
            url=url,
            headers=forward_headers,
            content=body,
        )
        return Response(
            content=backend_resp.content,
            status_code=backend_resp.status_code,
            headers=dict(backend_resp.headers),
            media_type=backend_resp.headers.get("content-type"),
        )
    except httpx.ConnectError:
        return JSONResponse(
            status_code=502,
            content={"error": "Backend unavailable", "backend": BACKEND_URL},
        )
    except httpx.TimeoutException:
        return JSONResponse(
            status_code=504,
            content={"error": "Backend timed out"},
        )
