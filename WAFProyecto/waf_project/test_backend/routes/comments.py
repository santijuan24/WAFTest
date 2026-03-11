"""
Simulated comments endpoint – vulnerable to Stored XSS (for demo).
Comments are stored in memory (no DB) – not sanitized intentionally.
"""

from fastapi import APIRouter
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import List

router = APIRouter(prefix="/comments", tags=["Comments"])

# In-memory store – intentionally not sanitized
_comments: List[dict] = [
    {"id": 1, "author": "Alice", "text": "Great product! Love it."},
    {"id": 2, "author": "Bob",   "text": "Works as expected."},
]
_next_id = 3


class CommentRequest(BaseModel):
    author: str
    text: str


@router.get("/")
def get_comments():
    """Returns all comments – unsanitized (XSS stored demo)."""
    return {"comments": _comments, "count": len(_comments)}


@router.post("/", status_code=201)
def add_comment(body: CommentRequest):
    """
    Adds a comment without sanitizing.
    A vulnerable app would render body.text directly into HTML.
    Payload example: <script>document.cookie</script>
    """
    global _next_id
    comment = {"id": _next_id, "author": body.author, "text": body.text}
    _comments.append(comment)
    _next_id += 1
    return comment


@router.delete("/clear")
def clear_comments():
    """Clears all comments."""
    global _next_id
    _comments.clear()
    _next_id = 1
    return {"ok": True}
