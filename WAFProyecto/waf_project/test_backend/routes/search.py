"""
Vulnerable search route – raw SQL query WITHOUT parameterization.
Reflects XSS content and runs unsanitized SQL LIKE queries.
"""

from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse
from test_backend.demo_db import get_conn

router = APIRouter(prefix="/search", tags=["Search"])


@router.get("/")
def search(q: str = Query(default="", description="Search query – vulnerable to SQLi & XSS")):
    """
    Intentionally vulnerable product search.
    Raw SQL: SELECT * FROM products WHERE name LIKE '%<q>%'
    
    SQLi payloads that work (direct port 5000):
      q=' OR '1'='1
      q=x' UNION SELECT id,username,password,email,role,created FROM users --
      q=' UNION SELECT 1,2,3,4,5,6 --  (UNION column count probe)
    """
    if not q:
        raw_query = "SELECT * FROM products"
    else:
        # ⚠️ VULNERABLE – raw string interpolation
        raw_query = f"SELECT * FROM products WHERE name LIKE '%{q}%' OR category LIKE '%{q}%'"

    try:
        conn = get_conn()
        c = conn.cursor()
        c.execute(raw_query)
        rows = [dict(r) for r in c.fetchall()]
        conn.close()
        return {
            "query":      q,
            "query_sql":  raw_query,
            "count":      len(rows),
            "results":    rows,
        }
    except Exception as e:
        return JSONResponse(
            status_code=400,
            content={"error": str(e), "query_sql": raw_query},
        )


@router.get("/users")
def list_users():
    """List all users (for demo purposes)."""
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT id, username, email, role, created FROM users")
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return {"users": rows, "count": len(rows)}
