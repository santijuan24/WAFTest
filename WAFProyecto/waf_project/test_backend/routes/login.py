"""
Vulnerable login route – raw SQL query WITHOUT parameterization.
When WAF is bypassed, SQLi payloads like ' OR 1=1 -- actually work.
"""

from fastapi import APIRouter, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from test_backend.demo_db import get_conn

router = APIRouter(prefix="/login", tags=["Auth"])


class LoginRequest(BaseModel):
    username: str
    password: str


@router.post("/")
def login(body: LoginRequest, response: Response):
    """
    Intentionally vulnerable login.
    Raw SQL: SELECT * FROM users WHERE username='<input>' AND password='<input>'
    
    Try via WAF proxy (port 9000) to see it blocked.
    Try directly (port 5000) to see the raw SQLi result.
    
    SQLi payloads that work:
      username: ' OR 1=1 --
      username: admin' --
      username: ' UNION SELECT id,username,password,email,role,created FROM users --
    """
    # ⚠️ VULNERABLE – raw string interpolation, no parameterization
    raw_query = (
        f"SELECT * FROM users WHERE username='{body.username}' "
        f"AND password='{body.password}'"
    )

    try:
        conn = get_conn()
        c = conn.cursor()
        c.execute(raw_query)   # ← SQL Injection happens here
        rows = c.fetchall()
        conn.close()

        if rows:
            users_found = [dict(r) for r in rows]
            # set a simple session cookie so the browser stays "logged in" after bypass
            response.set_cookie(key="session", value=users_found[0].get("username",""), max_age=86400)
            return {
                "status":     "success",
                "message":    f"Welcome! {len(users_found)} user(s) matched.",
                "users":      users_found,   # leaks ALL matched rows
                "query_used": raw_query,     # leaks the query for educational purposes
            }
        return {
            "status":     "failure",
            "detail":     "Invalid credentials",
            "query_used": raw_query,
        }
    except Exception as e:
        return JSONResponse(
            status_code=400,
            content={"status": "error", "detail": str(e), "query_used": raw_query},
        )


@router.get("/form")
def login_form():
    return {"fields": ["username", "password"], "method": "POST", "action": "/login/"}
