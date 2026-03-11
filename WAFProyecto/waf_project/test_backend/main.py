"""
Vulnerable test backend – simulates a real web application.
Port: 5000  (target of WAF proxy forwarding)
Run from inside waf_project/ with:
  python -m uvicorn test_backend.main:app --port 5000 --reload
"""

import os

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from test_backend.demo_db import init_demo_db
from test_backend.routes import login, search, comments

app = FastAPI(
    title="ShopVuln – Vulnerable Test App",
    description="Intentionally vulnerable app for WAF demo. Do NOT deploy in production.",
    version="2.0.0",
    docs_url="/backend-docs",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), "templates")
templates = Jinja2Templates(directory=TEMPLATES_DIR)


@app.on_event("startup")
def startup():
    init_demo_db()
    print("[Test Backend] ShopVuln running on port 5000")


app.include_router(login.router)
app.include_router(search.router)
app.include_router(comments.router)


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    """Main page – simulated vulnerable web app."""
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/health")
def health():
    return {"status": "running", "component": "Test Backend / ShopVuln", "port": 5000}
