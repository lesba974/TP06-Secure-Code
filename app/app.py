"""MiniShop : application FastAPI VOLONTAIREMENT VULNÉRABLE (support du TP Cours 7).

Ne jamais déployer ce code tel quel. Votre mission : le rendre conforme.
Documentation interactive : http://localhost:5000/docs
"""
import ast
import logging
import os
import sqlite3
import subprocess
import traceback
import operator
import html
import requests
import uvicorn
import yaml
import secrets
from pydantic import BaseModel
from fastapi import Body, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse
from starlette.middleware.sessions import SessionMiddleware
from ipaddress import ip_address
from pathlib import Path
from urllib.parse import urlparse
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from fastapi import Depends


SECRET_KEY = os.environ["SECRET_KEY"]
DB_PATH = os.environ.get("DB_PATH", "shop.db")
UPLOAD_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "uploads")

logging.INFO
log = logging.getLogger("minishop")

app = FastAPI(title="MiniShop", debug=True)
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY, https_only=True, same_site="lax")

def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

ph = PasswordHasher()

def verify_password(hashed: str, password: str) -> bool:
    try:
        return ph.verify(hashed, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False

def init_db():
    conn = db()
    conn.executescript(
        """
        DROP TABLE IF EXISTS users;
        DROP TABLE IF EXISTS products;
        DROP TABLE IF EXISTS invoices;
        CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT UNIQUE,
                            password TEXT, is_admin INTEGER DEFAULT 0);
        CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, price REAL);
        CREATE TABLE invoices (id INTEGER PRIMARY KEY, owner_id INTEGER,
                               label TEXT, amount REAL);
        """
    )
    conn.execute("INSERT INTO users (username, password, is_admin) VALUES (?, ?, 1)",
                 ("admin", ph.hash("admin123")))
    conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", ("alice", ph.hash("alice123")))
    conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", ("bob", ph.hash("bob123")))
    conn.executemany("INSERT INTO products (name, price) VALUES (?, ?)",
                     [("apple", 1.2), ("banana", 0.8), ("cherry", 3.5)])
    conn.executemany("INSERT INTO invoices (owner_id, label, amount) VALUES (?, ?, ?)",
                     [(2, "Facture Alice", 42.0), (3, "Facture Bob", 99.0)])
    conn.commit()
    conn.close()

@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["X-Frame-Options"] = "DENY"
    return response

@app.exception_handler(Exception)
async def handle_error(request: Request, exc: Exception):
    return HTMLResponse("<pre>" + traceback.format_exc() + "</pre>", status_code=500)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/login")
def login(request: Request, data: dict = Body(...)):
    username, password = data["username"], data["password"]
    log.info("login attempt user=%s", username) 
    row = db().execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    if not row or not verify_password(row["password"], password):
        return JSONResponse({"error": "bad credentials"}, status_code=401)
    request.session["user_id"] = row["id"]
    request.session["token"] = secrets.token_urlsafe(32)
    return {"status": "logged in", "user": row["username"]}


@app.get("/search")
def search(q: str = ""):
    rows = db().execute(
        "SELECT id, name, price FROM products WHERE name LIKE ?", (f"%{q}%",)
    ).fetchall()
    return [dict(r) for r in rows]


@app.get("/ping")
def ping(host: str = "127.0.0.1"):
    try:
        ip = str(ip_address(host))
    except ValueError:
        raise HTTPException(status_code=400, detail="invalid IP address")
    try:
        out = subprocess.run(
            ["ping", "-c", "1", "-W", "2", ip],
            capture_output=True, text=True, timeout=5,
        )
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="ping timeout")
    return PlainTextResponse(out.stdout + out.stderr)


@app.get("/hello")
def hello(name: str = ""):
    return HTMLResponse(f"<h1>Bonjour {html.escape(name)}</h1>")

UPLOAD_PATH = Path(UPLOAD_DIR).resolve()

@app.get("/files/{name:path}")
def get_file(name: str):
    target = (UPLOAD_PATH / name).resolve()
    if not target.is_relative_to(UPLOAD_PATH) or not target.is_file():
        raise HTTPException(status_code=404, detail="not found")
    return FileResponse(target)

OPS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
}

def safe_eval(node):
    if isinstance(node, ast.Expression):
        return safe_eval(node.body)
    if (isinstance(node, ast.Constant)
            and isinstance(node.value, (int, float))
            and not isinstance(node.value, bool)):
        return node.value
    if isinstance(node, ast.BinOp) and type(node.op) in OPS:
        return OPS[type(node.op)](safe_eval(node.left), safe_eval(node.right))
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.USub, ast.UAdd)):
        value = safe_eval(node.operand)
        return -value if isinstance(node.op, ast.USub) else value
    raise ValueError("expression not allowed")


@app.post("/calc")
def calc(data: dict = Body(...)):
    expr = data.get("expr")
    if not isinstance(expr, str) or len(expr) > 200:
        raise HTTPException(status_code=400, detail="invalid expression")
    try:
        result = safe_eval(ast.parse(expr, mode="eval"))
    except (ValueError, SyntaxError, ZeroDivisionError):
        raise HTTPException(status_code=400, detail="invalid expression")
    return {"result": str(result)}


@app.post("/import-yaml")
async def import_yaml(request: Request):
    try:
        cfg = yaml.safe_load(await request.body())
    except yaml.YAMLError:
        raise HTTPException(status_code=400, detail="invalid YAML")
    return {"keys": list(cfg.keys()) if isinstance(cfg, dict) else str(type(cfg))}


class Profile(BaseModel):
    username: str
    email: str


@app.post("/import-profile")
def import_profile(profile: Profile):
    return {"profile": profile.model_dump()}

ALLOWED_HOSTS = {"example.com"}

@app.get("/fetch")
def fetch(url: str):
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in ALLOWED_HOSTS:
        raise HTTPException(status_code=400, detail="url not allowed")
    try:
        r = requests.get(url, timeout=5, verify=True, allow_redirects=False)
    except requests.RequestException:
        raise HTTPException(status_code=502, detail="upstream error")
    return PlainTextResponse(r.text[:500])

def current_user(request: Request) -> dict:
    uid = request.session.get("user_id")
    row = None
    if uid is not None:
        row = db().execute(
            "SELECT id, username, is_admin FROM users WHERE id = ?", (uid,)
        ).fetchone()
    if not row:
        raise HTTPException(status_code=401, detail="login required")
    return dict(row)

@app.get("/invoices/{invoice_id}")
def invoice(invoice_id: int, user: dict = Depends(current_user)):
    row = db().execute(
        "SELECT * FROM invoices WHERE id = ? AND owner_id = ?",
        (invoice_id, user["id"]),
    ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="not found")
    return dict(row)

ROLE_PERMISSIONS = {
    "admin": {"user:list", "user:delete"},
    "user": set(),
}

def require(permission: str):
    def checker(user: dict = Depends(current_user)) -> dict:
        role = "admin" if user["is_admin"] else "user"
        if permission not in ROLE_PERMISSIONS.get(role, set()):
            raise HTTPException(status_code=403, detail="forbidden")
        return user
    return checker

@app.get("/admin/users")
def admin_users(user: dict = Depends(require("user:list"))):
    rows = db().execute("SELECT id, username, is_admin FROM users").fetchall()
    return [dict(r) for r in rows]

@app.delete("/users/{user_id}")
def delete_user(user_id: int, user: dict = Depends(require("user:delete"))):
    conn = db()
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    return {"deleted": user_id}


@app.get("/boom")
def boom():
    return 1 / 0


if __name__ == "__main__":
    init_db()
    uvicorn.run("app:app", host="0.0.0.0", port=5000, reload=True)
