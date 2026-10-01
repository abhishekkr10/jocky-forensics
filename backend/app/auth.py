import hashlib
import os
import secrets
import time
import uuid
from argon2 import PasswordHasher
from fastapi import Request, HTTPException
from .db import connection
from .core import DATA

HASHER = PasswordHasher()
def token_hash(value): return hashlib.sha256(value.encode()).hexdigest()

def create_user(username, password, role="administrator"):
    if len(password) < 12: raise ValueError("Password must have at least 12 characters")
    with connection() as db:
        db.execute("INSERT INTO users VALUES(?,?,?,?)", (str(uuid.uuid4()),username,HASHER.hash(password),role))

def bootstrap():
    with connection() as db:
        exists = db.execute("SELECT 1 FROM users LIMIT 1").fetchone()
    if not exists:
        password = secrets.token_urlsafe(24)
        create_user("investigator", password)
        path = DATA / "first-login.txt"
        path.write_text(f"Username: investigator\nPassword: {password}\nDelete this file after saving the credential.\n")
        path.chmod(0o600)

def clear_first_login_credential(username):
    if username == "investigator":
        (DATA / "first-login.txt").unlink(missing_ok=True)

def current_user(request: Request):
    token = request.cookies.get("jocky_session", "")
    with connection() as db:
        row = db.execute("SELECT users.*,sessions.csrf FROM sessions JOIN users ON users.id=sessions.user_id WHERE token_hash=? AND expires_at>?", (token_hash(token),time.time())).fetchone()
    if not row: raise HTTPException(401,"Authentication required")
    if request.method not in {"GET","HEAD","OPTIONS"} and not secrets.compare_digest(request.headers.get("X-CSRF-Token",""),row["csrf"]):
        raise HTTPException(403,"CSRF token required")
    return dict(row)

def writer(user):
    if user["role"] not in {"administrator","investigator"}: raise HTTPException(403,"Investigator role required")

def administrator(user):
    if user["role"] != "administrator": raise HTTPException(403,"Administrator role required")
    return user
