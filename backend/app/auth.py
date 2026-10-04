import hashlib
import csv
import io
import os
import re
import secrets
import subprocess
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

def _restrict_first_login(path):
    if os.name != "nt":
        return
    identity = subprocess.run(["whoami", "/user", "/fo", "csv", "/nh"], capture_output=True, text=True, check=True)
    sid = next(csv.reader(io.StringIO(identity.stdout)))[1]
    if not re.fullmatch(r"S-\d+(?:-\d+)+", sid):
        raise ValueError("Could not determine the local account SID")
    subprocess.run(["icacls", str(path), "/inheritance:r", "/grant:r",
                    f"*{sid}:(F)", "*S-1-5-18:(F)", "*S-1-5-32-544:(F)"],
                   capture_output=True, text=True, check=True)

def bootstrap():
    path = DATA / "first-login.txt"
    created = False
    try:
        with connection() as db:
            if db.execute("SELECT 1 FROM users LIMIT 1").fetchone():
                return
            password = secrets.token_urlsafe(24)
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(path, flags, 0o600)
            created = True
            with os.fdopen(fd, "w", encoding="utf-8") as credential:
                _restrict_first_login(path)
                credential.write(f"Username: investigator\nPassword: {password}\nDelete this file after saving the credential.\n")
            db.execute("INSERT INTO users VALUES(?,?,?,?)", (str(uuid.uuid4()), "investigator", HASHER.hash(password), "administrator"))
    except Exception:
        if created:
            path.unlink(missing_ok=True)
        raise

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
