from dotenv import load_dotenv
load_dotenv()

from flask import Flask, request, jsonify
from datetime import datetime, timezone, timedelta
from hashlib import sha256
import os, hmac, time
from functools import wraps
from flask_cors import CORS
import psycopg2
from psycopg2.extras import RealDictCursor
import secrets
import string

app = Flask(__name__)
CORS(app)

# =========================
# CONFIG
# =========================

ADMIN_KEY = os.getenv("ADMIN_KEY", "secret123")
ADMIN_HASH = sha256(ADMIN_KEY.encode()).hexdigest()

def db():
    url = os.getenv("DATABASE_URL")
    if not url:
        raise Exception("DATABASE_URL is missing")
    return psycopg2.connect(url, sslmode="require")

# =========================
# RATE LIMIT
# =========================

RATE_LIMIT = {}
RATE_WINDOW = 10
RATE_MAX = 20

def rate_limiter():
    ip = request.remote_addr
    now = time.time()

    requests = RATE_LIMIT.get(ip, [])
    requests = [t for t in requests if now - t < RATE_WINDOW]

    if len(requests) >= RATE_MAX:
        return False

    requests.append(now)
    RATE_LIMIT[ip] = requests
    return True

# =========================
# HELPERS
# =========================

def json_error(msg, code=400):
    return jsonify({"error": msg}), code

def require_auth():
    key = request.headers.get("Authorization")
    if not key:
        return False
    return hmac.compare_digest(
        sha256(key.encode()).hexdigest(),
        ADMIN_HASH
    )

def protected(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not rate_limiter():
            return json_error("rate limit exceeded", 429)
        if not require_auth():
            return json_error("unauthorized", 403)
        return f(*args, **kwargs)
    return wrapper

def generate_key():
    return "-".join(
        ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(4))
        for _ in range(3)
    )

# =========================
# CREATE LICENSE
# =========================
@app.route("/add", methods=["POST"])
@protected
def add_license():
    data = request.get_json(silent=True) or {}

    license_key = data.get("license_key")
    if not license_key:
        return json_error("license_key required")

    try:
        days = int(data.get("days", 7))
    except:
        return json_error("invalid days")

    # checks for 0 or negative days
    if days <= 0:
        return json_error("days must not be 0")

    conn = db()
    c = conn.cursor(cursor_factory=RealDictCursor)

    # duplicate check
    c.execute("SELECT 1 FROM users WHERE license_key=%s", (license_key,))
    if c.fetchone():
        conn.close()
        return json_error("duplicate key")

    expires = datetime.now(timezone.utc) + timedelta(days=days)

    c.execute("""
        INSERT INTO users (license_key, status, expires, banned, bound_device)
        VALUES (%s, %s, %s, %s, %s)
    """, (license_key, "premium", expires, False, None))

    conn.commit()
    conn.close()

    return jsonify({
        "message": "license created",
        "license_key": license_key,
        "expires": expires.isoformat()
    })

# =========================
# VALIDATE + BIND DEVICE
# =========================
@app.route("/validate", methods=["POST"])
def validate():
    data = request.get_json(silent=True) or {}

    license_key = data.get("license_key")
    device_id = data.get("device_id")

    if not license_key or not device_id:
        return json_error("license_key and device_id required")

    conn = db()
    c = conn.cursor(cursor_factory=RealDictCursor)

    c.execute("""
        SELECT license_key, status, expires, banned, bound_device
        FROM users
        WHERE license_key=%s
    """, (license_key,))

    user = c.fetchone()

    if not user:
        conn.close()
        return jsonify({"status": "invalid_key"})

    now = datetime.now(timezone.utc)

    if user["banned"]:
        conn.close()
        return jsonify({"status": "banned"})

    if now > user["expires"]:
        conn.close()
        return jsonify({"status": "expired"})

    # FIRST TIME ACTIVATION
    if not user["bound_device"]:
        c.execute("""
            UPDATE users
            SET bound_device=%s
            WHERE license_key=%s
        """, (device_id, license_key))

        conn.commit()
        conn.close()

        return jsonify({
            "status": "active",
            "license_key": license_key,
            "expires": user["expires"].isoformat(),
            "bound_device": device_id
        })

    # DEVICE CHECK
    if user["bound_device"] != device_id:
        conn.close()
        return jsonify({"status": "device_mismatch"})

    conn.close()
    return jsonify({
        "status": "active",
        "license_key": license_key,
        "expires": user["expires"].isoformat(),
        "bound_device": user["bound_device"]
    })

# =========================
# BAN
# =========================
@app.route("/ban", methods=["POST"])
@protected
def ban():
    data = request.get_json() or {}
    key = data.get("license_key")

    conn = db()
    c = conn.cursor()

    # checks current status
    c.execute("SELECT banned FROM  users WHERE license_key=%s", (key,))
    result = c.fetchone()

    if not result:
        conn.close()
        return  jsonify({"error": "put a key first"}), 404

    if result[0]: # if already banned
        conn.close()
        return jsonify({"error": "already banned"}), 404

    # only update if checks are negative
    c.execute("UPDATE users SET banned=TRUE WHERE license_key=%s", (key,))
    conn.commit()
    conn.close()

    return jsonify({"message": "banned successfully"})

# =========================
# UNBAN
# =========================
@app.route("/unban", methods=["POST"])
@protected
def unban():
    data = request.get_json() or {}
    key = data.get("license_key")

    conn = db()
    c = conn.cursor()

    # checks current status
    c.execute("SELECT banned FROM users WHERE license_key=%s", (key,))
    result = c.fetchone()

    if not result:
        conn.close()
        return jsonify({"error": "put a key first"}), 404

    if not result[0]: # check if already unbanned
        conn.close()
        return jsonify({"error": "already unbanned"}), 404

    # only update if checks are negative
    c.execute("UPDATE users SET banned=FALSE WHERE license_key=%s", (key,))
    conn.commit()
    conn.close()

    return jsonify({"message": "unbanned successfully"})

# =========================
# EXTEND
# =========================
@app.route("/extend", methods=["POST"])
@protected
def extend():
    data = request.get_json() or {}

    key = data.get("license_key")

    try:
        days = int(data.get("days", 1))
    except:
        return json_error("invalid days")

    # checks for 0 or negative days
    if days <= 0:
        return json_error("days must not be 0 or negative")

    conn = db()
    c = conn.cursor(cursor_factory=RealDictCursor)

    c.execute("SELECT expires, banned FROM users WHERE license_key=%s", (key,))
    row = c.fetchone()

    if not row:
        conn.close()
        return json_error("not found or missing key")

    # check for blocked users
    if row["banned"]:
        conn.close()
        return json_error("cannot extend banned account")

    new_exp = row["expires"] + timedelta(days=days)

    c.execute("""
        UPDATE users
        SET expires=%s
        WHERE license_key=%s
    """, (new_exp, key))

    conn.commit()
    conn.close()

    return jsonify({"message": "extended"})

# =========================
# DELETE
# =========================
@app.route("/delete", methods=["POST"])
@protected
def delete():
    data = request.get_json() or {}
    key = data.get("license_key")

    if not key:
        return jsonify({"error": "Put a key first"}), 400

    conn = db()
    c = conn.cursor()

    c.execute("DELETE FROM users WHERE license_key=%s", (key,))
    conn.commit()

    if c.rowcount == 0:
        conn.close()
        return jsonify({"message": "key not found or has been deleted"}), 404
    conn.close()

    return jsonify({"message": "successfully deleted"}), 200

# =========================
# STATS
# =========================
@app.route("/stats", methods=["GET"])
@protected
def stats():
    conn = db()
    c = conn.cursor(cursor_factory=RealDictCursor)

    c.execute("SELECT * FROM users")
    users = c.fetchall()
    conn.close()

    now = datetime.now(timezone.utc)

    total = len(users)
    active = banned = expired = 0

    for u in users:
        if u["banned"]:
            banned += 1
        elif now > u["expires"]:
            expired += 1
        else:
            active += 1

    return jsonify({
        "total": total,
        "active": active,
        "banned": banned,
        "expired": expired
    })

# =========================
# USERS
# =========================
@app.route("/users", methods=["GET"])
@protected
def users():
    conn = db()
    c = conn.cursor(cursor_factory=RealDictCursor)

    c.execute("SELECT * FROM users")
    rows = c.fetchall()
    conn.close()

    now = datetime.now(timezone.utc)

    result = []
    for u in rows:
        days_left = max(int((u["expires"] - now).total_seconds() / 86400), 0)

        result.append({
            "license_key": u["license_key"],
            "bound_device": u["bound_device"] or "NOT_BOUND",
            "status": u["status"],
            "banned": u["banned"],
            "days_left": days_left,
            "expires": u["expires"].isoformat()
        })

    return jsonify({"users": result})

# =========================
# RUN
# =========================
if __name__ == "__main__":
    app.run(debug=True)