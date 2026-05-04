from dotenv import load_dotenv
load_dotenv()

from flask import Flask, request, jsonify, g
from datetime import datetime, timezone, timedelta
from functools import wraps
from flask_cors import CORS
import psycopg2
from psycopg2.extras import RealDictCursor
import os
import time
import jwt
import bcrypt
from psycopg2 import OperationalError

#use to create hash password when adding new admin
#print(bcrypt.hashpw("my password here".encode(), bcrypt.gensalt()).decode())

SECRET_KEY = os.getenv("JWT_SECRET")
if not SECRET_KEY:
    raise RuntimeError("JWT SECRET is missing")

app = Flask(__name__)
CORS(app, origins=["https://licenseui.onrender.com"]) #talks to frontend

# =========================
# RBAC
# =========================
def roles_required(*roles):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):

            #prevent crash if role missing
            if not hasattr(g, "role"):
                return jsonify({"error": "unauthorized"}), 403

            if g.role not in roles:
                return jsonify({"error": "forbidden"}), 403

            return f(*args, **kwargs)

        return wrapper
    return decorator

# =========================
# DB (DataBase)
# =========================
def db():
    url = os.getenv("DATABASE_URL")
    if not url:
        raise Exception("DATABASE URL is missing")
    return psycopg2.connect(url, sslmode="require")

# =========================
# RATE LIMIT
# =========================
RATE_LIMIT = {}
RATE_WINDOW = 10
RATE_MAX = 20

def rate_limiter():
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    now = time.time()

    requests = RATE_LIMIT.get(ip, [])
    requests = [t for t in requests if now - t < RATE_WINDOW]

    if len(requests) >= RATE_MAX:
        return False

    requests.append(now)
    RATE_LIMIT[ip] = requests
    return True

# =========================
# HELPERS - might add helpers soon to decrease line of codes :)
# =========================
def json_error(msg, code=400):
    return jsonify({"error": msg}), code

# =========================
# JWT MIDDLEWARE - backend protection
# =========================
def token_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization")

        if not auth:
            return jsonify({"error": "missing token"}), 403

        #safer parsing
        token = auth.replace("Bearer ", "").strip()

        try:
            decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            g.user = decoded["user"]
            g.role = decoded["role"]
            g.admin_id = decoded["admin_id"]

        except jwt.ExpiredSignatureError:
            return jsonify({"error": "token expired"}), 403

        except jwt.InvalidTokenError:
            return jsonify({"error": "invalid token"}), 403

        return f(*args, **kwargs)

    return wrapper

# =========================
# LOGIN
# =========================
@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}

    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"error": "missing credentials"}), 400
    try:
        conn = db()
    except OperationalError:
        return jsonify({"error": "database connection failed"}), 500

    c = conn.cursor(cursor_factory=RealDictCursor)

    c.execute(
        "SELECT * FROM admins WHERE username=%s",
        (username,)
    )

    admin = c.fetchone()
    conn.close()

    if not admin:
        return jsonify({"error": "invalid credentials"}), 401

    # bcrypt check
    if not bcrypt.checkpw(
        password.encode(),
        admin["password_hash"].encode()
    ):
        return jsonify({"error": "invalid credentials"}), 401

    payload = {
        "user": username,
        "role": admin["role"],
        "admin_id": admin["id"],
        "exp": datetime.now(timezone.utc) + timedelta(hours=2)
    }

    token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")

    return jsonify({
        "message": "login successful",
        "token": token
    })

# =========================
# CREATE LICENSE
# =========================
@app.route("/add", methods=["POST"])
@token_required
@roles_required("admin", "moderator")
def add_license():
    data = request.get_json(silent=True) or {}

    license_key = data.get("license_key")
    if not license_key:
        return json_error("license key required")
    try:
        days = int(data.get("days", 7))
    except (TypeError, ValueError):
        return json_error("invalid days")

    if days <= 0:
        return json_error("days must be greater than 0")


    try:
        conn = db()
    except psycopg2.OperationalError: #catch error coming from db only
        return jsonify({"error": "database connection failed"}), 500

    c = conn.cursor(cursor_factory=RealDictCursor)

    c.execute("SELECT 1 FROM users WHERE license_key=%s", (license_key,))
    if c.fetchone():
        conn.close()
        return json_error("key already exist")

    expires = datetime.now(timezone.utc) + timedelta(days=days)

    c.execute("""
        INSERT INTO users (license_key, status, expires, banned, bound_device, admin_id)
        VALUES (%s, %s, %s, %s, %s, %s)
    """, (license_key, "premium", expires, False, None, g.admin_id))

    conn.commit()
    conn.close()

    return jsonify({
        "message": "license created",
        "license_key": license_key,
        "expires": expires.isoformat()
    })

# =========================
# VALIDATE - this where apps connect to validate their keys, ex. expiry, banned, etc.
# =========================
@app.route("/validate", methods=["POST"])
def validate():
    if not rate_limiter():
        return jsonify({"status": "rate_limited"}), 429

    data = request.get_json(silent=True) or {}

    license_key = data.get("license_key")
    device_id = data.get("device_id")

    if not license_key or not device_id:
        return json_error("license and device id required")

    try:
        conn = db()
    except OperationalError:
        return jsonify({"error": "database connection failed"}), 500

    c = conn.cursor(cursor_factory=RealDictCursor)

    c.execute("""
        SELECT license_key, status, expires, banned, bound_device
        FROM users
        WHERE license_key=%s
    """, (license_key,))

    user = c.fetchone()

    if not user:
        conn.close()
        return jsonify({"status": "invalid key"})

    now = datetime.now(timezone.utc)

    if user["banned"]:
        conn.close()
        return jsonify({"status": "banned"})

    if now > user["expires"]:
        conn.close()
        return jsonify({"status": "expired"})

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

    if user["bound_device"] != device_id:
        conn.close()
        return jsonify({"status": "device mismatch"})

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
@token_required
@roles_required("admin", "moderator")
def ban():
    data = request.get_json(silent=True) or {}
    key = data.get("license_key")

    if not key:
        return json_error("license key required")

    try:
        conn = db()
    except OperationalError:
        return jsonify({"error": "database connection failed"}), 500

    c = conn.cursor(cursor_factory=RealDictCursor)

    # check first
    c.execute("""
        SELECT banned FROM users
        WHERE license_key=%s AND admin_id=%s
    """, (key, g.admin_id))

    row = c.fetchone()

    if not row:
        conn.close()
        return json_error("not found")

    if row["banned"]:
        conn.close()
        return json_error("already banned")

    # update
    c.execute("""
        UPDATE users
        SET banned=TRUE
        WHERE license_key=%s AND admin_id=%s
    """, (key, g.admin_id))

    conn.commit()
    conn.close()

    return jsonify({"message": "banned successfully"})

# =========================
# UNBAN
# =========================
@app.route("/unban", methods=["POST"])
@token_required
@roles_required("admin", "moderator")
def unban():
    data = request.get_json(silent=True) or {}
    key = data.get("license_key")

    if not key:
        return json_error("license key required")

    try:
        conn = db()
    except OperationalError:
        return jsonify({"error": "database connection failed"}), 500

    c = conn.cursor(cursor_factory=RealDictCursor)

    c.execute("""
        SELECT banned FROM users
        WHERE license_key=%s AND admin_id=%s
    """, (key, g.admin_id))

    row = c.fetchone()

    if not row:
        conn.close()
        return json_error("not found")

    if not row["banned"]:
        conn.close()
        return json_error("already unbanned")

    c.execute("""
        UPDATE users
        SET banned=FALSE
        WHERE license_key=%s AND admin_id=%s
    """, (key, g.admin_id))

    conn.commit()
    conn.close()

    return jsonify({"message": "unbanned successfully"})

# =========================
# EXTEND
# =========================
@app.route("/extend", methods=["POST"])
@token_required
@roles_required("admin", "moderator")
def extend():
    data = request.get_json(silent=True) or {}

    key = data.get("license_key")
    if not key:
        return json_error("license key required")

    # FIX: only catch real input errors
    try:
        days = int(data.get("days", 1))
    except (ValueError, TypeError):
        return json_error("invalid days")

    if days <= 0:
        return json_error("days must be greater than 0")

    try:
        conn = db()
    except OperationalError:
        return jsonify({"error": "database connection failed"}), 500

    c = conn.cursor(cursor_factory=RealDictCursor)

    c.execute("""
        SELECT expires, banned 
        FROM users
        WHERE license_key=%s AND admin_id=%s
    """, (key, g.admin_id))

    row = c.fetchone()

    if not row:
        conn.close()
        return json_error("invalid key")

    if row["banned"]:
        conn.close()
        return json_error("cannot extend banned account")

    new_exp = row["expires"] + timedelta(days=days)

    c.execute("""
        UPDATE users
        SET expires=%s
        WHERE license_key=%s AND admin_id=%s
    """, (new_exp, key, g.admin_id))

    conn.commit()
    conn.close()

    return jsonify({
        "message": "extended",
        "new_expiry": new_exp.isoformat()
    })

# =========================
# DELETE
# =========================
@app.route("/delete", methods=["POST"])
@token_required
@roles_required("admin", "moderator")
def delete():
    data = request.get_json(silent=True) or {}
    key = data.get("license_key")

    if not key:
        return json_error("license key required")

    try:
        conn = db()
    except OperationalError:
        return jsonify({"error": "database connection failed"}), 500
    c = conn.cursor()

    c.execute("""
        DELETE FROM users
        WHERE license_key=%s AND admin_id=%s
    """, (key, g.admin_id))
    conn.commit()

    if c.rowcount == 0:
        conn.close()
        return jsonify({"message": "key not found"}), 404

    conn.close()
    return jsonify({"message": "successfully deleted"}), 200

# =========================
# STATS
# =========================
@app.route("/stats", methods=["GET"])
@token_required
@roles_required("admin", "moderator")
def stats():

    try:
        conn = db()
    except OperationalError:
        return jsonify({"error": "database connection failed"}), 500
    c = conn.cursor(cursor_factory=RealDictCursor)

    c.execute("""
        SELECT * FROM users
        WHERE admin_id = %s
    """, (g.admin_id,))
    records = c.fetchall()
    conn.close()

    now = datetime.now(timezone.utc)

    total = len(records)
    active = banned = expired = 0

    for u in records:
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
@token_required
@roles_required("admin", "moderator")
def users():

    try:
        conn = db()
    except OperationalError:
        return jsonify({"error": "database connection failed"}), 500

    c = conn.cursor(cursor_factory=RealDictCursor)

    c.execute("""
        UPDATE users
        SET state = CASE
            WHEN expires < NOW() THEN 'expired'
            ELSE 'active'
        END
        WHERE admin_id = %s
    """, (g.admin_id,))
    conn.commit()

    c.execute("""
        SELECT * FROM users
        WHERE admin_id = %s
    """, (g.admin_id,))

    rows = c.fetchall()
    conn.close()

    now = datetime.now(timezone.utc)

    result = []

    for u in rows:

        remaining_seconds = int((u["expires"] - now).total_seconds())

        if remaining_seconds <= 0:
            time_left = "expired"
        else:
            days = remaining_seconds // 86400
            hours = (remaining_seconds % 86400) // 3600
            minutes = (remaining_seconds % 3600) // 60

            if days > 0:
                time_left = f"{days}d {hours}h"
            elif hours > 0:
                time_left = f"{hours}h {minutes}m"
            else:
                time_left = f"{minutes}m"

        result.append({
            "license_key": u["license_key"],
            "bound_device": u["bound_device"] or "not bound",
            "status": u["status"],
            "banned": u["banned"],
            "state": u["state"],
            "time_left": time_left,
            "expires": u["expires"].isoformat()
        })

    return jsonify({"users": result})

# =========================
# RUN
# =========================

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        debug=False
    )