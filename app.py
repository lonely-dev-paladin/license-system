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

SECRET_KEY = os.getenv("JWT_SECRET")
if not SECRET_KEY:
    raise RuntimeError("JWT SECRET is missing")

app = Flask(__name__)
CORS(app, origins=["https://licenseui.onrender.com"])  # talks to frontend

# =========================
# RBAC
# =========================
def roles_required(*roles):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if not hasattr(g, "role"):
                return jsonify({"error": "unauthorized"}), 403
            if g.role not in roles:
                return jsonify({"error": "forbidden"}), 403
            return f(*args, **kwargs)
        return wrapper
    return decorator

# =========================
# DB
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
RATE_WINDOW = 60
RATE_MAX_IP = 30
RATE_MAX_USER = 5

# only sweep occasionally instead of every request, so we don't
# pay the cleanup cost on every single call
_LAST_SWEEP = 0
SWEEP_INTERVAL = 300  # 5 minutes


def _sweep_rate_limit(now):
    global _LAST_SWEEP
    if now - _LAST_SWEEP < SWEEP_INTERVAL:
        return
    _LAST_SWEEP = now
    dead_keys = []
    for key, history in RATE_LIMIT.items():
        fresh = [t for t in history if now - t < RATE_WINDOW]
        if fresh:
            RATE_LIMIT[key] = fresh
        else:
            dead_keys.append(key)
    for key in dead_keys:
        RATE_LIMIT.pop(key, None)


def get_client_ip():
    ip = request.headers.get("X-Forwarded-For")
    if ip:
        ip = ip.split(",")[0].strip()
    else:
        ip = request.remote_addr
    return ip or "unknown"


def rate_limiter(username=None):
    ip = get_client_ip()
    now = time.time()
    _sweep_rate_limit(now)

    ip_key = f"ip:{ip}"
    user_key = f"user:{username}" if username else None

    def check_limit(key, limit):
        history = list(RATE_LIMIT.get(key) or [])
        history = [t for t in history if now - t < RATE_WINDOW]
        if len(history) >= limit:
            RATE_LIMIT[key] = history
            return False
        history.append(now)
        RATE_LIMIT[key] = history
        return True

    if not check_limit(ip_key, RATE_MAX_IP):
        return False

    if user_key:
        if not check_limit(user_key, RATE_MAX_USER):
            return False

    return True

# =========================
# HELPERS
# =========================
def json_error(msg, code=400):
    return jsonify({"error": msg}), code


# a hash of a value nobody will ever guess, used purely so failed logins
# on unknown usernames still pay the bcrypt cost (timing-attack mitigation)
_DUMMY_HASH = bcrypt.hashpw(b"dummy-password-for-timing", bcrypt.gensalt()).decode()

MAX_LICENSE_DAYS = 3650  # 10 years, sanity cap


def valid_license_key(key: str) -> bool:
    if not isinstance(key, str):
        return False
    if not (4 <= len(key) <= 128):
        return False
    return all(c.isalnum() or c in "-_" for c in key)


def log_audit(conn, admin_id, action, target=None, details=None):
    """Best-effort audit log write. Never blocks the main request on failure."""
    try:
        c = conn.cursor()
        c.execute(
            """
            INSERT INTO audit_log (admin_id, action, target, details, created_at)
            VALUES (%s, %s, %s, %s, NOW())
            """,
            (admin_id, action, target, details),
        )
    except Exception as e:
        print("AUDIT LOG ERROR:", e)

# =========================
# JWT MIDDLEWARE
# =========================
def token_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization")
        if not auth:
            return jsonify({"error": "missing token"}), 403

        token = auth.replace("Bearer ", "").strip()

        try:
            decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            admin_id = decoded["admin_id"]

            conn = db()
            c = conn.cursor()
            c.execute("SELECT id FROM admins WHERE id=%s", (admin_id,))
            admin = c.fetchone()
            conn.close()

            if not admin:
                return jsonify({"error": "admin no longer exists"}), 403

            g.user = decoded["user"]
            g.role = decoded["role"]
            g.admin_id = admin_id

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
    if not rate_limiter():
        return jsonify({"error": "too many requests!"}), 429

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
    c.execute("SELECT * FROM admins WHERE username=%s", (username,))
    admin = c.fetchone()
    conn.close()

    # Always check a password hash, even for unknown usernames, so
    # response time doesn't leak whether the username exists.
    hash_to_check = admin["password_hash"] if admin else _DUMMY_HASH
    password_ok = bcrypt.checkpw(password.encode(), hash_to_check.encode())

    if not admin or not password_ok:
        return jsonify({"error": "invalid credentials"}), 401

    payload = {
        "user": username,
        "role": admin["role"],
        "admin_id": admin["id"],
        "exp": datetime.now(timezone.utc) + timedelta(hours=2)
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")

    return jsonify({"message": "login successful", "token": token})

# =========================
# CREATE LICENSE
# =========================
@app.route("/add", methods=["POST"])
@token_required
@roles_required("admin", "moderator", "superadmin")
def add_license():
    data = request.get_json(silent=True) or {}

    license_key = data.get("license_key")
    if not license_key or not valid_license_key(license_key):
        return json_error("license key required (4-128 alphanumeric/-/_ chars)")

    try:
        days = int(data.get("days", 7))
    except (TypeError, ValueError):
        return json_error("invalid days")

    if days <= 0 or days > MAX_LICENSE_DAYS:
        return json_error(f"days must be between 1 and {MAX_LICENSE_DAYS}")

    try:
        conn = db()
    except OperationalError:
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

    log_audit(conn, g.admin_id, "create_license", license_key, f"days={days}")

    conn.commit()
    conn.close()

    return jsonify({
        "message": "license created",
        "license_key": license_key,
        "expires": expires.isoformat()
    })

# =========================
# VALIDATE
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
        # Atomic claim: only succeeds if bound_device is still NULL at write time,
        # so two concurrent requests can't both bind different devices.
        c.execute("""
            UPDATE users
            SET bound_device=%s
            WHERE license_key=%s AND bound_device IS NULL
            RETURNING bound_device
        """, (device_id, license_key))
        claimed = c.fetchone()
        conn.commit()

        if claimed:
            conn.close()
            return jsonify({
                "status": "active",
                "license_key": license_key,
                "expires": user["expires"].isoformat(),
                "bound_device": device_id
            })

        # Someone else claimed it in the tiny window between our SELECT and UPDATE.
        c.execute("SELECT bound_device FROM users WHERE license_key=%s", (license_key,))
        user = c.fetchone()
        conn.close()
        if user["bound_device"] != device_id:
            return jsonify({"status": "device mismatch"})
        return jsonify({"status": "active", "license_key": license_key, "bound_device": device_id})

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
# RESET DEVICE (new)
# =========================
@app.route("/reset-device", methods=["POST"])
@token_required
@roles_required("admin", "moderator", "superadmin")
def reset_device():
    """Unbind a license from its device so it can be activated on a new machine."""
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
        SELECT bound_device FROM users
        WHERE license_key=%s AND admin_id=%s
    """, (key, g.admin_id))
    row = c.fetchone()

    if not row:
        conn.close()
        return json_error("not found")

    if not row["bound_device"]:
        conn.close()
        return json_error("license is not bound to any device")

    c.execute("""
        UPDATE users SET bound_device=NULL
        WHERE license_key=%s AND admin_id=%s
    """, (key, g.admin_id))

    log_audit(conn, g.admin_id, "reset_device", key, f"unbound to ={row['bound_device']}")

    conn.commit()
    conn.close()

    return jsonify({"message": "device reset successfully"})

# =========================
# BAN
# =========================
@app.route("/ban", methods=["POST"])
@token_required
@roles_required("admin", "moderator", "superadmin")
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

    c.execute("""
        UPDATE users SET banned=TRUE
        WHERE license_key=%s AND admin_id=%s
    """, (key, g.admin_id))

    log_audit(conn, g.admin_id, "ban", key)

    conn.commit()
    conn.close()

    return jsonify({"message": "banned successfully"})

# =========================
# UNBAN
# =========================
@app.route("/unban", methods=["POST"])
@token_required
@roles_required("admin", "moderator", "superadmin")
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
        UPDATE users SET banned=FALSE
        WHERE license_key=%s AND admin_id=%s
    """, (key, g.admin_id))

    log_audit(conn, g.admin_id, "unban", key)

    conn.commit()
    conn.close()

    return jsonify({"message": "unbanned successfully"})

# =========================
# EXTEND
# =========================
@app.route("/extend", methods=["POST"])
@token_required
@roles_required("admin", "moderator", "superadmin")
def extend():
    data = request.get_json(silent=True) or {}

    key = data.get("license_key")
    if not key:
        return json_error("license key required")

    try:
        days = int(data.get("days", 1))
    except (ValueError, TypeError):
        return json_error("invalid days")

    if days <= 0 or days > MAX_LICENSE_DAYS:
        return json_error(f"days must be between 1 and {MAX_LICENSE_DAYS}")

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
        UPDATE users SET expires=%s
        WHERE license_key=%s AND admin_id=%s
    """, (new_exp, key, g.admin_id))

    log_audit(conn, g.admin_id, "extend", key, f"days={days}, new_expiry={new_exp.isoformat()}")

    conn.commit()
    conn.close()

    return jsonify({"message": "extended", "new_expiry": new_exp.isoformat()})

# =========================
# DELETE
# =========================
@app.route("/delete", methods=["POST"])
@token_required
@roles_required("admin", "moderator", "superadmin")
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

    if c.rowcount == 0:
        conn.close()
        return jsonify({"message": "key not found"}), 404

    log_audit(conn, g.admin_id, "delete", key)

    conn.commit()
    conn.close()

    return jsonify({"message": "successfully deleted"}), 200

# =========================
# STATS
# =========================
@app.route("/stats", methods=["GET"])
@token_required
@roles_required("admin", "moderator", "superadmin")
def stats():
    try:
        conn = db()
    except OperationalError:
        return jsonify({"error": "database connection failed"}), 500

    c = conn.cursor(cursor_factory=RealDictCursor)
    c.execute("SELECT * FROM users WHERE admin_id = %s", (g.admin_id,))
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

    return jsonify({"total": total, "active": active, "banned": banned, "expired": expired})

# =========================
# USERS
# =========================
@app.route("/users", methods=["GET"])
@token_required
@roles_required("admin", "moderator", "superadmin")
def users():
    try:
        conn = db()
    except OperationalError:
        return jsonify({"error": "database connection failed"}), 500

    c = conn.cursor(cursor_factory=RealDictCursor)

    # NOTE: this mutates state on what's otherwise a read (GET) request.
    # Works fine today; if this grows, move the expiry sweep to a scheduled
    # job instead of running it on every dashboard load.
    c.execute("""
        UPDATE users
        SET state = CASE
            WHEN expires < NOW() THEN 'expired'
            ELSE 'active'
        END
        WHERE admin_id = %s
    """, (g.admin_id,))
    conn.commit()

    c.execute("SELECT * FROM users WHERE admin_id = %s", (g.admin_id,))
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
# AUDIT LOG (new)
# =========================
@app.route("/audit-log", methods=["GET"])
@token_required
@roles_required("admin", "moderator", "superadmin")
def audit_log():
    limit = request.args.get("limit", default=100, type=int)
    limit = max(1, min(limit, 500))

    try:
        conn = db()
    except OperationalError:
        return jsonify({"error": "database connection failed"}), 500

    c = conn.cursor(cursor_factory=RealDictCursor)
    c.execute("""
        SELECT al.id, al.action, al.target, al.details, al.created_at, a.username
        FROM audit_log al
        JOIN admins a ON a.id = al.admin_id
        WHERE al.admin_id = %s
        ORDER BY al.created_at DESC
        LIMIT %s
    """, (g.admin_id, limit))
    rows = c.fetchall()
    conn.close()

    return jsonify({
        "entries": [
            {
                "id": r["id"],
                "action": r["action"],
                "target": r["target"],
                "details": r["details"],
                "username": r["username"],
                "created_at": r["created_at"].isoformat(),
            }
            for r in rows
        ]
    })

# =========================
# ADMIN CONTEXT
# =========================
@app.route("/me", methods=["GET"])
@token_required
def me():
    return jsonify({"user": g.user, "role": g.role})

# ==========================
# SUPER ADMIN: CREATE ADMIN
# ==========================
@app.route("/create-admin", methods=["POST"])
@token_required
@roles_required("superadmin")
def create_admin():
    data = request.get_json(silent=True) or {}

    username = data.get("username")
    password = data.get("password")
    role = data.get("role", "admin")

    if not username or not password:
        return jsonify({"error": "missing fields"}), 400

    if role not in ("admin", "moderator", "superadmin"):
        return jsonify({"error": "invalid role"}), 400

    if len(password) < 8:
        return jsonify({"error": "password must be at least 8 characters"}), 400

    try:
        conn = db()
        c = conn.cursor(cursor_factory=RealDictCursor)

        c.execute("SELECT id FROM admins WHERE username=%s", (username,))
        if c.fetchone():
            conn.close()
            return jsonify({"error": "username already exists"}), 409

        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

        c.execute("""
            INSERT INTO admins (username, password_hash, role, created_at)
            VALUES (%s, %s, %s, NOW())
        """, (username, hashed, role))

        log_audit(conn, g.admin_id, "create_admin", username, f"role={role}")

        conn.commit()
        conn.close()

        return jsonify({"message": "admin created"}), 201

    except OperationalError:
        return jsonify({"error": "database connection failed"}), 500
    except Exception as e:
        print("CREATE ADMIN ERROR:", e)
        return jsonify({"error": "internal server error"}), 500

# =========================
# keep database alive
# =========================
@app.route("/ping", methods=["GET"])
def ping():
    try:
        conn = db()
        c = conn.cursor()
        c.execute("SELECT 1")
        conn.close()
        return jsonify({"status": "awake"}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

# =========================
# RUN
# =========================
if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        debug=False
    )