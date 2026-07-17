from dotenv import load_dotenv
load_dotenv()

from flask import Flask, request, jsonify, g
from datetime import datetime, timezone, timedelta
from functools import wraps
from flask_cors import CORS
from werkzeug.middleware.proxy_fix import ProxyFix
import psycopg2
from psycopg2.extras import RealDictCursor
import os
import time
import jwt
import bcrypt
import secrets
import base64
from psycopg2 import OperationalError

# redis is optional — only needed if you set REDIS_URL for shared rate
# limiting across multiple worker processes. Without it (or without the
# package installed), rate limiting just falls back to in-memory, per-process
# counting, same as before Redis support was added.
try:
    import redis
except ImportError:
    redis = None

SECRET_KEY = os.getenv("JWT_SECRET")
if not SECRET_KEY:
    raise RuntimeError("JWT SECRET is missing")

app = Flask(__name__)

# Render (and most PaaS platforms) sit exactly one reverse proxy in front of
# this app. ProxyFix rewrites request.remote_addr using ONLY the trusted
# rightmost hop of X-Forwarded-For — a client can prepend fake IPs to that
# header (e.g. "1.2.3.4, <real client ip>") and Werkzeug will correctly
# ignore the spoofed part. Without this, get_client_ip() below was reading
# the client-controlled first value, letting anyone bypass IP rate limiting
# by just sending a different fake IP on every request.
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1)

# Defense-in-depth against oversized request bodies (memory-exhaustion DoS).
# Raised from a stricter 16 KB to accommodate base64-encoded proof-of-payment
# screenshots on /admin-requests — every other endpoint still enforces its
# own tight per-field length limits regardless of this outer ceiling.
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024  # 5 MB

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
# Backed by Redis when available, so the limit is shared correctly across
# multiple worker processes/dynos instead of each one keeping its own count.
# Falls back to the original in-memory limiter automatically if Redis is
# unset or unreachable — degrades to per-process accuracy rather than
# breaking login/validate entirely during a Redis outage.
REDIS_URL = os.getenv("REDIS_URL")
_redis_client = None

if REDIS_URL and redis is not None:
    assert redis is not None  # narrows the type for static analysis below
    try:
        _redis_client = redis.from_url(
            REDIS_URL,
            decode_responses=True,
            socket_connect_timeout=2,
            socket_timeout=2,
        )
        _redis_client.ping()
        print("Rate limiting: connected to Redis")
    # noinspection PyBroadException
    except Exception as redis_startup_err:
        # Intentionally broad: ANY failure here (bad URL, auth, network,
        # timeout...) should fall back to in-memory limiting rather than
        # crash the whole app at import time.
        print("Rate limiting: Redis unreachable at startup, using in-memory fallback:", redis_startup_err)
        _redis_client = None
elif REDIS_URL and redis is None:
    print("Rate limiting: REDIS_URL is set but the 'redis' package isn't installed — using in-memory limiter")
else:
    print("Rate limiting: REDIS_URL not set, using in-memory limiter (per-process only)")

RATE_WINDOW = 60
RATE_MAX_IP = 30
RATE_MAX_USER = 5

# --- in-memory fallback store ---
RATE_LIMIT = {}
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


def _check_limit_memory(key, limit, now):
    _sweep_rate_limit(now)
    history = list(RATE_LIMIT.get(key) or [])
    history = [t for t in history if now - t < RATE_WINDOW]
    if len(history) >= limit:
        RATE_LIMIT[key] = history
        return False
    history.append(now)
    RATE_LIMIT[key] = history
    return True


def _check_limit_redis(key, limit, now):
    """Sliding-window limit using a Redis sorted set: score = request time,
    member = unique per-request string. Same semantics as the in-memory
    version, just shared across all processes."""
    try:
        redis_key = f"ratelimit:{key}"

        pipe = _redis_client.pipeline()
        pipe.zremrangebyscore(redis_key, 0, now - RATE_WINDOW)
        pipe.zcard(redis_key)
        _, count = pipe.execute()

        if count >= limit:
            return False

        member = f"{now}:{os.urandom(4).hex()}"  # random suffix avoids same-timestamp collisions
        pipe = _redis_client.pipeline()
        pipe.zadd(redis_key, {member: now})
        pipe.expire(redis_key, RATE_WINDOW + 5)
        pipe.execute()
        return True

    except Exception as e:
        # Transient Redis hiccup mid-request — don't lock everyone out,
        # fall back to this process's own in-memory count for this check.
        print("Rate limiting: Redis error, falling back to in-memory for this check:", e)
        return _check_limit_memory(key, limit, now)


def check_limit(key, limit):
    now = time.time()
    if _redis_client is not None:
        return _check_limit_redis(key, limit, now)
    return _check_limit_memory(key, limit, now)


def get_client_ip():
    # ProxyFix (registered above) already rewrote remote_addr using the
    # trusted proxy hop of X-Forwarded-For — reading the header directly
    # here would reopen the spoofing hole ProxyFix exists to close.
    return request.remote_addr or "unknown"


def rate_limiter(username=None):
    ip = get_client_ip()

    ip_key = f"ip:{ip}"
    user_key = f"user:{username}" if username else None

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
MAX_DEVICES_CAP = 1000   # sanity cap on devices-per-key


def valid_license_key(key: str) -> bool:
    if not isinstance(key, str):
        return False
    if not (10 <= len(key) <= 128):
        return False
    return all(c.isalnum() or c in "-_" for c in key)


def valid_device_id(device_id) -> bool:
    # device_id comes from client apps we don't fully control (Android
    # ANDROID_ID, custom hardware fingerprints, etc.), so this is deliberately
    # more permissive than valid_license_key — just enough to stop absurdly
    # long payloads or non-string junk from reaching the database.
    if not isinstance(device_id, str):
        return False
    if not (1 <= len(device_id) <= 256):
        return False
    return all(c.isalnum() or c in "-_:." for c in device_id)


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
# ADMIN PURCHASE REQUESTS (GCash + manual approval)
# =========================
# week/month plans expire; lifetime never does (None = no expiry).
PLAN_DURATIONS = {"week": 7, "month": 30, "lifetime": None}

ALLOWED_SCREENSHOT_MIME = {"image/png", "image/jpeg", "image/jpg", "image/webp"}
MAX_SCREENSHOT_BYTES = 3 * 1024 * 1024  # 3 MB decoded


def valid_username(username) -> bool:
    if not isinstance(username, str):
        return False
    if not (3 <= len(username) <= 32):
        return False
    return all(c.isalnum() or c == "_" for c in username)


def valid_plan(plan) -> bool:
    return plan in PLAN_DURATIONS


def valid_gcash_reference(ref) -> bool:
    if not isinstance(ref, str):
        return False
    return 4 <= len(ref) <= 64


def generate_reference_code(conn, table="admin_requests", prefix="REQ") -> str:
    """<PREFIX>-XXXXX, retried on the rare chance of a collision. Shared by
    admin purchase requests (REQ-) and password reset requests (PWR-)."""
    c = conn.cursor()
    for _ in range(10):
        code = f"{prefix}-" + secrets.token_hex(3).upper()  # e.g. REQ-9F3A1C
        c.execute(f"SELECT 1 FROM {table} WHERE reference_code=%s", (code,))
        if not c.fetchone():
            return code
    raise RuntimeError("could not generate a unique reference code")


def generate_temp_password() -> str:
    """12-character password from an unambiguous alphabet (no 0/O/1/l/I),
    for handing to an admin whose password was just reset."""
    alphabet = "ABCDEFGHJKMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789"
    return "".join(secrets.choice(alphabet) for _ in range(12))


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

            # Re-fetch role/username from the DB rather than trusting what
            # was embedded in the token at login time. Otherwise, if a
            # superadmin changes another admin's role mid-session, the old
            # token keeps working with the OLD role for up to 2 more hours.
            conn = db()
            c = conn.cursor(cursor_factory=RealDictCursor)
            c.execute("SELECT id, username, role, expires_at FROM admins WHERE id=%s", (admin_id,))
            admin = c.fetchone()
            conn.close()

            if not admin:
                # The only way this account row disappears is via the
                # terminate-admin action (there's no other delete path), so
                # this is safe to always attribute to termination.
                return jsonify({
                    "error": "You have been terminated by the owner.",
                    "terminated": True
                }), 403

            if admin["expires_at"] and datetime.now(timezone.utc) > admin["expires_at"]:
                return jsonify({"error": "admin account expired"}), 403

            g.user = admin["username"]
            g.role = admin["role"]
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

    # Always check a password hash, even for unknown usernames, so
    # response time doesn't leak whether the username exists.
    hash_to_check = admin["password_hash"] if admin else _DUMMY_HASH
    password_ok = bcrypt.checkpw(password.encode(), hash_to_check.encode())

    if not admin:
        # This username was likely terminated by a superadmin — the
        # terminate_admin audit entry survives the account wipe since it's
        # logged under the ACTING superadmin's own admin_id, not the
        # terminated admin's. Tell them clearly instead of a generic error.
        c.execute("""
            SELECT 1 FROM audit_log WHERE action='terminate_admin' AND target=%s LIMIT 1
        """, (username,))
        was_terminated = c.fetchone() is not None
        conn.close()

        if was_terminated:
            return jsonify({
                "error": "You have been terminated by the owner.",
                "terminated": True
            }), 403

        return jsonify({"error": "invalid credentials"}), 401

    conn.close()

    if not password_ok:
        return jsonify({"error": "invalid credentials"}), 401

    if admin["expires_at"] and datetime.now(timezone.utc) > admin["expires_at"]:
        return jsonify({"error": "your admin access has expired"}), 403

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
        return json_error("license key required (10-128 alphanumeric/-/_ chars)")

    try:
        days = int(data.get("days", 7))
    except (TypeError, ValueError):
        return json_error("invalid days")

    if days <= 0 or days > MAX_LICENSE_DAYS:
        return json_error(f"days must be between 1 and {MAX_LICENSE_DAYS}")

    try:
        max_devices = int(data.get("max_devices", 1))
    except (TypeError, ValueError):
        return json_error("invalid max_devices")

    if max_devices <= 0 or max_devices > MAX_DEVICES_CAP:
        return json_error(f"max_devices must be between 1 and {MAX_DEVICES_CAP}")

    try:
        conn = db()
    except OperationalError:
        return jsonify({"error": "database connection failed"}), 500

    c = conn.cursor(cursor_factory=RealDictCursor)

    c.execute("SELECT 1 FROM users WHERE license_key=%s", (license_key,))
    if c.fetchone():
        conn.close()
        return json_error("key already exist")

    # NOTE: expires and activated_at stay NULL here on purpose — the key's
    # countdown doesn't start until the first device binds to it via /validate.
    c.execute("""
        INSERT INTO users (license_key, status, banned, admin_id, max_devices, duration_days)
        VALUES (%s, %s, %s, %s, %s, %s)
    """, (license_key, "premium", False, g.admin_id, max_devices, days))

    log_audit(conn, g.admin_id, "create_license", license_key,
               f"duration_days={days}, max_devices={max_devices}")

    conn.commit()
    conn.close()

    return jsonify({
        "message": "license created",
        "license_key": license_key,
        "duration_days": days,
        "max_devices": max_devices
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

    if not isinstance(license_key, str) or len(license_key) > 128:
        return json_error("invalid license key")

    if not valid_device_id(device_id):
        return json_error("invalid device id")

    try:
        conn = db()
    except OperationalError:
        return jsonify({"error": "database connection failed"}), 500

    c = conn.cursor(cursor_factory=RealDictCursor)
    c.execute("""
        SELECT license_key, status, expires, banned, max_devices, duration_days, activated_at
        FROM users
        WHERE license_key=%s
    """, (license_key,))
    user = c.fetchone()

    if not user:
        conn.close()
        return jsonify({"status": "invalid key"})

    if user["banned"]:
        conn.close()
        return jsonify({"status": "banned"})

    now = datetime.now(timezone.utc)

    # ---- Activation: the countdown starts on first bind, not at creation ----
    if user["activated_at"] is None:
        new_expires = now + timedelta(days=user["duration_days"])

        # Atomic claim: only succeeds if still un-activated at write time,
        # so two concurrent "first binds" can't both start the clock.
        c.execute("""
            UPDATE users
            SET activated_at=%s, expires=%s
            WHERE license_key=%s AND activated_at IS NULL
            RETURNING expires
        """, (now, new_expires, license_key))
        claimed = c.fetchone()
        conn.commit()

        if claimed:
            user["expires"] = claimed["expires"]
        else:
            # Someone else activated it in the tiny window between SELECT and UPDATE.
            c.execute("SELECT expires FROM users WHERE license_key=%s", (license_key,))
            user["expires"] = c.fetchone()["expires"]

    if now > user["expires"]:
        conn.close()
        return jsonify({"status": "expired"})

    # ---- Device binding ----
    c.execute("""
        SELECT 1 FROM license_devices WHERE license_key=%s AND device_id=%s
    """, (license_key, device_id))
    already_bound = c.fetchone()

    if not already_bound:
        # Atomic claim: only inserts if the device count is still under the
        # cap at write time, so concurrent activations can't overshoot max_devices.
        c.execute("""
            INSERT INTO license_devices (license_key, device_id, bound_at)
            SELECT %s, %s, NOW()
            WHERE (SELECT COUNT(*) FROM license_devices WHERE license_key=%s) < %s
            ON CONFLICT (license_key, device_id) DO NOTHING
            RETURNING id
        """, (license_key, device_id, license_key, user["max_devices"]))
        inserted = c.fetchone()
        conn.commit()

        if not inserted:
            # Either the cap was already reached, or a concurrent request
            # bound this exact device first — tell them apart.
            c.execute("""
                SELECT 1 FROM license_devices WHERE license_key=%s AND device_id=%s
            """, (license_key, device_id))
            if not c.fetchone():
                conn.close()
                return jsonify({"status": "device limit reached"})

    conn.close()
    return jsonify({
        "status": "active",
        "license_key": license_key,
        "expires": user["expires"].isoformat(),
        "device_id": device_id
    })

# =========================
# RESET DEVICE (new)
# =========================
@app.route("/reset-device", methods=["POST"])
@token_required
@roles_required("admin", "moderator", "superadmin")
def reset_device():
    """Unbinds device(s) from a license so it can be activated elsewhere.
    Pass 'device_id' to unbind just that one device; omit it to clear all
    devices bound to the key."""
    data = request.get_json(silent=True) or {}
    key = data.get("license_key")
    device_id = data.get("device_id")  # optional

    if not key:
        return json_error("license key required")

    if device_id is not None and not valid_device_id(device_id):
        return json_error("invalid device id")

    try:
        conn = db()
    except OperationalError:
        return jsonify({"error": "database connection failed"}), 500

    c = conn.cursor(cursor_factory=RealDictCursor)

    # ownership check — this key must belong to the calling admin
    c.execute("SELECT 1 FROM users WHERE license_key=%s AND admin_id=%s", (key, g.admin_id))
    if not c.fetchone():
        conn.close()
        return json_error("not found")

    if device_id:
        c.execute("""
            DELETE FROM license_devices
            WHERE license_key=%s AND device_id=%s
        """, (key, device_id))
        removed = c.rowcount
        detail = f"device_id={device_id}"
    else:
        c.execute("DELETE FROM license_devices WHERE license_key=%s", (key,))
        removed = c.rowcount
        detail = "all devices"

    if removed == 0:
        conn.close()
        return json_error("no matching device bound to this license")

    log_audit(conn, g.admin_id, "reset_device", key, detail)

    conn.commit()
    conn.close()

    return jsonify({"message": "device reset successfully", "removed": removed})

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
        SELECT expires, banned, activated_at, duration_days
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

    if row["activated_at"] is None:
        # Key hasn't started its period yet — there's no expiry to push out,
        # so extend the length of the period it'll get once it does activate.
        new_duration = row["duration_days"] + days
        c.execute("""
            UPDATE users SET duration_days=%s
            WHERE license_key=%s AND admin_id=%s
        """, (new_duration, key, g.admin_id))

        log_audit(conn, g.admin_id, "extend", key,
                   f"days={days} (not yet activated, new duration_days={new_duration})")

        conn.commit()
        conn.close()

        return jsonify({
            "message": "extended (not yet activated — added to its future duration)",
            "new_duration_days": new_duration
        })

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
    active = banned = expired = pending = 0

    for u in records:
        if u["banned"]:
            banned += 1
        elif u["expires"] is None:
            pending += 1
        elif now > u["expires"]:
            expired += 1
        else:
            active += 1

    return jsonify({
        "total": total,
        "active": active,
        "banned": banned,
        "expired": expired,
        "pending": pending
    })

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

    # State is now computed in Python below instead of stored/updated via SQL —
    # a stored 'expired' column can't safely represent a NULL (not-yet-activated)
    # expires date, so we compute active/expired/pending/banned fresh each time.
    c.execute("""
        SELECT u.license_key, u.status, u.banned, u.expires, u.max_devices,
               u.duration_days, u.activated_at,
               COALESCE(d.device_count, 0) AS device_count,
               COALESCE(d.device_list, ARRAY[]::text[]) AS device_list
        FROM users u
        LEFT JOIN (
            SELECT license_key, COUNT(*) AS device_count, array_agg(device_id) AS device_list
            FROM license_devices
            GROUP BY license_key
        ) d ON d.license_key = u.license_key
        WHERE u.admin_id = %s
    """, (g.admin_id,))

    rows = c.fetchall()
    conn.close()

    now = datetime.now(timezone.utc)
    result = []

    for u in rows:
        if u["banned"]:
            state = "banned"
        elif u["expires"] is None:
            state = "pending"
        elif now > u["expires"]:
            state = "expired"
        else:
            state = "active"

        if u["expires"] is None:
            time_left = f"not started (period: {u['duration_days']}d)"
        else:
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
            "status": u["status"],
            "banned": u["banned"],
            "state": state,
            "time_left": time_left,
            "expires": u["expires"].isoformat() if u["expires"] else None,
            "max_devices": u["max_devices"],
            "device_count": u["device_count"],
            "devices": u["device_list"],
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

@app.route("/audit-log", methods=["DELETE"])
@token_required
@roles_required("admin", "moderator", "superadmin")
def clear_audit_log():
    """Clears only the calling admin's own audit history, not other admins'."""
    try:
        conn = db()
    except OperationalError:
        return jsonify({"error": "database connection failed"}), 500

    c = conn.cursor()
    c.execute("DELETE FROM audit_log WHERE admin_id = %s", (g.admin_id,))
    deleted_count = c.rowcount
    conn.commit()
    conn.close()

    return jsonify({"message": "audit log cleared", "deleted": deleted_count})

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

# ==========================
# ADMIN PURCHASE REQUESTS (public submission + status check)
# ==========================
@app.route("/admin-requests", methods=["POST"])
def submit_admin_request():
    if not rate_limiter():
        return jsonify({"error": "too many requests!"}), 429

    data = request.get_json(silent=True) or {}

    username = data.get("username")
    password = data.get("password")
    plan = data.get("plan")
    gcash_reference = data.get("gcash_reference")
    screenshot_b64 = data.get("screenshot_base64")
    screenshot_mime = data.get("screenshot_mime")

    if not valid_username(username):
        return json_error("username must be 3-32 characters, letters/numbers/underscore only")
    if not isinstance(password, str) or len(password) < 8:
        return json_error("password must be at least 8 characters")
    if not valid_plan(plan):
        return json_error("plan must be one of: week, month, lifetime")
    if not valid_gcash_reference(gcash_reference):
        return json_error("a valid GCash reference number is required")

    # Screenshot is optional — some buyers can't get the file picker to work
    # in certain WebView-based browsers. If they do attach one, it's still
    # validated normally; if not, we just store NULL for both fields.
    has_screenshot = isinstance(screenshot_b64, str) and screenshot_b64.strip() != ""

    if has_screenshot:
        if screenshot_mime not in ALLOWED_SCREENSHOT_MIME:
            return json_error("screenshot must be png, jpg, or webp")

        try:
            decoded_bytes = base64.b64decode(screenshot_b64, validate=True)
        except Exception:
            return json_error("screenshot is not valid base64 image data")

        if len(decoded_bytes) > MAX_SCREENSHOT_BYTES:
            return json_error("screenshot is too large (max 3MB)")
    else:
        screenshot_b64 = None
        screenshot_mime = None

    try:
        conn = db()
    except OperationalError:
        return jsonify({"error": "database connection failed"}), 500

    c = conn.cursor(cursor_factory=RealDictCursor)

    # Username must be free both among real admins and other pending requests,
    # so two people can't simultaneously reserve the same desired username.
    c.execute("SELECT 1 FROM admins WHERE username=%s", (username,))
    if c.fetchone():
        conn.close()
        return json_error("that username is already taken")

    c.execute("""
        SELECT 1 FROM admin_requests WHERE username=%s AND status='pending'
    """, (username,))
    if c.fetchone():
        conn.close()
        return json_error("that username already has a pending request")

    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    reference_code = generate_reference_code(conn)

    c.execute("""
        INSERT INTO admin_requests
            (reference_code, username, password_hash, plan, gcash_reference,
             screenshot_b64, screenshot_mime, status, created_at)
        VALUES (%s, %s, %s, %s, %s, %s, %s, 'pending', NOW())
    """, (reference_code, username, password_hash, plan, gcash_reference,
          screenshot_b64, screenshot_mime))

    conn.commit()
    conn.close()

    return jsonify({
        "message": "request submitted — save your reference code",
        "reference_code": reference_code
    }), 201


@app.route("/admin-requests/status", methods=["GET"])
def check_admin_request_status():
    if not rate_limiter():
        return jsonify({"error": "too many requests!"}), 429

    reference_code = request.args.get("reference_code", "")
    if not reference_code:
        return json_error("reference_code required")

    try:
        conn = db()
    except OperationalError:
        return jsonify({"error": "database connection failed"}), 500

    c = conn.cursor(cursor_factory=RealDictCursor)
    c.execute("""
        SELECT reference_code, plan, status, rejection_reason, created_at, reviewed_at
        FROM admin_requests
        WHERE reference_code=%s
    """, (reference_code,))
    row = c.fetchone()
    conn.close()

    if not row:
        return jsonify({"status": "not found"})

    return jsonify({
        "reference_code": row["reference_code"],
        "plan": row["plan"],
        "status": row["status"],
        "rejection_reason": row["rejection_reason"],
        "created_at": row["created_at"].isoformat(),
        "reviewed_at": row["reviewed_at"].isoformat() if row["reviewed_at"] else None,
    })

# ==========================
# ADMIN PURCHASE REQUESTS (superadmin review queue)
# ==========================
@app.route("/admin-requests", methods=["GET"])
@token_required
@roles_required("superadmin")
def list_admin_requests():
    status_filter = request.args.get("status", "pending")

    try:
        conn = db()
    except OperationalError:
        return jsonify({"error": "database connection failed"}), 500

    c = conn.cursor(cursor_factory=RealDictCursor)

    # screenshot bytes are deliberately excluded here — fetched on demand via
    # /admin-requests/<id>/screenshot so this list stays light even with many
    # pending requests. has_screenshot just tells the UI whether there's
    # anything to view, since the screenshot itself is now optional.
    if status_filter == "all":
        c.execute("""
            SELECT id, reference_code, username, plan, gcash_reference, status,
                   rejection_reason, created_at, reviewed_at,
                   (screenshot_b64 IS NOT NULL) AS has_screenshot
            FROM admin_requests ORDER BY created_at DESC
        """)
    else:
        c.execute("""
            SELECT id, reference_code, username, plan, gcash_reference, status,
                   rejection_reason, created_at, reviewed_at,
                   (screenshot_b64 IS NOT NULL) AS has_screenshot
            FROM admin_requests WHERE status=%s ORDER BY created_at DESC
        """, (status_filter,))

    rows = c.fetchall()
    conn.close()

    return jsonify({
        "requests": [
            {
                "id": r["id"],
                "reference_code": r["reference_code"],
                "username": r["username"],
                "plan": r["plan"],
                "gcash_reference": r["gcash_reference"],
                "status": r["status"],
                "rejection_reason": r["rejection_reason"],
                "created_at": r["created_at"].isoformat(),
                "reviewed_at": r["reviewed_at"].isoformat() if r["reviewed_at"] else None,
                "has_screenshot": r["has_screenshot"],
            }
            for r in rows
        ]
    })


@app.route("/admin-requests/<int:request_id>/screenshot", methods=["GET"])
@token_required
@roles_required("superadmin")
def get_admin_request_screenshot(request_id):
    try:
        conn = db()
    except OperationalError:
        return jsonify({"error": "database connection failed"}), 500

    c = conn.cursor(cursor_factory=RealDictCursor)
    c.execute("""
        SELECT screenshot_b64, screenshot_mime FROM admin_requests WHERE id=%s
    """, (request_id,))
    row = c.fetchone()
    conn.close()

    if not row or not row["screenshot_b64"]:
        return json_error("screenshot not found (may have already been reviewed)", 404)

    return jsonify({
        "screenshot_base64": row["screenshot_b64"],
        "screenshot_mime": row["screenshot_mime"]
    })


@app.route("/admin-requests/<int:request_id>/approve", methods=["POST"])
@token_required
@roles_required("superadmin")
def approve_admin_request(request_id):
    try:
        conn = db()
    except OperationalError:
        return jsonify({"error": "database connection failed"}), 500

    c = conn.cursor(cursor_factory=RealDictCursor)
    c.execute("SELECT * FROM admin_requests WHERE id=%s", (request_id,))
    reqrow = c.fetchone()

    if not reqrow:
        conn.close()
        return json_error("request not found", 404)

    if reqrow["status"] != "pending":
        conn.close()
        return json_error(f"request already {reqrow['status']}")

    # Race-condition guard: someone could have taken this username between
    # submission and approval (e.g. a manually-created admin).
    c.execute("SELECT 1 FROM admins WHERE username=%s", (reqrow["username"],))
    if c.fetchone():
        conn.close()
        return json_error("that username was taken in the meantime — reject this request")

    plan = reqrow["plan"]
    duration_days = PLAN_DURATIONS.get(plan)
    expires_at = (datetime.now(timezone.utc) + timedelta(days=duration_days)) if duration_days else None

    c.execute("""
        INSERT INTO admins (username, password_hash, role, created_at, expires_at, plan)
        VALUES (%s, %s, 'admin', NOW(), %s, %s)
    """, (reqrow["username"], reqrow["password_hash"], expires_at, plan))

    # Screenshot has served its purpose — clear it to keep the table lean.
    c.execute("""
        UPDATE admin_requests
        SET status='approved', reviewed_at=NOW(), reviewed_by=%s,
            screenshot_b64=NULL
        WHERE id=%s
    """, (g.admin_id, request_id))

    log_audit(conn, g.admin_id, "approve_admin_request", reqrow["username"], f"plan={plan}")

    conn.commit()
    conn.close()

    return jsonify({
        "message": "admin account created",
        "username": reqrow["username"],
        "expires_at": expires_at.isoformat() if expires_at else None
    })


@app.route("/admin-requests/<int:request_id>/reject", methods=["POST"])
@token_required
@roles_required("superadmin")
def reject_admin_request(request_id):
    data = request.get_json(silent=True) or {}
    reason = data.get("reason", "")

    try:
        conn = db()
    except OperationalError:
        return jsonify({"error": "database connection failed"}), 500

    c = conn.cursor(cursor_factory=RealDictCursor)
    c.execute("SELECT status, username FROM admin_requests WHERE id=%s", (request_id,))
    reqrow = c.fetchone()

    if not reqrow:
        conn.close()
        return json_error("request not found", 404)

    if reqrow["status"] != "pending":
        conn.close()
        return json_error(f"request already {reqrow['status']}")

    c.execute("""
        UPDATE admin_requests
        SET status='rejected', reviewed_at=NOW(), reviewed_by=%s,
            rejection_reason=%s, screenshot_b64=NULL
        WHERE id=%s
    """, (g.admin_id, reason or None, request_id))

    log_audit(conn, g.admin_id, "reject_admin_request", reqrow["username"], reason or "")

    conn.commit()
    conn.close()

    return jsonify({"message": "request rejected"})

# ==========================
# ADMIN MANAGEMENT (superadmin only) — view + permanently terminate accounts
# ==========================
@app.route("/admins", methods=["GET"])
@token_required
@roles_required("superadmin")
def list_admins():
    try:
        conn = db()
    except OperationalError:
        return jsonify({"error": "database connection failed"}), 500

    c = conn.cursor(cursor_factory=RealDictCursor)

    # key_count/log_count are shown up front in the dashboard so a superadmin
    # sees the full blast radius (how much data would be wiped) before ever
    # opening the termination confirmation — no separate "preview" call needed.
    c.execute("""
        SELECT a.id, a.username, a.role, a.plan, a.expires_at, a.created_at,
               COALESCE(u.key_count, 0) AS key_count,
               COALESCE(al.log_count, 0) AS log_count
        FROM admins a
        LEFT JOIN (
            SELECT admin_id, COUNT(*) AS key_count FROM users GROUP BY admin_id
        ) u ON u.admin_id = a.id
        LEFT JOIN (
            SELECT admin_id, COUNT(*) AS log_count FROM audit_log GROUP BY admin_id
        ) al ON al.admin_id = a.id
        ORDER BY a.created_at DESC NULLS LAST
    """)
    rows = c.fetchall()
    conn.close()

    return jsonify({
        "admins": [
            {
                "id": str(r["id"]),
                "username": r["username"],
                "role": r["role"],
                "plan": r["plan"],
                "expires_at": r["expires_at"].isoformat() if r["expires_at"] else None,
                "created_at": r["created_at"].isoformat() if r["created_at"] else None,
                "key_count": r["key_count"],
                "log_count": r["log_count"],
            }
            for r in rows
        ]
    })


@app.route("/admins/<admin_id>", methods=["DELETE"])
@token_required
@roles_required("superadmin")
def terminate_admin(admin_id):
    """Permanently deletes an admin/moderator account and ALL of their data:
    their license keys (which cascades to bound devices via an existing FK),
    and their own audit log history (which cascades via an existing FK on
    admins.id). This is intentionally a full wipe, not a soft-delete —
    there is no undo."""

    if admin_id == str(g.admin_id):
        return json_error("you cannot terminate your own account")

    try:
        conn = db()
    except OperationalError:
        return jsonify({"error": "database connection failed"}), 500

    c = conn.cursor(cursor_factory=RealDictCursor)
    c.execute("SELECT id, username, role FROM admins WHERE id=%s", (admin_id,))
    target = c.fetchone()

    if not target:
        conn.close()
        return json_error("admin not found", 404)

    # Superadmin accounts are protected from this action entirely — removing
    # one requires direct database access, not a button in the UI.
    if target["role"] == "superadmin":
        conn.close()
        return json_error("superadmin accounts cannot be terminated this way")

    # Captured before deletion, purely for the audit trail this action leaves
    # behind under the ACTING superadmin's own admin_id (not the deleted
    # admin's — that row is about to be gone).
    c.execute("SELECT COUNT(*) AS c FROM users WHERE admin_id=%s", (admin_id,))
    key_count = c.fetchone()["c"]
    c.execute("SELECT COUNT(*) AS c FROM audit_log WHERE admin_id=%s", (admin_id,))
    log_count = c.fetchone()["c"]

    # Delete their license keys first — license_devices cascades automatically
    # via its existing FK to users.license_key.
    c.execute("DELETE FROM users WHERE admin_id=%s", (admin_id,))

    # Deleting the admin row cascades their own audit_log entries (existing
    # FK), and any admin_requests.reviewed_by pointing at them gets set NULL
    # automatically rather than blocking the delete.
    c.execute("DELETE FROM admins WHERE id=%s", (admin_id,))

    log_audit(conn, g.admin_id, "terminate_admin", target["username"],
               f"role={target['role']}, keys_deleted={key_count}, log_entries_deleted={log_count}")

    conn.commit()
    conn.close()

    return jsonify({
        "message": "admin terminated",
        "username": target["username"],
        "keys_deleted": key_count,
        "log_entries_deleted": log_count
    })

# ==========================
# PASSWORD RESET (public submission + status check)
# ==========================
@app.route("/password-reset-requests", methods=["POST"])
def submit_password_reset_request():
    if not rate_limiter():
        return jsonify({"error": "too many requests!"}), 429

    data = request.get_json(silent=True) or {}
    username = data.get("username")

    if not valid_username(username):
        return json_error("enter a valid username")

    try:
        conn = db()
    except OperationalError:
        return jsonify({"error": "database connection failed"}), 500

    c = conn.cursor(cursor_factory=RealDictCursor)
    c.execute("SELECT 1 FROM admins WHERE username=%s", (username,))
    if not c.fetchone():
        conn.close()
        return json_error("no admin account found with that username")

    c.execute("""
        SELECT 1 FROM password_reset_requests WHERE username=%s AND status='pending'
    """, (username,))
    if c.fetchone():
        conn.close()
        return json_error("a reset request for this username is already pending")

    reference_code = generate_reference_code(conn, table="password_reset_requests", prefix="PWR")

    c.execute("""
        INSERT INTO password_reset_requests (reference_code, username, status, created_at)
        VALUES (%s, %s, 'pending', NOW())
    """, (reference_code, username))

    conn.commit()
    conn.close()

    return jsonify({
        "message": "reset request submitted — save your reference code",
        "reference_code": reference_code
    }), 201


@app.route("/password-reset-requests/status", methods=["GET"])
def check_password_reset_status():
    if not rate_limiter():
        return jsonify({"error": "too many requests!"}), 429

    reference_code = request.args.get("reference_code", "")
    if not reference_code:
        return json_error("reference_code required")

    try:
        conn = db()
    except OperationalError:
        return jsonify({"error": "database connection failed"}), 500

    c = conn.cursor(cursor_factory=RealDictCursor)
    c.execute("""
        SELECT reference_code, status, rejection_reason, created_at, reviewed_at
        FROM password_reset_requests
        WHERE reference_code=%s
    """, (reference_code,))
    row = c.fetchone()
    conn.close()

    if not row:
        return jsonify({"status": "not found"})

    # Deliberately never returns the new password itself, even once approved
    # — that's handed to the superadmin only, to relay out-of-band (same
    # trust model as confirming a GCash payment before approving a purchase).
    return jsonify({
        "reference_code": row["reference_code"],
        "status": row["status"],
        "rejection_reason": row["rejection_reason"],
        "created_at": row["created_at"].isoformat(),
        "reviewed_at": row["reviewed_at"].isoformat() if row["reviewed_at"] else None,
    })

# ==========================
# PASSWORD RESET (superadmin review queue)
# ==========================
@app.route("/password-reset-requests", methods=["GET"])
@token_required
@roles_required("superadmin")
def list_password_reset_requests():
    status_filter = request.args.get("status", "pending")

    try:
        conn = db()
    except OperationalError:
        return jsonify({"error": "database connection failed"}), 500

    c = conn.cursor(cursor_factory=RealDictCursor)

    if status_filter == "all":
        c.execute("""
            SELECT id, reference_code, username, status, rejection_reason,
                   created_at, reviewed_at
            FROM password_reset_requests ORDER BY created_at DESC
        """)
    else:
        c.execute("""
            SELECT id, reference_code, username, status, rejection_reason,
                   created_at, reviewed_at
            FROM password_reset_requests WHERE status=%s ORDER BY created_at DESC
        """, (status_filter,))

    rows = c.fetchall()
    conn.close()

    return jsonify({
        "requests": [
            {
                "id": r["id"],
                "reference_code": r["reference_code"],
                "username": r["username"],
                "status": r["status"],
                "rejection_reason": r["rejection_reason"],
                "created_at": r["created_at"].isoformat(),
                "reviewed_at": r["reviewed_at"].isoformat() if r["reviewed_at"] else None,
            }
            for r in rows
        ]
    })


@app.route("/password-reset-requests/<int:request_id>/approve", methods=["POST"])
@token_required
@roles_required("superadmin")
def approve_password_reset_request(request_id):
    try:
        conn = db()
    except OperationalError:
        return jsonify({"error": "database connection failed"}), 500

    c = conn.cursor(cursor_factory=RealDictCursor)
    c.execute("SELECT * FROM password_reset_requests WHERE id=%s", (request_id,))
    reqrow = c.fetchone()

    if not reqrow:
        conn.close()
        return json_error("request not found", 404)

    if reqrow["status"] != "pending":
        conn.close()
        return json_error(f"request already {reqrow['status']}")

    c.execute("SELECT id FROM admins WHERE username=%s", (reqrow["username"],))
    target_admin = c.fetchone()

    if not target_admin:
        conn.close()
        return json_error("that admin account no longer exists — reject this request")

    new_password = generate_temp_password()
    new_hash = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()

    c.execute("UPDATE admins SET password_hash=%s WHERE id=%s", (new_hash, target_admin["id"]))

    c.execute("""
        UPDATE password_reset_requests
        SET status='approved', reviewed_at=NOW(), reviewed_by=%s
        WHERE id=%s
    """, (g.admin_id, request_id))

    # The new password itself is deliberately NOT written to the audit log —
    # only that a reset happened, and for whom.
    log_audit(conn, g.admin_id, "approve_password_reset", reqrow["username"])

    conn.commit()
    conn.close()

    return jsonify({
        "message": "password reset — relay this to the admin, it will not be shown again",
        "username": reqrow["username"],
        "new_password": new_password
    })


@app.route("/password-reset-requests/<int:request_id>/reject", methods=["POST"])
@token_required
@roles_required("superadmin")
def reject_password_reset_request(request_id):
    data = request.get_json(silent=True) or {}
    reason = data.get("reason", "")

    try:
        conn = db()
    except OperationalError:
        return jsonify({"error": "database connection failed"}), 500

    c = conn.cursor(cursor_factory=RealDictCursor)
    c.execute("SELECT status, username FROM password_reset_requests WHERE id=%s", (request_id,))
    reqrow = c.fetchone()

    if not reqrow:
        conn.close()
        return json_error("request not found", 404)

    if reqrow["status"] != "pending":
        conn.close()
        return json_error(f"request already {reqrow['status']}")

    c.execute("""
        UPDATE password_reset_requests
        SET status='rejected', reviewed_at=NOW(), reviewed_by=%s, rejection_reason=%s
        WHERE id=%s
    """, (g.admin_id, reason or None, request_id))

    log_audit(conn, g.admin_id, "reject_password_reset", reqrow["username"], reason or "")

    conn.commit()
    conn.close()

    return jsonify({"message": "request rejected"})

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
        # /ping is public and unauthenticated — never echo exception details
        # (connection strings, internal paths, etc.) back to the caller.
        print("PING ERROR:", e)
        return jsonify({"status": "error"}), 500

# =========================
# RUN
# =========================
if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        debug=False
    )