"""
The Magoye Family Archives — Flask API
=======================================
Database : PostgreSQL (Railway)
Security : API key auth, rate limiting, input validation, CORS
Handles  : Updates, Members, Gallery, Chat
"""

from flask import Flask, jsonify, request
from flask_cors import CORS
from datetime import datetime
from functools import wraps
from collections import defaultdict
import json, uuid, os, time, re

import psycopg2
from psycopg2.extras import RealDictCursor

app = Flask(__name__)

# ─────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────
API_KEY      = os.environ.get("API_SECRET_KEY", "magoye-secret-2025")
DATABASE_URL = os.environ.get("DATABASE_URL", "")

CORS(app, resources={r"/api/*": {
    "origins": "*",
    "allow_headers": ["Content-Type", "X-API-Key"],
    "methods": ["GET", "POST", "PATCH", "DELETE", "OPTIONS"]
}})

# ─────────────────────────────────────────
# DATABASE
# ─────────────────────────────────────────
def get_db():
    return psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)

def init_db():
    conn = get_db()
    cur  = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS updates (
            id          TEXT PRIMARY KEY,
            title       TEXT NOT NULL,
            description TEXT DEFAULT '',
            category    TEXT DEFAULT '',
            date        TEXT,
            created_at  TEXT
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS members (
            id          TEXT PRIMARY KEY,
            name        TEXT NOT NULL,
            role        TEXT DEFAULT 'Member',
            born        TEXT,
            died        TEXT,
            town        TEXT,
            spouse      TEXT,
            bio         TEXT,
            photo       TEXT,
            generation  INTEGER DEFAULT 1,
            created_at  TEXT
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS gallery (
            id          TEXT PRIMARY KEY,
            title       TEXT,
            description TEXT DEFAULT '',
            category    TEXT DEFAULT '',
            url         TEXT,
            tags        TEXT DEFAULT '',
            created_at  TEXT
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS chat (
            id          TEXT PRIMARY KEY,
            name        TEXT NOT NULL,
            message     TEXT NOT NULL,
            created_at  TEXT
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id          TEXT PRIMARY KEY,
            email       TEXT UNIQUE NOT NULL,
            password    TEXT NOT NULL,
            full_name   TEXT,
            branch      TEXT,
            created_at  TEXT
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS contributions (
            id          TEXT PRIMARY KEY,
            donor_name  TEXT NOT NULL,
            amount      REAL,
            currency    TEXT DEFAULT 'UGX',
            is_anonymous BOOLEAN DEFAULT FALSE,
            created_at  TEXT
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS media (
            id          TEXT PRIMARY KEY,
            type        TEXT,
            title       TEXT NOT NULL,
            description TEXT DEFAULT '',
            date        TEXT,
            thumbnail   TEXT,
            src         TEXT NOT NULL,
            created_at  TEXT
        )
    """)

    conn.commit()
    cur.close()
    conn.close()
    print("  Database ready (PostgreSQL)")

def row(r):
    return dict(r)

# ─────────────────────────────────────────
# SECURITY
# ─────────────────────────────────────────
def require_api_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        key = request.headers.get("X-API-Key") or request.args.get("apikey")
        if not key or key != API_KEY:
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated

request_counts = defaultdict(list)
def rate_limit(max_per_minute=60):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            ip  = request.remote_addr or "unknown"
            now = time.time()
            request_counts[ip] = [t for t in request_counts[ip] if now - t < 60]
            if len(request_counts[ip]) >= max_per_minute:
                return jsonify({"error": "Too many requests"}), 429
            request_counts[ip].append(now)
            return f(*args, **kwargs)
        return decorated
    return decorator

def sanitise(text, max_len=500):
    if not isinstance(text, str): return ""
    text = re.sub(r'<[^>]+>', '', text)
    return text.strip()[:max_len]

def new_id():
    return uuid.uuid4().hex[:12].upper()

def now():
    return datetime.now().isoformat()

# ─────────────────────────────────────────
# HEALTH
# ─────────────────────────────────────────
@app.route("/api/ping")
def ping():
    return jsonify({"status": "ok", "service": "Magoye Family API", "db": "postgresql"})

# ─────────────────────────────────────────
# AUTHENTICATION
# ─────────────────────────────────────────
@app.route("/api/auth/register", methods=["POST"])
@rate_limit(10)
def register():
    data = request.get_json(force=True, silent=True) or {}
    email = sanitise(data.get("email",""), 100).strip().lower()
    password = data.get("password","")
    full_name = sanitise(data.get("fullName",""), 100)
    branch = sanitise(data.get("branch",""), 100)
    
    if not email or not password:
        return jsonify({"error": "email and password are required"}), 400
    if len(password) < 6:
        return jsonify({"error": "password must be at least 6 characters"}), 400
    
    try:
        conn = get_db(); cur = conn.cursor()
        cur.execute("SELECT id FROM users WHERE email=%s", (email,))
        if cur.fetchone():
            cur.close(); conn.close()
            return jsonify({"error": "Email already registered"}), 409
        
        rec = {
            "id": new_id(),
            "email": email,
            "password": password,
            "full_name": full_name,
            "branch": branch,
            "created_at": now()
        }
        cur.execute("""INSERT INTO users (id,email,password,full_name,branch,created_at)
            VALUES (%s,%s,%s,%s,%s,%s)""", tuple(rec.values()))
        conn.commit(); cur.close(); conn.close()
        return jsonify({"success": True, "id": rec["id"]}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/auth/login", methods=["POST"])
@rate_limit(20)
def login():
    data = request.get_json(force=True, silent=True) or {}
    email = sanitise(data.get("email",""), 100).strip().lower()
    password = data.get("password","")
    
    if not email or not password:
        return jsonify({"error": "email and password are required"}), 400
    
    try:
        conn = get_db(); cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE email=%s", (email,))
        user = cur.fetchone()
        cur.close(); conn.close()
        
        if not user or user['password'] != password:
            return jsonify({"error": "Invalid credentials"}), 401
        
        return jsonify({
            "success": True,
            "id": user['id'],
            "email": user['email'],
            "full_name": user['full_name'],
            "branch": user['branch']
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ─────────────────────────────────────────
# UPDATES
# ─────────────────────────────────────────
@app.route("/api/updates", methods=["GET"])
@require_api_key
@rate_limit(60)
def get_updates():
    category = request.args.get("category")
    conn = get_db(); cur = conn.cursor()
    if category:
        cur.execute("SELECT * FROM updates WHERE category=%s ORDER BY date DESC, created_at DESC", (category,))
    else:
        cur.execute("SELECT * FROM updates ORDER BY date DESC, created_at DESC")
    rows = cur.fetchall()
    cur.close(); conn.close()
    return jsonify([row(r) for r in rows])

@app.route("/api/updates", methods=["POST"])
@require_api_key
@rate_limit(30)
def add_update():
    data = request.get_json(force=True, silent=True) or {}
    title = sanitise(data.get("title","")).strip()
    if not title:
        return jsonify({"error": "title is required"}), 400
    rec = {
        "id":          new_id(),
        "title":       title,
        "description": sanitise(data.get("description",""), 1000),
        "category":    sanitise(data.get("category",""), 50),
        "date":        sanitise(data.get("date",""), 30),
        "created_at":  now()
    }
    conn = get_db(); cur = conn.cursor()
    cur.execute("INSERT INTO updates (id,title,description,category,date,created_at) VALUES (%s,%s,%s,%s,%s,%s)",
        tuple(rec.values()))
    conn.commit(); cur.close(); conn.close()
    return jsonify(rec), 201

@app.route("/api/updates/<uid>", methods=["PATCH"])
@require_api_key
@rate_limit(60)
def update_update(uid):
    data = request.get_json(force=True, silent=True) or {}
    fields, vals = [], []
    for col in ["title","description","category","date"]:
        if col in data:
            fields.append(f"{col}=%s")
            vals.append(sanitise(str(data[col]), 1000 if col=="description" else 200))
    if not fields:
        return jsonify({"error": "nothing to update"}), 400
    vals.append(uid)
    conn = get_db(); cur = conn.cursor()
    cur.execute(f"UPDATE updates SET {','.join(fields)} WHERE id=%s", vals)
    conn.commit(); cur.close(); conn.close()
    return jsonify({"success": True})

@app.route("/api/updates/<uid>", methods=["DELETE"])
@require_api_key
@rate_limit(60)
def delete_update(uid):
    conn = get_db(); cur = conn.cursor()
    cur.execute("DELETE FROM updates WHERE id=%s", (uid,))
    conn.commit(); cur.close(); conn.close()
    return jsonify({"success": True})

# ─────────────────────────────────────────
# MEMBERS
# ─────────────────────────────────────────
@app.route("/api/members", methods=["GET"])
@require_api_key
@rate_limit(60)
def get_members():
    conn = get_db(); cur = conn.cursor()
    cur.execute("SELECT * FROM members ORDER BY generation ASC, name ASC")
    rows = cur.fetchall()
    cur.close(); conn.close()
    return jsonify([row(r) for r in rows])

@app.route("/api/members", methods=["POST"])
@require_api_key
@rate_limit(30)
def add_member():
    data = request.get_json(force=True, silent=True) or {}
    name = sanitise(data.get("name","")).strip()
    if not name:
        return jsonify({"error": "name is required"}), 400
    rec = {
        "id":         new_id(),
        "name":       name,
        "role":       sanitise(data.get("role","Member"), 50),
        "born":       sanitise(data.get("born",""), 30),
        "died":       sanitise(data.get("died",""), 30),
        "town":       sanitise(data.get("town",""), 100),
        "spouse":     sanitise(data.get("spouse",""), 100),
        "bio":        sanitise(data.get("bio",""), 2000),
        "photo":      data.get("photo","")[:5000] if data.get("photo") else "",
        "generation": int(data.get("generation", 1)),
        "created_at": now()
    }
    conn = get_db(); cur = conn.cursor()
    cur.execute("""INSERT INTO members (id,name,role,born,died,town,spouse,bio,photo,generation,created_at)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""", tuple(rec.values()))
    conn.commit(); cur.close(); conn.close()
    return jsonify(rec), 201

@app.route("/api/members/<mid>", methods=["PATCH"])
@require_api_key
@rate_limit(60)
def update_member(mid):
    data = request.get_json(force=True, silent=True) or {}
    fields, vals = [], []
    for col in ["name","role","born","died","town","spouse","bio","photo","generation"]:
        if col in data:
            fields.append(f"{col}=%s")
            vals.append(data[col] if col in ["photo","generation"] else sanitise(str(data[col]), 2000))
    if not fields:
        return jsonify({"error": "nothing to update"}), 400
    vals.append(mid)
    conn = get_db(); cur = conn.cursor()
    cur.execute(f"UPDATE members SET {','.join(fields)} WHERE id=%s", vals)
    conn.commit(); cur.close(); conn.close()
    return jsonify({"success": True})

@app.route("/api/members/<mid>", methods=["DELETE"])
@require_api_key
@rate_limit(60)
def delete_member(mid):
    conn = get_db(); cur = conn.cursor()
    cur.execute("DELETE FROM members WHERE id=%s", (mid,))
    conn.commit(); cur.close(); conn.close()
    return jsonify({"success": True})

# ─────────────────────────────────────────
# GALLERY
# ─────────────────────────────────────────
@app.route("/api/gallery", methods=["GET"])
@require_api_key
@rate_limit(60)
def get_gallery():
    category = request.args.get("category")
    conn = get_db(); cur = conn.cursor()
    if category:
        cur.execute("SELECT * FROM gallery WHERE category=%s ORDER BY created_at DESC", (category,))
    else:
        cur.execute("SELECT * FROM gallery ORDER BY created_at DESC")
    rows = cur.fetchall()
    cur.close(); conn.close()
    return jsonify([row(r) for r in rows])

@app.route("/api/gallery", methods=["POST"])
@require_api_key
@rate_limit(20)
def add_photo():
    data = request.get_json(force=True, silent=True) or {}
    url = data.get("url","")
    if not url:
        return jsonify({"error": "url is required"}), 400
    rec = {
        "id":          new_id(),
        "title":       sanitise(data.get("title",""), 200),
        "description": sanitise(data.get("description",""), 500),
        "category":    sanitise(data.get("category",""), 50),
        "url":         url[:100000],  # base64 images can be large
        "tags":        sanitise(data.get("tags",""), 200),
        "created_at":  now()
    }
    conn = get_db(); cur = conn.cursor()
    cur.execute("INSERT INTO gallery (id,title,description,category,url,tags,created_at) VALUES (%s,%s,%s,%s,%s,%s,%s)",
        tuple(rec.values()))
    conn.commit(); cur.close(); conn.close()
    return jsonify({"success": True, "id": rec["id"]}), 201

@app.route("/api/gallery/<gid>", methods=["DELETE"])
@require_api_key
@rate_limit(60)
def delete_photo(gid):
    conn = get_db(); cur = conn.cursor()
    cur.execute("DELETE FROM gallery WHERE id=%s", (gid,))
    conn.commit(); cur.close(); conn.close()
    return jsonify({"success": True})

# ─────────────────────────────────────────
# CHAT
# ─────────────────────────────────────────
@app.route("/api/chat", methods=["GET"])
@require_api_key
@rate_limit(60)
def get_chat():
    limit = min(int(request.args.get("limit", 100)), 200)
    since = request.args.get("since")  # ISO timestamp for polling
    conn = get_db(); cur = conn.cursor()
    if since:
        cur.execute("SELECT * FROM chat WHERE created_at > %s ORDER BY created_at ASC LIMIT %s", (since, limit))
    else:
        cur.execute("SELECT * FROM chat ORDER BY created_at ASC LIMIT %s", (limit,))
    rows = cur.fetchall()
    cur.close(); conn.close()
    return jsonify([row(r) for r in rows])

@app.route("/api/chat", methods=["POST"])
@require_api_key
@rate_limit(30)
def send_chat():
    data = request.get_json(force=True, silent=True) or {}
    name    = sanitise(data.get("name",""), 60).strip()
    message = sanitise(data.get("message",""), 1000).strip()
    if not name or not message:
        return jsonify({"error": "name and message are required"}), 400
    rec = {"id": new_id(), "name": name, "message": message, "created_at": now()}
    conn = get_db(); cur = conn.cursor()
    cur.execute("INSERT INTO chat (id,name,message,created_at) VALUES (%s,%s,%s,%s)", tuple(rec.values()))
    conn.commit(); cur.close(); conn.close()
    return jsonify(rec), 201

# ─────────────────────────────────────────
# MEDIA LIBRARY
# ─────────────────────────────────────────
@app.route("/api/media/library", methods=["GET"])
@rate_limit(60)
def get_media():
    limit = min(int(request.args.get("limit", 50)), 200)
    conn = get_db(); cur = conn.cursor()
    cur.execute("SELECT * FROM media ORDER BY created_at DESC LIMIT %s", (limit,))
    rows = cur.fetchall()
    cur.close(); conn.close()
    return jsonify([row(r) for r in rows])

@app.route("/api/media/library", methods=["POST"])
@require_api_key
@rate_limit(30)
def add_media():
    data = request.get_json(force=True, silent=True) or {}
    title = sanitise(data.get("title",""), 200).strip()
    if not title:
        return jsonify({"error": "title is required"}), 400
    
    rec = {
        "id": new_id(),
        "type": sanitise(data.get("type","Podcast"), 50),
        "title": title,
        "description": sanitise(data.get("description",""), 500),
        "date": sanitise(data.get("date",""), 30),
        "thumbnail": data.get("thumbnail","")[:10000],
        "src": data.get("src","")[:10000],
        "created_at": now()
    }
    conn = get_db(); cur = conn.cursor()
    cur.execute("""INSERT INTO media (id,type,title,description,date,thumbnail,src,created_at)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s)""", tuple(rec.values()))
    conn.commit(); cur.close(); conn.close()
    return jsonify({"success": True, "id": rec["id"]}), 201

@app.route("/api/media/<mid>", methods=["DELETE"])
@require_api_key
@rate_limit(60)
def delete_media(mid):
    conn = get_db(); cur = conn.cursor()
    cur.execute("DELETE FROM media WHERE id=%s", (mid,))
    conn.commit(); cur.close(); conn.close()
    return jsonify({"success": True})

# ─────────────────────────────────────────
# LEGACY FUND
# ─────────────────────────────────────────
@app.route("/api/legacy-fund/summary", methods=["GET"])
@rate_limit(60)
def get_legacy_summary():
    conn = get_db(); cur = conn.cursor()
    cur.execute("SELECT COALESCE(SUM(amount), 0) as total_raised, COUNT(*) as supporters FROM contributions WHERE is_anonymous=FALSE")
    summary = dict(cur.fetchone())
    cur.close(); conn.close()
    return jsonify({
        "target_amount": 75000000,
        "target_currency": "UGX",
        "amount_raised": int(summary.get("total_raised", 0)),
        "currency": "UGX",
        "supporters": int(summary.get("supporters", 0)),
        "percentage": int((int(summary.get("total_raised", 0)) / 75000000) * 100) if summary.get("total_raised") else 0
    })

@app.route("/api/legacy-fund/contributions", methods=["GET"])
@rate_limit(60)
def get_contributions():
    limit = min(int(request.args.get("limit", 6)), 50)
    conn = get_db(); cur = conn.cursor()
    cur.execute("""SELECT id, donor_name, amount, currency, is_anonymous, created_at 
        FROM contributions ORDER BY created_at DESC LIMIT %s""", (limit,))
    rows = cur.fetchall()
    cur.close(); conn.close()
    return jsonify([row(r) for r in rows])

@app.route("/api/legacy-fund/contributions", methods=["POST"])
@rate_limit(20)
def add_contribution():
    data = request.get_json(force=True, silent=True) or {}
    donor_name = sanitise(data.get("donor_name",""), 100)
    amount = float(data.get("amount", 0))
    is_anonymous = data.get("is_anonymous", False)
    
    if amount <= 0:
        return jsonify({"error": "amount must be greater than 0"}), 400
    
    rec = {
        "id": new_id(),
        "donor_name": donor_name if not is_anonymous else "Anonymous Contributor",
        "amount": amount,
        "currency": sanitise(data.get("currency","UGX"), 10),
        "is_anonymous": is_anonymous,
        "created_at": now()
    }
    conn = get_db(); cur = conn.cursor()
    cur.execute("""INSERT INTO contributions (id,donor_name,amount,currency,is_anonymous,created_at)
        VALUES (%s,%s,%s,%s,%s,%s)""", tuple(rec.values()))
    conn.commit(); cur.close(); conn.close()
    return jsonify(rec), 201

# ─────────────────────────────────────────
# STATS
# ─────────────────────────────────────────
@app.route("/api/stats")
@require_api_key
@rate_limit(60)
def get_stats():
    conn = get_db(); cur = conn.cursor()
    cur.execute("""SELECT 
        (SELECT COUNT(*) FROM updates) AS updates, 
        (SELECT COUNT(*) FROM members) AS members, 
        (SELECT COUNT(*) FROM gallery) AS gallery, 
        (SELECT COUNT(*) FROM chat) AS chat,
        (SELECT COUNT(*) FROM users) AS users,
        (SELECT COUNT(*) FROM media) AS media,
        (SELECT COUNT(*) FROM contributions) AS contributions,
        (SELECT COALESCE(SUM(amount), 0) FROM contributions) AS total_raised
    """)
    r = dict(cur.fetchone())
    cur.close(); conn.close()
    return jsonify(r)

# ─────────────────────────────────────────
# STARTUP
# ─────────────────────────────────────────
init_db()

if __name__ == "__main__":
    print("\n  Magoye Family API — Running")
    print("  http://localhost:5000/api/ping\n")
    app.run(debug=False, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
