#!/usr/bin/env python3
"""
AI Women Safety Assistant - Backend Server
Uses only Python standard library (no external deps required)
For production: replace with Flask/FastAPI + PostgreSQL
"""

import json
import sqlite3
import uuid
import hashlib
import hmac
import base64
import os
import re
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime, timedelta
from urllib.parse import urlparse, parse_qs

# ─── Config ───────────────────────────────────────────────────────────────────
PORT = 8000
DB_FILE = "safety.db"
JWT_SECRET = os.environ.get("JWT_SECRET", "change-this-secret-in-production-please")
CORS_ORIGIN = os.environ.get("CORS_ORIGIN", "*")

# ─── Database Setup ───────────────────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()
    c.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            phone TEXT,
            password_hash TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS emergency_contacts (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            name TEXT NOT NULL,
            phone TEXT NOT NULL,
            relation TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS sos_alerts (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            latitude REAL,
            longitude REAL,
            address TEXT,
            status TEXT DEFAULT 'active',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            resolved_at TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS incident_reports (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            type TEXT NOT NULL,
            description TEXT,
            latitude REAL,
            longitude REAL,
            address TEXT,
            severity TEXT DEFAULT 'medium',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS safe_routes (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            from_location TEXT NOT NULL,
            to_location TEXT NOT NULL,
            distance_km REAL,
            est_time_mins INTEGER,
            safety_score INTEGER,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
    """)
    conn.commit()

    # Seed a demo user
    demo_id = "demo-user-001"
    existing = conn.execute("SELECT id FROM users WHERE id=?", (demo_id,)).fetchone()
    if not existing:
        pw_hash = hash_password("demo1234")
        conn.execute(
            "INSERT INTO users (id, name, email, phone, password_hash) VALUES (?,?,?,?,?)",
            (demo_id, "Priya Sharma", "priya@demo.com", "+91 9876543210", pw_hash)
        )
        # Add emergency contacts
        contacts = [
            ("ec-001", demo_id, "Mom", "+91 9876500001", "Parent"),
            ("ec-002", demo_id, "Sister", "+91 9123456789", "Sibling"),
            ("ec-003", demo_id, "Best Friend", "+91 9998776655", "Friend"),
        ]
        conn.executemany(
            "INSERT INTO emergency_contacts (id, user_id, name, phone, relation) VALUES (?,?,?,?,?)",
            contacts
        )
        conn.commit()
    conn.close()
    print(f"Database initialized: {DB_FILE}")

# ─── Auth Helpers ─────────────────────────────────────────────────────────────
def hash_password(password: str) -> str:
    salt = os.urandom(16)
    key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100_000)
    return base64.b64encode(salt + key).decode()

def verify_password(password: str, stored_hash: str) -> bool:
    try:
        data = base64.b64decode(stored_hash.encode())
        salt, key = data[:16], data[16:]
        check = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100_000)
        return hmac.compare_digest(key, check)
    except Exception:
        return False

def create_token(user_id: str, name: str) -> str:
    header = base64.urlsafe_b64encode(json.dumps({"alg":"HS256","typ":"JWT"}).encode()).decode().rstrip("=")
    exp = int((datetime.utcnow() + timedelta(days=7)).timestamp())
    payload = base64.urlsafe_b64encode(json.dumps({"sub": user_id, "name": name, "exp": exp}).encode()).decode().rstrip("=")
    sig_input = f"{header}.{payload}".encode()
    sig = base64.urlsafe_b64encode(hmac.new(JWT_SECRET.encode(), sig_input, hashlib.sha256).digest()).decode().rstrip("=")
    return f"{header}.{payload}.{sig}"

def verify_token(token: str):
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        header, payload, sig = parts
        sig_input = f"{header}.{payload}".encode()
        expected = base64.urlsafe_b64encode(hmac.new(JWT_SECRET.encode(), sig_input, hashlib.sha256).digest()).decode().rstrip("=")
        if not hmac.compare_digest(sig, expected):
            return None
        pad = lambda s: s + "=" * (-len(s) % 4)
        data = json.loads(base64.urlsafe_b64decode(pad(payload)).decode())
        if data.get("exp", 0) < datetime.utcnow().timestamp():
            return None
        return data
    except Exception:
        return None

def get_auth_user(handler):
    auth = handler.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    return verify_token(auth[7:])

# ─── Router ───────────────────────────────────────────────────────────────────
ROUTES = {}

def route(method, path):
    def dec(fn):
        ROUTES[(method, path)] = fn
        return fn
    return dec

def match_route(method, path):
    for (m, p), fn in ROUTES.items():
        if m != method:
            continue
        pattern = re.sub(r":(\w+)", r"(?P<\1>[^/]+)", p) + "$"
        m2 = re.match(pattern, path)
        if m2:
            return fn, m2.groupdict()
    return None, {}

# ─── Route Handlers ───────────────────────────────────────────────────────────

@route("POST", "/api/auth/register")
def register(body, params, user):
    name = body.get("name", "").strip()
    email = body.get("email", "").strip().lower()
    password = body.get("password", "")
    phone = body.get("phone", "").strip()

    if not all([name, email, password]):
        return 400, {"error": "Name, email and password are required"}
    if len(password) < 6:
        return 400, {"error": "Password must be at least 6 characters"}

    conn = get_db()
    existing = conn.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
    if existing:
        conn.close()
        return 409, {"error": "Email already registered"}

    user_id = str(uuid.uuid4())
    pw_hash = hash_password(password)
    conn.execute(
        "INSERT INTO users (id, name, email, phone, password_hash) VALUES (?,?,?,?,?)",
        (user_id, name, email, phone, pw_hash)
    )
    conn.commit()
    conn.close()
    token = create_token(user_id, name)
    return 201, {"token": token, "user": {"id": user_id, "name": name, "email": email, "phone": phone}}

@route("POST", "/api/auth/login")
def login(body, params, user):
    email = body.get("email", "").strip().lower()
    password = body.get("password", "")
    conn = get_db()
    row = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    conn.close()
    if not row or not verify_password(password, row["password_hash"]):
        return 401, {"error": "Invalid email or password"}
    token = create_token(row["id"], row["name"])
    return 200, {"token": token, "user": {"id": row["id"], "name": row["name"], "email": row["email"], "phone": row["phone"]}}

@route("GET", "/api/auth/me")
def get_me(body, params, user):
    if not user:
        return 401, {"error": "Unauthorized"}
    conn = get_db()
    row = conn.execute("SELECT id, name, email, phone, created_at FROM users WHERE id=?", (user["sub"],)).fetchone()
    conn.close()
    if not row:
        return 404, {"error": "User not found"}
    return 200, dict(row)

# Emergency Contacts
@route("GET", "/api/contacts")
def get_contacts(body, params, user):
    if not user:
        return 401, {"error": "Unauthorized"}
    conn = get_db()
    rows = conn.execute("SELECT * FROM emergency_contacts WHERE user_id=?", (user["sub"],)).fetchall()
    conn.close()
    return 200, [dict(r) for r in rows]

@route("POST", "/api/contacts")
def add_contact(body, params, user):
    if not user:
        return 401, {"error": "Unauthorized"}
    name = body.get("name", "").strip()
    phone = body.get("phone", "").strip()
    relation = body.get("relation", "").strip()
    if not name or not phone:
        return 400, {"error": "Name and phone required"}
    contact_id = str(uuid.uuid4())
    conn = get_db()
    conn.execute(
        "INSERT INTO emergency_contacts (id, user_id, name, phone, relation) VALUES (?,?,?,?,?)",
        (contact_id, user["sub"], name, phone, relation)
    )
    conn.commit()
    conn.close()
    return 201, {"id": contact_id, "name": name, "phone": phone, "relation": relation}

@route("DELETE", "/api/contacts/:id")
def delete_contact(body, params, user):
    if not user:
        return 401, {"error": "Unauthorized"}
    conn = get_db()
    conn.execute("DELETE FROM emergency_contacts WHERE id=? AND user_id=?", (params["id"], user["sub"]))
    conn.commit()
    conn.close()
    return 200, {"message": "Contact deleted"}

# SOS Alerts
@route("POST", "/api/sos")
def trigger_sos(body, params, user):
    if not user:
        return 401, {"error": "Unauthorized"}
    alert_id = str(uuid.uuid4())
    lat = body.get("latitude")
    lng = body.get("longitude")
    address = body.get("address", "Location shared")
    conn = get_db()
    conn.execute(
        "INSERT INTO sos_alerts (id, user_id, latitude, longitude, address) VALUES (?,?,?,?,?)",
        (alert_id, user["sub"], lat, lng, address)
    )
    # Get contacts to "notify"
    contacts = conn.execute("SELECT * FROM emergency_contacts WHERE user_id=?", (user["sub"],)).fetchall()
    conn.commit()
    conn.close()
    # In production: send SMS/call via Twilio here
    return 201, {
        "alert_id": alert_id,
        "status": "active",
        "contacts_notified": [{"name": c["name"], "phone": c["phone"]} for c in contacts],
        "message": "SOS alert sent to your emergency contacts"
    }

@route("PUT", "/api/sos/:id/cancel")
def cancel_sos(body, params, user):
    if not user:
        return 401, {"error": "Unauthorized"}
    conn = get_db()
    conn.execute(
        "UPDATE sos_alerts SET status='cancelled', resolved_at=? WHERE id=? AND user_id=?",
        (datetime.utcnow().isoformat(), params["id"], user["sub"])
    )
    conn.commit()
    conn.close()
    return 200, {"message": "Alert cancelled"}

@route("GET", "/api/sos/history")
def sos_history(body, params, user):
    if not user:
        return 401, {"error": "Unauthorized"}
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM sos_alerts WHERE user_id=? ORDER BY created_at DESC LIMIT 20",
        (user["sub"],)
    ).fetchall()
    conn.close()
    return 200, [dict(r) for r in rows]

# Incident Reports
@route("POST", "/api/incidents")
def create_incident(body, params, user):
    if not user:
        return 401, {"error": "Unauthorized"}
    inc_id = str(uuid.uuid4())
    conn = get_db()
    conn.execute(
        "INSERT INTO incident_reports (id, user_id, type, description, latitude, longitude, address, severity) VALUES (?,?,?,?,?,?,?,?)",
        (inc_id, user["sub"], body.get("type",""), body.get("description",""),
         body.get("latitude"), body.get("longitude"), body.get("address",""),
         body.get("severity","medium"))
    )
    conn.commit()
    conn.close()
    return 201, {"id": inc_id, "message": "Incident reported successfully"}

@route("GET", "/api/incidents")
def list_incidents(body, params, user):
    if not user:
        return 401, {"error": "Unauthorized"}
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM incident_reports WHERE user_id=? ORDER BY created_at DESC",
        (user["sub"],)
    ).fetchall()
    conn.close()
    return 200, [dict(r) for r in rows]

# Safe Routes
@route("POST", "/api/routes/find")
def find_route(body, params, user):
    if not user:
        return 401, {"error": "Unauthorized"}
    from_loc = body.get("from", "")
    to_loc = body.get("to", "")
    if not from_loc or not to_loc:
        return 400, {"error": "Origin and destination required"}
    # Simulate route calculation (in production: Google Maps / OSRM API)
    import random
    distance = round(random.uniform(2.5, 15.0), 1)
    time_mins = int(distance * 3.5)
    safety_score = random.randint(72, 96)
    route_id = str(uuid.uuid4())
    conn = get_db()
    conn.execute(
        "INSERT INTO safe_routes (id, user_id, from_location, to_location, distance_km, est_time_mins, safety_score) VALUES (?,?,?,?,?,?,?)",
        (route_id, user["sub"], from_loc, to_loc, distance, time_mins, safety_score)
    )
    conn.commit()
    conn.close()
    return 200, {
        "id": route_id,
        "from": from_loc,
        "to": to_loc,
        "distance_km": distance,
        "est_time_mins": time_mins,
        "safety_score": safety_score,
        "safety_level": "High" if safety_score >= 80 else "Medium" if safety_score >= 60 else "Low",
        "police_stations_nearby": random.randint(1, 4),
        "well_lit": safety_score >= 75,
        "alternate_available": True
    }

# AI Detection (mock - integrate with vision API in production)
@route("POST", "/api/detect")
def ai_detect(body, params, user):
    if not user:
        return 401, {"error": "Unauthorized"}
    # In production: send image to vision model (Gemini/GPT-4V/Claude)
    return 200, {
        "detected": True,
        "object": "No threat detected",
        "confidence": 98,
        "threat_level": "SAFE",
        "recommended_action": "Your surroundings appear safe. Stay alert and trust your instincts.",
        "note": "Connect a vision AI API (Claude Vision / Google Vision) for real detection"
    }

# Chat (uses Claude API in production)
@route("POST", "/api/chat")
def chat(body, params, user):
    if not user:
        return 401, {"error": "Unauthorized"}
    message = body.get("message", "").strip()
    responses = {
        "followed": "If you feel someone is following you:\n1. Stay calm and move to a crowded area\n2. Enter a shop or public building\n3. Call Police: 100 or Women Helpline: 181\n4. Use the SOS button if in danger\n5. Trust your instincts — don't hesitate to call for help",
        "helpline": "Important helpline numbers:\n• Police: 100\n• Women Helpline: 181\n• Women Helpline (All India): 1091\n• Child Helpline: 1098\n• National Emergency: 112\n• Cyber Crime: 1930",
        "safe": "Safety tips:\n1. Share your live location with trusted contacts\n2. Avoid isolated areas at night\n3. Keep your phone charged\n4. Trust your gut feeling\n5. Use our Safe Route feature to find well-lit paths",
    }
    msg_lower = message.lower()
    if any(w in msg_lower for w in ["follow", "stalking", "scared"]):
        reply = responses["followed"]
    elif any(w in msg_lower for w in ["helpline", "number", "call", "police"]):
        reply = responses["helpline"]
    else:
        reply = responses["safe"]
    return 200, {"reply": reply, "timestamp": datetime.utcnow().isoformat()}

# Nearby Services (mock - integrate with Google Places in production)
@route("GET", "/api/nearby")
def nearby_services(body, params, user):
    if not user:
        return 401, {"error": "Unauthorized"}
    return 200, {
        "police_stations": [
            {"name": "MG Road Police Station", "distance": "0.8 km", "phone": "100", "open_24h": True},
            {"name": "Brigade Road Station", "distance": "1.5 km", "phone": "080-22942222", "open_24h": True},
        ],
        "hospitals": [
            {"name": "Apollo Hospital", "distance": "1.2 km", "phone": "080-26304050", "open_24h": True},
            {"name": "Manipal Hospital", "distance": "2.1 km", "phone": "080-25024444", "open_24h": True},
        ],
        "help_centers": [
            {"name": "Women's Welfare Centre", "distance": "0.5 km", "phone": "181", "open_24h": False},
        ]
    }

# ─── HTTP Handler ─────────────────────────────────────────────────────────────
class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        print(f"[{datetime.now().strftime('%H:%M:%S')}] {fmt % args}")

    def send_json(self, status, data):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", CORS_ORIGIN)
        self.send_header("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type,Authorization")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", CORS_ORIGIN)
        self.send_header("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type,Authorization")
        self.end_headers()

    def handle_request(self, method):
        parsed = urlparse(self.path)
        path = parsed.path
        fn, params = match_route(method, path)
        if not fn:
            self.send_json(404, {"error": f"Route not found: {method} {path}"})
            return
        body = {}
        if method in ("POST", "PUT", "PATCH"):
            length = int(self.headers.get("Content-Length", 0))
            if length:
                try:
                    body = json.loads(self.rfile.read(length).decode())
                except Exception:
                    body = {}
        user = verify_token(self.headers.get("Authorization", "")[7:]) if self.headers.get("Authorization", "").startswith("Bearer ") else None
        try:
            status, data = fn(body, params, user)
            self.send_json(status, data)
        except Exception as e:
            print(f"Error: {e}")
            self.send_json(500, {"error": "Internal server error"})

    def do_GET(self): self.handle_request("GET")
    def do_POST(self): self.handle_request("POST")
    def do_PUT(self): self.handle_request("PUT")
    def do_DELETE(self): self.handle_request("DELETE")

# ─── Main ─────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    init_db()
    server = HTTPServer(("0.0.0.0", PORT), Handler)
    print(f"🛡️  Women Safety Backend running on http://localhost:{PORT}")
    print(f"📋 Demo login: priya@demo.com / demo1234")
    print(f"📖 Endpoints:")
    for (method, path) in ROUTES:
        print(f"   {method:6} {path}")
    server.serve_forever()
