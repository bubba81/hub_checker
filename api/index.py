"""
HubChecker Dashboard
Flask + Neon Postgres + Discord OAuth — Vercel deployment
"""
import os, secrets, psycopg2, psycopg2.extras
from datetime import datetime
from functools import wraps
from flask import (Flask, render_template, request, redirect,
                   url_for, session, jsonify, abort)
import requests

app = Flask(__name__, template_folder="../templates")
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

# ── Config ────────────────────────────────────────────────────────────────────
DISCORD_CLIENT_ID     = os.environ.get("DISCORD_CLIENT_ID", "")
DISCORD_CLIENT_SECRET = os.environ.get("DISCORD_CLIENT_SECRET", "")
DISCORD_REDIRECT_URI  = os.environ.get("DISCORD_REDIRECT_URI",
                                        "https://hub-checker.vercel.app/callback")
ALLOWED_IDS           = set(os.environ.get("ALLOWED_USER_IDS",
                            "1300155466193702974,1075384554120040559").split(","))
DATABASE_URL          = os.environ.get("DATABASE_URL", "")   # Neon postgres URL

DISCORD_API   = "https://discord.com/api/v10"
DISCORD_OAUTH = "https://discord.com/oauth2/authorize"
DISCORD_TOKEN = "https://discord.com/api/oauth2/token"

SCAN_PHASES = [
    "Initializing", "USN Journal Scan", "BAM Live Scan", "Prefetch Scan",
    "Signature Check", "VSS Cleanup", "Roblox Process Memory",
    "Injected Modules Check", "Discord Memory Scan", "Roblox Log Analysis",
    "Roblox FFlags Scan", "Registry Run Keys", "Recent Items Scan",
    "UserAssist Scan", "Browser Memory Scan", "Prefetch Integrity",
    "Amcache Integrity", "Shimcache Integrity", "SRUM Integrity",
    "Defender Integrity", "BAM Integrity", "USB History",
    "System Restore Points", "Recent Folder Integrity", "Services Check",
    "Unsigned Executables", "API Submission", "Webhook Upload", "Complete",
]

app.jinja_env.globals["enumerate"] = enumerate

# ── Database ──────────────────────────────────────────────────────────────────
def get_conn():
    return psycopg2.connect(DATABASE_URL, cursor_factory=psycopg2.extras.RealDictCursor)

def init_db():
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    id           SERIAL PRIMARY KEY,
                    scan_key     TEXT NOT NULL UNIQUE,
                    desktop_name TEXT NOT NULL,
                    created_at   TEXT NOT NULL,
                    updated_at   TEXT NOT NULL,
                    status       TEXT NOT NULL DEFAULT 'running',
                    trinity_json TEXT,
                    log_text     TEXT,
                    phase_index  INTEGER NOT NULL DEFAULT 0,
                    hostname     TEXT,
                    username     TEXT,
                    os_version   TEXT
                );
                CREATE TABLE IF NOT EXISTS scan_events (
                    id          SERIAL PRIMARY KEY,
                    scan_id     INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                    phase_index INTEGER NOT NULL,
                    phase_name  TEXT NOT NULL,
                    pct         INTEGER NOT NULL,
                    message     TEXT,
                    ts          TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS scan_findings (
                    id       SERIAL PRIMARY KEY,
                    scan_id  INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                    category TEXT NOT NULL,
                    severity TEXT NOT NULL DEFAULT 'info',
                    detail   TEXT NOT NULL,
                    ts       TEXT NOT NULL
                );
            """)
        conn.commit()

# Run init on cold start
try:
    init_db()
except Exception as e:
    print(f"DB init warning: {e}")

# ── Auth ──────────────────────────────────────────────────────────────────────
def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        if session.get("user_id") not in ALLOWED_IDS:
            return render_template("unauthorized.html"), 403
        return f(*args, **kwargs)
    return decorated

# ── Discord OAuth ─────────────────────────────────────────────────────────────
@app.route("/login")
def login():
    state = secrets.token_hex(16)
    session["oauth_state"] = state
    params = (f"?client_id={DISCORD_CLIENT_ID}"
              f"&redirect_uri={DISCORD_REDIRECT_URI}"
              f"&response_type=code&scope=identify&state={state}")
    return redirect(DISCORD_OAUTH + params)

@app.route("/callback")
def callback():
    if request.args.get("state") != session.pop("oauth_state", None):
        return "Invalid OAuth state", 400
    code = request.args.get("code")
    if not code:
        return "No code returned", 400

    r = requests.post(DISCORD_TOKEN, data={
        "client_id": DISCORD_CLIENT_ID, "client_secret": DISCORD_CLIENT_SECRET,
        "grant_type": "authorization_code", "code": code,
        "redirect_uri": DISCORD_REDIRECT_URI,
    }, headers={"Content-Type": "application/x-www-form-urlencoded"})
    if not r.ok:
        return f"Token exchange failed: {r.text}", 400

    access_token = r.json().get("access_token")
    user_r = requests.get(f"{DISCORD_API}/users/@me",
                          headers={"Authorization": f"Bearer {access_token}"})
    if not user_r.ok:
        return "Failed to fetch user info", 400

    user = user_r.json()
    session["user_id"]     = user["id"]
    session["username"]    = user["username"]
    session["avatar"]      = user.get("avatar")
    session["global_name"] = user.get("global_name", user["username"])

    if user["id"] not in ALLOWED_IDS:
        return render_template("unauthorized.html"), 403
    return redirect(url_for("dashboard"))

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# ── Dashboard pages ───────────────────────────────────────────────────────────
@app.route("/")
@require_auth
def dashboard():
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM scans ORDER BY created_at DESC")
            scans = cur.fetchall()
    return render_template("dashboard.html", scans=scans,
                           username=session.get("global_name"),
                           avatar=session.get("avatar"),
                           user_id=session.get("user_id"),
                           phases=SCAN_PHASES)

@app.route("/scan/<int:scan_id>/view")
@require_auth
def view_scan(scan_id):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM scans WHERE id=%s", (scan_id,))
            scan = cur.fetchone()
            if not scan:
                abort(404)
            cur.execute("SELECT * FROM scan_events WHERE scan_id=%s ORDER BY phase_index", (scan_id,))
            events = cur.fetchall()
            cur.execute("SELECT * FROM scan_findings WHERE scan_id=%s ORDER BY id", (scan_id,))
            findings = cur.fetchall()
    return render_template("view_scan.html", scan=scan, events=events,
                           findings=findings, phases=SCAN_PHASES,
                           username=session.get("global_name"),
                           avatar=session.get("avatar"))

# ── Dashboard AJAX ────────────────────────────────────────────────────────────

@app.route("/api/scans")
@require_auth
def api_scans():
    """Returns all scans as JSON for the dashboard frontend."""
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM scans ORDER BY created_at DESC")
            rows = cur.fetchall()
    # Normalise: DB stores 'complete', JS expects 'completed'
    result = []
    for r in rows:
        d = dict(r)
        if d.get("status") == "complete":
            d["status"] = "completed"
        result.append(d)
    return jsonify(result)

@app.route("/api/scan/<int:scan_id>/delete", methods=["POST"])
@require_auth
def delete_scan(scan_id):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM scans WHERE id=%s", (scan_id,))
        conn.commit()
    return jsonify({"ok": True})

@app.route("/api/scan/<int:scan_id>/rename", methods=["POST"])
@require_auth
def rename_scan(scan_id):
    data = request.get_json()
    new_name = (data or {}).get("name", "").strip()
    if not new_name:
        return jsonify({"ok": False, "error": "Name required"}), 400
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE scans SET desktop_name=%s, updated_at=%s WHERE id=%s",
                        (new_name, _now(), scan_id))
        conn.commit()
    return jsonify({"ok": True, "name": new_name})

@app.route("/api/scan/<int:scan_id>/findings")
@require_auth
def scan_findings(scan_id):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM scan_findings WHERE scan_id=%s ORDER BY id", (scan_id,))
            rows = cur.fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/api/scan/<int:scan_id>/log")
@require_auth
def scan_log(scan_id):
    """GET /api/scan/<id>/log — returns the full raw log text."""
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT log_text FROM scans WHERE id=%s", (scan_id,))
            row = cur.fetchone()
    if not row:
        return jsonify({"log": ""}), 404
    return jsonify({"log": row.get("log_text") or ""})

@app.route("/api/scan/<int:scan_id>/progress")
@require_auth
def scan_progress(scan_id):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM scans WHERE id=%s", (scan_id,))
            scan = cur.fetchone()
            if not scan:
                abort(404)
            cur.execute("SELECT * FROM scan_events WHERE scan_id=%s ORDER BY phase_index", (scan_id,))
            events = cur.fetchall()
    status = scan["status"]
    if status == "complete": status = "completed"
    return jsonify({
        "status": status,
        "phase_index": scan["phase_index"],
        "total_phases": len(SCAN_PHASES),
        "events": [dict(e) for e in events],
    })

# ── Extra REST routes called by dashboard.html JS ────────────────────────────

@app.route("/api/scans/<int:scan_id>")
@require_auth
def api_scan_detail(scan_id):
    """GET /api/scans/<id> — returns scan + events + findings as JSON."""
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM scans WHERE id=%s", (scan_id,))
            scan = cur.fetchone()
            if not scan:
                abort(404)
            cur.execute("SELECT * FROM scan_events WHERE scan_id=%s ORDER BY phase_index", (scan_id,))
            events = cur.fetchall()
            cur.execute("SELECT * FROM scan_findings WHERE scan_id=%s ORDER BY id", (scan_id,))
            findings = cur.fetchall()
    s = dict(scan)
    if s.get("status") == "complete":
        s["status"] = "completed"
    return jsonify({
        "scan": s,
        "progress": [dict(e) for e in events],
        "results": [dict(f) for f in findings],
        "trinity_json": s.get("trinity_json"),
        "log_text": s.get("log_text", ""),
    })

@app.route("/api/scans/<int:scan_id>", methods=["DELETE"])
@require_auth
def api_scan_delete(scan_id):
    """DELETE /api/scans/<id>"""
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM scan_findings WHERE scan_id=%s", (scan_id,))
            cur.execute("DELETE FROM scan_events WHERE scan_id=%s", (scan_id,))
            cur.execute("DELETE FROM scans WHERE id=%s", (scan_id,))
        conn.commit()
    return jsonify({"ok": True})

@app.route("/api/scans/<int:scan_id>/rename", methods=["PATCH", "POST"])
@require_auth
def api_scan_rename(scan_id):
    """PATCH /api/scans/<id>/rename"""
    data     = request.get_json(force=True) or {}
    new_name = data.get("desktop_name", data.get("name", "")).strip()
    if not new_name:
        return jsonify({"ok": False, "error": "Name required"}), 400
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE scans SET desktop_name=%s, updated_at=%s WHERE id=%s",
                        (new_name, _now(), scan_id))
        conn.commit()
    return jsonify({"ok": True, "name": new_name})

@app.route("/api/scan", methods=["POST"])
def trinity_scan_submit():
    """POST /api/scan — receives full structured JSON from the C++ exe.
    Stores everything: trinity detail + all hits array."""
    import json as _json
    data = request.get_json(force=True) or {}

    sys_info = data.get("systemInfo", {})
    hostname = sys_info.get("hostname", "")
    username = sys_info.get("username", "")
    scan_key = data.get("scan_key", "")

    with get_conn() as conn:
        with conn.cursor() as cur:
            # Match by scan_key first (most reliable), then hostname+username, then latest
            row = None
            if scan_key:
                cur.execute("SELECT id FROM scans WHERE scan_key=%s LIMIT 1", (scan_key,))
                row = cur.fetchone()
            if not row and hostname and username:
                cur.execute("""SELECT id FROM scans WHERE hostname=%s AND username=%s
                               ORDER BY created_at DESC LIMIT 1""", (hostname, username))
                row = cur.fetchone()
            if not row:
                cur.execute("SELECT id FROM scans ORDER BY created_at DESC LIMIT 1")
                row = cur.fetchone()
            if not row:
                return jsonify({"ok": False, "error": "No matching scan found"}), 404

            scan_id = row["id"]

            # Ensure columns exist
            cur.execute("ALTER TABLE scans ADD COLUMN IF NOT EXISTS trinity_json TEXT")
            cur.execute("ALTER TABLE scans ADD COLUMN IF NOT EXISTS log_text TEXT")

            # Store the full JSON blob + raw log
            raw_log = data.get("rawLog", "")
            cur.execute("UPDATE scans SET trinity_json=%s, log_text=%s, updated_at=%s WHERE id=%s",
                        (_json.dumps(data), raw_log, _now(), scan_id))

            # Also insert every hit from the hits array into scan_findings
            hits = data.get("hits", [])
            for h in hits:
                severity = h.get("severity", "alert")
                category = h.get("category", "")
                detail = (
                    f"[{h.get('tool','')}] {h.get('path') or h.get('filename','')}"
                    + (f" | {h.get('eventType','')}" if h.get('eventType') else "")
                    + (f" | Last Run: {h.get('timestamp','')}" if h.get('timestamp') else "")
                )
                cur.execute("""INSERT INTO scan_findings (scan_id, category, severity, detail, created_at)
                               VALUES (%s, %s, %s, %s, %s)""",
                            (scan_id, category, severity, detail[:2000], _now()))

        conn.commit()

    return jsonify({"ok": True, "scan_id": scan_id, "hits_stored": len(data.get("hits", []))})

# ── Scanner API (called by C++ exe) ──────────────────────────────────────────
@app.route("/api/scanner/start", methods=["POST"])
def scanner_start():
    data     = request.get_json(force=True) or {}
    scan_key = data.get("scan_key") or secrets.token_hex(8)
    desktop  = data.get("desktop_name", "Unknown Desktop")
    now      = _now()
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO scans
                  (scan_key,desktop_name,created_at,updated_at,status,phase_index,hostname,username,os_version)
                VALUES (%s,%s,%s,%s,'running',0,%s,%s,%s)
                ON CONFLICT (scan_key) DO NOTHING
                RETURNING id
            """, (scan_key, desktop, now, now,
                  data.get("hostname",""), data.get("username",""), data.get("os_version","")))
            row = cur.fetchone()
            if not row:
                cur.execute("SELECT id FROM scans WHERE scan_key=%s", (scan_key,))
                row = cur.fetchone()
        conn.commit()
    return jsonify({"ok": True, "scan_id": row["id"], "scan_key": scan_key})

@app.route("/api/scanner/progress", methods=["POST"])
def scanner_progress():
    data     = request.get_json(force=True) or {}
    scan_key = data.get("scan_key")
    if not scan_key:
        abort(400)
    pi  = int(data.get("phase_index", 0))
    pn  = data.get("phase_name", SCAN_PHASES[min(pi, len(SCAN_PHASES)-1)])
    now = _now()
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM scans WHERE scan_key=%s", (scan_key,))
            scan = cur.fetchone()
            if not scan:
                abort(404)
            cur.execute("""
                INSERT INTO scan_events (scan_id,phase_index,phase_name,pct,message,ts)
                VALUES (%s,%s,%s,%s,%s,%s)
            """, (scan["id"], pi, pn, int(data.get("pct", 0)), data.get("message",""), now))
            cur.execute("UPDATE scans SET phase_index=%s, updated_at=%s WHERE id=%s",
                        (pi, now, scan["id"]))
        conn.commit()
    return jsonify({"ok": True})

@app.route("/api/scanner/finding", methods=["POST"])
def scanner_finding():
    data     = request.get_json(force=True) or {}
    scan_key = data.get("scan_key")
    if not scan_key:
        abort(400)
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM scans WHERE scan_key=%s", (scan_key,))
            scan = cur.fetchone()
            if not scan:
                abort(404)
            cur.execute("""
                INSERT INTO scan_findings (scan_id,category,severity,detail,ts)
                VALUES (%s,%s,%s,%s,%s)
            """, (scan["id"], data.get("category","general"),
                  data.get("severity","warn"), data.get("detail",""), _now()))
        conn.commit()
    return jsonify({"ok": True})

@app.route("/api/scanner/complete", methods=["POST"])
def scanner_complete():
    data     = request.get_json(force=True) or {}
    scan_key = data.get("scan_key")
    if not scan_key:
        abort(400)
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE scans SET status='complete', phase_index=%s, updated_at=%s
                WHERE scan_key=%s
            """, (len(SCAN_PHASES)-1, _now(), scan_key))
        conn.commit()
    return jsonify({"ok": True})

# ── Helpers ───────────────────────────────────────────────────────────────────
def _now():
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

# Vercel WSGI entrypoint
app = app
