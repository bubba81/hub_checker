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
DATABASE_URL          = os.environ.get("DATABASE_URL", "")

DISCORD_API   = "https://discord.com/api/v10"
DISCORD_OAUTH = "https://discord.com/oauth2/authorize"
DISCORD_TOKEN = "https://discord.com/api/oauth2/token"

# Bot token for looking up arbitrary Discord users by ID in the admin panel.
# Set DISCORD_BOT_TOKEN in your Vercel env vars.
DISCORD_BOT_TOKEN = os.environ.get("DISCORD_BOT_TOKEN", "")

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
                    id              SERIAL PRIMARY KEY,
                    scan_key        TEXT NOT NULL UNIQUE,
                    desktop_name    TEXT NOT NULL,
                    created_at      TEXT NOT NULL,
                    updated_at      TEXT NOT NULL,
                    status          TEXT NOT NULL DEFAULT 'running',
                    trinity_json    TEXT,
                    log_text        TEXT,
                    phase_index     INTEGER NOT NULL DEFAULT 0,
                    hostname        TEXT,
                    username        TEXT,
                    os_version      TEXT,
                    discord_user_id TEXT
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
                    id          SERIAL PRIMARY KEY,
                    scan_id     INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                    category    TEXT NOT NULL,
                    severity    TEXT NOT NULL DEFAULT 'info',
                    detail      TEXT NOT NULL,
                    ts          TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS scan_pins (
                    id         SERIAL PRIMARY KEY,
                    pin        TEXT NOT NULL UNIQUE,
                    scan_key   TEXT NOT NULL UNIQUE,
                    label      TEXT NOT NULL DEFAULT '',
                    used       BOOLEAN NOT NULL DEFAULT FALSE,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL DEFAULT '',
                    used_at    TEXT
                );
                CREATE TABLE IF NOT EXISTS scanner_users (
                    id              SERIAL PRIMARY KEY,
                    discord_user_id TEXT NOT NULL UNIQUE,
                    discord_name    TEXT NOT NULL DEFAULT '',
                    discord_avatar  TEXT NOT NULL DEFAULT '',
                    access_until    TEXT NOT NULL,
                    added_by        TEXT NOT NULL,
                    added_at        TEXT NOT NULL,
                    notes           TEXT NOT NULL DEFAULT ''
                );
            """)
        conn.commit()

try:
    init_db()
except Exception as e:
    print(f"DB init warning: {e}")

# ── Migrations (safe on every cold start) ────────────────────────────────────
try:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("ALTER TABLE scans ADD COLUMN IF NOT EXISTS trinity_json TEXT")
            cur.execute("ALTER TABLE scans ADD COLUMN IF NOT EXISTS log_text TEXT")
            cur.execute("ALTER TABLE scans ADD COLUMN IF NOT EXISTS discord_user_id TEXT")
            cur.execute("""
                CREATE TABLE IF NOT EXISTS scan_pins (
                    id         SERIAL PRIMARY KEY,
                    pin        TEXT NOT NULL UNIQUE,
                    scan_key   TEXT NOT NULL UNIQUE,
                    label      TEXT NOT NULL DEFAULT '',
                    used       BOOLEAN NOT NULL DEFAULT FALSE,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL DEFAULT '',
                    used_at    TEXT
                )
            """)
            cur.execute("ALTER TABLE scan_pins ADD COLUMN IF NOT EXISTS expires_at TEXT NOT NULL DEFAULT ''")
            cur.execute("ALTER TABLE scan_findings ADD COLUMN IF NOT EXISTS keyword TEXT NOT NULL DEFAULT ''")
            cur.execute("ALTER TABLE scan_findings ADD COLUMN IF NOT EXISTS fields_json TEXT NOT NULL DEFAULT ''")
            cur.execute("""
                CREATE TABLE IF NOT EXISTS scanner_users (
                    id              SERIAL PRIMARY KEY,
                    discord_user_id TEXT NOT NULL UNIQUE,
                    discord_name    TEXT NOT NULL DEFAULT '',
                    discord_avatar  TEXT NOT NULL DEFAULT '',
                    access_until    TEXT NOT NULL,
                    added_by        TEXT NOT NULL,
                    added_at        TEXT NOT NULL,
                    notes           TEXT NOT NULL DEFAULT ''
                )
            """)
            cur.execute("ALTER TABLE scanner_users ADD COLUMN IF NOT EXISTS notes TEXT NOT NULL DEFAULT ''")
        conn.commit()
except Exception as e:
    print(f"Migration warning: {e}")

# ── Auth helpers ──────────────────────────────────────────────────────────────
def require_auth(f):
    """Requires the user to be in ALLOWED_IDS (admin only)."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        if session.get("user_id") not in ALLOWED_IDS:
            return render_template("unauthorized.html"), 403
        return f(*args, **kwargs)
    return decorated

def require_scanner_user(f):
    """
    Requires the user to be logged in AND either:
      - in ALLOWED_IDS (admin), OR
      - in scanner_users with a non-expired access_until date.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        uid = session.get("user_id")
        if uid in ALLOWED_IDS:
            return f(*args, **kwargs)
        try:
            with get_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "SELECT access_until FROM scanner_users WHERE discord_user_id=%s",
                        (uid,)
                    )
                    row = cur.fetchone()
            if row and row["access_until"] >= _now()[:10]:
                return f(*args, **kwargs)
        except Exception:
            pass
        return render_template("unauthorized.html"), 403
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
    uid  = user["id"]

    # ── Check access BEFORE writing anything to the session ──────────────
    # Admin always allowed
    if uid in ALLOWED_IDS:
        session["user_id"]     = uid
        session["username"]    = user["username"]
        session["avatar"]      = user.get("avatar")
        session["global_name"] = user.get("global_name", user["username"])
        return redirect(url_for("dashboard"))

    # Scanner user with valid, non-expired access
    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT access_until FROM scanner_users WHERE discord_user_id=%s",
                    (uid,)
                )
                row = cur.fetchone()
        if row and row["access_until"] >= _now()[:10]:
            session["user_id"]     = uid
            session["username"]    = user["username"]
            session["avatar"]      = user.get("avatar")
            session["global_name"] = user.get("global_name", user["username"])
            return redirect(url_for("dashboard"))
    except Exception:
        pass

    # No valid session written — user is not authorised
    session.clear()
    return render_template("unauthorized.html"), 403

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# ── Pages ─────────────────────────────────────────────────────────────────────
@app.route("/")
def home():
    """Public home page — Download + Login."""
    if "user_id" in session:
        uid = session["user_id"]
        if uid in ALLOWED_IDS:
            return redirect(url_for("dashboard"))
        try:
            with get_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "SELECT access_until FROM scanner_users WHERE discord_user_id=%s",
                        (uid,)
                    )
                    row = cur.fetchone()
            if row and row["access_until"] >= _now()[:10]:
                return redirect(url_for("dashboard"))
        except Exception:
            pass
    return render_template("index.html")

@app.route("/dashboard")
@require_scanner_user
def dashboard():
    uid      = session.get("user_id")
    is_admin = uid in ALLOWED_IDS
    with get_conn() as conn:
        with conn.cursor() as cur:
            if is_admin:
                # Admins see ALL scans by default
                cur.execute("SELECT * FROM scans ORDER BY created_at DESC")
            else:
                # Scanner users see only their own scans
                cur.execute(
                    "SELECT * FROM scans WHERE discord_user_id=%s ORDER BY created_at DESC",
                    (uid,)
                )
            scans = cur.fetchall()
    return render_template("dashboard.html", scans=scans,
                           username=session.get("global_name"),
                           avatar=session.get("avatar"),
                           user_id=uid,
                           is_admin=is_admin,
                           phases=SCAN_PHASES)

@app.route("/scan/<int:scan_id>/view")
@require_scanner_user
def view_scan(scan_id):
    uid      = session.get("user_id")
    is_admin = uid in ALLOWED_IDS
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM scans WHERE id=%s", (scan_id,))
            scan = cur.fetchone()
            if not scan:
                abort(404)
            if not is_admin and scan.get("discord_user_id") != uid:
                abort(403)
            cur.execute("SELECT * FROM scan_events WHERE scan_id=%s ORDER BY phase_index", (scan_id,))
            events = cur.fetchall()
            cur.execute("SELECT * FROM scan_findings WHERE scan_id=%s ORDER BY id", (scan_id,))
            findings = cur.fetchall()
    log_text = (scan.get("log_text") or "") if scan else ""
    return render_template("view_scan.html", scan=scan, events=events,
                           findings=findings, phases=SCAN_PHASES,
                           log_text=log_text,
                           username=session.get("global_name"),
                           avatar=session.get("avatar"))

@app.route("/admin")
@require_auth
def admin_panel():
    """Admin-only panel for managing scanner users."""
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM scanner_users ORDER BY added_at DESC")
            users = cur.fetchall()
    return render_template("admin.html",
                           users=users,
                           username=session.get("global_name"),
                           avatar=session.get("avatar"),
                           user_id=session.get("user_id"))

# ── Dashboard AJAX ────────────────────────────────────────────────────────────
@app.route("/api/scans")
@require_scanner_user
def api_scans():
    """
    Returns scans as JSON.
    Admins: pass ?user_id=<discord_id> to filter to one user, omit for all.
    Scanner users: always returns only their own scans.
    """
    uid        = session.get("user_id")
    is_admin   = uid in ALLOWED_IDS
    filter_uid = request.args.get("user_id", "").strip() or None

    with get_conn() as conn:
        with conn.cursor() as cur:
            if is_admin:
                if filter_uid:
                    cur.execute("""
                        SELECT s.*, COUNT(sf.id) AS findings_count
                        FROM scans s
                        LEFT JOIN scan_findings sf ON sf.scan_id = s.id
                        WHERE s.discord_user_id = %s
                        GROUP BY s.id ORDER BY s.created_at DESC
                    """, (filter_uid,))
                else:
                    cur.execute("""
                        SELECT s.*, COUNT(sf.id) AS findings_count
                        FROM scans s
                        LEFT JOIN scan_findings sf ON sf.scan_id = s.id
                        GROUP BY s.id ORDER BY s.created_at DESC
                    """)
            else:
                cur.execute("""
                    SELECT s.*, COUNT(sf.id) AS findings_count
                    FROM scans s
                    LEFT JOIN scan_findings sf ON sf.scan_id = s.id
                    WHERE s.discord_user_id = %s
                    GROUP BY s.id ORDER BY s.created_at DESC
                """, (uid,))
            rows = cur.fetchall()

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
    data     = request.get_json()
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
@require_scanner_user
def scan_findings(scan_id):
    uid      = session.get("user_id")
    is_admin = uid in ALLOWED_IDS
    with get_conn() as conn:
        with conn.cursor() as cur:
            if not is_admin:
                cur.execute("SELECT discord_user_id FROM scans WHERE id=%s", (scan_id,))
                row = cur.fetchone()
                if not row or row["discord_user_id"] != uid:
                    abort(403)
            cur.execute("SELECT * FROM scan_findings WHERE scan_id=%s ORDER BY id", (scan_id,))
            rows = cur.fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/api/scan/<int:scan_id>/log")
@require_scanner_user
def scan_log(scan_id):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT log_text FROM scans WHERE id=%s", (scan_id,))
            row = cur.fetchone()
    if not row:
        return jsonify({"log": ""}), 404
    return jsonify({"log": row.get("log_text") or ""})

@app.route("/api/scan/<int:scan_id>/progress")
@require_scanner_user
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
    if status == "complete":
        status = "completed"
    return jsonify({
        "status":       status,
        "phase_index":  scan["phase_index"],
        "total_phases": len(SCAN_PHASES),
        "events":       [dict(e) for e in events],
    })

@app.route("/api/scans/<int:scan_id>")
@require_scanner_user
def api_scan_detail(scan_id):
    uid      = session.get("user_id")
    is_admin = uid in ALLOWED_IDS
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM scans WHERE id=%s", (scan_id,))
            scan = cur.fetchone()
            if not scan:
                abort(404)
            if not is_admin and scan.get("discord_user_id") != uid:
                abort(403)
            cur.execute("SELECT * FROM scan_events WHERE scan_id=%s ORDER BY phase_index", (scan_id,))
            events = cur.fetchall()
            cur.execute("SELECT * FROM scan_findings WHERE scan_id=%s ORDER BY id", (scan_id,))
            findings = cur.fetchall()
    s = dict(scan)
    if s.get("status") == "complete":
        s["status"] = "completed"
    return jsonify({
        "scan":         s,
        "progress":     [dict(e) for e in events],
        "results":      [dict(f) for f in findings],
        "trinity_json": s.get("trinity_json"),
        "log_text":     s.get("log_text", ""),
    })

@app.route("/api/scans/<int:scan_id>", methods=["DELETE"])
@require_auth
def api_scan_delete(scan_id):
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
    import json as _json
    data     = request.get_json(force=True) or {}
    sys_info = data.get("systemInfo", {})
    hostname = sys_info.get("hostname", "")
    username = sys_info.get("username", "")
    scan_key = data.get("scan_key", "")

    with get_conn() as conn:
        with conn.cursor() as cur:
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
            cur.execute("ALTER TABLE scans ADD COLUMN IF NOT EXISTS trinity_json TEXT")
            cur.execute("ALTER TABLE scans ADD COLUMN IF NOT EXISTS log_text TEXT")
            cur.execute("ALTER TABLE scan_findings ADD COLUMN IF NOT EXISTS keyword TEXT NOT NULL DEFAULT ''")
            cur.execute("ALTER TABLE scan_findings ADD COLUMN IF NOT EXISTS fields_json TEXT NOT NULL DEFAULT ''")

            raw_log = data.get("rawLog", "")
            cur.execute("UPDATE scans SET trinity_json=%s, log_text=%s, updated_at=%s WHERE id=%s",
                        (_json.dumps(data), raw_log, _now(), scan_id))

            hits = data.get("hits", [])
            if hits:
                cur.execute("DELETE FROM scan_findings WHERE scan_id=%s", (scan_id,))
                for h in hits:
                    severity   = h.get("severity", "alert") or "alert"
                    category   = h.get("category", "") or ""
                    keyword    = h.get("keyword", "") or ""
                    path_or_fn = h.get("path") or h.get("filename", "")
                    parts = []
                    if keyword:            parts.append(f"[{keyword}]")
                    if path_or_fn:         parts.append(path_or_fn)
                    if h.get("tool"):      parts.append(f"(tool: {h['tool']})")
                    if h.get("eventType"): parts.append(f"| {h['eventType']}")
                    if h.get("timestamp"): parts.append(f"@ {h['timestamp']}")
                    if h.get("source"):    parts.append(f"| source: {h['source']}")
                    if h.get("inSession"): parts.append(f"| in-session: {h['inSession']}")
                    if h.get("signature"): parts.append(f"| sig: {h['signature']}")
                    if h.get("signer"):    parts.append(f"| signer: {h['signer']}")
                    if h.get("onDisk"):    parts.append(f"| on-disk: {h['onDisk']}")
                    if h.get("bamSeqNum"): parts.append(f"| BAM-seq: {h['bamSeqNum']}")
                    if h.get("runCount"):  parts.append(f"| runs: {h['runCount']}")
                    if h.get("patterns"):  parts.append(f"| patterns: {'; '.join(h['patterns'])}")
                    detail      = " ".join(parts)[:2000]
                    fields_json = _json.dumps(h)
                    cur.execute("""INSERT INTO scan_findings
                                   (scan_id,category,severity,detail,keyword,fields_json,ts)
                                   VALUES (%s,%s,%s,%s,%s,%s,%s)""",
                                (scan_id, category, severity, detail, keyword, fields_json, _now()))
        conn.commit()
    return jsonify({"ok": True, "scan_id": scan_id, "hits_stored": len(hits)})

# ── Scanner API (called by C++ exe) ──────────────────────────────────────────
@app.route("/api/scanner/start", methods=["POST"])
def scanner_start():
    """
    Called by the C++ scanner at startup.
    The scan_key was issued via a PIN whose label stores the scanner user's
    discord_user_id — we look it up here and stamp it on the scan row so
    the scan appears under that user in the dashboard.
    """
    data     = request.get_json(force=True) or {}
    scan_key = data.get("scan_key") or secrets.token_hex(8)
    desktop  = data.get("desktop_name", "Unknown Desktop")
    now      = _now()

    # Resolve discord_user_id from the pin → scan_key link
    discord_user_id = None
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT label FROM scan_pins WHERE scan_key=%s", (scan_key,))
            pin_row = cur.fetchone()
            if pin_row and pin_row.get("label"):
                possible_uid = pin_row["label"].strip()
                cur.execute(
                    "SELECT discord_user_id FROM scanner_users WHERE discord_user_id=%s",
                    (possible_uid,)
                )
                su = cur.fetchone()
                if su:
                    discord_user_id = su["discord_user_id"]

            cur.execute("""
                INSERT INTO scans
                  (scan_key,desktop_name,created_at,updated_at,status,
                   phase_index,hostname,username,os_version,discord_user_id)
                VALUES (%s,%s,%s,%s,'running',0,%s,%s,%s,%s)
                ON CONFLICT (scan_key) DO NOTHING
                RETURNING id
            """, (scan_key, desktop, now, now,
                  data.get("hostname", ""), data.get("username", ""),
                  data.get("os_version", ""), discord_user_id))
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
            """, (scan["id"], pi, pn, int(data.get("pct", 0)), data.get("message", ""), now))
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
                INSERT INTO scan_findings (scan_id,category,severity,detail,keyword,ts)
                VALUES (%s,%s,%s,%s,%s,%s)
            """, (scan["id"], data.get("category", "general"),
                  data.get("severity", "warn"), data.get("detail", ""),
                  data.get("keyword", ""), _now()))
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

# ── PIN routes ────────────────────────────────────────────────────────────────
@app.route("/api/pin/generate", methods=["POST"])
@require_auth
def api_pin_generate():
    import random, string as _string
    from datetime import datetime as _dt, timedelta as _td
    data     = request.get_json(force=True) or {}
    label    = data.get("label", "").strip()[:80]
    pin      = "".join(random.choices(_string.digits, k=6))
    scan_key = secrets.token_hex(8)
    now      = _now()
    expires  = (_dt.utcnow() + _td(minutes=30)).strftime("%Y-%m-%d %H:%M:%S")
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "DELETE FROM scan_pins WHERE expires_at <> '' AND expires_at < %s AND used = FALSE",
                (now,)
            )
            cur.execute("""INSERT INTO scan_pins (pin,scan_key,label,used,created_at,expires_at)
                           VALUES (%s,%s,%s,FALSE,%s,%s)""",
                        (pin, scan_key, label, now, expires))
        conn.commit()
    return jsonify({"ok": True, "pin": pin, "scan_key": scan_key, "expires_at": expires})

@app.route("/api/pin/validate", methods=["GET"])
def api_pin_validate():
    pin = request.args.get("pin", "").strip()
    if not pin:
        return jsonify({"ok": False, "error": "PIN required"}), 400
    now = _now()
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM scan_pins WHERE pin=%s", (pin,))
            row = cur.fetchone()
            if not row:
                return jsonify({"ok": False, "error": "Invalid PIN"}), 404
            if row["used"]:
                return jsonify({"ok": False, "error": "PIN already used"}), 403
            if row["expires_at"] and row["expires_at"] < now:
                return jsonify({"ok": False, "error": "PIN expired"}), 403
            cur.execute("UPDATE scan_pins SET used=TRUE, used_at=%s WHERE pin=%s", (now, pin))
        conn.commit()
    return jsonify({"ok": True, "scan_key": row["scan_key"], "label": row["label"]})

@app.route("/api/pin/list", methods=["GET"])
@require_auth
def api_pin_list():
    now = _now()
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""SELECT pin,scan_key,label,used,created_at,expires_at,used_at
                           FROM scan_pins ORDER BY created_at DESC LIMIT 50""")
            rows = cur.fetchall()
    result = []
    for r in rows:
        d = dict(r)
        d["expired"] = bool(d.get("expires_at") and d["expires_at"] < now and not d["used"])
        result.append(d)
    return jsonify(result)

# ── Keys tab API ──────────────────────────────────────────────────────────────
@app.route("/api/keys/unused", methods=["GET"])
@require_auth
def api_keys_unused():
    now = _now()
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT id,pin,scan_key,label,created_at,expires_at
                FROM scan_pins
                WHERE used=FALSE AND (expires_at='' OR expires_at>=%s)
                ORDER BY created_at DESC
            """, (now,))
            rows = cur.fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/api/keys/<int:key_id>/revoke", methods=["POST"])
@require_auth
def api_key_revoke(key_id):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT used FROM scan_pins WHERE id=%s", (key_id,))
            row = cur.fetchone()
            if not row:
                return jsonify({"ok": False, "error": "Key not found"}), 404
            if row["used"]:
                return jsonify({"ok": False, "error": "Cannot revoke a used key"}), 409
            cur.execute("DELETE FROM scan_pins WHERE id=%s AND used=FALSE", (key_id,))
        conn.commit()
    return jsonify({"ok": True})

# ── Admin — Scanner Users API ─────────────────────────────────────────────────
@app.route("/api/admin/users", methods=["GET"])
@require_auth
def api_admin_users():
    """Return all scanner_users with their scan counts."""
    now = _now()
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT u.*,
                       COUNT(s.id)      AS scan_count,
                       MAX(s.created_at) AS last_scan_at
                FROM scanner_users u
                LEFT JOIN scans s ON s.discord_user_id = u.discord_user_id
                GROUP BY u.id
                ORDER BY u.added_at DESC
            """)
            rows = cur.fetchall()
    result = []
    for r in rows:
        d = dict(r)
        d["expired"]    = d["access_until"] < now[:10]
        d["scan_count"] = d["scan_count"] or 0
        result.append(d)
    return jsonify(result)

@app.route("/api/admin/users", methods=["POST"])
@require_auth
def api_admin_add_user():
    """Add or update a scanner user. Body: {discord_user_id, access_until, notes}."""
    data  = request.get_json(force=True) or {}
    uid   = data.get("discord_user_id", "").strip()
    until = data.get("access_until", "").strip()   # YYYY-MM-DD
    notes = data.get("notes", "").strip()[:300]

    if not uid or not until:
        return jsonify({"ok": False, "error": "discord_user_id and access_until required"}), 400

    # Fetch Discord profile via bot token
    name   = uid
    avatar = ""
    if DISCORD_BOT_TOKEN:
        try:
            resp = requests.get(f"{DISCORD_API}/users/{uid}",
                                headers={"Authorization": f"Bot {DISCORD_BOT_TOKEN}"},
                                timeout=5)
            if resp.ok:
                u      = resp.json()
                name   = u.get("global_name") or u.get("username") or uid
                avatar = u.get("avatar") or ""
        except Exception:
            pass

    now = _now()
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO scanner_users
                  (discord_user_id,discord_name,discord_avatar,access_until,added_by,added_at,notes)
                VALUES (%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT (discord_user_id) DO UPDATE SET
                  discord_name   = EXCLUDED.discord_name,
                  discord_avatar = EXCLUDED.discord_avatar,
                  access_until   = EXCLUDED.access_until,
                  notes          = EXCLUDED.notes
                RETURNING *
            """, (uid, name, avatar, until, session.get("user_id"), now, notes))
            row = cur.fetchone()
        conn.commit()
    d = dict(row)
    d["expired"]    = d["access_until"] < now[:10]
    d["scan_count"] = 0
    return jsonify({"ok": True, "user": d})

@app.route("/api/admin/users/<uid>", methods=["DELETE"])
@require_auth
def api_admin_remove_user(uid):
    """Remove a scanner user (does NOT delete their scans)."""
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM scanner_users WHERE discord_user_id=%s", (uid,))
        conn.commit()
    return jsonify({"ok": True})

@app.route("/api/admin/users/<uid>/extend", methods=["POST"])
@require_auth
def api_admin_extend_user(uid):
    """Update access_until for a user. Body: {access_until}."""
    data  = request.get_json(force=True) or {}
    until = data.get("access_until", "").strip()
    if not until:
        return jsonify({"ok": False, "error": "access_until required"}), 400
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE scanner_users SET access_until=%s WHERE discord_user_id=%s",
                        (until, uid))
        conn.commit()
    return jsonify({"ok": True})

@app.route("/api/admin/lookup/<uid>", methods=["GET"])
@require_auth
def api_admin_lookup_user(uid):
    """Look up a Discord user by ID via the bot token."""
    if not DISCORD_BOT_TOKEN:
        return jsonify({"ok": False, "error": "No bot token configured — add DISCORD_BOT_TOKEN to env"}), 503
    try:
        resp = requests.get(f"{DISCORD_API}/users/{uid}",
                            headers={"Authorization": f"Bot {DISCORD_BOT_TOKEN}"},
                            timeout=5)
        if not resp.ok:
            return jsonify({"ok": False, "error": "User not found"}), 404
        u = resp.json()
        return jsonify({
            "ok":     True,
            "id":     u["id"],
            "name":   u.get("global_name") or u.get("username"),
            "avatar": u.get("avatar") or "",
        })
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/api/admin/scans/<uid>", methods=["GET"])
@require_auth
def api_admin_user_scans(uid):
    """Return all scans for a specific discord_user_id."""
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT s.*, COUNT(sf.id) AS findings_count
                FROM scans s
                LEFT JOIN scan_findings sf ON sf.scan_id = s.id
                WHERE s.discord_user_id = %s
                GROUP BY s.id ORDER BY s.created_at DESC
            """, (uid,))
            rows = cur.fetchall()
    result = []
    for r in rows:
        d = dict(r)
        if d.get("status") == "complete":
            d["status"] = "completed"
        result.append(d)
    return jsonify(result)

# ── Helpers ───────────────────────────────────────────────────────────────────
def _now():
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

# Vercel WSGI entrypoint
app = app
