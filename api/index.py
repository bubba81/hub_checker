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
            """)
        conn.commit()

# Run init on cold start
try:
    init_db()
except Exception as e:
    print(f"DB init warning: {e}")

# Run column migrations (safe to run on every cold start)
try:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("ALTER TABLE scans ADD COLUMN IF NOT EXISTS trinity_json TEXT")
            cur.execute("ALTER TABLE scans ADD COLUMN IF NOT EXISTS log_text TEXT")
            # scan_pins table (created in init_db above, but guard for older deploys)
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
        conn.commit()
except Exception as e:
    print(f"Migration warning: {e}")

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
    log_text = (scan.get("log_text") or "") if scan else ""
    return render_template("view_scan.html", scan=scan, events=events,
                           findings=findings, phases=SCAN_PHASES,
                           log_text=log_text,
                           username=session.get("global_name"),
                           avatar=session.get("avatar"))

# ── Dashboard AJAX ────────────────────────────────────────────────────────────

@app.route("/api/scans")
@require_auth
def api_scans():
    """Returns all scans as JSON for the dashboard frontend."""
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT s.*, COUNT(sf.id) AS findings_count
                FROM scans s
                LEFT JOIN scan_findings sf ON sf.scan_id = s.id
                GROUP BY s.id ORDER BY s.created_at DESC
            """)
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
    Stores everything: trinity detail + all hits array with structured fields."""
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
            cur.execute("ALTER TABLE scan_findings ADD COLUMN IF NOT EXISTS keyword TEXT NOT NULL DEFAULT ''")
            cur.execute("ALTER TABLE scan_findings ADD COLUMN IF NOT EXISTS fields_json TEXT NOT NULL DEFAULT ''")

            # Store the full JSON blob + raw log
            raw_log = data.get("rawLog", "")
            cur.execute("UPDATE scans SET trinity_json=%s, log_text=%s, updated_at=%s WHERE id=%s",
                        (_json.dumps(data), raw_log, _now(), scan_id))

            hits = data.get("hits", [])
            if hits:
                cur.execute("DELETE FROM scan_findings WHERE scan_id=%s", (scan_id,))
                for h in hits:
                    severity    = h.get("severity", "alert") or "alert"
                    category    = h.get("category", "") or ""
                    keyword     = h.get("keyword", "") or ""
                    path_or_fn  = h.get("path") or h.get("filename", "")
                    detail_parts = []
                    if keyword:       detail_parts.append(f"[{keyword}]")
                    if path_or_fn:    detail_parts.append(path_or_fn)
                    if h.get("tool"): detail_parts.append(f"(tool: {h['tool']})")
                    if h.get("eventType"): detail_parts.append(f"| {h['eventType']}")
                    if h.get("timestamp"):  detail_parts.append(f"@ {h['timestamp']}")
                    if h.get("source"):     detail_parts.append(f"| source: {h['source']}")
                    if h.get("inSession"):  detail_parts.append(f"| in-session: {h['inSession']}")
                    if h.get("signature"):  detail_parts.append(f"| sig: {h['signature']}")
                    if h.get("signer"):     detail_parts.append(f"| signer: {h['signer']}")
                    if h.get("onDisk"):     detail_parts.append(f"| on-disk: {h['onDisk']}")
                    if h.get("bamSeqNum"):  detail_parts.append(f"| BAM-seq: {h['bamSeqNum']}")
                    if h.get("runCount"):   detail_parts.append(f"| runs: {h['runCount']}")
                    if h.get("patterns"):   detail_parts.append(f"| patterns: {'; '.join(h['patterns'])}")
                    detail = " ".join(detail_parts)[:2000]
                    fields_json = _json.dumps(h)
                    cur.execute("""INSERT INTO scan_findings
                                   (scan_id, category, severity, detail, keyword, fields_json, ts)
                                   VALUES (%s,%s,%s,%s,%s,%s,%s)""",
                                (scan_id, category, severity, detail, keyword, fields_json, _now()))

        conn.commit()

    return jsonify({"ok": True, "scan_id": scan_id, "hits_stored": len(hits)})

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
                INSERT INTO scan_findings (scan_id,category,severity,detail,keyword,ts)
                VALUES (%s,%s,%s,%s,%s,%s)
            """, (scan["id"], data.get("category","general"),
                  data.get("severity","warn"), data.get("detail",""),
                  data.get("keyword",""), _now()))
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
            cur.execute("DELETE FROM scan_pins WHERE expires_at <> '' AND expires_at < %s AND used = FALSE", (now,))
            cur.execute("""INSERT INTO scan_pins (pin, scan_key, label, used, created_at, expires_at)
                           VALUES (%s, %s, %s, FALSE, %s, %s)""",
                        (pin, scan_key, label, now, expires))
        conn.commit()
    return jsonify({"ok": True, "pin": pin, "scan_key": scan_key, "expires_at": expires})

@app.route("/api/pin/validate", methods=["GET"])
def api_pin_validate():
    """Called by the C++ scanner to exchange a PIN for a scan_key. No auth required."""
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
    """Return recent pins so the dashboard can show their status."""
    now = _now()
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""SELECT pin, scan_key, label, used, created_at, expires_at, used_at
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
    """GET /api/keys/unused
    Returns all scan_pins that are unused AND not yet expired.
    These are the "live" keys shown in the Keys tab — they can still be
    redeemed by a scanner that enters the correct PIN.
    """
    now = _now()
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT id, pin, scan_key, label, created_at, expires_at
                FROM scan_pins
                WHERE used = FALSE
                  AND (expires_at = '' OR expires_at >= %s)
                ORDER BY created_at DESC
            """, (now,))
            rows = cur.fetchall()
    result = []
    for r in rows:
        d = dict(r)
        # Return the full PIN — the Keys tab is behind auth and shows it
        # prominently so operators can read it out to the person at the machine.
        result.append(d)
    return jsonify(result)


@app.route("/api/keys/<int:key_id>/revoke", methods=["POST"])
@require_auth
def api_key_revoke(key_id):
    """POST /api/keys/<id>/revoke
    Hard-deletes an unused, unexpired key so it can never be redeemed.
    Returns 409 if the key has already been used (audit trail preserved).
    """
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT used FROM scan_pins WHERE id=%s", (key_id,))
            row = cur.fetchone()
            if not row:
                return jsonify({"ok": False, "error": "Key not found"}), 404
            if row["used"]:
                return jsonify({"ok": False, "error": "Cannot revoke a key that has already been used"}), 409
            cur.execute("DELETE FROM scan_pins WHERE id=%s AND used = FALSE", (key_id,))
        conn.commit()
    return jsonify({"ok": True})


# ── Helpers ───────────────────────────────────────────────────────────────────
def _now():
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

# Vercel WSGI entrypoint
app = app
