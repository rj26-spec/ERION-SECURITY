import os
import sqlite3
import json
from io import BytesIO
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, send_file
from functools import wraps
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors

app = Flask(__name__)
app.secret_key = "cyberguard-development-secret-change-before-deployment"

ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "Admin@123"

# Database paths
DB_FILE = "cyberguard_root.db"
IMG_DB  = os.path.join("CyberGuard-Image-Detection", "cyberguard_audit.db")
MAIL_DB = os.path.join("mailguard", "mailguard.db")


def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS url_logs
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, url TEXT, title TEXT,
                  verdict TEXT, score INTEGER, reason TEXT,
                  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')
    c.execute('''CREATE TABLE IF NOT EXISTS blocked_urls
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, url TEXT UNIQUE)''')
    conn.commit()
    conn.close()

init_db()


def admin_required(view_function):
    @wraps(view_function)
    def wrapped_view(*args, **kwargs):
        if session.get("role") != "admin":
            return redirect(url_for("index"))
        return view_function(*args, **kwargs)
    return wrapped_view


# ===========================================================
#  Auth
# ===========================================================
@app.route("/")
def index():
    return render_template("login.html")


@app.route("/admin-login", methods=["POST"])
def admin_login():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
        session.clear()
        session["role"] = "admin"
        session["username"] = username
        return redirect(url_for("admin_dashboard"))
    return "Invalid admin username or password. <a href='/'>Return to login</a>", 401


@app.route("/admin-dashboard")
@admin_required
def admin_dashboard():
    return render_template("admin_dashboard.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


# ===========================================================
#  Users Panel (reads from mailguard.db)
# ===========================================================
@app.route("/admin/users")
@admin_required
def admin_users():
    users = []
    if os.path.exists(MAIL_DB):
        try:
            conn = sqlite3.connect(MAIL_DB)
            c = conn.cursor()
            c.execute("SELECT id, email FROM users")
            users = [{"id": r[0], "email": r[1]} for r in c.fetchall()]
            conn.close()
        except Exception as e:
            print("Error reading mailguard DB:", e)
    return render_template("users.html", users=users)


# ===========================================================
#  URL Detection
# ===========================================================
@app.route("/threats/url")
@admin_required
def url_detection():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT id, url, title, verdict, score, reason, timestamp "
              "FROM url_logs ORDER BY id DESC LIMIT 50")
    logs = [{"id": r[0], "url": r[1], "title": r[2], "verdict": r[3],
             "score": r[4], "reason": r[5], "timestamp": r[6]}
            for r in c.fetchall()]
    c.execute("SELECT id, url FROM blocked_urls")
    blocked = [{"id": r[0], "url": r[1]} for r in c.fetchall()]
    conn.close()
    return render_template("url_detection.html", logs=logs, blocked=blocked)


@app.route("/api/url-logs", methods=["POST"])
def add_url_log():
    data = request.json
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("INSERT INTO url_logs (url, title, verdict, score, reason) "
              "VALUES (?, ?, ?, ?, ?)",
              (data.get("url"), data.get("title"), data.get("verdict"),
               data.get("score"), data.get("reason")))
    conn.commit()
    conn.close()
    return jsonify({"status": "ok"})


@app.route("/api/blocked-urls", methods=["GET", "POST", "DELETE"])
def api_blocked_urls():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    if request.method == "GET":
        c.execute("SELECT url FROM blocked_urls")
        urls = [r[0] for r in c.fetchall()]
        conn.close()
        return jsonify({"blockedUrls": urls})
    elif request.method == "POST":
        url = request.json.get("url")
        try:
            c.execute("INSERT INTO blocked_urls (url) VALUES (?)", (url,))
            conn.commit()
        except Exception:
            pass
        conn.close()
        return jsonify({"status": "ok"})
    elif request.method == "DELETE":
        url = request.json.get("url")
        c.execute("DELETE FROM blocked_urls WHERE url=?", (url,))
        conn.commit()
        conn.close()
        return jsonify({"status": "ok"})


@app.route("/api/url-report/pdf")
@admin_required
def url_report_pdf():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT timestamp, url, verdict, score FROM url_logs "
              "ORDER BY id DESC LIMIT 100")
    logs = c.fetchall()
    conn.close()

    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4)
    styles = getSampleStyleSheet()
    elements = []
    elements.append(Paragraph("ERION SECURITY URL Detection Audit Report",
                              styles["Title"]))
    elements.append(Spacer(1, 12))

    data = [["Timestamp", "URL", "Verdict", "Score"]]
    for log in logs:
        url = log[1][:50] + "..." if log[1] and len(log[1]) > 50 else (log[1] or "")
        data.append([str(log[0]), url, str(log[2]), str(log[3])])

    table = Table(data)
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    elements.append(table)
    doc.build(elements)
    buffer.seek(0)
    return send_file(buffer, as_attachment=True,
                     download_name="URL_Audit_Report.pdf",
                     mimetype="application/pdf")


# ===========================================================
#  CENTRALIZED AUDIT LOGS  (aggregates ALL databases)
# ===========================================================
def _safe_str(val, max_len=80):
    """Convert value to a truncated string."""
    if val is None:
        return ""
    s = str(val)
    return s[:max_len] + "..." if len(s) > max_len else s


def get_all_audit_records():
    """Pull audit records from Image Detection DB, URL logs, and Mailguard."""
    records = []

    # --- 1. Image Detection DB ---
    if os.path.exists(IMG_DB):
        try:
            conn = sqlite3.connect(IMG_DB)
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            c.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [r[0] for r in c.fetchall()]
            for tbl in tables:
                if tbl == "sqlite_sequence":
                    continue
                try:
                    c.execute(f"SELECT * FROM {tbl} ORDER BY rowid DESC LIMIT 200")
                    rows = c.fetchall()
                    cols = [d[0] for d in c.description]
                    for row in rows:
                        d = dict(zip(cols, row))
                        records.append({
                            "source":    "Image Detection",
                            "timestamp": d.get("timestamp") or d.get("created_at") or d.get("scanned_at") or "",
                            "type":      d.get("category") or d.get("threat_type") or d.get("label") or tbl,
                            "verdict":   d.get("risk_level") or d.get("verdict") or d.get("result") or "",
                            "detail":    d.get("filename") or d.get("url") or d.get("detail") or "",
                        })
                except Exception:
                    pass
            conn.close()
        except Exception as e:
            print("IMG DB error:", e)

    # --- 2. URL logs (root DB) ---
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("SELECT timestamp, url, verdict, score, reason "
                  "FROM url_logs ORDER BY id DESC LIMIT 200")
        for row in c.fetchall():
            records.append({
                "source":    "URL Detection",
                "timestamp": row[0] or "",
                "type":      "URL Scan",
                "verdict":   row[2] or "",
                "detail":    _safe_str(row[1], 60),
            })
        conn.close()
    except Exception as e:
        print("URL DB error:", e)

    # --- 3. Mailguard DB ---
    if os.path.exists(MAIL_DB):
        try:
            conn = sqlite3.connect(MAIL_DB)
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            c.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [r[0] for r in c.fetchall()]
            for tbl in tables:
                if tbl in ("sqlite_sequence", "users"):
                    continue
                try:
                    c.execute(f"SELECT * FROM {tbl} ORDER BY rowid DESC LIMIT 200")
                    rows = c.fetchall()
                    cols = [d[0] for d in c.description]
                    for row in rows:
                        d = dict(zip(cols, row))
                        records.append({
                            "source":    "Email / Mailguard",
                            "timestamp": d.get("timestamp") or d.get("created_at") or d.get("scanned_at") or "",
                            "type":      d.get("threat_type") or d.get("category") or d.get("verdict") or tbl,
                            "verdict":   d.get("verdict") or d.get("risk_level") or d.get("result") or "",
                            "detail":    d.get("sender") or d.get("subject") or d.get("email") or d.get("detail") or "",
                        })
                except Exception:
                    pass
            conn.close()
        except Exception as e:
            print("MAIL DB error:", e)

    # Sort newest first
    records.sort(key=lambda r: str(r.get("timestamp") or ""), reverse=True)
    return records


@app.route("/admin/audit-logs")
@admin_required
def audit_logs():
    records = get_all_audit_records()
    return render_template("audit_logs.html", records=records)


@app.route("/api/audit-all")
@admin_required
def api_audit_all():
    return jsonify(get_all_audit_records())


@app.route("/admin/audit-logs/pdf")
@admin_required
def audit_pdf():
    records = get_all_audit_records()

    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=landscape(A4),
                            rightMargin=20, leftMargin=20,
                            topMargin=30, bottomMargin=20)
    styles = getSampleStyleSheet()
    elements = []

    elements.append(Paragraph("ERION SECURITY &mdash; Unified Audit Report",
                              styles["Title"]))
    elements.append(Spacer(1, 10))

    data = [["#", "Source", "Timestamp", "Type", "Verdict", "Detail"]]
    for i, r in enumerate(records, 1):
        data.append([
            str(i),
            _safe_str(r.get("source"), 20),
            _safe_str(r.get("timestamp"), 19),
            _safe_str(r.get("type"), 25),
            _safe_str(r.get("verdict"), 15),
            _safe_str(r.get("detail"), 50),
        ])

    if len(data) == 1:
        data.append(["", "No records", "", "", "", ""])

    col_widths = [25, 100, 120, 100, 70, 200]
    table = Table(data, colWidths=col_widths, repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0), colors.HexColor("#1f2937")),
        ("TEXTCOLOR",     (0, 0), (-1, 0), colors.white),
        ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, 0), 9),
        ("FONTSIZE",      (0, 1), (-1, -1), 8),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1),
         [colors.HexColor("#f4f6fa"), colors.white]),
        ("GRID",          (0, 0), (-1, -1), 0.4, colors.grey),
        ("ALIGN",         (0, 0), (-1, -1), "LEFT"),
        ("TOPPADDING",    (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    elements.append(table)

    doc.build(elements)
    buffer.seek(0)
    return send_file(buffer, as_attachment=True,
                     download_name="ERION_SECURITY_Audit_Report.pdf",
                     mimetype="application/pdf")


# ===========================================================
#  Dashboard stub APIs (charts)
# ===========================================================
@app.route('/api/dashboard/summary')
def db_summary():
    return jsonify({
        "total_scans": 0, "total_threats": 0,
        "category_count": 0, "risk_counts": {}, "categories": []
    })

@app.route('/api/dashboard/recent')
def db_recent():
    records = get_all_audit_records()[:5]
    mapped = []
    for r in records:
        mapped.append({
            "timestamp": r.get("timestamp", ""),
            "category": f"{r.get('source', '')}",
            "risk_level": r.get("verdict", ""),
            "result": r.get("detail", "")
        })
    return jsonify(mapped)

@app.route('/api/dashboard/history')
def db_history():
    records = get_all_audit_records()
    mapped = []
    for r in records:
        mapped.append({
            "timestamp": r.get("timestamp", ""),
            "category": f"{r.get('source', '')} - {r.get('type', '')}",
            "risk_level": r.get("verdict", ""),
            "result": r.get("detail", "")
        })
    return jsonify(mapped)

@app.route('/api/dashboard/daily')
def db_daily():
    return jsonify({"labels": [], "counts": []})

@app.route('/api/dashboard/category')
def db_category():
    return jsonify({"risk_counts": {}})


if __name__ == "__main__":
    app.run(debug=True, port=5000)



