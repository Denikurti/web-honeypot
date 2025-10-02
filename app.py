from flask import Flask, request, render_template, redirect
import csv
import datetime
import os
import time
import requests
from collections import defaultdict

app = Flask(__name__)
LOGFILE = "hits.csv"
brute_force_tracker = defaultdict(list)

# Suspicious inputs and tools
SUSPICIOUS_KEYWORDS = [
    "' OR 1=1", "<script>", "<?php", "union select", "drop table", "--", "'#", "admin' --",
    "1=1", "' or ''='", "sleep(", "benchmark(", "etc/passwd"
]
SUSPICIOUS_AGENTS = ["sqlmap", "curl", "python-requests", "nmap", "nikto", "fuzzer", "httpie"]

# Fake endpoints to track
FAKE_ENDPOINTS = [
    "/login", "/admin", "/api/login", "/user/login", "/cpanel", "/dashboard",
    "/.env", "/wp-login.php", "/auth", "/signin"
]

# CSV Headers
CSV_HEADERS = [
    "timestamp", "remote_ip", "country", "city", "isp",
    "method", "path", "user_agent", "headers",
    "form_data", "query", "alert"
]

# Init CSV
if not os.path.exists(LOGFILE):
    with open(LOGFILE, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(CSV_HEADERS)

# --- GeoIP Lookup ---
def geoip_lookup(ip):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=2)
        data = response.json()
        return data.get("country", ""), data.get("city", ""), data.get("isp", "")
    except:
        return "", "", ""

# --- Suspicious Check Rules ---
def check_suspicious(req, form):
    ua = req.headers.get("User-Agent", "").lower()
    raw_data = str(form).lower() + req.query_string.decode("utf-8", errors="ignore").lower()
    ip = req.remote_addr or ""

    # SQLi, XSS, LFI
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword.lower() in raw_data:
            return f"Keyword matched: {keyword}"

    # Known scanning tools
    for bad_ua in SUSPICIOUS_AGENTS:
        if bad_ua in ua:
            return f"Suspicious User-Agent: {bad_ua}"

    # Brute force rule (3+ in 60 sec)
    now = time.time()
    brute_force_tracker[ip] = [t for t in brute_force_tracker[ip] if now - t < 60]
    brute_force_tracker[ip].append(now)
    if len(brute_force_tracker[ip]) > 3:
        return "Brute-force attempt detected"

    return ""

# --- Logging Function ---
def log_hit(req, form=None):
    ts = datetime.datetime.utcnow().isoformat() + "Z"
    ip = req.remote_addr or ""
    ua = req.headers.get("User-Agent", "")
    headers = dict(req.headers)
    form_data = dict(form) if form else {}
    query = req.query_string.decode("utf-8", errors="ignore")
    alert = check_suspicious(req, form_data)
    country, city, isp = geoip_lookup(ip)

    row = [
        ts, ip, country, city, isp,
        req.method, req.path, ua, str(headers),
        str(form_data), query, alert
    ]

    with open(LOGFILE, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(row)

    print(f"[LOG] {ts} | {ip} | {country}/{city} | {req.method} {req.path} | ALERT: {alert or 'None'}")

# --- Routes ---
@app.route("/", methods=["GET"])
def home():
    return redirect("/login")

# Dynamically create endpoints for each fake page
for path in FAKE_ENDPOINTS:
    @app.route(path, methods=["GET"], endpoint=f"{path}_get")
    def fake_login_get():
        log_hit(request)
        return render_template("login.html")

    @app.route(path, methods=["POST"], endpoint=f"{path}_post")
    def fake_login_post():
        log_hit(request, form=request.form)
        return render_template("login.html", message="Invalid username or password.")
    
# --- Run App ---
if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
