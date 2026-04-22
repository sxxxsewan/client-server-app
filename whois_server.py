from __future__ import annotations

import socket
import time
from datetime import datetime

import pymysql
import pymysql.cursors
from flask import Flask, request, jsonify
from flask_cors import CORS

DB_CONFIG = {
    "host": "127.0.0.1",
    "port": 3306,
    "user": "root",
    "password": "",
    "database": "whois_db",
    "charset": "utf8mb4",
    "cursorclass": pymysql.cursors.DictCursor
}

REGISTRARS = [
    {"name": "IANA", "host": "whois.iana.org", "port": 43},
    {"name": "RIPE NCC", "host": "whois.ripe.net", "port": 43},
    {"name": "VERISIGHN", "host": "whois.verisighn-grs.com", "port": 43}
]

WHOIS_TIMEOUT = 10

app = Flask(__name__)
CORS(app)

def raw_whois_query(domain: str, host: str, port: int = 43) -> str:
    visited = set()
    current_host = host

    while current_host and current_host not in visited:
        visited.add(current_host)
        try:
            with socket.create_connection((current_host, port), timeout=WHOIS_TIMEOUT) as sock:
                sock.sendall((domain + "\r\n").encode())
                chunks = []
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    chunks.append(chunk)
                raw = b"".join(chunks).decode("utf-8", errors="replace")
        except Exception as exc:
            return f"ERROR: {exc}"

        next_host = None
        for line in raw.splitlines():
            if line.lower().startswith("refer:"):
                next_host = line.split(":", 1)[1].strip()
                break

        if next_host and next_host != current_host:
            current_host = next_host 
        else:
            return raw

    return f"ERROR: цикл перенаправлений для {domain}"
    

def parse_whois_text(raw: str) -> dict:
    fields_of_interests = {
        "domain name":       "domain",
        "registrar":         "registrar",
        "registrar url":     "registrar_url",
        "updated date":      "updated_date",
        "creation date":     "creation_date",
        "registry expiry date": "expiry_date",
        "registrant name":   "registrant_name",
        "registrant organisation": "registrant_org",
        "registrant country": "registrant_country",
        "registrant email":  "registrant_email",
        "registrant phone":  "registrant_phone",
        "admin name":        "admin_name",
        "admin email":       "admin_email",
        "name server":       "name_servers",
        "dnssec":            "dnssec",
        "status":            "status"
    }

    result: dict = {}
    for line in raw.splitlines():
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key_clean = key.strip().lower()
        value_clean = value.strip()
        if not value_clean:
            continue
        for pattern, field in fields_of_interests.items():
            if pattern in key_clean:
                if field == "name_servers":
                    result.setdefault("name_servers", []).append(value_clean)
                elif field not in result:
                    result[field] = value_clean
                break

    result["raw"] = raw
    return result

def query_multiple_registrars(domain: str) -> dict:
    best: dict | None = None
    best_registrar = ""

    for reg in REGISTRARS:
        raw = raw_whois_query(domain, reg["host"], reg["port"])
        if raw.startswith("ERROR:"):
            continue
        parsed = parse_whois_text(raw)
        parsed["_source_registrar"] = reg["name"]

        if parsed.get("registrant_name") or parsed.get("registrant_org") or parsed.get("registrar"):
            return parsed

        if best is None:
            best = parsed
            best_registrar = reg["name"]

    return best or {"error": "Нет данных ни от одного регистратора", "_source_registrar": ""}



def get_db():
    return pymysql.connect(**DB_CONFIG)


def log_query(client_ip: str, domain: str, registrar: str, status: str = "success"):
    try:
        conn = get_db()
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO query_log (client_ip, domain_name, queried_at, registrar, status)
                    VALUES (%s, %s, %s, %s, %s)
                    """,
                    (client_ip, domain, datetime.now(), registrar, status),
                )
            conn.commit()
    except Exception as exc:
        app.logger.error("DB log error: %s", exc)



@app.route("/api/whois", methods=["GET"])
def api_whois():
    domain = request.args.get("domain", "").strip().lower()
    if not domain:
        return jsonify({"error": "Параметр 'domain' обязателен"}), 400

    domain = domain.replace("https://", "").replace("http://", "").split("/")[0]

    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr)

    result = query_multiple_registrars(domain)

    status = "error" if "error" in result else "success"
    log_query(client_ip, domain, result.get("_source_registrar", ""), status)

    return jsonify({
        "domain":   domain,
        "source":   result.pop("_source_registrar", ""),
        "data":     result,
        "queried_at": datetime.now().isoformat(),
    })


@app.route("/api/logs", methods=["GET"])
def api_logs():
    limit = min(int(request.args.get("limit", 50)), 500)
    try:
        conn = get_db()
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT id, client_ip, domain_name,
                           DATE_FORMAT(queried_at, '%%Y-%%m-%%d %%H:%%i:%%s') AS queried_at,
                           registrar, status
                    FROM query_log
                    ORDER BY queried_at DESC
                    LIMIT %s
                    """,
                    (limit,),
                )
                rows = cur.fetchall()
        return jsonify(rows)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "time": datetime.now().isoformat()})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)

