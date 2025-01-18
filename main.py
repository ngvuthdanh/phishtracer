import os
import sqlite3
import requests
import whois
import ssl
import socket
from flask import Flask, request, jsonify

app = Flask(__name__)

def init_db():
    conn = sqlite3.connect("database/phishing_sites.db")
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS phishing_sites (
        id INTEGER PRIMARY KEY,
        domain TEXT UNIQUE,
        status TEXT
    )
    """)
    conn.commit()
    conn.close()

init_db()

def whois_lookup(domain):
    try:
        w = whois.whois(domain)
        return w.text
    except Exception as e:
        return str(e)

def check_ssl(domain):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.connect((domain, 443))
            cert = s.getpeercert()
        return cert
    except Exception as e:
        return str(e)

def check_virustotal(domain):
    API_KEY = "YOUR_API_KEY"
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": API_KEY}
    try:
        response = requests.get(url, headers=headers)
        return response.json()
    except Exception as e:
        return str(e)

@app.route("/check", methods=["GET"])
def check_domain():
    domain = request.args.get("domain")
    if not domain:
        return jsonify({"error": "Domain parameter is required"}), 400
    
    whois_data = whois_lookup(domain)
    ssl_data = check_ssl(domain)
    vt_data = check_virustotal(domain)
    
    return jsonify({
        "domain": domain,
        "whois": whois_data,
        "ssl": ssl_data,
        "virustotal": vt_data
    })

if __name__ == "__main__":
    app.run(debug=True)