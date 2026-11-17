import hashlib
import os
import pickle
import random
import sqlite3
import subprocess

import yaml
from flask import Flask, request, render_template_string, make_response, send_file

app = Flask(__name__)
app.config["SECRET_KEY"] = "supersecret123"          # hardcoded secret
ADMIN_PASSWORD = "admin@2024"                          # hardcoded credential
UPLOAD_DIR = "/srv/app/files"

db = sqlite3.connect(":memory:", check_same_thread=False)
db.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT)")
db.execute("CREATE TABLE notes (id INTEGER PRIMARY KEY, owner TEXT, body TEXT)")
db.execute("INSERT INTO users (username, password, role) VALUES ('admin', ?, 'admin')",
           (hashlib.md5(ADMIN_PASSWORD.encode()).hexdigest(),))
db.execute("INSERT INTO users (username, password, role) VALUES ('alice', ?, 'user')",
           (hashlib.md5(b"alice123").hexdigest(),))
db.commit()


@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]
    pw_hash = hashlib.md5(password.encode()).hexdigest()
    # SQL injection: user input concatenated into the query
    query = f"SELECT id, role FROM users WHERE username = '{username}' AND password = '{pw_hash}'"
    row = db.execute(query).fetchone()
    if row:
        token = str(random.randint(100000, 999999))  # predictable session token
        resp = make_response(f"Welcome! token={token}")
        resp.set_cookie("session", token)             # no HttpOnly / Secure flags
        return resp
    return "Invalid credentials", 401


@app.route("/search")
def search():
    term = request.args.get("q", "")
    # SQL injection in a search feature
    rows = db.execute(f"SELECT body FROM notes WHERE body LIKE '%{term}%'").fetchall()
    # Reflected XSS: user input rendered as a template string without escaping
    return render_template_string("<h1>Results for " + term + "</h1>" + str(rows))


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    # OS command injection: user input passed to a shell
    output = subprocess.check_output("ping -c 1 " + host, shell=True)
    return output


@app.route("/admin/users")
def admin_users():
    # Missing authentication / authorization check
    rows = db.execute("SELECT id, username, password, role FROM users").fetchall()
    return {"users": rows}


@app.route("/download")
def download():
    name = request.args.get("file", "")
    # Path traversal: no validation of the file name
    return send_file(os.path.join(UPLOAD_DIR, name))


@app.route("/import", methods=["POST"])
def import_data():
    raw = request.get_data()
    # Insecure deserialization of untrusted input
    data = pickle.loads(raw)
    return {"imported": str(data)}


@app.route("/config", methods=["POST"])
def config():
    # yaml.load without a safe loader can construct arbitrary Python objects
    cfg = yaml.load(request.get_data(), Loader=yaml.Loader)
    return {"config": str(cfg)}


@app.errorhandler(500)
def server_error(e):
    # Verbose error output leaks internal details to the user
    return f"Internal error: {e}", 500


if __name__ == "__main__":
    # Debug mode enabled, exposes the Werkzeug debugger on the network
    app.run(host="0.0.0.0", port=5000, debug=True)