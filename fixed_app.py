import ipaddress
import json
import os
import secrets
import sqlite3
import subprocess
from functools import wraps

from flask import Flask, request, make_response, send_from_directory, session, abort, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("APP_SECRET_KEY") or secrets.token_hex(32)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SECURE"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

UPLOAD_DIR = os.environ.get("UPLOAD_DIR", "/srv/app/files")

db = sqlite3.connect(":memory:", check_same_thread=False)
db.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, role TEXT)")
db.execute("CREATE TABLE notes (id INTEGER PRIMARY KEY, owner TEXT, body TEXT)")
db.execute("INSERT INTO users (username, password, role) VALUES (?, ?, 'admin')",
           ("admin", generate_password_hash(os.environ.get("ADMIN_PASSWORD", secrets.token_urlsafe(16)))))
db.execute("INSERT INTO users (username, password, role) VALUES (?, ?, 'user')",
           ("alice", generate_password_hash(secrets.token_urlsafe(16))))
db.commit()


def login_required(role=None):
    def decorator(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            if "user_id" not in session:
                abort(401)
            if role and session.get("role") != role:
                abort(403)
            return view(*args, **kwargs)
        return wrapper
    return decorator


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    row = db.execute("SELECT id, password, role FROM users WHERE username = ?", (username,)).fetchone()
    if row and check_password_hash(row[1], password):
        session.clear()
        session["user_id"] = row[0]
        session["role"] = row[2]
        return "Welcome!"
    return "Invalid credentials", 401


@app.route("/search")
@login_required()
def search():
    term = request.args.get("q", "")
    rows = db.execute("SELECT body FROM notes WHERE body LIKE ?", (f"%{term}%",)).fetchall()
    return jsonify({"results": [r[0] for r in rows]})


@app.route("/ping")
@login_required(role="admin")
def ping():
    host = request.args.get("host", "127.0.0.1")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        abort(400, description="Invalid IP address")
    output = subprocess.check_output(["ping", "-c", "1", host], timeout=10)
    return output


@app.route("/admin/users")
@login_required(role="admin")
def admin_users():
    rows = db.execute("SELECT id, username, role FROM users").fetchall()
    return jsonify({"users": [{"id": r[0], "username": r[1], "role": r[2]} for r in rows]})


@app.route("/download")
@login_required()
def download():
    name = secure_filename(request.args.get("file", ""))
    if not name:
        abort(400)
    return send_from_directory(UPLOAD_DIR, name, as_attachment=True)


@app.route("/import", methods=["POST"])
@login_required()
def import_data():
    data = request.get_json(silent=True)
    if data is None:
        abort(400)
    return jsonify({"imported": data})


@app.route("/config", methods=["POST"])
@login_required(role="admin")
def config():
    cfg = request.get_json(silent=True)
    if cfg is None:
        abort(400)
    return jsonify({"config": cfg})


@app.errorhandler(500)
def server_error(e):
    app.logger.exception("Unhandled error")
    return "An internal error occurred.", 500


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=os.environ.get("FLASK_DEBUG") == "1")
