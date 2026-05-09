"""
SWE210 Software Security - Group Project
Secure Web Application with Flask

Features:
  1. Authentication  — Registration & Login with password hashing (bcrypt)
  2. Access Control  — Role-Based Access Control (Admin / User)
  3. Encryption      — Fernet symmetric encryption for sensitive data

How to run:
  pip install flask flask-login bcrypt cryptography
  python app.py
"""

import os
import sqlite3
from datetime import datetime

from flask import (
    Flask, render_template, request, redirect,
    url_for, flash, abort, g
)
from flask_login import (
    LoginManager, UserMixin, login_user,
    logout_user, login_required, current_user
)
import bcrypt
from cryptography.fernet import Fernet

# ──────────────────────────────────────────────
# APP CONFIGURATION
# ──────────────────────────────────────────────

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Random secret key for sessions

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"  # Redirect here if not logged in

# Database path
DATABASE = os.path.join(os.path.dirname(__file__), "database.db")

# ──────────────────────────────────────────────
# ENCRYPTION SETUP (Fernet / AES-128-CBC)
# ──────────────────────────────────────────────
# Fernet uses AES-128-CBC for encryption + HMAC-SHA256 for authentication.
# The key is generated once and stored in a file so data can be
# decrypted across server restarts.

KEY_FILE = os.path.join(os.path.dirname(__file__), "secret.key")

def load_or_create_key():
    """Load existing Fernet key or generate a new one."""
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            return f.read()
    else:
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
        return key

FERNET_KEY = load_or_create_key()
cipher = Fernet(FERNET_KEY)


def encrypt_data(plaintext: str) -> str:
    """Encrypt a string and return the ciphertext as a string."""
    return cipher.encrypt(plaintext.encode("utf-8")).decode("utf-8")


def decrypt_data(ciphertext: str) -> str:
    """Decrypt a ciphertext string back to plaintext."""
    return cipher.decrypt(ciphertext.encode("utf-8")).decode("utf-8")


# ──────────────────────────────────────────────
# DATABASE HELPERS
# ──────────────────────────────────────────────

def get_db():
    """Open a database connection for the current request."""
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row  # Access columns by name
    return g.db


@app.teardown_appcontext
def close_db(exception):
    """Close database connection when request ends."""
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    """Create tables if they don't exist yet."""
    db = sqlite3.connect(DATABASE)
    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            username    TEXT    UNIQUE NOT NULL,
            password    TEXT    NOT NULL,          -- bcrypt hash (NEVER plaintext)
            role        TEXT    NOT NULL DEFAULT 'user',  -- 'admin' or 'user'
            created_at  TEXT    NOT NULL
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS secrets (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER NOT NULL,
            title       TEXT    NOT NULL,
            content     TEXT    NOT NULL,           -- Fernet-encrypted ciphertext
            created_at  TEXT    NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)
    db.commit()

    # Create a default admin account if none exists
    existing = db.execute("SELECT id FROM users WHERE role = 'admin'").fetchone()
    if not existing:
        hashed = bcrypt.hashpw("admin123".encode("utf-8"), bcrypt.gensalt())
        db.execute(
            "INSERT INTO users (username, password, role, created_at) VALUES (?, ?, ?, ?)",
            ("admin", hashed.decode("utf-8"), "admin", datetime.now().isoformat())
        )
        db.commit()
        print("[+] Default admin created  →  username: admin  |  password: admin123")

    db.close()


# ──────────────────────────────────────────────
# USER MODEL (Flask-Login)
# ──────────────────────────────────────────────

class User(UserMixin):
    """Represents an authenticated user."""

    def __init__(self, id, username, role):
        self.id = id
        self.username = username
        self.role = role

    def is_admin(self):
        return self.role == "admin"


@login_manager.user_loader
def load_user(user_id):
    """Flask-Login calls this to reload a user from the session."""
    db = get_db()
    row = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if row:
        return User(row["id"], row["username"], row["role"])
    return None


# ──────────────────────────────────────────────
# DECORATOR: Admin-only access
# ──────────────────────────────────────────────

def admin_required(f):
    """
    Custom decorator that checks if the current user has the 'admin' role.
    If not, returns HTTP 403 Forbidden.
    This implements Role-Based Access Control (RBAC).
    """
    from functools import wraps
    @wraps(f)
    @login_required
    def decorated(*args, **kwargs):
        if not current_user.is_admin():
            abort(403)  # Forbidden — user does not have admin role
        return f(*args, **kwargs)
    return decorated


# ──────────────────────────────────────────────
# ROUTES
# ──────────────────────────────────────────────

# ── Home Page ──
@app.route("/")
def home():
    return redirect(url_for("login"))


# ── Registration ──
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"].strip()

        if not username or not password:
            flash("Username and password are required.", "error")
            return redirect(url_for("register"))

        if len(password) < 6:
            flash("Password must be at least 6 characters.", "error")
            return redirect(url_for("register"))

        db = get_db()

        # Check if username already exists
        existing = db.execute(
            "SELECT id FROM users WHERE username = ?", (username,)
        ).fetchone()

        if existing:
            flash("Username already taken.", "error")
            return redirect(url_for("register"))

        # ── PASSWORD HASHING ──
        # bcrypt automatically generates a random salt and includes it
        # in the hash output.  We NEVER store the plaintext password.
        hashed_password = bcrypt.hashpw(
            password.encode("utf-8"),
            bcrypt.gensalt()
        )

        db.execute(
            "INSERT INTO users (username, password, role, created_at) VALUES (?, ?, ?, ?)",
            (username, hashed_password.decode("utf-8"), "user", datetime.now().isoformat())
        )
        db.commit()

        flash("Account created! Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


# ── Login ──
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"].strip()

        db = get_db()
        row = db.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()

        if row is None:
            flash("Invalid username or password.", "error")
            return redirect(url_for("login"))

        # ── PASSWORD VERIFICATION ──
        # bcrypt.checkpw compares the entered password against the
        # stored hash.  It extracts the salt from the hash automatically.
        if bcrypt.checkpw(password.encode("utf-8"), row["password"].encode("utf-8")):
            user = User(row["id"], row["username"], row["role"])
            login_user(user)
            flash(f"Welcome back, {user.username}!", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid username or password.", "error")
            return redirect(url_for("login"))

    return render_template("login.html")


# ── Logout ──
@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out successfully.", "success")
    return redirect(url_for("login"))


# ── Dashboard (any logged-in user) ──
@app.route("/dashboard")
@login_required
def dashboard():
    db = get_db()
    rows = db.execute(
        "SELECT * FROM secrets WHERE user_id = ? ORDER BY created_at DESC",
        (current_user.id,)
    ).fetchall()

    # Decrypt each secret for display
    secrets = []
    for row in rows:
        secrets.append({
            "id": row["id"],
            "title": row["title"],
            "content": decrypt_data(row["content"]),  # ← DECRYPTION happens here
            "encrypted_content": row["content"],       # Show raw ciphertext too
            "created_at": row["created_at"]
        })

    return render_template("dashboard.html", secrets=secrets)


# ── Add Secret (encrypted note) ──
@app.route("/add-secret", methods=["POST"])
@login_required
def add_secret():
    title = request.form["title"].strip()
    content = request.form["content"].strip()

    if not title or not content:
        flash("Title and content are required.", "error")
        return redirect(url_for("dashboard"))

    # ── ENCRYPTION ──
    # The plaintext content is encrypted using Fernet (AES-128-CBC + HMAC)
    # before being stored in the database.
    encrypted_content = encrypt_data(content)

    db = get_db()
    db.execute(
        "INSERT INTO secrets (user_id, title, content, created_at) VALUES (?, ?, ?, ?)",
        (current_user.id, title, encrypted_content, datetime.now().isoformat())
    )
    db.commit()

    flash("Secret saved and encrypted!", "success")
    return redirect(url_for("dashboard"))


# ── Delete Secret ──
@app.route("/delete-secret/<int:secret_id>", methods=["POST"])
@login_required
def delete_secret(secret_id):
    db = get_db()
    db.execute(
        "DELETE FROM secrets WHERE id = ? AND user_id = ?",
        (secret_id, current_user.id)
    )
    db.commit()
    flash("Secret deleted.", "success")
    return redirect(url_for("dashboard"))


# ── Admin Panel (RBAC — admin role only) ──
@app.route("/admin")
@admin_required
def admin_panel():
    db = get_db()

    users = db.execute("SELECT id, username, role, created_at FROM users ORDER BY id").fetchall()

    stats = {
        "total_users": db.execute("SELECT COUNT(*) FROM users").fetchone()[0],
        "total_admins": db.execute("SELECT COUNT(*) FROM users WHERE role = 'admin'").fetchone()[0],
        "total_secrets": db.execute("SELECT COUNT(*) FROM secrets").fetchone()[0],
    }

    return render_template("admin.html", users=users, stats=stats)


# ── Promote user to admin (admin only) ──
@app.route("/admin/promote/<int:user_id>", methods=["POST"])
@admin_required
def promote_user(user_id):
    db = get_db()
    db.execute("UPDATE users SET role = 'admin' WHERE id = ?", (user_id,))
    db.commit()
    flash("User promoted to admin.", "success")
    return redirect(url_for("admin_panel"))


# ── Demote admin to user (admin only) ──
@app.route("/admin/demote/<int:user_id>", methods=["POST"])
@admin_required
def demote_user(user_id):
    if user_id == current_user.id:
        flash("You cannot demote yourself.", "error")
        return redirect(url_for("admin_panel"))
    db = get_db()
    db.execute("UPDATE users SET role = 'user' WHERE id = ?", (user_id,))
    db.commit()
    flash("User demoted to regular user.", "success")
    return redirect(url_for("admin_panel"))


# ── Error Handlers ──
@app.errorhandler(403)
def forbidden(e):
    return render_template("403.html"), 403


@app.errorhandler(404)
def not_found(e):
    return render_template("404.html"), 404


# ──────────────────────────────────────────────
# RUN
# ──────────────────────────────────────────────

if __name__ == "__main__":
    init_db()
    print("\n[*] Server running at http://127.0.0.1:5000\n")
    app.run(debug=True, port=5000)
