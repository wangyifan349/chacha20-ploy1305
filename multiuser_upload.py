"""
This file implements a lightweight web application using the Flask framework that provides a simple multi‑user system with registration and login backed by a SQLite database, and supports file upload, listing, and downloading for each authenticated user. It uses SQLite’s CREATE TABLE, INSERT, and SELECT SQL statements to store and validate user credentials, and organizes uploaded files into per‑user folders on the server’s filesystem rather than storing file metadata in the database.
The application is built with embedded HTML templates styled via Bootstrap with a custom color theme, uses secure sessions signed by a generated secret key, and is configured to run over HTTPS using a temporary self‑signed certificate (ssl_context='adhoc') suitable for development, demonstrating common patterns for handling user sessions, database interaction, and file I/O in a Python web service.
"""
import os
import sqlite3
import secrets
from flask import Flask, request, redirect, session, send_from_directory, render_template_string
from werkzeug.utils import secure_filename

app = Flask(__name__)

# Generate a strong random secret key for session signing
app.secret_key = secrets.token_hex(32)

# Root directory for all user uploads
BASE_UPLOAD = "uploads"
os.makedirs(BASE_UPLOAD, exist_ok=True)

# SQLite database file path
DB_FILE = "database.db"

def get_db():
    """
    Connect to the SQLite database.
    row_factory = sqlite3.Row allows accessing columns by name.
    """
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

@app.before_first_request
def init_db():
    """
    Initialize the database and create the 'users' table if it doesn't already exist.

    The SQL below:
      - Creates 'users' table if it doesn't exist.
      - 'id' is auto‑increment primary key.
      - 'username' is UNIQUE so duplicate accounts cannot be inserted.
      - 'password' is a TEXT column storing the password.
    """
    db = get_db()
    db.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    );""")
    db.commit()
    db.close()

@app.route("/")
def index():
    # Redirect to files if logged in, otherwise to login
    if "user_id" in session:
        return redirect("/files")
    return redirect("/login")

@app.route("/register", methods=["GET","POST"])
def register():
    """
    Register a new user.

    On POST:
      - The INSERT SQL below adds a new record to 'users'.
      - Uses parameterized queries (placeholders) to avoid SQL injection.
      - IntegrityError is thrown if username already exists (violates UNIQUE constraint).
    """
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        db = get_db()
        try:
            db.execute(
                "INSERT INTO users (username, password) VALUES (?, ?)",
                (username, password)
            )
            db.commit()
        except sqlite3.IntegrityError:
            return "Username already exists"
        return redirect("/login")
    return render_template_string(PAGE_REGISTER)

@app.route("/login", methods=["GET","POST"])
def login():
    """
    Log in an existing user.

    On POST:
      - The SELECT SQL below looks up a user by username and password.
      - fetchone() returns the first matching row or None.
      - If a matching record is found, the session is populated.
    """
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE username=? AND password=?",
            (username, password)
        ).fetchone()
        if user:
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            return redirect("/files")
        return "Incorrect username or password"
    return render_template_string(PAGE_LOGIN)

@app.route("/logout")
def logout():
    # Log the user out by clearing session
    session.clear()
    return redirect("/login")

@app.route("/upload", methods=["GET","POST"])
def upload():
    # Upload file for the logged‑in user
    if "user_id" not in session:
        return redirect("/login")
    if request.method == "POST":
        f = request.files.get("file")
        if f and f.filename:
            fname = secure_filename(f.filename)
            user_dir = os.path.join(BASE_UPLOAD, str(session["user_id"]))
            os.makedirs(user_dir, exist_ok=True)
            f.save(os.path.join(user_dir, fname))
            return redirect("/files")
    return render_template_string(PAGE_UPLOAD)

@app.route("/files")
def files():
    # List all files in the user's directory
    if "user_id" not in session:
        return redirect("/login")
    user_dir = os.path.join(BASE_UPLOAD, str(session["user_id"]))
    os.makedirs(user_dir, exist_ok=True)
    file_list = os.listdir(user_dir)
    return render_template_string(PAGE_FILES, files=file_list)

@app.route("/download/<filename>")
def download(filename):
    # Serve the file as a download for the logged‑in user
    if "user_id" not in session:
        return redirect("/login")
    user_dir = os.path.join(BASE_UPLOAD, str(session["user_id"]))
    return send_from_directory(user_dir, filename, as_attachment=True)

PAGE_BASE = """
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Flask App</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
  <style>
    :root {
      --bs-primary: #d4a373;
      --bs-secondary: #c9b29b;
      --bs-success: #c7b198;
      --bs-info: #e9d8a6;
      --bs-warning: #f1b24a;
      --bs-light: #faf3e0;
      --bs-dark: #6b5b4a;
    }
    .btn-primary {
      background-color: var(--bs-primary) !important;
      border-color: var(--bs-primary) !important;
      color: #fff;
    }
    .form-control:focus {
      border-color: var(--bs-warning) !important;
      box-shadow: 0 0 0 .25rem rgba(241,178,74, .25) !important;
    }
  </style>
</head>
<body class="bg-light">
<div class="container py-4">
  {% block body %}{% endblock %}
</div>
</body>
</html>
"""

PAGE_LOGIN = PAGE_BASE + """
{% block body %}
<div class="card mx-auto" style="max-width: 420px;">
  <div class="card-body">
    <h4 class="text-center">Login</h4>
    <form method="post">
      <input type="text" name="username" class="form-control mb-2" placeholder="Username" required>
      <input type="password" name="password" class="form-control mb-2" placeholder="Password" required>
      <button class="btn btn-primary w-100">Login</button>
    </form>
    <div class="mt-2 text-center">
      <a href="/register">Register here</a>
    </div>
  </div>
</div>
{% endblock %}
"""

PAGE_REGISTER = PAGE_BASE + """
{% block body %}
<div class="card mx-auto" style="max-width: 420px;">
  <div class="card-body">
    <h4 class="text-center">Register</h4>
    <form method="post">
      <input type="text" name="username" class="form-control mb-2" placeholder="Username" required>
      <input type="password" name="password" class="form-control mb‑2" placeholder="Password" required>
      <button class="btn btn-primary w-100">Register</button>
    </form>
  </div>
</div>
{% endblock %}
"""

PAGE_UPLOAD = PAGE_BASE + """
{% block body %}
<h4>Upload Files</h4>
<form method="post" enctype="multipart/form-data">
  <input type="file" name="file" class="form-control mb-2" required>
  <button class="btn btn-primary">Upload</button>
</form>
<a class="btn btn-secondary mt-2" href="/files">Back to list</a>
{% endblock %}
"""

PAGE_FILES = PAGE_BASE + """
{% block body %}
<h4>{{ session.username }}'s Files</h4>
<a class="btn btn-primary mb‑3" href="/upload">Upload New</a>
<a class="btn btn-secondary mb‑3" href="/logout">Logout</a>
<ul class="list-group">
  {% for f in files %}
  <li class="list-group-item">
    {{ f }}
    <a class="btn btn-sm btn-outline-dark float-end" href="/download/{{ f }}">Download</a>
  </li>
  {% endfor %}
</ul>
{% endblock %}
"""

if __name__ == "__main__":
    # Run with HTTPS using adhoc self‑signed cert (development only)
    app.run(host="0.0.0.0", port=5000, debug=True, ssl_context="adhoc")
