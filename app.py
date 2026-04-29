import os
import sqlite3
import secrets
from functools import wraps
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, session, flash, g, abort
from werkzeug.security import generate_password_hash, check_password_hash

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, "bookstore.db")

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", secrets.token_hex(32))
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = False  # local Kali HTTP demo; set True when running HTTPS

BOOKS = [
    ("Cybersecurity Fundamentals", "Nithin Press", "Education", 24.99, 15, "A beginner-friendly guide to digital security, threats, controls, and safe online behaviour."),
    ("Web Application Security", "Secure Code House", "Education", 29.99, 12, "Practical introduction to OWASP risks, authentication, input validation, and secure sessions."),
    ("Ethical Hacking Handbook", "Red Team Reads", "Technology", 34.99, 8, "A structured handbook for reconnaissance, vulnerability discovery, and responsible testing."),
    ("Secure Coding in Python", "DevSec Library", "Programming", 22.99, 20, "Learn defensive coding patterns, password hashing, parameterised queries, and secure API design."),
    ("Network Security Basics", "Blue Team Books", "Technology", 19.99, 18, "Core concepts covering firewalls, logs, secure protocols, and network monitoring."),
    ("Malware Analysis Introduction", "Forensics Shelf", "Cybersecurity", 39.99, 6, "Static and dynamic malware analysis foundations for students and junior analysts."),
    ("Digital Forensics Essentials", "IR Academy", "Cybersecurity", 31.99, 10, "Evidence handling, timelines, artifacts, and incident investigation essentials."),
    ("Cloud Security Guide", "CloudSec Press", "Technology", 27.99, 14, "Identity, permissions, logging, encryption, and cloud workload protection basics."),
]


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'customer',
            failed_attempts INTEGER NOT NULL DEFAULT 0,
            locked INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS books (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            author TEXT NOT NULL,
            category TEXT NOT NULL,
            price REAL NOT NULL,
            stock INTEGER NOT NULL,
            description TEXT NOT NULL,
            image TEXT NOT NULL DEFAULT 'book.jpg',
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            total REAL NOT NULL,
            payment_method TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS order_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            order_id INTEGER NOT NULL,
            book_id INTEGER NOT NULL,
            quantity INTEGER NOT NULL,
            unit_price REAL NOT NULL,
            FOREIGN KEY(order_id) REFERENCES orders(id),
            FOREIGN KEY(book_id) REFERENCES books(id)
        );
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT NOT NULL,
            details TEXT,
            ip_address TEXT,
            created_at TEXT NOT NULL
        );
        """
    )
    admin = db.execute("SELECT id FROM users WHERE username = ?", ("admin_nithin",)).fetchone()
    if not admin:
        db.execute(
            "INSERT INTO users(username,email,password_hash,role,created_at) VALUES(?,?,?,?,?)",
            ("admin_nithin", "admin@example.local", generate_password_hash("ChangeMe@12345"), "admin", datetime.utcnow().isoformat()),
        )
    count = db.execute("SELECT COUNT(*) AS c FROM books").fetchone()["c"]
    if count == 0:
        db.executemany(
            "INSERT INTO books(title,author,category,price,stock,description,created_at) VALUES(?,?,?,?,?,?,?)",
            [(title, author, category, price, stock, desc, datetime.utcnow().isoformat()) for title, author, category, price, stock, desc in BOOKS],
        )
    db.commit()


def log_action(action, details=""):
    db = get_db()
    db.execute(
        "INSERT INTO audit_logs(user_id, action, details, ip_address, created_at) VALUES(?,?,?,?,?)",
        (session.get("user_id"), action, details, request.remote_addr, datetime.utcnow().isoformat()),
    )
    db.commit()


def current_user():
    if "user_id" not in session:
        return None
    return get_db().execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()


@app.context_processor
def inject_user():
    return {"current_user": current_user(), "cart_count": sum(session.get("cart", {}).values())}


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not current_user():
            flash("Please log in first.", "warning")
            return redirect(url_for("login", next=request.path))
        return fn(*args, **kwargs)
    return wrapper


def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        user = current_user()
        if not user or user["role"] != "admin":
            log_action("ADMIN_ACCESS_BLOCKED", "Blocked access to " + request.path)
            abort(403)
        return fn(*args, **kwargs)
    return wrapper


@app.route("/")
def index():
    db = get_db()
    books = db.execute("SELECT * FROM books ORDER BY id DESC LIMIT 8").fetchall()
    return render_template("index.html", books=books)


@app.route("/books")
def books():
    q = request.args.get("q", "").strip()
    category = request.args.get("category", "").strip()
    db = get_db()
    params = []
    sql = "SELECT * FROM books WHERE 1=1"
    if q:
        sql += " AND (title LIKE ? OR author LIKE ? OR description LIKE ?)"
        params += [f"%{q}%", f"%{q}%", f"%{q}%"]
    if category:
        sql += " AND category = ?"
        params.append(category)
    sql += " ORDER BY title"
    books = db.execute(sql, params).fetchall()
    categories = db.execute("SELECT DISTINCT category FROM books ORDER BY category").fetchall()
    return render_template("books.html", books=books, q=q, category=category, categories=categories)


@app.route("/book/<int:book_id>")
def book_detail(book_id):
    book = get_db().execute("SELECT * FROM books WHERE id = ?", (book_id,)).fetchone()
    if not book:
        abort(404)
    return render_template("book_detail.html", book=book)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        if len(username) < 3 or "@" not in email or len(password) < 10:
            flash("Use a username of 3+ characters, a valid email, and a password of 10+ characters.", "danger")
            return render_template("register.html")
        try:
            get_db().execute(
                "INSERT INTO users(username,email,password_hash,role,created_at) VALUES(?,?,?,?,?)",
                (username, email, generate_password_hash(password), "customer", datetime.utcnow().isoformat()),
            )
            get_db().commit()
            log_action("REGISTER", f"New customer account: {username}")
            flash("Registration successful. You can now log in.", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Username or email already exists.", "danger")
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if user and user["locked"]:
            flash("Account is locked due to repeated failed attempts.", "danger")
            return render_template("login.html")
        if user and check_password_hash(user["password_hash"], password):
            db.execute("UPDATE users SET failed_attempts = 0 WHERE id = ?", (user["id"],))
            db.commit()
            session.clear()
            session["user_id"] = user["id"]
            session["cart"] = session.get("cart", {})
            log_action("LOGIN_SUCCESS", username)
            flash("Logged in successfully.", "success")
            return redirect(request.args.get("next") or url_for("index"))
        if user:
            failed = user["failed_attempts"] + 1
            locked = 1 if failed >= 5 else 0
            db.execute("UPDATE users SET failed_attempts = ?, locked = ? WHERE id = ?", (failed, locked, user["id"]))
            db.commit()
        log_action("LOGIN_FAILURE", username)
        flash("Invalid credentials.", "danger")
    return render_template("login.html")


@app.route("/logout")
def logout():
    log_action("LOGOUT", "User logged out") if current_user() else None
    session.clear()
    flash("Logged out.", "info")
    return redirect(url_for("index"))


@app.route("/cart")
def cart():
    cart_data = session.get("cart", {})
    rows = []
    total = 0.0
    db = get_db()
    for book_id, qty in cart_data.items():
        book = db.execute("SELECT * FROM books WHERE id = ?", (book_id,)).fetchone()
        if book:
            line_total = book["price"] * qty
            total += line_total
            rows.append({"book": book, "quantity": qty, "line_total": line_total})
    return render_template("cart.html", rows=rows, total=total)


@app.route("/cart/add/<int:book_id>", methods=["POST"])
def add_to_cart(book_id):
    book = get_db().execute("SELECT * FROM books WHERE id = ?", (book_id,)).fetchone()
    if not book:
        abort(404)
    qty = max(1, min(int(request.form.get("quantity", 1)), 10))
    cart_data = session.get("cart", {})
    key = str(book_id)
    cart_data[key] = cart_data.get(key, 0) + qty
    session["cart"] = cart_data
    flash(f"Added {book['title']} to cart.", "success")
    return redirect(url_for("cart"))


@app.route("/cart/remove/<int:book_id>", methods=["POST"])
def remove_from_cart(book_id):
    cart_data = session.get("cart", {})
    cart_data.pop(str(book_id), None)
    session["cart"] = cart_data
    flash("Item removed from cart.", "info")
    return redirect(url_for("cart"))


@app.route("/checkout", methods=["GET", "POST"])
@login_required
def checkout():
    if not session.get("cart"):
        flash("Your cart is empty.", "warning")
        return redirect(url_for("books"))
    db = get_db()
    cart_data = session.get("cart", {})
    items = []
    total = 0.0
    for book_id, qty in cart_data.items():
        book = db.execute("SELECT * FROM books WHERE id = ?", (book_id,)).fetchone()
        if book:
            total += book["price"] * qty
            items.append((book, qty))
    if request.method == "POST":
        # Business-logic protection: never trust a client-supplied price/total.
        # The hidden client_total field exists only so the demo can show a tampering attempt.
        try:
            client_total = float(request.form.get("client_total", total))
        except ValueError:
            client_total = -1
        if abs(client_total - total) > 0.01:
            log_action("CHECKOUT_TAMPER_BLOCKED", f"client_total={client_total:.2f}, server_total={total:.2f}")
            flash("Checkout tampering detected: the order total was recalculated on the server and the request was blocked.", "danger")
            return redirect(url_for("checkout"))

        payment_method = "Test Payment / Tokenised Demo"
        cur = db.execute(
            "INSERT INTO orders(user_id,total,payment_method,status,created_at) VALUES(?,?,?,?,?)",
            (session["user_id"], total, payment_method, "Confirmed", datetime.utcnow().isoformat()),
        )
        order_id = cur.lastrowid
        for book, qty in items:
            db.execute("INSERT INTO order_items(order_id,book_id,quantity,unit_price) VALUES(?,?,?,?)", (order_id, book["id"], qty, book["price"]))
            db.execute("UPDATE books SET stock = MAX(stock - ?, 0) WHERE id = ?", (qty, book["id"]))
        db.commit()
        session["cart"] = {}
        log_action("ORDER_CREATED", f"Order #{order_id}, total={total:.2f}, no PAN/CVV stored")
        flash("Order placed using demo payment. No real card data was collected or stored.", "success")
        return redirect(url_for("order_success", order_id=order_id))
    return render_template("checkout.html", items=items, total=total)


@app.route("/order/<int:order_id>")
@login_required
def order_success(order_id):
    order = get_db().execute("SELECT * FROM orders WHERE id = ? AND user_id = ?", (order_id, session["user_id"])).fetchone()
    if not order:
        abort(404)
    return render_template("order_success.html", order=order)


@app.route("/admin")
@admin_required
def admin_dashboard():
    db = get_db()
    books = db.execute("SELECT * FROM books ORDER BY id DESC").fetchall()
    orders = db.execute("SELECT orders.*, users.username FROM orders JOIN users ON users.id = orders.user_id ORDER BY orders.id DESC LIMIT 10").fetchall()
    logs = db.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 10").fetchall()
    return render_template("admin.html", books=books, orders=orders, logs=logs)


@app.route("/admin/book/new", methods=["GET", "POST"])
@admin_required
def admin_book_new():
    if request.method == "POST":
        data = get_book_form()
        get_db().execute("INSERT INTO books(title,author,category,price,stock,description,created_at) VALUES(?,?,?,?,?,?,?)", (*data, datetime.utcnow().isoformat()))
        get_db().commit()
        log_action("ADMIN_BOOK_CREATE", data[0])
        flash("Book created.", "success")
        return redirect(url_for("admin_dashboard"))
    return render_template("admin_book_form.html", book=None)


@app.route("/admin/book/<int:book_id>/edit", methods=["GET", "POST"])
@admin_required
def admin_book_edit(book_id):
    db = get_db()
    book = db.execute("SELECT * FROM books WHERE id = ?", (book_id,)).fetchone()
    if not book:
        abort(404)
    if request.method == "POST":
        data = get_book_form()
        db.execute("UPDATE books SET title=?, author=?, category=?, price=?, stock=?, description=? WHERE id=?", (*data, book_id))
        db.commit()
        log_action("ADMIN_BOOK_UPDATE", data[0])
        flash("Book updated.", "success")
        return redirect(url_for("admin_dashboard"))
    return render_template("admin_book_form.html", book=book)


@app.route("/admin/book/<int:book_id>/delete", methods=["POST"])
@admin_required
def admin_book_delete(book_id):
    get_db().execute("DELETE FROM books WHERE id = ?", (book_id,))
    get_db().commit()
    log_action("ADMIN_BOOK_DELETE", str(book_id))
    flash("Book deleted.", "info")
    return redirect(url_for("admin_dashboard"))


def get_book_form():
    title = request.form.get("title", "").strip()
    author = request.form.get("author", "").strip()
    category = request.form.get("category", "").strip()
    description = request.form.get("description", "").strip()
    try:
        price = float(request.form.get("price", "0"))
        stock = int(request.form.get("stock", "0"))
    except ValueError:
        abort(400)
    if not title or not author or not category or price < 0 or stock < 0:
        abort(400)
    return title, author, category, price, stock, description


@app.route("/security-plan")
def security_plan():
    return render_template("security_plan.html")


@app.route("/robots.txt")
def robots():
    return "User-agent: *\nDisallow: /admin\nDisallow: /checkout\nSitemap: http://127.0.0.1:5000/sitemap.xml\n", 200, {"Content-Type": "text/plain"}


@app.errorhandler(403)
def forbidden(error):
    return render_template("error.html", message="Access denied."), 403


@app.errorhandler(404)
def not_found(error):
    return render_template("error.html", message="Page not found."), 404


with app.app_context():
    init_db()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
