"""VulnMart derivative: targeted fixes for SQLi, XSS, IDOR and password storage.
Not production-ready: demo credentials and absent CSRF/rate limiting remain."""

import sqlite3
import secrets
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, request, render_template, redirect, session, url_for, g

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  # Fresh key per lab process
DB = "vulnmart-fixed.db"


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.executescript("""
        DROP TABLE IF EXISTS users;
        DROP TABLE IF EXISTS products;
        DROP TABLE IF EXISTS reviews;
        DROP TABLE IF EXISTS orders;

        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL   -- Password hash
        );

        CREATE TABLE products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            price REAL NOT NULL,
            description TEXT NOT NULL
        );

        CREATE TABLE reviews (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            product_id INTEGER NOT NULL,
            username TEXT NOT NULL,
            comment TEXT NOT NULL
        );

        CREATE TABLE orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            product_name TEXT NOT NULL,
            quantity INTEGER NOT NULL,
            shipping_address TEXT NOT NULL,
            card_last4 TEXT NOT NULL
        );
    """)

    c.executemany(
        "INSERT INTO users (username, password) VALUES (?, ?)",
        [
            ("admin", generate_password_hash("password123")),
            ("sarah", generate_password_hash("sarah1995")),
            ("devraj", generate_password_hash("devraj_2001")),
        ],
    )

    c.executemany(
        "INSERT INTO products (name, price, description) VALUES (?, ?, ?)",
        [
            ("Mechanical Keyboard", 3499.00, "Hot-swappable, tactile brown switches."),
            ("Wireless Mouse", 899.00, "Silent click, 2.4GHz + Bluetooth."),
            ("USB-C Hub", 1299.00, "7-in-1, HDMI + SD card reader."),
        ],
    )

    c.executemany(
        "INSERT INTO orders (user_id, product_name, quantity, shipping_address, card_last4) VALUES (?, ?, ?, ?, ?)",
        [
            (1, "Mechanical Keyboard", 1, "Admin HQ, Server Room 4, Mumbai", "4242"),
            (2, "Wireless Mouse", 2, "Sarah's House, 12 Palm Street, Pune", "1881"),
            (3, "USB-C Hub", 1, "Devraj's Flat, 9th Floor, Bengaluru", "5566"),
        ],
    )

    conn.commit()
    conn.close()


@app.route("/")
def index():
    db = get_db()
    products = db.execute("SELECT * FROM products").fetchall()
    return render_template("index.html", products=products, user=session.get("username"))


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        db = get_db()
        query = "SELECT * FROM users WHERE username = ?"
        try:
            user = db.execute(query, (username,)).fetchone()
            if user is not None and not check_password_hash(user["password"], password):
                user = None
        except sqlite3.OperationalError:
            user = None

        if user:
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            return redirect(url_for("index"))
        else:
            error = "Invalid credentials."

    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/product/<int:product_id>", methods=["GET"])
def product_detail(product_id):
    db = get_db()
    product = db.execute("SELECT * FROM products WHERE id = ?", (product_id,)).fetchone()
    if product is None:
        return render_template("not_found.html", item="product"), 404
    reviews = db.execute("SELECT * FROM reviews WHERE product_id = ?", (product_id,)).fetchall()
    return render_template("product.html", product=product, reviews=reviews, user=session.get("username"))


@app.route("/product/<int:product_id>/review", methods=["POST"])
def add_review(product_id):
    db = get_db()
    username = session.get("username", "Guest")
    comment = request.form["comment"]
    db.execute(
        "INSERT INTO reviews (product_id, username, comment) VALUES (?, ?, ?)",
        (product_id, username, comment),
    )
    db.commit()
    return redirect(url_for("product_detail", product_id=product_id))


@app.route("/orders")
def my_orders():
    if "user_id" not in session:
        return redirect(url_for("login"))
    db = get_db()
    orders = db.execute("SELECT * FROM orders WHERE user_id = ?", (session["user_id"],)).fetchall()
    return render_template("orders.html", orders=orders, user=session.get("username"))


@app.route("/order/<int:order_id>")
def order_detail(order_id):
    if "user_id" not in session:
        return redirect(url_for("login"))
    db = get_db()
    order = db.execute("SELECT * FROM orders WHERE id = ? AND user_id = ?", (order_id, session["user_id"])).fetchone()
    status = 200 if order is not None else 404
    return render_template("order_detail.html", order=order, user=session.get("username")), status


if __name__ == "__main__":
    import os
    if not os.path.exists(DB):
        init_db()
    app.run(host="127.0.0.1", port=5056, debug=False)
