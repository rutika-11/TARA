"""
TARA - Everyday Jewelry E-Commerce + Ethical Hacking Academic Project
======================================================================
Run with:  python app.py
Opens at:  http://127.0.0.1:5000

Unlike an earlier version of this project, there is NO separate
"security lab" page. The three academic vulnerabilities (SQL Injection,
XSS, Broken Authentication) live directly inside TARA's real Login and
Product Review features, and are switched on/off together by the single
LAB_MODE setting below. See that setting for how to toggle it.
"""

import os
import sqlite3
from functools import wraps

from flask import (
    Flask, render_template, request, redirect, url_for,
    session, g, flash, abort
)
from werkzeug.security import generate_password_hash, check_password_hash

from database.init_db import init_db, DB_PATH

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__)

# ----------------------------------------------------------------
# Secret key
# ----------------------------------------------------------------
# Reads FLASK_SECRET_KEY from the environment if you've set one (recommended
# if you ever run this somewhere less trusted than your own laptop). Falls
# back to a fixed local-development value so the project still runs with
# zero setup for a beginner following the README.
app.secret_key = os.environ.get(
    "FLASK_SECRET_KEY",
    "tara-local-dev-secret-key-change-if-you-like",
)

# ----------------------------------------------------------------
# Security demonstration mode — THIS is the one switch that matters
# ----------------------------------------------------------------
# TARA's three academic vulnerabilities live inside its NORMAL Login and
# Product Review features (not a separate demo page):
#
#   LAB_MODE = "secure"      (default) -> Login and Reviews behave securely
#   LAB_MODE = "vulnerable"            -> the SAME Login and Review features
#                                          intentionally behave insecurely,
#                                          for YOUR OWN local, authorized
#                                          demonstration only
#
# Toggle it with an environment variable before starting the app:
#   Windows (cmd):        set TARA_LAB_MODE=vulnerable && python app.py
#   Windows (PowerShell): $env:TARA_LAB_MODE="vulnerable"; python app.py
#   macOS/Linux:           TARA_LAB_MODE=vulnerable python app.py
#
# INTENTIONALLY VULNERABLE — LOCAL ACADEMIC LAB ONLY. Only ever run with
# LAB_MODE=vulnerable against this local instance (127.0.0.1), for your own
# authorized coursework demonstration. Never expose this application, in
# either mode, to a public network interface.
LAB_MODE = os.environ.get("TARA_LAB_MODE", "secure").strip().lower()
if LAB_MODE not in ("secure", "vulnerable"):
    LAB_MODE = "secure"


# ----------------------------------------------------------------
# Database helpers
# ----------------------------------------------------------------
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


def current_user():
    """
    Identify the logged-in user (if any). This single function is what
    every protected route, including the admin dashboard, relies on --
    which is exactly why LAB_MODE's Broken Authentication weakness lives
    here: whichever identification scheme is active applies everywhere.
    """
    if LAB_MODE == "vulnerable":
        # ------------------------------------------------------------
        # INTENTIONALLY VULNERABLE — LOCAL ACADEMIC LAB ONLY
        # Identity is trusted from a plain, UNSIGNED cookie instead of
        # Flask's cryptographically signed session. Flask's real session
        # cookie is tamper-evident (it's signed with app.secret_key, so
        # editing it invalidates it); this custom "debug_uid" cookie has
        # no such protection, so its value can simply be edited in the
        # browser's dev tools to impersonate ANY user id -- including the
        # admin account -- without ever knowing that user's password.
        # This is a textbook "improper session validation" / broken
        # authentication weakness. See the SECURE branch below for the fix.
        # ------------------------------------------------------------
        uid = request.cookies.get("debug_uid")
        if not uid:
            return None
        db = get_db()
        try:
            return db.execute("SELECT * FROM users WHERE id = ?", (int(uid),)).fetchone()
        except (TypeError, ValueError):
            return None
    else:
        # SECURE: Flask's session cookie is signed with app.secret_key.
        # Any tampering with it client-side invalidates the signature and
        # Flask discards it entirely, so a user can never edit their way
        # into someone else's session.
        if "user_id" not in session:
            return None
        db = get_db()
        return db.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()


@app.context_processor
def inject_globals():
    return {
        "current_user": current_user(),
        "cart_count": sum(session.get("cart", {}).values()),
        "lab_mode": LAB_MODE,
    }


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if current_user() is None:
            flash("Please log in to continue.", "error")
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        user = current_user()
        if user is None or not user["is_admin"]:
            abort(403)
        return view(*args, **kwargs)
    return wrapped


# ----------------------------------------------------------------
# Customer-facing routes
# ----------------------------------------------------------------
@app.route("/")
def home():
    db = get_db()
    new_arrivals = db.execute("SELECT * FROM products WHERE is_new = 1 LIMIT 4").fetchall()
    bestsellers = db.execute("SELECT * FROM products WHERE is_bestseller = 1 LIMIT 4").fetchall()
    everyday = db.execute("SELECT * FROM products WHERE collection = 'Everyday Essentials' LIMIT 4").fetchall()
    gifting = db.execute("SELECT * FROM products WHERE collection = 'Gifting' LIMIT 4").fetchall()
    collections = ["College Edit", "Work Edit", "Everyday Essentials", "Minimal Classics", "Gifting"]
    categories = ["Earrings", "Rings", "Necklaces", "Pendants", "Bracelets", "Jewelry Sets"]
    category_icons = {
        "Earrings": "earrings.jpeg",
        "Rings": "rings.jpeg",
        "Necklaces": "necklaces.jpeg",
        "Pendants": "pendants.jpeg",
        "Bracelets": "bracelets.jpeg",
        "Jewelry Sets": "sets.jpeg",
    }
    return render_template(
        "index.html",
        new_arrivals=new_arrivals,
        bestsellers=bestsellers,
        everyday=everyday,
        gifting=gifting,
        collections=collections,
        categories=categories,
        category_icons=category_icons,
    )


@app.route("/shop")
def shop():
    db = get_db()
    query = "SELECT * FROM products WHERE 1=1"
    params = []

    category = request.args.get("category")
    if category:
        query += " AND category = ?"
        params.append(category)

    search = request.args.get("q")
    if search:
        # SECURE: parameterized query even on the live shop search.
        query += " AND name LIKE ?"
        params.append(f"%{search}%")

    min_price = request.args.get("min_price", type=float)
    max_price = request.args.get("max_price", type=float)
    if min_price is not None:
        query += " AND price >= ?"
        params.append(min_price)
    if max_price is not None:
        query += " AND price <= ?"
        params.append(max_price)

    sort = request.args.get("sort", "featured")
    if sort == "price_low":
        query += " ORDER BY price ASC"
    elif sort == "price_high":
        query += " ORDER BY price DESC"
    elif sort == "rating":
        query += " ORDER BY rating DESC"
    else:
        query += " ORDER BY id ASC"

    products = db.execute(query, params).fetchall()
    categories = ["Earrings", "Rings", "Necklaces", "Pendants", "Bracelets", "Jewelry Sets"]
    return render_template("shop.html", products=products, categories=categories,
                           selected_category=category, search=search or "", sort=sort)


@app.route("/collections")
def collections():
    db = get_db()
    names = ["College Edit", "Work Edit", "Everyday Essentials", "Minimal Classics", "Gifting"]
    grouped = {}
    for name in names:
        grouped[name] = db.execute("SELECT * FROM products WHERE collection = ? LIMIT 4", (name,)).fetchall()
    return render_template("collections.html", grouped=grouped)


@app.route("/collections/<name>")
def collection_detail(name):
    db = get_db()
    products = db.execute("SELECT * FROM products WHERE collection = ?", (name,)).fetchall()
    return render_template("shop.html", products=products, categories=[], selected_category=None,
                           search="", sort="featured", collection_name=name)


@app.route("/new-arrivals")
def new_arrivals():
    db = get_db()
    products = db.execute("SELECT * FROM products WHERE is_new = 1").fetchall()
    return render_template("new_arrivals.html", products=products)


@app.route("/product/<int:product_id>")
def product_detail(product_id):
    db = get_db()
    product = db.execute("SELECT * FROM products WHERE id = ?", (product_id,)).fetchone()
    if product is None:
        abort(404)
    reviews = db.execute(
        "SELECT * FROM reviews WHERE product_id = ? ORDER BY created_at DESC", (product_id,)
    ).fetchall()
    return render_template("product.html", product=product, reviews=reviews)


@app.route("/product/<int:product_id>/review", methods=["POST"])
@login_required
def submit_review(product_id):
    db = get_db()
    user = current_user()
    rating = request.form.get("rating", 5, type=int)
    comment = request.form.get("comment", "").strip()
    if comment:
        # The review text is always stored exactly as submitted, in both
        # modes -- the vulnerability (and its fix) lives entirely in how
        # it's RENDERED, not how it's stored. See templates/product.html:
        #   LAB_MODE == "vulnerable" -> rendered with |safe (XSS-vulnerable)
        #   LAB_MODE == "secure"     -> rendered with Jinja's default
        #                               auto-escaping (XSS-safe)
        db.execute(
            "INSERT INTO reviews (product_id, user_name, rating, comment) VALUES (?, ?, ?, ?)",
            (product_id, user["name"], rating, comment),
        )
        db.commit()
        flash("Review submitted, thank you!", "success")
    return redirect(url_for("product_detail", product_id=product_id))


# ---------------- Cart (session-based) ----------------
@app.route("/cart")
def cart():
    db = get_db()
    cart_items = session.get("cart", {})
    items = []
    total = 0
    for pid_str, qty in cart_items.items():
        product = db.execute("SELECT * FROM products WHERE id = ?", (int(pid_str),)).fetchone()
        if product:
            subtotal = product["price"] * qty
            total += subtotal
            items.append({"product": product, "quantity": qty, "subtotal": subtotal})
    return render_template("cart.html", items=items, total=total)


@app.route("/cart/add/<int:product_id>", methods=["POST"])
def cart_add(product_id):
    # Read the quantity the customer actually selected (product detail page
    # sends it via the hidden "quantity" field synced to the +/- selector;
    # a plain "Add to Cart" button on a product card sends none, so we
    # default to 1). Always clamp to at least 1 so the cart can never end
    # up with a zero or negative quantity from a stray/edited request.
    quantity = request.form.get("quantity", 1, type=int) or 1
    quantity = max(1, quantity)

    cart_items = session.get("cart", {})
    key = str(product_id)
    cart_items[key] = cart_items.get(key, 0) + quantity
    session["cart"] = cart_items
    flash(f"Added {quantity} to cart." if quantity > 1 else "Added to cart.", "success")
    return redirect(request.referrer or url_for("shop"))


@app.route("/cart/update/<int:product_id>", methods=["POST"])
def cart_update(product_id):
    action = request.form.get("action")
    cart_items = session.get("cart", {})
    key = str(product_id)
    if key in cart_items:
        if action == "increase":
            cart_items[key] += 1
        elif action == "decrease":
            cart_items[key] -= 1
            if cart_items[key] <= 0:
                del cart_items[key]
    session["cart"] = cart_items
    return redirect(url_for("cart"))


@app.route("/cart/remove/<int:product_id>", methods=["POST"])
def cart_remove(product_id):
    cart_items = session.get("cart", {})
    cart_items.pop(str(product_id), None)
    session["cart"] = cart_items
    return redirect(url_for("cart"))


@app.route("/checkout", methods=["POST"])
@login_required
def checkout():
    db = get_db()
    user = current_user()
    cart_items = session.get("cart", {})
    if not cart_items:
        flash("Your cart is empty.", "error")
        return redirect(url_for("cart"))

    total = 0
    line_items = []
    for pid_str, qty in cart_items.items():
        product = db.execute("SELECT * FROM products WHERE id = ?", (int(pid_str),)).fetchone()
        if product:
            total += product["price"] * qty
            line_items.append((product["id"], qty, product["price"]))

    db.execute("INSERT INTO orders (user_id, total, status) VALUES (?, ?, 'Placed')", (user["id"], total))
    order_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
    for pid, qty, price in line_items:
        db.execute(
            "INSERT INTO order_items (order_id, product_id, quantity, price) VALUES (?, ?, ?, ?)",
            (order_id, pid, qty, price),
        )
    db.commit()
    session["cart"] = {}
    flash("Order placed successfully! (academic demo checkout — no real payment taken)", "success")
    return redirect(url_for("orders"))


# ---------------- Wishlist (requires login) ----------------
@app.route("/wishlist")
@login_required
def wishlist():
    db = get_db()
    user = current_user()
    products = db.execute(
        """SELECT products.* FROM products
           JOIN wishlist ON products.id = wishlist.product_id
           WHERE wishlist.user_id = ?""",
        (user["id"],),
    ).fetchall()
    return render_template("wishlist.html", products=products)


@app.route("/wishlist/add/<int:product_id>", methods=["POST"])
@login_required
def wishlist_add(product_id):
    db = get_db()
    user = current_user()
    db.execute(
        "INSERT OR IGNORE INTO wishlist (user_id, product_id) VALUES (?, ?)",
        (user["id"], product_id),
    )
    db.commit()
    flash("Added to wishlist.", "success")
    return redirect(request.referrer or url_for("shop"))


@app.route("/wishlist/remove/<int:product_id>", methods=["POST"])
@login_required
def wishlist_remove(product_id):
    db = get_db()
    user = current_user()
    db.execute("DELETE FROM wishlist WHERE user_id = ? AND product_id = ?", (user["id"], product_id))
    db.commit()
    return redirect(url_for("wishlist"))


@app.route("/wishlist/move-to-cart/<int:product_id>", methods=["POST"])
@login_required
def wishlist_move_to_cart(product_id):
    cart_items = session.get("cart", {})
    key = str(product_id)
    cart_items[key] = cart_items.get(key, 0) + 1
    session["cart"] = cart_items
    db = get_db()
    user = current_user()
    db.execute("DELETE FROM wishlist WHERE user_id = ? AND product_id = ?", (user["id"], product_id))
    db.commit()
    flash("Moved to cart.", "success")
    return redirect(url_for("wishlist"))


# ---------------- Account / Auth ----------------
@app.route("/account")
def account():
    user = current_user()
    if not user:
        return render_template("account.html", user=None)
    db = get_db()
    orders_list = db.execute(
        "SELECT * FROM orders WHERE user_id = ? ORDER BY created_at DESC", (user["id"],)
    ).fetchall()
    return render_template("account.html", user=user, orders=orders_list)


@app.route("/orders")
@login_required
def orders():
    db = get_db()
    user = current_user()
    orders_list = db.execute(
        "SELECT * FROM orders WHERE user_id = ? ORDER BY created_at DESC", (user["id"],)
    ).fetchall()
    order_data = []
    for o in orders_list:
        items = db.execute(
            """SELECT order_items.*, products.name, products.image FROM order_items
               JOIN products ON products.id = order_items.product_id
               WHERE order_id = ?""",
            (o["id"],),
        ).fetchall()
        order_data.append({"order": o, "items": items})
    return render_template("orders.html", order_data=order_data)


@app.route("/login", methods=["GET", "POST"])
def login():
    """
    TARA's real login form. Its behavior depends entirely on LAB_MODE
    (see the top of this file) -- there is no separate "demo" login
    anywhere else. This single route is where two of the three required
    vulnerabilities live: SQL Injection and Broken Authentication.
    """
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        db = get_db()

        if LAB_MODE == "vulnerable":
            # ------------------------------------------------------------
            # INTENTIONALLY VULNERABLE — LOCAL ACADEMIC LAB ONLY
            #
            # (1) SQL INJECTION: the email is concatenated directly into
            #     the SQL string instead of being bound as a parameter.
            #     Try, in the Email field (password can be anything):
            #
            #         admin@tara.local' --
            #
            #     The trailing "--" comments out the rest of the query,
            #     so the AND password_plain = '...' check never happens
            #     and the admin row is returned unconditionally. Or try:
            #
            #         x' OR '1'='1
            #
            #     which matches every row in the table.
            #
            # (2) BROKEN AUTHENTICATION: the password is checked against
            #     a PLAINTEXT copy of the password (password_plain) instead
            #     of the secure bcrypt-style hash, and successful login
            #     issues a plain, unsigned "debug_uid" cookie instead of
            #     Flask's signed session (see current_user() above) --
            #     that cookie's value can be edited directly in the
            #     browser to impersonate any other user id, admin
            #     included, without ever knowing their password.
            # ------------------------------------------------------------
            query = ("SELECT * FROM users WHERE email = '" + email +
                     "' AND password_plain = '" + password + "'")
            try:
                user = db.execute(query).fetchone()  # noqa: intentionally vulnerable
            except sqlite3.Error:
                user = None

            if user:
                flash(f"Welcome back, {user['name']}! (LAB_MODE=vulnerable)", "success")
                resp = redirect(request.args.get("next") or url_for("account"))
                resp.set_cookie("debug_uid", str(user["id"]))
                return resp
            else:
                flash("Invalid email or password.", "error")

        else:
            # SECURE authentication:
            #  1. parameterized lookup (no string concatenation)
            #  2. password compared via hash, never in plaintext
            #  3. session set only after both checks pass, and Flask signs
            #     the session cookie so it cannot be tampered with
            user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()

            if user and check_password_hash(user["password_hash"], password):
                session.clear()
                session["user_id"] = user["id"]
                flash(f"Welcome back, {user['name']}!", "success")
                next_url = request.args.get("next")
                return redirect(next_url or url_for("account"))
            else:
                flash("Invalid email or password.", "error")

    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")

        if not name or not email or not password:
            flash("All fields are required.", "error")
            return render_template("register.html")

        db = get_db()
        existing = db.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
        if existing:
            flash("An account with this email already exists.", "error")
            return render_template("register.html")

        # The password is ALWAYS hashed and stored securely, in both modes.
        # Only when LAB_MODE is explicitly set to "vulnerable" do we ALSO
        # mirror it in plaintext (password_plain), purely so the login
        # vulnerability demo above has a real plaintext value to compare
        # against for freshly-registered accounts. In secure mode,
        # password_plain is always left NULL.
        #
        # INTENTIONALLY VULNERABLE (password_plain only) — LOCAL ACADEMIC
        # LAB ONLY. Never do this in a real application.
        password_plain = password if LAB_MODE == "vulnerable" else None
        db.execute(
            "INSERT INTO users (name, email, password_hash, password_plain) VALUES (?, ?, ?, ?)",
            (name, email, generate_password_hash(password), password_plain),
        )
        db.commit()
        flash("Account created! Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    resp = redirect(url_for("home"))
    resp.delete_cookie("debug_uid")  # clears the vulnerable-mode identity cookie too, if present
    return resp


# ----------------------------------------------------------------
# Admin dashboard (separate, authenticated, not in customer nav)
# ----------------------------------------------------------------
@app.route("/admin")
@admin_required
def admin_dashboard():
    db = get_db()
    stats = {
        "products": db.execute("SELECT COUNT(*) FROM products").fetchone()[0],
        "users": db.execute("SELECT COUNT(*) FROM users").fetchone()[0],
        "orders": db.execute("SELECT COUNT(*) FROM orders").fetchone()[0],
        "reviews": db.execute("SELECT COUNT(*) FROM reviews").fetchone()[0],
        "revenue": db.execute("SELECT COALESCE(SUM(total), 0) FROM orders").fetchone()[0],
    }
    return render_template("admin/dashboard.html", stats=stats)


@app.route("/admin/products")
@admin_required
def admin_products():
    db = get_db()
    products = db.execute("SELECT * FROM products ORDER BY id DESC").fetchall()
    return render_template("admin/products.html", products=products)


@app.route("/admin/products/add", methods=["POST"])
@admin_required
def admin_products_add():
    db = get_db()
    db.execute(
        """INSERT INTO products (name, category, collection, price, description, material, image)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (
            request.form.get("name"),
            request.form.get("category"),
            request.form.get("collection"),
            request.form.get("price", type=float),
            request.form.get("description"),
            request.form.get("material"),
            "ring.jpeg",  # real, existing image used as a neutral default for new products
        ),
    )
    db.commit()
    flash("Product added.", "success")
    return redirect(url_for("admin_products"))


@app.route("/admin/products/edit/<int:product_id>", methods=["POST"])
@admin_required
def admin_products_edit(product_id):
    db = get_db()
    db.execute(
        """UPDATE products SET name=?, category=?, collection=?, price=?, description=?, material=?
           WHERE id=?""",
        (
            request.form.get("name"),
            request.form.get("category"),
            request.form.get("collection"),
            request.form.get("price", type=float),
            request.form.get("description"),
            request.form.get("material"),
            product_id,
        ),
    )
    db.commit()
    flash("Product updated.", "success")
    return redirect(url_for("admin_products"))


@app.route("/admin/products/delete/<int:product_id>", methods=["POST"])
@admin_required
def admin_products_delete(product_id):
    db = get_db()
    db.execute("DELETE FROM products WHERE id = ?", (product_id,))
    db.commit()
    flash("Product deleted.", "success")
    return redirect(url_for("admin_products"))


@app.route("/admin/users")
@admin_required
def admin_users():
    db = get_db()
    users = db.execute("SELECT id, name, email, is_admin, created_at FROM users ORDER BY id DESC").fetchall()
    return render_template("admin/users.html", users=users)


@app.route("/admin/orders")
@admin_required
def admin_orders():
    db = get_db()
    orders_list = db.execute(
        """SELECT orders.*, users.name AS user_name, users.email FROM orders
           JOIN users ON users.id = orders.user_id ORDER BY orders.created_at DESC"""
    ).fetchall()
    return render_template("admin/orders.html", orders=orders_list)


@app.route("/admin/reviews")
@admin_required
def admin_reviews():
    db = get_db()
    reviews_list = db.execute(
        """SELECT reviews.*, products.name AS product_name FROM reviews
           JOIN products ON products.id = reviews.product_id ORDER BY reviews.created_at DESC"""
    ).fetchall()
    return render_template("admin/reviews.html", reviews=reviews_list)


@app.route("/admin/reviews/delete/<int:review_id>", methods=["POST"])
@admin_required
def admin_reviews_delete(review_id):
    db = get_db()
    db.execute("DELETE FROM reviews WHERE id = ?", (review_id,))
    db.commit()
    flash("Review removed.", "success")
    return redirect(url_for("admin_reviews"))


# ----------------------------------------------------------------
# Error handlers
# ----------------------------------------------------------------
@app.errorhandler(404)
def not_found(e):
    return render_template("404.html"), 404


@app.errorhandler(403)
def forbidden(e):
    return render_template("404.html", message="403 — You don't have permission to view this page."), 403


@app.errorhandler(500)
def server_error(e):
    return render_template("404.html", message="500 — Something went wrong on our end."), 500


if __name__ == "__main__":
    os.makedirs(os.path.join(BASE_DIR, "database"), exist_ok=True)
    init_db()
    print(f"TARA starting — LAB_MODE = '{LAB_MODE}' "
          f"({'customer site is intentionally vulnerable for your demo' if LAB_MODE == 'vulnerable' else 'customer site is fully secure'})")
    # Bound to localhost only, on purpose -- this app must never be
    # reachable from another machine, in either LAB_MODE. debug=False so a
    # visitor is never shown a raw Python stack trace (see the custom
    # error handlers above); use Flask's `flask run --debug` yourself if
    # you need the interactive debugger while developing.
    app.run(host="127.0.0.1", port=5000, debug=False)
