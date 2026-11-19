# TARA — Security Assessment and Vulnerability Demonstration of an E-Commerce Web Application

**TARA** is a modern, everyday jewelry e-commerce website (built for the
project brief) whose real Login and Product Review features can run in
either a fully **secure** mode or an intentionally **vulnerable** mode, for
a **B.Sc. Computer Science academic Ethical Hacking project**.

There is no separate "Security Lab" page. The three required
vulnerabilities — SQL Injection, Cross-Site Scripting, and Broken
Authentication — live inside TARA's actual Login and Review functionality
and are switched on/off together with a single setting. This is not a real
store, and both modes are restricted to your own local machine.

---

## 1. Features

**Customer-facing store**
- Home (real hero photo, category tiles, collections, new arrivals, best
  sellers, everyday essentials, gifting section, newsletter)
- Shop, Collections, New Arrivals, Wishlist, Cart, Account
- 30 products across 6 categories: Earrings, Rings, Necklaces, Pendants,
  Bracelets, Jewelry Sets — every product has a real local image
- Product search, category filters, price filters, sorting
- Product detail pages with a **working quantity selector** and customer
  reviews
- Working cart (session-based) and checkout (academic demo, no real
  payment)
- Wishlist for logged-in users
- Login / Register

**Admin dashboard** (separate from customer nav, login + role protected)
- Dashboard statistics, product management, users, orders, reviews

**The security demonstration**
- One switch (`LAB_MODE`, see Section 8) that makes the real Login and
  real Product Review features behave vulnerably or securely.

---

## 2. Technology Stack

| Layer      | Technology            |
|------------|------------------------|
| Frontend   | HTML5, CSS3, Vanilla JavaScript |
| Backend    | Python 3, Flask         |
| Database   | SQLite                  |

No XAMPP, PHP, MySQL, Apache, or Node.js required.

---

## 3. Folder Structure

```
TARA/
├── app.py                       # Main Flask application (all routes)
├── requirements.txt
├── README.md, SECURITY_REPORT.md, SYLLABUS_MAPPING.md
├── VIVA_NOTES.md, PRESENTATION_CONTENT.md, TEST_CASES.md, FINAL_CHECKLIST.md
│
├── database/
│   ├── database.db            # created automatically on first run
│   └── init_db.py             # schema + seed data
│
├── templates/                 # Jinja2 HTML templates
│   ├── base.html, index.html, shop.html, product.html, ...
│   └── admin/                 # admin dashboard templates
│
├── static/
│   ├── css/style.css
│   ├── js/script.js
│   └── images/
│       ├── hero/               # homepage hero photo + lifestyle graphic
│       ├── products/            # one illustration per product (30 + fallback)
│       └── categories/          # 6 category tile icons
│
└── vulnerability_notes/        # written technical explanation of each
    ├── sql_injection.md          vulnerability, for your report/viva
    ├── xss.md
    └── broken_authentication.md
```

---

## 4. Installation

**Requirements:** Python 3.9+ (tested through Python 3.14) on Windows,
macOS, or Linux.

```bash
cd TARA
python -m venv venv
venv\Scripts\activate        # Windows
source venv/bin/activate     # macOS/Linux
pip install -r requirements.txt
```

## 5. Database Setup

No manual setup needed — the database is created and seeded automatically
the first time you run the app. To reset it manually:

```bash
python database/init_db.py
```

## 6. How to Run

```bash
python app.py
```

Then open your browser at:

```
http://127.0.0.1:5000
```

The app is bound to `127.0.0.1` (localhost) only, and `debug=False`, on
purpose, in both modes.

---

## 7. Demo Accounts

| Role     | Email                | Password      |
|----------|-----------------------|---------------|
| Admin    | admin@tara.local      | Admin@123     |
| Customer | customer@tara.local   | Customer@123  |

---

## 8. The Security Demonstration — `LAB_MODE`

TARA's real Login route and real Product Review rendering both check a
single setting, `LAB_MODE`, defined at the top of `app.py`:

```python
LAB_MODE = os.environ.get("TARA_LAB_MODE", "secure").strip().lower()
```

- **`secure`** (the default — no setup needed): Login uses parameterized
  queries and hashed passwords with Flask's signed session; reviews render
  with automatic output-escaping.
- **`vulnerable`**: the *same* Login and Review features intentionally
  behave insecurely, so you can demonstrate the attack against a real,
  normal feature — not a toy demo page.

**To run in vulnerable mode**, set an environment variable before
starting the app:

```bash
# Windows (cmd)
set TARA_LAB_MODE=vulnerable && python app.py

# Windows (PowerShell)
$env:TARA_LAB_MODE="vulnerable"; python app.py

# macOS/Linux
TARA_LAB_MODE=vulnerable python app.py
```

Leave the variable unset (or run `python app.py` normally) to stay secure.

### The three vulnerabilities, exactly where they live

| # | Vulnerability | Real feature affected | Vulnerable behavior | Secure fix |
|---|----------------|------------------------|----------------------|------------|
| 1 | SQL Injection | `/login` | String-concatenated SQL query | Parameterized query (`?`) |
| 2 | Cross-Site Scripting | Product review display | `\|safe` disables output escaping | Default Jinja auto-escaping |
| 3 | Broken Authentication | `/login` + session identification | Plaintext password check + unsigned, tamperable `debug_uid` cookie | `check_password_hash` + Flask's signed session |

Full step-by-step demonstration instructions for each, plus the exact
attacker payloads to use, are in `vulnerability_notes/*.md` and
`SECURITY_REPORT.md`.

**Quick preview** — with `TARA_LAB_MODE=vulnerable`, at `/login`, enter:
```
Email:    admin@tara.local' --
Password: anything
```
This logs you in as the admin account without knowing its password
(SQL Injection). Then, in DevTools, look at the `debug_uid` cookie set on
your browser and try editing its value to impersonate a different user id
(Broken Authentication). On any product page, submit a review containing
`<script>alert('XSS')</script>` and watch it execute (Cross-Site
Scripting).

---

## 9. Secret Key

```python
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "tara-local-dev-secret-key-change-if-you-like")
```
For a purely local academic run, the built-in fallback is fine — nothing
extra to configure. If you'd like to set your own, export
`FLASK_SECRET_KEY` before running `python app.py`.

---

## 10. Academic Safety Statement

This project is an **authorized, local-only** academic exercise. In
**either** mode:

- The app is bound to `127.0.0.1` only, and `debug=False`
- Nothing here targets real websites, external systems, or third-party
  accounts
- The vulnerable code paths are clearly marked in `app.py` and the
  templates with `INTENTIONALLY VULNERABLE — LOCAL ACADEMIC LAB ONLY`
  comments, so they can never be mistaken for the intended, secure
  behavior

Do not expose this application to the public internet, in either mode.
