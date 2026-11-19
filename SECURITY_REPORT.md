# SECURITY_REPORT.md
## Security Assessment and Vulnerability Demonstration of TARA — An E-Commerce Web Application

---

### 1. Introduction
TARA is a locally-hosted e-commerce web application built for an academic
Ethical Hacking course. Its real Login and Product Review features can run
in either a secure mode or an intentionally vulnerable mode (toggled by a
single `LAB_MODE` setting), so that three representative vulnerability
classes can be demonstrated against genuine application functionality
rather than a separate "demo" page.

### 2. Objective
To identify, demonstrate, and remediate representative examples of common
web application vulnerabilities — SQL Injection, Cross-Site Scripting, and
Broken Authentication — within TARA's own real login and review
functionality, and to document the process as an academic deliverable.

### 3. Scope
- **In scope:** the local TARA Flask application running on
  `127.0.0.1:5000`, specifically the `/login` route and the product review
  rendering path, in both `LAB_MODE` settings.
- **Out of scope:** any external website, third-party service, public IP
  address, or real user account. No testing was performed against systems
  outside this local application.

### 4. Technologies Used
- Frontend: HTML5, CSS3, vanilla JavaScript
- Backend: Python 3, Flask
- Database: SQLite
- Password hashing: Werkzeug security helpers (`generate_password_hash`,
  `check_password_hash`)

### 5. Application Architecture
TARA follows a classic server-rendered MVC-style structure: `app.py`
defines all routes and business logic, `database/init_db.py` defines the
schema and seed data, `templates/` contains Jinja2 templates rendered
server-side, and `static/` contains CSS/JS/image assets. A single module
constant, `LAB_MODE`, read once at startup from the `TARA_LAB_MODE`
environment variable, is threaded through `current_user()`, `/login`, and
the review-rendering template, so the whole application's security posture
changes together with one switch rather than through a separate code path.

### 6. Threat Model
Assumed attacker: an unauthenticated or low-privilege user of the local
application attempting to bypass authentication, inject malicious script
content, or exploit weak session/password handling. No physical access,
network-level, or infrastructure attacks are considered.

### 7. Attack Surface
- The real login form (`/login`) — email and password fields
- The real product review submission form — rating and comment fields
- The identity-resolution logic used by every protected route
  (`current_user()`), including the admin dashboard

### 8. SQL Injection
**Feature affected:** `/login`
**Vulnerable pattern:**
```python
query = ("SELECT * FROM users WHERE email = '" + email +
         "' AND password_plain = '" + password + "'")
user = db.execute(query).fetchone()
```
**Payload:** `admin@tara.local' --` in the Email field, any password.
**Result:** the `--` comments out the password check entirely, returning
the admin row and logging the attacker in as admin without knowing the
password. See `vulnerability_notes/sql_injection.md` for full detail.

### 9. Cross-Site Scripting (XSS)
**Feature affected:** product review rendering (`templates/product.html`)
**Vulnerable pattern:**
```html
<p>{{ review['comment']|safe }}</p>
```
**Payload:** `<script>alert('XSS')</script>` submitted as a review.
**Result:** the script executes in the browser of anyone who views that
product page afterward (stored XSS). See
`vulnerability_notes/xss.md`.

### 10. Broken Authentication
**Feature affected:** `/login` and `current_user()` (session
identification, used by every protected route)
**Vulnerable pattern:**
```python
uid = request.cookies.get("debug_uid")     # unsigned, client-editable
```
**Demonstration:** log in as a normal customer, then edit the `debug_uid`
cookie's value in DevTools to another user's id (e.g. the admin's) and
reload — you become that user, including gaining admin dashboard access,
without ever knowing their password. Combined with plaintext password
comparison during login itself. See
`vulnerability_notes/broken_authentication.md`.

### 11. Vulnerability Impact
| Vulnerability | Impact |
|---|---|
| SQL Injection | Full authentication bypass, including admin login without a password |
| XSS | Script execution in victims' browsers, stored/persistent across visits |
| Broken Authentication | Complete account/session takeover and privilege escalation via cookie tampering |

### 12. Vulnerable Implementation
See Sections 8–10 above and the accompanying `vulnerability_notes/*.md`
files for full vulnerable code listings, exact payloads, and explanations.

### 13. Testing Method
Manual, black-box style testing performed directly against the running
local instance with `TARA_LAB_MODE=vulnerable` set:
- SQLi: submitted `admin@tara.local' --` and `x' OR '1'='1' --` to the real
  login form and confirmed authentication bypass.
- XSS: submitted `<script>alert('XSS')</script>` as a real product review
  and confirmed script execution on page reload.
- Broken Auth: logged in as a normal customer, inspected the `debug_uid`
  cookie, edited its value to the admin's user id, and confirmed both
  account takeover and admin dashboard access.
- Repeated all three with `TARA_LAB_MODE` unset (default `secure`) and
  confirmed each attack fails cleanly.

### 14. Secure Implementation
| Vulnerability | Secure Pattern |
|---|---|
| SQL Injection | `db.execute("SELECT * FROM users WHERE email = ?", (email,))` |
| XSS | Default Jinja auto-escaping: `<p>{{ comment }}</p>` (no `\|safe`) |
| Broken Authentication | `check_password_hash(...)` + Flask's signed `session` cookie |

### 15. Remediation
1. Always use parameterized queries; never build SQL via string
   concatenation with user input.
2. Never disable output auto-escaping (`\|safe`) on untrusted input.
3. Never store or compare passwords in plaintext; use a strong hashing
   scheme (`generate_password_hash`/`check_password_hash`).
4. Never trust an unsigned, client-editable identifier for session
   identity; use a cryptographically signed session mechanism (Flask's
   built-in `session`, backed by `app.secret_key`) so tampering
   invalidates the cookie rather than being silently accepted.
5. Enforce both authentication (who the user is) and authorization (what
   they are allowed to do) on every protected route — see
   `admin_required` in `app.py`, which is automatically strengthened once
   `current_user()` is fixed.

### 16. Conclusion
This assessment demonstrates that all three vulnerability classes can be
reliably reproduced inside TARA's own real login and review features —
not a separate toy demo — and that each has a clear, verifiable secure
counterpart controlled by the same `LAB_MODE` switch. By default
(`LAB_MODE=secure`), TARA's live shop uses parameterized queries, default
auto-escaping, hashed passwords, and Flask's signed session throughout;
switching to `LAB_MODE=vulnerable` demonstrates, in the exact same code
paths, what happens when each of those protections is removed.
