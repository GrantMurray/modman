#!/usr/bin/env python3
"""Local control page for modman. Started by `web start`, not run on its own."""

import base64
import gzip
import hashlib
import hmac
import json
import os
import re
import secrets
import select
import ssl
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import modman_acme

PASSWORD_FILE = os.environ.get("MODMAN_WEB_PASSWORD_FILE", "")
BIN = os.environ.get("MODMAN_BIN", "")
PORT = int(os.environ.get("MODMAN_WEB_PORT", "8787"))
HTTP_PORT = int(os.environ.get("MODMAN_WEB_HTTP_PORT", str(PORT + 1)))
BIND = os.environ.get("MODMAN_WEB_BIND", "0.0.0.0")
CERT = os.environ.get("MODMAN_WEB_CERT", "")
KEY = os.environ.get("MODMAN_WEB_KEY", "")
CA = os.environ.get("MODMAN_WEB_CA", "")
DATA_DIR = os.path.dirname(os.path.abspath(CERT)) if CERT else ""
if not CA and DATA_DIR:
    CA = os.path.join(DATA_DIR, ".modman-web-ca.pem")
DOMAIN_FILE = os.path.join(DATA_DIR, ".modman-web-domain") if DATA_DIR else ""
LE_CERT = os.path.join(DATA_DIR, ".modman-web-le-cert.pem") if DATA_DIR else ""
LE_KEY = os.path.join(DATA_DIR, ".modman-web-le-key.pem") if DATA_DIR else ""
ACME_ACCOUNT = os.path.join(DATA_DIR, ".modman-web-acme-key.pem") if DATA_DIR else ""
CHALLENGE_DIR = os.path.join(DATA_DIR, ".modman-web-acme") if DATA_DIR else ""
ADMIN_HASH_FILE = os.path.join(DATA_DIR, ".modman-web-admin-hash") if DATA_DIR else ""
BLACKLIST_FILE = os.path.join(DATA_DIR, "blacklist.txt") if DATA_DIR else ""
VIEW_HASH_FILE = os.path.join(DATA_DIR, ".modman-web-view-hash") if DATA_DIR else ""
le_holder = [None]

if not PASSWORD_FILE or not os.path.isfile(PASSWORD_FILE):
    sys.stderr.write("Error: password file is missing.\n")
    sys.exit(1)
with open(PASSWORD_FILE, encoding="utf-8") as fh:
    STORED_HASH = fh.read().strip().lower()
os.remove(PASSWORD_FILE)

# "scrypt$n$r$p$salt$digest", written by `web password`. A bare SHA-256 hex
# digest is the older format; it still signs in until the password is set again.
SCRYPT_RE = re.compile(r"scrypt\$(\d+)\$(\d+)\$(\d+)\$([0-9a-f]{32})\$([0-9a-f]{64})")
scrypt_match = SCRYPT_RE.fullmatch(STORED_HASH)
if scrypt_match:
    SCRYPT_N, SCRYPT_R, SCRYPT_P = (int(x) for x in scrypt_match.group(1, 2, 3))
    if not (2 ** 10 <= SCRYPT_N <= 2 ** 17 and SCRYPT_N & (SCRYPT_N - 1) == 0
            and 1 <= SCRYPT_R <= 16 and 1 <= SCRYPT_P <= 4):
        sys.stderr.write("Error: password hash is invalid.\n")
        sys.exit(1)
    PASSWORD_SALT = bytes.fromhex(scrypt_match.group(4))
    PASSWORD_DIGEST = bytes.fromhex(scrypt_match.group(5))
    PASSWORD_LEGACY = False
elif re.fullmatch(r"[0-9a-f]{64}", STORED_HASH):
    PASSWORD_DIGEST = bytes.fromhex(STORED_HASH)
    PASSWORD_LEGACY = True
    sys.stderr.write("Warning: the saved password uses the old hash. Run web password to replace it.\n")
else:
    sys.stderr.write("Error: password hash is invalid.\n")
    sys.exit(1)
del STORED_HASH
if not BIN:
    sys.stderr.write("Error: MODMAN_BIN is not set.\n")
    sys.exit(1)

SESSION_IDLE = 12 * 3600
SESSION_MAX = 7 * 24 * 3600
# token -> [created, last used]
sessions = {}
sessions_lock = threading.Lock()
call_lock = threading.Lock()

# One address gets LOGIN_IP_LIMIT wrong passwords per LOGIN_WINDOW. Every
# address together gets LOGIN_GLOBAL_LIMIT per minute.
LOGIN_WINDOW = 15 * 60
LOGIN_IP_LIMIT = 10
LOGIN_GLOBAL_LIMIT = 30
login_failures = {}
global_failures = []
login_lock = threading.Lock()


def read_domain():
    name = os.environ.get("MODMAN_WEB_DOMAIN", "").strip().lower()
    if not name and DOMAIN_FILE and os.path.isfile(DOMAIN_FILE):
        with open(DOMAIN_FILE, encoding="utf-8") as fh:
            text = fh.read().strip()
        name = text.split()[0].lower() if text else ""
    if modman_acme.valid_domain(name):
        return name
    return ""


def make_context(cert, key):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.set_alpn_protocols(["http/1.1"])
    context.load_cert_chain(cert, key)
    return context


def use_signed_certificate(domain):
    if not modman_acme.certificate_matches(LE_CERT, domain):
        return
    le_holder[0] = {"name": domain, "context": make_context(LE_CERT, LE_KEY)}


def sign_loop(domain):
    # The http port has to be accepting before the signing check comes back.
    time.sleep(0.5)
    delay = 12 * 3600
    while True:
        try:
            changed = modman_acme.ensure(domain, LE_CERT, LE_KEY, ACME_ACCOUNT, CHALLENGE_DIR)
            use_signed_certificate(domain)
            if changed:
                sys.stderr.write(f"signed https certificate for {domain}\n")
            delay = 12 * 3600
        except Exception as exc:
            sys.stderr.write(f"certificate signing failed: {exc}\n")
            delay = 15 * 60
        time.sleep(delay)


def acme_challenge(token):
    if not CHALLENGE_DIR or not re.fullmatch(r"[A-Za-z0-9_-]{8,128}", token or ""):
        return None
    path = os.path.join(CHALLENGE_DIR, token)
    if not os.path.isfile(path):
        return None
    with open(path, "rb") as fh:
        return fh.read()


def password_ok(given):
    if not given:
        return False
    if PASSWORD_LEGACY:
        # The old prompt read the password with `read -r`, which drops outer blanks.
        got = hashlib.sha256(given.strip(" \t").encode("utf-8")).digest()
    else:
        got = hashlib.scrypt(
            given.encode("utf-8"),
            salt=PASSWORD_SALT,
            n=SCRYPT_N,
            r=SCRYPT_R,
            p=SCRYPT_P,
            maxmem=2 * 128 * SCRYPT_R * SCRYPT_N * SCRYPT_P + (1 << 20),
            dklen=len(PASSWORD_DIGEST),
        )
    return hmac.compare_digest(got, PASSWORD_DIGEST)


def command_words(text):
    """Lowercase words of a console command, without a leading / or a namespace
    such as minecraft: on the command name."""
    words = text.strip().lower().lstrip("/").split()
    if words:
        words[0] = words[0].rpartition(":")[2]
    return words


def read_blacklist():
    """Each line of blacklist.txt is a command, or the first words of one.
    Read on every send, so edits apply without a restart."""
    rules = []
    if not BLACKLIST_FILE or not os.path.isfile(BLACKLIST_FILE):
        return rules
    try:
        with open(BLACKLIST_FILE, encoding="utf-8") as fh:
            for line in fh:
                line = line.split("#", 1)[0]
                words = command_words(line)
                if words:
                    rules.append(words)
    except (OSError, UnicodeDecodeError):
        pass
    return rules


def blacklisted(command):
    """The blacklist line that command matches, or "". The command after each
    `run` in an execute command is checked too."""
    rules = read_blacklist()
    if not rules:
        return ""
    words = command_words(command)
    starts = [0]
    if words and words[0] == "execute":
        starts += [i + 1 for i, word in enumerate(words) if word == "run"]
    for start in starts:
        tail = command_words(" ".join(words[start:]))
        for rule in rules:
            if tail[:len(rule)] == rule:
                return " ".join(rule)
    return ""


def read_hash_file(path):
    if not path:
        return ""
    try:
        with open(path, encoding="utf-8") as fh:
            return fh.read().strip().lower()
    except OSError:
        return ""


def stored_password_ok(stored, given):
    """Check given against a scrypt hash saved by `web admin` or `web viewer`."""
    if not given or not stored:
        return False
    match = SCRYPT_RE.fullmatch(stored)
    if not match:
        return False
    n, r, p = (int(x) for x in match.group(1, 2, 3))
    if not (2 ** 10 <= n <= 2 ** 17 and n & (n - 1) == 0 and 1 <= r <= 16 and 1 <= p <= 4):
        return False
    digest = bytes.fromhex(match.group(5))
    got = hashlib.scrypt(
        given.encode("utf-8"),
        salt=bytes.fromhex(match.group(4)),
        n=n,
        r=r,
        p=p,
        maxmem=2 * 128 * r * n * p + (1 << 20),
        dklen=len(digest),
    )
    return hmac.compare_digest(got, digest)


def admin_password_ok(given):
    # Read each time, so a new admin password applies without a restart.
    return stored_password_ok(read_hash_file(ADMIN_HASH_FILE), given)


def admin_password_set():
    return bool(ADMIN_HASH_FILE) and os.path.isfile(ADMIN_HASH_FILE) and os.path.getsize(ADMIN_HASH_FILE) > 0


def login_blocked(addr):
    now = time.monotonic()
    with login_lock:
        global_failures[:] = [t for t in global_failures if now - t < 60]
        if len(global_failures) >= LOGIN_GLOBAL_LIMIT:
            return True
        recent = [t for t in login_failures.get(addr, []) if now - t < LOGIN_WINDOW]
        if recent:
            login_failures[addr] = recent
        else:
            login_failures.pop(addr, None)
        return len(recent) >= LOGIN_IP_LIMIT


def login_failed(addr):
    now = time.monotonic()
    with login_lock:
        global_failures.append(now)
        login_failures.setdefault(addr, []).append(now)
        if len(login_failures) > 1000:
            for key in list(login_failures):
                if now - login_failures[key][-1] >= LOGIN_WINDOW:
                    del login_failures[key]


def login_succeeded(addr):
    with login_lock:
        login_failures.pop(addr, None)


# view_hash is "" for a full sign-in. A view-only sign-in keeps the hash it
# signed in with, and ends when `web viewer` changes or removes that password.
def new_session(view_hash=""):
    token = secrets.token_urlsafe(32)
    now = time.monotonic()
    with sessions_lock:
        for key, (created, used, _) in list(sessions.items()):
            if now - created > SESSION_MAX or now - used > SESSION_IDLE:
                del sessions[key]
        sessions[token] = [now, now, view_hash]
    return token


def session_role(token):
    """"full", "view", or "" when the token is not signed in."""
    if not token:
        return ""
    now = time.monotonic()
    with sessions_lock:
        entry = sessions.get(token)
        if entry is None:
            return ""
        created, used, view_hash = entry
        if now - created > SESSION_MAX or now - used > SESSION_IDLE:
            del sessions[token]
            return ""
        if view_hash and not hmac.compare_digest(view_hash, read_hash_file(VIEW_HASH_FILE)):
            del sessions[token]
            return ""
        entry[1] = now
        return "view" if view_hash else "full"


def page_csp(html):
    """Allow only the page's own inline scripts, by hash."""
    hashes = []
    for body in re.findall(r"<script>(.*?)</script>", html, re.S):
        digest = base64.b64encode(hashlib.sha256(body.encode("utf-8")).digest()).decode("ascii")
        hashes.append(f"'sha256-{digest}'")
    return (
        "default-src 'self'; script-src " + " ".join(hashes)
        + "; style-src 'unsafe-inline'; img-src 'self'; object-src 'none'"
        + "; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
    )


HOST_RE = re.compile(r"([A-Za-z0-9.-]+|\[[0-9A-Fa-f:.]+\])(?::(\d{1,5}))?")


def modman_call(args, timeout):
    with call_lock:
        return subprocess.run(
            ["bash", BIN, "--web-call", *args],
            capture_output=True,
            text=True,
            timeout=timeout,
        )


# A console poll with nothing new waits up to LOG_WAIT seconds for the log to
# grow before answering, so an idle console costs one request per LOG_WAIT.
LOG_WAIT = 20
LOG_NAME_RE = re.compile(r"[A-Za-z0-9._-]+")
root_holder = [None]


def minecraft_root():
    if root_holder[0] is None:
        try:
            proc = modman_call(["root"], 10)
        except subprocess.TimeoutExpired:
            return ""
        root = (proc.stdout or "").strip() if proc.returncode == 0 else ""
        root_holder[0] = root if os.path.isabs(root) else ""
    return root_holder[0]


# (session, page id) -> [newest request number, last used]. A page's newer
# console request, such as on switching servers, ends the wait of its older one
# with a normal reply, so the page never has to cancel a request.
log_turns = {}
log_turns_lock = threading.Lock()
PAGE_ID_RE = re.compile(r"[A-Za-z0-9]{8,40}")


def take_log_turn(key):
    now = time.monotonic()
    with log_turns_lock:
        if len(log_turns) > 256:
            for old in [k for k, v in log_turns.items() if now - v[1] > 3600]:
                del log_turns[old]
        entry = log_turns.setdefault(key, [0, now])
        entry[0] += 1
        entry[1] = now
        return entry[0]


def log_turn_current(key, turn):
    with log_turns_lock:
        entry = log_turns.get(key)
        return entry is not None and entry[0] == turn


def wait_for_log(name, offset, conn, key, turn):
    # Returns "grew" (or "timeout") to read the log again, "superseded" when the
    # same page sent a newer request, and "gone" when the page hung up.
    # modman has already checked name; this only re-checks it before building
    # a path. A missing or odd root just skips the wait.
    root = minecraft_root()
    if not root or not LOG_NAME_RE.fullmatch(name) or ".." in name:
        return "grew"
    path = os.path.join(root, name, "logs", "latest.log")
    deadline = time.monotonic() + LOG_WAIT
    while time.monotonic() < deadline:
        try:
            if os.stat(path).st_size != offset:
                return "grew"
        except OSError:
            return "grew"
        if key is not None and not log_turn_current(key, turn):
            return "superseded"
        # The page sends nothing while it waits, so the socket only turns
        # readable when the browser closes it.
        try:
            readable, _, _ = select.select([conn], [], [], 0.5)
        except (OSError, ValueError):
            return "gone"
        if readable:
            return "gone"
    return "timeout"


# The page resends a POST whose connection failed, with the same X-Request-Id.
# (session, id) -> [finished event, (code, reply) or None, when]. A resend
# gets the first try's reply, so an action never runs twice. Finished entries
# are kept REPLY_KEEP seconds.
replies = {}
replies_lock = threading.Lock()
REQUEST_ID_RE = re.compile(r"[A-Za-z0-9]{16,40}")
REPLY_KEEP = 600


def parse_log_frame(stdout):
    header, sep, body = stdout.partition("\n")
    if not sep:
        return None
    parts = header.split()
    if len(parts) != 3 or parts[0] != "MODMAN_LOG" or parts[1] not in ("0", "1"):
        return None
    if not parts[2].isdigit():
        return None
    return parts[1] == "1", int(parts[2]), body


def command_text(proc):
    parts = []
    if proc.stdout:
        parts.append(proc.stdout.rstrip("\n"))
    if proc.stderr:
        parts.append(proc.stderr.rstrip("\n"))
    return "\n".join(part for part in parts if part)


# Both pages link this icon, so browsers do not fetch /favicon.ico and log the
# empty answer as an error.
FAVICON_SVG = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16">'
    '<rect width="16" height="16" rx="3" fill="#1f3d2d"/>'
    '<rect x="3" y="3" width="10" height="10" fill="#c8c2b4"/>'
    '<rect x="3" y="3" width="10" height="3" fill="#5f9e3a"/>'
    '</svg>'
).encode("utf-8")

LOGIN_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>modman</title>
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<style>
  :root {
    color-scheme: light;
    --bg: #f4f2ec; --surface: #fff; --border: #e3ded3; --border-strong: #cdc6b7; --text: #1c1c1c; --muted: #5f5a52;
    --accent: #2f6b47; --accent-hover: #275a3b; --bad: #a12a2a; --focus: #2f6b47;
  }
  @media (prefers-color-scheme: dark) {
    :root {
      color-scheme: dark;
      --bg: #121412; --surface: #1b1e1b; --border: #2d322d; --border-strong: #3e453e; --text: #e8e5de; --muted: #a39e94;
      --accent: #337a4f; --accent-hover: #3b8a5a; --bad: #f19090; --focus: #74cf93;
    }
  }
  * { box-sizing: border-box; }
  body { margin: 0; padding: 0 1rem; font: 16px/1.45 system-ui, -apple-system, "Segoe UI", sans-serif; background: var(--bg); color: var(--text); }
  main { max-width: 22rem; margin: 14vh auto; background: var(--surface); padding: 1.75rem; border: 1px solid var(--border); border-radius: 12px; box-shadow: 0 8px 28px rgba(0, 0, 0, 0.08); }
  h1 { margin: 0 0 0.4rem; font-size: 1.4rem; display: flex; align-items: center; gap: 0.55rem; }
  p { margin: 0 0 1.1rem; color: var(--muted); }
  label { display: block; font-size: 0.9rem; margin-bottom: 1rem; }
  input { display: block; width: 100%; margin-top: 0.35rem; padding: 0.55rem 0.7rem; font: inherit; color: inherit; background: var(--surface); border: 1px solid var(--border-strong); border-radius: 7px; }
  :focus-visible { outline: 2px solid var(--focus); outline-offset: 2px; }
  button { width: 100%; font: inherit; font-weight: 600; padding: 0.55rem 0.8rem; background: var(--accent); color: #fff; border: 0; border-radius: 7px; cursor: pointer; }
  button:hover { background: var(--accent-hover); }
  .err { color: var(--bad); }
</style>
</head>
<body>
<main>
  <h1><img src="/favicon.svg" alt="" width="26" height="26"> modman</h1>
  <p>Sign in with the password set when this page was started.</p>
  __ERROR__
  <form id="login">
    <label>Password
      <input id="password" type="password" autocomplete="current-password" autofocus required>
    </label>
    <button type="submit">Sign in</button>
  </form>
</main>
<script>
document.getElementById("login").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const input = document.getElementById("password");
  const password = input.value;
  input.value = "";
  const res = await fetch("/login", {
    method: "POST",
    headers: {"Content-Type": "application/x-www-form-urlencoded"},
    body: "password=" + encodeURIComponent(password)
  });
  location.href = res.redirected ? res.url : "/login?error=1";
});
</script>
</body>
</html>
"""

APP_PAGE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>modman</title>
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<style>
  :root {
    color-scheme: light;
    --bg: #f4f2ec; --surface: #fff; --surface-2: #f9f7f2; --border: #e3ded3; --border-strong: #cdc6b7;
    --text: #1c1c1c; --muted: #5f5a52; --hover: #f0ece3; --focus: #2f6b47;
    --brand: #1f3d2d; --brand-text: #f4f1ea; --brand-line: #4f6e5c;
    --accent: #2f6b47; --accent-hover: #275a3b;
    --ok: #1d7a3a; --ok-bg: #e2f1e6; --warn: #8a5a00; --warn-bg: #faefd6;
    --bad: #a12a2a; --bad-bg: #f8e2e2; --idle: #6f6a61; --idle-bg: #ebe8e1;
    --term-bg: #151815; --term-text: #dad7cf; --term-muted: #8d897f; --term-warn: #e8c46a; --term-err: #ff9191;
    --shadow: 0 1px 2px rgba(0, 0, 0, 0.05), 0 4px 14px rgba(0, 0, 0, 0.05);
    --pop-shadow: 0 8px 28px rgba(0, 0, 0, 0.16);
    --radius: 10px;
  }
  @media (prefers-color-scheme: dark) {
    :root {
      color-scheme: dark;
      --bg: #121412; --surface: #1b1e1b; --surface-2: #202420; --border: #2d322d; --border-strong: #3e453e;
      --text: #e8e5de; --muted: #a39e94; --hover: #262b26; --focus: #74cf93;
      --brand: #17271e; --brand-text: #e8e5de; --brand-line: #3b5746;
      --accent: #337a4f; --accent-hover: #3b8a5a;
      --ok: #74cf93; --ok-bg: #1b3324; --warn: #e5b95c; --warn-bg: #362b14;
      --bad: #f19090; --bad-bg: #3b1e1e; --idle: #a09b91; --idle-bg: #272b27;
      --term-bg: #0d0f0d;
      --shadow: 0 1px 2px rgba(0, 0, 0, 0.4);
      --pop-shadow: 0 10px 32px rgba(0, 0, 0, 0.55);
    }
  }
  * { box-sizing: border-box; }
  body { margin: 0; font: 15px/1.45 system-ui, -apple-system, "Segoe UI", sans-serif; background: var(--bg); color: var(--text); }
  button, input, select { font: inherit; color: inherit; }
  button { background: var(--surface); color: var(--text); border: 1px solid var(--border-strong); border-radius: 7px; padding: 0.3rem 0.75rem; cursor: pointer; line-height: 1.35; }
  button:hover:not(:disabled) { background: var(--hover); }
  button:disabled { opacity: 0.5; cursor: default; }
  :focus-visible { outline: 2px solid var(--focus); outline-offset: 2px; }
  .primary, .row-actions button[type="submit"] { background: var(--accent); border-color: var(--accent); color: #fff; font-weight: 600; }
  .primary:hover:not(:disabled), .row-actions button[type="submit"]:hover:not(:disabled) { background: var(--accent-hover); }
  .danger { color: var(--bad); }
  .row-actions button.danger[type="submit"] { background: var(--bad); border-color: var(--bad); color: #fff; }
  input[type="text"], input[type="search"], input[type="number"], input[type="url"], select { background: var(--surface); border: 1px solid var(--border-strong); border-radius: 7px; padding: 0.35rem 0.6rem; }
  .muted { color: var(--muted); font-size: 0.9rem; }

  header { display: flex; flex-wrap: wrap; gap: 0.6rem 1rem; align-items: center; background: var(--brand); color: var(--brand-text); padding: 0.65rem 1.25rem; }
  header h1 { margin: 0; font-size: 1.1rem; font-weight: 650; display: flex; align-items: center; gap: 0.5rem; }
  header h1 img { border-radius: 5px; }
  .header-end { margin-left: auto; display: flex; flex-wrap: wrap; align-items: center; gap: 0.5rem 0.6rem; }
  .pill { display: inline-flex; align-items: center; gap: 0.4rem; font-size: 0.82rem; padding: 0.22rem 0.65rem; border-radius: 999px; background: rgba(255, 255, 255, 0.08); white-space: nowrap; }
  .pill b { font-weight: 600; }
  .dot { width: 0.55rem; height: 0.55rem; border-radius: 50%; background: #e46a6a; flex: none; }
  .dot.on { background: #48d27a; }
  .menu { position: relative; }
  .menu summary { list-style: none; cursor: pointer; border: 1px solid var(--brand-line); border-radius: 7px; padding: 0.3rem 0.75rem; user-select: none; }
  .menu summary:hover { background: rgba(255, 255, 255, 0.08); }
  .menu summary::-webkit-details-marker { display: none; }
  .menu summary::after { content: " \25BE"; font-size: 0.8em; }
  .menu-panel { position: absolute; right: 0; top: calc(100% + 0.4rem); z-index: 5; display: flex; flex-direction: column; min-width: 13rem; background: var(--surface); color: var(--text); border: 1px solid var(--border); border-radius: var(--radius); box-shadow: var(--pop-shadow); padding: 0.3rem; }
  .menu-panel button, .pop button { border: 0; background: transparent; text-align: left; border-radius: 6px; padding: 0.45rem 0.65rem; white-space: nowrap; }
  .menu-panel button:hover, .pop button:hover, .pop button:focus { background: var(--hover); outline: none; }
  .pop hr, .menu-panel hr { border: 0; border-top: 1px solid var(--border); margin: 0.25rem 0.2rem; }

  main { padding: 1.25rem; max-width: 76rem; margin: 0 auto; display: grid; gap: 1.5rem; }
  .card { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); box-shadow: var(--shadow); }
  .section-head { display: flex; align-items: center; gap: 0.75rem; }
  .section-head h2 { margin: 0; font-size: 1.05rem; font-weight: 650; }
  .section-head .primary { margin-left: auto; }
  .group-title { display: flex; align-items: center; gap: 0.45rem; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.06em; color: var(--muted); font-weight: 650; margin: 1.1rem 0 0.45rem; }
  .group > summary { cursor: pointer; list-style: none; user-select: none; width: fit-content; }
  .group > summary::-webkit-details-marker { display: none; }
  .group > summary::before { content: "\25B8"; font-size: 0.85rem; transition: transform 0.15s; }
  .group[open] > summary::before { transform: rotate(90deg); }
  .group > summary:hover { color: var(--text); }
  .count { font-size: 0.72rem; background: var(--idle-bg); color: var(--muted); border-radius: 999px; padding: 0 0.45rem; letter-spacing: 0; }
  .empty { padding: 1.25rem; color: var(--muted); }

  .table-card { overflow: hidden; }
  table { width: 100%; border-collapse: collapse; }
  th { text-align: left; font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--muted); font-weight: 600; background: var(--surface-2); padding: 0.5rem 0.85rem; border-bottom: 1px solid var(--border); }
  td { padding: 0.65rem 0.85rem; border-bottom: 1px solid var(--border); vertical-align: middle; }
  tbody tr:last-child td { border-bottom: 0; }
  tbody tr:hover { background: var(--surface-2); }
  .name { font-weight: 600; overflow-wrap: anywhere; }
  .meta { font-size: 0.82rem; color: var(--muted); }
  .warn-text { font-size: 0.8rem; color: var(--warn); margin-top: 0.15rem; }
  .warn-text:empty { display: none; }
  .num { font-variant-numeric: tabular-nums; white-space: nowrap; }
  .badge { display: inline-flex; align-items: center; gap: 0.4rem; font-size: 0.8rem; font-weight: 600; padding: 0.12rem 0.6rem; border-radius: 999px; background: var(--idle-bg); color: var(--idle); white-space: nowrap; }
  .badge::before { content: ""; width: 0.5rem; height: 0.5rem; border-radius: 50%; background: currentColor; }
  .badge.running { background: var(--ok-bg); color: var(--ok); }
  .badge.starting { background: var(--warn-bg); color: var(--warn); }
  .badge.error { background: var(--bad-bg); color: var(--bad); }
  .badge.starting::before { animation: pulse 1.2s ease-in-out infinite; }
  @keyframes pulse { 50% { opacity: 0.25; } }
  td.actions { width: 1%; }
  .actions-inner { display: flex; gap: 0.35rem; justify-content: flex-end; align-items: center; }
  .actions-inner button { white-space: nowrap; }
  .more { padding-left: 0.6rem; padding-right: 0.6rem; font-weight: 700; letter-spacing: 0.05em; }
  tr.busy td { color: var(--muted); }
  tr.busy .badge { opacity: 0.6; }
  .loadbar { display: block; margin-top: 0.4rem; height: 0.25rem; background: var(--border); overflow: hidden; border-radius: 999px; }
  .loadbar[hidden] { display: none; }
  .loadbar span { display: block; height: 100%; width: 35%; background: var(--accent); animation: loadbar 1s ease-in-out infinite; }
  .loadbar.known span { width: var(--pct, 0%); animation: none; transition: width 0.3s; }
  @keyframes loadbar { from { transform: translateX(-120%); } to { transform: translateX(320%); } }

  .console-panel { padding: 0.9rem; display: flex; flex-direction: column; gap: 0.55rem; min-width: 0; }
  .console-head { display: flex; align-items: center; gap: 0.5rem; }
  .console-head h2 { margin: 0; font-size: 1.05rem; font-weight: 650; }
  .spinner { width: 0.9rem; height: 0.9rem; border: 2px solid var(--border-strong); border-top-color: var(--accent); border-radius: 50%; animation: spin 0.7s linear infinite; flex: none; }
  .spinner[hidden] { display: none; }
  @keyframes spin { to { transform: rotate(360deg); } }
  .view-pill { display: none; }
  body.view-only .view-pill { display: inline-flex; }
  body.view-only #svc-menu, body.view-only #install-open, body.view-only [data-primary],
  body.view-only [data-act="more"], body.view-only #console-cmd,
  body.view-only #console-form button[type=submit] { display: none; }
  .console-form { display: flex; flex-wrap: wrap; gap: 0.4rem; align-items: center; }
  .console-form input { flex: 1; min-width: 10rem; }
  #console-msg { margin: 0; }
  #console-msg:empty { display: none; }
  .term { position: relative; flex: 1; min-height: 0; display: flex; }
  #out { flex: 1; margin: 0; white-space: pre-wrap; overflow-wrap: anywhere; background: var(--term-bg); color: var(--term-text); font: 12.5px/1.5 ui-monospace, SFMono-Regular, Menlo, Consolas, "DejaVu Sans Mono", monospace; padding: 0.75rem 0.9rem; border-radius: 8px; min-height: 14rem; max-height: 30rem; overflow: auto; }
  #out:empty::before { content: attr(data-empty); color: var(--term-muted); font-family: system-ui, sans-serif; }
  #out .lw { color: var(--term-warn); }
  #out .le { color: var(--term-err); }
  .jump { position: absolute; right: 0.9rem; bottom: 0.75rem; border: 0; border-radius: 999px; background: var(--accent); color: #fff; font-size: 0.8rem; font-weight: 600; padding: 0.3rem 0.8rem; box-shadow: var(--pop-shadow); }
  .jump:hover:not(:disabled) { background: var(--accent-hover); }
  .jump[hidden] { display: none; }

  .pick { position: relative; }
  .pick-btn { background: var(--surface); border: 1px solid var(--border-strong); padding: 0.35rem 0.65rem; min-width: 11rem; text-align: left; }
  .pick-btn::after { content: " \25BE"; float: right; margin-left: 0.6rem; }
  .pick-menu, .pop { position: absolute; z-index: 6; background: var(--surface); color: var(--text); border: 1px solid var(--border); border-radius: var(--radius); box-shadow: var(--pop-shadow); display: flex; flex-direction: column; padding: 0.3rem; }
  .pick-menu { left: 0; top: calc(100% + 0.25rem); min-width: 100%; max-height: 16rem; overflow-y: auto; }
  .pick-menu[hidden], .pop[hidden] { display: none; }
  .pick-menu button { border: 0; background: transparent; text-align: left; border-radius: 6px; padding: 0.4rem 0.65rem; white-space: nowrap; }
  .pick-menu button:hover, .pick-menu button:focus { background: var(--hover); outline: none; }
  .pick-menu button[aria-selected="true"] { font-weight: 600; }
  .pop { top: 0; left: 0; min-width: 12rem; }
  .pop .danger { color: var(--bad); }
  .props-menu { min-width: 16rem; max-width: min(28rem, calc(100vw - 2rem)); }
  .props-menu input { margin: 0.2rem 0.2rem 0.35rem; }
  .props-menu .props-list { overflow-y: auto; max-height: 14rem; display: flex; flex-direction: column; }
  .props-menu .props-list button { display: flex; gap: 0.8rem; justify-content: space-between; }
  .props-menu .props-val { color: var(--muted); overflow: hidden; text-overflow: ellipsis; max-width: 12rem; }
  .props-menu p { margin: 0.4rem 0.6rem; }

  dialog { border: 1px solid var(--border); border-radius: 12px; background: var(--surface); color: var(--text); box-shadow: var(--pop-shadow); padding: 1.25rem; width: min(30rem, calc(100vw - 2rem)); }
  dialog::backdrop { background: rgba(10, 14, 10, 0.45); }
  dialog p { margin: 0 0 0.75rem; }
  dialog label { display: block; margin: 0.6rem 0; }
  dialog [hidden] { display: none; }
  dialog input[type="text"], dialog input[type="search"], dialog input[type="number"], dialog input[type="url"], dialog select { width: 100%; margin-top: 0.25rem; }
  .dlg-msg { color: var(--bad); }
  .dlg-msg:empty { display: none; }
  .dlg-head { display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.9rem; }
  .dlg-head h2 { margin: 0; font-size: 1.1rem; }
  .dlg-head button { margin-left: auto; border: 0; background: transparent; font-size: 1.3rem; line-height: 1; padding: 0.2rem 0.45rem; }
  #install-dlg { width: min(38rem, calc(100vw - 2rem)); }
  #search-form { display: flex; gap: 0.4rem; }
  #search-q { flex: 1; min-width: 0; }
  #search-msg { margin: 0.6rem 0 0; }
  #search-msg:empty { display: none; }
  .results { list-style: none; padding: 0; margin: 0.6rem 0 0; max-height: min(24rem, 55vh); overflow: auto; display: flex; flex-direction: column; gap: 0.4rem; }
  .results:empty { display: none; }
  .results button { display: block; width: 100%; text-align: left; padding: 0.55rem 0.75rem; }
  .results button.on { outline: 2px solid var(--accent); }
  .upd-check { padding: 0.5rem 0.7rem; background: var(--surface-2); border-left: 3px solid var(--idle); border-radius: 0 6px 6px 0; }
  .ver-info { display: grid; grid-template-columns: auto 1fr; gap: 0.3rem 0.8rem; margin: 0 0 0.9rem; padding: 0.6rem 0.75rem; background: var(--surface-2); border-radius: 8px; font-size: 0.9rem; }
  .ver-info dt { color: var(--muted); }
  .ver-info dd { margin: 0; overflow-wrap: anywhere; }
  .ver-info code { font: 0.82rem ui-monospace, SFMono-Regular, Menlo, Consolas, "DejaVu Sans Mono", monospace; }
  .upd-source { display: flex; flex-wrap: wrap; gap: 0 1.2rem; }
  .upd-source label { margin: 0.3rem 0; }
  .upd-check.warn { border-left-color: var(--warn); color: var(--warn); }
  .row-actions { display: flex; gap: 0.5rem; justify-content: flex-end; margin-top: 1rem; }

  .toasts { position: fixed; right: 1rem; bottom: 1rem; z-index: 20; display: flex; flex-direction: column; gap: 0.5rem; width: min(24rem, calc(100vw - 2rem)); pointer-events: none; }
  .toast { pointer-events: auto; display: grid; grid-template-columns: auto 1fr auto; gap: 0.2rem 0.6rem; align-items: start; background: var(--surface); border: 1px solid var(--border); border-left: 4px solid var(--idle); border-radius: 8px; box-shadow: var(--pop-shadow); padding: 0.6rem 0.5rem 0.6rem 0.75rem; animation: toast-in 0.18s ease-out; }
  .toast[data-kind="ok"] { border-left-color: var(--ok); }
  .toast[data-kind="error"] { border-left-color: var(--bad); }
  .toast[data-kind="busy"] { border-left-color: var(--accent); }
  .toast-icon { width: 1rem; height: 1rem; margin-top: 0.15rem; border-radius: 50%; display: grid; place-items: center; font-size: 0.7rem; font-weight: 700; color: #fff; }
  .toast[data-kind="ok"] .toast-icon { background: var(--ok); }
  .toast[data-kind="ok"] .toast-icon::before { content: "\2713"; }
  .toast[data-kind="error"] .toast-icon { background: var(--bad); }
  .toast[data-kind="error"] .toast-icon::before { content: "!"; }
  .toast[data-kind="busy"] .toast-icon { border: 2px solid var(--border-strong); border-top-color: var(--accent); animation: spin 0.7s linear infinite; }
  .toast-body { white-space: pre-wrap; overflow-wrap: anywhere; font-size: 0.88rem; max-height: 7.5em; overflow: hidden; }
  .toast.open .toast-body { max-height: 40vh; overflow: auto; }
  .toast-x { border: 0; background: transparent; padding: 0 0.35rem; font-size: 1.1rem; line-height: 1.2; color: var(--muted); }
  .toast-more { grid-column: 2; justify-self: start; border: 0; background: transparent; padding: 0; font-size: 0.8rem; color: var(--accent); font-weight: 600; }
  .toast-more[hidden] { display: none; }
  @keyframes toast-in { from { opacity: 0; transform: translateY(0.5rem); } }

  @media (prefers-reduced-motion: reduce) {
    .badge.starting::before, .toast { animation: none; }
  }

  /* Wide screens: servers on the left, the console beside them so a log is
     always in view. */
  @media (min-width: 75rem) {
    main { max-width: 112rem; grid-template-columns: minmax(0, 1fr) minmax(28rem, 38rem); align-items: start; }
    .console-panel { position: sticky; top: 1rem; height: calc(100vh - 2rem); }
    #out { max-height: none; }
  }

  /* Phones: each server becomes a card, and controls get finger-sized.
     Inputs use 16px so iOS does not zoom in on focus. */
  @media (max-width: 40rem) {
    main { padding: 0.75rem; gap: 1.1rem; }
    header { padding: 0.6rem 0.75rem; }
    .header-end { margin-left: 0; width: 100%; }
    .menu summary { min-height: 2.5rem; display: flex; align-items: center; }
    .menu-panel button { min-height: 2.75rem; }
    #page-menu .menu-panel { right: 0; }
    #svc-menu .menu-panel { right: auto; left: 0; }
    button, .pick-btn { min-height: 2.75rem; }
    input, select { font-size: 16px; min-height: 2.75rem; }

    .table-card { background: none; border: 0; box-shadow: none; overflow: visible; }
    #packs table, #packs tbody, #packs tr, #packs td { display: block; }
    #packs thead { display: none; }
    .group > summary { min-height: 2.75rem; margin: 0.3rem 0; padding-right: 1rem; }
    #packs tr { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); box-shadow: var(--shadow); margin-bottom: 0.65rem; padding: 0.65rem 0.8rem; }
    #packs tbody tr:hover { background: var(--surface); }
    #packs td { border: 0; padding: 0; }
    #packs td[data-label="Status"] { display: inline-block; margin: 0.45rem 0.8rem 0 0; }
    #packs td.stat { display: inline-block; margin: 0.45rem 0.8rem 0 0; font-size: 0.88rem; }
    #packs td.stat::before { content: attr(data-label) " "; color: var(--muted); font-size: 0.75rem; }
    #packs td.actions { width: auto; padding-top: 0.65rem; }
    .actions-inner { display: grid; grid-template-columns: 1fr 1fr 3.25rem; }

    .console-form .pick { flex: 1 1 100%; }
    .console-form .pick-btn { width: 100%; }
    .console-form input { min-width: 0; }
    .pick-menu button, .pop button { padding: 0.65rem 0.75rem; }
    #out { min-height: 12rem; max-height: 60vh; font-size: 12px; padding: 0.6rem; }
    .props-menu { min-width: 0; width: calc(100vw - 1.5rem); }
    .props-menu .props-list { max-height: 50vh; }
    .props-menu .props-val { max-width: 45%; }
    .row-actions button { flex: 1; }
    .toasts { right: 0.75rem; left: 0.75rem; bottom: 0.75rem; width: auto; }
  }
</style>
</head>
<body>
<header>
  <h1><img src="/favicon.svg" alt="" width="22" height="22"> modman</h1>
  <div class="header-end">
    <span class="pill view-pill" title="This sign-in can watch the servers but not change them">View only</span>
    <span class="pill" title="The boot service starts and stops the Active servers together"><span id="svc-dot" class="dot" role="img" aria-label="unknown"></span>Service <b id="svc-text">unknown</b></span>
    <span class="pill" title="Whether the boot service starts the Active servers when this machine boots"><span id="boot-dot" class="dot" role="img" aria-label="unknown"></span>Start at boot <b id="boot-text">unknown</b></span>
    <details class="menu" id="svc-menu">
      <summary>Service</summary>
      <div class="menu-panel">
        <button type="button" id="svc-start">Start service</button>
        <button type="button" id="svc-stop">Stop service</button>
        <button type="button" id="svc-restart">Restart service</button>
        <hr>
        <button type="button" id="svc-enable">Start at boot</button>
        <button type="button" id="svc-disable">Don't start at boot</button>
      </div>
    </details>
    <details class="menu" id="page-menu">
      <summary>Menu</summary>
      <div class="menu-panel">
        <button type="button" id="unlock" title="Cancel pending requests and re-enable every greyed-out control">Unlock page</button>
        <button type="button" id="logout">Sign out</button>
      </div>
    </details>
  </div>
</header>
<main>
  <section class="servers" aria-labelledby="servers-title">
    <div class="section-head">
      <h2 id="servers-title">Servers</h2>
      <button type="button" id="install-open" class="primary">+ Install modpack</button>
    </div>
    <div id="packs"></div>
  </section>
  <section class="console-panel card" aria-labelledby="console-title">
    <div class="console-head">
      <h2 id="console-title">Console</h2>
      <span id="console-spin" class="spinner" hidden role="status" aria-label="Loading"></span>
    </div>
    <form id="console-form" class="console-form">
      <div class="pick">
        <select id="console-pack" aria-label="Server" hidden>
          <option value="">Actions</option>
        </select>
        <button type="button" id="console-pick-btn" class="pick-btn" aria-haspopup="listbox" aria-expanded="false">Actions</button>
        <div id="console-pick-menu" class="pick-menu" role="listbox" aria-label="Server" hidden></div>
      </div>
      <input id="console-cmd" type="text" maxlength="300" placeholder="Command (↑ for history)" autocomplete="off" aria-label="Command">
      <button type="submit" class="primary">Send</button>
    </form>
    <p id="console-msg" class="muted"></p>
    <div class="term">
      <pre id="out" tabindex="0" aria-label="Server log" data-empty="No server selected. Press Log on a server, or choose a running one above."></pre>
      <button type="button" id="jump" class="jump" hidden>&#8595; Latest</button>
    </div>
  </section>
  <script>
  (function () {
    try {
      var saved = JSON.parse(localStorage.getItem("modman-page") || "");
      if (!saved) return;
      if (saved.packsHtml) document.getElementById("packs").innerHTML = saved.packsHtml;
      if (typeof saved.consoleText === "string") document.getElementById("out").textContent = saved.consoleText;
      var svc = saved.service || {};
      var active = document.getElementById("svc-dot");
      var boot = document.getElementById("boot-dot");
      if (active && svc.active) active.classList.toggle("on", svc.active === "active");
      if (boot && svc.enabled) boot.classList.toggle("on", svc.enabled === "enabled");
    } catch (err) {}
  })();
  </script>
</main>
<dialog id="dlg"></dialog>
<dialog id="install-dlg" aria-labelledby="install-title">
  <div class="dlg-head">
    <h2 id="install-title">Install a modpack</h2>
    <button type="button" id="install-close" aria-label="Close">&times;</button>
  </div>
  <form id="search-form">
    <input id="search-q" type="search" placeholder="Search CurseForge" aria-label="Search CurseForge" required>
    <button type="submit" class="primary">Search</button>
  </form>
  <p id="search-msg" class="muted"></p>
  <ul id="search-results" class="results"></ul>
</dialog>
<div id="row-menu" class="pop" role="menu" hidden></div>
<div id="props-menu" class="pop props-menu" role="menu" aria-label="server.properties" hidden></div>
<div id="toasts" class="toasts" aria-live="polite"></div>
<script>
const out = document.getElementById("out");
const dlg = document.getElementById("dlg");
let hold = false;
let rowBusy = false;
let packsBusy = false;
let packsTicket = 0;
let packsAsked = 0;
let logBusy = false;
let packs = [];
let searchAbort = null;
let consoleName = null;
let actionText = "";
let consoleOffset = 0;
let consoleBusy = false;
let consoleTicket = 0;
let consoleText = "";
let packsLoaded = false;
let packsNote = null;
const jumpBtn = document.getElementById("jump");

function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  }[c]));
}

// How long the page waits for each endpoint before giving up, in seconds. Each
// is the server's own modman timeout plus a margin, so a request is only
// dropped once the server would have answered. A stalled connection then
// rejects instead of leaving the page greyed out.
const API_TIMEOUTS = {
  "/api/run": 180, "/api/packs": 120, "/api/log": 30, "/api/command": 30,
  "/api/search": 60, "/api/install": 3600, "/api/update": 3600,
  "/api/props": 30, "/api/update-check": 90,
};
const API_MARGIN = 15;

class ApiTimeout extends Error {
  constructor() {
    super("The server did not answer in time.");
    this.name = "ApiTimeout";
  }
}

// Requests in flight, so clearBusy() can cancel them.
const pending = new Set();

async function api(path, body, signal) {
  const ctrl = new AbortController();
  pending.add(ctrl);
  const secs = (API_TIMEOUTS[path.split("?")[0]] || 30) + API_MARGIN;
  let timedOut = false;
  const timer = setTimeout(() => { timedOut = true; ctrl.abort(); }, secs * 1000);
  const onAbort = () => ctrl.abort();
  if (signal) {
    if (signal.aborted) ctrl.abort();
    else signal.addEventListener("abort", onAbort, {once: true});
  }
  const opts = {headers: {}, signal: ctrl.signal};
  if (body !== undefined) {
    opts.method = "POST";
    opts.headers["Content-Type"] = "application/json";
    // The server answers a resend with this id from the first try's reply.
    opts.headers["X-Request-Id"] = Array.from(crypto.getRandomValues(new Uint8Array(16)),
      (b) => b.toString(16).padStart(2, "0")).join("");
    opts.body = JSON.stringify(body);
  }
  try {
    // A connection can drop between requests, such as in the playit tunnel,
    // and fail the next request with a reset. Try once more before giving up.
    for (let attempt = 0; ; attempt++) {
      try {
        const res = await fetch(path, opts);
        if (res.status === 401) {
          location.href = "/login";
          return null;
        }
        const text = await res.text();
        try { return JSON.parse(text); }
        catch { return {ok: false, output: text}; }
      } catch (err) {
        if (timedOut) throw new ApiTimeout();
        if (attempt > 0 || ctrl.signal.aborted) throw err;
        await new Promise((resolve) => setTimeout(resolve, 300));
      }
    }
  } finally {
    pending.delete(ctrl);
    clearTimeout(timer);
    if (signal) signal.removeEventListener("abort", onAbort);
  }
}

// Cancels every request the page is waiting on and re-enables everything a
// busy state greyed out. The server may still finish an action it already
// started; the next list poll shows the result.
function clearBusy() {
  for (const ctrl of pending) ctrl.abort();
  pending.clear();
  if (searchAbort) searchAbort.abort();
  searchAbort = null;
  hold = false;
  packsBusy = false;
  packsTicket++;
  logBusy = false;
  consoleTicket++;
  closeProps();
  closeRowMenu();
  setServerBusy(null, false);
  setConsoleBusy(false);
  setCommandEnabled(!!consoleName && runningPacks().some((p) => p.name === consoleName));
}

// Puts fixed text in the console, such as a stopped server's last log, and
// stops following a server.
function showStatic(text) {
  actionText = text || "";
  consoleName = "";
  consoleOffset = 0;
  const sel = document.getElementById("console-pack");
  if ([...sel.options].some((opt) => opt.value === "")) sel.value = "";
  syncPick();
  setConsoleText(actionText);
  if (!consoleBusy) {
    document.getElementById("console-cmd").disabled = true;
    document.querySelector("#console-form button[type=submit]").disabled = true;
  }
  saveState();
}

// Minecraft log lines carry their level as "[thread/LEVEL]". Lines after an
// error that do not start a new entry, such as a stack trace, keep its color.
const LOG_LEVEL_RE = /\/(WARN|WARNING|ERROR|FATAL|SEVERE)\]/;

function setConsoleText(text) {
  consoleText = text;
  if (!text) {
    out.replaceChildren();
    jumpBtn.hidden = true;
    return;
  }
  const frag = document.createDocumentFragment();
  const lines = text.split("\n");
  let inError = false;
  lines.forEach((line, i) => {
    const level = LOG_LEVEL_RE.exec(line);
    let cls = "";
    if (level) {
      cls = level[1].startsWith("WARN") ? "lw" : "le";
      inError = cls === "le";
    } else if (line.startsWith("[")) {
      inError = false;
    } else if (inError && line) {
      cls = "le";
    }
    const span = document.createElement("span");
    if (cls) span.className = cls;
    span.textContent = i < lines.length - 1 ? line + "\n" : line;
    frag.appendChild(span);
  });
  out.replaceChildren(frag);
}

function consoleAtBottom() {
  return out.scrollHeight - out.scrollTop - out.clientHeight < 48;
}

out.addEventListener("scroll", () => {
  if (consoleAtBottom()) jumpBtn.hidden = true;
});
jumpBtn.onclick = () => {
  out.scrollTop = out.scrollHeight;
  jumpBtn.hidden = true;
};

// Action results show as notes in the corner, so the console keeps its log.
// A busy note stays until updated. A done note fades after a while unless
// the pointer is on it, and an error stays until closed.
const toastBox = document.getElementById("toasts");

function toast(text, kind) {
  const el = document.createElement("div");
  el.className = "toast";
  const icon = document.createElement("span");
  icon.className = "toast-icon";
  icon.setAttribute("aria-hidden", "true");
  const body = document.createElement("div");
  body.className = "toast-body";
  const x = document.createElement("button");
  x.type = "button";
  x.className = "toast-x";
  x.setAttribute("aria-label", "Dismiss");
  x.textContent = "×";
  const more = document.createElement("button");
  more.type = "button";
  more.className = "toast-more";
  el.append(icon, body, x, more);
  let timer = 0;
  let current = kind;
  const close = () => {
    clearTimeout(timer);
    el.remove();
  };
  const arm = () => {
    clearTimeout(timer);
    if (current === "ok") timer = setTimeout(close, 7000);
  };
  const update = (nextText, nextKind) => {
    current = nextKind;
    el.dataset.kind = nextKind;
    el.setAttribute("role", nextKind === "error" ? "alert" : "status");
    body.textContent = String(nextText || "").trim();
    const long = body.textContent.split("\n").length > 5 || body.textContent.length > 280;
    more.hidden = !long;
    el.classList.remove("open");
    more.textContent = "Show all";
    arm();
  };
  x.onclick = close;
  more.onclick = () => {
    const open = el.classList.toggle("open");
    more.textContent = open ? "Show less" : "Show all";
  };
  el.addEventListener("pointerenter", () => clearTimeout(timer));
  el.addEventListener("pointerleave", arm);
  update(text, kind);
  toastBox.appendChild(el);
  // Keep the corner tidy: drop the oldest finished notes past four.
  const done = [...toastBox.children].filter((t) => t.dataset.kind !== "busy");
  while (toastBox.children.length > 4 && done.length) done.shift().remove();
  return {update, close, isOpen: () => el.isConnected};
}

function setServerBusy(name, on) {
  rowBusy = on;
  if (on) closeRowMenu();
  document.querySelectorAll("#packs tr").forEach((tr) => {
    const mine = on && tr.dataset.name === name;
    tr.classList.toggle("busy", mine);
    for (const el of tr.querySelectorAll("button, input")) el.disabled = on;
    const bar = tr.querySelector(".loadbar");
    if (bar) bar.hidden = !mine;
  });
}

async function finishServer(name, label, request) {
  if (rowBusy) return;
  hold = true;
  if (name) setServerBusy(name, true);
  else rowBusy = true;
  const note = toast(label || "Working…", "busy");
  let reached = false;
  try {
    const data = await request(note);
    reached = true;
    if (!data) {
      note.close();
      return;
    }
    note.update(data.output || (data.ok ? "Done." : "Failed."), data.ok === false ? "error" : "ok");
    return data;
  } catch (err) {
    note.update(err instanceof ApiTimeout
      ? "The server did not answer in time. Check the server list for the result."
      : err && err.name === "AbortError"
        ? "Cancelled. The server may still finish the action; check the server list."
        : "The page could not reach the server.", "error");
  } finally {
    // Keep the row busy until the list shows the result of the action. If the
    // server could not be reached, release the row now rather than waiting on
    // a list request that will likely stall the same way.
    hold = false;
    if (reached) await loadPacks(true);
    else loadPacks(true);
    if (name) setServerBusy(name, false);
    else rowBusy = false;
  }
}

// Steps a webpage update reports to /api/update-progress.
const UPDATE_STEPS = {
  start: "Preparing", check: "Checking CurseForge", stop: "Stopping the server",
  download: "Downloading", unpack: "Unpacking", install: "Replacing files",
};

// Run an update request while polling its progress into the row's bar and
// the busy note, and its output into the console's Actions view. A step
// without a percent keeps the moving bar.
async function trackUpdate(name, note, request) {
  let live = true;
  let stepLine = "Starting…";
  let output = "";
  // Shows the update in the Actions view. Someone who switched the console
  // to a server meanwhile keeps that view; the text waits in Actions.
  const showOutput = () => {
    actionText = `Updating ${name}: ${stepLine}\n\n${output}`;
    if (consoleName) return;
    const stick = consoleAtBottom();
    setConsoleText(actionText);
    if (stick) out.scrollTop = out.scrollHeight;
  };
  showStatic(`Updating ${name}: ${stepLine}\n\n`);
  const bar = () => {
    const tr = [...document.querySelectorAll("#packs tr")].find((row) => row.dataset.name === name);
    return tr && tr.querySelector(".loadbar");
  };
  const show = (step, pct) => {
    const known = Number.isInteger(pct);
    const el = bar();
    if (el) {
      el.classList.toggle("known", known);
      el.style.setProperty("--pct", known ? `${pct}%` : "0%");
      if (known) el.setAttribute("aria-valuenow", String(pct));
      else el.removeAttribute("aria-valuenow");
    }
    stepLine = `${UPDATE_STEPS[step] || "Working"}${known ? ` ${pct}%` : "…"}`;
    note.update(`Updating ${name}: ${stepLine}`, "busy");
    showOutput();
  };
  (async () => {
    while (live) {
      await new Promise((resolve) => setTimeout(resolve, 1000));
      if (!live) return;
      let data, log;
      try {
        [data, log] = await Promise.all([
          api(`/api/update-progress?name=${encodeURIComponent(name)}`),
          api(`/api/update-log?name=${encodeURIComponent(name)}`),
        ]);
      } catch {
        continue;
      }
      // The update may have finished while this poll was out.
      if (!live) return;
      if (log && typeof log.text === "string") output = log.text;
      if (data && data.step) show(data.step, data.percent);
      else showOutput();
    }
  })();
  try {
    const data = await request();
    if (data) {
      // The reply holds the whole output, including the last lines.
      stepLine = data.ok === false ? "Failed." : "Done.";
      output = data.output || output;
      live = false;
      showOutput();
      saveState();
    }
    return data;
  } finally {
    live = false;
    const el = bar();
    if (el) {
      el.classList.remove("known");
      el.removeAttribute("aria-valuenow");
    }
  }
}

async function run(payload, label) {
  const data = await finishServer(payload.name || "", label, () => api("/api/run", payload));
  if (data && data.eula && payload.name) askEula(payload, label);
}

function askEula(payload, label) {
  const url = "https://aka.ms/MinecraftEULA";
  ask(`<form>
    <p><strong>${esc(payload.name)}</strong> needs the Minecraft End User License Agreement (EULA) accepted before it can start.</p>
    <p>Read the full terms: <a href="${url}" target="_blank" rel="noopener noreferrer">${url}</a></p>
    <p>By choosing I agree, you are indicating your agreement to the Minecraft EULA, and <code>eula=true</code> is written to the server's <code>eula.txt</code>.</p>
    <div class="row-actions"><button type="button" data-cancel>Cancel</button><button type="submit">I agree</button></div>
  </form>`, () => {
    dlg.close();
    run({...payload, eula: "agree"}, label);
  });
}

function ask(html, onok) {
  dlg.innerHTML = html;
  dlg.showModal();
  dlg.querySelector("[data-cancel]").onclick = () => dlg.close();
  dlg.querySelector("form").onsubmit = (ev) => {
    ev.preventDefault();
    const fields = Object.fromEntries(new FormData(ev.target).entries());
    onok(fields);
  };
}

function service(action, label, question) {
  if (question) {
    ask(
      `<form><p>${esc(question)}</p><div class="row-actions"><button type="button" data-cancel>Cancel</button><button type="submit">Continue</button></div></form>`,
      () => { dlg.close(); run({cmd: "service", action}, label); }
    );
    return;
  }
  run({cmd: "service", action}, label);
}

document.getElementById("svc-start").onclick = () => service("start", "Starting the boot service…");
document.getElementById("svc-stop").onclick = () => service("stop", "Stopping the boot service…",
  "Stop every Active server and the boot service?");
document.getElementById("svc-restart").onclick = () => service("restart", "Restarting the boot service…",
  "Restart every Active server through the boot service?");
document.getElementById("svc-enable").onclick = () => service("enable", "Turning on start at boot…");
document.getElementById("svc-disable").onclick = () => service("disable", "Turning off start at boot…");
document.getElementById("logout").onclick = async () => {
  await fetch("/logout", {method: "POST"});
  location.href = "/login";
};
document.addEventListener("click", (ev) => {
  for (const menu of document.querySelectorAll("details.menu[open]")) {
    if (menu.contains(ev.target)) {
      if (ev.target.closest("button")) menu.open = false;
      continue;
    }
    menu.open = false;
  }
});

// Java the pack needs is a minimum, except before Minecraft 1.17, which needs Java 8 exactly.
function javaWarning(pack) {
  const have = Number(pack.java);
  const need = Number(pack.java_need);
  if (!Number.isFinite(have) || !Number.isFinite(need)) return "";
  if (need === 8 ? have !== 8 : have < need) return `This pack needs Java ${need}, but start.sh runs Java ${have}`;
  return "";
}

function javaText(pack) {
  return javaWarning(pack) ? `${pack.java} (needs ${pack.java_need})` : pack.java;
}

// A server is active when it is up, or enabled so it starts with the others.
function isActive(pack) {
  return pack.indexed || (pack.status && pack.status !== "stopped");
}

function portWarning(pack) {
  if (!pack.port || pack.port === "-" || !isActive(pack)) return "";
  const others = packs.filter((p) => p.name !== pack.name && p.port === pack.port && isActive(p));
  if (!others.length) return "";
  const names = others.map((p) => `${p.name} (${p.status === "stopped" ? "enabled" : p.status})`);
  return `Port ${pack.port} is also used by ${names.join(", ")}`;
}

// The one action a row shows as a button. The rest are in its ⋯ menu.
function primaryAction(pack) {
  if (!pack.indexed) return {act: "enable", label: "Enable", cls: "primary"};
  if (pack.status === "running" || pack.status === "starting") return {act: "stop", label: "Stop", cls: ""};
  if (pack.status === "error") return {act: "restart", label: "Restart", cls: "primary"};
  return {act: "start", label: "Start", cls: "primary"};
}

function rowMenuItems(pack) {
  const items = [];
  if (pack.indexed) {
    const main = primaryAction(pack).act;
    const up = pack.status && pack.status !== "stopped";
    if (up && main !== "restart") items.push(["restart", "Restart"]);
    if (up && main !== "stop") items.push(["stop", "Stop"]);
  }
  items.push(["props", "Properties…"], ["port", "Change port…"], ["version", "Version…"], ["update", "Update…"]);
  if (pack.indexed) items.push(["disable", "Disable (move to Installed)"]);
  items.push("-", ["uninstall", "Uninstall…"]);
  return items;
}

function metaText(pack) {
  const port = pack.port && pack.port !== "-" ? pack.port : "none";
  return `Java ${javaText(pack)} · Port ${port}` + (pack.version ? ` · Version ${pack.version}` : "");
}

function row(pack) {
  const p = primaryAction(pack);
  // Installed packs are not started from the page, so they have no status or usage columns.
  const usage = pack.indexed
    ? `<td data-label="Status"><span class="badge ${esc(pack.status)}" data-badge>${esc(pack.status)}</span></td>
    <td class="num stat" data-cpu data-label="CPU">${esc(pack.cpu)}</td>
    <td class="num stat" data-ram data-label="RAM">${esc(pack.ram)}</td>
    <td class="num stat" data-uptime data-label="Up">${esc(pack.uptime)}</td>`
    : "";
  return `<tr data-name="${esc(pack.name)}" data-indexed="${pack.indexed ? 1 : 0}">
    <td data-pack-name>
      <div class="name">${esc(pack.name)}</div>
      <div class="meta" data-meta>${esc(metaText(pack))}</div>
      <div class="warn-text" data-java-warn>${esc(javaWarning(pack))}</div>
      <div class="warn-text" data-port-warn>${esc(portWarning(pack))}</div>
    </td>
    ${usage}
    <td class="actions"><div class="actions-inner">
      <button type="button" data-act="${p.act}" data-primary class="${p.cls}">${p.label}</button>
      <button type="button" data-act="log">Log</button>
      <button type="button" class="more" data-act="more" aria-haspopup="menu" aria-expanded="false" aria-label="More actions for ${esc(pack.name)}" title="More actions">&#8943;</button>
    </div><span class="loadbar" hidden role="progressbar" aria-label="Working" aria-valuemin="0" aria-valuemax="100"><span></span></span></td>
  </tr>`;
}

function table(title, rows, usage) {
  if (!rows.length) return "";
  const usageHead = usage ? "<th>Status</th><th>CPU</th><th>RAM</th><th>Uptime</th>" : "";
  return `<div class="card table-card"><table>
    <thead><tr><th>Server</th>${usageHead}<th><span hidden>Actions</span></th></tr></thead>
    <tbody>${rows.map(row).join("")}</tbody></table></div>`;
}

// The Installed list folds away. It starts folded on phones, where it is long,
// and after that keeps whatever this browser last chose.
const INSTALLED_KEY = "modman-installed-open";

function installedOpen() {
  try {
    const saved = localStorage.getItem(INSTALLED_KEY);
    if (saved === "1" || saved === "0") return saved === "1";
  } catch (err) {}
  return !matchMedia("(max-width: 40rem)").matches;
}

function installedGroup(rows) {
  if (!rows.length) return "";
  return `<details class="group" data-group="installed"${installedOpen() ? " open" : ""}>
    <summary class="group-title">Installed <span class="count">${rows.length}</span></summary>
    ${table("Installed", rows, false)}
  </details>`;
}

// toggle does not bubble, so listen while it travels down.
document.getElementById("packs").addEventListener("toggle", (ev) => {
  if (!ev.target.matches || !ev.target.matches('details[data-group="installed"]')) return;
  try { localStorage.setItem(INSTALLED_KEY, ev.target.open ? "1" : "0"); } catch (err) {}
  if (!ev.target.open) closeRowMenu();
  saveState();
}, true);

function paintDot(id, good, label) {
  const el = document.getElementById(id);
  const text = label || "unknown";
  el.classList.toggle("on", !!good);
  el.title = text;
  el.setAttribute("aria-label", text);
  const word = document.getElementById(id.replace("-dot", "-text"));
  if (word) word.textContent = text;
}

function render() {
  closeRowMenu();
  const indexed = packs.filter((p) => p.indexed);
  const other = packs.filter((p) => !p.indexed);
  const box = document.getElementById("packs");
  if (!packs.length) {
    box.innerHTML = `<div class="card empty">${packsLoaded
      ? "No modpacks yet. Use Install modpack to add one."
      : "Loading servers…"}</div>`;
    return;
  }
  box.innerHTML = (indexed.length ? `<h3 class="group-title">Active <span class="count">${indexed.length}</span></h3>` : "")
    + table("Active", indexed, true) + installedGroup(other);
  // A properties menu open on a row follows the redrawn row's ⋯ button.
  if (!propsMenu.hidden && propsAnchor && !propsAnchor.isConnected) {
    propsAnchor = moreButton(propsMenu.dataset.name);
    if (!propsAnchor) closeProps();
    else placeMenu(propsMenu, propsAnchor);
  }
}

function moreButton(name) {
  const tr = document.querySelector(`#packs tr[data-name="${CSS.escape(name || "")}"]`);
  return tr ? tr.querySelector('[data-act="more"]') : null;
}

function saveState() {
  try {
    if (!packsLoaded && !packs.length) return;
    const stick = consoleAtBottom();
    localStorage.setItem("modman-page", JSON.stringify({
      packs,
      service: {
        active: document.getElementById("svc-dot").getAttribute("aria-label"),
        enabled: document.getElementById("boot-dot").getAttribute("aria-label")
      },
      consoleName,
      consoleOffset,
      actionText,
      consoleText,
      packsHtml: document.getElementById("packs").innerHTML,
      consoleStick: stick,
      consoleScroll: out.scrollTop
    }));
  } catch (err) {}
}

function restoreState() {
  let saved;
  try {
    saved = JSON.parse(localStorage.getItem("modman-page") || "");
  } catch (err) {
    return false;
  }
  if (!saved || !Array.isArray(saved.packs)) return false;
  packs = saved.packs.filter((p) => p && typeof p.name === "string");
  actionText = typeof saved.actionText === "string" ? saved.actionText : "";
  consoleOffset = Number.isFinite(saved.consoleOffset) && saved.consoleOffset >= 0 ? saved.consoleOffset : 0;
  consoleName = saved.consoleName == null ? null : String(saved.consoleName);
  // Rebuild from the saved list instead of keeping the saved table, which may
  // come from an older page whose rows lack newer buttons.
  render();
  const list = runningPacks();
  fillPicker(list);
  const follow = !!(consoleName && list.some((p) => p.name === consoleName));
  document.getElementById("console-pack").value = follow ? consoleName : "";
  syncPick();
  setCommandEnabled(follow);
  const svc = saved.service || {};
  if (typeof svc.active === "string") paintDot("svc-dot", svc.active === "active", svc.active);
  if (typeof svc.enabled === "string") paintDot("boot-dot", svc.enabled === "enabled", svc.enabled);
  setConsoleText(typeof saved.consoleText === "string" ? saved.consoleText : actionText);
  if (saved.consoleStick) out.scrollTop = out.scrollHeight;
  else if (Number.isFinite(saved.consoleScroll)) out.scrollTop = saved.consoleScroll;
  return true;
}

function setText(el, text) {
  if (el && el.textContent !== text) el.textContent = text;
}

function updateVisibleStatus() {
  for (const pack of packs) {
    const tr = document.querySelector(`#packs tr[data-name="${CSS.escape(pack.name)}"]`);
    if (!tr) continue;
    const badge = tr.querySelector("[data-badge]");
    if (badge) {
      const cls = `badge ${pack.status}`;
      if (badge.className !== cls) badge.className = cls;
      setText(badge, pack.status);
    }
    setText(tr.querySelector("[data-meta]"), metaText(pack));
    setText(tr.querySelector("[data-java-warn]"), javaWarning(pack));
    setText(tr.querySelector("[data-port-warn]"), portWarning(pack));
    for (const [attr, text] of [["data-cpu", pack.cpu], ["data-ram", pack.ram], ["data-uptime", pack.uptime]]) {
      setText(tr.querySelector(`[${attr}]`), text);
    }
    const main = tr.querySelector("[data-primary]");
    const p = primaryAction(pack);
    if (main && main.dataset.act !== p.act) {
      main.dataset.act = p.act;
      main.textContent = p.label;
      main.className = p.cls;
    }
  }
}

function syncPacks() {
  const rows = [...document.querySelectorAll("#packs tr[data-name]")];
  const same = packs.length > 0 && rows.length === packs.length && rows.every((tr, i) => {
    const pack = packs[i];
    return tr.dataset.name === pack.name && tr.dataset.indexed === (pack.indexed ? "1" : "0");
  });
  if (!same) render();
  else updateVisibleStatus();
}

// Servers the console can follow: up and booting, or up and done booting.
function runningPacks() {
  return packs.filter((p) => p.status === "running" || p.status === "starting");
}

function setConsoleBusy(on) {
  consoleBusy = on;
  document.getElementById("console-spin").hidden = !on;
  for (const el of document.querySelectorAll("#console-form select, #console-form input, #console-form button")) {
    el.disabled = on;
  }
  if (on) closePick();
}

// The console picker is drawn by the page. The hidden <select> holds the value
// and options. A native dropdown popup can show as a blank white box when its
// options change or it is disabled while open, so it is not used.
const pickBtn = document.getElementById("console-pick-btn");
const pickMenu = document.getElementById("console-pick-menu");

function pickOpen() {
  return !pickMenu.hidden;
}

function fillPickMenu() {
  const sel = document.getElementById("console-pack");
  const focused = document.activeElement && pickMenu.contains(document.activeElement)
    ? document.activeElement.dataset.value : null;
  pickMenu.replaceChildren(...[...sel.options].map((opt) => {
    const b = document.createElement("button");
    b.type = "button";
    b.setAttribute("role", "option");
    b.dataset.value = opt.value;
    b.textContent = opt.textContent;
    b.setAttribute("aria-selected", String(opt.value === sel.value));
    return b;
  }));
  if (focused != null) {
    const again = [...pickMenu.children].find((b) => b.dataset.value === focused);
    if (again) again.focus();
  }
}

// Show the selected option on the button, and refresh the menu if it is open.
function syncPick() {
  const sel = document.getElementById("console-pack");
  const opt = sel.options[sel.selectedIndex];
  const label = opt ? opt.textContent : "Actions";
  if (pickBtn.textContent !== label) pickBtn.textContent = label;
  if (pickOpen()) fillPickMenu();
}

function openPick() {
  if (pickBtn.disabled) return;
  fillPickMenu();
  pickMenu.hidden = false;
  pickBtn.setAttribute("aria-expanded", "true");
  const current = pickMenu.querySelector('[aria-selected="true"]') || pickMenu.firstElementChild;
  if (current) current.focus();
}

function closePick(refocus) {
  if (!pickOpen()) return;
  pickMenu.hidden = true;
  pickBtn.setAttribute("aria-expanded", "false");
  if (refocus) pickBtn.focus();
}

pickBtn.onclick = () => (pickOpen() ? closePick(true) : openPick());

pickMenu.onclick = (ev) => {
  const b = ev.target.closest("button");
  if (!b) return;
  const sel = document.getElementById("console-pack");
  closePick(true);
  if (b.dataset.value === sel.value) return;
  sel.value = b.dataset.value;
  syncPick();
  sel.dispatchEvent(new Event("change"));
};

pickMenu.onkeydown = (ev) => {
  const items = [...pickMenu.children];
  const i = items.indexOf(document.activeElement);
  if (ev.key === "ArrowDown" || ev.key === "ArrowUp") {
    ev.preventDefault();
    const next = items[(i + (ev.key === "ArrowDown" ? 1 : items.length - 1)) % items.length];
    if (next) next.focus();
  } else if (ev.key === "Escape") {
    ev.preventDefault();
    closePick(true);
  } else if (ev.key === "Tab") {
    closePick(false);
  }
};

document.addEventListener("pointerdown", (ev) => {
  if (pickOpen() && !ev.target.closest(".pick")) closePick(false);
});

function consoleLabel(pack) {
  return pack.status === "starting" ? `${pack.name} (starting)` : pack.name;
}

// Update the options in place, only when the names or labels changed.
function fillPicker(list) {
  const sel = document.getElementById("console-pack");
  const wanted = [["", "Actions"], ...list.map((p) => [p.name, consoleLabel(p)])];
  const same = wanted.length === sel.options.length &&
    wanted.every(([value, label], i) => sel.options[i].value === value && sel.options[i].textContent === label);
  if (!same) {
    const value = sel.value;
    sel.replaceChildren(...wanted.map(([v, label]) => new Option(label, v)));
    sel.value = wanted.some(([v]) => v === value) ? value : "";
  }
  syncPick();
}

function setCommandEnabled(on) {
  if (consoleBusy) return;
  document.getElementById("console-cmd").disabled = !on;
  document.querySelector("#console-form button[type=submit]").disabled = !on;
}

function fillConsolePacks() {
  if (consoleBusy) return;
  const list = runningPacks();
  const names = list.map((p) => p.name);
  fillPicker(list);
  if (consoleName == null) {
    consoleName = names[0] || "";
    consoleOffset = 0;
  } else if (consoleName && !names.includes(consoleName)) {
    // The server went down. Keep its last output on screen, such as a crash,
    // rather than jumping to another server's log.
    document.getElementById("console-msg").textContent = `${consoleName} is no longer running.`;
    actionText = consoleText;
    consoleName = "";
    consoleOffset = 0;
  }
  document.getElementById("console-pack").value = consoleName;
  syncPick();
  setCommandEnabled(!!consoleName);
  if (!consoleName && consoleText !== actionText) setConsoleText(actionText);
}

function trimConsole(text) {
  const lines = text.split("\n");
  const keep = text.endsWith("\n") ? 201 : 200;
  if (lines.length <= keep) return text;
  return lines.slice(lines.length - keep).join("\n");
}

function showConsole(text, replace) {
  const next = trimConsole(replace ? text : consoleText + text);
  if (next === consoleText) return;
  const nearBottom = consoleAtBottom();
  setConsoleText(next);
  if (nearBottom || replace) {
    out.scrollTop = out.scrollHeight;
    jumpBtn.hidden = true;
  } else {
    jumpBtn.hidden = false;
  }
  saveState();
}

// The server holds an idle log request open until new lines arrive. A newer
// request from this page, such as a forced refresh after switching servers,
// makes the server answer the waiting one at once, so nothing is cancelled.
// A forced refresh never waits itself, since the page shows it as busy.
const PAGE_ID = Array.from(crypto.getRandomValues(new Uint8Array(12)),
  (b) => b.toString(16).padStart(2, "0")).join("");

async function refreshConsole(force) {
  if (!consoleName || hold || dlg.open) return;
  if ((consoleBusy || logBusy) && !force) return;
  logBusy = true;
  const ticket = ++consoleTicket;
  const name = consoleName;
  const offset = consoleOffset;
  try {
    const data = await api("/api/log?name=" + encodeURIComponent(name) + "&offset=" + offset +
      "&page=" + PAGE_ID + (force ? "&wait=0" : ""));
    if (ticket !== consoleTicket || !data || hold || name !== consoleName) return;
    if (data.ok === false) {
      document.getElementById("console-msg").textContent = data.output || "Failed.";
      return;
    }
    if (Number.isFinite(data.offset) && data.offset >= 0) consoleOffset = data.offset;
    const chunk = data.output || "";
    const replace = !!data.reset || offset === 0;
    if (!replace && !chunk) {
      saveState();
      return;
    }
    showConsole(chunk, replace);
  } finally {
    // An older request answering late leaves the newer one's busy flag alone.
    if (ticket === consoleTicket) logBusy = false;
  }
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// Each request returns as soon as the log grows, so poll again right away.
// The one-second floor keeps errors from spinning.
async function consoleLoop() {
  for (;;) {
    const start = Date.now();
    if (!document.hidden) {
      try { await refreshConsole(); } catch {}
    }
    const left = 1000 - (Date.now() - start);
    if (left > 0) await sleep(left);
  }
}

async function followConsole(name) {
  if (consoleBusy) return;
  if (!runningPacks().some((p) => p.name === name)) {
    document.getElementById("console-msg").textContent = "That server is not running.";
    return;
  }
  if (name !== consoleName) consoleOffset = 0;
  consoleName = name;
  const sel = document.getElementById("console-pack");
  if ([...sel.options].some((opt) => opt.value === name)) sel.value = name;
  syncPick();
  document.getElementById("console-msg").textContent = "";
  setConsoleBusy(true);
  try {
    await refreshConsole(true);
  } catch {
    document.getElementById("console-msg").textContent = "The page could not reach the server.";
  } finally {
    setConsoleBusy(false);
  }
}

document.getElementById("console-pack").onchange = () => {
  if (consoleBusy) return;
  const name = document.getElementById("console-pack").value;
  if (!name) {
    consoleName = "";
    consoleOffset = 0;
    setConsoleText(actionText);
    document.getElementById("console-msg").textContent = "";
    document.getElementById("console-cmd").disabled = true;
    document.querySelector("#console-form button[type=submit]").disabled = true;
    return;
  }
  followConsole(name);
};

document.getElementById("console-form").onsubmit = async (ev) => {
  ev.preventDefault();
  if (consoleBusy) return;
  const name = document.getElementById("console-pack").value;
  const input = document.getElementById("console-cmd");
  const command = input.value;
  const msg = document.getElementById("console-msg");
  if (!name || !command.trim()) return;
  if (name !== consoleName) consoleOffset = 0;
  consoleName = name;
  msg.textContent = "";
  remember(command.trim());
  await sendCommand(name, command);
};

// A blacklisted command comes back asking for the admin password. The
// password is sent with that one command and not kept.
async function sendCommand(name, command, adminPassword) {
  const input = document.getElementById("console-cmd");
  const msg = document.getElementById("console-msg");
  const body = {name, command};
  if (adminPassword) body.admin_password = adminPassword;
  setConsoleBusy(true);
  try {
    const data = await api("/api/command", body);
    if (!data) return;
    if (data.admin) {
      msg.textContent = data.output || "";
      askAdmin(name, command, data.rule || command, adminPassword ? data.output : "");
      return;
    }
    if (!data.ok) msg.textContent = data.output || "Failed.";
    else { input.value = ""; msg.textContent = ""; }
    await refreshConsole(true);
  } catch {
    msg.textContent = "The page could not reach the server.";
  } finally {
    setConsoleBusy(false);
    // Sending disabled the box, which drops focus. Put it back for the next command.
    if (!input.disabled) input.focus();
  }
  setTimeout(refreshConsole, 500);
}

function askAdmin(name, command, rule, error) {
  ask(`<form>
    <p><code>${esc(rule)}</code> is blacklisted. Enter the admin password to send it to <strong>${esc(name)}</strong>.</p>
    ${error ? `<p class="danger">${esc(error)}</p>` : ""}
    <label>Admin password <input type="password" name="admin" autocomplete="off" required></label>
    <div class="row-actions"><button type="button" data-cancel>Cancel</button><button type="submit">Send</button></div>
  </form>`, (fields) => {
    dlg.close();
    sendCommand(name, command, fields.admin);
  });
  dlg.querySelector("[name=admin]").focus();
}

// Up and Down step through earlier commands, newest first, like a shell.
// The list is kept in this browser only.
const HISTORY_KEY = "modman-history";
let cmdHistory = [];
try {
  const saved = JSON.parse(localStorage.getItem(HISTORY_KEY) || "[]");
  if (Array.isArray(saved)) cmdHistory = saved.filter((c) => typeof c === "string").slice(-50);
} catch (err) {}
let historyPos = -1;
let historyDraft = "";

function remember(command) {
  historyPos = -1;
  if (cmdHistory[cmdHistory.length - 1] !== command) cmdHistory.push(command);
  cmdHistory = cmdHistory.slice(-50);
  try { localStorage.setItem(HISTORY_KEY, JSON.stringify(cmdHistory)); } catch (err) {}
}

document.getElementById("console-cmd").addEventListener("keydown", (ev) => {
  if (ev.key !== "ArrowUp" && ev.key !== "ArrowDown") return;
  const input = ev.target;
  if (ev.key === "ArrowUp") {
    if (!cmdHistory.length || historyPos >= cmdHistory.length - 1) return;
    if (historyPos === -1) historyDraft = input.value;
    historyPos++;
  } else {
    if (historyPos === -1) return;
    historyPos--;
  }
  ev.preventDefault();
  input.value = historyPos === -1 ? historyDraft : cmdHistory[cmdHistory.length - 1 - historyPos];
  input.setSelectionRange(input.value.length, input.value.length);
});
document.getElementById("console-cmd").addEventListener("input", () => { historyPos = -1; });

// After an action, force skips the busy checks and replaces any poll still in
// flight, whose list may predate the action.
async function loadPacks(force) {
  if (!force && (hold || rowBusy || dlg.open || packsBusy)) return;
  packsBusy = true;
  packsAsked = Date.now();
  const ticket = ++packsTicket;
  let data;
  try {
    data = await api("/api/packs");
  } catch (err) {
    if (ticket === packsTicket) packsBusy = false;
    return;
  }
  if (ticket !== packsTicket) return;
  if (!force && (hold || rowBusy || dlg.open)) {
    packsBusy = false;
    return;
  }
  if (!data || !data.packs) {
    packsBusy = false;
    // Polls repeat, so one note is reused instead of stacking a new one each time.
    if (data && data.output) {
      if (packsNote && packsNote.isOpen()) packsNote.update(data.output, "error");
      else packsNote = toast(data.output, "error");
    }
    return;
  }
  if (packsNote) {
    packsNote.close();
    packsNote = null;
  }
  packs = data.packs;
  packsLoaded = true;
  fillConsolePacks();
  const svc = data.service || {};
  paintDot("svc-dot", svc.active === "active", svc.active);
  paintDot("boot-dot", svc.enabled === "enabled", svc.enabled);
  syncPacks();
  saveState();
  packsBusy = false;
  refreshConsole();
}

const ACT_LABELS = {
  start: "Starting", stop: "Stopping", restart: "Restarting", enable: "Enabling", disable: "Disabling",
};

document.getElementById("packs").onclick = (ev) => {
  const btn = ev.target.closest("button[data-act]");
  if (!btn || rowBusy) return;
  const name = btn.closest("tr").dataset.name;
  if (btn.dataset.act === "more") {
    if (!rowMenu.hidden && rowMenuAnchor === btn) closeRowMenu(true);
    else openRowMenu(btn, name);
    return;
  }
  rowAction(btn.dataset.act, name, btn);
};

function askPort(name, current) {
  ask(`<form>
    <p>Set the port for <strong>${esc(name)}</strong>.</p>
    <label>Port <input type="number" name="port" min="1" max="65535" value="${esc(current)}" required></label>
    <div class="row-actions"><button type="button" data-cancel>Cancel</button><button type="submit">Save</button></div>
  </form>`, (fields) => {
    dlg.close();
    run({cmd: "port", name, port: fields.port}, `Setting ${name} port to ${fields.port}…`);
  });
  const input = dlg.querySelector("[name=port]");
  input.focus();
  input.select();
}

// Shows what .modman-version saved for a pack, and lets the version be typed
// by hand. The next install or update replaces a typed version.
function versionDetails(pack) {
  const info = (pack && pack.version_info) || {};
  const rows = [];
  const version = pack && pack.version
    ? esc(pack.version) + (info.edited ? ' <span class="muted">(typed by hand)</span>' : "")
    : '<span class="muted">unknown</span>';
  rows.push(["Version", version]);
  if (info.source === "curseforge") {
    rows.push(["Source", "CurseForge" + (info.from ? ` project ${esc(info.from)}` : "")]);
  } else if (info.source === "link") {
    rows.push(["Source", "Download link"], ["Link", `<code>${esc(info.from)}</code>`]);
  } else if (info.source === "zip") {
    rows.push(["Source", "Zip file"], ["File", `<code>${esc(info.from)}</code>`]);
  } else if (info.source) {
    rows.push(["Source", esc(info.source)]);
  }
  const when = (iso) => {
    const d = new Date(iso);
    return Number.isNaN(d.getTime()) ? esc(iso) : esc(d.toLocaleString());
  };
  if (info.installed) rows.push(["Installed", when(info.installed)]);
  if (info.edited) rows.push(["Typed", when(info.edited)]);
  if (info.sha256) rows.push(["SHA-256", `<code>${esc(info.sha256)}</code>`]);
  return `<dl class="ver-info">${rows.map(([k, v]) => `<dt>${k}</dt><dd>${v}</dd>`).join("")}</dl>`;
}

function askVersion(name, pack) {
  const current = (pack && pack.version) || "";
  const note = pack && (pack.version || (pack.version_info && pack.version_info.source))
    ? ""
    : '<p class="muted">No version is saved for this server yet. The next install or update guesses one, or type it here.</p>';
  ask(`<form>
    <p>Version of <strong>${esc(name)}</strong></p>
    ${versionDetails(pack)}
    ${note}
    <label>Change the version <input type="text" name="version" maxlength="64" value="${esc(current)}" placeholder="2.5.0" autocomplete="off" spellcheck="false" required></label>
    <p class="muted">A typed version stays until the next install or update.</p>
    <div class="row-actions"><button type="button" data-cancel>Close</button><button type="submit" id="ver-save" disabled>Save</button></div>
  </form>`, (fields) => {
    const version = String(fields.version || "").trim();
    if (!version || version === current) return;
    dlg.close();
    run({cmd: "version", name, version}, `Setting ${name} version to ${version}…`);
  });
  // Save turns on once the field holds a new version.
  const input = dlg.querySelector("[name=version]");
  const save = dlg.querySelector("#ver-save");
  input.oninput = () => {
    const value = input.value.trim();
    save.disabled = !value || value === current;
  };
}

// anchor is the button the action came from, which a menu it opens hangs off.
async function rowAction(act, name, anchor) {
  if (rowBusy) return;
  const pack = packs.find((p) => p.name === name);
  if ((act === "start" || act === "stop" || act === "restart") && (!pack || !pack.indexed)) return;
  if (act === "port") {
    askPort(name, pack && pack.port !== "-" ? pack.port : "");
    return;
  }
  if (act === "version") {
    askVersion(name, pack);
    return;
  }
  if (act === "props") {
    openProps(anchor, name);
    return;
  }
  if (act === "log") {
    // On narrow screens the console sits below the list, often off screen.
    const panel = document.querySelector(".console-panel");
    const top = panel.getBoundingClientRect().top;
    if (top < 0 || top > window.innerHeight * 0.6) {
      const reduce = matchMedia("(prefers-reduced-motion: reduce)").matches;
      panel.scrollIntoView({behavior: reduce ? "auto" : "smooth", block: "start"});
    }
    // A running server streams into the console. A stopped one shows its last log once.
    if (runningPacks().some((p) => p.name === name)) {
      followConsole(name);
      return;
    }
    hold = true;
    showStatic(`Reading ${name} log…`);
    try {
      const data = await api("/api/log?name=" + encodeURIComponent(name) + "&offset=0");
      if (data) showStatic(data.ok === false ? (data.output || "Could not read the log.") : `${name} is not running. Last log:\n\n${data.output || "(empty)"}`);
    } catch {
      showStatic("The page could not reach the server.");
    } finally { hold = false; }
    out.scrollTop = out.scrollHeight;
    return;
  }
  if (act === "uninstall") {
    ask(`<form>
      <p>Delete <strong>${esc(name)}</strong>, including its world?</p>
      <label>Type yes to confirm <input name="confirm" autocomplete="off" required></label>
      <div class="row-actions"><button type="button" data-cancel>Cancel</button><button type="submit" class="danger">Uninstall</button></div>
    </form>`, (fields) => {
      dlg.close();
      if (String(fields.confirm).toLowerCase() !== "yes") { toast("Uninstall cancelled.", "ok"); return; }
      run({cmd: "uninstall", name, confirm: "yes"}, `Uninstalling ${name}…`);
    });
    return;
  }
  if (act === "update") {
    const search = pack && pack.curseforge ? "" : `
      <p class="muted">This folder has no CurseForge id. Search for the modpack, then pick one result.</p>
      <label>CurseForge name <input name="query" type="search"></label>
      <button type="button" id="upd-search">Search</button>
      <ul class="results" id="upd-results"></ul>
      <input type="hidden" name="mod_id" id="upd-id">`;
    ask(`<form>
      <p>Update <strong>${esc(name)}</strong> from:</p>
      <div class="upd-source">
        <label><input type="radio" name="source" value="curseforge" checked> CurseForge</label>
        <label><input type="radio" name="source" value="link"> Download link</label>
      </div>
      <div id="upd-cf">
        ${search}
        <p id="upd-check" class="upd-check muted">${pack && pack.curseforge ? "Checking CurseForge…" : "Pick a modpack to see its newest version."}</p>
      </div>
      <div id="upd-link" hidden>
        <p class="upd-check">Installed version: ${esc((pack && pack.version) || "unknown")}</p>
        <label>Link to the server pack zip <input name="link" type="url" inputmode="url" placeholder="https://…" autocomplete="off" spellcheck="false"></label>
        <p class="muted">Google Drive, OneDrive, Dropbox, or any public https link to a zip. Anyone with the link must be able to download it. The server runs sandboxed, but only use packs you trust.</p>
      </div>
      <label><input type="radio" name="world" value="keep" checked> Keep the world</label>
      <label><input type="radio" name="world" value="delete"> Delete the world</label>
      <label id="del-label" hidden>Type yes to delete the world <input name="delete_confirm" autocomplete="off"></label>
      <label>Type yes to update <input name="confirm" autocomplete="off" required></label>
      <p id="upd-msg" class="dlg-msg" role="alert"></p>
      <div class="row-actions"><button type="button" data-cancel>Cancel</button><button type="submit" id="upd-go" disabled>Update</button></div>
    </form>`, (fields) => {
      const fromLink = fields.source === "link";
      const link = String(fields.link || "").trim();
      if (!fromLink && !checked) return;
      const world = fields.world || "keep";
      if (String(fields.confirm).toLowerCase() !== "yes") { toast("Update cancelled.", "ok"); dlg.close(); return; }
      const updMsg = dlg.querySelector("#upd-msg");
      if (world === "delete" && String(fields.delete_confirm || "").toLowerCase() !== "yes") {
        updMsg.textContent = "Type yes to delete the world, or choose Keep the world.";
        return;
      }
      if (fromLink && !/^https:\/\/\S+$/i.test(link)) {
        updMsg.textContent = "Enter one link that starts with https://";
        return;
      }
      if (!fromLink && !(pack && pack.curseforge) && !fields.mod_id) {
        updMsg.textContent = "Choose a CurseForge modpack first.";
        return;
      }
      dlg.close();
      const payload = {
        name, world,
        confirm: "yes",
        delete_confirm: world === "delete" ? "yes" : ""
      };
      if (fromLink) {
        payload.link = link;
      } else {
        payload.file = checked.file;
        if (fields.mod_id) payload.mod_id = fields.mod_id;
      }
      finishServer(name, `Updating ${name}…`, (note) => trackUpdate(name, note, () => api("/api/update", payload)));
    });
    // The Update button stays off until a check shows there is something to
    // install. The file it showed goes with the request, so the server refuses
    // if a newer release lands in between.
    // A link has no version check, so Update turns on once one is typed.
    const checkLine = dlg.querySelector("#upd-check");
    const goBtn = dlg.querySelector("#upd-go");
    const linkInput = dlg.querySelector('input[name="link"]');
    const fromLink = () => dlg.querySelector('input[name="source"]:checked').value === "link";
    const syncGo = () => { goBtn.disabled = fromLink() ? !linkInput.value.trim() : !checked; };
    let checked = null;
    let checkTicket = 0;
    const checkUpdate = async (modId) => {
      const ticket = ++checkTicket;
      checked = null;
      syncGo();
      checkLine.className = "upd-check muted";
      checkLine.textContent = "Checking CurseForge…";
      let data;
      try {
        data = await api("/api/update-check", {name, mod_id: modId || ""});
      } catch (err) {
        if (ticket !== checkTicket) return;
        checkLine.textContent = err instanceof ApiTimeout ? err.message : "The page could not reach the server.";
        return;
      }
      if (ticket !== checkTicket || !data) return;
      if (!data.ok || !data.latest) {
        checkLine.className = "upd-check warn";
        checkLine.textContent = data.output || "Could not check for updates.";
        return;
      }
      const when = (d) => (d ? ` (released ${d})` : "");
      const latest = data.latest.version + when(data.latest.date)
        + (data.latest.minecraft ? `, Minecraft ${data.latest.minecraft}` : "");
      const inst = data.installed;
      const installed = inst ? (inst.version || "unknown") + when(inst.date) : "";
      checkLine.className = "upd-check";
      if (data.state === "current") {
        checkLine.textContent = `Already on the latest version: ${latest}.`;
      } else if (data.state === "older") {
        checkLine.className = "upd-check warn";
        checkLine.textContent = `Not updating: the newest server pack, ${latest}, is older than the installed ${installed}.`;
      } else if (data.state === "unknown") {
        checkLine.className = "upd-check warn";
        checkLine.textContent = `Installed version unknown. This will install ${latest}.`;
        checked = data.latest;
      } else {
        checkLine.textContent = `Installed: ${installed} → Latest: ${latest}`;
        checked = data.latest;
      }
      syncGo();
    };
    if (pack && pack.curseforge) checkUpdate("");
    dlg.querySelectorAll('input[name="source"]').forEach((el) => {
      el.onchange = () => {
        dlg.querySelector("#upd-cf").hidden = fromLink();
        dlg.querySelector("#upd-link").hidden = !fromLink();
        if (fromLink()) linkInput.focus();
        syncGo();
      };
    });
    linkInput.oninput = syncGo;
    dlg.querySelectorAll('input[name="world"]').forEach((el) => {
      el.onchange = () => {
        dlg.querySelector("#del-label").hidden = dlg.querySelector('input[name="world"]:checked').value !== "delete";
      };
    });
    const searchBtn = dlg.querySelector("#upd-search");
    if (searchBtn) {
      searchBtn.onclick = async () => {
        const query = dlg.querySelector('input[name="query"]').value;
        const list = dlg.querySelector("#upd-results");
        list.textContent = "Searching…";
        searchBtn.disabled = true;
        let data;
        try {
          data = await api("/api/search", {query});
        } catch (err) {
          list.textContent = err instanceof ApiTimeout ? err.message : "The page could not reach the server.";
          return;
        } finally {
          searchBtn.disabled = false;
        }
        if (!data) return;
        list.innerHTML = "";
        if (data.ok === false && !(data.results || []).length) {
          list.textContent = data.output || "Search failed.";
          return;
        }
        (data.results || []).forEach((item) => {
          const b = document.createElement("button");
          b.type = "button";
          b.textContent = `${item.name} (${item.downloads})`;
          b.onclick = () => {
            dlg.querySelector("#upd-id").value = item.id;
            list.querySelectorAll("button").forEach((n) => n.classList.remove("on"));
            b.classList.add("on");
            checkUpdate(String(item.id));
          };
          list.appendChild(b);
        });
        if (!list.children.length) list.textContent = "No matches.";
      };
    }
    return;
  }
  if (!ACT_LABELS[act]) return;
  run({cmd: act, name}, `${ACT_LABELS[act]} ${name}…`);
}

// The server.properties menu floats over the page, outside the table, so a
// table redraw or saved page state never holds a half-open menu.
const propsMenu = document.getElementById("props-menu");
let propsTicket = 0;
let propsAnchor = null;

// Lines a floating menu's right edge up with its button, kept on screen.
function placeMenu(menu, anchor) {
  if (!anchor || !anchor.isConnected) return;
  const r = anchor.getBoundingClientRect();
  const width = menu.offsetWidth;
  const left = Math.max(8, Math.min(r.right - width, document.documentElement.clientWidth - width - 8));
  menu.style.left = (left + window.scrollX) + "px";
  menu.style.top = (r.bottom + window.scrollY + 4) + "px";
}

function placeProps() {
  placeMenu(propsMenu, propsAnchor);
}

// Each row's ⋯ menu, drawn outside the table like the properties menu.
const rowMenu = document.getElementById("row-menu");
let rowMenuAnchor = null;

function closeRowMenu(refocus) {
  if (rowMenu.hidden) return;
  rowMenu.hidden = true;
  if (rowMenuAnchor) {
    rowMenuAnchor.setAttribute("aria-expanded", "false");
    if (refocus && rowMenuAnchor.isConnected) rowMenuAnchor.focus();
  }
  rowMenuAnchor = null;
}

function openRowMenu(btn, name) {
  closeRowMenu();
  closeProps();
  const pack = packs.find((p) => p.name === name);
  if (!pack) return;
  rowMenu.replaceChildren(...rowMenuItems(pack).map((item) => {
    if (item === "-") return document.createElement("hr");
    const b = document.createElement("button");
    b.type = "button";
    b.setAttribute("role", "menuitem");
    b.dataset.act = item[0];
    b.textContent = item[1];
    if (item[0] === "uninstall") b.className = "danger";
    return b;
  }));
  rowMenu.setAttribute("aria-label", `Actions for ${name}`);
  rowMenu.dataset.name = name;
  rowMenu.hidden = false;
  rowMenuAnchor = btn;
  btn.setAttribute("aria-expanded", "true");
  placeMenu(rowMenu, btn);
  rowMenu.querySelector("button").focus();
}

rowMenu.onclick = (ev) => {
  const b = ev.target.closest("button[data-act]");
  if (!b) return;
  const name = rowMenu.dataset.name;
  const anchor = rowMenuAnchor;
  closeRowMenu(false);
  rowAction(b.dataset.act, name, anchor);
};

rowMenu.onkeydown = (ev) => {
  const items = [...rowMenu.querySelectorAll("button")];
  const i = items.indexOf(document.activeElement);
  if (ev.key === "ArrowDown" || ev.key === "ArrowUp") {
    ev.preventDefault();
    const next = items[(i + (ev.key === "ArrowDown" ? 1 : items.length - 1)) % items.length];
    if (next) next.focus();
  } else if (ev.key === "Escape") {
    ev.preventDefault();
    closeRowMenu(true);
  } else if (ev.key === "Tab") {
    closeRowMenu(false);
  }
};

document.addEventListener("pointerdown", (ev) => {
  if (rowMenu.hidden) return;
  if (rowMenu.contains(ev.target) || (rowMenuAnchor && rowMenuAnchor.contains(ev.target))) return;
  closeRowMenu();
});
window.addEventListener("resize", () => placeMenu(rowMenu, rowMenuAnchor));

function closeProps(refocus) {
  propsTicket++;
  if (propsMenu.hidden) return;
  propsMenu.hidden = true;
  propsMenu.dataset.name = "";
  if (propsAnchor) propsAnchor.setAttribute("aria-expanded", "false");
  if (refocus && propsAnchor && propsAnchor.isConnected) propsAnchor.focus();
  propsAnchor = null;
}

function propsNote(text) {
  const p = document.createElement("p");
  p.className = "muted";
  p.textContent = text;
  propsMenu.replaceChildren(p);
  placeProps();
}

async function openProps(btn, name) {
  closeProps();
  const ticket = ++propsTicket;
  propsAnchor = btn;
  propsMenu.dataset.name = name;
  btn.setAttribute("aria-expanded", "true");
  propsMenu.hidden = false;
  propsNote("Loading…");
  let data;
  try {
    data = await api("/api/props?name=" + encodeURIComponent(name));
  } catch (err) {
    if (ticket === propsTicket) {
      propsNote(err instanceof ApiTimeout ? err.message : "The page could not reach the server.");
    }
    return;
  }
  if (ticket !== propsTicket || !data) return;
  if (!data.ok || !Array.isArray(data.properties)) {
    propsNote(data.output || "Could not read server.properties.");
    return;
  }
  const filter = document.createElement("input");
  filter.type = "search";
  filter.placeholder = "Filter";
  filter.setAttribute("aria-label", "Filter properties");
  const list = document.createElement("div");
  list.className = "props-list";
  for (const prop of data.properties) {
    const b = document.createElement("button");
    b.type = "button";
    b.setAttribute("role", "menuitem");
    b.dataset.key = prop.key;
    b.dataset.value = prop.value;
    b.title = `${prop.key}=${prop.value}`;
    const k = document.createElement("span");
    k.textContent = prop.key;
    const v = document.createElement("span");
    v.className = "props-val";
    v.textContent = prop.value;
    b.append(k, v);
    list.appendChild(b);
  }
  filter.oninput = () => {
    const q = filter.value.trim().toLowerCase();
    for (const b of list.children) b.hidden = !!q && !b.dataset.key.toLowerCase().includes(q);
  };
  propsMenu.replaceChildren(filter, list);
  placeProps();
  filter.focus();
}

function editProp(name, key, value) {
  const bool = value === "true" || value === "false";
  const field = bool
    ? `<select name="value">
        <option value="true"${value === "true" ? " selected" : ""}>true</option>
        <option value="false"${value === "false" ? " selected" : ""}>false</option>
      </select>`
    : `<input type="text" name="value" value="${esc(value)}" maxlength="1000" autocomplete="off">`;
  ask(`<form>
    <p>Change <strong>${esc(key)}</strong> for <strong>${esc(name)}</strong>.</p>
    <label>Value ${field}</label>
    <p class="muted">A running server needs a restart to use the new value.</p>
    <div class="row-actions"><button type="button" data-cancel>Cancel</button><button type="submit">Save</button></div>
  </form>`, (fields) => {
    dlg.close();
    run({cmd: "prop", name, key, value: fields.value || ""}, `Setting ${name} ${key}…`);
  });
  const input = dlg.querySelector("[name=value]");
  input.focus();
  if (input.select) input.select();
}

propsMenu.onclick = (ev) => {
  const b = ev.target.closest("button[data-key]");
  if (!b) return;
  const name = propsMenu.dataset.name;
  closeProps();
  if (rowBusy) return;
  editProp(name, b.dataset.key, b.dataset.value);
};

propsMenu.onkeydown = (ev) => {
  if (ev.key === "Escape") {
    ev.preventDefault();
    closeProps(true);
    return;
  }
  if (ev.key !== "ArrowDown" && ev.key !== "ArrowUp") return;
  const items = [...propsMenu.querySelectorAll("button[data-key]")].filter((b) => !b.hidden);
  if (!items.length) return;
  ev.preventDefault();
  const i = items.indexOf(document.activeElement);
  const down = ev.key === "ArrowDown";
  const next = i < 0 ? items[down ? 0 : items.length - 1] : items[(i + (down ? 1 : items.length - 1)) % items.length];
  next.focus();
};

document.addEventListener("pointerdown", (ev) => {
  if (propsMenu.hidden) return;
  if (propsMenu.contains(ev.target) || (propsAnchor && propsAnchor.contains(ev.target))) return;
  closeProps();
});
window.addEventListener("resize", placeProps);

// Installing lives in its own dialog, so the list and console keep updating
// while the person browses results.
const installDlg = document.getElementById("install-dlg");
const searchMsg = document.getElementById("search-msg");

document.getElementById("install-open").onclick = () => {
  installDlg.showModal();
  const q = document.getElementById("search-q");
  q.focus();
  q.select();
};
document.getElementById("install-close").onclick = () => installDlg.close();
installDlg.addEventListener("close", () => {
  if (searchAbort) searchAbort.abort();
});

function install(item) {
  if (!window.confirm(`Install ${item.name}?`)) return;
  installDlg.close();
  // Installing holds modman for minutes, so polls would only queue behind it.
  hold = true;
  const note = toast(`Installing ${item.name}… This can take several minutes.`, "busy");
  api("/api/install", {id: String(item.id)}).then((res) => {
    if (!res) note.close();
    else note.update(res.output || (res.ok ? "Done." : "Failed."), res.ok === false ? "error" : "ok");
  }).catch((err) => {
    note.update(err instanceof ApiTimeout ? err.message : "The page could not reach the server.", "error");
  }).finally(() => { hold = false; loadPacks(true); });
}

document.getElementById("search-form").onsubmit = async (ev) => {
  ev.preventDefault();
  if (searchAbort) searchAbort.abort();
  const query = document.getElementById("search-q").value;
  const list = document.getElementById("search-results");
  const ctrl = new AbortController();
  searchAbort = ctrl;
  hold = true;
  searchMsg.textContent = `Searching for ${query}…`;
  try {
    const data = await api("/api/search", {query}, ctrl.signal);
    if (searchAbort !== ctrl) return;
    list.replaceChildren();
    if (!data) return;
    const results = Array.isArray(data.results) ? data.results : [];
    searchMsg.textContent = data.output || (results.length ? "" : "No matches.");
    for (const item of results) {
      const li = document.createElement("li");
      const b = document.createElement("button");
      b.type = "button";
      b.innerHTML = `<strong>${esc(item.name)}</strong> <span class="muted">${esc(item.downloads)} downloads</span><br><span class="muted">${esc(item.summary || "")}</span>`;
      b.onclick = () => install(item);
      li.appendChild(b);
      list.appendChild(li);
    }
  } catch (err) {
    if (!err || err.name !== "AbortError") {
      searchMsg.textContent = err instanceof ApiTimeout ? err.message : "The page could not reach the server.";
    } else if (searchAbort === ctrl) {
      searchMsg.textContent = "";
    }
  } finally {
    if (searchAbort === ctrl) {
      searchAbort = null;
      hold = false;
    }
  }
};

document.getElementById("unlock").onclick = () => {
  clearBusy();
  loadPacks(true);
};

if (!restoreState()) render();
// The saved table may have been stored while a row was busy.
clearBusy();
loadPacks();
// Polling a hidden tab only burns bandwidth and server CPU, so pause it and
// catch up as soon as the tab is shown again.
// The list only needs to be quick while a server boots, so the table shows
// it come up. Otherwise just CPU, RAM and uptime change, and each poll costs
// the host about a second of CPU. Every finished action reloads it at once.
const PACKS_FAST = 5000;
const PACKS_SLOW = 15000;
setInterval(() => {
  if (document.hidden) return;
  const wait = packs.some((p) => p.status === "starting") ? PACKS_FAST : PACKS_SLOW;
  if (Date.now() - packsAsked >= wait) loadPacks();
}, 1000);
consoleLoop();
document.addEventListener("visibilitychange", () => {
  if (!document.hidden) loadPacks();
});
</script>
</body>
</html>
"""

LOGIN_CSP = page_csp(LOGIN_PAGE)
APP_CSP = page_csp(APP_PAGE)
# The same page with every control that changes something hidden by CSS. The
# server refuses those requests from a view-only sign-in either way. Only the
# <body> tag differs, so the script hashes in APP_CSP still match.
VIEW_PAGE = APP_PAGE.replace("<body>\n<header>", '<body class="view-only">\n<header>', 1)
assert VIEW_PAGE != APP_PAGE
LOGIN_ERRORS = {
    "1": "Wrong password.",
    "2": "Too many wrong passwords. Try again later.",
}


class Handler(BaseHTTPRequestHandler):
    # Browsers drop an https page that answers HTTP/1.0.
    protocol_version = "HTTP/1.1"
    server_version = "modman"
    timeout = 60
    # How long a kept-alive connection may sit idle between requests. Browsers
    # drop idle connections after at most 300 seconds (Chrome), so this outlasts
    # them and the browser always hangs up first. When the server hung up first,
    # the playit tunnel could still pass the browser's next request on to the
    # closed socket, and that request failed with a connection reset.
    idle_timeout = 330
    reply_key = None

    def log_message(self, fmt, *args):
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def setup(self):
        # setup() sets the socket timeout first, so a client that never
        # finishes the TLS handshake only holds its own thread.
        super().setup()
        self.tls_failed = False
        if isinstance(self.connection, ssl.SSLSocket):
            try:
                self.connection.do_handshake()
            except (ssl.SSLError, OSError):
                self.tls_failed = True

    def handle(self):
        if self.tls_failed:
            self.close_connection = True
            return
        self.close_connection = True
        self.handle_one_request()
        while not self.close_connection and self.wait_for_request():
            self.handle_one_request()

    def wait_for_request(self):
        # Only the wait for a request's first byte gets idle_timeout. The rest
        # of it is read under the shorter timeout again.
        try:
            self.connection.settimeout(self.idle_timeout)
            return bool(self.rfile.peek(1))
        except (OSError, ValueError):
            return False
        finally:
            try:
                self.connection.settimeout(self.timeout)
            except OSError:
                pass

    def end_headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        if getattr(self.server, "tls", False):
            self.send_header("Strict-Transport-Security", "max-age=31536000")
        super().end_headers()

    def cookie_flags(self):
        flags = "HttpOnly; SameSite=Lax; Path=/"
        if getattr(self.server, "tls", False):
            flags += "; Secure"
        return flags

    def cookie_token(self):
        raw = self.headers.get("Cookie", "")
        for part in raw.split(";"):
            name, _, value = part.strip().partition("=")
            if name == "modman_session" and value:
                return value
        return ""

    def authed(self):
        self.role = session_role(self.cookie_token())
        return bool(self.role)

    def send_html(self, code, html, csp):
        data = html.encode("utf-8")
        # The app page is about 53 kB and gzips to about 15 kB. Neither page
        # carries a secret, so BREACH does not apply.
        gzipped = len(data) > 512 and "gzip" in self.headers.get("Accept-Encoding", "")
        if gzipped:
            data = gzip.compress(data, compresslevel=6)
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        if gzipped:
            self.send_header("Content-Encoding", "gzip")
        self.send_header("Vary", "Accept-Encoding")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", csp)
        self.end_headers()
        self.wfile.write(data)

    def send_json(self, code, obj):
        data = json.dumps(obj, separators=(",", ":")).encode("utf-8")
        # The pack list is polled every few seconds, so compress anything
        # sizeable. No JSON reply carries a secret, so BREACH does not apply.
        gzipped = len(data) > 512 and "gzip" in self.headers.get("Accept-Encoding", "")
        if gzipped:
            data = gzip.compress(data, compresslevel=6)
        # Kept before writing, which fails if the browser's connection died.
        if self.reply_key is not None:
            with replies_lock:
                replies[self.reply_key][1] = (code, obj)
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        if gzipped:
            self.send_header("Content-Encoding", "gzip")
        self.send_header("Vary", "Accept-Encoding")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def start_reply(self, key):
        # True when this request should run. A resend of one already seen
        # instead waits for the first to finish and gets its reply.
        now = time.monotonic()
        with replies_lock:
            for old in [k for k, v in replies.items() if v[0].is_set() and now - v[2] > REPLY_KEEP]:
                del replies[old]
            entry = replies.get(key)
            if entry is None:
                replies[key] = [threading.Event(), None, now]
                self.reply_key = key
                return True
        entry[0].wait()
        if entry[1] is None:
            self.send_json(500, {"ok": False, "output": "The request failed. Try again."})
        else:
            self.send_json(*entry[1])
        return False

    def finish_reply(self):
        key, self.reply_key = self.reply_key, None
        with replies_lock:
            entry = replies[key]
            entry[2] = time.monotonic()
            entry[0].set()

    def redirect(self, location, cookie=None):
        self.send_response(303)
        self.send_header("Location", location)
        if cookie is not None:
            self.send_header("Set-Cookie", cookie)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def read_json(self):
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length < 0 or length > 65536:
            return None
        raw = self.rfile.read(length) if length else b""
        if not raw:
            return {}
        try:
            data = json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError:
            return None
        return data if isinstance(data, dict) else None

    def send_ca(self):
        if not CA or not os.path.isfile(CA):
            self.send_json(404, {"ok": False, "output": "No certificate."})
            return
        with open(CA, "rb") as fh:
            data = fh.read()
        self.send_response(200)
        self.send_header("Content-Type", "application/x-x509-ca-cert")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Content-Disposition", 'attachment; filename="modman-ca.crt"')
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def serve_public(self, path):
        """Answer the paths that need no sign-in. False when path is not one of them."""
        if path.startswith("/.well-known/acme-challenge/"):
            body = acme_challenge(path[len("/.well-known/acme-challenge/"):])
            if body is None:
                self.send_response(404)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return True
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return True
        if path == "/modman-ca.crt":
            self.send_ca()
            return True
        if path == "/favicon.svg":
            self.send_response(200)
            self.send_header("Content-Type", "image/svg+xml")
            self.send_header("Content-Length", str(len(FAVICON_SVG)))
            self.send_header("Cache-Control", "public, max-age=86400")
            self.end_headers()
            self.wfile.write(FAVICON_SVG)
            return True
        if path == "/favicon.ico":
            self.send_response(204)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return True
        return False

    def do_GET(self):
        parsed = urlparse(self.path)
        if self.serve_public(parsed.path):
            return
        if parsed.path == "/login":
            query = parse_qs(parsed.query or "")
            error = (query.get("error") or [""])[0]
            message = LOGIN_ERRORS.get(error, "")
            html = f"<p class=\"err\">{message}</p>" if message else ""
            self.send_html(200, LOGIN_PAGE.replace("__ERROR__", html), LOGIN_CSP)
            return
        if parsed.path == "/":
            if not self.authed():
                self.redirect("/login")
                return
            self.send_html(200, VIEW_PAGE if self.role == "view" else APP_PAGE, APP_CSP)
            return
        if not self.authed():
            self.send_json(401, {"ok": False, "output": "Sign in required."})
            return
        if parsed.path == "/api/packs":
            self.handle_packs()
            return
        if parsed.path == "/api/log":
            query = parse_qs(parsed.query or "")
            name = (query.get("name") or [""])[0]
            offset = (query.get("offset") or ["0"])[0]
            page = (query.get("page") or [""])[0]
            wait = (query.get("wait") or ["1"])[0] != "0"
            self.handle_log(name, offset, page, wait)
            return
        if parsed.path == "/api/props":
            query = parse_qs(parsed.query or "")
            self.handle_props((query.get("name") or [""])[0])
            return
        if parsed.path == "/api/update-progress":
            query = parse_qs(parsed.query or "")
            self.handle_update_progress((query.get("name") or [""])[0])
            return
        if parsed.path == "/api/update-log":
            query = parse_qs(parsed.query or "")
            self.handle_update_log((query.get("name") or [""])[0])
            return
        self.send_json(404, {"ok": False, "output": "Not found."})

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path == "/login":
            self.handle_login()
            return
        if parsed.path == "/logout":
            token = self.cookie_token()
            with sessions_lock:
                sessions.pop(token, None)
            self.redirect(
                "/login",
                f"modman_session=; {self.cookie_flags()}; Max-Age=0",
            )
            return
        if not self.authed():
            self.send_json(401, {"ok": False, "output": "Sign in required."})
            return
        # Every POST changes something, so a view-only sign-in sends none.
        if self.role != "full":
            self.send_json(403, {"ok": False, "output": "This sign-in is view only."})
            return
        if self.headers.get("Content-Type", "").split(";")[0].strip() != "application/json":
            self.send_json(400, {"ok": False, "output": "Expected JSON."})
            return
        body = self.read_json()
        if body is None:
            self.send_json(400, {"ok": False, "output": "Bad JSON."})
            return
        request_id = self.headers.get("X-Request-Id", "")
        if not REQUEST_ID_RE.fullmatch(request_id):
            self.route_post(parsed.path, body)
            return
        if not self.start_reply((self.cookie_token(), request_id)):
            return
        try:
            self.route_post(parsed.path, body)
        finally:
            self.finish_reply()

    def route_post(self, path, body):
        if path == "/api/run":
            self.handle_run(body)
            return
        if path == "/api/search":
            self.handle_search(body)
            return
        if path == "/api/install":
            self.handle_install(body)
            return
        if path == "/api/update":
            self.handle_update(body)
            return
        if path == "/api/update-check":
            self.handle_update_check(body)
            return
        if path == "/api/command":
            self.handle_command(body)
            return
        self.send_json(404, {"ok": False, "output": "Not found."})

    def handle_login(self):
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length < 0 or length > 4096:
            self.redirect("/login?error=1")
            return
        raw = self.rfile.read(length) if length else b""
        addr = self.client_address[0]
        if login_blocked(addr):
            time.sleep(1)
            self.redirect("/login?error=2")
            return
        fields = parse_qs(raw.decode("utf-8", "replace"), keep_blank_values=True)
        given = (fields.get("password") or [""])[0]
        view_hash = ""
        if not password_ok(given):
            view_hash = read_hash_file(VIEW_HASH_FILE)
            if not stored_password_ok(view_hash, given):
                login_failed(addr)
                time.sleep(1)
                self.redirect("/login?error=1")
                return
        login_succeeded(addr)
        token = new_session(view_hash)
        self.redirect(
            "/",
            f"modman_session={token}; {self.cookie_flags()}",
        )

    def handle_packs(self):
        try:
            proc = modman_call(["packs"], 120)
        except subprocess.TimeoutExpired:
            self.send_json(504, {"ok": False, "output": "Timed out reading modpacks."})
            return
        if proc.returncode != 0:
            self.send_json(500, {"ok": False, "output": command_text(proc)})
            return
        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError:
            self.send_json(500, {"ok": False, "output": command_text(proc)})
            return
        self.send_json(200, data)

    def handle_command(self, body):
        command = str(body.get("command") or "")
        rule = blacklisted(command)
        if rule:
            if not admin_password_set():
                self.send_json(403, {
                    "ok": False,
                    "output": f"'{rule}' is blacklisted. Run web admin to set an admin password that allows it.",
                })
                return
            given = str(body.get("admin_password") or "")
            if not given:
                self.send_json(403, {"ok": False, "admin": True, "rule": rule,
                                     "output": f"'{rule}' needs the admin password."})
                return
            # Wrong admin passwords count toward the same limit as sign-ins.
            addr = self.client_address[0]
            if login_blocked(addr):
                time.sleep(1)
                self.send_json(429, {"ok": False, "output": "Too many wrong passwords. Try again in 15 minutes."})
                return
            if not admin_password_ok(given):
                login_failed(addr)
                time.sleep(1)
                self.send_json(403, {"ok": False, "admin": True, "rule": rule,
                                     "output": "Wrong admin password."})
                return
        self.finish_call([
            "command",
            str(body.get("name") or ""),
            command,
        ], 30)

    def handle_update_progress(self, name):
        """The step a running update last reported. It reads the file modman
        writes, since a modman call would wait behind the update itself."""
        if not LOG_NAME_RE.fullmatch(name) or not DATA_DIR:
            self.send_json(400, {"ok": False, "output": "Bad name."})
            return
        try:
            with open(os.path.join(DATA_DIR, f".update-progress-{name}"), encoding="utf-8") as fh:
                step, _, percent = fh.readline().strip().partition("\t")
        except OSError:
            step, percent = "", ""
        self.send_json(200, {
            "ok": True,
            "step": step,
            "percent": min(int(percent), 100) if percent.isdigit() else None,
        })

    # The most of an update's output the page is sent at once.
    UPDATE_LOG_MAX = 256 * 1024

    def handle_update_log(self, name):
        """What a running or finished update has printed so far. Like the
        progress, it reads the file modman writes instead of calling modman."""
        if not LOG_NAME_RE.fullmatch(name) or not DATA_DIR:
            self.send_json(400, {"ok": False, "output": "Bad name."})
            return
        try:
            with open(os.path.join(DATA_DIR, f".update-log-{name}"), "rb") as fh:
                fh.seek(0, os.SEEK_END)
                size = fh.tell()
                fh.seek(max(0, size - self.UPDATE_LOG_MAX))
                text = fh.read().decode("utf-8", "replace")
        except OSError:
            text = ""
        self.send_json(200, {"ok": True, "text": text})

    def handle_props(self, name):
        try:
            proc = modman_call(["props", name], 30)
        except subprocess.TimeoutExpired:
            self.send_json(504, {"ok": False, "output": "Timed out reading server.properties."})
            return
        if proc.returncode != 0:
            self.send_json(400, {"ok": False, "output": command_text(proc)})
            return
        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError:
            self.send_json(500, {"ok": False, "output": command_text(proc)})
            return
        self.send_json(200, data)

    def handle_log(self, name, offset, page="", wait=True):
        if not str(offset).isdigit() or len(str(offset)) > 18:
            offset = "0"
        key = (self.cookie_token(), page) if PAGE_ID_RE.fullmatch(page) else None
        turn = take_log_turn(key) if key is not None else 0
        try:
            proc = modman_call(["log", name, str(offset)], 30)
        except subprocess.TimeoutExpired:
            self.send_json(504, {"ok": False, "output": "Timed out reading the log."})
            return
        if proc.returncode != 0:
            self.send_json(400, {
                "ok": False,
                "output": command_text(proc),
                "offset": 0,
                "reset": True,
            })
            return
        parsed = parse_log_frame(proc.stdout or "")
        if parsed is None:
            self.send_json(500, {"ok": False, "output": "Could not read the log.", "offset": 0, "reset": True})
            return
        reset, new_offset, body = parsed
        if wait and not reset and not body and new_offset == int(offset) > 0:
            outcome = wait_for_log(name, new_offset, self.connection, key, turn)
            if outcome == "gone":
                self.close_connection = True
                return
            if outcome == "superseded":
                self.send_json(200, {"ok": True, "output": "", "offset": new_offset, "reset": False})
                return
            try:
                proc = modman_call(["log", name, str(offset)], 30)
            except subprocess.TimeoutExpired:
                proc = None
            again = parse_log_frame(proc.stdout or "") if proc and proc.returncode == 0 else None
            if again is not None:
                reset, new_offset, body = again
        self.send_json(200, {
            "ok": True,
            "output": body,
            "offset": new_offset,
            "reset": reset,
        })

    def handle_run(self, body):
        cmd = str(body.get("cmd") or "")
        name = str(body.get("name") or "")
        args = ["run", cmd]
        if cmd in {"start", "stop", "restart", "enable", "disable"}:
            if name:
                args.append(name)
                if cmd in {"start", "restart"} and body.get("eula") == "agree":
                    args.append("agree")
        elif cmd == "port":
            args.extend([name, str(body.get("port") or "")])
        elif cmd == "prop":
            args.extend([name, str(body.get("key") or ""), str(body.get("value") or "")])
        elif cmd == "version":
            args.extend([name, str(body.get("version") or "")])
        elif cmd == "uninstall":
            args.extend([name, str(body.get("confirm") or "")])
        elif cmd == "service":
            args.append(str(body.get("action") or ""))
        else:
            self.send_json(400, {"ok": False, "output": "Unknown action."})
            return
        self.finish_call(args, 180, eula=cmd in {"start", "restart"} and bool(name))

    def handle_search(self, body):
        query = str(body.get("query") or "")
        try:
            proc = modman_call(["search", query], 60)
        except subprocess.TimeoutExpired:
            self.send_json(504, {"ok": False, "output": "Search timed out."})
            return
        if proc.returncode != 0:
            self.send_json(400, {"ok": False, "output": command_text(proc), "results": []})
            return
        try:
            results = json.loads(proc.stdout or "[]")
        except json.JSONDecodeError:
            self.send_json(500, {"ok": False, "output": command_text(proc), "results": []})
            return
        self.send_json(200, {"ok": True, "output": "", "results": results})

    def handle_install(self, body):
        self.finish_call(["install", str(body.get("id") or "")], 3600)

    def handle_update(self, body):
        self.finish_call([
            "update",
            str(body.get("name") or ""),
            str(body.get("world") or ""),
            str(body.get("confirm") or ""),
            str(body.get("delete_confirm") or ""),
            str(body.get("mod_id") or ""),
            str(body.get("file") or ""),
            str(body.get("link") or "").strip(),
        ], 3600)

    def handle_update_check(self, body):
        try:
            proc = modman_call([
                "updatecheck",
                str(body.get("name") or ""),
                str(body.get("mod_id") or ""),
            ], 90)
        except subprocess.TimeoutExpired:
            self.send_json(504, {"ok": False, "output": "Timed out checking CurseForge."})
            return
        if proc.returncode != 0:
            self.send_json(400, {"ok": False, "output": command_text(proc)})
            return
        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError:
            self.send_json(500, {"ok": False, "output": command_text(proc)})
            return
        self.send_json(200, data)

    def finish_call(self, args, timeout, eula=False):
        try:
            proc = modman_call(args, timeout)
        except subprocess.TimeoutExpired:
            self.send_json(504, {"ok": False, "output": "Timed out."})
            return
        reply = {
            "ok": proc.returncode == 0,
            "output": command_text(proc),
        }
        # Exit status 3 from start or restart means the Minecraft EULA is not accepted yet.
        if eula and proc.returncode == 3:
            reply["eula"] = True
        self.send_json(200 if proc.returncode == 0 else 400, reply)


class HTTPHandler(Handler):
    """The plain http port. It answers the Let's Encrypt check and the CA
    download, and sends everything else to https."""

    def do_GET(self):
        if self.serve_public(urlparse(self.path).path):
            return
        self.redirect_https(301)

    def do_POST(self):
        self.redirect_https(308)

    def redirect_https(self, code):
        match = HOST_RE.fullmatch(self.headers.get("Host", ""))
        if not match:
            self.close_connection = True
            self.send_json(400, {"ok": False, "output": "Open this page with https."})
            return
        host, port = match.group(1), match.group(2)
        # A port in the Host header means the browser reached this port
        # directly. No port means public port 80 forwarded here, so https is
        # on public port 443.
        target = f"https://{host}:{PORT}" if port else f"https://{host}"
        path = self.path if self.path.startswith("/") else "/"
        # A POST body is left unread, so the connection cannot be reused.
        self.close_connection = True
        self.send_response(code)
        self.send_header("Location", target + path)
        self.send_header("Content-Length", "0")
        self.send_header("Connection", "close")
        self.end_headers()


class HTTPSServer(ThreadingHTTPServer):
    tls = True

    def __init__(self, address, handler, context):
        self.tls_context = context
        super().__init__(address, handler)

    def get_request(self):
        sock, addr = super().get_request()
        try:
            # The handshake runs in the request thread. See Handler.setup.
            return self.tls_context.wrap_socket(
                sock, server_side=True, do_handshake_on_connect=False
            ), addr
        except OSError:
            sock.close()
            raise


def sni_callback(sock, server_name, _initial):
    chosen = le_holder[0]
    if server_name and chosen and server_name == chosen.get("name"):
        sock.context = chosen["context"]
    return None


def main():
    if not CERT or not KEY or not os.path.isfile(CERT) or not os.path.isfile(KEY):
        sys.stderr.write("Error: https needs a certificate.\n")
        sys.exit(1)
    if HTTP_PORT == PORT:
        sys.stderr.write("Error: the http fallback port must differ from the https port.\n")
        sys.exit(1)
    context = make_context(CERT, KEY)
    context.sni_callback = sni_callback
    domain = read_domain()
    if domain:
        use_signed_certificate(domain)
    https = HTTPSServer((BIND, PORT), Handler, context)
    http = ThreadingHTTPServer((BIND, HTTP_PORT), HTTPHandler)
    http.tls = False
    threading.Thread(target=http.serve_forever, daemon=True).start()
    if domain:
        threading.Thread(target=sign_loop, args=(domain,), daemon=True).start()
    sys.stdout.write(f"listening {PORT}\n")
    sys.stdout.flush()
    https.serve_forever()


if __name__ == "__main__":
    main()
