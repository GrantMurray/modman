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


def new_session():
    token = secrets.token_urlsafe(32)
    now = time.monotonic()
    with sessions_lock:
        for key, (created, used) in list(sessions.items()):
            if now - created > SESSION_MAX or now - used > SESSION_IDLE:
                del sessions[key]
        sessions[token] = [now, now]
    return token


def session_ok(token):
    if not token:
        return False
    now = time.monotonic()
    with sessions_lock:
        times = sessions.get(token)
        if times is None:
            return False
        created, used = times
        if now - created > SESSION_MAX or now - used > SESSION_IDLE:
            del sessions[token]
            return False
        times[1] = now
        return True


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
  body { margin: 0; font: 16px/1.4 system-ui, sans-serif; background: #f3f0e8; color: #1c1c1c; }
  main { max-width: 22rem; margin: 12vh auto; background: #fff; padding: 1.5rem; border: 1px solid #ddd; }
  h1 { margin: 0 0 0.4rem; font-size: 1.4rem; }
  p { margin: 0 0 1rem; color: #444; }
  label { display: block; font-size: 0.9rem; margin-bottom: 0.8rem; }
  input { display: block; width: 100%; box-sizing: border-box; margin-top: 0.3rem; padding: 0.45rem; font: inherit; }
  button { font: inherit; padding: 0.4rem 0.8rem; background: #1f3d2d; color: #fff; border: 0; cursor: pointer; }
  .err { color: #8d1d1d; }
</style>
</head>
<body>
<main>
  <h1>modman</h1>
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
  body { margin: 0; font: 15px/1.4 system-ui, sans-serif; background: #f3f0e8; color: #1c1c1c; }
  header { display: flex; flex-wrap: wrap; gap: 0.6rem 1rem; align-items: center; background: #1f3d2d; color: #f4f1ea; padding: 0.8rem 1rem; }
  header h1 { margin: 0; font-size: 1.15rem; font-weight: 600; }
  header button, .tools button, .row button, dialog button { font: inherit; background: #fff; color: #1c1c1c; border: 1px solid #c8c2b4; padding: 0.25rem 0.55rem; cursor: pointer; }
  header button { background: transparent; color: #f4f1ea; border-color: #8eaa98; }
  .header-end { margin-left: auto; display: flex; flex-wrap: wrap; align-items: center; gap: 0.75rem 1rem; }
  .menu { position: relative; }
  .menu summary { list-style: none; cursor: pointer; border: 1px solid #8eaa98; padding: 0.25rem 0.55rem; color: #f4f1ea; user-select: none; }
  .menu summary::-webkit-details-marker { display: none; }
  .menu summary::after { content: " \25BE"; font-size: 0.8em; }
  .menu-panel { position: absolute; right: 0; top: calc(100% + 0.35rem); z-index: 5; display: flex; flex-direction: column; gap: 0.25rem; min-width: 12rem; background: #1f3d2d; border: 1px solid #8eaa98; padding: 0.35rem; }
  .menu-panel button { text-align: left; }
  main { padding: 1rem; max-width: 72rem; margin: 0 auto; }
  h2 { font-size: 1rem; margin: 1.2rem 0 0.4rem; }
  table { width: 100%; border-collapse: collapse; background: #fff; }
  th, td { text-align: left; padding: 0.4rem 0.5rem; border-bottom: 1px solid #e4dfd4; vertical-align: top; }
  th { font-size: 0.75rem; letter-spacing: 0.04em; color: #555; }
  .status { font-weight: 600; }
  .stopped { color: #8d1d1d; }
  .starting { color: #8a5a00; }
  .running { color: #1d7a3a; }
  .error { color: #9a3412; }
  .java-warn { color: #9a3412; font-weight: 600; }
  .port-warn { color: #9a3412; font-size: 0.8rem; margin-top: 0.25rem; max-width: 12rem; }
  .port-warn:empty { display: none; }
  .actions { display: flex; flex-wrap: wrap; gap: 0.3rem; }
  .actions input[type="number"] { width: 5.5rem; font: inherit; padding: 0.2rem; }
  tr.busy { color: #8a8478; }
  tr.busy .status { color: #8a8478; }
  tr.busy button, tr.busy input { opacity: 0.45; }
  .loadbar { flex: 1 0 100%; height: 0.3rem; background: #e4dfd4; overflow: hidden; border-radius: 999px; }
  .loadbar[hidden] { display: none; }
  .loadbar span { display: block; height: 100%; width: 35%; background: #6d7a72; animation: loadbar 1s ease-in-out infinite; }
  @keyframes loadbar { from { transform: translateX(-120%); } to { transform: translateX(320%); } }
  .danger { color: #8d1d1d; border-color: #e0b4b4; }
  .console-head { display: flex; align-items: center; gap: 0.45rem; margin: 1.2rem 0 0.4rem; }
  .console-head h2 { margin: 0; }
  .spinner { width: 0.9rem; height: 0.9rem; border: 2px solid #c8c2b4; border-top-color: #1f3d2d; border-radius: 50%; animation: spin 0.7s linear infinite; }
  .spinner[hidden] { display: none; }
  @keyframes spin { to { transform: rotate(360deg); } }
  .console-form { display: flex; flex-wrap: wrap; gap: 0.4rem; align-items: center; margin: 0.4rem 0; }
  .console-form[hidden] { display: none; }
  .console-form select, .console-form input { font: inherit; padding: 0.3rem; }
  .console-form input { flex: 1; min-width: 12rem; }
  .pick { position: relative; }
  .pick-btn { font: inherit; background: #fff; color: #1c1c1c; border: 1px solid #c8c2b4; padding: 0.3rem 0.55rem; cursor: pointer; min-width: 10rem; text-align: left; }
  .pick-btn::after { content: " \25BE"; float: right; margin-left: 0.6rem; }
  .pick-btn:disabled { opacity: 0.6; cursor: default; }
  .pick-menu { position: absolute; left: 0; top: calc(100% + 0.2rem); z-index: 6; min-width: 100%; max-height: 16rem; overflow-y: auto; background: #fff; border: 1px solid #c8c2b4; box-shadow: 0 4px 12px rgba(0, 0, 0, 0.12); display: flex; flex-direction: column; }
  .pick-menu[hidden] { display: none; }
  .pick-menu button { font: inherit; text-align: left; background: #fff; color: #1c1c1c; border: 0; padding: 0.35rem 0.6rem; cursor: pointer; white-space: nowrap; }
  .pick-menu button:hover, .pick-menu button:focus { background: #ece7dc; outline: none; }
  .pick-menu button[aria-selected="true"] { font-weight: 600; }
  .props-menu { position: absolute; top: 0; left: 0; min-width: 16rem; max-width: min(28rem, calc(100vw - 2rem)); }
  .props-menu input { font: inherit; margin: 0.35rem; padding: 0.25rem 0.4rem; border: 1px solid #c8c2b4; }
  .props-menu .props-list { overflow-y: auto; max-height: 14rem; display: flex; flex-direction: column; }
  .props-menu button { display: flex; gap: 0.8rem; justify-content: space-between; }
  .props-menu .props-val { color: #555; overflow: hidden; text-overflow: ellipsis; max-width: 12rem; }
  .props-menu p { margin: 0.4rem 0.6rem; }
  #out { white-space: pre-wrap; background: #1c1c1c; color: #f3f0e8; padding: 0.8rem; min-height: 2.5rem; max-height: 24rem; overflow: auto; }
  dialog { border: 1px solid #ccc; padding: 1rem; max-width: 28rem; }
  dialog label { display: block; margin: 0.5rem 0; }
  dialog [hidden] { display: none; }
  dialog input[type="text"], dialog input[type="search"] { font: inherit; padding: 0.3rem; width: 100%; box-sizing: border-box; }
  .results { list-style: none; padding: 0; margin: 0.4rem 0; max-height: 12rem; overflow: auto; }
  .results button { display: block; width: 100%; text-align: left; margin-bottom: 0.25rem; }
  .results button.on { outline: 2px solid #1f3d2d; }
  .muted { color: #555; font-size: 0.9rem; }
  .upd-check { padding: 0.45rem 0.6rem; background: #f3f0e8; border-left: 3px solid #6d7a72; }
  .upd-check.warn { border-left-color: #9a3412; color: #7c2d12; }
  .row-actions { display: flex; gap: 0.4rem; justify-content: flex-end; margin-top: 0.8rem; }
  .svc-state { display: inline-flex; align-items: center; gap: 0.35rem; }
  .dot { width: 0.7rem; height: 0.7rem; border-radius: 50%; background: #e15d5d; }
  .dot.on { background: #3dce6e; }

  /* Phones: each server becomes a card with labelled lines, and controls get
     finger-sized. Inputs use 16px so iOS does not zoom in on focus. */
  @media (max-width: 40rem) {
    main { padding: 0.75rem; }
    header { padding: 0.7rem 0.75rem; }
    header button, .menu summary { min-height: 2.5rem; padding: 0.4rem 0.7rem; box-sizing: border-box; }
    .header-end { gap: 0.5rem 0.75rem; }
    .menu-panel button { min-height: 2.75rem; }
    button, .pick-btn { min-height: 2.75rem; }
    input, select { font-size: 16px; min-height: 2.75rem; box-sizing: border-box; }

    #search-form { display: flex; flex-wrap: wrap; gap: 0.4rem; }
    #search-q { flex: 1 1 100%; padding: 0.4rem; }
    #search-form button { flex: 1; }
    .results button { padding: 0.5rem; }

    #packs table, #packs tbody, #packs tr, #packs td { display: block; }
    #packs table { background: none; }
    #packs thead { display: none; }
    #packs tr { background: #fff; border: 1px solid #e4dfd4; margin-bottom: 0.75rem; padding: 0.4rem 0; }
    #packs td { border: 0; padding: 0.3rem 0.75rem; }
    #packs td[data-label] { display: flex; flex-wrap: wrap; align-items: center; gap: 0.4rem; }
    #packs td[data-label]::before { content: attr(data-label); flex: 0 0 4.5rem; font-size: 0.75rem; letter-spacing: 0.04em; color: #555; font-weight: 400; }
    #packs td[data-pack-name] { font-size: 1.05rem; font-weight: 600; padding-top: 0.2rem; overflow-wrap: anywhere; }
    #packs .actions input[type="number"], #packs td[data-label="Port"] input { width: 7rem; }
    #packs .port-warn { flex: 1 0 100%; max-width: none; margin: 0; }
    #packs td.actions { display: grid; grid-template-columns: repeat(auto-fill, minmax(6.5rem, 1fr)); gap: 0.4rem; padding-top: 0.5rem; }
    #packs .loadbar { grid-column: 1 / -1; }

    .console-form .pick { flex: 1 1 100%; }
    .console-form .pick-btn { width: 100%; }
    .console-form input { min-width: 0; }
    .pick-menu button { padding: 0.6rem 0.75rem; }
    #out { max-height: 60vh; font-size: 13px; padding: 0.6rem; }

    .props-menu { min-width: 0; width: calc(100vw - 1.5rem); }
    .props-menu .props-list { max-height: 50vh; }
    .props-menu button { padding: 0.6rem 0.75rem; }
    .props-menu .props-val { max-width: 45%; }
    dialog { width: calc(100vw - 2rem); box-sizing: border-box; }
    .row-actions button { flex: 1; }
  }
</style>
</head>
<body>
<header>
  <h1>modman</h1>
  <div class="header-end">
    <span class="svc-state">Service <span id="svc-dot" class="dot" role="img" aria-label="unknown"></span></span>
    <span class="svc-state">Boot <span id="boot-dot" class="dot" role="img" aria-label="unknown"></span></span>
    <details class="menu" id="svc-menu">
      <summary>Service</summary>
      <div class="menu-panel">
        <button type="button" id="svc-start">Start service</button>
        <button type="button" id="svc-stop">Stop service</button>
        <button type="button" id="svc-restart">Restart service</button>
        <button type="button" id="svc-enable">Enable at boot</button>
        <button type="button" id="svc-disable">Disable at boot</button>
      </div>
    </details>
    <button type="button" id="unlock" title="Cancel pending requests and re-enable every greyed-out control">Unlock</button>
    <button type="button" id="logout">Sign out</button>
  </div>
</header>
<main>
  <section class="tools">
    <h2>Install a modpack</h2>
    <form id="search-form">
      <input id="search-q" type="search" placeholder="Search CurseForge" required>
      <button type="submit">Search</button>
      <button type="button" id="search-clear">Clear</button>
    </form>
    <ul id="search-results" class="results"></ul>
  </section>
  <div id="packs"></div>
  <div class="console-head">
    <h2>Console</h2>
    <span id="console-spin" class="spinner" hidden role="status" aria-label="Loading"></span>
  </div>
  <form id="console-form" class="console-form">
    <div class="pick">
      <select id="console-pack" aria-label="Modpack" hidden>
        <option value="">Actions</option>
      </select>
      <button type="button" id="console-pick-btn" class="pick-btn" aria-haspopup="listbox" aria-expanded="false">Actions</button>
      <div id="console-pick-menu" class="pick-menu" role="listbox" aria-label="Modpack" hidden></div>
    </div>
    <input id="console-cmd" type="text" maxlength="300" placeholder="Command" autocomplete="off">
    <button type="submit">Send</button>
  </form>
  <p id="console-msg" class="muted"></p>
  <pre id="out"></pre>
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
<div id="props-menu" class="pick-menu props-menu" role="menu" aria-label="server.properties" hidden></div>
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
  setServerBusy(null, false);
  setConsoleBusy(false);
  setCommandEnabled(!!consoleName && runningPacks().some((p) => p.name === consoleName));
}

function show(text) {
  actionText = text || "";
  consoleName = "";
  consoleOffset = 0;
  const sel = document.getElementById("console-pack");
  if ([...sel.options].some((opt) => opt.value === "")) sel.value = "";
  syncPick();
  out.textContent = actionText;
  if (!consoleBusy) {
    document.getElementById("console-cmd").disabled = true;
    document.querySelector("#console-form button[type=submit]").disabled = true;
  }
  saveState();
}

function setServerBusy(name, on) {
  rowBusy = on;
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
  show(label || "Working…");
  let reached = false;
  try {
    const data = await request();
    reached = true;
    if (!data) return;
    show(data.output || (data.ok ? "Done." : "Failed."));
    return data;
  } catch (err) {
    show(err instanceof ApiTimeout
      ? "The server did not answer in time. Check the server list for the result."
      : err && err.name === "AbortError"
        ? "Cancelled. The server may still finish the action; check the server list."
        : "The page could not reach the server.");
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

function service(action, label) {
  if (action === "stop" || action === "restart") {
    ask(
      `<form><p>${esc(label)}</p><div class="row-actions"><button type="button" data-cancel>Cancel</button><button type="submit">Continue</button></div></form>`,
      () => { dlg.close(); run({cmd: "service", action}, label); }
    );
    return;
  }
  run({cmd: "service", action}, label);
}

document.getElementById("svc-start").onclick = () => service("start", "Starting the boot service…");
document.getElementById("svc-stop").onclick = () => service("stop", "Stop every indexed server and the boot service?");
document.getElementById("svc-restart").onclick = () => service("restart", "Restart every indexed server through the boot service?");
document.getElementById("svc-enable").onclick = () => service("enable", "Enabling the boot service…");
document.getElementById("svc-disable").onclick = () => service("disable", "Disabling the boot service…");
document.getElementById("logout").onclick = async () => {
  await fetch("/logout", {method: "POST"});
  location.href = "/login";
};
document.addEventListener("click", (ev) => {
  const menu = document.getElementById("svc-menu");
  if (!menu.open) return;
  if (menu.contains(ev.target)) {
    if (ev.target.closest("button")) menu.open = false;
    return;
  }
  menu.open = false;
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

function row(pack) {
  const port = pack.port === "-" ? "" : pack.port;
  const indexBtn = pack.indexed
    ? `<button type="button" data-act="disable">Disable</button>`
    : `<button type="button" data-act="enable">Enable</button>`;
  const runBtns = pack.indexed
    ? `<button type="button" data-act="start">Start</button>
      <button type="button" data-act="stop">Stop</button>
      <button type="button" data-act="restart">Restart</button>`
    : "";
  // Installed packs are not started from the page, so they have no status or usage columns.
  const usage = pack.indexed
    ? `<td class="status ${esc(pack.status)}" data-label="Status">${esc(pack.status)}</td>
    <td data-cpu data-label="CPU">${esc(pack.cpu)}</td>
    <td data-ram data-label="RAM">${esc(pack.ram)}</td>
    <td data-uptime data-label="Uptime">${esc(pack.uptime)}</td>`
    : "";
  return `<tr data-name="${esc(pack.name)}">
    <td data-pack-name>${esc(pack.name)}</td>
    <td class="${javaWarning(pack) ? "java-warn" : ""}" data-label="Java" title="${esc(javaWarning(pack))}">${esc(javaText(pack))}</td>
    <td data-label="Port"><input type="number" min="1" max="65535" value="${esc(port)}" data-port> <button type="button" data-act="port">Set</button>
      <div class="port-warn" data-port-warn>${esc(portWarning(pack))}</div></td>
    ${usage}
    <td class="actions">
      ${runBtns}
      ${indexBtn}
      <button type="button" data-act="log">Log</button>
      <button type="button" data-act="props" aria-haspopup="menu" title="Edit server.properties">Properties &#9662;</button>
      <button type="button" data-act="update">Update</button>
      <button type="button" class="danger" data-act="uninstall">Uninstall</button>
      <span class="loadbar" hidden role="progressbar" aria-label="Working"><span></span></span>
    </td>
  </tr>`;
}

function table(title, rows, usage) {
  if (!rows.length) return "";
  const usageHead = usage ? "<th>Status</th><th>CPU</th><th>RAM</th><th>Uptime</th>" : "";
  return `<h2>${esc(title)}</h2><table>
    <thead><tr><th>Modpack</th><th>Java</th><th>Port</th>${usageHead}<th></th></tr></thead>
    <tbody>${rows.map(row).join("")}</tbody></table>`;
}

function paintDot(id, good, label) {
  const el = document.getElementById(id);
  const text = label || "unknown";
  el.classList.toggle("on", !!good);
  el.title = text;
  el.setAttribute("aria-label", text);
}

function render() {
  const indexed = packs.filter((p) => p.indexed);
  const other = packs.filter((p) => !p.indexed);
  document.getElementById("packs").innerHTML =
    table("Active", indexed, true) + table("Installed", other, false);
}

function saveState() {
  try {
    if (out.textContent === "Loading…") return;
    const stick = out.scrollHeight - out.scrollTop - out.clientHeight < 48;
    localStorage.setItem("modman-page", JSON.stringify({
      packs,
      service: {
        active: document.getElementById("svc-dot").getAttribute("aria-label"),
        enabled: document.getElementById("boot-dot").getAttribute("aria-label")
      },
      consoleName,
      consoleOffset,
      actionText,
      consoleText: out.textContent,
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
  out.textContent = typeof saved.consoleText === "string" ? saved.consoleText : actionText;
  if (saved.consoleStick) out.scrollTop = out.scrollHeight;
  else if (Number.isFinite(saved.consoleScroll)) out.scrollTop = saved.consoleScroll;
  return true;
}

function updateVisibleStatus() {
  for (const pack of packs) {
    const tr = document.querySelector(`#packs tr[data-name="${CSS.escape(pack.name)}"]`);
    if (!tr) continue;
    const statusCell = tr.querySelector(".status");
    const cells = tr.children;
    if (statusCell) {
      statusCell.className = `status ${pack.status}`;
      statusCell.textContent = pack.status;
    }
    cells[1].textContent = javaText(pack);
    cells[1].className = javaWarning(pack) ? "java-warn" : "";
    cells[1].title = javaWarning(pack);
    const portInput = tr.querySelector("[data-port]");
    if (portInput && document.activeElement !== portInput) {
      const next = pack.port === "-" ? "" : String(pack.port);
      if (portInput.value !== next) portInput.value = next;
    }
    const warn = tr.querySelector("[data-port-warn]");
    if (warn) {
      const text = portWarning(pack);
      if (warn.textContent !== text) warn.textContent = text;
    }
    for (const [attr, text] of [["data-cpu", pack.cpu], ["data-ram", pack.ram], ["data-uptime", pack.uptime]]) {
      const cell = tr.querySelector(`[${attr}]`);
      if (cell && cell.textContent !== text) cell.textContent = text;
    }
  }
}

function syncPacks() {
  const rows = [...document.querySelectorAll("#packs tr[data-name]")];
  const same = rows.length === packs.length && rows.every((tr, i) => {
    const pack = packs[i];
    return tr.dataset.name === pack.name && !!tr.querySelector('[data-act="disable"]') === !!pack.indexed;
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
    actionText = out.textContent;
    consoleName = "";
    consoleOffset = 0;
  }
  document.getElementById("console-pack").value = consoleName;
  syncPick();
  setCommandEnabled(!!consoleName);
  if (!consoleName) out.textContent = actionText;
}

function trimConsole(text) {
  const lines = text.split("\n");
  const keep = text.endsWith("\n") ? 201 : 200;
  if (lines.length <= keep) return text;
  return lines.slice(lines.length - keep).join("\n");
}

function showConsole(text, replace) {
  const next = trimConsole(replace ? text : out.textContent + text);
  if (next === out.textContent) return;
  const nearBottom = out.scrollHeight - out.scrollTop - out.clientHeight < 48;
  out.textContent = next;
  if (nearBottom || replace) out.scrollTop = out.scrollHeight;
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
    out.textContent = actionText;
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
  setConsoleBusy(true);
  try {
    const data = await api("/api/command", {name, command});
    if (!data) return;
    if (!data.ok) msg.textContent = data.output || "Failed.";
    else input.value = "";
    await refreshConsole(true);
  } catch {
    msg.textContent = "The page could not reach the server.";
  } finally {
    setConsoleBusy(false);
  }
  setTimeout(refreshConsole, 500);
};

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
    if (data && data.output) show(data.output);
    return;
  }
  packs = data.packs;
  fillConsolePacks();
  const svc = data.service || {};
  paintDot("svc-dot", svc.active === "active", svc.active);
  paintDot("boot-dot", svc.enabled === "enabled", svc.enabled);
  syncPacks();
  if (out.textContent === "Loading…" && !consoleName) out.textContent = actionText;
  saveState();
  packsBusy = false;
  refreshConsole();
}

document.getElementById("packs").onclick = async (ev) => {
  const btn = ev.target.closest("button");
  if (!btn || rowBusy) return;
  const tr = btn.closest("tr");
  const name = tr.dataset.name;
  const act = btn.dataset.act;
  const pack = packs.find((p) => p.name === name);
  if ((act === "start" || act === "stop" || act === "restart") && (!pack || !pack.indexed)) return;
  if (act === "port") {
    const port = tr.querySelector("[data-port]").value;
    run({cmd: "port", name, port}, `Setting ${name} port to ${port}…`);
    return;
  }
  if (act === "props") {
    if (propsMenu.dataset.name === name && !propsMenu.hidden) closeProps(true);
    else openProps(btn, name);
    return;
  }
  if (act === "log") {
    // The console sits below the list, often off screen.
    const reduce = matchMedia("(prefers-reduced-motion: reduce)").matches;
    document.querySelector(".console-head").scrollIntoView({behavior: reduce ? "auto" : "smooth", block: "start"});
    // A running server streams into the console. A stopped one shows its last log once.
    if (runningPacks().some((p) => p.name === name)) {
      followConsole(name);
      return;
    }
    hold = true;
    show(`Reading ${name} log…`);
    try {
      const data = await api("/api/log?name=" + encodeURIComponent(name) + "&offset=0");
      if (data) show(data.ok === false ? (data.output || "Could not read the log.") : `${name} is not running. Last log:\n\n${data.output || "(empty)"}`);
    } catch {
      show("The page could not reach the server.");
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
      if (String(fields.confirm).toLowerCase() !== "yes") { show("Cancelled."); return; }
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
      <p>Update <strong>${esc(name)}</strong>.</p>
      ${search}
      <p id="upd-check" class="upd-check muted">${pack && pack.curseforge ? "Checking CurseForge…" : "Pick a modpack to see its newest version."}</p>
      <label><input type="radio" name="world" value="keep" checked> Keep the world</label>
      <label><input type="radio" name="world" value="delete"> Delete the world</label>
      <label id="del-label" hidden>Type yes to delete the world <input name="delete_confirm" autocomplete="off"></label>
      <label>Type yes to update <input name="confirm" autocomplete="off" required></label>
      <div class="row-actions"><button type="button" data-cancel>Cancel</button><button type="submit" id="upd-go" disabled>Update</button></div>
    </form>`, (fields) => {
      if (!checked) return;
      const world = fields.world || "keep";
      if (String(fields.confirm).toLowerCase() !== "yes") { show("Cancelled."); dlg.close(); return; }
      if (world === "delete" && String(fields.delete_confirm || "").toLowerCase() !== "yes") {
        show("Cancelled. Type yes to delete the world.");
        return;
      }
      if (!(pack && pack.curseforge) && !fields.mod_id) {
        show("Choose a CurseForge modpack first.");
        return;
      }
      dlg.close();
      const payload = {
        name, world,
        confirm: "yes",
        delete_confirm: world === "delete" ? "yes" : "",
        file: checked.file
      };
      if (fields.mod_id) payload.mod_id = fields.mod_id;
      finishServer(name, `Updating ${name}…`, () => api("/api/update", payload));
    });
    // The Update button stays off until a check shows there is something to
    // install. The file it showed goes with the request, so the server refuses
    // if a newer release lands in between.
    const checkLine = dlg.querySelector("#upd-check");
    const goBtn = dlg.querySelector("#upd-go");
    let checked = null;
    let checkTicket = 0;
    const checkUpdate = async (modId) => {
      const ticket = ++checkTicket;
      checked = null;
      goBtn.disabled = true;
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
      goBtn.disabled = !checked;
    };
    if (pack && pack.curseforge) checkUpdate("");
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
  run({cmd: act, name}, `${act} ${name}…`);
};

// The server.properties menu floats over the page, outside the table, so a
// table redraw or saved page state never holds a half-open menu.
const propsMenu = document.getElementById("props-menu");
let propsTicket = 0;
let propsAnchor = null;

function placeProps() {
  if (!propsAnchor || !propsAnchor.isConnected) return;
  const r = propsAnchor.getBoundingClientRect();
  const width = propsMenu.offsetWidth;
  const left = Math.max(8, Math.min(r.left, document.documentElement.clientWidth - width - 8));
  propsMenu.style.left = (left + window.scrollX) + "px";
  propsMenu.style.top = (r.bottom + window.scrollY + 3) + "px";
}

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

function clearSearch() {
  if (searchAbort) searchAbort.abort();
  document.getElementById("search-q").value = "";
  document.getElementById("search-results").innerHTML = "";
  if (actionText.startsWith("Searching for ")) {
    actionText = "";
    if (consoleName === "") out.textContent = "";
    saveState();
  }
}

document.getElementById("search-clear").onclick = clearSearch;

document.getElementById("search-form").onsubmit = async (ev) => {
  ev.preventDefault();
  if (searchAbort) searchAbort.abort();
  const query = document.getElementById("search-q").value;
  const ctrl = new AbortController();
  searchAbort = ctrl;
  hold = true;
  show(`Searching for ${query}…`);
  try {
    const data = await api("/api/search", {query}, ctrl.signal);
    if (searchAbort !== ctrl) return;
    const list = document.getElementById("search-results");
    list.innerHTML = "";
    if (!data) return;
    show(data.output || "");
    (data.results || []).forEach((item) => {
      const b = document.createElement("button");
      b.type = "button";
      b.innerHTML = `<strong>${esc(item.name)}</strong> <span class="muted">${esc(item.downloads)} downloads</span><br><span class="muted">${esc(item.summary || "")}</span>`;
      b.onclick = () => {
        if (!window.confirm(`Install ${item.name}?`)) return;
        hold = true;
        show(`Installing ${item.name}…`);
        api("/api/install", {id: String(item.id)}).then((res) => {
          if (res) show(res.output || (res.ok ? "Done." : "Failed."));
        }).catch((err) => {
          show(err instanceof ApiTimeout ? err.message : "The page could not reach the server.");
        }).finally(() => { hold = false; loadPacks(true); });
      };
      list.appendChild(b);
    });
  } catch (err) {
    if (!err || err.name !== "AbortError") show(String(err && err.message || err));
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

if (!restoreState()) out.textContent = "Loading…";
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
        return session_ok(self.cookie_token())

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
            self.send_html(200, APP_PAGE, APP_CSP)
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
        if not password_ok(given):
            login_failed(addr)
            time.sleep(1)
            self.redirect("/login?error=1")
            return
        login_succeeded(addr)
        token = new_session()
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
        self.finish_call([
            "command",
            str(body.get("name") or ""),
            str(body.get("command") or ""),
        ], 30)

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
