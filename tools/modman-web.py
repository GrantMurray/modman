#!/usr/bin/env python3
"""Local control page for modman. Started by `web start`, not run on its own."""

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
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


LOGIN_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>modman</title>
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
  #out { white-space: pre-wrap; background: #1c1c1c; color: #f3f0e8; padding: 0.8rem; min-height: 2.5rem; max-height: 24rem; overflow: auto; }
  dialog { border: 1px solid #ccc; padding: 1rem; max-width: 28rem; }
  dialog label { display: block; margin: 0.5rem 0; }
  dialog [hidden] { display: none; }
  dialog input[type="text"], dialog input[type="search"] { font: inherit; padding: 0.3rem; width: 100%; box-sizing: border-box; }
  .results { list-style: none; padding: 0; margin: 0.4rem 0; max-height: 12rem; overflow: auto; }
  .results button { display: block; width: 100%; text-align: left; margin-bottom: 0.25rem; }
  .results button.on { outline: 2px solid #1f3d2d; }
  .muted { color: #555; font-size: 0.9rem; }
  .row-actions { display: flex; gap: 0.4rem; justify-content: flex-end; margin-top: 0.8rem; }
  .svc-state { display: inline-flex; align-items: center; gap: 0.35rem; }
  .dot { width: 0.7rem; height: 0.7rem; border-radius: 50%; background: #e15d5d; }
  .dot.on { background: #3dce6e; }
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
    <select id="console-pack" aria-label="Modpack">
      <option value="">Actions</option>
    </select>
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
<script>
const out = document.getElementById("out");
const dlg = document.getElementById("dlg");
let hold = false;
let rowBusy = false;
let packsBusy = false;
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

async function api(path, body, signal) {
  const opts = {headers: {}, signal};
  if (body !== undefined) {
    opts.method = "POST";
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  const res = await fetch(path, opts);
  if (res.status === 401) {
    location.href = "/login";
    return null;
  }
  const text = await res.text();
  try { return JSON.parse(text); }
  catch { return {ok: false, output: text}; }
}

function show(text) {
  actionText = text || "";
  consoleName = "";
  consoleOffset = 0;
  const sel = document.getElementById("console-pack");
  if ([...sel.options].some((opt) => opt.value === "")) sel.value = "";
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
  try {
    const data = await request();
    if (!data) return;
    show(data.output || (data.ok ? "Done." : "Failed."));
  } catch {
    show("The page could not reach the server.");
  } finally {
    if (name) setServerBusy(name, false);
    else rowBusy = false;
    hold = false;
    loadPacks();
  }
}

async function run(payload, label) {
  await finishServer(payload.name || "", label, () => api("/api/run", payload));
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
  return `<tr data-name="${esc(pack.name)}">
    <td>${esc(pack.name)}</td>
    <td>${esc(pack.java)}</td>
    <td><input type="number" min="1" max="65535" value="${esc(port)}" data-port> <button type="button" data-act="port">Set</button></td>
    <td class="status ${esc(pack.status)}">${esc(pack.status)}</td>
    <td>${esc(pack.cpu)}</td>
    <td>${esc(pack.ram)}</td>
    <td>${esc(pack.uptime)}</td>
    <td class="actions">
      ${runBtns}
      ${indexBtn}
      <button type="button" data-act="update">Update</button>
      <button type="button" class="danger" data-act="uninstall">Uninstall</button>
      <span class="loadbar" hidden role="progressbar" aria-label="Working"><span></span></span>
    </td>
  </tr>`;
}

function table(title, rows) {
  if (!rows.length) return "";
  return `<h2>${esc(title)}</h2><table>
    <thead><tr><th>Modpack</th><th>Java</th><th>Port</th><th>Status</th><th>CPU</th><th>RAM</th><th>Uptime</th><th></th></tr></thead>
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
    table("Active", indexed) + table("Installed", other);
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
  if (!document.querySelector("#packs tr")) render();
  const sel = document.getElementById("console-pack");
  const names = runningPacks().map((p) => p.name);
  sel.innerHTML = `<option value="">Actions</option>` + names.map((name) => `<option value="${esc(name)}">${esc(name)}</option>`).join("");
  const follow = !!(consoleName && names.includes(consoleName));
  sel.value = follow ? consoleName : "";
  document.getElementById("console-cmd").disabled = !follow;
  document.querySelector("#console-form button[type=submit]").disabled = !follow;
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
    if (!statusCell || cells.length < 7) continue;
    statusCell.className = `status ${pack.status}`;
    statusCell.textContent = pack.status;
    cells[1].textContent = pack.java;
    const portInput = tr.querySelector("[data-port]");
    if (portInput && document.activeElement !== portInput) {
      const next = pack.port === "-" ? "" : String(pack.port);
      if (portInput.value !== next) portInput.value = next;
    }
    cells[4].textContent = pack.cpu;
    cells[5].textContent = pack.ram;
    cells[6].textContent = pack.uptime;
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

function runningPacks() {
  return packs.filter((p) => p.status === "running");
}

function setConsoleBusy(on) {
  consoleBusy = on;
  document.getElementById("console-spin").hidden = !on;
  for (const el of document.querySelectorAll("#console-form select, #console-form input, #console-form button")) {
    el.disabled = on;
  }
}

function fillConsolePacks() {
  if (consoleBusy) return;
  const sel = document.getElementById("console-pack");
  if (document.activeElement === sel) return;
  const names = runningPacks().map((p) => p.name);
  const wanted = ["", ...names];
  const same = wanted.length === sel.options.length && wanted.every((name, i) => sel.options[i].value === name);
  if (!same) {
    sel.innerHTML = `<option value="">Actions</option>` + names.map((name) => `<option value="${esc(name)}">${esc(name)}</option>`).join("");
  }
  if (consoleName == null) consoleName = names[0] || "";
  else if (consoleName && !names.includes(consoleName)) {
    consoleName = names[0] || "";
    consoleOffset = 0;
  }
  sel.value = consoleName;
  if (!consoleName) {
    out.textContent = actionText;
    if (!consoleBusy) {
      document.getElementById("console-cmd").disabled = true;
      document.querySelector("#console-form button[type=submit]").disabled = true;
    }
  }
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

async function refreshConsole(force) {
  if (!consoleName || hold || dlg.open) return;
  if ((consoleBusy || logBusy) && !force) return;
  logBusy = true;
  const ticket = ++consoleTicket;
  const name = consoleName;
  const offset = consoleOffset;
  try {
    const data = await api("/api/log?name=" + encodeURIComponent(name) + "&offset=" + offset);
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
    logBusy = false;
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

async function loadPacks() {
  if (hold || rowBusy || dlg.open || packsBusy) return;
  packsBusy = true;
  let data;
  try {
    data = await api("/api/packs");
  } catch (err) {
    packsBusy = false;
    return;
  }
  if (hold || rowBusy || dlg.open) {
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
      <label><input type="radio" name="world" value="keep" checked> Keep the world</label>
      <label><input type="radio" name="world" value="delete"> Delete the world</label>
      <label id="del-label" hidden>Type yes to delete the world <input name="delete_confirm" autocomplete="off"></label>
      <label>Type yes to update <input name="confirm" autocomplete="off" required></label>
      <div class="row-actions"><button type="button" data-cancel>Cancel</button><button type="submit">Update</button></div>
    </form>`, (fields) => {
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
        delete_confirm: world === "delete" ? "yes" : ""
      };
      if (fields.mod_id) payload.mod_id = fields.mod_id;
      finishServer(name, `Updating ${name}…`, () => api("/api/update", payload));
    });
    dlg.querySelectorAll('input[name="world"]').forEach((el) => {
      el.onchange = () => {
        dlg.querySelector("#del-label").hidden = dlg.querySelector('input[name="world"]:checked').value !== "delete";
      };
    });
    const searchBtn = dlg.querySelector("#upd-search");
    if (searchBtn) {
      searchBtn.onclick = async () => {
        const query = dlg.querySelector('input[name="query"]').value;
        const data = await api("/api/search", {query});
        const list = dlg.querySelector("#upd-results");
        list.innerHTML = "";
        (data && data.results || []).forEach((item) => {
          const b = document.createElement("button");
          b.type = "button";
          b.textContent = `${item.name} (${item.downloads})`;
          b.onclick = () => {
            dlg.querySelector("#upd-id").value = item.id;
            list.querySelectorAll("button").forEach((n) => n.classList.remove("on"));
            b.classList.add("on");
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
        }).finally(() => { hold = false; loadPacks(); });
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

if (!restoreState()) out.textContent = "Loading…";
loadPacks();
setInterval(loadPacks, 5000);
setInterval(refreshConsole, 2000);
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
        super().handle()

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
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", csp)
        self.end_headers()
        self.wfile.write(data)

    def send_json(self, code, obj):
        data = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

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
            self.handle_log(name, offset)
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
        if parsed.path == "/api/run":
            self.handle_run(body)
            return
        if parsed.path == "/api/search":
            self.handle_search(body)
            return
        if parsed.path == "/api/install":
            self.handle_install(body)
            return
        if parsed.path == "/api/update":
            self.handle_update(body)
            return
        if parsed.path == "/api/command":
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

    def handle_log(self, name, offset):
        if not str(offset).isdigit() or len(str(offset)) > 18:
            offset = "0"
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
        elif cmd == "port":
            args.extend([name, str(body.get("port") or "")])
        elif cmd == "uninstall":
            args.extend([name, str(body.get("confirm") or "")])
        elif cmd == "service":
            args.append(str(body.get("action") or ""))
        else:
            self.send_json(400, {"ok": False, "output": "Unknown action."})
            return
        self.finish_call(args, 180)

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
        ], 3600)

    def finish_call(self, args, timeout):
        try:
            proc = modman_call(args, timeout)
        except subprocess.TimeoutExpired:
            self.send_json(504, {"ok": False, "output": "Timed out."})
            return
        self.send_json(200 if proc.returncode == 0 else 400, {
            "ok": proc.returncode == 0,
            "output": command_text(proc),
        })


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
