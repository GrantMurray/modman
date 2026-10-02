#!/usr/bin/env python3
"""Local control page for modman. Started by `web start`, not run on its own."""

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
    PASSWORD_HEX = fh.read().strip().lower()
os.remove(PASSWORD_FILE)
if len(PASSWORD_HEX) != 64 or any(ch not in "0123456789abcdef" for ch in PASSWORD_HEX):
    sys.stderr.write("Error: password hash is invalid.\n")
    sys.exit(1)
if not BIN:
    sys.stderr.write("Error: MODMAN_BIN is not set.\n")
    sys.exit(1)

sessions = set()
sessions_lock = threading.Lock()
call_lock = threading.Lock()


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
    given = given.strip().lower()
    if len(given) != len(PASSWORD_HEX):
        return False
    return hmac.compare_digest(PASSWORD_HEX, given)


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
function sha256hex(text) {
  function rotr(x, n) { return (x >>> n) | (x << (32 - n)); }
  const K = [
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
  ];
  const msg = new TextEncoder().encode(text);
  const total = ((msg.length + 9 + 63) >> 6) << 6;
  const buf = new Uint8Array(total);
  buf.set(msg);
  buf[msg.length] = 0x80;
  const view = new DataView(buf.buffer);
  view.setUint32(total - 4, msg.length * 8, false);
  let h0=0x6a09e667,h1=0xbb67ae85,h2=0x3c6ef372,h3=0xa54ff53a;
  let h4=0x510e527f,h5=0x9b05688c,h6=0x1f83d9ab,h7=0x5be0cd19;
  const w = new Uint32Array(64);
  for (let i = 0; i < buf.length; i += 64) {
    for (let t = 0; t < 16; t++) w[t] = view.getUint32(i + t * 4, false);
    for (let t = 16; t < 64; t++) {
      const s0 = rotr(w[t-15], 7) ^ rotr(w[t-15], 18) ^ (w[t-15] >>> 3);
      const s1 = rotr(w[t-2], 17) ^ rotr(w[t-2], 19) ^ (w[t-2] >>> 10);
      w[t] = (w[t-16] + s0 + w[t-7] + s1) >>> 0;
    }
    let a=h0,b=h1,c=h2,d=h3,e=h4,f=h5,g=h6,h=h7;
    for (let t = 0; t < 64; t++) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const t1 = (h + S1 + ch + K[t] + w[t]) >>> 0;
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) >>> 0;
      h=g; g=f; f=e; e=(d + t1) >>> 0; d=c; c=b; b=a; a=(t1 + t2) >>> 0;
    }
    h0=(h0+a)>>>0; h1=(h1+b)>>>0; h2=(h2+c)>>>0; h3=(h3+d)>>>0;
    h4=(h4+e)>>>0; h5=(h5+f)>>>0; h6=(h6+g)>>>0; h7=(h7+h)>>>0;
  }
  return [h0,h1,h2,h3,h4,h5,h6,h7].map((x) => x.toString(16).padStart(8, "0")).join("");
}
document.getElementById("login").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const input = document.getElementById("password");
  const hash = sha256hex(input.value);
  input.value = "";
  const res = await fetch("/login", {
    method: "POST",
    headers: {"Content-Type": "application/x-www-form-urlencoded"},
    body: "password=" + encodeURIComponent(hash),
    redirect: "manual"
  });
  location.href = res.headers.get("Location") || "/";
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
  .actions { display: flex; flex-wrap: wrap; gap: 0.3rem; }
  .actions input[type="number"] { width: 5.5rem; font: inherit; padding: 0.2rem; }
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
    <select id="console-pack" aria-label="Modpack"></select>
    <input id="console-cmd" type="text" maxlength="300" placeholder="Command" autocomplete="off">
    <button type="submit">Send</button>
  </form>
  <p id="console-msg" class="muted"></p>
  <pre id="out">Loading…</pre>
</main>
<dialog id="dlg"></dialog>
<script>
const out = document.getElementById("out");
const dlg = document.getElementById("dlg");
let hold = false;
let packs = [];
let searchAbort = null;
let consoleName = "";
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
  out.textContent = text || "";
}

async function run(payload, label) {
  hold = true;
  show(label || "Working…");
  try {
    const data = await api("/api/run", payload);
    if (!data) return;
    show(data.output || (data.ok ? "Done." : "Failed."));
  } finally {
    hold = false;
    loadPacks();
  }
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
  return `<tr data-name="${esc(pack.name)}">
    <td>${esc(pack.name)}</td>
    <td>${esc(pack.java)}</td>
    <td><input type="number" min="1" max="65535" value="${esc(port)}" data-port> <button type="button" data-act="port">Set</button></td>
    <td class="status ${esc(pack.status)}">${esc(pack.status)}</td>
    <td>${esc(pack.cpu)}</td>
    <td>${esc(pack.ram)}</td>
    <td>${esc(pack.uptime)}</td>
    <td class="actions">
      <button type="button" data-act="start">Start</button>
      <button type="button" data-act="stop">Stop</button>
      <button type="button" data-act="restart">Restart</button>
      ${indexBtn}
      <button type="button" data-act="update">Update</button>
      <button type="button" class="danger" data-act="uninstall">Uninstall</button>
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
  const same = names.length === sel.options.length && names.every((name, i) => sel.options[i].value === name);
  const previous = sel.value;
  if (!same) {
    sel.innerHTML = names.map((name) => `<option value="${esc(name)}">${esc(name)}</option>`).join("");
  }
  const keep = names.includes(consoleName) ? consoleName : (names.includes(previous) ? previous : (names[0] || ""));
  if (keep) sel.value = keep;
  if (consoleName && !names.includes(consoleName)) {
    consoleName = "";
    consoleOffset = 0;
  }
  if (!consoleName && sel.value && names.includes(sel.value)) consoleName = sel.value;
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
}

async function refreshConsole(force) {
  if (!consoleName || hold || dlg.open) return;
  if (consoleBusy && !force) return;
  const ticket = ++consoleTicket;
  const name = consoleName;
  const offset = consoleOffset;
  const data = await api("/api/log?name=" + encodeURIComponent(name) + "&offset=" + offset);
  if (ticket !== consoleTicket || !data || hold || name !== consoleName) return;
  if (data.ok === false) {
    document.getElementById("console-msg").textContent = data.output || "Failed.";
    return;
  }
  if (Number.isFinite(data.offset) && data.offset >= 0) consoleOffset = data.offset;
  const chunk = data.output || "";
  const replace = !!data.reset || offset === 0;
  if (!replace && !chunk) return;
  showConsole(chunk, replace);
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
  followConsole(document.getElementById("console-pack").value);
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
  if (hold || dlg.open) return;
  const data = await api("/api/packs");
  if (!data || !data.packs) {
    if (data && data.output) show(data.output);
    return;
  }
  packs = data.packs;
  fillConsolePacks();
  const svc = data.service || {};
  paintDot("svc-dot", svc.active === "active", svc.active);
  paintDot("boot-dot", svc.enabled === "enabled", svc.enabled);
  if (document.activeElement && document.activeElement.matches("input")) {
    refreshConsole();
    return;
  }
  render();
  if (out.textContent === "Loading…" && !consoleName) show("");
  refreshConsole();
}

document.getElementById("packs").onclick = async (ev) => {
  const btn = ev.target.closest("button");
  if (!btn) return;
  const tr = btn.closest("tr");
  const name = tr.dataset.name;
  const act = btn.dataset.act;
  const pack = packs.find((p) => p.name === name);
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
      hold = true;
      show(`Updating ${name}…`);
      api("/api/update", payload).then((data) => {
        if (data) show(data.output || (data.ok ? "Done." : "Failed."));
      }).finally(() => { hold = false; loadPacks(); });
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
  if (out.textContent.startsWith("Searching for ")) show("");
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

loadPacks();
setInterval(loadPacks, 5000);
setInterval(refreshConsole, 2000);
</script>
</body>
</html>
"""


class Handler(BaseHTTPRequestHandler):
    # Browsers drop an https page that answers HTTP/1.0.
    protocol_version = "HTTP/1.1"
    server_version = "modman"
    timeout = 60

    def log_message(self, fmt, *args):
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

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
        token = self.cookie_token()
        with sessions_lock:
            return token in sessions

    def send_html(self, code, html):
        data = html.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
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

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path.startswith("/.well-known/acme-challenge/"):
            body = acme_challenge(parsed.path[len("/.well-known/acme-challenge/"):])
            if body is None:
                self.send_response(404)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if parsed.path == "/modman-ca.crt":
            self.send_ca()
            return
        if parsed.path == "/favicon.ico":
            self.send_response(204)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if parsed.path == "/login":
            error = "<p class=\"err\">Wrong password.</p>" if "error=1" in (parsed.query or "") else ""
            self.send_html(200, LOGIN_PAGE.replace("__ERROR__", error))
            return
        if parsed.path == "/":
            if not self.authed():
                self.redirect("/login")
                return
            self.send_html(200, APP_PAGE)
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
                sessions.discard(token)
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
        fields = parse_qs(raw.decode("utf-8", "replace"), keep_blank_values=True)
        given = (fields.get("password") or [""])[0]
        if not password_ok(given):
            time.sleep(1)
            self.redirect("/login?error=1")
            return
        token = secrets.token_urlsafe(32)
        with sessions_lock:
            sessions.add(token)
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


class HTTPSServer(ThreadingHTTPServer):
    tls = True

    def __init__(self, address, handler, context):
        self.tls_context = context
        super().__init__(address, handler)

    def get_request(self):
        sock, addr = super().get_request()
        try:
            return self.tls_context.wrap_socket(sock, server_side=True), addr
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
    http = ThreadingHTTPServer((BIND, HTTP_PORT), Handler)
    http.tls = False
    threading.Thread(target=http.serve_forever, daemon=True).start()
    if domain:
        threading.Thread(target=sign_loop, args=(domain,), daemon=True).start()
    sys.stdout.write(f"listening {PORT}\n")
    sys.stdout.flush()
    https.serve_forever()


if __name__ == "__main__":
    main()
