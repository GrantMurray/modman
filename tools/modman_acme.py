"""Sign and renew the webpage certificate for one domain.

Let's Encrypt connects to http://<domain>/.well-known/acme-challenge/<token>
on port 80. The webpage answers that from the http port.
"""

import base64
import hashlib
import json
import os
import re
import subprocess
import time
import urllib.error
import urllib.request

DIRECTORY = "https://acme-v02.api.letsencrypt.org/directory"
DOMAIN_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$")


class ACMEError(Exception):
    pass


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def valid_domain(name):
    return bool(name) and bool(DOMAIN_RE.fullmatch(name))


def certificate_matches(path, domain):
    """True when the certificate names the domain and lasts more than 30 days."""
    if not path or not os.path.isfile(path) or not valid_domain(domain):
        return False
    proc = subprocess.run(
        ["openssl", "x509", "-in", path, "-noout", "-ext", "subjectAltName", "-checkend", "2592000"],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        return False
    return f"DNS:{domain}" in proc.stdout


def _openssl(args, input_bytes=None):
    proc = subprocess.run(args, input=input_bytes, capture_output=True)
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or b"").decode("utf-8", "replace").strip()
        raise ACMEError(detail or "openssl failed")
    return proc.stdout


def _ensure_rsa(path):
    if os.path.isfile(path) and os.path.getsize(path) > 0:
        return
    os.makedirs(os.path.dirname(path), exist_ok=True)
    _openssl(["openssl", "genrsa", "-out", path, "2048"])
    os.chmod(path, 0o600)


def _rsa_jwk(path):
    text = _openssl(["openssl", "rsa", "-in", path, "-noout", "-modulus", "-text"]).decode("ascii", "replace")
    modulus = re.search(r"Modulus=([0-9A-Fa-f]+)", text)
    exponent = re.search(r"publicExponent:\s+(\d+)", text)
    if not modulus or not exponent:
        raise ACMEError("could not read the account key")
    n_bytes = bytes.fromhex(modulus.group(1)).lstrip(b"\x00") or b"\x00"
    e_num = int(exponent.group(1))
    e_bytes = e_num.to_bytes((e_num.bit_length() + 7) // 8, "big")
    return {"e": b64(e_bytes), "kty": "RSA", "n": b64(n_bytes)}


def _thumbprint(jwk):
    raw = json.dumps(jwk, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return b64(hashlib.sha256(raw).digest())


class Client:
    def __init__(self, account_key):
        self.account_key = account_key
        self.jwk = _rsa_jwk(account_key)
        self.thumb = _thumbprint(self.jwk)
        self.kid = None
        self.nonce = None
        req = urllib.request.Request(DIRECTORY)
        with urllib.request.urlopen(req, timeout=30) as resp:
            self.directory = json.loads(resp.read().decode("utf-8"))

    def _nonce(self):
        if self.nonce:
            return
        req = urllib.request.Request(self.directory["newNonce"], method="HEAD")
        with urllib.request.urlopen(req, timeout=30) as resp:
            self.nonce = resp.headers["Replay-Nonce"]

    def post(self, url, payload, accept=None, retried=False):
        self._nonce()
        protected = {"alg": "RS256", "nonce": self.nonce, "url": url}
        if self.kid:
            protected["kid"] = self.kid
        else:
            protected["jwk"] = self.jwk
        protected_b = b64(json.dumps(protected, separators=(",", ":"), sort_keys=True).encode("utf-8"))
        if payload is None:
            payload_bytes = b""
        else:
            payload_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        signature = _openssl(
            ["openssl", "dgst", "-sha256", "-sign", self.account_key],
            protected_b.encode("ascii") + b"." + b64(payload_bytes).encode("ascii"),
        )
        body = json.dumps({
            "protected": protected_b,
            "payload": b64(payload_bytes),
            "signature": b64(signature),
        }).encode("utf-8")
        self.nonce = None
        headers = {"Content-Type": "application/jose+json"}
        if accept:
            headers["Accept"] = accept
        req = urllib.request.Request(url, data=body, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                self.nonce = resp.headers.get("Replay-Nonce")
                raw = resp.read()
                location = resp.headers.get("Location")
                parsed = json.loads(raw.decode("utf-8")) if raw and "json" in resp.headers.get("Content-Type", "") else raw
                return parsed, location
        except urllib.error.HTTPError as err:
            self.nonce = err.headers.get("Replay-Nonce")
            detail = err.read().decode("utf-8", "replace")
            if err.code == 400 and "badNonce" in detail and not retried:
                self.nonce = None
                return self.post(url, payload, accept=accept, retried=True)
            raise ACMEError(detail or f"signing request failed ({err.code})") from err


def _poll(client, url):
    for _ in range(40):
        obj, _location = client.post(url, None)
        status = obj.get("status") if isinstance(obj, dict) else ""
        if status in ("ready", "valid", "invalid"):
            return obj
        time.sleep(2)
    raise ACMEError("timed out waiting for the certificate")


def ensure(domain, cert_path, key_path, account_key_path, challenge_dir):
    """Issue or renew a certificate for domain. Leaves cert_path in place on failure."""
    if not valid_domain(domain):
        raise ACMEError(f"invalid domain: {domain}")
    if certificate_matches(cert_path, domain):
        return False
    _ensure_rsa(account_key_path)
    _ensure_rsa(key_path)
    os.makedirs(challenge_dir, exist_ok=True)
    client = Client(account_key_path)
    _account, kid = client.post(client.directory["newAccount"], {"termsOfServiceAgreed": True})
    if not kid:
        raise ACMEError("the certificate authority did not return an account")
    client.kid = kid
    order, order_url = client.post(
        client.directory["newOrder"],
        {"identifiers": [{"type": "dns", "value": domain}]},
    )
    if not order_url:
        raise ACMEError("the certificate authority did not return an order")
    token_files = []
    csr_pem = os.path.join(challenge_dir, "request.pem")
    try:
        for auth_url in order.get("authorizations") or []:
            auth, _location = client.post(auth_url, None)
            challenge = next((item for item in auth.get("challenges") or [] if item.get("type") == "http-01"), None)
            if not challenge:
                raise ACMEError("no http signing check was offered")
            token = challenge["token"]
            if not re.fullmatch(r"[A-Za-z0-9_-]{8,128}", token):
                raise ACMEError("the signing check token was rejected")
            keyauth = f"{token}.{client.thumb}"
            path = os.path.join(challenge_dir, token)
            with open(path, "w", encoding="ascii") as fh:
                fh.write(keyauth)
            os.chmod(path, 0o644)
            token_files.append(path)
            check_url = f"http://{domain}/.well-known/acme-challenge/{token}"
            try:
                with urllib.request.urlopen(check_url, timeout=20) as resp:
                    seen = resp.read().decode("utf-8", "replace").strip()
            except urllib.error.URLError as err:
                raise ACMEError(f"could not reach {check_url}: {err}") from err
            if seen != keyauth:
                raise ACMEError(f"{check_url} did not return the signing check")
            client.post(challenge["url"], {})
            auth = _poll(client, auth_url)
            if auth.get("status") != "valid":
                detail = ""
                for item in auth.get("challenges") or []:
                    problem = item.get("error") or {}
                    detail = problem.get("detail") or detail
                raise ACMEError(detail or "the signing check failed")
        order = _poll(client, order_url)
        if order.get("status") == "ready":
            _openssl([
                "openssl", "req", "-new", "-key", key_path, "-out", csr_pem,
                "-subj", f"/CN={domain}",
                "-addext", f"subjectAltName=DNS:{domain}",
            ])
            csr_der = _openssl(["openssl", "req", "-in", csr_pem, "-outform", "DER"])
            client.post(order["finalize"], {"csr": b64(csr_der)})
            order = _poll(client, order_url)
        if order.get("status") != "valid" or not order.get("certificate"):
            raise ACMEError("the certificate was not issued")
        chain, _location = client.post(order["certificate"], None, accept="application/pem-certificate-chain")
        if isinstance(chain, bytes):
            pem = chain
        else:
            raise ACMEError("the certificate download was empty")
        if b"BEGIN CERTIFICATE" not in pem:
            raise ACMEError("the certificate download was not a certificate")
        tmp_cert = cert_path + ".tmp"
        os.makedirs(os.path.dirname(cert_path), exist_ok=True)
        with open(tmp_cert, "wb") as fh:
            fh.write(pem)
        os.chmod(tmp_cert, 0o644)
        os.replace(tmp_cert, cert_path)
        return True
    finally:
        for path in token_files:
            try:
                os.remove(path)
            except OSError:
                pass
        try:
            os.remove(csr_pem)
        except OSError:
            pass
