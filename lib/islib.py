"""Mini client REST pour WSO2 IS (stdlib uniquement)."""
import base64, getpass, json, os, ssl, sys, time, urllib.error, urllib.parse, urllib.request

_CTX = ssl.create_default_context()
_CTX.check_hostname = False
_CTX.verify_mode = ssl.CERT_NONE


class IS:
    def __init__(self, base, user="admin", password="admin", token=None):
        self.base = base.rstrip("/")
        self.auth = "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()
        if token:
            self.auth = "Bearer " + token

    def req(self, method, path, body=None, ok=(200, 201, 202, 204), ctype="application/json", raw=False):
        url = path if path.startswith("http") else self.base + path
        data = None
        if body is not None:
            data = body if isinstance(body, (bytes, str)) else json.dumps(body)
            data = data.encode() if isinstance(data, str) else data
        r = urllib.request.Request(url, data=data, method=method)
        r.add_header("Authorization", self.auth)
        r.add_header("Accept", "application/json")
        if data is not None:
            r.add_header("Content-Type", ctype)
        try:
            with urllib.request.urlopen(r, context=_CTX, timeout=60) as resp:
                txt = resp.read().decode()
                if raw:
                    return resp.status, txt, dict(resp.headers)
                return json.loads(txt) if txt.strip() else {"_headers": dict(resp.headers)}
        except urllib.error.HTTPError as e:
            txt = e.read().decode()
            if e.code in ok:
                return json.loads(txt) if txt.strip() else {}
            if e.code == 401:
                raise SystemExit(f"{self.base} : authentification refusée (utilisateur ou mot de passe incorrect)")
            raise RuntimeError(f"{method} {url} -> {e.code}: {txt[:600]}")

    get = lambda s, p, **k: s.req("GET", p, **k)
    post = lambda s, p, b=None, **k: s.req("POST", p, b, **k)
    put = lambda s, p, b=None, **k: s.req("PUT", p, b, **k)
    patch = lambda s, p, b=None, **k: s.req("PATCH", p, b, **k)
    delete = lambda s, p, **k: s.req("DELETE", p, **k)

    def try_(self, method, path, body=None, **k):
        try:
            return self.req(method, path, body, **k)
        except RuntimeError as e:
            return {"_error": str(e)}

    def wait_up(self, timeout=600):
        t0 = time.time()
        while time.time() - t0 < timeout:
            try:
                self.get("/api/server/v1/applications?limit=1")
                return True
            except Exception:
                time.sleep(5)
        raise SystemExit(f"IS {self.base} pas prêt après {timeout}s")


def log(*a):
    print(*a, file=sys.stderr, flush=True)


def credentials(url):
    """Identifiants admin : IS_USER / IS_PASSWORD s'ils sont définis, sinon saisie interactive (mot de passe masqué)."""
    user = os.environ.get("IS_USER")
    if not user:
        sys.stderr.write(f"Utilisateur pour {url} [admin] : ")
        sys.stderr.flush()
        user = sys.stdin.readline().strip() or "admin"
    pwd = os.environ.get("IS_PASSWORD") or getpass.getpass(f"Mot de passe de {user} : ")
    if not pwd:
        sys.exit("mot de passe vide")
    return user, pwd
