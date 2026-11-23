"""In-memory stand-ins for the Cloudflare and Kubernetes APIs, served over real
HTTP so the client's URLs, query strings and bodies are exercised as sent.

Shapes follow Cloudflare's published OpenAPI schema (github.com/cloudflare/api-schemas):
list endpoints return result_info, tunnel lists carry total_count but not
total_pages, a missing entry point ruleset is a 404, and PUT ?dry_run=true
validates without saving.
"""
import base64
import copy
import itertools
import json
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

_ids = itertools.count(1)


def new_id(prefix):
    return f"{prefix}{next(_ids):04d}"


class Server:
    def __init__(self, handler):
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _do(self):
                u = urllib.parse.urlsplit(self.path)
                q = dict(urllib.parse.parse_qsl(u.query))
                n = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(n)) if n else None
                status, doc = handler(self.command, u.path, q, body, self.headers)
                raw = json.dumps(doc).encode() if doc is not None else b""
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = _do

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


def ok(result, info=None):
    doc = {"success": True, "errors": [], "messages": [], "result": result}
    if info is not None:
        doc["result_info"] = info
    return 200, doc


def err(status, message):
    return status, {"success": False, "errors": [{"code": 1000, "message": message}],
                    "messages": [], "result": None}


def page(items, q, style="pages"):
    p, per = int(q.get("page", 1)), int(q.get("per_page", 20))
    chunk = items[(p - 1) * per: p * per]
    info = {"page": p, "per_page": per, "count": len(chunk)}
    if style == "pages":
        info["total_pages"] = max(1, -(-len(items) // per))
        info["total_count"] = len(items)
    elif style == "count":
        info["total_count"] = len(items)
    return ok(copy.deepcopy(chunk), info)


class FakeCloudflare:
    ACCOUNT = "acct1"
    TOKEN = "cf-test-token"

    def __init__(self):
        self.tunnels, self.configs, self.tokens = [], {}, {}
        self.zones = {"example.com": "zone1", "example.org": "zone2"}
        self.dns, self.rulesets, self.apps, self.tags = [], {}, [], []
        self.requests = []
        self.server = Server(self.handle)
        self.url = self.server.url

    def writes(self):
        return [(m, p) for m, p, q, b in self.requests
                if m != "GET" and q.get("dry_run") != "true"]

    # -- helpers for tests
    def add_tunnel(self, name, remote=True, config=None):
        t = {"id": new_id("tun-"), "name": name, "remote_config": remote,
             "config_src": "cloudflare" if remote else "local", "deleted_at": None}
        self.tunnels.append(t)
        self.tokens[t["id"]] = "run-token-" + t["id"]
        if config is not None:
            self.configs[t["id"]] = config
        return t

    def handle(self, method, path, q, body, headers):
        self.requests.append((method, path, q, body))
        if headers.get("Authorization") != f"Bearer {self.TOKEN}":
            return err(403, "Authentication error")
        parts = path.strip("/").split("/")
        acct = f"/accounts/{self.ACCOUNT}"

        # ---- tunnels
        if path == f"{acct}/cfd_tunnel":
            if method == "GET":
                items = [t for t in self.tunnels
                         if t["name"] == q.get("name", t["name"])
                         and not (q.get("is_deleted") == "false" and t["deleted_at"])]
                return page(items, q, style="count")
            if method == "POST":
                t = self.add_tunnel(body["name"], remote=body.get("config_src") == "cloudflare")
                return ok(copy.deepcopy(t))
        if path.startswith(f"{acct}/cfd_tunnel/"):
            tid, what = parts[3], parts[4]
            if what == "configurations":
                if method == "GET":
                    if tid not in self.configs:
                        return ok({"tunnel_id": tid, "config": None, "version": 0})
                    return ok({"tunnel_id": tid, "config": copy.deepcopy(self.configs[tid]),
                               "source": "cloudflare", "version": 1})
                if method == "PUT":
                    cfg = copy.deepcopy(body["config"])
                    # Cloudflare echoes back extra keys; the client must ignore them.
                    for r in cfg["ingress"]:
                        r.setdefault("originRequest", {})
                    cfg.setdefault("warp-routing", {"enabled": False})
                    self.configs[tid] = cfg
                    return ok({"tunnel_id": tid, "config": cfg})
            if what == "token" and method == "GET":
                return ok(self.tokens[tid])

        # ---- zones + DNS
        if path == "/zones" and method == "GET":
            items = [{"id": i, "name": n} for n, i in self.zones.items() if n == q.get("name", n)]
            return page(items, q)
        if len(parts) >= 3 and parts[0] == "zones" and parts[2] == "dns_records":
            zid = parts[1]
            if len(parts) == 3 and method == "GET":
                items = [r for r in self.dns if r["zone_id"] == zid
                         and r["name"] == q.get("name.exact", r["name"])
                         and r.get("comment") == q.get("comment.exact", r.get("comment"))
                         and r["type"] == q.get("type", r["type"])]
                return page(items, q)
            if len(parts) == 3 and method == "POST":
                r = dict(body, id=new_id("dns-"), zone_id=zid)
                self.dns.append(r)
                return ok(copy.deepcopy(r))
            rec = next(r for r in self.dns if r["id"] == parts[3])
            if method == "PATCH":
                rec.update(body)
                return ok(copy.deepcopy(rec))
            if method == "DELETE":
                self.dns.remove(rec)
                return ok({"id": rec["id"]})

        # ---- rulesets
        if len(parts) == 6 and parts[0] == "zones" and parts[2] == "rulesets":
            key = (parts[1], parts[4])
            if method == "GET":
                if key not in self.rulesets:
                    return err(404, "could not find entrypoint ruleset")
                return ok(copy.deepcopy(self.rulesets[key]))
            if method == "PUT":
                for r in body["rules"]:
                    if "version" in r or "last_updated" in r:
                        return err(400, "read-only field sent")
                    if not r.get("expression") or not r.get("action"):
                        return err(400, "rule needs expression and action")
                if q.get("dry_run") == "true":
                    return 200, {"success": True, "errors": [], "messages": [], "result": None}
                rules = []
                for r in body["rules"]:
                    r = copy.deepcopy(r)
                    r.setdefault("id", new_id("rule-"))
                    r.update(version="1", last_updated="2026-01-01T00:00:00Z")
                    r.setdefault("enabled", True)
                    if r["action"] == "block":
                        r.setdefault("action_parameters", {})
                    rules.append(r)
                rs = self.rulesets.setdefault(key, {"id": new_id("rs-"), "phase": parts[4]})
                rs["rules"] = rules
                return ok(copy.deepcopy(rs))

        # ---- access
        if path == f"{acct}/access/tags":
            if method == "GET":
                return page(self.tags, q)
            if method == "POST":
                t = {"name": body["name"], "app_count": 0}
                self.tags.append(t)
                return ok(t)
        if path == f"{acct}/access/apps":
            if method == "GET":
                return page(self.apps, q)
            if method == "POST":
                return ok(self._save_app(dict(id=new_id("app-")), body))
        if path.startswith(f"{acct}/access/apps/"):
            app = next(a for a in self.apps if a["id"] == parts[4])
            if method == "PUT":
                self.apps.remove(app)
                return ok(self._save_app({"id": app["id"]}, body))
            if method == "DELETE":
                self.apps.remove(app)
                return ok({"id": app["id"]})
        return err(404, f"no fake route for {method} {path}")

    def _save_app(self, app, body):
        for t in body.get("tags", []):
            if not any(x["name"] == t for x in self.tags):
                return err(400, f"tag {t} does not exist")[1]
        app.update(copy.deepcopy(body))
        app.setdefault("session_duration", "24h")
        app["aud"] = "aud-" + app["id"]
        app["policies"] = [dict(p, id=new_id("pol-")) for p in app["policies"]]
        self.apps.append(app)
        return copy.deepcopy(app)


class FakeKubernetes:
    TOKEN = "kube-test-token"

    def __init__(self, namespace="tunnel"):
        self.namespace = namespace
        self.secrets = {}
        self.requests = []
        self.server = Server(self.handle)
        self.url = self.server.url

    def value(self, name, key="token", ns=None):
        s = self.secrets.get((ns or self.namespace, name))
        return None if s is None else base64.b64decode(s["data"][key]).decode()

    def handle(self, method, path, q, body, headers):
        self.requests.append((method, path))
        if headers.get("Authorization") != f"Bearer {self.TOKEN}":
            return 401, {}
        parts = path.strip("/").split("/")   # api v1 namespaces NS secrets [NAME]
        ns = parts[3]
        if method == "POST":
            self.secrets[(ns, body["metadata"]["name"])] = body
            return 201, body
        key = (ns, parts[5])
        if key not in self.secrets:
            return 404, {}
        if method == "GET":
            return 200, copy.deepcopy(self.secrets[key])
        if method == "PATCH":
            assert headers.get("Content-Type") == "application/merge-patch+json"
            self.secrets[key]["data"].update(body["data"])
            return 200, self.secrets[key]
        return 405, {}
