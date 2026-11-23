#!/usr/bin/env python3
"""cloudflare-sync: make a Cloudflare account match a config file.

It manages, each only when its section is present in the config:

  tunnel     a remotely managed Cloudflare Tunnel, found by name and created if
             missing; its ingress rules; optionally one proxied CNAME alias that
             points at it; optionally its run token, written to a Kubernetes
             Secret for cloudflared to read.
  zones      per zone, the custom WAF rules (phase http_request_firewall_custom)
             and the rate-limiting rules (phase http_ratelimit) that it owns.
  access     self-hosted Cloudflare Access applications that it owns, with
             their inline policies.

Ownership. Everything it creates carries a marker built from `owner` (default
"cloudflare-sync"): WAF and rate-limit rule descriptions start with "[owner] ",
Access applications carry the Access tag `owner`, and the alias record's
comment is "managed by owner". Objects without the marker are never changed or
deleted; they are reported, so a hand-made rule is visible but left alone.
Owned objects that are no longer in the config are deleted.

Standard library only. Usage:

  cloudflare_sync.py --config config.json [--dry-run [--validate]]

Environment:
  CLOUDFLARE_API_TOKEN or CLOUDFLARE_API_TOKEN_FILE   the API token
  CLOUDFLARE_API          API base (default https://api.cloudflare.com/client/v4)
  DRY_RUN=1               same as --dry-run
  VALIDATE=1              same as --validate

Exit status is non-zero if any section failed, after every section has run.
"""
import argparse
import base64
import json
import os
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

VERSION = "0.1.0"
CF_API = "https://api.cloudflare.com/client/v4"
SA_DIR = "/var/run/secrets/kubernetes.io/serviceaccount"

WAF_PHASES = {
    "customRules": "http_request_firewall_custom",
    "rateLimits": "http_ratelimit",
}
# Fields a ruleset GET returns that a PUT must not send back.
RULE_READ_ONLY = ("version", "last_updated")
TUNNEL_RULE_FIELDS = ("hostname", "service", "path", "originRequest")


class ConfigError(Exception):
    pass


class APIError(Exception):
    def __init__(self, method, path, status, errors):
        self.status = status
        msg = "; ".join(
            f"{e.get('code')}: {e.get('message')}" if isinstance(e, dict) else str(e)
            for e in errors) or "no error detail"
        super().__init__(f"{method} {path} -> HTTP {status}: {msg}")


def log(msg):
    print(msg, flush=True)


# ------------------------------------------------------------------- config ----
SCHEMA = {
    "": {"required": ["accountId"],
         "optional": ["owner", "tunnel", "zones", "access"]},
    "tunnel": {"required": ["name", "ingress"],
               "optional": ["catchAll", "originRequest", "dnsAlias", "tokenSecret"]},
    "tunnel.ingress[]": {"required": ["hostname", "service"],
                         "optional": ["path", "originRequest"]},
    "tunnel.dnsAlias": {"required": ["zone", "name"], "optional": []},
    "tunnel.tokenSecret": {"required": ["name"], "optional": ["key", "namespace"]},
    "zones[]": {"required": ["name"], "optional": list(WAF_PHASES)},
    "access": {"required": ["apps"], "optional": []},
    "access.apps[]": {"required": ["name", "domain", "policies"],
                      "optional": ["sessionDuration", "settings"]},
    "access.apps[].policies[]": {"required": ["name", "decision", "include"],
                                 "optional": ["exclude", "require"]},
}


def _check(obj, where):
    spec = SCHEMA[where]
    label = where or "config"
    if not isinstance(obj, dict):
        raise ConfigError(f"{label}: expected an object")
    unknown = set(obj) - set(spec["required"]) - set(spec["optional"])
    if unknown:
        # An unknown key is an error, never ignored: a misspelt key that is
        # silently skipped looks applied and is not.
        raise ConfigError(f"{label}: unknown key(s) {sorted(unknown)}")
    missing = [k for k in spec["required"] if k not in obj]
    if missing:
        raise ConfigError(f"{label}: missing key(s) {missing}")


def _list(obj, key, where):
    val = obj.get(key)
    if not isinstance(val, list):
        raise ConfigError(f"{where}.{key}: expected a list")
    return val


def validate(cfg):
    _check(cfg, "")
    if not isinstance(cfg["accountId"], str) or not cfg["accountId"]:
        raise ConfigError("accountId: expected a non-empty string")
    t = cfg.get("tunnel")
    if t is not None:
        _check(t, "tunnel")
        for r in _list(t, "ingress", "tunnel"):
            _check(r, "tunnel.ingress[]")
        if "dnsAlias" in t:
            _check(t["dnsAlias"], "tunnel.dnsAlias")
        if "tokenSecret" in t:
            _check(t["tokenSecret"], "tunnel.tokenSecret")
    if "zones" in cfg:
        names = []
        for z in _list(cfg, "zones", "config"):
            _check(z, "zones[]")
            names.append(z["name"])
            for key in WAF_PHASES:
                if key in z:
                    for r in _list(z, key, f"zones[{z['name']}]"):
                        _check_rule(r, f"zones[{z['name']}].{key}")
        if len(set(names)) != len(names):
            raise ConfigError("zones: a zone is listed twice")
    a = cfg.get("access")
    if a is not None:
        _check(a, "access")
        domains = []
        for app in _list(a, "apps", "access"):
            _check(app, "access.apps[]")
            domains.append(app["domain"])
            if not _list(app, "policies", f"access.apps[{app['domain']}]"):
                raise ConfigError(f"access.apps[{app['domain']}]: needs at least one policy")
            for p in app["policies"]:
                _check(p, "access.apps[].policies[]")
        if len(set(domains)) != len(domains):
            raise ConfigError("access.apps: a domain is listed twice")
    return cfg


def _check_rule(rule, where):
    if not isinstance(rule, dict):
        raise ConfigError(f"{where}: each rule must be an object")
    for k in ("description", "expression", "action"):
        if not isinstance(rule.get(k), str) or not rule[k]:
            raise ConfigError(f"{where}: every rule needs a non-empty {k!r}")


# ----------------------------------------------------------------- Cloudflare ----
class Cloudflare:
    def __init__(self, token, base=CF_API, dry_run=False, validate=False):
        self.token = token
        self.base = base.rstrip("/")
        self.dry_run = dry_run
        self.validate = dry_run and validate
        self.writes = 0
        self.zones = {}

    def call(self, method, path, body=None, query=None, allow_404=False):
        url = self.base + path
        if query:
            url += "?" + urllib.parse.urlencode(query)
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(url, data=data, method=method, headers={
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
            "User-Agent": f"cloudflare-sync/{VERSION}",
        })
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                raw = resp.read()
        except urllib.error.HTTPError as e:
            with e:
                if e.code == 404 and allow_404:
                    return None
                try:
                    errors = json.loads(e.read() or b"{}").get("errors") or []
                except ValueError:
                    errors = []
            raise APIError(method, path, e.code, errors) from None
        doc = json.loads(raw) if raw else {}
        if doc.get("success") is False:
            raise APIError(method, path, 200, doc.get("errors") or [])
        return doc

    def get(self, path, query=None, allow_404=False):
        doc = self.call("GET", path, query=query, allow_404=allow_404)
        return None if doc is None else doc.get("result")

    def list(self, path, query=None):
        """Every page of a paged list. A list that stops at one page looks
        complete and is not, so this follows result_info to the end."""
        out, page, per_page = [], 1, 50
        while True:
            doc = self.call("GET", path, query=dict(query or {}, page=page, per_page=per_page))
            results = doc.get("result") or []
            out.extend(results)
            info = doc.get("result_info") or {}
            if not results:
                return out
            if info.get("total_pages") is not None:
                done = page >= info["total_pages"]
            elif info.get("total_count") is not None:
                done = len(out) >= info["total_count"]
            else:
                done = len(results) < per_page
            if done:
                return out
            page += 1

    def write(self, method, path, body=None, what=""):
        """A change. Under --dry-run it is logged and not sent."""
        if self.dry_run:
            log(f"  dry-run: would {method} {path}{(' (' + what + ')') if what else ''}")
            return None
        self.writes += 1
        doc = self.call(method, path, body=body)
        return doc.get("result") if doc else None


# ----------------------------------------------------------------- Kubernetes ----
class Kubernetes:
    """Just enough of the Kubernetes API to keep one Secret, from inside a pod."""

    def __init__(self, base=None, token=None, namespace=None, cafile=None):
        host = os.environ.get("KUBERNETES_SERVICE_HOST")
        port = os.environ.get("KUBERNETES_SERVICE_PORT", "443")
        if host and ":" in host:          # an IPv6 service address
            host = f"[{host}]"
        self.base = base or os.environ.get("KUBE_API") or (
            f"https://{host}:{port}" if host else None)
        if not self.base:
            raise ConfigError("tunnel.tokenSecret needs the Kubernetes API: "
                              "run in a pod, or set KUBE_API")
        self.token = token if token is not None else _read(f"{SA_DIR}/token", "")
        self.namespace = namespace or _read(f"{SA_DIR}/namespace", "default")
        ctx = None
        if self.base.startswith("https://"):
            ca = cafile or f"{SA_DIR}/ca.crt"
            ctx = ssl.create_default_context(cafile=ca if os.path.exists(ca) else None)
        self.ctx = ctx

    def call(self, method, path, body=None, ctype="application/json"):
        req = urllib.request.Request(
            self.base + path, method=method,
            data=None if body is None else json.dumps(body).encode(),
            headers={"Authorization": f"Bearer {self.token}", "Content-Type": ctype})
        try:
            with urllib.request.urlopen(req, timeout=30, context=self.ctx) as resp:
                return resp.status, json.loads(resp.read() or b"{}")
        except urllib.error.HTTPError as e:
            with e:
                return e.code, None


def _read(path, default):
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError:
        return default


def write_secret(kube, name, key, value, namespace=None, dry_run=False):
    """Create or update one key of one Secret. Returns 'created', 'updated' or
    'unchanged'. The value is never logged."""
    ns = namespace or kube.namespace
    path = f"/api/v1/namespaces/{ns}/secrets/{name}"
    status, obj = kube.call("GET", path)
    encoded = base64.b64encode(value.encode()).decode()
    if status == 404:
        if dry_run:
            return "would create"
        body = {"apiVersion": "v1", "kind": "Secret",
                "metadata": {"name": name, "namespace": ns,
                             "labels": {"app.kubernetes.io/managed-by": "cloudflare-sync"}},
                "type": "Opaque", "data": {key: encoded}}
        status, _ = kube.call("POST", f"/api/v1/namespaces/{ns}/secrets", body)
        if status not in (200, 201):
            raise RuntimeError(f"creating Secret {ns}/{name}: HTTP {status}")
        return "created"
    if status != 200:
        raise RuntimeError(f"reading Secret {ns}/{name}: HTTP {status}")
    if (obj.get("data") or {}).get(key) == encoded:
        return "unchanged"
    if dry_run:
        return "would update"
    status, _ = kube.call("PATCH", path, {"data": {key: encoded}},
                          ctype="application/merge-patch+json")
    if status != 200:
        raise RuntimeError(f"updating Secret {ns}/{name}: HTTP {status}")
    return "updated"


# ------------------------------------------------------------------ comparing ----
def matches(want, have):
    """True when `have` already says everything `want` says. Keys Cloudflare
    adds on its own (ids, defaults, timestamps) are ignored; lists must have
    the same length, so a removed rule or policy is still a change. A key
    deleted from the config is NOT seen as a change until something else in
    that object changes."""
    if isinstance(want, dict):
        return isinstance(have, dict) and all(matches(v, have.get(k)) for k, v in want.items())
    if isinstance(want, list):
        return (isinstance(have, list) and len(want) == len(have)
                and all(matches(w, h) for w, h in zip(want, have)))
    return want == have


# --------------------------------------------------------------------- tunnel ----
def _clean(d, fields):
    """The comparable part of an object: listed fields that are set and not empty."""
    return {k: d[k] for k in fields if k in d and d[k] not in (None, "", {}, [])}


def desired_tunnel_config(t):
    ingress = [_clean(r, TUNNEL_RULE_FIELDS) for r in t["ingress"]]
    ingress.append({"service": t.get("catchAll", "http_status:404")})
    cfg = {"ingress": ingress}
    if t.get("originRequest"):
        cfg["originRequest"] = t["originRequest"]
    return cfg


def sync_tunnel(cf, cfg, kube_factory):
    t, acct, owner = cfg["tunnel"], cfg["accountId"], cfg.get("owner", "cloudflare-sync")
    base = f"/accounts/{acct}/cfd_tunnel"
    found = cf.list(base, {"name": t["name"], "is_deleted": "false"})
    found = [x for x in found if x.get("name") == t["name"] and not x.get("deleted_at")]
    if len(found) > 1:
        raise RuntimeError(f"tunnel {t['name']!r}: {len(found)} tunnels have that name")
    if found:
        tunnel = found[0]
        if tunnel.get("remote_config") is False:
            raise RuntimeError(f"tunnel {t['name']!r} is locally managed (config file); "
                               "cloudflare-sync manages only remotely managed tunnels")
        log(f"tunnel {t['name']}: exists ({tunnel['id']})")
    else:
        tunnel = cf.write("POST", base, {"name": t["name"], "config_src": "cloudflare"},
                          what=f"create tunnel {t['name']}")
        if tunnel is None:
            log(f"tunnel {t['name']}: missing; would create it (dry run stops here)")
            return
        log(f"tunnel {t['name']}: created ({tunnel['id']})")
    tid = tunnel["id"]

    want = desired_tunnel_config(t)
    have = cf.get(f"{base}/{tid}/configurations", allow_404=True) or {}
    if matches(want, have.get("config")):
        log(f"tunnel {t['name']}: ingress rules unchanged")
    else:
        if have.get("config"):
            log(f"tunnel {t['name']}: ingress rules differ from the config (drift or a "
                f"config change); live was {json.dumps(have['config'].get('ingress'))}")
        cf.write("PUT", f"{base}/{tid}/configurations", {"config": want},
                 what="tunnel ingress rules")
        log(f"tunnel {t['name']}: ingress rules set ({len(want['ingress'])} rules)")

    if "dnsAlias" in t:
        sync_alias(cf, t["dnsAlias"], f"{tid}.cfargotunnel.com", owner)

    if "tokenSecret" in t:
        token = cf.get(f"{base}/{tid}/token")
        if not isinstance(token, str) or not token:
            raise RuntimeError(f"tunnel {t['name']}: the API returned no run token")
        ts = t["tokenSecret"]
        result = write_secret(kube_factory(), ts["name"], ts.get("key", "token"), token,
                              namespace=ts.get("namespace"), dry_run=cf.dry_run)
        log(f"tunnel {t['name']}: run token Secret {ts['name']} {result}")


def zone_id(cf, name):
    cache = cf.zones
    if name not in cache:
        zones = [z for z in cf.list("/zones", {"name": name}) if z.get("name") == name]
        if len(zones) != 1:
            raise RuntimeError(f"zone {name!r}: found {len(zones)} zones with that name "
                               "(is the token allowed to read it?)")
        cache[name] = zones[0]["id"]
    return cache[name]


def sync_alias(cf, alias, target, owner):
    marker = f"managed by {owner}"
    zid = zone_id(cf, alias["zone"])
    path = f"/zones/{zid}/dns_records"
    want = {"type": "CNAME", "name": alias["name"], "content": target,
            "proxied": True, "ttl": 1, "comment": marker}
    same_name = cf.list(path, {"name.exact": alias["name"]})
    ours = [r for r in same_name if r.get("comment") == marker]
    theirs = [r for r in same_name if r.get("comment") != marker]
    if theirs:
        raise RuntimeError(f"DNS {alias['name']}: a record not managed by {owner} already "
                           f"exists ({theirs[0].get('type')}); left alone")
    if not ours:
        cf.write("POST", path, want, what=f"CNAME {alias['name']} -> {target}")
        log(f"DNS {alias['name']}: created CNAME to the tunnel")
    else:
        rec = ours[0]
        if rec.get("type") == "CNAME" and rec.get("content") == target and rec.get("proxied") is True:
            log(f"DNS {alias['name']}: unchanged")
        else:
            cf.write("PATCH", f"{path}/{rec['id']}", want, what=f"CNAME {alias['name']}")
            log(f"DNS {alias['name']}: updated to the tunnel")
    # An alias we made under a name that is no longer configured.
    for rec in cf.list(path, {"comment.exact": marker, "type": "CNAME"}):
        if rec.get("name") != alias["name"] and rec.get("content", "").endswith(".cfargotunnel.com"):
            cf.write("DELETE", f"{path}/{rec['id']}", what=f"old alias {rec.get('name')}")
            log(f"DNS {rec.get('name')}: deleted (old alias, no longer configured)")


# ------------------------------------------------------------------- rulesets ----
def owned_rule(rule, owner):
    return (rule.get("description") or "").startswith(f"[{owner}] ")


def desired_rule(rule, owner):
    out = {k: v for k, v in rule.items() if v is not None}
    out["description"] = f"[{owner}] {rule['description']}"
    out.setdefault("enabled", True)
    return out


def sync_ruleset(cf, zone, zid, key, phase, desired, owner):
    path = f"/zones/{zid}/rulesets/phases/{phase}/entrypoint"
    current = cf.get(path, allow_404=True) or {}
    rules = current.get("rules") or []
    kept = [r for r in rules if not owned_rule(r, owner)]
    mine = [r for r in rules if owned_rule(r, owner)]
    want = [desired_rule(r, owner) for r in desired]
    for r in kept:
        log(f"zone {zone} {key}: left alone (not ours): {r.get('description') or r.get('id')!r}")
    if matches(want, mine):
        log(f"zone {zone} {key}: {len(want)} rule(s) unchanged")
        return
    if mine:
        log(f"zone {zone} {key}: owned rules differ from the config (drift or a config change)")
    body = {"rules": [{k: v for k, v in r.items() if k not in RULE_READ_ONLY} for r in kept] + want}
    if cf.dry_run:
        if cf.validate:
            # Opt-in: Cloudflare's schema documents ?dry_run=true as "validates the
            # request without persisting changes". Still a PUT, so never by default.
            cf.call("PUT", path, body=body, query={"dry_run": "true"})
            log(f"zone {zone} {key}: dry-run: would set {len(want)} rule(s); Cloudflare validated them")
        else:
            log(f"zone {zone} {key}: dry-run: would set {len(want)} rule(s)")
        return
    cf.write("PUT", path, body, what=f"{key} on {zone}")
    log(f"zone {zone} {key}: set {len(want)} rule(s)")


def sync_zones(cf, cfg):
    owner = cfg.get("owner", "cloudflare-sync")
    for z in cfg["zones"]:
        zid = zone_id(cf, z["name"])
        for key, phase in WAF_PHASES.items():
            if key in z:
                sync_ruleset(cf, z["name"], zid, key, phase, z[key], owner)


# --------------------------------------------------------------------- access ----
def _policy(p, precedence):
    return {"name": p["name"], "decision": p["decision"], "include": p["include"],
            "exclude": p.get("exclude", []), "require": p.get("require", []),
            "precedence": precedence}


def desired_app(app, owner):
    body = dict(app.get("settings") or {})
    body.update({
        "type": "self_hosted", "name": app["name"], "domain": app["domain"],
        "tags": [owner],
        "policies": [_policy(p, i + 1) for i, p in enumerate(app["policies"])],
    })
    if "sessionDuration" in app:
        body["session_duration"] = app["sessionDuration"]
    return body


def app_differs(have, want):
    for k, v in want.items():
        if k == "policies":
            hp = sorted(have.get("policies") or [], key=lambda p: p.get("precedence", 0))
            # precedence is ours to set; compare what each policy says
            strip = [{k: x for k, x in p.items() if k != "precedence"} for p in v]
            if not matches(strip, hp):
                return True
        elif k == "tags":
            if set(have.get("tags") or []) != set(v):
                return True
        elif not matches(v, have.get(k)):
            return True
    return False


def sync_access(cf, cfg):
    acct, owner = cfg["accountId"], cfg.get("owner", "cloudflare-sync")
    base = f"/accounts/{acct}/access/apps"
    apps = cf.list(base)
    mine = {a.get("domain"): a for a in apps if owner in (a.get("tags") or [])}
    theirs = {a.get("domain"): a for a in apps if owner not in (a.get("tags") or [])}
    wanted = cfg["access"]["apps"]
    failed = []
    if wanted and not any(t.get("name") == owner for t in cf.list(f"/accounts/{acct}/access/tags")):
        cf.write("POST", f"/accounts/{acct}/access/tags", {"name": owner},
                 what=f"Access tag {owner}")
        log(f"access: created tag {owner}")
    for app in wanted:
        want = desired_app(app, owner)
        dom = app["domain"]
        if dom in theirs and dom not in mine:
            failed.append(dom)
            log(f"access {dom}: an application not managed by {owner} already covers it; left alone")
            continue
        if dom not in mine:
            cf.write("POST", base, want, what=f"Access app {dom}")
            log(f"access {dom}: created")
        elif app_differs(mine[dom], want):
            cf.write("PUT", f"{base}/{mine[dom]['id']}", want, what=f"Access app {dom}")
            log(f"access {dom}: updated (drift or a config change)")
        else:
            log(f"access {dom}: unchanged")
    for dom, a in mine.items():
        if dom not in {x["domain"] for x in wanted}:
            cf.write("DELETE", f"{base}/{a['id']}", what=f"Access app {dom}")
            log(f"access {dom}: deleted (no longer configured)")
    for dom in theirs:
        if dom not in {x["domain"] for x in wanted}:
            log(f"access {dom}: left alone (not ours)")
    if failed:
        raise RuntimeError(f"access: {len(failed)} application(s) blocked by unmanaged ones: {failed}")


# ----------------------------------------------------------------------- main ----
def run(cfg, cf, kube_factory=Kubernetes):
    """Every configured section, each on its own; returns the failures."""
    failures = []
    sections = [("tunnel", sync_tunnel), ("zones", sync_zones), ("access", sync_access)]
    for name, fn in sections:
        if name not in cfg:
            continue
        try:
            if fn is sync_tunnel:
                fn(cf, cfg, kube_factory)
            else:
                fn(cf, cfg)
        except (APIError, RuntimeError, ConfigError, OSError) as e:
            log(f"ERROR {name}: {e}")
            failures.append(name)
    return failures


def load_token():
    token = os.environ.get("CLOUDFLARE_API_TOKEN")
    path = os.environ.get("CLOUDFLARE_API_TOKEN_FILE")
    if not token and path:
        token = _read(path, "")
    if not token:
        raise ConfigError("set CLOUDFLARE_API_TOKEN or CLOUDFLARE_API_TOKEN_FILE")
    return token


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--config", required=True, help="JSON config file")
    ap.add_argument("--dry-run", action="store_true",
                    default=os.environ.get("DRY_RUN", "") not in ("", "0", "false"),
                    help="read everything, change nothing")
    ap.add_argument("--validate", action="store_true",
                    default=os.environ.get("VALIDATE", "") not in ("", "0", "false"),
                    help="with --dry-run, send ruleset changes to Cloudflare with "
                         "?dry_run=true to be validated (a PUT Cloudflare documents "
                         "as not persisted); off by default, so a dry run sends no "
                         "request that changes anything")
    ap.add_argument("--version", action="version", version=VERSION)
    args = ap.parse_args(argv)
    try:
        with open(args.config) as f:
            cfg = validate(json.load(f))
        cf = Cloudflare(load_token(), os.environ.get("CLOUDFLARE_API", CF_API),
                        args.dry_run, args.validate)
    except (ConfigError, ValueError, OSError) as e:
        log(f"ERROR config: {e}")
        return 2
    log(f"cloudflare-sync {VERSION}{' (dry run)' if args.dry_run else ''}")
    failures = run(cfg, cf)
    log(f"done: {cf.writes} change(s)" + (f", FAILED: {', '.join(failures)}" if failures else ""))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
