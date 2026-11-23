import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
import unittest.mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(__file__))

import cloudflare_sync as cs  # noqa: E402
from fakes import FakeCloudflare, FakeKubernetes  # noqa: E402

ACCT = FakeCloudflare.ACCOUNT


def config(**sections):
    cfg = {"accountId": ACCT}
    cfg.update(sections)
    return cfg


TUNNEL = {
    "name": "edge",
    "ingress": [{"hostname": "*.example.com", "service": "http://gateway.public.svc:80"}],
    "dnsAlias": {"zone": "example.com", "name": "tunnel.example.com"},
    "tokenSecret": {"name": "tunnel-token"},
}

BLOCK = {"description": "block admin", "expression": '(http.request.uri.path contains "/admin")',
         "action": "block"}
LIMIT = {"description": "login limit", "expression": '(http.request.uri.path eq "/login")',
         "action": "block",
         "ratelimit": {"characteristics": ["ip.src", "cf.colo.id"], "period": 10,
                       "requests_per_period": 20, "mitigation_timeout": 10}}

APP = {"name": "Dashboard", "domain": "dash.example.com", "sessionDuration": "12h",
       "policies": [{"name": "staff", "decision": "allow",
                     "include": [{"email_domain": {"domain": "example.com"}}]}]}


class Base(unittest.TestCase):
    def setUp(self):
        self.cf = FakeCloudflare()
        self.kube = FakeKubernetes()
        self.addCleanup(self.cf.server.close)
        self.addCleanup(self.kube.server.close)

    def kube_client(self):
        return cs.Kubernetes(base=self.kube.url, token=FakeKubernetes.TOKEN, namespace="tunnel")

    def sync(self, cfg, dry_run=False, validate=False):
        cfg = cs.validate(json.loads(json.dumps(cfg)))
        client = cs.Cloudflare(FakeCloudflare.TOKEN, self.cf.url, dry_run=dry_run, validate=validate)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            failures = cs.run(cfg, client, self.kube_client)
        self.output = out.getvalue()
        return failures

    def assertNoWrites(self, cfg):
        """A second run against what the first one made changes nothing."""
        before = len(self.cf.writes())
        kube_before = [r for r in self.kube.requests if r[0] != "GET"]
        self.assertEqual(self.sync(cfg), [], self.output)
        self.assertEqual(self.cf.writes()[before:], [], self.output)
        self.assertEqual([r for r in self.kube.requests if r[0] != "GET"], kube_before)


class TunnelTests(Base):
    def test_first_run_builds_everything_and_second_run_changes_nothing(self):
        cfg = config(tunnel=TUNNEL)
        self.assertEqual(self.sync(cfg), [], self.output)
        self.assertEqual(len(self.cf.tunnels), 1)
        t = self.cf.tunnels[0]
        self.assertTrue(t["remote_config"])
        self.assertEqual(self.cf.configs[t["id"]]["ingress"][0]["hostname"], "*.example.com")
        self.assertEqual(self.cf.configs[t["id"]]["ingress"][-1], {"service": "http_status:404", "originRequest": {}})
        rec = self.cf.dns[0]
        self.assertEqual((rec["type"], rec["name"], rec["content"], rec["proxied"]),
                         ("CNAME", "tunnel.example.com", f"{t['id']}.cfargotunnel.com", True))
        self.assertEqual(self.kube.value("tunnel-token"), self.cf.tokens[t["id"]])
        self.assertNotIn(self.cf.tokens[t["id"]], self.output, "the run token must never be logged")
        self.assertNoWrites(cfg)

    def test_existing_tunnel_is_adopted_not_recreated(self):
        t = self.cf.add_tunnel("edge")
        self.assertEqual(self.sync(config(tunnel=TUNNEL)), [], self.output)
        self.assertEqual(len(self.cf.tunnels), 1)
        self.assertNotIn(("POST", f"/accounts/{ACCT}/cfd_tunnel"), self.cf.writes())
        self.assertEqual(self.kube.value("tunnel-token"), self.cf.tokens[t["id"]])

    def test_rebuilt_cluster_gets_the_token_back(self):
        cfg = config(tunnel=TUNNEL)
        self.sync(cfg)
        self.kube.secrets.clear()                  # a new cluster: no Secret
        self.assertEqual(self.sync(cfg), [], self.output)
        self.assertEqual(self.kube.value("tunnel-token"), self.cf.tokens[self.cf.tunnels[0]["id"]])
        self.assertIn("created", self.output)

    def test_rotated_token_is_rewritten(self):
        cfg = config(tunnel=TUNNEL)
        self.sync(cfg)
        tid = self.cf.tunnels[0]["id"]
        self.cf.tokens[tid] = "rotated"
        self.sync(cfg)
        self.assertEqual(self.kube.value("tunnel-token"), "rotated")
        self.assertIn("Secret tunnel-token updated", self.output)

    def test_dashboard_edit_is_reverted_and_reported(self):
        cfg = config(tunnel=TUNNEL)
        self.sync(cfg)
        tid = self.cf.tunnels[0]["id"]
        self.cf.configs[tid]["ingress"].insert(0, {"hostname": "x.example.com", "service": "http://evil"})
        self.sync(cfg)
        self.assertIn("differ from the config", self.output)
        self.assertEqual(len(self.cf.configs[tid]["ingress"]), 2)

    def test_locally_managed_tunnel_is_refused(self):
        self.cf.add_tunnel("edge", remote=False)
        self.assertEqual(self.sync(config(tunnel=TUNNEL)), ["tunnel"])
        self.assertIn("locally managed", self.output)
        self.assertEqual(self.cf.writes(), [])

    def test_two_tunnels_with_the_name_is_an_error(self):
        self.cf.add_tunnel("edge")
        self.cf.add_tunnel("edge")
        self.assertEqual(self.sync(config(tunnel=TUNNEL)), ["tunnel"])

    def test_tunnel_list_is_paged_by_total_count(self):
        # 60 other tunnels with the same name prefix would not match `name=`,
        # so page through a list that only carries total_count.
        for _ in range(55):
            self.cf.add_tunnel("edge-other")
        client = cs.Cloudflare(FakeCloudflare.TOKEN, self.cf.url)
        got = client.list(f"/accounts/{ACCT}/cfd_tunnel")
        self.assertEqual(len(got), 55)

    def test_unmanaged_alias_record_is_left_alone(self):
        self.cf.dns.append({"id": "dns-x", "zone_id": "zone1", "type": "A",
                            "name": "tunnel.example.com", "content": "192.0.2.1"})
        self.assertEqual(self.sync(config(tunnel=TUNNEL)), ["tunnel"])
        self.assertEqual(self.cf.dns[0]["content"], "192.0.2.1")
        self.assertIn("not managed by cloudflare-sync", self.output)

    def test_renamed_alias_removes_the_old_one(self):
        self.sync(config(tunnel=TUNNEL))
        moved = dict(TUNNEL, dnsAlias={"zone": "example.com", "name": "edge.example.com"})
        self.assertEqual(self.sync(config(tunnel=moved)), [], self.output)
        self.assertEqual([r["name"] for r in self.cf.dns], ["edge.example.com"])

    def test_dry_run_changes_nothing(self):
        self.assertEqual(self.sync(config(tunnel=TUNNEL), dry_run=True), [], self.output)
        self.assertEqual(self.cf.writes(), [])
        self.assertEqual(self.cf.tunnels, [])
        self.assertIn("would POST", self.output)


class RulesetTests(Base):
    def test_rules_are_created_and_stay_put(self):
        cfg = config(zones=[{"name": "example.com", "customRules": [BLOCK], "rateLimits": [LIMIT]}])
        self.assertEqual(self.sync(cfg), [], self.output)
        custom = self.cf.rulesets[("zone1", "http_request_firewall_custom")]["rules"]
        self.assertEqual(custom[0]["description"], "[cloudflare-sync] block admin")
        rl = self.cf.rulesets[("zone1", "http_ratelimit")]["rules"]
        self.assertEqual(rl[0]["ratelimit"]["period"], 10)
        self.assertNoWrites(cfg)

    def test_hand_made_rules_are_kept_first_and_reported(self):
        self.cf.rulesets[("zone1", "http_request_firewall_custom")] = {"id": "rs", "rules": [
            {"id": "mine", "description": "hand made", "expression": "true", "action": "log",
             "version": "3", "last_updated": "x", "enabled": True}]}
        cfg = config(zones=[{"name": "example.com", "customRules": [BLOCK]}])
        self.assertEqual(self.sync(cfg), [], self.output)
        rules = self.cf.rulesets[("zone1", "http_request_firewall_custom")]["rules"]
        self.assertEqual([r["id"] for r in rules][0], "mine")
        self.assertEqual(rules[1]["description"], "[cloudflare-sync] block admin")
        self.assertIn("left alone (not ours): 'hand made'", self.output)

    def test_removed_rule_is_deleted_but_hand_made_survives(self):
        cfg = config(zones=[{"name": "example.com", "customRules": [BLOCK]}])
        self.sync(cfg)
        rs = self.cf.rulesets[("zone1", "http_request_firewall_custom")]
        rs["rules"].append({"id": "theirs", "description": "keep me", "expression": "true",
                            "action": "log", "version": "1", "last_updated": "x"})
        self.sync(config(zones=[{"name": "example.com", "customRules": []}]))
        self.assertEqual([r["id"] for r in rs["rules"]], ["theirs"])

    def test_changed_expression_is_pushed(self):
        self.sync(config(zones=[{"name": "example.com", "customRules": [BLOCK]}]))
        changed = dict(BLOCK, expression='(http.request.uri.path contains "/wp-admin")')
        self.sync(config(zones=[{"name": "example.com", "customRules": [changed]}]))
        rule = self.cf.rulesets[("zone1", "http_request_firewall_custom")]["rules"][0]
        self.assertIn("wp-admin", rule["expression"])

    def test_absent_phase_is_not_touched(self):
        self.sync(config(zones=[{"name": "example.com", "customRules": [BLOCK]}]))
        self.assertFalse(any("http_ratelimit" in p for _, p, _, _ in self.cf.requests))

    def test_empty_config_with_no_ruleset_makes_no_ruleset(self):
        self.assertEqual(self.sync(config(zones=[{"name": "example.com", "customRules": []}])), [])
        self.assertEqual(self.cf.writes(), [])

    def test_dry_run_sends_nothing_but_reads(self):
        cfg = config(zones=[{"name": "example.com", "customRules": [BLOCK]}])
        self.assertEqual(self.sync(cfg, dry_run=True), [], self.output)
        self.assertEqual([m for m, _, _, _ in self.cf.requests if m != "GET"], [])

    def test_validate_asks_cloudflare_to_check_without_saving(self):
        cfg = config(zones=[{"name": "example.com", "customRules": [BLOCK]}])
        self.assertEqual(self.sync(cfg, dry_run=True, validate=True), [], self.output)
        self.assertEqual(self.cf.writes(), [])
        sent = [q for m, _, q, _ in self.cf.requests if m != "GET"]
        self.assertEqual(sent, [{"dry_run": "true"}])

    def test_validate_without_dry_run_is_ignored(self):
        client = cs.Cloudflare("t", self.cf.url, dry_run=False, validate=True)
        self.assertFalse(client.validate)

    def test_unknown_zone_fails_that_section_only(self):
        cfg = config(tunnel=TUNNEL, zones=[{"name": "nope.example", "customRules": [BLOCK]}])
        self.assertEqual(self.sync(cfg), ["zones"])
        self.assertEqual(len(self.cf.tunnels), 1)


class AccessTests(Base):
    def test_app_is_created_tagged_and_then_left_alone(self):
        cfg = config(access={"apps": [APP]})
        self.assertEqual(self.sync(cfg), [], self.output)
        app = self.cf.apps[0]
        self.assertEqual(app["tags"], ["cloudflare-sync"])
        self.assertEqual(app["session_duration"], "12h")
        self.assertEqual(app["policies"][0]["precedence"], 1)
        self.assertEqual([t["name"] for t in self.cf.tags], ["cloudflare-sync"])
        self.assertNoWrites(cfg)

    def test_policy_change_updates_the_app(self):
        self.sync(config(access={"apps": [APP]}))
        changed = dict(APP, policies=[dict(APP["policies"][0],
                                           include=[{"email": {"email": "a@example.com"}}])])
        self.sync(config(access={"apps": [changed]}))
        self.assertEqual(self.cf.apps[0]["policies"][0]["include"], [{"email": {"email": "a@example.com"}}])
        self.assertEqual(len(self.cf.apps), 1)

    def test_unconfigured_owned_app_is_deleted_unowned_kept(self):
        self.sync(config(access={"apps": [APP]}))
        self.cf.apps.append({"id": "hand", "domain": "other.example.com", "tags": [], "policies": []})
        self.assertEqual(self.sync(config(access={"apps": []})), [], self.output)
        self.assertEqual([a["id"] for a in self.cf.apps], ["hand"])
        self.assertIn("other.example.com: left alone", self.output)

    def test_unowned_app_on_the_same_domain_blocks_and_fails(self):
        self.cf.apps.append({"id": "hand", "domain": "dash.example.com", "tags": [], "policies": []})
        self.assertEqual(self.sync(config(access={"apps": [APP]})), ["access"])
        self.assertEqual([a["id"] for a in self.cf.apps], ["hand"])

    def test_app_list_is_paged(self):
        for i in range(120):
            self.cf.apps.append({"id": f"h{i}", "domain": f"h{i}.example.com", "tags": []})
        self.cf.apps.append({"id": "old", "domain": "old.example.com", "tags": ["cloudflare-sync"]})
        self.sync(config(access={"apps": []}))
        self.assertNotIn("old", [a["id"] for a in self.cf.apps], "an owned app on page 3 was missed")

    def test_another_owner_is_not_ours(self):
        self.sync(config(access={"apps": [APP]}))
        self.assertEqual(self.sync(config(owner="team-b", access={"apps": []})), [])
        self.assertEqual(len(self.cf.apps), 1)


class ConfigTests(unittest.TestCase):
    def test_unknown_key_is_an_error_not_ignored(self):
        with self.assertRaisesRegex(cs.ConfigError, "unknown key"):
            cs.validate(config(tunnel=dict(TUNNEL, ingres=[])))
        with self.assertRaisesRegex(cs.ConfigError, "unknown key"):
            cs.validate(config(zones=[{"name": "example.com", "customRule": []}]))

    def test_rule_needs_description(self):
        with self.assertRaisesRegex(cs.ConfigError, "description"):
            cs.validate(config(zones=[{"name": "example.com",
                                       "customRules": [{"expression": "true", "action": "block"}]}]))

    def test_duplicate_access_domain(self):
        with self.assertRaisesRegex(cs.ConfigError, "twice"):
            cs.validate(config(access={"apps": [APP, APP]}))

    def test_main_exit_codes(self):
        cf = FakeCloudflare()
        self.addCleanup(cf.server.close)
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(config(zones=[{"name": "example.com", "customRules": [BLOCK]}]), f)
        self.addCleanup(os.unlink, f.name)
        env = {"CLOUDFLARE_API_TOKEN": FakeCloudflare.TOKEN, "CLOUDFLARE_API": cf.url}
        with unittest.mock.patch.dict(os.environ, env), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cs.main(["--config", f.name]), 0)
        with unittest.mock.patch.dict(os.environ, dict(env, CLOUDFLARE_API_TOKEN="wrong")), \
                contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(cs.main(["--config", f.name]), 1)
        self.assertNotIn("wrong", out.getvalue(), "the API token must never be logged")
        with unittest.mock.patch.dict(os.environ, {"CLOUDFLARE_API_TOKEN": ""}), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cs.main(["--config", f.name]), 2)



class ReleaseTests(unittest.TestCase):
    def test_chart_app_version_matches_the_code(self):
        chart = os.path.join(os.path.dirname(__file__), "..", "chart", "Chart.yaml")
        with open(chart) as f:
            app_version = next(l.split(":", 1)[1].strip().strip('"') for l in f
                               if l.startswith("appVersion:"))
        self.assertEqual(app_version, "v" + cs.VERSION)


if __name__ == "__main__":
    unittest.main()
