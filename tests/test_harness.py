import json
import os
import tempfile
import unittest

from am_i_vulnerable import harness as harness_mod
from am_i_vulnerable.config import Config
from am_i_vulnerable.feed import CveEntry
from am_i_vulnerable.packages import CmdResult, Package, PackageManager
from am_i_vulnerable.state import StateStore

CVES = [
    CveEntry(cve_id="CVE-2025-12345", title="RCE in openssl", description="bad in openssl < 3.0.15", link="http://x"),
    CveEntry(cve_id="CVE-2025-99999", title="Foo in bar", description="bar product", link="http://y"),
]


def tool_call_msg(calls):
    return {
        "role": "assistant",
        "content": None,
        "tool_calls": [
            {"id": cid, "type": "function", "function": {"name": name, "arguments": json.dumps(args)}}
            for cid, name, args in calls
        ],
    }


class ScriptedClient:
    def __init__(self, messages):
        self.queue = list(messages)
        self.requests = []

    def complete_with_tools(self, messages, tools):
        self.requests.append({"messages": [dict(m) for m in messages], "tools": tools})
        if not self.queue:
            raise AssertionError("keine scripted Antwort mehr vorhanden")
        return self.queue.pop(0)


class FakePm(PackageManager):
    name = "fake"

    def __init__(self, update_rc=0, update_out="Setting up openssl (3.0.15) ...", updatable=("openssl",)):
        self.update_rc = update_rc
        self.update_out = update_out
        self.updatable = set(updatable)
        self.updated = []

    def list_installed(self):
        return [Package("openssl", "3.0.13"), Package("nginx", "1.24.0")]

    def update_available(self, package):
        return package in self.updatable

    def update(self, package):
        self.updated.append(package)
        return CmdResult(["apt-get", "install", package], self.update_rc, self.update_out, "")


class FakeMailer:
    def __init__(self):
        self.sent = []

    def send(self, subject, body):
        self.sent.append((subject, body))


def make_cfg():
    cfg = Config()
    cfg.set("harness", "max_iterations", "8")
    cfg.set("harness", "max_updates_per_run", "2")
    cfg.set("mistral", "max_packages", "100")
    return cfg


class HarnessTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        os.environ["AMIVULNERABLE_STATE_DB"] = os.path.join(self.tmp.name, "state.db")
        self.store = StateStore(os.environ["AMIVULNERABLE_STATE_DB"])
        self.mailer = FakeMailer()
        self.pm = FakePm()
        self.cfg = make_cfg()

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()
        os.environ.pop("AMIVULNERABLE_STATE_DB", None)

    def make_harness(self, client, pm=None):
        return harness_mod.Harness(
            client, pm or self.pm, lambda: self.mailer, self.store, "testhost", self.cfg, "Debian 12"
        )

    def final_msg(self, results):
        return {"role": "assistant", "content": json.dumps({"results": results})}

    def test_full_loop_with_update(self):
        client = ScriptedClient(
            [
                tool_call_msg([("1", "list_packages", {"packages": ["openssl"]})]),
                tool_call_msg([("2", "update_package", {"package": "openssl", "cve_id": "CVE-2025-12345", "reason": "betroffen"})]),
                self.final_msg(
                    [
                        {"cve_id": "CVE-2025-12345", "verdict": "updated", "packages_updated": ["openssl"], "notes": "geupdated"},
                        {"cve_id": "CVE-2025-99999", "verdict": "not_vulnerable", "packages_updated": [], "notes": "nicht installiert"},
                    ]
                ),
            ]
        )
        result = self.make_harness(client).run(CVES, feed_url="http://feed")
        self.assertFalse(result["exhausted"])
        self.assertEqual(result["updates"], [{"cve_id": "CVE-2025-12345", "package": "openssl", "from": "3.0.13", "reason": "betroffen"}])
        self.assertEqual(self.pm.updated, ["openssl"])
        self.assertEqual(result["alerts"], [])
        msgs = client.requests[-1]["messages"]
        tool_msgs = [m for m in msgs if m["role"] == "tool"]
        self.assertEqual(len(tool_msgs), 2)
        scoped = json.loads(tool_msgs[0]["content"])
        self.assertEqual(scoped["count"], 1)
        self.assertEqual(scoped["packages"], [{"name": "openssl", "version": "3.0.13"}])
        self.assertTrue(json.loads(tool_msgs[1]["content"])["ok"])
        self.assertEqual(client.requests[-1]["tools"][0]["function"]["name"], "list_packages")
        self.assertEqual([t["name"] for t in result["tool_calls"]], ["list_packages", "update_package"])

    def test_list_packages_all(self):
        client = ScriptedClient([tool_call_msg([("1", "list_packages", {})]), self.final_msg([])])
        result = self.make_harness(client).run(CVES)
        msgs = client.requests[-1]["messages"]
        tool_content = json.loads([m for m in msgs if m["role"] == "tool"][0]["content"])
        self.assertEqual(tool_content["count"], 2)
        self.assertEqual({p["name"] for p in tool_content["packages"]}, {"openssl", "nginx"})
        self.assertFalse(result["exhausted"])

    def test_update_not_installed_refused(self):
        client = ScriptedClient(
            [tool_call_msg([("1", "update_package", {"package": "ghost", "reason": "x"})]), self.final_msg([])]
        )
        self.make_harness(client).run(CVES)
        self.assertEqual(self.pm.updated, [])
        content = json.loads([m for m in client.requests[-1]["messages"] if m["role"] == "tool"][0]["content"])
        self.assertFalse(content["ok"])
        self.assertIn("nicht installiert", content["error"])

    def test_update_without_available_fix(self):
        client = ScriptedClient(
            [tool_call_msg([("1", "update_package", {"package": "nginx", "reason": "x"})]), self.final_msg([])]
        )
        self.make_harness(client).run(CVES)
        self.assertEqual(self.pm.updated, [])
        content = json.loads([m for m in client.requests[-1]["messages"] if m["role"] == "tool"][0]["content"])
        self.assertFalse(content["ok"])
        self.assertEqual(content["reason"], "kein Update verfuegbar")

    def test_update_conflict_sends_alert(self):
        pm = FakePm(update_rc=100, update_out="E: Unable to lock /var/lib/dpkg/lock - conflict")
        client = ScriptedClient(
            [tool_call_msg([("1", "update_package", {"package": "openssl", "cve_id": "CVE-2025-12345", "reason": "betroffen"})]), self.final_msg([])]
        )
        result = self.make_harness(client, pm=pm).run(CVES)
        self.assertEqual(len(result["failed"]), 1)
        self.assertEqual(len(result["alerts"]), 1)
        self.assertTrue(result["alerts"][0]["sent"])
        self.assertEqual(len(self.mailer.sent), 1)
        subject, body = self.mailer.sent[0]
        self.assertIn("[am-i-vulnerable@testhost]", subject)
        self.assertIn("openssl", subject)
        self.assertIn("CVE-2025-12345", body)
        self.assertIn("conflict", body.lower())
        content = json.loads([m for m in client.requests[-1]["messages"] if m["role"] == "tool"][0]["content"])
        self.assertTrue(content["conflict"])
        self.assertTrue(content["alert_sent"])
        alerts = self.store.recent_alerts()
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["ok"], 1)

    def test_max_updates_cap(self):
        pm = FakePm(updatable=("openssl", "nginx"))
        calls = [
            tool_call_msg([(f"{i}", "update_package", {"package": p, "cve_id": "CVE-2025-12345", "reason": "r"})])
            for i, p in enumerate(["openssl", "nginx", "openssl"], start=1)
        ]
        client = ScriptedClient(calls + [self.final_msg([])])
        result = self.make_harness(client, pm=pm).run(CVES)
        self.assertEqual(len(result["updates"]), 2)
        tool_contents = [
            json.loads(m["content"]) for m in client.requests[-1]["messages"] if m["role"] == "tool"
        ]
        self.assertIn("max_updates_per_run", tool_contents[2]["error"])

    def test_notify_user_tool(self):
        client = ScriptedClient(
            [
                tool_call_msg([("1", "notify_user", {"subject": "Kein Fix", "message": "CVE-2025-99999: kein Fix verfuegbar"})]),
                self.final_msg([]),
            ]
        )
        result = self.make_harness(client).run(CVES)
        self.assertEqual(len(self.mailer.sent), 1)
        subject, body = self.mailer.sent[0]
        self.assertIn("Kein Fix", subject)
        self.assertIn("CVE-2025-99999", body)
        self.assertEqual(len(result["alerts"]), 1)
        self.assertTrue(result["alerts"][0]["sent"])
        self.assertEqual(self.store.recent_alerts()[0]["ok"], 1)

    def test_notify_mail_failure_recorded(self):
        class FailingMailer:
            def send(self, subject, body):
                raise RuntimeError("smtp down")

        self.mailer = FailingMailer()
        client = ScriptedClient(
            [tool_call_msg([("1", "notify_user", {"subject": "s", "message": "m"})]), self.final_msg([])]
        )
        result = self.make_harness(client).run(CVES)
        self.assertEqual(result["alerts"][0]["sent"], False)
        self.assertIn("smtp down", result["alerts"][0]["error"])
        self.assertEqual(self.store.recent_alerts()[0]["ok"], 0)

    def test_max_iterations_exhausted(self):
        cfg = make_cfg()
        cfg.set("harness", "max_iterations", "3")
        client = ScriptedClient([tool_call_msg([("1", "list_packages", {})])] * 10)
        harness = harness_mod.Harness(client, self.pm, lambda: self.mailer, self.store, "testhost", cfg, "Debian")
        result = harness.run(CVES)
        self.assertTrue(result["exhausted"])
        self.assertIn("max_iterations", result["final"])
        self.assertEqual(len(client.requests), 3)

    def test_unknown_tool_and_bad_arguments(self):
        bad = {
            "role": "assistant",
            "content": None,
            "tool_calls": [{"id": "1", "type": "function", "function": {"name": "rm_rf", "arguments": "not-json"}}],
        }
        client = ScriptedClient([bad, self.final_msg([])])
        result = self.make_harness(client).run(CVES)
        content = json.loads([m for m in client.requests[-1]["messages"] if m["role"] == "tool"][0]["content"])
        self.assertIn("unbekanntes Tool", content["error"])
        self.assertEqual(result["tool_calls"][0]["name"], "rm_rf")

    def test_user_prompt_contains_cves(self):
        client = ScriptedClient([self.final_msg([])])
        self.make_harness(client).run(CVES, feed_url="http://feed")
        user_msg = client.requests[0]["messages"][1]
        self.assertEqual(user_msg["role"], "user")
        self.assertIn("CVE-2025-12345", user_msg["content"])
        self.assertIn("http://feed", user_msg["content"])
        self.assertIn("testhost", user_msg["content"])
        self.assertEqual(client.requests[0]["messages"][0]["role"], "system")


if __name__ == "__main__":
    unittest.main()
