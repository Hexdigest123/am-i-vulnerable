import json
import os
import tempfile
import unittest

from am_i_vulnerable import daemon as daemon_mod
from am_i_vulnerable.config import Config
from am_i_vulnerable.packages import CmdResult, Package, PackageManager
from am_i_vulnerable.state import StateStore


RSS = """<?xml version="1.0"?>
<rss version="2.0"><channel>
<item><title>CVE-2025-12345 RCE in openssl</title><description>Bad in openssl &lt; 3.0.15</description>
<cve_id>CVE-2025-12345</cve_id><cvss_score>9.8</cvss_score><cvss_severity>CRITICAL</cvss_severity></item>
<item><title>CVE-2025-99999 in nicht-installiert</title><description>Foo product</description>
<cve_id>CVE-2025-99999</cve_id></item>
</channel></rss>
"""


class FakeAi:
    def __init__(self, verdicts_by_cve):
        self.verdicts_by_cve = verdicts_by_cve
        self.calls = []

    def analyze(self, hostname, distro, packages, cves):
        self.calls.append([c.cve_id for c in cves])
        return [self.verdicts_by_cve[c.cve_id] for c in cves]


class FakeHarness:
    def __init__(self, result=None, exc=None):
        self.result = result or {"final": "", "exhausted": False, "updates": [], "failed": [], "alerts": [], "tool_calls": []}
        self.exc = exc
        self.calls = []

    def run(self, cves, feed_url=""):
        self.calls.append([c.cve_id for c in cves])
        if self.exc:
            raise self.exc
        return self.result


class FakePm(PackageManager):
    name = "fake"

    def __init__(self, update_rc=0, update_out="Setting up openssl (3.0.15) ..."):
        self.update_rc = update_rc
        self.update_out = update_out
        self.updated = []
        self.refreshed = 0

    def list_installed(self):
        return [Package("openssl", "3.0.13"), Package("nginx", "1.24.0")]

    def refresh_index(self):
        self.refreshed += 1
        return CmdResult(["apt-get", "update"], 0, "ok", "")

    def update_available(self, package):
        return package == "openssl"

    def update(self, package):
        self.updated.append(package)
        return CmdResult(["apt-get", "install", package], self.update_rc, self.update_out, "")


class FakeMailer:
    def __init__(self):
        self.sent = []

    def send(self, subject, body):
        self.sent.append((subject, body))


def make_cfg(tmp):
    cfg = Config()
    cfg.set("feed", "url", "https://example.invalid/feed.xml")
    cfg.set("daemon", "refresh_index", "true")
    cfg.set("mail", "from_addr", "from@x")
    cfg.set("mail", "to_addr", "to@x")
    os.environ["AMIVULNERABLE_STATE_DB"] = os.path.join(tmp, "state.db")
    os.environ["AMIVULNERABLE_LOG_FILE"] = os.path.join(tmp, "aiv.log")
    return cfg


def harness_result(final_results, updates=None, failed=None, alerts=None):
    return {
        "final": json.dumps({"results": final_results}),
        "exhausted": False,
        "updates": updates or [],
        "failed": failed or [],
        "alerts": alerts or [],
        "tool_calls": [],
    }


class DaemonScanTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cfg = make_cfg(self.tmp.name)
        daemon_mod.setup_logging(self.cfg.log_file())
        self.store = StateStore(self.cfg.state_db())
        self.mailer = FakeMailer()

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()
        os.environ.pop("AMIVULNERABLE_STATE_DB", None)
        os.environ.pop("AMIVULNERABLE_LOG_FILE", None)

    def _daemon(self, harness=None, ai_client=None, pm=None):
        return daemon_mod.Daemon(
            self.cfg,
            fetcher=lambda url, timeout=60: RSS.encode(),
            ai_client=ai_client or FakeAi({}),
            pkg_manager=pm or FakePm(),
            mailer_obj=self.mailer,
            store=self.store,
            harness_factory=(lambda c, p, d: harness) if harness is not None else None,
        )

    def test_harness_update_happy_path(self):
        harness = FakeHarness(
            result=harness_result(
                final_results=[
                    {"cve_id": "CVE-2025-12345", "verdict": "updated", "packages_updated": ["openssl"], "notes": "geupdated"},
                    {"cve_id": "CVE-2025-99999", "verdict": "not_vulnerable", "packages_updated": [], "notes": "nicht installiert"},
                ],
                updates=[{"cve_id": "CVE-2025-12345", "package": "openssl", "from": "3.0.13", "reason": "betroffen"}],
            )
        )
        pm = FakePm()
        result = self._daemon(harness=harness, pm=pm).scan()
        self.assertEqual(result["new"], 2)
        self.assertEqual(result["updated"], [{"cve": "CVE-2025-12345", "package": "openssl"}])
        self.assertEqual(result["alerts"], 0)
        self.assertEqual(pm.refreshed, 1)
        self.assertEqual(self.mailer.sent, [])
        self.assertEqual(self.store.processed_cves(), {"CVE-2025-12345", "CVE-2025-99999"})
        verdicts = {r["cve_id"]: r["verdict"] for r in self.store.conn.execute("SELECT cve_id, verdict FROM cves")}
        self.assertEqual(verdicts["CVE-2025-12345"], "updated")
        self.assertEqual(verdicts["CVE-2025-99999"], "not_vulnerable")

    def test_harness_conflict_counted_as_alert(self):
        harness = FakeHarness(
            result=harness_result(
                final_results=[{"cve_id": "CVE-2025-12345", "verdict": "update_failed"}, {"cve_id": "CVE-2025-99999", "verdict": "not_vulnerable"}],
                failed=[{"cve_id": "CVE-2025-12345", "package": "openssl", "returncode": 100, "output_tail": "conflict"}],
                alerts=[{"subject": "[am-i-vulnerable@h] Update fehlgeschlagen", "sent": True}],
            )
        )
        result = self._daemon(harness=harness).scan()
        self.assertEqual(result["alerts"], 1)
        self.assertEqual(result["updated"], [])
        verdicts = {r["cve_id"]: r["verdict"] for r in self.store.conn.execute("SELECT cve_id, verdict FROM cves")}
        self.assertEqual(verdicts["CVE-2025-12345"], "update_failed")

    def test_harness_verdict_fallback_from_tool_log(self):
        harness = FakeHarness(
            result={
                "final": "kein JSON hier",
                "exhausted": False,
                "updates": [{"cve_id": "CVE-2025-12345", "package": "openssl"}],
                "failed": [],
                "alerts": [],
                "tool_calls": [],
            }
        )
        self._daemon(harness=harness).scan()
        verdicts = {r["cve_id"]: r["verdict"] for r in self.store.conn.execute("SELECT cve_id, verdict FROM cves")}
        self.assertEqual(verdicts["CVE-2025-12345"], "updated")
        self.assertEqual(verdicts["CVE-2025-99999"], "processed")

    def test_second_scan_no_new(self):
        harness = FakeHarness(result=harness_result(final_results=[]))
        daemon = self._daemon(harness=harness)
        daemon.scan()
        result = daemon.scan()
        self.assertEqual(result["new"], 0)
        self.assertEqual(len(harness.calls), 1)

    def test_harness_failure_alerts_and_retries_next_run(self):
        failing = FakeHarness(exc=RuntimeError("api down"))
        daemon = self._daemon(harness=failing)
        result = daemon.scan()
        self.assertEqual(result["alerts"], 1)
        self.assertEqual(len(self.mailer.sent), 1)
        self.assertIn("Mini-Harness", self.mailer.sent[0][0])
        self.assertEqual(self.store.processed_cves(), set())
        ok = FakeHarness(
            result=harness_result(
                final_results=[
                    {"cve_id": "CVE-2025-12345", "verdict": "not_vulnerable"},
                    {"cve_id": "CVE-2025-99999", "verdict": "not_vulnerable"},
                ]
            )
        )
        daemon.harness_factory = lambda c, p, d: ok
        result = daemon.scan()
        self.assertEqual(result["new"], 2)
        self.assertEqual(len(self.store.processed_cves()), 2)

    def test_fallback_batch_mode_when_harness_disabled(self):
        self.cfg.set("harness", "enabled", "false")
        ai_client = FakeAi(
            {
                "CVE-2025-12345": {
                    "cve_id": "CVE-2025-12345",
                    "vulnerable": True,
                    "action": "update",
                    "summary": "openssl betroffen",
                    "affected_packages": [{"package": "openssl", "installed_version": "3.0.13", "fixed_version": "3.0.15"}],
                },
                "CVE-2025-99999": {"cve_id": "CVE-2025-99999", "vulnerable": False, "action": "none", "affected_packages": []},
            }
        )
        pm = FakePm()
        result = self._daemon(ai_client=ai_client, pm=pm, harness=None).scan()
        self.assertEqual(result["updated"], [{"cve": "CVE-2025-12345", "package": "openssl"}])
        self.assertEqual(pm.updated, ["openssl"])

    def test_feed_error_alerts(self):
        def bad_fetcher(url, timeout=60):
            raise RuntimeError("network down")

        daemon = daemon_mod.Daemon(
            self.cfg,
            fetcher=bad_fetcher,
            ai_client=FakeAi({}),
            pkg_manager=FakePm(),
            mailer_obj=self.mailer,
            store=self.store,
            harness_factory=lambda c, p, d: FakeHarness(),
        )
        result = daemon.scan()
        self.assertIn("error", result)
        self.assertEqual(len(self.mailer.sent), 1)
        runs = self.store.recent_runs()
        self.assertEqual(runs[0]["status"], "error")


if __name__ == "__main__":
    unittest.main()
