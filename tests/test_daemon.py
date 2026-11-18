import os
import tempfile
import unittest
from unittest import mock

from am_i_vulnerable import daemon as daemon_mod
from am_i_vulnerable.config import Config
from am_i_vulnerable.feed import CveEntry
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


class FakeAiFail:
    def analyze(self, hostname, distro, packages, cves):
        raise RuntimeError("api down")


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
    os.environ["AMIVULNERABLE_LOG_FILE"] = os.path.join(tmp, "am-i-vulnerable.log")
    return cfg


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

    def _daemon(self, ai_client, pm):
        return daemon_mod.Daemon(
            self.cfg,
            fetcher=lambda url, timeout=60: RSS.encode(),
            ai_client=ai_client,
            pkg_manager=pm,
            mailer_obj=self.mailer,
            store=self.store,
        )

    def test_update_happy_path(self):
        ai_client = FakeAi(
            {
                "CVE-2025-12345": {
                    "cve_id": "CVE-2025-12345",
                    "vulnerable": True,
                    "action": "update",
                    "summary": "openssl betroffen",
                    "affected_packages": [{"package": "openssl", "installed_version": "3.0.13", "fixed_version": "3.0.15"}],
                },
                "CVE-2025-99999": {
                    "cve_id": "CVE-2025-99999",
                    "vulnerable": False,
                    "action": "none",
                    "summary": "nicht installiert",
                    "affected_packages": [],
                },
            }
        )
        pm = FakePm()
        result = self._daemon(ai_client, pm).scan()
        self.assertEqual(result["new"], 2)
        self.assertEqual(result["updated"], [{"cve": "CVE-2025-12345", "package": "openssl"}])
        self.assertEqual(pm.updated, ["openssl"])
        self.assertEqual(pm.refreshed, 1)
        self.assertEqual(self.mailer.sent, [])
        processed = self.store.processed_cves()
        self.assertEqual(processed, {"CVE-2025-12345", "CVE-2025-99999"})
        verdicts = {r["cve_id"]: r["verdict"] for r in self.store.conn.execute("SELECT cve_id, verdict FROM cves")}
        self.assertEqual(verdicts["CVE-2025-12345"], "updated")
        self.assertEqual(verdicts["CVE-2025-99999"], "not_vulnerable")

    def test_second_scan_no_new(self):
        ai_client = FakeAi(
            {
                "CVE-2025-12345": {"cve_id": "CVE-2025-12345", "vulnerable": False, "action": "none", "affected_packages": []},
                "CVE-2025-99999": {"cve_id": "CVE-2025-99999", "vulnerable": False, "action": "none", "affected_packages": []},
            }
        )
        pm = FakePm()
        daemon = self._daemon(ai_client, pm)
        daemon.scan()
        result = daemon.scan()
        self.assertEqual(result["new"], 0)
        self.assertEqual(len(ai_client.calls), 1)

    def test_conflict_sends_alert(self):
        ai_client = FakeAi(
            {
                "CVE-2025-12345": {
                    "cve_id": "CVE-2025-12345",
                    "vulnerable": True,
                    "action": "update",
                    "summary": "s",
                    "affected_packages": [{"package": "openssl", "installed_version": "3.0.13"}],
                },
                "CVE-2025-99999": {"cve_id": "CVE-2025-99999", "vulnerable": False, "action": "none", "affected_packages": []},
            }
        )
        pm = FakePm(update_rc=100, update_out="E: Unable to lock /var/lib/dpkg/lock - conflict")
        result = self._daemon(ai_client, pm).scan()
        self.assertEqual(result["alerts"], 1)
        self.assertEqual(len(self.mailer.sent), 1)
        subject, body = self.mailer.sent[0]
        self.assertIn("openssl", subject)
        self.assertIn("CVE-2025-12345", body)
        self.assertIn("conflict", body.lower())
        verdicts = {r["cve_id"]: r["verdict"] for r in self.store.conn.execute("SELECT cve_id, verdict FROM cves")}
        self.assertEqual(verdicts["CVE-2025-12345"], "update_failed")

    def test_no_fix_available(self):
        ai_client = FakeAi(
            {
                "CVE-2025-12345": {
                    "cve_id": "CVE-2025-12345",
                    "vulnerable": True,
                    "action": "update",
                    "summary": "s",
                    "affected_packages": [{"package": "nginx", "installed_version": "1.24.0"}],
                },
                "CVE-2025-99999": {"cve_id": "CVE-2025-99999", "vulnerable": False, "action": "none", "affected_packages": []},
            }
        )
        pm = FakePm()
        self._daemon(ai_client, pm).scan()
        verdicts = {r["cve_id"]: r["verdict"] for r in self.store.conn.execute("SELECT cve_id, verdict FROM cves")}
        self.assertEqual(verdicts["CVE-2025-12345"], "no_fix_available")
        self.assertEqual(pm.updated, [])
        self.assertEqual(self.mailer.sent, [])

    def test_ai_failure_alerts_and_retries_next_run(self):
        pm = FakePm()
        daemon = self._daemon(FakeAiFail(), pm)
        result = daemon.scan()
        self.assertEqual(result["alerts"], 1)
        self.assertEqual(len(self.mailer.sent), 1)
        self.assertIn("Mistral", self.mailer.sent[0][0])
        self.assertEqual(self.store.processed_cves(), set())
        daemon.ai_client = FakeAi(
            {
                "CVE-2025-12345": {"cve_id": "CVE-2025-12345", "vulnerable": False, "action": "none", "affected_packages": []},
                "CVE-2025-99999": {"cve_id": "CVE-2025-99999", "vulnerable": False, "action": "none", "affected_packages": []},
            }
        )
        result = daemon.scan()
        self.assertEqual(result["new"], 2)
        self.assertEqual(len(self.store.processed_cves()), 2)

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
        )
        result = daemon.scan()
        self.assertIn("error", result)
        self.assertEqual(len(self.mailer.sent), 1)
        runs = self.store.recent_runs()
        self.assertEqual(runs[0]["status"], "error")


if __name__ == "__main__":
    unittest.main()
