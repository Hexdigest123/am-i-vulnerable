import os
import tempfile
import unittest

from cvewatch.state import StateStore


class StateStoreTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = StateStore(os.path.join(self.tmp.name, "sub", "state.db"))

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def test_mark_and_processed(self):
        self.assertEqual(self.store.processed_cves(), set())
        self.store.mark_processed("CVE-2025-1", "updated", {"package": "openssl"})
        self.assertEqual(self.store.processed_cves(), {"CVE-2025-1"})
        self.store.mark_processed("CVE-2025-1", "update_failed", {"rc": 100})
        rows = self.store.conn.execute("SELECT verdict FROM cves WHERE cve_id='CVE-2025-1'").fetchall()
        self.assertEqual(rows[0]["verdict"], "update_failed")

    def test_runs_and_alerts(self):
        self.store.record_run("2025-01-01T00:00:00+00:00", "ok", "2 neue CVEs", 2, [{"cve": "CVE-2025-1", "package": "openssl"}], 0)
        self.store.record_alert("[cvewatch] x", cve_id="CVE-2025-1", package="openssl", ok=True)
        self.store.record_alert("[cvewatch] y", ok=False, error="smtp down")
        self.store.mark_processed("CVE-2025-1", "updated")
        runs = self.store.recent_runs()
        self.assertEqual(len(runs), 1)
        self.assertEqual(runs[0]["new_cves"], 2)
        alerts = self.store.recent_alerts()
        self.assertEqual(len(alerts), 2)
        self.assertEqual(sorted(row["ok"] for row in alerts), [0, 1])
        stats = self.store.stats()
        self.assertEqual(stats["cves_total"], 1)


if __name__ == "__main__":
    unittest.main()
