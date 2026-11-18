import os
import stat
import tempfile
import unittest
from unittest import mock

from am_i_vulnerable.config import Config


INI = """
[feed]
url = https://logiqit.de/api/cve/feed.xml?term=next&cvss_min=7&limit=50

[mistral]
api_key = secret-key-123
model = mistral-large-latest

[mail]
password = smtp-pass
to_addr = admin@example.com
"""


class ConfigTest(unittest.TestCase):
    def test_load_and_defaults(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "config.ini")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(INI)
            cfg = Config(path)
        self.assertEqual(cfg.feed_url, "https://logiqit.de/api/cve/feed.xml?term=next&cvss_min=7&limit=50")
        self.assertEqual(cfg.get("mistral", "model"), "mistral-large-latest")
        self.assertEqual(cfg.get_int("daemon", "interval_hours", 5), 5)
        self.assertEqual(cfg.get("daemon", "interval_hours"), "5")
        self.assertTrue(cfg.get_bool("daemon", "run_on_start", True))
        self.assertEqual(cfg.get("feed", "timeout_seconds"), "60")

    def test_env_overrides(self):
        cfg = Config()
        with mock.patch.dict(os.environ, {"MISTRAL_API_KEY": "env-key", "AMIVULNERABLE_SMTP_PASSWORD": "env-pass"}):
            self.assertEqual(cfg.api_key(), "env-key")
            self.assertEqual(cfg.smtp_password(), "env-pass")
        cfg.set("mistral", "api_key", "ini-key")
        with mock.patch.dict(os.environ, {"MISTRAL_API_KEY": "env-key"}):
            self.assertEqual(cfg.api_key(), "env-key")
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("MISTRAL_API_KEY", None)
            self.assertEqual(cfg.api_key(), "ini-key")

    def test_save_permissions_and_masked(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "cfg", "config.ini")
            cfg = Config()
            cfg.set("mistral", "api_key", "secret-key-123")
            cfg.set("mail", "password", "smtp-pass")
            cfg.set("mail", "to_addr", "admin@example.com")
            cfg.save(path)
            mode = stat.S_IMODE(os.stat(path).st_mode)
            self.assertEqual(mode, 0o600)
            reloaded = Config(path)
            self.assertEqual(reloaded.get("mail", "to_addr"), "admin@example.com")
            masked = reloaded.masked()
            self.assertEqual(masked["mistral"]["api_key"], "********")
            self.assertEqual(masked["mail"]["password"], "********")
            self.assertEqual(masked["mail"]["to_addr"], "admin@example.com")

    def test_state_db_env_override(self):
        cfg = Config()
        with mock.patch.dict(os.environ, {"AMIVULNERABLE_STATE_DB": "/tmp/x.db"}):
            self.assertEqual(cfg.state_db(), "/tmp/x.db")


if __name__ == "__main__":
    unittest.main()
