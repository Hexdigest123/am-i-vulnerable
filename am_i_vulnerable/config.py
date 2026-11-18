import configparser
import os
from pathlib import Path

DEFAULT_FEED_URL = "https://logiqit.de/api/cve/feed.xml?term=microsoft%2Cnext%2Creact&cvss_min=7&limit=50"

DEFAULTS = {
    "feed": {
        "url": DEFAULT_FEED_URL,
        "timeout_seconds": "60",
    },
    "daemon": {
        "interval_hours": "5",
        "run_on_start": "true",
        "refresh_index": "true",
    },
    "mistral": {
        "api_key": "",
        "base_url": "https://api.mistral.ai/v1",
        "model": "mistral-small-latest",
        "timeout_seconds": "90",
        "max_retries": "3",
        "batch_size": "5",
        "max_packages": "1500",
        "temperature": "0.1",
    },
    "harness": {
        "enabled": "true",
        "max_iterations": "12",
        "max_updates_per_run": "20",
    },
    "mail": {
        "smtp_host": "127.0.0.1",
        "smtp_port": "25",
        "security": "none",
        "username": "",
        "password": "",
        "from_addr": "",
        "to_addr": "",
        "timeout_seconds": "30",
    },
    "paths": {},
}

SECRET_KEYS = {("mistral", "api_key"), ("mail", "password")}


def _default_state_db():
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        return "/var/lib/am-i-vulnerable/state.db"
    return str(Path.home() / ".local" / "share" / "am-i-vulnerable" / "state.db")


def _default_log_file():
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        return "/var/log/am-i-vulnerable/am-i-vulnerable.log"
    return str(Path.home() / ".local" / "share" / "am-i-vulnerable" / "am-i-vulnerable.log")


def default_config_path():
    env = os.environ.get("AMIVULNERABLE_CONFIG")
    if env:
        return env
    for candidate in ("/etc/am-i-vulnerable/config.ini", os.path.join(os.getcwd(), "config.ini")):
        if os.path.exists(candidate):
            return candidate
    return None


def suggested_config_path():
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        return "/etc/am-i-vulnerable/config.ini"
    return str(Path.home() / ".config" / "am-i-vulnerable" / "config.ini")


class Config:
    def __init__(self, path=None):
        self.path = path
        self.parser = configparser.ConfigParser(interpolation=None)
        if path and os.path.exists(path):
            self.parser.read(path, encoding="utf-8")

    def get(self, section, key, fallback=None):
        if self.parser.has_option(section, key):
            return self.parser.get(section, key)
        if section in DEFAULTS and key in DEFAULTS[section]:
            return DEFAULTS[section][key]
        return fallback

    def get_int(self, section, key, fallback=0):
        try:
            return int(self.get(section, key, fallback))
        except (TypeError, ValueError):
            return fallback

    def get_float(self, section, key, fallback=0.0):
        try:
            return float(self.get(section, key, fallback))
        except (TypeError, ValueError):
            return fallback

    def get_bool(self, section, key, fallback=False):
        value = self.get(section, key)
        if value is None:
            return fallback
        return str(value).strip().lower() in ("1", "true", "yes", "on")

    def set(self, section, key, value):
        if not self.parser.has_section(section):
            self.parser.add_section(section)
        self.parser.set(section, key, str(value))

    @property
    def feed_url(self):
        return self.get("feed", "url", DEFAULT_FEED_URL)

    def api_key(self):
        return os.environ.get("MISTRAL_API_KEY") or self.get("mistral", "api_key", "") or ""

    def smtp_password(self):
        return os.environ.get("AMIVULNERABLE_SMTP_PASSWORD") or self.get("mail", "password", "") or ""

    def state_db(self):
        return os.environ.get("AMIVULNERABLE_STATE_DB") or self.get("paths", "state_db") or _default_state_db()

    def log_file(self):
        return os.environ.get("AMIVULNERABLE_LOG_FILE") or self.get("paths", "log_file") or _default_log_file()

    def save(self, path=None):
        path = path or self.path or suggested_config_path()
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            self.parser.write(fh)
        os.chmod(path, 0o600)
        self.path = path
        return path

    def masked(self):
        result = {}
        sections = set(self.parser.sections()) | set(DEFAULTS)
        for section in sorted(sections):
            result[section] = {}
            keys = set(self.parser.options(section)) if self.parser.has_section(section) else set()
            keys |= set(DEFAULTS.get(section, {}))
            for key in sorted(keys):
                value = self.get(section, key, "")
                if (section, key) in SECRET_KEYS and value:
                    value = "********"
                result[section][key] = value
        return result
