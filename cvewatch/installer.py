import os
import shutil
import subprocess
from pathlib import Path

APP_DIR = Path("/opt/cvewatch")
CONFIG_DIR = Path("/etc/cvewatch")
STATE_DIR = Path("/var/lib/cvewatch")
LOG_DIR = Path("/var/log/cvewatch")
UNIT_PATH = Path("/etc/systemd/system/cvewatch.service")
ENV_PATH = CONFIG_DIR / "cvewatch.env"


def unit_content(python_bin):
    return f"""[Unit]
Description=cvewatch - prueft regelmaessig neue CVEs (RSS-Feed + Mistral KI) gegen installierte Pakete und patcht automatisch
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory={APP_DIR}
Environment=CVEWATCH_CONFIG={CONFIG_DIR}/cvewatch.ini
EnvironmentFile=-{ENV_PATH}
ExecStart={python_bin} -m cvewatch run
Restart=always
RestartSec=30s

[Install]
WantedBy=multi-user.target
"""


def _systemctl(*args):
    return subprocess.run(["systemctl", *args], capture_output=True, text=True)


def install(config_path=None, start=False):
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        raise RuntimeError("'install' benoetigt root-Rechte (sudo)")
    source_pkg = Path(__file__).resolve().parent
    python_bin = shutil.which("python3") or "/usr/bin/python3"
    if APP_DIR.exists():
        shutil.rmtree(APP_DIR)
    shutil.copytree(source_pkg, APP_DIR / "cvewatch")
    for directory, mode in ((CONFIG_DIR, 0o700), (STATE_DIR, 0o750), (LOG_DIR, 0o750)):
        directory.mkdir(parents=True, exist_ok=True)
        os.chmod(directory, mode)
    cfg_path = Path(config_path) if config_path else CONFIG_DIR / "cvewatch.ini"
    if not cfg_path.exists():
        from .config import Config

        Config().save(str(cfg_path))
        print(f"Standard-Konfiguration written: {cfg_path} (bitte mit 'cvewatch setup' anpassen)")
    UNIT_PATH.write_text(unit_content(python_bin), encoding="utf-8")
    _systemctl("daemon-reload")
    _systemctl("enable", "cvewatch.service")
    if start:
        result = _systemctl("start", "cvewatch.service")
        if result.returncode != 0:
            raise RuntimeError(f"systemctl start fehlgeschlagen: {result.stderr.strip()}")
    print(f"Installiert nach {APP_DIR}")
    print(f"Konfiguration: {cfg_path}")
    print("Naechste Schritte:")
    print("  sudo python3 -m cvewatch setup        # Feed-URL, Mistral-Key, SMTP konfigurieren")
    print("  sudo python3 -m cvewatch test-mail")
    print("  sudo python3 -m cvewatch test-ai")
    print("  sudo systemctl start cvewatch         # oder: install --start")
    print("  journalctl -u cvewatch -f")
    return 0


def uninstall(purge=False):
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        raise RuntimeError("'uninstall' benoetigt root-Rechte (sudo)")
    _systemctl("stop", "cvewatch.service")
    _systemctl("disable", "cvewatch.service")
    if UNIT_PATH.exists():
        UNIT_PATH.unlink()
    _systemctl("daemon-reload")
    if APP_DIR.exists():
        shutil.rmtree(APP_DIR)
    if purge:
        for directory in (CONFIG_DIR, STATE_DIR, LOG_DIR):
            if directory.exists():
                shutil.rmtree(directory)
    print("cvewatch deinstalliert" + (" (inkl. Konfiguration und State)" if purge else ""))
    return 0
