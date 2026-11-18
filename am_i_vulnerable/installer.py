import os
import shutil
import subprocess
from pathlib import Path

APP_DIR = Path("/opt/am-i-vulnerable")
CONFIG_DIR = Path("/etc/am-i-vulnerable")
STATE_DIR = Path("/var/lib/am-i-vulnerable")
LOG_DIR = Path("/var/log/am-i-vulnerable")
UNIT_PATH = Path("/etc/systemd/system/am-i-vulnerable.service")
ENV_PATH = CONFIG_DIR / "am-i-vulnerable.env"


def unit_content(python_bin):
    return f"""[Unit]
Description=am-i-vulnerable - prueft regelmaessig neue CVEs (RSS-Feed + Mistral KI) gegen installierte Pakete und patcht automatisch
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory={APP_DIR}
Environment=AMIVULNERABLE_CONFIG={CONFIG_DIR}/config.ini
EnvironmentFile=-{ENV_PATH}
ExecStart={python_bin} -m am_i_vulnerable run
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
    shutil.copytree(source_pkg, APP_DIR / "am_i_vulnerable")
    for directory, mode in ((CONFIG_DIR, 0o700), (STATE_DIR, 0o750), (LOG_DIR, 0o750)):
        directory.mkdir(parents=True, exist_ok=True)
        os.chmod(directory, mode)
    cfg_path = Path(config_path) if config_path else CONFIG_DIR / "config.ini"
    if not cfg_path.exists():
        from .config import Config

        Config().save(str(cfg_path))
        print(f"Standard-Konfiguration written: {cfg_path} (bitte mit 'am-i-vulnerable setup' anpassen)")
    UNIT_PATH.write_text(unit_content(python_bin), encoding="utf-8")
    _systemctl("daemon-reload")
    _systemctl("enable", "am-i-vulnerable.service")
    if start:
        result = _systemctl("start", "am-i-vulnerable.service")
        if result.returncode != 0:
            raise RuntimeError(f"systemctl start fehlgeschlagen: {result.stderr.strip()}")
    print(f"Installiert nach {APP_DIR}")
    print(f"Konfiguration: {cfg_path}")
    print("Naechste Schritte:")
    print("  sudo python3 -m am_i_vulnerable setup        # Feed-URL, Mistral-Key, SMTP konfigurieren")
    print("  sudo python3 -m am_i_vulnerable test-mail")
    print("  sudo python3 -m am_i_vulnerable test-ai")
    print("  sudo systemctl start am-i-vulnerable.service         # oder: install --start")
    print("  journalctl -u am-i-vulnerable -f")
    return 0


def uninstall(purge=False):
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        raise RuntimeError("'uninstall' benoetigt root-Rechte (sudo)")
    _systemctl("stop", "am-i-vulnerable.service")
    _systemctl("disable", "am-i-vulnerable.service")
    if UNIT_PATH.exists():
        UNIT_PATH.unlink()
    _systemctl("daemon-reload")
    if APP_DIR.exists():
        shutil.rmtree(APP_DIR)
    if purge:
        for directory in (CONFIG_DIR, STATE_DIR, LOG_DIR):
            if directory.exists():
                shutil.rmtree(directory)
    print("am-i-vulnerable deinstalliert" + (" (inkl. Konfiguration und State)" if purge else ""))
    return 0
