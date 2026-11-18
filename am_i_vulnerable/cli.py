import argparse
import getpass
import json
import os
import socket
import sys

from . import ai as ai_mod
from . import config as config_mod
from . import daemon as daemon_mod
from . import installer as installer_mod
from . import state as state_mod


def _load_config(args):
    path = getattr(args, "config", None) or config_mod.default_config_path()
    return config_mod.Config(path), path


def cmd_setup(args):
    path = args.config or config_mod.default_config_path() or config_mod.suggested_config_path()
    cfg = config_mod.Config(path if os.path.exists(path) else None)
    interactive = not args.non_interactive
    hostname = socket.gethostname()

    def value(flag, section, key, prompt, secret=False, default=None):
        if flag is not None:
            result = str(flag)
        elif not interactive:
            result = cfg.get(section, key, default or "")
        else:
            current = cfg.get(section, key, default or "")
            shown = "********" if (secret and current) else current
            fn = getpass.getpass if secret else input
            entered = fn(f"{prompt} [{shown}]: ").strip()
            result = entered or current
        if result:
            cfg.set(section, key, result)
        return result

    print("am-i-vulnerable Einrichtung")
    print("====================")
    value(args.feed_url, "feed", "url", "RSS/CVE-Feed-URL", default=config_mod.DEFAULT_FEED_URL)
    value(args.interval_hours, "daemon", "interval_hours", "Pruef-Intervall in Stunden", default="5")
    api_key = args.api_key if args.api_key is not None else os.environ.get("MISTRAL_API_KEY")
    if api_key:
        cfg.set("mistral", "api_key", api_key)
    elif interactive:
        entered = getpass.getpass("Mistral API-Key (leer = nur Umgebungsvariable MISTRAL_API_KEY): ").strip()
        if entered:
            cfg.set("mistral", "api_key", entered)
    value(args.model, "mistral", "model", "Mistral Modell", default="mistral-small-latest")
    value(args.smtp_host, "mail", "smtp_host", "SMTP-Host", default="127.0.0.1")
    value(args.smtp_port, "mail", "smtp_port", "SMTP-Port", default="25")
    if args.smtp_security:
        cfg.set("mail", "security", args.smtp_security)
    elif interactive:
        current = cfg.get("mail", "security", "none")
        entered = input(f"SMTP-Sicherheit (none/starttls/ssl) [{current}]: ").strip().lower()
        cfg.set("mail", "security", entered or current)
    value(args.smtp_username, "mail", "username", "SMTP-Benutzername (leer = kein Login)")
    smtp_password = args.smtp_password if args.smtp_password is not None else os.environ.get("AMIVULNERABLE_SMTP_PASSWORD")
    if smtp_password:
        cfg.set("mail", "password", smtp_password)
    elif interactive:
        entered = getpass.getpass("SMTP-Passwort (leer = Umgebungsvariable AMIVULNERABLE_SMTP_PASSWORD oder keins): ").strip()
        if entered:
            cfg.set("mail", "password", entered)
    value(args.from_addr, "mail", "from_addr", "Absender-Adresse", default=f"am-i-vulnerable@{hostname}")
    value(args.to_addr, "mail", "to_addr", "Empfaenger-Adresse (Alerts)")
    saved = cfg.save(path)
    print(f"Konfiguration gespeichert: {saved} (chmod 600)")
    if not cfg.get("mail", "to_addr"):
        print("Hinweis: ohne Empfaenger-Adresse (to_addr) werden Alerts nur geloggt, nicht gemailt.")
    if not cfg.api_key():
        print("Hinweis: ohne Mistral API-Key (ini oder MISTRAL_API_KEY) kann die KI-Analyse nicht laufen.")
    if interactive:
        if input("Test-E-Mail jetzt senden? [j/N]: ").strip().lower() in ("j", "ja", "y", "yes"):
            _run_test_mail(cfg)
        if input("Mistral API jetzt testen? [j/N]: ").strip().lower() in ("j", "ja", "y", "yes"):
            _run_test_ai(cfg)
    return 0


def _run_test_mail(cfg):
    from . import mailer as mailer_mod

    mailer = mailer_mod.Mailer(
        cfg.get("mail", "smtp_host", "127.0.0.1"),
        cfg.get_int("mail", "smtp_port", 25),
        cfg.get("mail", "security", "none"),
        cfg.get("mail", "username", ""),
        cfg.smtp_password(),
        cfg.get("mail", "from_addr", ""),
        cfg.get("mail", "to_addr", ""),
        timeout=cfg.get_int("mail", "timeout_seconds", 30),
    )
    mailer.send(
        f"[am-i-vulnerable@{socket.gethostname()}] Test-E-Mail",
        f"am-i-vulnerable auf {socket.gethostname()} funktioniert.\nFeed: {cfg.feed_url}\nZeit (UTC): {state_mod.utcnow()}",
    )
    print("Test-E-Mail versendet.")


def _run_test_ai(cfg):
    key = cfg.api_key()
    if not key:
        print("Kein Mistral API-Key konfiguriert - Test uebersprungen.")
        return 1
    client = ai_mod.MistralClient(
        key,
        base_url=cfg.get("mistral", "base_url", "https://api.mistral.ai/v1"),
        model=cfg.get("mistral", "model", "mistral-small-latest"),
        timeout=cfg.get_int("mistral", "timeout_seconds", 90),
        max_retries=cfg.get_int("mistral", "max_retries", 3),
    )
    answer = client.complete("Antworte nur mit JSON.", 'Sag: {"ok": true, "modell": "<model>"}')
    print(f"Mistral API antwortet: {answer}")
    return 0


def cmd_test_mail(args):
    cfg, _ = _load_config(args)
    _run_test_mail(cfg)
    return 0


def cmd_test_ai(args):
    cfg, _ = _load_config(args)
    return _run_test_ai(cfg)


def cmd_install(args):
    return installer_mod.install(config_path=args.config, start=args.start)


def cmd_uninstall(args):
    return installer_mod.uninstall(purge=args.purge)


def _make_daemon(args):
    cfg, path = _load_config(args)
    if path is None:
        print("Hinweis: keine Konfigurationsdatei gefunden, es werden Standardwerte verwendet.")
    daemon_mod.setup_logging(cfg.log_file())
    return daemon_mod.Daemon(cfg)


def cmd_run(args):
    daemon = _make_daemon(args)
    daemon.install_signal_handlers()
    return daemon.run_forever()


def cmd_scan(args):
    daemon = _make_daemon(args)
    result = daemon.scan()
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if "error" not in result else 1


def cmd_status(args):
    cfg, _ = _load_config(args)
    store = state_mod.StateStore(cfg.state_db())
    stats = store.stats()
    print(f"State-DB: {store.path}")
    print(f"CVEs gesamt: {stats['cves_total']}")
    for verdict, count in sorted(stats["by_verdict"].items()):
        print(f"  {verdict}: {count}")
    print("\nLetzte Laeufe:")
    for row in store.recent_runs(args.limit):
        print(
            f"  #{row['id']} {row['started_at']} status={row['status']} neu={row['new_cves']} "
            f"updates={row['updated']} alerts={row['alerts']} msg={row['message']}"
        )
    print("\nLetzte Alerts:")
    for row in store.recent_alerts(args.limit):
        ok = "ok" if row["ok"] else f"FEHLER: {row['error']}"
        print(f"  #{row['id']} {row['sent_at']} {row['subject']} [{ok}]")
    store.close()
    return 0


def cmd_show_config(args):
    cfg, path = _load_config(args)
    print(f"Konfiguration: {path or '(Standardwerte)'}")
    for section, values in cfg.masked().items():
        print(f"[{section}]")
        for key, value in values.items():
            print(f"{key} = {value}")
    return 0


def build_parser():
    parser = argparse.ArgumentParser(
        prog="am-i-vulnerable",
        description=(
            "am-i-vulnerable: Linux-Daemon, der in einem konfigurierbaren Intervall (Standard: 5h) einen CVE-RSS-Feed liest, "
            "neue CVEs per Mistral API gegen die installierten Pakete prueft, betroffene Pakete automatisch updated "
            "und bei Problemen/Konflikten eine Alert-E-Mail versendet."
        ),
    )
    parser.add_argument("--config", help="Pfad zur INI-Konfiguration (Alternative: Umgebungsvariable AMIVULNERABLE_CONFIG)")
    sub = parser.add_subparsers(dest="command", required=True)

    p_setup = sub.add_parser("setup", help="Interaktive CLI-Einrichtung (Feed-URL, Mistral-Key, SMTP/Mail, Intervall)")
    p_setup.add_argument("--feed-url", help="RSS/CVE-Feed-URL (z.B. https://logiqit.de/api/cve/feed.xml?term=...&cvss_min=7&limit=50)")
    p_setup.add_argument("--interval-hours", help="Pruef-Intervall in Stunden (Standard: 5)")
    p_setup.add_argument("--api-key", help="Mistral API-Key (Alternative: MISTRAL_API_KEY)")
    p_setup.add_argument("--model", help="Mistral Modell (Standard: mistral-small-latest)")
    p_setup.add_argument("--smtp-host", help="SMTP-Host")
    p_setup.add_argument("--smtp-port", help="SMTP-Port")
    p_setup.add_argument("--smtp-security", choices=["none", "starttls", "ssl"], help="SMTP-Verschluesselung")
    p_setup.add_argument("--smtp-username", help="SMTP-Benutzername")
    p_setup.add_argument("--smtp-password", help="SMTP-Passwort (Alternative: AMIVULNERABLE_SMTP_PASSWORD)")
    p_setup.add_argument("--from-addr", help="Absender-Adresse der Alert-Mails")
    p_setup.add_argument("--to-addr", help="Empfaenger-Adresse der Alert-Mails")
    p_setup.add_argument("--non-interactive", action="store_true", help="Keine Rueckfragen, nur Flags/Defaults uebernehmen")
    p_setup.set_defaults(func=cmd_setup)

    p_install = sub.add_parser("install", help="Nach /opt/am-i-vulnerable installieren + systemd-Service einrichten (root)")
    p_install.add_argument("--start", action="store_true", help="Service direkt starten")
    p_install.set_defaults(func=cmd_install)

    p_uninstall = sub.add_parser("uninstall", help="Service stoppen und entfernen (root)")
    p_uninstall.add_argument("--purge", action="store_true", help="Auch Konfiguration und State-DB loeschen")
    p_uninstall.set_defaults(func=cmd_uninstall)

    p_run = sub.add_parser("run", help="Daemon im Vordergrund starten (Endlosschleife)")
    p_run.set_defaults(func=cmd_run)

    p_scan = sub.add_parser("scan", help="Einmaliger Prueflauf (Feed lesen, analysieren, patchen)")
    p_scan.set_defaults(func=cmd_scan)

    p_mail = sub.add_parser("test-mail", help="Test-E-Mail ueber die konfigurierte SMTP-Verbindung senden")
    p_mail.set_defaults(func=cmd_test_mail)

    p_ai = sub.add_parser("test-ai", help="Mistral API mit einem Test-Prompt aufrufen")
    p_ai.set_defaults(func=cmd_test_ai)

    p_status = sub.add_parser("status", help="Letzte Laeufe, Verdikte und Alerts aus der State-DB anzeigen")
    p_status.add_argument("--limit", type=int, default=10)
    p_status.set_defaults(func=cmd_status)

    p_show = sub.add_parser("show-config", help="Aktuelle Konfiguration anzeigen (Secrets werden maskiert)")
    p_show.set_defaults(func=cmd_show_config)

    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        return 130
    except Exception as exc:
        print(f"Fehler: {exc}", file=sys.stderr)
        return 1
