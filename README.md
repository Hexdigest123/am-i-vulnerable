# cvewatch – am I vulnerable?

Linux-Daemon, der im Hintergrund läuft und **alle 5 Stunden** (konfigurierbar) einen **CVE-RSS-Feed** liest. Jede neu erschienene CVE wird per **Mistral API (KI)** gegen die **installierten Systempakete** geprüft. Ist das System betroffen, wird das Paket automatisch geupdated. Gibt es dabei **Probleme oder Konflikte**, wird eine **Alert-E-Mail** versendet.

Nur Python-Standardbibliothek – keine `pip install`-Abhängigkeiten nötig.

## Funktionsweise (pro Lauf)

1. RSS/CVE-Feed laden (Default: `https://logiqit.de/api/cve/feed.xml?term=microsoft%2Cnext%2Creact&cvss_min=7&limit=50`, in der Setup-CLI frei wählbar)
2. Bereits verarbeitete CVEs werden über eine SQLite-State-DB übersprungen
3. Paketindex aktualisieren (`apt-get update` etc.) und installierte Pakete listen (apt, dnf, pacman, apk, zypper)
4. Neue CVEs batched an die **Mistral API** (`/v1/chat/completions`) senden – die KI entscheidet pro CVE: betroffen? welches Paket? Fix-Version?
5. Betroffene Pakete mit verfügbarem Update werden **einzeln geupdated**
6. Bei Fehler/Konflikt (oder wenn Feed/KI/SMTP nicht erreichbar sind) → **E-Mail-Alert** mit Befehl, Returncode und Log-Auszug

## Schnellstart

```bash
git clone https://github.com/Hexdigest123/am-i-vulnerable.git
cd am-i-vulnerable
sudo python3 -m cvewatch setup      # interaktive CLI: Feed-URL, Mistral-Key, SMTP/Mail, Intervall
sudo python3 -m cvewatch test-mail  # Mailversand testen
sudo python3 -m cvewatch test-ai    # Mistral API testen
sudo python3 -m cvewatch scan       # einmaliger Testlauf
sudo python3 -m cvewatch install --start   # systemd-Daemon installieren + starten
journalctl -u cvewatch -f           # Logs verfolgen
```

Die ausführliche, CLI-basierte Anleitung inkl. Mail-Einrichtung (lokaler Postfix oder externer SMTP) und Mistral-API-Key liegt in [docs/SETUP.md](docs/SETUP.md).

## CLI-Kommandos

| Kommando | Zweck |
|---|---|
| `setup` | Interaktive Einrichtung (Feed-URL, Intervall, Mistral-Key, SMTP) oder per Flags: `--feed-url`, `--api-key`, `--smtp-host`, `--smtp-port`, `--smtp-security none|starttls|ssl`, `--smtp-username`, `--smtp-password`, `--from-addr`, `--to-addr`, `--non-interactive` |
| `install [--start]` | Installiert nach `/opt/cvewatch`, legt `/etc/cvewatch` an und richtet den systemd-Service ein (root) |
| `uninstall [--purge]` | Entfernt Service und Installation |
| `run` | Daemon im Vordergrund (Endlosschleife, alle 5h) |
| `scan` | Einmaliger Prüflauf |
| `test-mail` / `test-ai` | SMTP-Versand bzw. Mistral API testen |
| `status` | Letzte Läufe, Verdikte und Alerts aus der State-DB |
| `show-config` | Konfiguration anzeigen (Secrets maskiert) |

## Konfiguration

INI-Datei unter `/etc/cvewatch/cvewatch.ini` (wird von `setup` mit `chmod 600` angelegt), siehe [examples/cvewatch.ini.example](examples/cvewatch.ini.example). Secrets können statt in der INI auch über die Umgebungsvariablen `MISTRAL_API_KEY` und `CVEWATCH_SMTP_PASSWORD` kommen (systemd lädt sie über `EnvironmentFile=-/etc/cvewatch/cvewatch.env`, siehe [examples/cvewatch.env.example](examples/cvewatch.env.example)).

Wichtigste Optionen:

```ini
[feed]
url = https://logiqit.de/api/cve/feed.xml?term=microsoft%2Cnext%2Creact&cvss_min=7&limit=50

[daemon]
interval_hours = 5

[mistral]
model = mistral-small-latest
batch_size = 5

[mail]
smtp_host = 127.0.0.1
smtp_port = 25
security = none
```

## Verdikte in der State-DB (`/var/lib/cvewatch/state.db`)

`updated`, `not_vulnerable`, `no_fix_available`, `investigate`, `update_failed`. Als `update_failed` markierte CVEs werden nicht automatisch erneut versucht – nach manuellem Fix ist ein `DELETE FROM cves WHERE cve_id=...` möglich, damit sie erneut geprüft werden.

## Sicherheit

- Konfig/Env-Dateien liegen nur für root lesbar (`0600`/`0700`)
- API-Keys/Passwörter werden nie geloggt und nie ins Repo committed (`.gitignore`)
- Updates laufen non-interaktiv mit `--force-confdef/--force-confold` (apt), Konflikte landen als Alert-Mail

## Tests

```bash
python3 -m unittest discover -s tests -v
```

## Projektlayout

```
cvewatch/            Python-Paket (stdlib only)
  cli.py             argparse-CLI (setup, install, run, scan, test-mail, test-ai, status, show-config)
  config.py          INI-Konfiguration + Env-Overrides + Secret-Masking
  feed.py            RSS/Atom/NVD-Feed: fetch (gzip) + Parser
  ai.py              Mistral-Chat-Client + JSON-Verdict-Parsing
  packages.py        apt/dnf/pacman/apk/zypper: list, update_available, update, Konflikt-Erkennung
  mailer.py          SMTP (none/starttls/ssl) Alert-Mails
  state.py           SQLite-State (gesehene CVEs, Läufe, Alerts)
  daemon.py          Scan-Orchestrierung + 5h-Endlosschleife + Lock
  installer.py       /opt/cvewatch + systemd-Unit
systemd/             cvewatch.service (Template)
examples/            cvewatch.ini.example, cvewatch.env.example
docs/SETUP.md        CLI-Setup-Guide (deutsch)
tests/               unittest-Suite
```
