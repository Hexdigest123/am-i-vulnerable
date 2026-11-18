# am-i-vulnerable

Linux-Daemon (Python, nur Standardbibliothek): liest alle 5 Stunden einen CVE-RSS-Feed, prüft jede neue CVE per Mistral API gegen die installierten Pakete, updated betroffene Pakete automatisch und sendet bei Problemen/Konflikten eine Alert-E-Mail.

Der Daemon arbeitet mit einem eingebauten Mini-Agenten (Tool-Calls gegen die Mistral API): `list_packages` (alle oder gefilterte Paketversionen lesen), `update_package` (gezieltes Update eines betroffenen Pakets, Auto-Alert bei Konflikt) und `notify_user` (E-Mail an den Administrator). Konfigurierbar über `[harness]` in der Config (`enabled`, `max_iterations`, `max_updates_per_run`).

## Quickstart

```bash
git clone https://github.com/Hexdigest123/am-i-vulnerable.git && cd am-i-vulnerable
sudo python3 -m am_i_vulnerable setup          # Feed-URL, Mistral-API-Key, SMTP/Mail, Intervall
sudo python3 -m am_i_vulnerable test-mail      # optional: Mailversand testen
sudo python3 -m am_i_vulnerable test-ai        # optional: Mistral API testen
sudo python3 -m am_i_vulnerable install --start
journalctl -u am-i-vulnerable.service -f
```

## Konfiguration

- `/etc/am-i-vulnerable/config.ini` (chmod 600, wird von `setup` angelegt): Feed-URL, Intervall (Default 5 h), Mistral-Modell, SMTP
- Secrets alternativ per Umgebungsvariable: `MISTRAL_API_KEY`, `AMIVULNERABLE_SMTP_PASSWORD` (systemd lädt dazu `/etc/am-i-vulnerable/am-i-vulnerable.env`)
- Default-Feed: `https://logiqit.de/api/cve/feed.xml?term=microsoft%2Cnext%2Creact&cvss_min=7&limit=50` (in `setup` per `--feed-url` änderbar)

## Weitere Kommandos

`run` (Vordergrund), `scan` (einmaliger Lauf), `status`, `show-config`, `uninstall` – Übersicht: `python3 -m am_i_vulnerable --help`

## Tests

```bash
python3 -m unittest discover -s tests
```
