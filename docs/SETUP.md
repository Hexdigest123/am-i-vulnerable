# cvewatch – Setup-Guide (CLI-basiert)

Dieser Guide richtet den Daemon komplett über die Kommandozeile ein:
1. Voraussetzungen
2. Projekt holen
3. `cvewatch setup` – Feed-URL, Mistral-API-Key, E-Mail (SMTP) konfigurieren
4. Mail-Einrichtung (lokaler Postfix **oder** externer SMTP-Anbieter)
5. Mistral-API-Key einrichten
6. Testlauf + Dienst installieren (systemd)
7. Betrieb, Logs, Fehlersuche

Getestet mit Python 3.9+ auf Debian/Ubuntu (apt), Fedora/RHEL (dnf), Arch (pacman), Alpine (apk), openSUSE (zypper). Root-Rechte (`sudo`) sind nötig, weil der Daemon Pakete aktualisiert.

---

## 1. Voraussetzungen

```bash
sudo apt update && sudo apt install -y python3 git   # Debian/Ubuntu; analog: dnf install python3 git, pacman -S python git, ...
python3 --version    # >= 3.9
```

Netzwerk-Zugriff des Servers wird benötigt für:
- den CVE-RSS-Feed (z. B. `https://logiqit.de/api/cve/feed.xml?...`)
- die Mistral API (`https://api.mistral.ai`)
- den SMTP-Server für Alert-Mails

## 2. Projekt holen

```bash
git clone https://github.com/Hexdigest123/am-i-vulnerable.git
cd am-i-vulnerable
```

Keine Python-Abhängigkeiten außerhalb der Standardbibliothek – `pip install` ist **nicht** nötig.

## 3. `cvewatch setup` – interaktive CLI-Einrichtung

```bash
sudo python3 -m cvewatch setup
```

Der Assistent fragt (alle Werte können danach in `/etc/cvewatch/cvewatch.ini` angepasst werden):

| Prompt | Bedeutung | Beispiel |
|---|---|---|
| RSS/CVE-Feed-URL | Feed mit neuen CVEs | `https://logiqit.de/api/cve/feed.xml?term=microsoft%2Cnext%2Creact&cvss_min=7&limit=50` |
| Prüf-Intervall in Stunden | Abstand der Scans (Default 5h) | `5` |
| Mistral API-Key | Key für die KI-Analyse | `sk-...` (oder leer lassen und `MISTRAL_API_KEY` setzen, siehe 5) |
| Mistral Modell | Modell für `/v1/chat/completions` | `mistral-small-latest` (günstig) oder `mistral-large-latest` |
| SMTP-Host / Port / Sicherheit | Mailversand | `127.0.0.1` / `25` / `none` (lokal) oder `smtp.gmail.com` / `587` / `starttls` |
| SMTP-Benutzername / Passwort | Login am SMTP (leer = ohne Auth) | bei lokalem Postfix leer lassen |
| Absender-Adresse | `From:` der Alerts | `cvewatch@dein-server.example` |
| Empfänger-Adresse | `To:` der Alerts | `admin@example.com` |

Die Konfiguration wird nach `/etc/cvewatch/cvewatch.ini` geschrieben (**chmod 600**, nur root lesbar). Der Assistent bietet am Ende optional `test-mail` und `test-ai` an.

### Nicht-interaktiv (per Flags, z. B. für Ansible/CI)

```bash
sudo python3 -m cvewatch setup --non-interactive \
  --feed-url "https://logiqit.de/api/cve/feed.xml?term=microsoft%2Cnext%2Creact&cvss_min=7&limit=50" \
  --interval-hours 5 \
  --api-key "$MISTRAL_API_KEY" \
  --smtp-host 127.0.0.1 --smtp-port 25 --smtp-security none \
  --from-addr cvewatch@mein-server.example --to-addr admin@example.com
```

## 4. E-Mail-Einrichtung

Alerts gehen nur raus, wenn `from_addr` und `to_addr` gesetzt sind und der SMTP-Versand klappt.

### Variante A: lokaler Postfix (empfohlen für reine Server)

```bash
sudo apt install -y postfix        # Konfiguration "Internet Site" wählen
sudo systemctl enable --now postfix
```

In `setup` dann: Host `127.0.0.1`, Port `25`, Sicherheit `none`, Benutzername/Passwort leer.

### Variante B: externer SMTP-Anbieter (z. B. Gmail, Mailbox.org, Microsoft 365)

- Host/Port des Anbieters eintragen, Sicherheit `starttls` (Port 587) oder `ssl` (Port 465)
- Login mit Benutzername + **App-Passwort** (bei Gmail: Google-Konto → Sicherheit → App-Passwörter; bei M365 ggf. SMTP AUTH aktivieren)
- Beispiel Gmail: `--smtp-host smtp.gmail.com --smtp-port 587 --smtp-security starttls --smtp-username du@gmail.com --smtp-password <app-passwort>`

### Mail testen

```bash
sudo python3 -m cvewatch test-mail
```

Erhält `to_addr` eine Mail mit Betreff `[cvewatch@<host>] Test-E-Mail`, ist der Versand ok.

## 5. Mistral-API-Key

1. Einloggen auf [console.mistral.ai](https://console.mistral.ai) → Bereich **API Keys** → neuen Key erstellen (z. B. `sk-...`)
2. Key **nicht** ins Repo committen. Zwei sichere Wege:
   - beim `setup` direkt eingeben ( landet mit `chmod 600` in `/etc/cvewatch/cvewatch.ini` ), **oder**
   - als Umgebungsvariable über systemd-Env-Datei:

```bash
sudo install -m 600 /dev/null /etc/cvewatch/cvewatch.env
sudo bash -c 'echo "MISTRAL_API_KEY=sk-..." >> /etc/cvewatch/cvewatch.env'
sudo bash -c 'echo "CVEWATCH_SMTP_PASSWORD=..." >> /etc/cvewatch/cvewatch.env'   # optional statt ini
```

Die systemd-Unit lädt die Datei über `EnvironmentFile=-/etc/cvewatch/cvewatch.env` (siehe `systemd/cvewatch.service`). Env-Variablen haben Vorrang vor der INI.

### API testen

```bash
sudo python3 -m cvewatch test-ai
```

Antwortet die API mit einem JSON (`{"ok": true, ...}`), ist Key + Endpoint korrekt.

## 6. Testlauf + Dienst installieren

```bash
# einmaliger manueller Prüflauf (holt Feed, prüft CVEs per KI, patcht ggf.):
sudo python3 -m cvewatch scan

# als systemd-Daemon installieren (legt /opt/cvewatch, /etc/cvewatch, Unit an):
sudo python3 -m cvewatch install --start

sudo systemctl status cvewatch
journalctl -u cvewatch -f          # Live-Logs
sudo python3 -m cvewatch status    # letzte Läufe/Verdikte/Alerts aus der State-DB
```

Der Daemon läuft dann alle 5 Stunden (`interval_hours`), startet aber auch sofort einmalig (`run_on_start = true`). Ein Lockfile verhindert parallele Läufe.

## 7. Betrieb & Fehlersuche

- Logs: `journalctl -u cvewatch -f` und Datei `/var/log/cvewatch/cvewatch.log`
- State-DB: `/var/lib/cvewatch/state.db` (SQLite) – Verdikte pro CVE: `updated`, `not_vulnerable`, `no_fix_available`, `investigate`, `update_failed`
- Alert-Mails werden bei Update-Konflikten/Fehlern, fehlgeschlagener KI-Analyse, Feed-/SMTP-Problemen versendet
- Konfiguration anzeigen (Secrets maskiert): `sudo python3 -m cvewatch show-config`
- Deinstallation: `sudo python3 -m cvewatch uninstall --purge`

| Symptom | Ursache/Lösung |
|---|---|
| `Feed nicht erreichbar` | URL in `setup` prüfen, Firewall/HTTPS-Outbound zu logiqit.de testen (`curl -I <feed-url>`) |
| `Mistral API ... 401` | API-Key falsch – `test-ai` mit neuem Key wiederholen |
| Alert-Mail kommt nicht an | `test-mail` ausführen; SMTP-Host/Port/Sicherheit + Credentials prüfen; `journalctl -u cvewatch` nach `Alert-E-Mail konnte nicht gesendet werden` suchen |
| CVE wird nicht erneut geprüft | State-DB merkt sich Verdikte; Zeile löschen: `sqlite3 /var/lib/cvewatch/state.db "DELETE FROM cves WHERE cve_id='CVE-...';"` |
| `Kein unterstützter Paketmanager` | apt/dnf/pacman/apk/zypper muss installiert sein |

## 8. Sicherheitshinweise

- `/etc/cvewatch/` ist `0700`, `cvewatch.ini` und `cvewatch.env` sind `0600` – Keys/Passwörter nie committen (`.gitignore` schützt `cvewatch.ini`/`cvewatch.env`)
- Der Daemon läuft als root (Paket-Updates brauchen das); Updates erfolgen gezielt **pro betroffenem Paket**, nicht als komplettes `upgrade`
- apt läuft mit `--force-confdef/--force-confold`, damit keine interaktiven Prompts hängen bleiben; echte Konflikte landen als Alert-Mail
