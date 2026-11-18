import fcntl
import logging
import os
import platform
import signal
import socket
import time
import traceback

from . import ai, feed, mailer, packages
from . import state as state_mod

log = logging.getLogger("am-i-vulnerable")


def setup_logging(log_file=None):
    handlers = [logging.StreamHandler()]
    if log_file:
        try:
            directory = os.path.dirname(log_file)
            if directory:
                os.makedirs(directory, exist_ok=True)
            handlers.append(logging.FileHandler(log_file))
        except OSError as exc:
            print(f"Warnung: Logdatei {log_file} nicht schreibbar: {exc}")
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        handlers=handlers,
        force=True,
    )


class Daemon:
    def __init__(self, cfg, fetcher=None, ai_client=None, pkg_manager=None, mailer_obj=None, store=None):
        self.cfg = cfg
        self.fetcher = fetcher or feed.fetch
        self.ai_client = ai_client
        self.pkg_manager = pkg_manager
        self.mailer = mailer_obj
        self.store = store or state_mod.StateStore(cfg.state_db())
        self.hostname = socket.gethostname()
        self._stop = False
        self._lock_fh = None
        self._owns_lock = False

    def request_stop(self, *args):
        self._stop = True

    def install_signal_handlers(self):
        signal.signal(signal.SIGTERM, self.request_stop)
        signal.signal(signal.SIGINT, self.request_stop)

    def _acquire_lock(self):
        lock_path = self.store.path + ".lock"
        fh = open(lock_path, "w")
        try:
            fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return fh
        except OSError:
            fh.close()
            return None

    def run_forever(self):
        interval = max(0.05, self.cfg.get_float("daemon", "interval_hours", 5.0)) * 3600
        self._lock_fh = self._acquire_lock()
        self._owns_lock = True
        if self._lock_fh is None:
            log.error("Lock (%s.lock) wird bereits gehalten - laeuft schon eine Instanz?", self.store.path)
            return 1
        try:
            if self.cfg.get_bool("daemon", "run_on_start", True):
                self.scan(acquire=False)
            while not self._stop:
                slept = 0.0
                while slept < interval and not self._stop:
                    step = min(60.0, interval - slept)
                    time.sleep(step)
                    slept += step
                if not self._stop:
                    self.scan(acquire=False)
            log.info("Daemon wird beendet (Signal erhalten)")
            return 0
        finally:
            if self._owns_lock and self._lock_fh is not None:
                self._lock_fh.close()
                self._lock_fh = None
                self._owns_lock = False

    def _get_ai_client(self):
        if self.ai_client is None:
            self.ai_client = ai.MistralClient(
                self.cfg.api_key(),
                base_url=self.cfg.get("mistral", "base_url", "https://api.mistral.ai/v1"),
                model=self.cfg.get("mistral", "model", "mistral-small-latest"),
                timeout=self.cfg.get_int("mistral", "timeout_seconds", 90),
                max_retries=self.cfg.get_int("mistral", "max_retries", 3),
                temperature=self.cfg.get_float("mistral", "temperature", 0.1),
            )
        return self.ai_client

    def _get_mailer(self):
        if self.mailer is None:
            self.mailer = mailer.Mailer(
                self.cfg.get("mail", "smtp_host", "127.0.0.1"),
                self.cfg.get_int("mail", "smtp_port", 25),
                self.cfg.get("mail", "security", "none"),
                self.cfg.get("mail", "username", ""),
                self.cfg.smtp_password(),
                self.cfg.get("mail", "from_addr", ""),
                self.cfg.get("mail", "to_addr", ""),
                timeout=self.cfg.get_int("mail", "timeout_seconds", 30),
            )
        return self.mailer

    def send_alert(self, subject, body, cve_id=None, package=None):
        full_subject = f"[am-i-vulnerable@{self.hostname}] {subject}"
        log.warning("ALERT: %s", subject)
        try:
            self._get_mailer().send(full_subject, body)
            self.store.record_alert(full_subject, cve_id=cve_id, package=package, ok=True)
        except Exception as exc:
            log.error("Alert-E-Mail konnte nicht gesendet werden: %s", exc)
            try:
                self.store.record_alert(full_subject, cve_id=cve_id, package=package, ok=False, error=str(exc))
            except Exception:
                pass

    def scan(self, acquire=True):
        started = state_mod.utcnow()
        log.info("Scan gestartet")
        updated = []
        alerts = 0
        new_count = 0
        if acquire and self._lock_fh is None:
            self._lock_fh = self._acquire_lock()
            if self._lock_fh is None:
                log.error("Lock wird bereits gehalten - Scan wird uebersprungen")
                return {"error": "lock held by another instance"}
            self._owns_lock = True
        try:
            data = self.fetcher(self.cfg.feed_url, timeout=self.cfg.get_int("feed", "timeout_seconds", 60))
            entries = feed.parse(data)
            processed = self.store.processed_cves()
            new_entries = [entry for entry in entries if entry.cve_id not in processed]
            new_count = len(new_entries)
            log.info("Feed geladen: %d Eintraege, davon %d neu", len(entries), new_count)
            if not new_entries:
                self.store.record_run(started, "ok", "keine neuen CVEs", 0, [], 0)
                return {"new": 0, "updated": [], "alerts": 0}
            pm = self.pkg_manager or packages.detect()
            if self.cfg.get_bool("daemon", "refresh_index", True):
                res = pm.refresh_index()
                if res.is_conflict:
                    log.error("Paketindex konnte nicht aktualisiert werden (rc=%s)", res.returncode)
                    self.send_alert(
                        "Paketindex konnte nicht aktualisiert werden",
                        self._alert_body(cmd=res),
                    )
                    alerts += 1
            installed = pm.list_installed()
            max_packages = self.cfg.get_int("mistral", "max_packages", 1500)
            if len(installed) > max_packages:
                log.warning("Paketliste wird auf %d Eintraege begrenzt", max_packages)
                installed = installed[:max_packages]
            distro = self._distro()
            batch_size = max(1, self.cfg.get_int("mistral", "batch_size", 5))
            client = self._get_ai_client()
            for offset in range(0, len(new_entries), batch_size):
                batch = new_entries[offset : offset + batch_size]
                try:
                    verdicts = client.analyze(self.hostname, distro, installed, batch)
                except Exception as exc:
                    log.error("KI-Analyse fehlgeschlagen: %s", exc)
                    self.send_alert(
                        "KI-Analyse (Mistral API) fehlgeschlagen - betroffene CVEs werden beim naechsten Lauf erneut geprueft",
                        self._alert_body(
                            error=str(exc),
                            cves=[entry.cve_id for entry in batch],
                        ),
                    )
                    alerts += 1
                    continue
                for entry, verdict in zip(batch, verdicts):
                    alerts += self._handle_verdict(entry, verdict, pm, installed, updated)
            self.store.record_run(started, "ok", f"{new_count} neue CVEs geprueft", new_count, updated, alerts)
            log.info("Scan fertig: %d neu, %d Updates, %d Alerts", new_count, len(updated), alerts)
            return {"new": new_count, "updated": updated, "alerts": alerts}
        except Exception as exc:
            log.error("Scan fehlgeschlagen: %s\n%s", exc, traceback.format_exc())
            self.send_alert(
                "Scan fehlgeschlagen (unerwarteter Fehler)",
                self._alert_body(error=traceback.format_exc()),
            )
            alerts += 1
            self.store.record_run(started, "error", str(exc), new_count, updated, alerts)
            return {"new": new_count, "updated": updated, "alerts": alerts, "error": str(exc)}
        finally:
            if self._owns_lock and self._lock_fh is not None:
                self._lock_fh.close()
                self._lock_fh = None
                self._owns_lock = False

    def _distro(self):
        try:
            with open("/etc/os-release", encoding="utf-8") as fh:
                for line in fh:
                    if line.startswith("PRETTY_NAME="):
                        return line.split("=", 1)[1].strip().strip('"')
        except OSError:
            pass
        return platform.platform()

    def _handle_verdict(self, entry, verdict, pm, installed, updated):
        alerts = 0
        cve = entry.cve_id
        vulnerable = bool(verdict.get("vulnerable"))
        action = verdict.get("action", "none")
        summary = verdict.get("summary", "")
        log.info("%s: vulnerable=%s action=%s (%s)", cve, vulnerable, action, summary)
        if not vulnerable or action == "none":
            self.store.mark_processed(cve, "not_vulnerable", {"verdict": verdict, "published": entry.published})
            return alerts
        if action == "investigate":
            self.store.mark_processed(cve, "investigate", {"verdict": verdict, "published": entry.published})
            return alerts
        installed_map = {pkg.name.lower(): pkg for pkg in installed}
        affected = verdict.get("affected_packages") or []
        if not affected:
            self.store.mark_processed(cve, "investigate", {"verdict": verdict, "published": entry.published})
            return alerts
        for aff in affected:
            pkg = packages.match_package(installed_map, aff.get("package", ""))
            if pkg is None:
                log.info("%s: betroffenes Paket '%s' ist nicht installiert - uebersprungen", cve, aff.get("package"))
                continue
            if not pm.update_available(pkg.name):
                log.warning(
                    "%s: Paket %s betroffen (installiert %s), aber kein Update verfuegbar (Fix lt. KI: %s)",
                    cve,
                    pkg.name,
                    pkg.version,
                    aff.get("fixed_version"),
                )
                self.store.mark_processed(
                    cve,
                    "no_fix_available",
                    {
                        "verdict": verdict,
                        "package": pkg.name,
                        "installed": pkg.version,
                        "fixed": aff.get("fixed_version"),
                        "published": entry.published,
                    },
                )
                continue
            res = pm.update(pkg.name)
            if not res.is_conflict:
                log.info("%s: Paket %s erfolgreich aktualisiert", cve, pkg.name)
                updated.append({"cve": cve, "package": pkg.name})
                self.store.mark_processed(
                    cve,
                    "updated",
                    {"verdict": verdict, "package": pkg.name, "installed": pkg.version, "published": entry.published},
                )
            else:
                log.error("%s: Update von %s fehlgeschlagen (rc=%s)", cve, pkg.name, res.returncode)
                self.send_alert(
                    f"Update fehlgeschlagen / Konflikt bei Paket '{pkg.name}' ({cve})",
                    self._alert_body(
                        cve=cve,
                        package=pkg.name,
                        installed=pkg.version,
                        fixed=aff.get("fixed_version"),
                        cmd=res,
                    ),
                    cve_id=cve,
                    package=pkg.name,
                )
                alerts += 1
                self.store.mark_processed(
                    cve,
                    "update_failed",
                    {
                        "verdict": verdict,
                        "package": pkg.name,
                        "installed": pkg.version,
                        "returncode": res.returncode,
                        "output_tail": res.output[-2000:],
                        "published": entry.published,
                    },
                )
        return alerts

    def _alert_body(self, cve=None, package=None, installed=None, fixed=None, cmd=None, error=None, cves=None):
        lines = [
            f"Host: {self.hostname}",
            f"Zeit (UTC): {state_mod.utcnow()}",
            "Daemon: am-i-vulnerable",
            "",
        ]
        if cve:
            lines.append(f"CVE: {cve}")
        if cves:
            lines.append("Betroffene CVEs: " + ", ".join(cves))
        if package:
            lines.append(f"Paket: {package}")
        if installed:
            lines.append(f"Installierte Version: {installed}")
        if fixed:
            lines.append(f"Fix-Version laut KI: {fixed}")
        if error:
            lines.extend(["", "Fehler:", error[-3000:]])
        if cmd is not None:
            lines.extend(
                [
                    "",
                    "Befehl:",
                    " ".join(cmd.command),
                    "",
                    f"Returncode: {cmd.returncode}",
                    "",
                    "Ausgabe (gekürzt):",
                    cmd.output[-3000:],
                ]
            )
        lines.extend(
            [
                "",
                "Bitte manuell pruefen und beheben. Als 'update_failed' markierte CVEs werden nicht automatisch erneut versucht.",
            ]
        )
        return "\n".join(lines)
