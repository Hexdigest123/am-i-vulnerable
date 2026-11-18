import json
import logging

from . import packages as packages_mod
from . import state as state_mod

log = logging.getLogger("am-i-vulnerable")

TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "list_packages",
            "description": (
                "Installierte Pakete mit Versionen lesen. Ohne 'packages' werden alle Pakete geliefert "
                "(auf max_packages limitiert), mit 'packages' nur die genannten Paketnamen."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "packages": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Optionaler Filter auf diese Paketnamen; leer/fehlend = alle Pakete",
                    }
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "update_package",
            "description": (
                "Ein installiertes Paket auf die neueste verfuegbare Version updaten. Nur aufrufen, wenn das Paket "
                "laut CVE betroffen ist. Prueft zuerst, ob ueberhaupt ein Update verfuegbar ist; bei Konflikt/Fehler "
                "wird automatisch eine Alert-E-Mail versendet."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "package": {"type": "string", "description": "Exakter Name des installierten Pakets"},
                    "cve_id": {"type": "string", "description": "CVE, wegen der geupdated wird (optional)"},
                    "reason": {"type": "string", "description": "Kurze Begruendung"},
                },
                "required": ["package", "reason"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "notify_user",
            "description": (
                "Den Administrator per E-Mail informieren, z. B. bei Konflikten, wenn kein Fix verfuegbar ist, "
                "oder fuer wichtige Hinweise aus der Analyse."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "subject": {"type": "string"},
                    "message": {"type": "string"},
                },
                "required": ["subject", "message"],
            },
        },
    },
]

SYSTEM_PROMPT = (
    "You are the patching agent of the am-i-vulnerable daemon on a Linux server. "
    "You receive newly published CVEs from an RSS feed. "
    "Use the tools to inspect the system and act: "
    "1) list_packages to read installed package versions (all or scoped to suspicious packages), "
    "2) update_package to update a package that is actually affected by a CVE (only affected packages, never unrelated ones), "
    "3) notify_user to inform the administrator via e-mail about conflicts, missing fixes or important findings. "
    "Rules: only update packages that are installed AND affected by one of the given CVEs; "
    "update_package already checks whether an update exists and sends an alert on conflicts; "
    "never run other commands, there is no shell tool. "
    "When done, respond with JSON only (no markdown): "
    '{"results":[{"cve_id":"CVE-XXXX-XXXXX","verdict":"updated|not_vulnerable|no_fix_available|update_failed|investigate",'
    '"packages_updated":["name"],"notes":"one sentence"}]} covering every given CVE.'
)


def build_user_prompt(hostname, distro, feed_url, cves):
    blocks = []
    for cve in cves:
        description = (cve.description or "")[:2000]
        blocks.append(
            f"ID: {cve.cve_id}\n"
            f"Title: {cve.title}\n"
            f"Severity: {cve.severity or 'unknown'} Score: {cve.score or 'unknown'}\n"
            f"Link: {cve.link}\n"
            f"Description: {description}"
        )
    return (
        f"Host: {hostname}\n"
        f"Distro: {distro}\n"
        f"Feed: {feed_url}\n\n"
        f"New CVEs to assess and patch if affected ({len(cves)}):\n\n" + "\n\n".join(blocks)
    )


class Harness:
    def __init__(self, client, pm, mailer_getter, store, hostname, cfg, distro):
        self.client = client
        self.pm = pm
        self._mailer_getter = mailer_getter
        self.store = store
        self.hostname = hostname
        self.distro = distro
        self.cfg = cfg
        self.max_iterations = max(1, cfg.get_int("harness", "max_iterations", 12))
        self.max_updates = max(1, cfg.get_int("harness", "max_updates_per_run", 20))
        self.max_packages = cfg.get_int("mistral", "max_packages", 1500)
        self.updates = []
        self.failed = []
        self.alerts = []
        self.tool_log = []

    def run(self, cves, feed_url=""):
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": build_user_prompt(self.hostname, self.distro, feed_url, cves)},
        ]
        final = ""
        exhausted = False
        for _ in range(self.max_iterations):
            msg = self.client.complete_with_tools(messages, TOOLS)
            messages.append(
                {"role": "assistant", "content": msg.get("content"), "tool_calls": msg.get("tool_calls")}
            )
            calls = msg.get("tool_calls") or []
            if not calls:
                final = msg.get("content") or ""
                break
            for call in calls:
                result = self._execute(call)
                messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": call.get("id"),
                        "name": (call.get("function") or {}).get("name"),
                        "content": json.dumps(result, ensure_ascii=False),
                    }
                )
        else:
            exhausted = True
            final = "max_iterations erreicht - Harness abgebrochen"
        log.info(
            "Harness fertig: %d Tool-Calls, %d Updates, %d fehlgeschlagen, %d Alerts, exhausted=%s",
            len(self.tool_log),
            len(self.updates),
            len(self.failed),
            len(self.alerts),
            exhausted,
        )
        return {
            "final": final,
            "exhausted": exhausted,
            "updates": self.updates,
            "failed": self.failed,
            "alerts": self.alerts,
            "tool_calls": self.tool_log,
        }

    def _execute(self, call):
        fn = call.get("function") or {}
        name = fn.get("name", "")
        try:
            args = json.loads(fn.get("arguments") or "{}")
        except (json.JSONDecodeError, TypeError):
            args = {}
        if not isinstance(args, dict):
            args = {}
        self.tool_log.append({"name": name, "args": args})
        log.info("tool call: %s %s", name, args)
        if name == "list_packages":
            return self._list_packages(args)
        if name == "update_package":
            return self._update_package(args)
        if name == "notify_user":
            return self._notify_user(args)
        return {"error": f"unbekanntes Tool: {name}"}

    def _list_packages(self, args):
        installed_map = self.pm.installed_map()
        names = args.get("packages") or []
        if names:
            pkgs = []
            for name in names:
                if isinstance(name, str):
                    pkg = packages_mod.match_package(installed_map, name)
                    if pkg is not None and pkg not in pkgs:
                        pkgs.append(pkg)
        else:
            pkgs = list(installed_map.values())[: self.max_packages]
        return {
            "count": len(pkgs),
            "packages": [{"name": p.name, "version": p.version} for p in pkgs],
        }

    def _update_package(self, args):
        package = (args.get("package") or "").strip()
        cve_id = (args.get("cve_id") or "").strip().upper()
        reason = args.get("reason") or ""
        if not package:
            return {"ok": False, "error": "Parameter 'package' fehlt"}
        installed_map = self.pm.installed_map()
        pkg = packages_mod.match_package(installed_map, package)
        if pkg is None:
            return {"ok": False, "error": f"Paket '{package}' ist nicht installiert", "package": package}
        if len(self.updates) + len(self.failed) >= self.max_updates:
            return {"ok": False, "error": "max_updates_per_run erreicht - Rest bitte manuell", "package": pkg.name}
        if not self.pm.update_available(pkg.name):
            return {
                "ok": False,
                "reason": "kein Update verfuegbar",
                "package": pkg.name,
                "installed": pkg.version,
            }
        res = self.pm.update(pkg.name)
        if res.is_conflict:
            entry = {
                "cve_id": cve_id,
                "package": pkg.name,
                "returncode": res.returncode,
                "output_tail": res.output[-2000:],
            }
            self.failed.append(entry)
            body = "\n".join(
                [
                    f"CVE: {cve_id or '-'}",
                    f"Paket: {pkg.name}",
                    f"Installierte Version: {pkg.version}",
                    f"Grund: {reason}",
                    f"Befehl: {' '.join(res.command)}",
                    f"Returncode: {res.returncode}",
                    "",
                    "Ausgabe (gekürzt):",
                    res.output[-3000:],
                    "",
                    "Bitte manuell pruefen und beheben.",
                ]
            )
            subject = f"Update fehlgeschlagen / Konflikt bei Paket '{pkg.name}'" + (f" ({cve_id})" if cve_id else "")
            alert = self._notify(subject, body)
            return {
                "ok": False,
                "conflict": True,
                "package": pkg.name,
                "returncode": res.returncode,
                "output_tail": res.output[-1500:],
                "alert_sent": alert["sent"],
            }
        self.updates.append({"cve_id": cve_id, "package": pkg.name, "from": pkg.version, "reason": reason})
        log.info("Paket %s aktualisiert (von %s) wegen %s", pkg.name, pkg.version, cve_id or reason)
        return {"ok": True, "package": pkg.name, "installed_before": pkg.version, "reason": reason}

    def _notify_user(self, args):
        return self._notify(args.get("subject") or "Hinweis", args.get("message") or "")

    def _notify(self, subject, body):
        full_subject = f"[am-i-vulnerable@{self.hostname}] {subject}"
        text = "\n".join(
            [
                f"Host: {self.hostname}",
                f"Zeit (UTC): {state_mod.utcnow()}",
                "Daemon: am-i-vulnerable (Mini-Harness)",
                "",
                body,
            ]
        )
        try:
            self._mailer_getter().send(full_subject, text)
            self.store.record_alert(full_subject, ok=True)
            entry = {"subject": full_subject, "sent": True}
        except Exception as exc:
            log.error("notify_user fehlgeschlagen: %s", exc)
            try:
                self.store.record_alert(full_subject, ok=False, error=str(exc))
            except Exception:
                pass
            entry = {"subject": full_subject, "sent": False, "error": str(exc)}
        self.alerts.append(entry)
        return entry
