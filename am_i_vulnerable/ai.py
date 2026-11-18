import json
import time
import urllib.error
import urllib.request


class AiError(Exception):
    pass


SYSTEM_PROMPT = (
    "You are a security analyst inside an automated patching daemon. "
    "You receive the host's installed packages and newly published CVEs. "
    "Decide for every CVE whether this host is actually vulnerable. "
    "Set vulnerable=true only if one of the listed installed packages is affected; "
    "map product names from the CVE text onto the installed package list "
    "(e.g. 'OpenSSL' -> 'openssl' or 'libssl3', 'Next.js' -> 'node-nextjs' if present). "
    "Use action='update' when a distro package update is expected to fix it, "
    "'investigate' when it looks affected but no package-level fix is clear, "
    "'none' when the host is not affected. "
    "Respond with JSON only, no markdown fences, no text outside the JSON object. "
    'Schema: {"results":[{"cve_id":"CVE-XXXX-XXXXX","vulnerable":true|false,'
    '"confidence":"high|medium|low","affected_packages":[{"package":"<exact installed package name>",'
    '"installed_version":"...","fixed_version":"..."|null,"severity":"critical|high|medium|low"}],'
    '"summary":"one sentence","action":"update|investigate|none"}]}'
)


def build_user_prompt(hostname, distro, packages, cves):
    pkg_lines = "\n".join(f"{pkg.name}={pkg.version}" for pkg in packages) or "(none)"
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
        f"Distro: {distro}\n\n"
        f"Installed packages (name=version):\n{pkg_lines}\n\n"
        f"New CVEs to assess ({len(cves)}):\n\n" + "\n\n".join(blocks)
    )


def extract_json(text):
    if not text:
        raise AiError("Leere Antwort der KI")
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        raise AiError("Antwort der KI enthaelt kein JSON-Objekt")
    try:
        return json.loads(text[start : end + 1])
    except json.JSONDecodeError as exc:
        raise AiError(f"JSON der KI nicht parsebar: {exc}") from exc


class MistralClient:
    def __init__(
        self,
        api_key,
        base_url="https://api.mistral.ai/v1",
        model="mistral-small-latest",
        timeout=90,
        max_retries=3,
        temperature=0.1,
    ):
        if not api_key:
            raise AiError("Mistral API-Key fehlt")
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout
        self.max_retries = max(1, max_retries)
        self.temperature = temperature

    def _post(self, payload):
        request = urllib.request.Request(
            self.base_url + "/chat/completions",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}",
            },
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            return json.loads(response.read().decode("utf-8"))

    def _request(self, payload):
        last_error = None
        for attempt in range(self.max_retries):
            try:
                return self._post(payload)
            except (urllib.error.URLError, KeyError, IndexError, TypeError, ValueError, OSError) as exc:
                last_error = exc
                if attempt < self.max_retries - 1:
                    time.sleep(min(2**attempt, 8))
        raise AiError(f"Mistral API nach {self.max_retries} Versuchen fehlgeschlagen: {last_error}")

    def complete(self, system, user):
        payload = {
            "model": self.model,
            "temperature": self.temperature,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        data = self._request(payload)
        return data["choices"][0]["message"]["content"]

    def complete_with_tools(self, messages, tools):
        payload = {
            "model": self.model,
            "temperature": self.temperature,
            "messages": messages,
            "tools": tools,
            "tool_choice": "auto",
        }
        data = self._request(payload)
        return data["choices"][0]["message"]

    def analyze(self, hostname, distro, packages, cves):
        content = self.complete(SYSTEM_PROMPT, build_user_prompt(hostname, distro, packages, cves))
        data = extract_json(content)
        results = data.get("results")
        if not isinstance(results, list):
            raise AiError("Antwort der KI enthaelt keine 'results'-Liste")
        by_id = {}
        for item in results:
            if isinstance(item, dict) and item.get("cve_id"):
                by_id[str(item["cve_id"]).upper()] = item
        verdicts = []
        for cve in cves:
            item = by_id.get(cve.cve_id)
            if item is None:
                item = {
                    "cve_id": cve.cve_id,
                    "vulnerable": False,
                    "confidence": "low",
                    "affected_packages": [],
                    "summary": "CVE fehlt in der KI-Antwort",
                    "action": "investigate",
                }
            item.setdefault("cve_id", cve.cve_id)
            item.setdefault("vulnerable", False)
            item.setdefault("action", "investigate")
            item.setdefault("affected_packages", [])
            item.setdefault("summary", "")
            verdicts.append(item)
        return verdicts
