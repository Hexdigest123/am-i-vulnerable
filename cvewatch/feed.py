import gzip
import re
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
USER_AGENT = "cvewatch/0.1 (+https://github.com/Hexdigest123/am-i-vulnerable)"


class FeedError(Exception):
    pass


@dataclass
class CveEntry:
    cve_id: str
    title: str = ""
    description: str = ""
    link: str = ""
    published: str = ""
    severity: str = ""
    score: str = ""
    extra: dict = field(default_factory=dict)


def fetch(url, timeout=60):
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "application/rss+xml, application/atom+xml, application/xml, text/xml, */*",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            data = response.read()
    except Exception as exc:
        raise FeedError(f"Feed nicht erreichbar ({url}): {exc}") from exc
    if data[:2] == b"\x1f\x8b":
        try:
            data = gzip.decompress(data)
        except OSError as exc:
            raise FeedError(f"Feed ist gzip-komprimiert aber nicht entpackbar: {exc}") from exc
    return data


def _local(tag):
    return tag.rsplit("}", 1)[-1].lower().replace("-", "_")


def _child_fields(elem):
    fields = {}
    for child in elem:
        text = child.text or child.get("href") or ""
        fields[_local(child.tag)] = text.strip()
    return fields


def _all_text(elem):
    parts = []
    for node in elem.iter():
        if node.text:
            parts.append(node.text)
        if node.tail:
            parts.append(node.tail)
    return " ".join(parts)


_KNOWN_KEYS = {
    "title",
    "link",
    "description",
    "summary",
    "pubdate",
    "published",
    "updated",
    "guid",
    "cve_id",
    "cvss_score",
    "cvss_severity",
}


def parse(data):
    if isinstance(data, bytes):
        data = data.decode("utf-8", errors="replace")
    try:
        root = ET.fromstring(data)
    except ET.ParseError as exc:
        raise FeedError(f"Feed ist kein gueltiges XML: {exc}") from exc
    entries = []
    seen = set()
    for elem in root.iter():
        if _local(elem.tag) not in ("item", "entry"):
            continue
        fields = _child_fields(elem)
        blob = _all_text(elem)
        ids = CVE_RE.findall(blob)
        if not ids:
            continue
        cve_id = ids[0].upper()
        if cve_id in seen:
            continue
        seen.add(cve_id)
        extra = {k: v for k, v in fields.items() if k not in _KNOWN_KEYS and v}
        entries.append(
            CveEntry(
                cve_id=cve_id,
                title=fields.get("title", ""),
                description=fields.get("description") or fields.get("summary", ""),
                link=fields.get("link", ""),
                published=fields.get("pubdate") or fields.get("published") or fields.get("updated", ""),
                severity=fields.get("cvss_severity", ""),
                score=fields.get("cvss_score", ""),
                extra=extra,
            )
        )
    return entries
