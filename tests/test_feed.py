import gzip
import os
import tempfile
import unittest

from cvewatch import feed


RSS_SAMPLE = """<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>CVE Feed</title>
    <link>https://logiqit.de/api/cve/feed.xml</link>
    <item>
      <title>CVE-2025-12345 Remote code execution in Foo</title>
      <link>https://nvd.nist.gov/vuln/detail/CVE-2025-12345</link>
      <description>A critical RCE in Foo before version 2.0.</description>
      <pubDate>Mon, 06 Jan 2025 10:00:00 GMT</pubDate>
      <guid>CVE-2025-12345</guid>
      <cve_id>CVE-2025-12345</cve_id>
      <cvss_score>9.8</cvss_score>
      <cvss_severity>CRITICAL</cvss_severity>
      <vendors>foo</vendors>
    </item>
    <item>
      <title>CVE-2025-67890 Buffer overflow in Bar</title>
      <link>https://nvd.nist.gov/vuln/detail/CVE-2025-67890</link>
      <description>Heap overflow in Bar &lt; 1.2.</description>
      <pubDate>Mon, 06 Jan 2025 09:00:00 GMT</pubDate>
      <cvss_score>7.5</cvss_score>
      <cvss_severity>HIGH</cvss_severity>
    </item>
    <item>
      <title>CVE-2025-12345 Duplikat</title>
      <description>Duplikat zum Dedup-Test.</description>
    </item>
  </channel>
</rss>
"""

NVD_SAMPLE = """<?xml version="1.0" encoding="UTF-8"?>
<nvd:nvd xmlns:nvd="http://scap.nist.gov/schema/feed/vulnerability/2.0" xmlns:vuln="http://scap.nist.gov/schema/vulnerability/0.4">
  <vuln:entry id="CVE-2024-11111">
    <vuln:cve-id>CVE-2024-11111</vuln:cve-id>
    <vuln:published-date>2024-01-01T00:00:00.000Z</vuln:published-date>
    <vuln:description>Something in Baz.</vuln:description>
  </vuln:entry>
</nvd:nvd>
"""

ATOM_SAMPLE = """<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <title>CVE Atom</title>
  <entry>
    <title>CVE-2025-22222 in Qux</title>
    <link href="https://example.org/CVE-2025-22222"/>
    <summary>Atom summary for CVE-2025-22222.</summary>
    <published>2025-02-02T00:00:00Z</published>
  </entry>
</feed>
"""


class ParseTest(unittest.TestCase):
    def test_rss_items(self):
        entries = feed.parse(RSS_SAMPLE)
        self.assertEqual([e.cve_id for e in entries], ["CVE-2025-12345", "CVE-2025-67890"])
        first = entries[0]
        self.assertIn("Remote code execution", first.title)
        self.assertEqual(first.score, "9.8")
        self.assertEqual(first.severity, "CRITICAL")
        self.assertEqual(first.link, "https://nvd.nist.gov/vuln/detail/CVE-2025-12345")
        self.assertEqual(first.published, "Mon, 06 Jan 2025 10:00:00 GMT")
        self.assertIn("A critical RCE", first.description)
        self.assertEqual(first.extra.get("vendors"), "foo")

    def test_dedup(self):
        entries = feed.parse(RSS_SAMPLE)
        ids = [e.cve_id for e in entries]
        self.assertEqual(len(ids), len(set(ids)))

    def test_nvd_namespaced(self):
        entries = feed.parse(NVD_SAMPLE)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].cve_id, "CVE-2024-11111")
        self.assertIn("Baz", entries[0].description)

    def test_atom(self):
        entries = feed.parse(ATOM_SAMPLE)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].cve_id, "CVE-2025-22222")
        self.assertEqual(entries[0].link, "https://example.org/CVE-2025-22222")
        self.assertIn("Atom summary", entries[0].description)

    def test_invalid_xml(self):
        with self.assertRaises(feed.FeedError):
            feed.parse("<rss><channel>")

    def test_no_cve_items_skipped(self):
        xml = "<rss><channel><item><title>no cve here</title></item></channel></rss>"
        self.assertEqual(feed.parse(xml), [])

    def test_bytes_input(self):
        entries = feed.parse(RSS_SAMPLE.encode("utf-8"))
        self.assertEqual(len(entries), 2)


class FetchTest(unittest.TestCase):
    def test_fetch_plain_and_gzip_via_file_url(self):
        with tempfile.TemporaryDirectory() as tmp:
            plain = os.path.join(tmp, "feed.xml")
            with open(plain, "w", encoding="utf-8") as fh:
                fh.write(RSS_SAMPLE)
            data = feed.fetch("file://" + plain, timeout=10)
            self.assertIn(b"CVE-2025-12345", data)
            gz = os.path.join(tmp, "feed.xml.gz")
            with open(gz, "wb") as fh:
                fh.write(gzip.compress(RSS_SAMPLE.encode("utf-8")))
            data = feed.fetch("file://" + gz, timeout=10)
            self.assertIn(b"CVE-2025-12345", data)

    def test_fetch_error(self):
        with self.assertRaises(feed.FeedError):
            feed.fetch("file:///nonexistent/feed.xml", timeout=5)


if __name__ == "__main__":
    unittest.main()
