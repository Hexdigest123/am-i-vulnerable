import unittest
import urllib.error

from cvewatch import ai
from cvewatch.feed import CveEntry
from cvewatch.packages import Package


class ExtractJsonTest(unittest.TestCase):
    def test_plain(self):
        self.assertEqual(ai.extract_json('{"a": 1}'), {"a": 1})

    def test_fenced(self):
        text = 'Hier ist das Ergebnis:\n```json\n{"results": []}\n```\nFertig.'
        self.assertEqual(ai.extract_json(text), {"results": []})

    def test_prose_around(self):
        text = 'Sure! {"results": [{"cve_id": "CVE-2025-1"}]} hope that helps'
        data = ai.extract_json(text)
        self.assertEqual(data["results"][0]["cve_id"], "CVE-2025-1")

    def test_invalid(self):
        with self.assertRaises(ai.AiError):
            ai.extract_json("garbage without json")
        with self.assertRaises(ai.AiError):
            ai.extract_json("")


class PromptTest(unittest.TestCase):
    def test_prompt_contains_packages_and_cves(self):
        cves = [CveEntry(cve_id="CVE-2025-12345", title="RCE in Foo", description="desc", link="http://x")]
        packages = [Package("openssl", "3.0.13-1"), Package("nginx", "1.24.0")]
        prompt = ai.build_user_prompt("myhost", "Debian 12", packages, cves)
        self.assertIn("openssl=3.0.13-1", prompt)
        self.assertIn("nginx=1.24.0", prompt)
        self.assertIn("CVE-2025-12345", prompt)
        self.assertIn("myhost", prompt)
        self.assertIn("Debian 12", prompt)


class FakeClient(ai.MistralClient):
    def __init__(self, responses, max_retries=3):
        super().__init__("test-key", max_retries=max_retries)
        self.responses = list(responses)
        self.calls = 0

    def _post(self, payload):
        self.calls += 1
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return {"choices": [{"message": {"content": item}}]}


class AnalyzeTest(unittest.TestCase):
    def setUp(self):
        self._sleep = ai.time.sleep
        ai.time.sleep = lambda *_: None

    def tearDown(self):
        ai.time.sleep = self._sleep

    def test_analyze_parses_results(self):
        payload = (
            '{"results": [{"cve_id": "CVE-2025-12345", "vulnerable": true, "confidence": "high", '
            '"affected_packages": [{"package": "openssl", "installed_version": "3.0.13", "fixed_version": "3.0.15"}], '
            '"summary": "openssl betroffen", "action": "update"}]}'
        )
        client = FakeClient([payload])
        cves = [CveEntry(cve_id="CVE-2025-12345")]
        verdicts = client.analyze("host", "Debian", [Package("openssl", "3.0.13")], cves)
        self.assertEqual(len(verdicts), 1)
        self.assertTrue(verdicts[0]["vulnerable"])
        self.assertEqual(verdicts[0]["action"], "update")
        self.assertEqual(verdicts[0]["affected_packages"][0]["package"], "openssl")

    def test_missing_cve_gets_investigate(self):
        client = FakeClient(['{"results": []}'])
        cves = [CveEntry(cve_id="CVE-2025-99999")]
        verdicts = client.analyze("host", "Debian", [], cves)
        self.assertEqual(verdicts[0]["action"], "investigate")
        self.assertFalse(verdicts[0]["vulnerable"])

    def test_retries_then_success(self):
        client = FakeClient([urllib.error.URLError("boom"), '{"results": []}'])
        content = client.complete("s", "u")
        self.assertIn("results", content)
        self.assertEqual(client.calls, 2)

    def test_retries_exhausted(self):
        client = FakeClient([urllib.error.URLError("boom")] * 5, max_retries=2)
        with self.assertRaises(ai.AiError):
            client.complete("s", "u")
        self.assertEqual(client.calls, 2)

    def test_no_key(self):
        with self.assertRaises(ai.AiError):
            ai.MistralClient("")


if __name__ == "__main__":
    unittest.main()
