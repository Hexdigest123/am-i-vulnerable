import unittest
from unittest import mock

from cvewatch import mailer
from cvewatch.mailer import MailError, Mailer, build_message


class FakeSMTP:
    instances = []

    def __init__(self, host, port, timeout=None):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.started_tls = False
        self.logged_in = None
        self.sent = []
        FakeSMTP.instances.append(self)

    def starttls(self):
        self.started_tls = True

    def login(self, user, password):
        self.logged_in = (user, password)

    def send_message(self, msg):
        self.sent.append(msg)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class BuildMessageTest(unittest.TestCase):
    def test_headers(self):
        msg = build_message("a@b.c", "d@e.f", "Betreff", "Text")
        self.assertEqual(msg["From"], "a@b.c")
        self.assertEqual(msg["To"], "d@e.f")
        self.assertEqual(msg["Subject"], "Betreff")
        self.assertIn("Text", msg.get_content())
        self.assertTrue(msg["Message-ID"])


class MailerTest(unittest.TestCase):
    def setUp(self):
        FakeSMTP.instances = []

    def _mailer(self, security="none", username=""):
        return Mailer("smtp.example.com", 587, security, username, "pw", "from@x", "to@x", timeout=5)

    def test_send_starttls_with_login(self):
        with mock.patch.object(mailer.smtplib, "SMTP", FakeSMTP), mock.patch.object(mailer.smtplib, "SMTP_SSL", FakeSMTP):
            self._mailer("starttls", "user").send("S", "B")
        smtp = FakeSMTP.instances[0]
        self.assertTrue(smtp.started_tls)
        self.assertEqual(smtp.logged_in, ("user", "pw"))
        self.assertEqual(len(smtp.sent), 1)
        self.assertEqual(smtp.sent[0]["To"], "to@x")

    def test_send_ssl_no_login(self):
        with mock.patch.object(mailer.smtplib, "SMTP", FakeSMTP), mock.patch.object(mailer.smtplib, "SMTP_SSL", FakeSMTP):
            self._mailer("ssl").send("S", "B")
        smtp = FakeSMTP.instances[0]
        self.assertIsNone(smtp.logged_in)
        self.assertEqual(len(smtp.sent), 1)

    def test_missing_addresses(self):
        with self.assertRaises(MailError):
            Mailer("h", 25, "none", "", "", "", "to@x").send("S", "B")
        with self.assertRaises(MailError):
            Mailer("h", 25, "none", "", "", "from@x", "").send("S", "B")

    def test_smtp_failure_wrapped(self):
        class FailingSMTP(FakeSMTP):
            def send_message(self, msg):
                import smtplib

                raise smtplib.SMTPException("nope")

        with mock.patch.object(mailer.smtplib, "SMTP", FailingSMTP):
            with self.assertRaises(MailError):
                self._mailer().send("S", "B")


if __name__ == "__main__":
    unittest.main()
