import smtplib
from email.message import EmailMessage
from email.utils import formatdate, make_msgid


class MailError(Exception):
    pass


def build_message(from_addr, to_addr, subject, body):
    msg = EmailMessage()
    msg["From"] = from_addr
    msg["To"] = to_addr
    msg["Subject"] = subject
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid("cvewatch")
    msg.set_content(body)
    return msg


class Mailer:
    def __init__(self, host, port, security, username, password, from_addr, to_addr, timeout=30):
        self.host = host
        self.port = int(port)
        self.security = (security or "none").lower()
        self.username = username
        self.password = password
        self.from_addr = from_addr
        self.to_addr = to_addr
        self.timeout = timeout

    def send(self, subject, body):
        if not self.from_addr or not self.to_addr:
            raise MailError("Absender (from_addr) und Empfaenger (to_addr) sind nicht konfiguriert")
        if not self.host:
            raise MailError("SMTP-Host ist nicht konfiguriert")
        msg = build_message(self.from_addr, self.to_addr, subject, body)
        try:
            if self.security == "ssl":
                server = smtplib.SMTP_SSL(self.host, self.port, timeout=self.timeout)
            else:
                server = smtplib.SMTP(self.host, self.port, timeout=self.timeout)
                if self.security == "starttls":
                    server.starttls()
            with server:
                if self.username:
                    server.login(self.username, self.password)
                server.send_message(msg)
        except (smtplib.SMTPException, OSError) as exc:
            raise MailError(f"E-Mail konnte nicht gesendet werden ({self.host}:{self.port}): {exc}") from exc
