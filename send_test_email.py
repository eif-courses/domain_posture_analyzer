import os
import smtplib
from email.message import EmailMessage
from email.utils import formataddr, make_msgid
from dotenv import load_dotenv

load_dotenv()

SMTP_HOST = os.getenv("SMTP_HOST", "smtp.hostinger.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASS = os.getenv("SMTP_PASS")

TO_EMAIL = os.getenv("TO_EMAIL")

if not all([SMTP_USER, SMTP_PASS, TO_EMAIL]):
    raise SystemExit("Missing env vars. Set SMTP_USER, SMTP_PASS, TO_EMAIL in .env")

def send_email(
    subject: str,
    text_body: str,
    to_email: str,
    display_from_name: str | None = None,
    header_from_email: str | None = None,
    reply_to: str | None = None,
) -> None:
    """
    Safe sending via authenticated SMTP.

    - The actual sending identity is controlled by SMTP_USER/SMTP_PASS.
    - header_from_email can change the visible From header, BUT many providers
      will rewrite it or reject it unless you have permission.
    - reply_to is the recommended way to let recipients reply to another address.
    """
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["To"] = to_email
    msg["Message-ID"] = make_msgid()

    # Default: From is your authenticated mailbox
    from_email = header_from_email or SMTP_USER
    from_name = display_from_name or "Programuoki Mail"

    msg["From"] = formataddr((from_name, from_email))

    if reply_to:
        msg["Reply-To"] = reply_to

    msg.set_content(text_body)

    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=20) as server:
        server.ehlo()
        server.starttls()
        server.ehlo()
        server.login(SMTP_USER, SMTP_PASS)
        server.send_message(msg)

    print(f"Sent to {to_email} via {SMTP_HOST}:{SMTP_PORT}")
    print(f"SMTP auth user: {SMTP_USER}")
    print(f"Header From: {msg['From']}")
    if reply_to:
        print(f"Reply-To: {reply_to}")

if __name__ == "__main__":
    # Normal send (recommended)
    send_email(
        subject="DMARC Demo (normal authenticated send)",
        text_body="Hello! This is a test email sent via authenticated SMTP.\n\nNext step: check Outlook headers (Authentication-Results).",
        to_email=TO_EMAIL,
        display_from_name="Programvimo imone ir programavimo paslaugos (programuoki.lt)",
        reply_to="fake@programuoki.lt"
    )

    # OPTIONAL: try changing visible From (often rewritten/blocked)
    # Best practice is to keep From as your real mailbox and use Reply-To instead.
    #
    # send_email(
    #     subject="DMARC Demo (attempt different From)",
    #     text_body="This attempts a different From header. Many providers will rewrite or reject it.",
    #     to_email=TO_EMAIL,
    #     display_from_name="Fake Display",
    #     header_from_email="fake@programuoki.lt",
    #     reply_to="marius@programuoki.lt",
    # )