import smtplib
import os
import time
import markdown
from email.mime.text import MIMEText
from dotenv import load_dotenv

load_dotenv()

EMAIL_USER = os.getenv("EMAIL_USER")
EMAIL_PASS = os.getenv("EMAIL_PASS")
EMAIL_TO = os.getenv("EMAIL_TO")


def mailer_agent(state):
    print("-------------------------SENDING EMAILS-------------------------")
    time.sleep(2.5)

    report_md = state.get("report", "No report generated")

    # Convert Markdown → HTML
    report_html = markdown.markdown(report_md)

    msg = MIMEText(report_html, "html")   # send as HTML
    msg["Subject"] = "Threat Hunter Investigation Report"
    msg["From"] = EMAIL_USER
    msg["To"] = EMAIL_TO

    with smtplib.SMTP("smtp.gmail.com", 587) as server:
        server.starttls()
        server.login(EMAIL_USER, EMAIL_PASS)
        server.send_message(msg)

    print("EMAIL SENT")

    return state