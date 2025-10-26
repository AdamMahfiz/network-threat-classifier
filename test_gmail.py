import smtplib
import os
from dotenv import load_dotenv

load_dotenv()

smtp_server = "smtp.gmail.com"
port = 587
sender = os.environ.get('MAIL_USERNAME', 'your_email@gmail.com')
password = os.environ.get('MAIL_PASSWORD', 'your_app_password')  # Use environment variable

try:
    server = smtplib.SMTP(smtp_server, port)
    server.starttls()
    server.login(sender, password)
    print("Login successful!")
    server.quit()
except Exception as e:
    print("Error:", e)