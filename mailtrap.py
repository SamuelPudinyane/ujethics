from flask import Flask
from dotenv import load_dotenv
from flask_mail import Mail, Message
from flask import current_app
import os


load_dotenv()

mail = Mail()
# Looking to send emails in production? Check out our Email API/SMTP product!
def configure_mail(app):
    app.config['MAIL_SERVER'] = os.getenv("MAIL_SERVER")
    app.config['MAIL_PORT'] = int(os.getenv("MAIL_PORT", "587"))
    app.config['MAIL_DEFAULT_SENDER'] = 'noreply@example.com'
    app.config['MAIL_USERNAME'] = os.getenv("MAIL_USERNAME")
    app.config['MAIL_PASSWORD'] = os.getenv("MAIL_PASSWORD")
    app.config['MAIL_USE_TLS'] = True
    app.config['MAIL_USE_SSL'] = False
    mail.init_app(app)



def send_email(app, mail, message, recipient):
    with app.app_context():
        msg = Message(
        subject='ETHICS NOTIFICATION',
        recipients=[recipient],
        body=message
    )
    mail.send(msg)
    