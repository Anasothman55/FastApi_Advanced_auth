from typing import List
from fastapi_mail import FastMail, ConnectionConfig, MessageSchema, MessageType
from pydantic import EmailStr
from jinja2 import Environment, FileSystemLoader
from ..core.config import setting
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent

mail_config = ConnectionConfig(
  MAIL_USERNAME= setting.MAIL_USERNAME,
  MAIL_PASSWORD= setting.MAIL_PASSWORD,
  MAIL_FROM= setting.MAIL_FROM,
  MAIL_PORT= 587,
  MAIL_SERVER = setting.MAIL_SERVER,
  MAIL_FROM_NAME =  "Monix",#setting.MAIL_FROM_NAME,
  MAIL_STARTTLS = True,
  MAIL_SSL_TLS = False,
  USE_CREDENTIALS = True,
  VALIDATE_CERTS = True,
  TEMPLATE_FOLDER = Path(BASE_DIR, "templates"),
)



mail = FastMail(
  config= mail_config
)

env = Environment(loader=FileSystemLoader(str(mail_config.TEMPLATE_FOLDER)))

def render_template(template_name: str, context: dict):
  """Renders the email template with the given context"""
  context["static_url"] = "http://127.0.0.1:8000/static/"
  template = env.get_template(template_name)
  return template.render(context)


def create_message(recipients: List[EmailStr], subject: str, body: str):
  
  message = MessageSchema(
    subject=subject,
    recipients=recipients,
    body=body,
    subtype=MessageType.html
  )

  return message


env = Environment(loader=FileSystemLoader(str(mail_config.TEMPLATE_FOLDER)))






