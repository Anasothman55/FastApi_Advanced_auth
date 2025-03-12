from typing import List
from pydantic import EmailStr
from .index import render_template, create_message, mail




class UserAuthEmail:
  
  DEFAULT_MESSAGE = "Verification email sent successfully please check your email address and verify your account."
  @classmethod
  async def send_verification_email(cls,recipient: List[EmailStr], datadict: dict, msg: str = None) -> dict:
    """Sends verification email using the template."""
    if msg is None:
      msg = cls.DEFAULT_MESSAGE

    context = datadict
    html_content = render_template("verify_email.html", context)
    message = create_message(recipients=recipient, subject="Welcome to our platform", body=html_content)

    await mail.send_message(message)
    return {"message": msg}

  @classmethod
  async def send_reset_password_email(cls,recipient: List[EmailStr], datadict: dict, msg: str = None) -> dict:
    """Sends reset password email using the template."""
    if msg is None:
      msg = cls.DEFAULT_MESSAGE

    context = datadict
    html_content = render_template("reset_password_email.html", context)
    message = create_message(recipients= recipient, subject="Reset your password", body=html_content)

    await mail.send_message(message)
    return {"message": msg}





