from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, EmailStr
import os
from dotenv import load_dotenv
from sib_api_v3_sdk import Configuration, ApiClient, TransactionalEmailsApi, SendSmtpEmail

# Load environment variables
load_dotenv()

app = FastAPI()

# Brevo API key setup
config = Configuration()
config.api_key['api-key'] = os.getenv("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")

# Initialize API client
client = ApiClient(configuration=config)
email_api = TransactionalEmailsApi(client)

# Email templates and basic model
class InviteRequest(BaseModel):
    email: EmailStr
    invite_link: str

class AlertEmail(BaseModel):
    email: EmailStr
    username: str

class LoginAlert(BaseModel):
    email: EmailStr
    username: str
    login_time: str

# Helper function to send an email
def send_email(subject: str, to_email: str, content: str):
    send_email = SendSmtpEmail(
        to=[{"email": to_email}],
        subject=subject,
        html_content=content,
        sender={"name": "Your App Name", "email": "your_email@example.com"}
    )

    try:
        email_api.send_transac_email(send_email)
        return {"message": "Email sent successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    
@app.post("/send-invite/")
async def send_invite(invite: InviteRequest):
    subject = "You're Invited!"
    invite_link = invite.invite_link
    content = f"""
    <h1>Welcome to Our Platform!</h1>
    <p>You've been invited to join our platform. Please click on the link below to sign up:</p>
    <a href="{invite_link}">Complete Your Registration</a>
    """
    
    return send_email(subject, invite.email, content)
@app.post("/send-password-update-alert/")
async def send_password_update_alert(alert: AlertEmail):
    subject = "Password Update Notification"
    content = f"""
    <h1>Hello, {alert.username}</h1>
    <p>This is a notification that your password was successfully updated. If you didn't make this request, please contact support immediately.</p>
    """
    
    return send_email(subject, alert.email, content)

@app.post("/send-login-alert/")
async def send_login_alert(alert: LoginAlert):
    subject = "Login Alert Notification"
    content = f"""
    <h1>Hello, {alert.username}</h1>
    <p>This is a notification that a login occurred on your account at {alert.login_time}. If this wasn't you, please contact support immediately.</p>
    """
    
    return send_email(subject, alert.email, content)