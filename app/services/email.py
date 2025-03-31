from fastapi import BackgroundTasks
from app.config.settings import get_settings
from app.models.user import User
from app.config.email import send_email
from app.utils.email_context import USER_VERIFY_ACCOUNT, FORGOT_PASSWORD

settings = get_settings()

async def send_account_verification_email(user: User,code: str, background_tasks: BackgroundTasks):
    data = {
        'app_name': settings.APP_NAME,
        "name": user.full_name,
        'verification_code' : code
    }
    subject = f"Account Verification - {settings.APP_NAME}"
    await send_email(
        recipients=[user.email],
        subject=subject,
        template_name="user/account-verification.html",
        context=data,
        background_tasks=background_tasks
    )

async def send_account_activation_confirmation_email(user: User, background_tasks: BackgroundTasks):
    data = {
        'app_name': settings.APP_NAME,
        "name": user.full_name,
        'login_url': f'{settings.FRONTEND_HOST}'
    }
    subject = f"Welcome - {settings.APP_NAME}"
    await send_email(
        recipients=[user.email],
        subject=subject,
        template_name="user/account-verification-confirmation.html",
        context=data,
        background_tasks=background_tasks
    )

async def send_password_reset_email(user: User, code: str, background_tasks: BackgroundTasks):
    data = {
        'app_name': settings.APP_NAME,
        "name": user.full_name,
        "verification_code": code,
    }
    subject = f"Reset Password - {settings.APP_NAME}"
    await send_email(
        recipients=[user.email],
        subject=subject,
        template_name="user/password-reset.html",
        context=data,
        background_tasks=background_tasks
    )