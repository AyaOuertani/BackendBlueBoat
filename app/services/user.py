from datetime import datetime, timedelta, timezone
import logging
from sqlalchemy.orm import joinedload
from fastapi import HTTPException
from app.config.security import generate_token, get_token_payload, hash_password, is_password_strong_enough, load_user, str_decode, str_encode, verify_password
from app.models.user import User, UserToken, VerificationCode
from app.services.email import send_account_activation_confirmation_email, send_account_verification_email, send_password_reset_email
from app.utils.email_context import FORGOT_PASSWORD, USER_VERIFY_ACCOUNT
from app.utils.string import generate_verification_code, unique_string
from app.config.settings import get_settings

settings = get_settings()

async def create_user_account(data, session, background_tasks):
    user_exist = session.query(User).filter(User.email == data.email).first()
    if user_exist:
        raise HTTPException(status_code=400, detail="Email already exists.")
    
    if not is_password_strong_enough(data.password):
        raise HTTPException(status_code=400, detail="Please provide a strong password")

    user = User()
    user.full_name = data.full_name
    user.email = data.email
    user.mobile_number = data.mobile_number
    user.password = hash_password(data.password)
    user.is_active = False
    user.created_at = datetime.now(timezone.utc) + timedelta(hours=1)
    user.updated_at = datetime.now(timezone.utc) + timedelta(hours=1)

    session.add(user)
    session.commit()
    session.refresh(user)

    code = generate_verification_code()
    verification = VerificationCode(
        user_id=user.id,
        code=code,
        purpose='account_verification',
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=30) +timedelta(hours=1)
    )
    session.add(verification)
    session.commit()

    await send_account_verification_email(user, code, background_tasks=background_tasks)
    return user

async def activate_user_account(data, session, background_tasks):
    user = session.query(User).filter(User.email == data.email).first()
    if not user:
        raise HTTPException(status_code=400, detail="Invalid email address.")
    
    verification = session.query(VerificationCode).filter(
        VerificationCode.user_id == user.id,
        VerificationCode.code == data.code,
        VerificationCode.purpose == 'account_verification',
        VerificationCode.expires_at > datetime.now(timezone.utc) + timedelta(hours=1),
        VerificationCode.used == False
    ).first()

    if not verification:
        raise HTTPException(status_code=400, detail="Invalid or expired verification code.")
    
    verification.used = True
    user.is_active = True
    user.updated_at = datetime.now(timezone.utc) + timedelta(hours=1)
    user.verified_at = datetime.now(timezone.utc) + timedelta(hours=1)
    user.loggedin_at = datetime.now(timezone.utc) + timedelta(hours=1)
    session.add(verification)
    session.add(user)
    session.commit()
    session.refresh(user)
    session.refresh(verification)

    await send_account_activation_confirmation_email(user, background_tasks)
    return user

async def get_login_token(data, session):
    logging.info(f"Login attempt with identifier: {data.identifier}")
    user = await load_user(data.identifier, session)
    if not user: 
        raise HTTPException(status_code=401, detail="Email not found")
    
    if not verify_password(data.password, user.password):
        raise HTTPException(status_code=401, detail="Incorrect email or password.")
    
    if not user.verified_at:
        raise HTTPException(status_code=400, detail="Your account is not verified. Please check your email inbox to verify your account.")
    
    if not user.is_active:
        raise HTTPException(status_code=400, detail="Your account has been deactivated. Please contact support.")
        
    # Generate the JWT Token
    return _generate_tokens(user, session)

async def get_refresh_token(refresh_token, session):
    token_payload = get_token_payload(refresh_token, settings.SECRET_KEY, settings.JWT_ALGORITHM)
    if not token_payload:
        raise HTTPException(status_code=400, detail="Invalid Request")
    
    refresh_key = token_payload.get('t')
    access_key = token_payload.get('a')
    user_id = str_decode(token_payload.get('sub'))
    user_token = session.query(UserToken).options(joinedload(UserToken.user)).filter(UserToken.refresh_key == refresh_key,
                                                                                    UserToken.access_key == access_key,
                                                                                    UserToken.user_id == user_id,
                                                                                  UserToken.expires_at > datetime.now(timezone.utc) + timedelta(hours=1)).first()
    if not user_token:
        raise HTTPException(status_code= 400, detail="Invalid Request")
    
    user_token.expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
    session.add(user_token)
    session.commit()
    return _generate_tokens(user_token.user, session)

def _generate_tokens(user, session):
    refresh_key = unique_string(100)
    access_key = unique_string(50)
    rt_expires = timedelta(minutes=settings.REFRESH_TOKEN_EXPIRE_MINUTES)

    user_token = UserToken()
    user_token.user_id = user.id
    user_token.refresh_key = refresh_key
    user_token.access_key = access_key
    user_token.expires_at = datetime.now(timezone.utc) + rt_expires
    user.loggedin_at = datetime.now(timezone.utc) + timedelta(hours=1)
    session.add(user_token)
    session.commit()
    session.refresh(user_token)
    session.refresh(user)

    at_playload = {
        "sub": str_decode(str(user.id)),
        'a': access_key,
        'r': str_encode(str(user_token.id)),
        'n': str_encode(f"{user.full_name}")
    }

    at_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = generate_token(at_playload, settings.JWT_SECRET, settings.JWT_ALGORITHM, at_expires)

    rt_payload = {"sub" : str_encode(str(user.id)), "t": refresh_key, 'm': access_key}
    refresh_token = generate_token(rt_payload, settings.SECRET_KEY, settings.JWT_ALGORITHM, rt_expires)
    return{
        "access_token": access_token,
        "refresh_token": refresh_token,
        "expires_in": at_expires.seconds,
        # User information
        "id": user.id,
        "full_name": user.full_name,
        "email": user.email,
        "mobile_number": user.mobile_number,
        "is_active": user.is_active,
        "loggedin_at": user.loggedin_at
    }

async def email_forget_password_code(data, background_tasks, session):
    user = await load_user(data.email, session)

    if not user :
        return{"message": "if the email exists, a reset code will be sent."}
    
    logging.info(
        "Password reset requested for user",
        extra={
            "id": user.id,
            "email": user.email,
            "is_active": user.is_active
        }
    )
    code = generate_verification_code()
    verification = VerificationCode(
        user_id=user.id,
        code=code,
        purpose= 'password_reset',
        expires_at = datetime.now(timezone.utc) + timedelta(hours=1,minutes=30)
    )
    session.add(verification)
    session.commit()
    
    
    await send_password_reset_email(user, code, background_tasks)
    return {"message": "If the email exists, a reset code will be sent."}

async def reset_user_password(data, session):
    user = await load_user(data.email, session)

    if not user:
        raise HTTPException(status_code=400, detail="Invalid Request (Not a User)")
    
    verification = session.query(VerificationCode).filter(
        VerificationCode.user_id == user.id,
        VerificationCode.code == data.code,
        VerificationCode.purpose == 'password_reset',
        VerificationCode.expires_at > datetime.now(timezone.utc) + timedelta(hours=1),
        VerificationCode.used == False
    ).first()
    if not verification: 
        raise HTTPException(status_code=400, detail='Invalid or expired verification code.')
    
    verification.used = True

    user.password = hash_password(data.password)
    user.updated_at = datetime.now()

    session.add(verification)
    session.add(user)
    session.commit()
    session.refresh(user)
    # Notify user that password has been updated

    return {"message": "Your password has been updated"}

async def fetch_user_detail(pk, session):
    user = await session.query(User).filter(User.id == pk).first()
    if user:
        return user
    raise HTTPException(status_code=400, detail="User does not exists")

async def process_oauth_login(provider,  oauth_id, email, full_name, session, background_tasks):
    user = session.query(User).filter(
        User.oauth_provider == provider,
        User.oauth_id == oauth_id,
    ).first()

    if not user:
        user = session.query(User).filter(
            User.email == email,
        ).first()

        if User:
            user.oauth_provider = provider
            user.oauth_id = oauth_id
            user.is_active = True
            user.verified_at = user.verified_at or  datetime.now(timezone.utc) + timedelta(hours=1)
            user.updated_at = datetime.now(timezone.utc) + timedelta(hours=1)
            session.add(user)
            session.commit()
            session.refresh(user)
        
        else:
            user = User(
            email = email,
            full_name = full_name,
            mobile_number = None,
            oauth_provider = provider,
            oauth_id = oauth_id,
            is_active = True,
            verified_at = datetime.now(timezone.utc) + timedelta(hours=1),
            created_at = datetime.now(timezone.utc) + timedelta(hours=1),
            updated_at = datetime.now(timezone.utc) + timedelta(hours=1),
        )

        session.add(user)
        session.commit()
        session.refresh(user)
    
    await send_account_activation_confirmation_email(user, background_tasks)
    return _generate_tokens(user, session)

    