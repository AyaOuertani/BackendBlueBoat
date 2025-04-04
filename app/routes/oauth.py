from fastapi import APIRouter, BackgroundTasks, Depends, status, Request, Response
from fastapi.responses import RedirectResponse, JSONResponse
from sqlalchemy.orm import Session
from authlib.integrations.starlette_client import OAuthError
from app.config.database import get_session
from app.config.settings import get_settings
from app.config.oauth import oauth
from app.services import user
from app.services import user as user_service

settings = get_settings()

oauth_router = APIRouter(
    prefix="/auth",
    tags=["Auth"],
    responses={404: {"description": "Not Found"}},
)

@oauth_router.get("/google/login")
async def login_google(request: Request):
    redirect_uri = request.url_for("oauth_google_callback")
    return await oauth.google.authorize_redirect(request, redirect_uri)

@oauth_router.get("/google/callback")
async def oauth_google_callback(request: Request, background_tasks: BackgroundTasks,session: Session = Depends(get_session)):
    try:
        token = await oauth.google.authorize_access_token(request)
    except OAuthError as e:
        return JSONResponse(
            status_code=401,
            content={"detail": f"OAuth Error: {e.error}"}
        )
    user_info = token.get("userinfo")
    if not user_info:
        return JSONResponse(
            status_code=401,
            content={"detail": "Could not fetch user information from Google"}
        )
    result = await user_service.process_oauth_login(
        provider="google",
        oauth_id=user_info["sub"],
        email=user_info["email"],
        full_name=user_info["name"],
        session=session,
        background_tasks=background_tasks,
    )

    frontend_redirect_url = f"{settings.FRONTEND_HOST}/oauth-callback?access_token={result['access_token']}&refresh_token={result['refresh_token']}"
    return RedirectResponse(url=frontend_redirect_url, status_code=status.HTTP_302_FOUND)