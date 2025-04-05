from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status, Request, Response
from fastapi.responses import RedirectResponse, JSONResponse
from sqlalchemy.orm import Session
from authlib.integrations.starlette_client import OAuthError
from app.config.database import get_session
from app.config.settings import get_settings
from app.config.oauth import oauth
from app.services import user
from app.services import user as user_service
import httpx
settings = get_settings()

oauth_router = APIRouter(
    prefix="/auth",
    tags=["Auth"],
    responses={404: {"description": "Not Found"}},
)

@oauth_router.get("/google/login")
async def login_google(request: Request):
    # Add debug logging
    print("Starting OAuth login flow")
    redirect = await oauth.google.authorize_redirect(request, request.url_for("oauth_google_callback"))
    print(f"Redirecting to: {redirect.headers['location']}")
    return redirect

@oauth_router.get("/google/callback")
async def oauth_google_callback(request: Request, background_tasks: BackgroundTasks, session: Session = Depends(get_session)):
    print("Callback received")
    print(f"Request query params: {request.query_params}")
    print(f"Request session: {request.session}")
    try:
        token = await oauth.google.authorize_access_token(request)
        # Rest of your code...
    except OAuthError as e:
        print(f"OAuth Error details: {e}")
        # Rest of your error handling...
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


@oauth_router.post("/google/token")
async def exchange_google_code(requests: Request, background_tasks: BackgroundTasks, session: Session = Depends(get_session)):
    data = await requests.json()
    id_token = data.get("id_token")
    if not id_token:
        raise HTTPException(status_code=400, detail="ID token is required")
    
    async with httpx.AsyncClient() as client:
        response = await client.post(
            "https://oauth2.googleapis.com/oauth2/v3/tokeninfo",
            params={"id_token": id_token},
        )
    if response.status_code != 200:
        raise HTTPException(status_code=400, detail="Invalid ID token")
    user_info = response.json()

    result = await user_service.process_oauth_login(
        provider="google",
        oauth_id=user_info["sub"],
        email=user_info["email"],
        full_name=user_info["name"],
        session=session,
        background_tasks=background_tasks,
    )
    return result