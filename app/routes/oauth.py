# In your auth routes file
from fastapi import APIRouter, BackgroundTasks, Depends, Request, HTTPException
from fastapi.responses import RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from authlib.integrations.starlette_client import OAuthError
import logging

from app.config.database import get_session
from app.config.oauth import oauth
from app.services.email import send_account_activation_confirmation_email
from app.services.user import process_oauth_login
from app.config.settings import get_settings

settings = get_settings()
templates = Jinja2Templates(directory="app/templates")

# Create a dedicated router for OAuth routes
oauth_router = APIRouter(
    prefix="/auth",
    tags=["OAuth"],
    responses={404: {"description": "Not Found"}},
)

@oauth_router.get("/google/login")
async def login_google(request: Request):
    """
    Initiates the Google OAuth login flow
    """
    # Define the exact, full callback URL
    redirect_uri = f"{settings.API_HOST}/auth/google/callback"
    
    # Log the redirect URI for debugging
    logging.info(f"Redirecting to Google with callback URI: {redirect_uri}")
    
    # Clear any existing session data
    request.session.clear()
    
    # Initialize a new session
    response = await oauth.google.authorize_redirect(request, redirect_uri)
    
    # Log the state for debugging
    if 'state' in request.session:
        logging.info(f"Generated OAuth state: {request.session['state']}")
    else:
        logging.warning("No state found in session after authorize_redirect")
    
    return response

@oauth_router.get("/google/callback")
async def google_callback(
    request: Request, 
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_session)
):
    """
    Handles the callback from Google OAuth
    """
    try:
        # Process tokens as you already do
        token = await oauth.google.authorize_access_token(request)
        user_info = token.get('userinfo')
        profile_picture = user_info.get('picture')

        # Process the login
        result = await process_oauth_login(
            provider='google',
            oauth_id=user_info.get('sub'),
            email=user_info.get('email'),
            full_name=user_info.get('name'),
            session=db,
            access_token=token.get('access_token', ''),
            refresh_token=token.get('refresh_token', ''),
            background_tasks=background_tasks,
            profile_picture = profile_picture
        )
        
        # Update this line - redirect to Expo app instead of web frontend
        # Include expo-specific redirect URL for your dev environment
        frontend_redirect = f"exp://192.168.173.93:8081/--/oauth-callback?token={result['access_token']}"
        logging.info(f"Redirecting authenticated user to: {frontend_redirect}")
        return RedirectResponse(url=frontend_redirect)
        
    except Exception as e:
        error_message = f"Error during OAuth callback: {str(e)}"
        logging.exception(error_message)
        return templates.TemplateResponse(
            name='error.html', 
            context={'request': request, 'error': error_message},
            status_code=500
        )

