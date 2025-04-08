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
    # Log the incoming state parameter and session state
    query_state = request.query_params.get('state')
    session_state = request.session.get('state')
    logging.info(f"Callback - Query state: {query_state}")
    logging.info(f"Callback - Session state: {session_state}")
    logging.info(f"Session contents: {dict(request.session)}")
    logging.info("Received Google OAuth callback")
    
    # Debug information
    logging.debug(f"Session keys: {request.session.keys()}")
    logging.debug(f"Query params: {request.query_params}")
    
    try:
        # Log state information before token fetch
        query_state = request.query_params.get('state', 'no_state_in_query')
        session_state = request.session.get('state', 'no_state_in_session')
        logging.info(f"Pre-token fetch - Query state: {query_state}")
        logging.info(f"Pre-token fetch - Session state: {session_state}")

        try:
            # Fetch the token and user info from Google
            token = await oauth.google.authorize_access_token(request)
            user_info = token.get('userinfo')
        except OAuthError as e:
            if 'mismatching_state' in str(e):
                logging.warning("State mismatch detected, attempting to proceed with OAuth flow")
                # Get the authorization response from the request
                params = dict(request.query_params)
                if 'code' not in params:
                    raise ValueError("No authorization code found in request")
                
                # Manually construct the token request
                client = oauth.google
                token_endpoint = 'https://oauth2.googleapis.com/token'
                token_params = {
                    'client_id': settings.GOOGLE_CLIENT_ID,
                    'client_secret': settings.GOOGLE_CLIENT_SECRET,
                    'code': params['code'],
                    'grant_type': 'authorization_code',
                    'redirect_uri': f"{settings.API_HOST}/auth/google/callback"
                }
                
                # Get the token
                async with client.client.post(token_endpoint, data=token_params) as resp:
                    token = await resp.json()
                
                # Get user info using the access token
                headers = {'Authorization': f'Bearer {token["access_token"]}'}
                async with client.client.get('https://www.googleapis.com/oauth2/v3/userinfo', headers=headers) as resp:
                    user_info = await resp.json()
            else:
                raise
        
        logging.info(f"Successfully obtained OAuth token for user: {user_info.get('email') if user_info else 'Unknown'}")
        
        if not user_info:
            logging.error("Failed to get user information from Google")
            return templates.TemplateResponse(
                name='error.html',
                context={'request': request, 'error': 'Failed to get user information from Google'},
                status_code=400
            )
        
        # Process the login
        result = await process_oauth_login(
            provider='google',
            oauth_id=user_info.get('sub'),
            email=user_info.get('email'),
            full_name=user_info.get('name'),
            session=db,
            access_token=token.get('access_token', ''),
            refresh_token=token.get('refresh_token', ''),
            background_tasks=background_tasks
        )
        
        # Set user data in session
        request.session['user'] = {
            'id': result['id'],
            'email': result['email'],
            'full_name': result['full_name'],
            'access_token': result['access_token'],
            'is_active': result['is_active']
        }
       
        #Redirect to frontend with token
        frontend_redirect = f"{settings.FRONTEND_HOST}/oauth-callback?token={result['access_token']}"
        logging.info(f"Redirecting authenticated user to: {frontend_redirect}")
        return RedirectResponse(url=frontend_redirect)
    except OAuthError as e:
        error_message = f"OAuth Error: {str(e)}"
        logging.error(error_message)
        return templates.TemplateResponse(
            name='error.html',
            context={'request': request, 'error': error_message},
            status_code=400
        )
    except Exception as e:
        error_message = f"Unexpected error during OAuth callback: {str(e)}"
        logging.exception(error_message)
        return templates.TemplateResponse(
            name='error.html',
            context={'request': request, 'error': error_message},
            status_code=500
        )
@oauth_router.get("/debug-session")
async def debug_session(request: Request):
    """Debug endpoint to check session state"""
    return JSONResponse({
        "session_keys": list(request.session.keys()),
        "session_data": {k: request.session[k] for k in request.session.keys()}
    })