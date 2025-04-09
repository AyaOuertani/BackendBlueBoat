# In app/config/oauth.py
from fastapi import FastAPI
from starlette.middleware.sessions import SessionMiddleware
from authlib.integrations.starlette_client import OAuth
from app.config.settings import get_settings
import logging

settings = get_settings()

# Initialize OAuth
oauth = OAuth()

def setup_oauth(app: FastAPI):
    """
    Configure OAuth for the FastAPI application
    """
    # Add session middleware for managing OAuth state
    # Use a secure session secret and ensure cookie security settings
    app.add_middleware(
        SessionMiddleware, 
        secret_key=settings.SECRET_KEY,
        session_cookie="fastapi_oauth_session",
        max_age=3600,  # 1 hour
        same_site="lax",  # Important for OAuth redirects
        https_only=settings.API_HOST.startswith("https://"),
        
    )
    
    # Configure OAuth client with proper settings
    oauth.register(
        name='google',
        server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
        client_id=settings.GOOGLE_CLIENT_ID,
        client_secret=settings.GOOGLE_CLIENT_SECRET,
        client_kwargs={
            'scope': 'openid email profile',
            'prompt': 'select_account',  # Force Google account selection
            'access_type': 'offline'  # Enable refresh tokens
        }
    )
    
    return oauth