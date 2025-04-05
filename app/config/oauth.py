from fastapi import FastAPI
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from authlib.integrations.starlette_client import OAuth
from app.config.settings import get_settings

settings = get_settings()

oauth = OAuth()

def setup_oauth(app: FastAPI):
    app.add_middleware(SessionMiddleware, secret_key=settings.SECRET_KEY)
    oauth.register(
        name='google',
        server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
        client_id=settings.GOOGLE_CLIENT_ID,
        client_secret=settings.GOOGLE_CLIENT_SECRET,
        client_kwargs={'scope': 'openid email profile', 'redirect_uri': f"{settings.API_HOST}/auth/google/token-callback"},
    )

    return oauth