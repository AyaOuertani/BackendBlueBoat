from ast import parse
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from sqlalchemy.orm import Session
from authlib.integrations.starlette_client import OAuthError, OAuth
from app.config.database import get_session
from app.config.settings import get_settings
from app.config.oauth import oauth
from app.services import user
from fastapi import FastAPI, Request, Depends
from starlette.middleware.sessions import SessionMiddleware
from app.services import user as user_service
import httpx
settings = get_settings()

oauth = OAuth()

def setup_oauth(app: FastAPI):
    app.add_middlleware(SessionMiddleware, secret_key=settings.SECRET_KEY)
    oauth.register(
        name="google",
        server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
        client_id=settings.GOOGLE_CLIENT_ID,
        client_secret=settings.GOOGLE_CLIENT_SECRET,
        client_kwargs={'scope': 'openid email profile', 'redirect_uri': f"{settings.API_HOST}/auth/google/token-callback"},
    )
    return oauth
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

@oauth_router.get("/google/token-callback")
async def oauth_google_token_callback(request: Request):
    # This endpoint just needs to capture the code and redirect
    # Log all query parameters for debugging
    print(f"Token callback received with params: {dict(request.query_params)}")
    
    # Extract the authorization code
    code = request.query_params.get("code")
    if not code:
        # Nouvelle logique pour les apps mobiles
        raw_url = str(request.url)
        if "yourapp://" in raw_url:  # Extraire le code depuis l'URL deep link
            parsed = parse.parse_qs(parse.urlsplit(raw_url).query)
            code = parsed.get("code", [None])[0]

    if not code:
        return JSONResponse(status_code=400, content={"detail": "No authorization code received"})

    
    # Create an HTML page that will close the web browser and return to app
    html_content = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Authentication Successful</title>
        <script>
            // Store the code in localStorage
            localStorage.setItem('auth_code', '{}');
            // Post message to Expo's AuthSession
            window.opener && window.opener.postMessage(
                JSON.stringify({{
                    type: 'success',
                    params: {{
                        code: '{}'
                    }}
                }}),
                window.location.origin
            );
            // Close window if opened directly
            setTimeout(function() {{
                window.close();
            }}, 1000);
        </script>
    </head>
    <body>
        <h2>Authentication Successful</h2>
        <p>You can close this window and return to the application.</p>
    </body>
    </html>
    """.format(code, code)
    
    return Response(content=html_content, media_type="text/html")
    
# Add to your oauth.py file
@oauth_router.post("/google/exchange-code")
async def exchange_google_code(request: Request, background_tasks: BackgroundTasks, session: Session = Depends(get_session)):
    data = await request.json()
    code = data.get("code")
    redirect_uri = data.get("redirect_uri")
    device_id = data.get("device_id")
    device_name = data.get("device_name")
    
    if not all([code, redirect_uri, device_id, device_name]):
        raise HTTPException(
            status_code=400,
            detail="code, redirect_uri, device_id and device_name are required"
        )
    if not code:
        raise HTTPException(status_code=400, detail="Authorization code is required")
    
    if not device_id or not device_name:
        raise HTTPException(status_code=400, detail="device_id and device_name are required")
    
    try:
        # Exchange the authorization code for tokens
        token_endpoint = "https://oauth2.googleapis.com/token"
        token_payload = {
            "code": code,
            "client_id": settings.GOOGLE_CLIENT_ID,
            "client_secret": settings.GOOGLE_CLIENT_SECRET,
            "redirect_uri": redirect_uri,
            "grant_type": "authorization_code"
        }
        
        async with httpx.AsyncClient() as client:
            token_response = await client.post(token_endpoint, data=token_payload)
            
        if token_response.status_code != 200:
            print(f"Token exchange error: {token_response.text}")
            raise HTTPException(status_code=400, detail="Failed to exchange code for tokens")
            
        token_data = token_response.json()
        id_token = token_data.get("id_token")
        
        # Verify and decode the ID token
        async with httpx.AsyncClient() as client:
            user_info_response = await client.get(
                "https://oauth2.googleapis.com/tokeninfo",
                params={"id_token": id_token}
            )
            
        if user_info_response.status_code != 200:
            raise HTTPException(status_code=400, detail="Invalid ID token")
            
        user_info = user_info_response.json()
        
        # Process the login
        result = await user_service.process_oauth_login(
            provider="google",
            oauth_id=user_info["sub"],
            email=user_info["email"],
            full_name=user_info["name"],
            session=session,
            background_tasks=background_tasks,
        )
        
        return result
        
    except Exception as e:
        print(f"Error during code exchange: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Authentication failed: {str(e)}")
    
    # Dans oauth.py (backend)
@oauth_router.get("/google/mobile-callback")
async def mobile_callback(request: Request):
    code = request.query_params.get("code")
    return RedirectResponse(f"blueboat://auth/google/callback?code={code}") 