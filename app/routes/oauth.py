from fastapi import APIRouter, Depends, HTTPException, status, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from sqlalchemy.orm import Session
from authlib.integrations.starlette_client import OAuthError
from app.config.database import get_session
from app.config.settings import get_settings
from app.config.oauth import oauth
import httpx
from app.services import user as user_service

settings = get_settings()

oauth_router = APIRouter(
    prefix="/auth",
    tags=["Auth"],
    responses={404: {"description": "Not Found"}},
)

@oauth_router.get("/google/login")
async def login_google(request: Request):
    redirect_uri = request.query_params.get('redirect_uri', f"{settings.API_HOST}/auth/google/token-callback")
    return await oauth.google.authorize_redirect(request, redirect_uri)

@oauth_router.get("/google/token-callback")
async def oauth_google_token_callback(request: Request):
    # This endpoint captures the code and sends it back to the mobile app
    code = request.query_params.get("code")
    
    if not code:
        return JSONResponse(status_code=400, content={"detail": "No authorization code received"})
    
    # HTML page that will pass the code back to Expo's AuthSession
    html_content = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Authentication Successful</title>
        <script>
            // Post message to Expo's AuthSession
            window.opener && window.opener.postMessage(
                JSON.stringify({
                    type: 'success',
                    params: {
                        code: '%s',
                        id_token: '',
                        access_token: ''
                    }
                }),
                window.location.origin
            );
            // Close window after a short delay
            setTimeout(function() {
                window.close();
            }, 1000);
        </script>
    </head>
    <body>
        <h2>Authentication Successful</h2>
        <p>You can close this window and return to the application.</p>
    </body>
    </html>
    """ % code
    
    return HTMLResponse(content=html_content)

@oauth_router.post("/google/exchange-code")
async def exchange_google_code(request: Request, session: Session = Depends(get_session)):
    data = await request.json()
    code = data.get("code")
    redirect_uri = data.get("redirect_uri")
    
    if not code or not redirect_uri:
        raise HTTPException(status_code=400, detail="Authorization code and redirect URI are required")
    
    try:
        # Exchange the code for tokens
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
        
        # Get user info from ID token
        id_token = token_data.get("id_token")
        
        # Verify the ID token
        async with httpx.AsyncClient() as client:
            user_info_response = await client.get(
                "https://oauth2.googleapis.com/tokeninfo",
                params={"id_token": id_token}
            )
            
        if user_info_response.status_code != 200:
            raise HTTPException(status_code=400, detail="Invalid ID token")
            
        user_info = user_info_response.json()
        
        # Return the tokens and user info directly
        # This simplified approach skips database operations for now
        return {
            "access_token": token_data.get("access_token"),
            "id_token": id_token,
            "user_info": {
                "id": user_info.get("sub"),
                "email": user_info.get("email"),
                "name": user_info.get("name"),
                "picture": user_info.get("picture")
            }
        }
        
    except Exception as e:
        print(f"Error during code exchange: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Authentication failed: {str(e)}")