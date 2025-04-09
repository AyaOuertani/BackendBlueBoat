from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.config.database import Base,engine
from app.config.settings import get_settings
from app.config.oauth import setup_oauth
from app.routes.user import user_router, auth_router, guest_router
from app.routes.oauth import oauth_router

Base.metadata.create_all(bind=engine)
settings = get_settings()

app = FastAPI(
    title=settings.APP_NAME,
    debug=settings.DEBUG
)

# Setup OAuth (this adds the session middleware)
oauth = setup_oauth(app)

# Add CORS middleware AFTER session middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # For production, specify actual origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(user_router)
app.include_router(auth_router)
app.include_router(guest_router)
app.include_router(oauth_router)

@app.get("/")
async def root():
    return {"message": f"Welcome to {settings.APP_NAME} API"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)