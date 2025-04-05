from fastapi import FastAPI
from app.config.database import Base, engine
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
from app.config.settings import get_settings
from app.config.oauth import setup_oauth
from app.routes import oauth, user

Base.metadata.create_all(bind = engine)
settings = get_settings()
def create_application():
    application = FastAPI()

    origins = [
    "http://localhost",
    "http://localhost:3000",
    "http://localhost:8000",
    "http://localhost:19006",
    "http://192.168.173.93:8000",  # Your backend IP
    ]

    application.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    application.add_middleware(SessionMiddleware, secret_key=settings.SECRET_KEY)
    setup_oauth(application)
    application.include_router(user.user_router)
    application.include_router(user.guest_router)
    application.include_router(user.auth_router)
    application.include_router(oauth.oauth_router)
    return application


app = create_application()


@app.get("/")
async def root():
    return {"message": "Hi, I am BlueBoat. Awesome - Your setrup is done & working."}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)