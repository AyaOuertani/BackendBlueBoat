from datetime import datetime, timedelta, timezone
from sqlalchemy import Boolean, Column, DateTime, Integer, String, func, ForeignKey
from app.config.database import Base
from sqlalchemy.orm import mapped_column, relationship

DB_OFFSET = timedelta(hours=1)
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    full_name = Column(String(150), index=True, nullable=False)
    email = Column(String(255), unique=True, index=True, nullable=False)
    mobile_number = Column(String(15), unique=True, nullable=True, default='')
    password = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=False)
    verified_at = Column(DateTime(timezone=True), nullable=True, default=None)
    created_at= Column(DateTime(timezone=True), nullable=False,  default=lambda: datetime.now(timezone.utc) + DB_OFFSET)
    updated_at = Column(DateTime(timezone=True), nullable=True, default=None, onupdate=datetime.now(timezone.utc) + DB_OFFSET)
    loggedin_at = Column(DateTime(timezone=True), nullable=True, default=None, onupdate=datetime.now(timezone.utc) + DB_OFFSET)
    oauth_provider = Column(String(50), nullable=True, default=None)
    oauth_id = Column(String(255), nullable=True, default=None)
    oauth_access_token = Column(String(2000), nullable=True, default=None)
    oauth_refresh_token = Column(String(2000), nullable=True, default=None)
    profile_picture = Column(String(1000), nullable=True, default=None)

    tokens = relationship("UserToken", back_populates="user")
    verification_codes = relationship("VerificationCode", back_populates="user")

    def get_context_string(self, context: str):
        update_time = self.updated_at or datetime.now(timezone.utc) + DB_OFFSET
        return f"{context}{self.password[-6:]}{update_time.strftime('%m%d%Y%H%M%S')}".strip()
    
class UserToken(Base):
    __tablename__ = "user_token"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = mapped_column(ForeignKey('users.id'))
    access_key = Column(String(250), nullable=True, index=True, default=None)
    refresh_key = Column(String(250), nullable=True, index=True, default=None)
    created_at = Column(DateTime(timezone=True), nullable=False,  default=lambda: datetime.now(timezone.utc) + DB_OFFSET)
    expires_at = Column(DateTime(timezone=True), nullable=False)

    user = relationship("User", back_populates="tokens")

class VerificationCode(Base):
    __tablename__ = "verification_codes"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = mapped_column(ForeignKey('users.id'))
    code = Column(String(5), nullable = False)
    purpose = Column(String(50), nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False,  default=lambda: datetime.now(timezone.utc) + DB_OFFSET)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    used = Column(Boolean, default=False)

    user = relationship("User", back_populates="verification_codes")