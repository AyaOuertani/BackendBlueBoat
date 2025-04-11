from typing import Optional, Union
from datetime import datetime
from pydantic import EmailStr, BaseModel
from app.responses.base import BaseResponse

class UserResponse(BaseResponse):
    id: int 
    full_name: str
    email: EmailStr
    mobile_number: str
    is_active : bool
    created_at: Union[str, None, datetime] = None
    loggedin_at: Optional[datetime]
    profile_picture: Optional[str] = None

class LoginResponse(BaseModel):
    access_token: str
    refresh_token: str
    expires_in: int
    
    # Include user information
    id: int = None
    full_name: str = None
    email: str = None
    mobile_number: str = None
    is_active: bool = None
    loggedin_at: Union[str, None, datetime] = None
