from typing import Union
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

class LoginResponse(BaseModel):
    id: int 
    full_name: str
    email: EmailStr
    mobile_number: str
    is_active : bool
    