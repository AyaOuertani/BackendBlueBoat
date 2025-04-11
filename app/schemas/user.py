import re
from typing import Optional
from pydantic import BaseModel, EmailStr, Field, validator

class UserBase(BaseModel):
    full_name: str
    email: EmailStr
    mobile_number: str

    #Validation for mobile number
    @validator('mobile_number')
    def mobile_number_must_be_valid(cls, v):
        pattern = r'^\+?[0-9]{10,15}$'
        if not re.match(pattern, v):
            raise ValueError('Invalid mobile number format')
        return v
    
class RegisterUserRequest(UserBase):
    full_name: str
    email: EmailStr
    mobile_number: str

class UserCreatePassword(UserBase):
    email: EmailStr
    password: str = Field(..., min_length=8)
    confirm_password: str

    @validator('confirm_password')
    def passwords_match(cls, v, values):
        if 'password' in values and v != values['password']:
            raise ValueError('Passwords do not match')
        return v
    
class VerifyUserRequest(BaseModel):
    code: str
    email: EmailStr


class EmailRequest(BaseModel):
    email: EmailStr

class LoginRequest(BaseModel):
    identifier: str
    password: str

class ResetRequest(BaseModel):
    code: str
    email: EmailStr
    password: str
    confirm_password: str
    @validator('confirm_password')
    def passwords_match(cls, v, values):
        if 'password' in values and v != values['password']:
            raise ValueError('Passwords do not match')
        return v

class UserUpdateRequest(BaseModel):
    full_name: Optional[str] = None
    mobile_number: Optional[str] = None
    profile_picture: Optional[str] = None

    @validator('mobile_number')
    def mobile_number_must_be_valid(cls, v):
        if v is None:
            return v
        pattern = r'^\+?[0-9]{10,15}$'
        if not re.match(pattern, v):
            raise ValueError('Invalid mobile number format')
        return v
    @validator('profile_picture')
    def profile_picture_must_be_valid_url(cls, v):
        if v is None:
            return v
        # Basic URL validation - you could make this more sophisticated
        pattern = r'^https?://.+'
        if not re.match(pattern, v):
            raise ValueError('Profile picture must be a valid URL')
        return v

class PasswordVerificationRequest(BaseModel):
    password: str