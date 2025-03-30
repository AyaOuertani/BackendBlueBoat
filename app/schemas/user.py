import re
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
    token: str
    email: EmailStr

class EmailRequest(BaseModel):
    email: EmailStr

class LoginRequest(BaseModel):
    identifier: str
    password: str

class ResetRequest(BaseModel):
    token: str
    email: EmailStr
    password: str