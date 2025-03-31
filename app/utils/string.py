import secrets
import random

def unique_string(byte: int = 8) -> str:
    return secrets.token_urlsafe(byte)

def generate_verification_code(length=5):
    """Generate a numeric verification code of specified length"""
    return ''.join(random.choices('0123456789', k=length))