from datetime import datetime, timedelta, timezone
import hashlib, secrets
import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from .config import settings

ph = PasswordHasher()

def hash_password(password: str) -> str:
    return ph.hash(password)

def verify_password(password: str, password_hash: str) -> bool:
    try: return ph.verify(password_hash, password)
    except VerifyMismatchError: return False

def create_access_token(subject: str, role: str, org_id: str) -> str:
    now=datetime.now(timezone.utc)
    payload={"sub":subject,"role":role,"org_id":org_id,"iat":now,"exp":now+timedelta(minutes=settings.access_token_expire_minutes)}
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)

def decode_token(token: str) -> dict:
    return jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])

def generate_api_key() -> str:
    return "gx_" + secrets.token_urlsafe(32)

def hash_api_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()
