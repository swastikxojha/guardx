from fastapi import Depends, HTTPException, Header
from sqlalchemy.orm import Session
from app.db.database import get_db
from app.db.models.models import User, APIKey
from app.core.security import decode_token, hash_api_key
from datetime import datetime, timezone

def current_user(authorization: str|None=Header(default=None), db:Session=Depends(get_db)):
    if not authorization or not authorization.startswith("Bearer "): raise HTTPException(401,"Authentication required")
    try: payload=decode_token(authorization.split(" ",1)[1])
    except Exception: raise HTTPException(401,"Invalid or expired token")
    user=db.get(User,payload.get("sub"))
    if not user: raise HTTPException(401,"User not found")
    return user

def api_identity(x_api_key: str|None=Header(default=None), authorization: str|None=Header(default=None), db:Session=Depends(get_db)):
    if x_api_key:
        key=db.query(APIKey).filter(APIKey.key_hash==hash_api_key(x_api_key),APIKey.revoked==False).first()
        expires=key.expires_at if key else None
        if expires and expires.tzinfo is None:
            expires=expires.replace(tzinfo=timezone.utc)
        if not key or (expires and expires <= datetime.now(timezone.utc)): raise HTTPException(401,"Invalid or expired API key")
        return {"org_id":key.organization_id,"app_id":key.application_id,"scopes":key.scopes,"user":None}
    user=current_user(authorization,db)
    return {"org_id":user.organization_id,"app_id":None,"scopes":["guard:check","guard:read","guard:admin"],"user":user}

def require_admin(identity=Depends(api_identity)):
    if identity["user"] and identity["user"].role not in {"OWNER","ADMIN"}: raise HTTPException(403,"Admin role required")
    if identity["user"] is None and "guard:admin" not in identity["scopes"]: raise HTTPException(403,"Admin scope required")
    return identity
