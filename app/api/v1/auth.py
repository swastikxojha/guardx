from fastapi import APIRouter,Depends,HTTPException
from sqlalchemy.orm import Session
from app.db.database import get_db
from app.db.models.models import User,Organization
from app.schemas.schemas import SignupIn,LoginIn,TokenOut
from app.core.security import hash_password,verify_password,create_access_token
r=APIRouter(prefix="/auth",tags=["auth"])
@r.post("/signup",response_model=TokenOut)
def signup(data:SignupIn,db:Session=Depends(get_db)):
    if db.query(User).filter(User.email==data.email.lower()).first(): raise HTTPException(409,"Email already registered")
    org=Organization(name=data.organization_name); db.add(org); db.flush(); user=User(email=data.email.lower(),password_hash=hash_password(data.password),role="OWNER",organization_id=org.id); db.add(user); db.commit()
    return TokenOut(access_token=create_access_token(user.id,user.role,org.id))
@r.post("/login",response_model=TokenOut)
def login(data:LoginIn,db:Session=Depends(get_db)):
    user=db.query(User).filter(User.email==data.email.lower()).first()
    if not user or not verify_password(data.password,user.password_hash): raise HTTPException(401,"Invalid credentials")
    return TokenOut(access_token=create_access_token(user.id,user.role,user.organization_id))
