from datetime import datetime, timezone
from fastapi import APIRouter,Depends,HTTPException
from sqlalchemy.orm import Session
from app.db.database import get_db
from app.db.models.models import APIKey, Application
from app.schemas.schemas import APIKeyIn
from app.core.dependencies import require_admin
from app.core.security import generate_api_key,hash_api_key
r=APIRouter(prefix="/api-keys",tags=["api-keys"])
@r.get("")
def list_keys(identity=Depends(require_admin),db:Session=Depends(get_db)):
    rows=db.query(APIKey).filter(APIKey.organization_id==identity["org_id"]).all()
    return [{"id":k.id,"application_id":k.application_id,"name":k.name,"scopes":k.scopes,"expires_at":k.expires_at,"revoked":k.revoked,"created_at":k.created_at} for k in rows]
@r.post("")
def create_key(data:APIKeyIn,identity=Depends(require_admin),db:Session=Depends(get_db)):
    if data.application_id and not db.query(Application).filter(Application.id==data.application_id,Application.organization_id==identity["org_id"]).first():
        raise HTTPException(404,"Application not found")
    raw=generate_api_key(); expires=data.expires_at
    if expires and expires.tzinfo is None:
        expires=expires.replace(tzinfo=timezone.utc)
    if expires:
        expires=expires.astimezone(timezone.utc)
    k=APIKey(organization_id=identity["org_id"],application_id=data.application_id,name=data.name,key_hash=hash_api_key(raw),scopes=data.scopes,expires_at=expires); db.add(k);db.commit();db.refresh(k);return {"id":k.id,"name":k.name,"api_key":raw,"scopes":k.scopes}
@r.post("/{key_id}/revoke")
def revoke(key_id:str,identity=Depends(require_admin),db:Session=Depends(get_db)):
    k=db.query(APIKey).filter(APIKey.id==key_id,APIKey.organization_id==identity["org_id"]).first()
    if not k: raise HTTPException(404,"Key not found")
    k.revoked=True;db.commit();return {"status":"revoked"}
