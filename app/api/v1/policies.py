from fastapi import APIRouter,Depends,HTTPException
from sqlalchemy.orm import Session
from app.db.database import get_db
from app.db.models.models import Policy,PolicyRule
from app.schemas.schemas import PolicyIn
from app.core.dependencies import current_user,require_admin
r=APIRouter(prefix="/policies",tags=["policies"])
@r.get("")
def list_policies(user=Depends(current_user),db:Session=Depends(get_db)):
    return db.query(Policy).filter(Policy.organization_id==user.organization_id).all()
@r.post("")
def create_policy(data:PolicyIn,identity=Depends(require_admin),db:Session=Depends(get_db)):
    p=Policy(organization_id=identity["org_id"],name=data.name,enabled=data.enabled);db.add(p);db.flush()
    for x in data.rules: db.add(PolicyRule(policy_id=p.id,category=x.category,action=x.action,threshold=x.threshold,config=x.config))
    db.commit();db.refresh(p);return p
