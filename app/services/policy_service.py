from sqlalchemy.orm import Session
from app.db.models.models import Policy,PolicyRule

def get_rules(db:Session, org_id:str, policy_id:str|None):
    if not policy_id: return []
    p=db.query(Policy).filter(Policy.id==policy_id,Policy.organization_id==org_id,Policy.enabled==True).first()
    return [{"category":r.category,"action":r.action,"threshold":r.threshold,"config":r.config} for r in p.rules] if p else []
