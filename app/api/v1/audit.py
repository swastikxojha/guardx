from fastapi import APIRouter,Depends,HTTPException
from sqlalchemy.orm import Session
from app.db.database import get_db
from app.db.models.models import GuardRequest,AgentResult,Decision,Review
from app.core.dependencies import current_user
r=APIRouter(prefix="/audit",tags=["audit"])
@r.get("/requests")
def requests(user=Depends(current_user),db:Session=Depends(get_db),limit:int=50):
    return db.query(GuardRequest).filter(GuardRequest.organization_id==user.organization_id).order_by(GuardRequest.created_at.desc()).limit(min(limit,100)).all()
@r.get("/requests/{request_id}")
def request_detail(request_id:str,user=Depends(current_user),db:Session=Depends(get_db)):
    x=db.query(GuardRequest).filter(GuardRequest.id==request_id,GuardRequest.organization_id==user.organization_id).first()
    if not x: raise HTTPException(404,"Request not found")
    agents=db.query(AgentResult).filter(AgentResult.request_id==x.id).all()
    decision=db.query(Decision).filter(Decision.request_id==x.id).first()
    review=db.query(Review).filter(Review.request_id==x.id).first()
    return {"request":x,"agents":agents,"decision":decision,"review":review}
