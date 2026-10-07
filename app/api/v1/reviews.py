from fastapi import APIRouter,Depends,HTTPException
from sqlalchemy.orm import Session
from app.db.database import get_db
from app.db.models.models import Review,GuardRequest
from app.schemas.schemas import ReviewIn,FeedbackIn
from app.core.dependencies import current_user
from datetime import datetime,timezone
r=APIRouter(prefix="/reviews",tags=["reviews"])
@r.get("")
def reviews(user=Depends(current_user),db:Session=Depends(get_db)):
    return db.query(Review).join(GuardRequest,Review.request_id==GuardRequest.id).filter(GuardRequest.organization_id==user.organization_id).all()
@r.post("/{review_id}")
def review(review_id:str,data:ReviewIn,user=Depends(current_user),db:Session=Depends(get_db)):
    rv=db.query(Review).filter(Review.id==review_id).first()
    if not rv: raise HTTPException(404,"Review not found")
    req=db.get(GuardRequest,rv.request_id)
    if req.organization_id!=user.organization_id: raise HTTPException(403,"Forbidden")
    rv.status="RESOLVED";rv.reviewer_id=user.id;rv.decision=data.decision;rv.comment=data.comment;rv.updated_at=datetime.now(timezone.utc);db.commit();return rv
@r.post("/{request_id}/feedback")
def feedback(request_id:str,data:FeedbackIn,user=Depends(current_user),db:Session=Depends(get_db)):
    from app.db.models.models import Feedback
    req=db.get(GuardRequest,request_id)
    if not req or req.organization_id!=user.organization_id: raise HTTPException(404,"Request not found")
    f=Feedback(request_id=request_id,label=data.label,comment=data.comment);db.add(f);db.commit();return f
