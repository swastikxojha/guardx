from fastapi import APIRouter,Depends
from sqlalchemy.orm import Session
from sqlalchemy import func
from app.db.database import get_db
from app.db.models.models import GuardRequest
from app.core.dependencies import current_user
r=APIRouter(prefix="/analytics",tags=["analytics"])
@r.get("")
def analytics(user=Depends(current_user),db:Session=Depends(get_db)):
    q=db.query(GuardRequest).filter(GuardRequest.organization_id==user.organization_id)
    rows=q.all(); counts={d:sum(x.decision==d for x in rows) for d in ["ALLOW","MODIFY","BLOCK","HUMAN_REVIEW"]}; avg=sum(x.risk_score for x in rows)/len(rows) if rows else 0
    cats={}
    for x in rows:
        for c in x.categories: cats[c]=cats.get(c,0)+1
    return {"total_requests":len(rows),"decision_distribution":counts,"average_risk":round(avg,4),"high_risk":sum(x.risk_score>=.75 for x in rows),"threat_categories":cats}
