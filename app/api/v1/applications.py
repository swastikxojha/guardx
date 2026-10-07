from fastapi import APIRouter,Depends
from sqlalchemy.orm import Session
from app.db.database import get_db
from app.db.models.models import Application
from app.schemas.schemas import ApplicationIn
from app.core.dependencies import current_user
r=APIRouter(prefix="/applications",tags=["applications"])
@r.get("")
def list_apps(user=Depends(current_user),db:Session=Depends(get_db)):
    return db.query(Application).filter(Application.organization_id==user.organization_id).all()
@r.post("")
def create_app(data:ApplicationIn,user=Depends(current_user),db:Session=Depends(get_db)):
    x=Application(organization_id=user.organization_id,name=data.name,description=data.description);db.add(x);db.commit();db.refresh(x);return x
