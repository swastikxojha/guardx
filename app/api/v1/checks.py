from fastapi import APIRouter,Depends
from sqlalchemy.orm import Session
from app.db.database import get_db
from app.schemas.schemas import CheckIn,ActionIn
from app.core.dependencies import api_identity
from fastapi import HTTPException
from app.db.models.models import Application, Policy
from app.services.pipeline_service import PipelineService
from app.services.policy_service import get_rules
r=APIRouter(prefix="/check",tags=["checks"])
def check_scope(identity):
    if identity["user"] is None and "guard:check" not in identity["scopes"]: raise HTTPException(403,"guard:check scope required")
def validate_scope(db,identity,application_id,policy_id):
    bound_app=identity.get("app_id")
    if bound_app and application_id and application_id!=bound_app: raise HTTPException(403,"API key is bound to a different application")
    app_id=application_id or bound_app
    if app_id and not db.query(Application).filter(Application.id==app_id,Application.organization_id==identity["org_id"]).first(): raise HTTPException(404,"Application not found")
    if policy_id and not db.query(Policy).filter(Policy.id==policy_id,Policy.organization_id==identity["org_id"],Policy.enabled==True).first(): raise HTTPException(404,"Policy not found")
    return app_id
def out(req,res):
    return {"request_id":req.id,"request_type":res["request_type"],"decision":res["decision"],"risk_score":res["risk_score"],"risk_level":res["risk_level"],"categories":res["categories"],"sanitized_content":res["sanitized_content"],"agents":{a.agent:{"score":a.score,"level":a.level,"decision":a.decision,"categories":a.categories,"explanation":a.explanation,"confidence":a.confidence} for a in res["agents"]},"arbiter":res["arbiter"],"latency_ms":res["latency_ms"]}
@r.post("/input")
def check_input(data:CheckIn,identity=Depends(api_identity),db:Session=Depends(get_db)):
    check_scope(identity); app_id=validate_scope(db,identity,data.application_id,data.policy_id); req,res=PipelineService(db).evaluate(data.content,"input",identity["org_id"],app_id,data.policy_id,get_rules(db,identity["org_id"],data.policy_id),data.metadata,sensitive_context=data.sensitive_context);return out(req,res)
@r.post("/output")
def check_output(data:CheckIn,identity=Depends(api_identity),db:Session=Depends(get_db)):
    check_scope(identity); app_id=validate_scope(db,identity,data.application_id,data.policy_id); req,res=PipelineService(db).evaluate(data.content,"output",identity["org_id"],app_id,data.policy_id,get_rules(db,identity["org_id"],data.policy_id),data.metadata,sensitive_context=data.sensitive_context);return out(req,res)
@r.post("/action")
def check_action(data:ActionIn,identity=Depends(api_identity),db:Session=Depends(get_db)):
    check_scope(identity); app_id=validate_scope(db,identity,data.application_id,data.policy_id); content=f"tool={data.tool}; parameters={data.parameters}";req,res=PipelineService(db).evaluate(content,"action",identity["org_id"],app_id,data.policy_id,get_rules(db,identity["org_id"],data.policy_id),action=data.model_dump());return out(req,res)
