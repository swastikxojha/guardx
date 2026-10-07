from sqlalchemy.orm import Session
from app.db.models.models import GuardRequest,AgentResult,Decision,AuditLog,Review,UsageRecord
from app.engine.pipeline import GuardPipeline
class PipelineService:
    def __init__(self,db:Session): self.db=db; self.pipeline=GuardPipeline()
    def evaluate(self, content, request_type, org_id, app_id=None, policy_id=None, policy_rules=None, metadata=None, action=None, sensitive_context=None):
        result=self.pipeline.run(content,request_type,{"policy_rules":policy_rules or [],"action":action or {},"metadata":metadata or {},"sensitive_context":sensitive_context or []})
        req=GuardRequest(organization_id=org_id,application_id=app_id,request_type=request_type,content_hash=result["content_hash"],risk_score=result["risk_score"],risk_level=result["risk_level"],decision=result["decision"],categories=result["categories"],policy_id=policy_id,latency_ms=result["latency_ms"])
        self.db.add(req); self.db.flush()
        for r in result["agents"]:
            self.db.add(AgentResult(request_id=req.id,agent=r.agent,score=r.score,level=r.level,decision=r.decision,categories=r.categories,explanation=r.explanation,confidence=r.confidence))
        a=result["arbiter"]; self.db.add(Decision(request_id=req.id,decision=a["decision"],reason=a["reason"],remediation=a["remediation"],contributing_agents=a["contributing_agents"]))
        self.db.add(AuditLog(request_id=req.id,organization_id=org_id,event="guard.decision",metadata_json={"request_type":request_type,"risk_score":result["risk_score"],"risk_level":result["risk_level"],"decision":result["decision"],"categories":result["categories"]}))
        self.db.add(UsageRecord(organization_id=org_id,request_type=request_type,latency_ms=result["latency_ms"]))
        if result["decision"]=="HUMAN_REVIEW": self.db.add(Review(request_id=req.id))
        self.db.commit(); return req,result
