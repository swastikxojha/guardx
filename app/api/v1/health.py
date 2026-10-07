from fastapi import APIRouter,Depends
from sqlalchemy import text
from sqlalchemy.orm import Session
from app.db.database import get_db
from app.core.config import settings
r=APIRouter(tags=["health"])
@r.get("/health")
def health(db:Session=Depends(get_db)):
    db.execute(text("SELECT 1"))
    judge={"enabled":settings.semantic_judge_enabled,"provider":settings.llm_provider if settings.semantic_judge_enabled else None,"status":"disabled"}
    if settings.semantic_judge_enabled:
        try:
            from app.providers.factory import build_semantic_judge_provider
            provider=build_semantic_judge_provider()
            judge["status"]="available" if provider.health() else "unavailable"
        except Exception:
            judge["status"]="misconfigured"
    return {"status":"ok","application":"ok","database":"ok","semantic_judge":judge}
