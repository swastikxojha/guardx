from pathlib import Path
from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from app.core.logging import configure_logging
from app.db.database import Base,engine
from app.api.v1 import auth,applications,api_keys,policies,checks,audit,reviews,analytics,health
configure_logging()
app=FastAPI(title="GuardX",version="1.0.0",description="Multi-Agent AI Safety & Guardrail Framework")
from app.core.config import settings
if settings.auto_create_db:
    Base.metadata.create_all(bind=engine)
for router in [auth.r,applications.r,api_keys.r,policies.r,checks.r,audit.r,reviews.r,analytics.r,health.r]: app.include_router(router,prefix="/api/v1")
frontend=Path(__file__).resolve().parent.parent/"frontend"
app.mount("/static",StaticFiles(directory=frontend/"static"),name="static")
@app.get("/",response_class=HTMLResponse)
def index(): return (frontend/"templates"/"index.html").read_text(encoding="utf-8")
