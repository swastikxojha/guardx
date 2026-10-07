from .base import GuardrailAgent, AgentResult
from app.detectors.pii_detector import detect_pii
from app.core.config import settings
class PrivacyAgent(GuardrailAgent):
    name="privacy"
    def evaluate(self, content, context):
        matches=context["pii_matches"] if "pii_matches" in context else detect_pii(content)
        mode=(context.get("pii_mode") or settings.pii_mode).upper()
        score=0 if not matches else min(1.0, .45+.08*len(matches))
        high=any(m.entity_type in {"API_KEY","PASSWORD","ACCESS_TOKEN","CREDIT_CARD","SSN"} for m in matches)
        if high: score=max(score,.92)
        decision="BLOCK" if matches and (high or mode not in {"ALLOW","REDACT","PSEUDONYMIZE"}) else ("MODIFY" if matches and mode in {"REDACT","PSEUDONYMIZE"} else "ALLOW")
        level="CRITICAL" if high else ("HIGH" if matches else "LOW")
        return AgentResult(self.name,score,level,decision,[m.entity_type for m in matches],f"Detected {len(matches)} sensitive item(s)" if matches else "No PII detected",min(.99,.85+.03*len(matches)),{"matches":matches})
