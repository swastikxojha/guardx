from .base import GuardrailAgent, AgentResult
from app.detectors.injection_detector import detect_injection, detect_output_disclosure
class SecurityAgent(GuardrailAgent):
    name="security"
    def evaluate(self, content, context):
        hits=detect_injection(content)
        disclosures=detect_output_disclosure(content, context.get("sensitive_context", [])) if context.get("request_type")=="output" else []
        action=context.get("action",{})
        suspicious_action=False
        if action and action.get("tool") in {"send_email","http_request","database_export"}:
            params=str(action.get("parameters",{})).lower()
            suspicious_action=any(x in params for x in ["password","token","secret","customer database","api key"])
        severe=bool(disclosures or hits)
        score=min(1.0, (.90 if severe else 0)+(.72 if suspicious_action else 0))
        if severe: level="CRITICAL"; decision="BLOCK"
        elif suspicious_action and score>=.70: level="HIGH"; decision="BLOCK"
        elif score>=.75: level="HIGH"; decision="BLOCK"
        elif score>=.5: level="MEDIUM"; decision="HUMAN_REVIEW"
        elif score>0: level="LOW"; decision="MODIFY"
        else: level="LOW"; decision="ALLOW"
        cats=hits+(["prompt_injection"] if hits else [])+["suspicious_action"]*suspicious_action+disclosures
        reason="Detected a prompt-injection or internal-information disclosure signal" if severe else ("Tool action contains suspicious sensitive-data transfer" if suspicious_action else "No obvious security violation detected")
        return AgentResult(self.name,score,level,decision,cats,reason,.99 if severe else min(.95,.82+.04*len(hits)))
