from .base import AgentResult
class ArbiterAgent:
    def decide(self, results, overall_score, context):
        # Deterministic precedence keeps safety outcomes reproducible.
        categories={c for r in results for c in r.categories}
        if any(r.decision=="BLOCK" for r in results) or any(c in categories for c in {"API_KEY","PASSWORD","ACCESS_TOKEN","CREDIT_CARD","SSN","prompt_injection"}):
            decision="BLOCK"; reason="A high-severity security, credential, or policy violation was detected."; remediation="Remove the unsafe instruction or sensitive data before continuing."
        elif any(r.decision=="HUMAN_REVIEW" for r in results):
            decision="HUMAN_REVIEW"; reason="The combined signals are ambiguous or policy-sensitive."; remediation="Route the request to a reviewer before execution or delivery."
        elif any(r.decision=="MODIFY" for r in results):
            decision="MODIFY"; reason="The request can continue only after configured sanitization or transformation."; remediation="Use the sanitized content returned by GuardX."
        else:
            decision="ALLOW"; reason="No configured safety threshold was exceeded."; remediation="Continue normally."
        contributing=[r.agent for r in results if r.decision!="ALLOW" or r.score>0]
        return {"decision":decision,"risk_score":overall_score,"reason":reason,"primary_reason":reason,"contributing_agents":contributing,"detected_categories":sorted(categories),"remediation":remediation}
