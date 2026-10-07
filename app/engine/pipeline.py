import hashlib,time
import logging
from app.agents.security_agent import SecurityAgent
from app.agents.privacy_agent import PrivacyAgent
from app.agents.content_agent import ContentAgent
from app.agents.policy_agent import PolicyAgent
from app.agents.arbiter_agent import ArbiterAgent
from app.agents.base import AgentResult
from app.agents.semantic_judge import SemanticJudgeAgent
from app.core.config import settings
from app.engine.risk_scorer import score
from app.engine.sanitizer import sanitize_content
from app.detectors.pii_detector import sanitize
from app.providers.factory import build_semantic_judge_provider

logger=logging.getLogger(__name__)

class GuardPipeline:
    def __init__(self, judge_provider=None, judge_enabled=None):
        self.agents=[SecurityAgent(),PrivacyAgent(),ContentAgent(),PolicyAgent()]
        self.arbiter=ArbiterAgent()
        self.judge_enabled=settings.semantic_judge_enabled if judge_enabled is None else judge_enabled
        self.judge_provider=judge_provider
        self.judge_setup_error=False
        if self.judge_enabled and self.judge_provider is None:
            try:
                self.judge_provider=build_semantic_judge_provider()
            except Exception:
                self.judge_setup_error=True

    @staticmethod
    def _judge_failure(reason="unavailable"):
        mode=settings.semantic_judge_fail_mode.strip().upper()
        decision="BLOCK" if mode=="BLOCK" else "HUMAN_REVIEW"
        return AgentResult("semantic_judge",.9 if decision=="BLOCK" else .65,"HIGH" if decision=="BLOCK" else "MEDIUM",decision,[f"semantic_judge_{reason}"],"Semantic judge unavailable; request held for safety.",0.0)

    def run(self, content, request_type, context=None):
        context=context or {}; started=time.perf_counter()
        # Privacy is always local and runs before any optional external judge.
        sanitized,matches=sanitize_content(content, context.get("pii_mode"))
        ctx=dict(context); ctx["pii_matches"]=matches; ctx["request_type"]=request_type
        results=[a.evaluate(content,ctx) for a in self.agents]

        # The judge gets only locally redacted text and an allow-listed summary.
        # Sensitive context markers, metadata, original content, and raw PII
        # matches are never passed to the provider.
        if self.judge_enabled and not any(r.decision=="BLOCK" for r in results):
            local_security = next((r for r in results if r.agent == "security"), None)
            # A semantic model can mistake redaction placeholders or ordinary
            # contact-details context for an attack. When local security found
            # no attack and the only deterministic signal is PII, the privacy
            # agent is authoritative: don't let the semantic model turn a
            # redact/allow decision into an unrelated injection block.
            pii_only_signal = bool(matches) and not (local_security and local_security.decision != "ALLOW")
            if pii_only_signal:
                results.append(AgentResult("semantic_judge", 0.0, "LOW", "ALLOW", [], "Skipped semantic analysis because the local privacy detector found PII and local security found no attack.", 1.0))
            else:
                judge_content=sanitize(content,matches,"REDACT")
            if not pii_only_signal and judge_content is None:
                results.append(self._judge_failure("sanitization_failed"))
            elif not pii_only_signal and (self.judge_setup_error or self.judge_provider is None):
                results.append(self._judge_failure("unavailable"))
            elif not pii_only_signal:
                try:
                    results.append(SemanticJudgeAgent(self.judge_provider).evaluate(judge_content,ctx))
                except Exception as exc:
                    logger.warning("Semantic judge failed (%s)",type(exc).__name__)
                    results.append(self._judge_failure("unavailable"))
        overall,level,confidence=score(results)
        decision=self.arbiter.decide(results,overall,ctx)
        if decision["decision"]=="MODIFY" and sanitized is None:
            # Never return MODIFY without a safe replacement for the caller.
            decision["decision"]="BLOCK"
            decision["reason"]="Sensitive content could not be safely transformed."
            decision["primary_reason"]=decision["reason"]
            decision["remediation"]="Remove or redact sensitive content before continuing."
        decision["sanitized_content"]=sanitized if decision["decision"]=="MODIFY" and sanitized!=content else None
        return {"request_type":request_type,"decision":decision["decision"],"risk_score":overall,"risk_level":level,"confidence":confidence,"categories":decision["detected_categories"],"sanitized_content":decision.get("sanitized_content"),"agents":results,"arbiter":decision,"latency_ms":round((time.perf_counter()-started)*1000,3),"content_hash":hashlib.sha256(content.encode()).hexdigest()}
