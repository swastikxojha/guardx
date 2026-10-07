from .base import GuardrailAgent, AgentResult
from app.detectors.content_detector import detect_content
class ContentAgent(GuardrailAgent):
    name="content"
    def evaluate(self, content, context):
        toxic,harmful=detect_content(content)
        score=min(1.0,.65*bool(toxic)+.9*bool(harmful))
        decision="BLOCK" if score>=.65 else ("HUMAN_REVIEW" if score else "ALLOW")
        level="HIGH" if score>=.65 else ("MEDIUM" if score else "LOW")
        cats=["toxicity"]*bool(toxic)+["harmfulness"]*bool(harmful)
        return AgentResult(self.name,score,level,decision,cats,"Potentially unsafe content detected" if cats else "No configured harmful-content pattern detected",.9)
