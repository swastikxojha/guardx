from app.core.config import settings
WEIGHTS={"security":.25,"privacy":.25,"content":.15,"policy":.15,"semantic_judge":.20}
def level(score):
    if score>=settings.risk_threshold_high:return "HIGH"
    if score>=settings.risk_threshold_medium:return "MEDIUM"
    return "LOW"
def score(results):
    total=sum(r.score*WEIGHTS.get(r.agent,0) for r in results)
    # A hard block must not be presented as a low-risk event just because its
    # evaluator has a small ensemble weight.
    if any(r.decision=="BLOCK" for r in results): total=max(total,.75)
    if any(r.decision=="HUMAN_REVIEW" for r in results): total=max(total,.50)
    conf=sum(r.confidence for r in results)/len(results) if results else 0
    return round(min(1,total),4),level(total),round(conf,4)
