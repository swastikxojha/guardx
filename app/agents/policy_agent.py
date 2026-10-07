from .base import GuardrailAgent, AgentResult
class PolicyAgent(GuardrailAgent):
    name="policy"
    def evaluate(self, content, context):
        rules=context.get("policy_rules",[]); hits=[]; forced=[]
        for r in rules:
            category=r.get("category","").lower(); action=r.get("action","ALLOW")
            if category and category in content.lower(): hits.append(category); forced.append(action)
        if not hits:
            return AgentResult(self.name,0,"LOW","ALLOW",[],"No configured policy rule matched",.88)
        order={"ALLOW":0,"MODIFY":1,"HUMAN_REVIEW":2,"BLOCK":3}; action=max(forced,key=lambda x:order.get(x,0))
        score={"MODIFY":.55,"HUMAN_REVIEW":.65,"BLOCK":.9}.get(action,.2)
        return AgentResult(self.name,score,"HIGH" if score>=.75 else "MEDIUM",action,hits,"Configured policy rule matched",.95)
