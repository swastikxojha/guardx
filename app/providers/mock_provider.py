from .base import LLMProvider
class MockProvider(LLMProvider):
    def judge(self, content, policy):
        return {"score":0.0,"decision":"ALLOW","reason":"Mock evaluator: no additional signal"}
