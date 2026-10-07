import httpx
from .base import LLMProvider
class OpenAICompatibleProvider(LLMProvider):
    def __init__(self,api_key,base_url="https://api.openai.com/v1",model="gpt-4o-mini"):
        self.api_key=api_key; self.base_url=base_url.rstrip('/'); self.model=model
    def judge(self,content,policy):
        r=httpx.post(f"{self.base_url}/chat/completions",headers={"Authorization":f"Bearer {self.api_key}"},json={"model":self.model,"messages":[{"role":"system","content":"Return strict JSON safety evaluation."},{"role":"user","content":f"Policy: {policy}\nContent: {content}"}],"temperature":0},timeout=30)
        r.raise_for_status(); return {"raw":r.json()["choices"][0]["message"]["content"]}
