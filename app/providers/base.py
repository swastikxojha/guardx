from abc import ABC, abstractmethod
class LLMProvider(ABC):
    @abstractmethod
    def judge(self, content: str, policy: dict) -> dict: ...
