from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

@dataclass
class AgentResult:
    agent: str
    score: float
    level: str
    decision: str
    categories: list[str]=field(default_factory=list)
    explanation: str=""
    confidence: float=0.0
    metadata: dict[str,Any]=field(default_factory=dict)

class GuardrailAgent(ABC):
    name: str
    @abstractmethod
    def evaluate(self, content: str, context: dict[str,Any]) -> AgentResult: ...
