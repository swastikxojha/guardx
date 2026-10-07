"""Validate and normalize results from an optional semantic LLM judge."""

from __future__ import annotations

import re
from typing import Any

from .base import AgentResult, GuardrailAgent
from app.providers.base import LLMProvider


_DECISIONS = {"ALLOW", "MODIFY", "BLOCK", "HUMAN_REVIEW"}
_CATEGORIES = {
    "prompt_injection", "instruction_override", "indirect_prompt_injection",
    "system_prompt_disclosure", "sensitive_data_exfiltration", "tool_misuse",
    "harmful_content", "policy_violation", "social_engineering", "ambiguous",
}


def _unit_interval(value: Any, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"Judge {name} must be numeric")
    result = float(value)
    if not 0.0 <= result <= 1.0:
        raise ValueError(f"Judge {name} must be between 0 and 1")
    return result


class SemanticJudgeAgent(GuardrailAgent):
    """Use a local provider as a second opinion; never echo model prose."""

    name = "semantic_judge"

    def __init__(self, provider: LLMProvider):
        self.provider = provider

    def evaluate(self, content: str, context: dict[str, Any]) -> AgentResult:
        # Only labels/actions reach the model. Never forward policy config,
        # metadata, trusted markers, or the system/developer prompt.
        policy_categories = []
        for rule in context.get("policy_rules", [])[:50]:
            category = rule.get("category")
            action = rule.get("action")
            if isinstance(category, str) and isinstance(action, str):
                normalized = re.sub(r"[^a-z0-9_]+", "_", category.lower()).strip("_")
                policy_categories.append({
                    "category": normalized if normalized in _CATEGORIES else "custom_policy_rule",
                    "action": action if action in _DECISIONS else "HUMAN_REVIEW",
                })
        raw = self.provider.judge(content, {"request_type": context.get("request_type", "input"), "policy_categories": policy_categories})
        if not isinstance(raw, dict):
            raise ValueError("Judge response must be an object")

        score = _unit_interval(raw.get("risk_score", raw.get("score")), "risk_score")
        confidence = _unit_interval(raw.get("confidence", 0.5), "confidence")
        proposed = str(raw.get("decision", "")).upper()
        if proposed not in _DECISIONS:
            raise ValueError("Judge returned an unsupported decision")

        raw_categories = raw.get("categories", [])
        if not isinstance(raw_categories, list) or len(raw_categories) > 20:
            raise ValueError("Judge categories must be a short list")
        categories: list[str] = []
        for category in raw_categories:
            if not isinstance(category, str):
                raise ValueError("Judge category must be text")
            normalized = re.sub(r"[^a-z0-9_]+", "_", category.lower()).strip("_")[:64]
            if normalized and normalized in _CATEGORIES and normalized not in categories:
                categories.append(normalized)
        # Tiny models can emit a contradictory category list alongside a
        # confident low-risk ALLOW. Do not let that unsupported label trigger
        # high-severity arbiter rules; local detectors remain authoritative.
        if score < 0.25:
            categories = []
        if score >= 0.25 and not categories:
            categories = ["ambiguous"]

        # The judge cannot rewrite content, downgrade local decisions, or act
        # on tools. MODIFY and uncertain/high-risk disagreement go to review.
        if proposed == "BLOCK" and confidence >= 0.60 and score >= 0.60:
            decision = "BLOCK"
        elif proposed == "HUMAN_REVIEW" or proposed == "MODIFY":
            decision = "HUMAN_REVIEW"
        elif proposed == "BLOCK" or score >= 0.45 or (score >= 0.25 and confidence < 0.60):
            decision = "HUMAN_REVIEW"
        else:
            decision = "ALLOW"

        level = "HIGH" if score >= 0.75 else ("MEDIUM" if score >= 0.45 else "LOW")
        if decision == "BLOCK":
            reason = "The semantic judge found a high-confidence safety violation."
        elif decision == "HUMAN_REVIEW":
            reason = "The semantic judge found an ambiguous or elevated-risk signal."
        elif categories:
            reason = "The semantic judge found a low-risk signal; local policy remains authoritative."
        else:
            reason = "The semantic judge found no additional safety signal."
        return AgentResult(self.name, score, level, decision, categories, reason, confidence)
