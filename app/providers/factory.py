"""Construct only the explicitly configured semantic judge provider."""

from app.core.config import settings
from .base import LLMProvider
from .ollama_provider import OllamaProvider


def build_semantic_judge_provider() -> LLMProvider:
    provider_name = settings.llm_provider.strip().lower()
    if provider_name != "ollama":
        raise ValueError("Semantic judge requires LLM_PROVIDER=ollama")
    return OllamaProvider(
        url=settings.ollama_url,
        model=settings.ollama_model,
        timeout=settings.ollama_timeout_seconds,
    )
