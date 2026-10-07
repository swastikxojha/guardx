from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    database_url: str = "sqlite:///./guardx.db"
    jwt_secret: str = "change-this-development-secret-32chars-min"
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 60
    llm_provider: str = "mock"
    llm_api_key: str | None = None
    ollama_url: str = "http://localhost:11434"
    ollama_model: str = "qwen2.5:3b"
    ollama_timeout_seconds: float = 30.0
    semantic_judge_enabled: bool = False
    semantic_judge_fail_mode: str = "HUMAN_REVIEW"
    log_level: str = "INFO"
    pii_mode: str = "REDACT"
    pii_ner_model: str = "en_core_web_sm"
    risk_threshold_low: float = 0.25
    risk_threshold_medium: float = 0.50
    risk_threshold_high: float = 0.75
    guardx_seed: bool = False
    max_request_chars: int = 50000
    auto_create_db: bool = True
    model_config = SettingsConfigDict(env_file=".env", case_sensitive=False, extra="ignore")

settings = Settings()
