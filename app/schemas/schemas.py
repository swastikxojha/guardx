from datetime import datetime
from typing import Annotated, Any, Literal
from pydantic import BaseModel, Field

Decision=Literal["ALLOW","MODIFY","BLOCK","HUMAN_REVIEW"]

class SignupIn(BaseModel): email: str; password: str = Field(min_length=8); organization_name: str = Field(min_length=2)
class LoginIn(BaseModel): email: str; password: str
class TokenOut(BaseModel): access_token: str; token_type: str="bearer"
class ApplicationIn(BaseModel): name: str; description: str|None=None
class PolicyRuleIn(BaseModel): category: str; action: Decision; threshold: float|None=None; config: dict[str,Any]={}
class PolicyIn(BaseModel): name: str; enabled: bool=True; rules: list[PolicyRuleIn]=[]
class CheckIn(BaseModel): content: str = Field(min_length=1, max_length=50000); application_id: str|None=None; policy_id: str|None=None; metadata: dict[str,Any]=Field(default_factory=dict); sensitive_context: list[Annotated[str,Field(max_length=2048)]]=Field(default_factory=list, max_length=50)
class ActionIn(BaseModel): tool: str; parameters: dict[str,Any]={}; application_id: str|None=None; policy_id: str|None=None
class ReviewIn(BaseModel): decision: Literal["ALLOW","BLOCK","MODIFY"]; comment: str|None=None
class FeedbackIn(BaseModel): label: Literal["correct","incorrect","false_positive","false_negative","human_override"]; comment: str|None=None
class APIKeyIn(BaseModel): name: str; application_id: str|None=None; scopes: list[str]=["guard:check"]; expires_at: datetime|None=None
