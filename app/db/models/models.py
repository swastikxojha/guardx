from datetime import datetime, timezone
from uuid import uuid4
from sqlalchemy import String, Text, Boolean, Float, DateTime, ForeignKey, JSON, Integer, Index
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.database import Base

def uid(): return str(uuid4())
def now(): return datetime.now(timezone.utc)

class User(Base):
    __tablename__="users"
    id: Mapped[str]=mapped_column(String(36), primary_key=True, default=uid)
    email: Mapped[str]=mapped_column(String(255), unique=True, index=True)
    password_hash: Mapped[str]=mapped_column(Text)
    role: Mapped[str]=mapped_column(String(20), default="MEMBER")
    organization_id: Mapped[str]=mapped_column(ForeignKey("organizations.id"), index=True)
    created_at: Mapped[datetime]=mapped_column(DateTime(timezone=True), default=now)

class Organization(Base):
    __tablename__="organizations"
    id: Mapped[str]=mapped_column(String(36), primary_key=True, default=uid)
    name: Mapped[str]=mapped_column(String(255))
    created_at: Mapped[datetime]=mapped_column(DateTime(timezone=True), default=now)

class Application(Base):
    __tablename__="applications"
    id: Mapped[str]=mapped_column(String(36), primary_key=True, default=uid)
    organization_id: Mapped[str]=mapped_column(ForeignKey("organizations.id"), index=True)
    name: Mapped[str]=mapped_column(String(255))
    description: Mapped[str|None]=mapped_column(Text, nullable=True)
    created_at: Mapped[datetime]=mapped_column(DateTime(timezone=True), default=now)

class APIKey(Base):
    __tablename__="api_keys"
    id: Mapped[str]=mapped_column(String(36), primary_key=True, default=uid)
    organization_id: Mapped[str]=mapped_column(ForeignKey("organizations.id"), index=True)
    application_id: Mapped[str|None]=mapped_column(ForeignKey("applications.id"), nullable=True)
    name: Mapped[str]=mapped_column(String(255))
    key_hash: Mapped[str]=mapped_column(String(64), unique=True)
    scopes: Mapped[list]=mapped_column(JSON, default=lambda:["guard:check"])
    expires_at: Mapped[datetime|None]=mapped_column(DateTime(timezone=True), nullable=True)
    revoked: Mapped[bool]=mapped_column(Boolean, default=False)
    created_at: Mapped[datetime]=mapped_column(DateTime(timezone=True), default=now)

class Policy(Base):
    __tablename__="policies"
    id: Mapped[str]=mapped_column(String(36), primary_key=True, default=uid)
    organization_id: Mapped[str]=mapped_column(ForeignKey("organizations.id"), index=True)
    name: Mapped[str]=mapped_column(String(255))
    enabled: Mapped[bool]=mapped_column(Boolean, default=True)
    created_at: Mapped[datetime]=mapped_column(DateTime(timezone=True), default=now)
    rules=relationship("PolicyRule", cascade="all, delete-orphan", back_populates="policy")

class PolicyRule(Base):
    __tablename__="policy_rules"
    id: Mapped[str]=mapped_column(String(36), primary_key=True, default=uid)
    policy_id: Mapped[str]=mapped_column(ForeignKey("policies.id"), index=True)
    category: Mapped[str]=mapped_column(String(100))
    action: Mapped[str]=mapped_column(String(30))
    threshold: Mapped[float|None]=mapped_column(Float, nullable=True)
    config: Mapped[dict]=mapped_column(JSON, default=dict)
    policy=relationship("Policy", back_populates="rules")

class GuardRequest(Base):
    __tablename__="guard_requests"
    id: Mapped[str]=mapped_column(String(36), primary_key=True, default=uid)
    organization_id: Mapped[str]=mapped_column(ForeignKey("organizations.id"), index=True)
    application_id: Mapped[str|None]=mapped_column(ForeignKey("applications.id"), nullable=True, index=True)
    request_type: Mapped[str]=mapped_column(String(20), index=True)
    content_hash: Mapped[str|None]=mapped_column(String(64), nullable=True)
    risk_score: Mapped[float]=mapped_column(Float, default=0)
    risk_level: Mapped[str]=mapped_column(String(20), index=True)
    decision: Mapped[str]=mapped_column(String(30), index=True)
    categories: Mapped[list]=mapped_column(JSON, default=list)
    policy_id: Mapped[str|None]=mapped_column(ForeignKey("policies.id"), nullable=True)
    latency_ms: Mapped[float]=mapped_column(Float, default=0)
    created_at: Mapped[datetime]=mapped_column(DateTime(timezone=True), default=now, index=True)

class AgentResult(Base):
    __tablename__="agent_results"
    id: Mapped[str]=mapped_column(String(36), primary_key=True, default=uid)
    request_id: Mapped[str]=mapped_column(ForeignKey("guard_requests.id"), index=True)
    agent: Mapped[str]=mapped_column(String(50))
    score: Mapped[float]=mapped_column(Float)
    level: Mapped[str]=mapped_column(String(20))
    decision: Mapped[str]=mapped_column(String(30))
    categories: Mapped[list]=mapped_column(JSON, default=list)
    explanation: Mapped[str]=mapped_column(Text)
    confidence: Mapped[float]=mapped_column(Float)
    latency_ms: Mapped[float]=mapped_column(Float, default=0)

class Decision(Base):
    __tablename__="decisions"
    id: Mapped[str]=mapped_column(String(36), primary_key=True, default=uid)
    request_id: Mapped[str]=mapped_column(ForeignKey("guard_requests.id"), unique=True, index=True)
    decision: Mapped[str]=mapped_column(String(30))
    reason: Mapped[str]=mapped_column(Text)
    remediation: Mapped[str]=mapped_column(Text)
    contributing_agents: Mapped[list]=mapped_column(JSON, default=list)
    created_at: Mapped[datetime]=mapped_column(DateTime(timezone=True), default=now)

class AuditLog(Base):
    __tablename__="audit_logs"
    id: Mapped[str]=mapped_column(String(36), primary_key=True, default=uid)
    request_id: Mapped[str]=mapped_column(ForeignKey("guard_requests.id"), index=True)
    organization_id: Mapped[str]=mapped_column(ForeignKey("organizations.id"), index=True)
    event: Mapped[str]=mapped_column(String(100))
    metadata_json: Mapped[dict]=mapped_column(JSON, default=dict)
    created_at: Mapped[datetime]=mapped_column(DateTime(timezone=True), default=now, index=True)

class Review(Base):
    __tablename__="reviews"
    id: Mapped[str]=mapped_column(String(36), primary_key=True, default=uid)
    request_id: Mapped[str]=mapped_column(ForeignKey("guard_requests.id"), unique=True, index=True)
    status: Mapped[str]=mapped_column(String(30), default="PENDING")
    reviewer_id: Mapped[str|None]=mapped_column(ForeignKey("users.id"), nullable=True)
    decision: Mapped[str|None]=mapped_column(String(30), nullable=True)
    comment: Mapped[str|None]=mapped_column(Text, nullable=True)
    created_at: Mapped[datetime]=mapped_column(DateTime(timezone=True), default=now)
    updated_at: Mapped[datetime]=mapped_column(DateTime(timezone=True), default=now)

class Feedback(Base):
    __tablename__="feedback"
    id: Mapped[str]=mapped_column(String(36), primary_key=True, default=uid)
    request_id: Mapped[str]=mapped_column(ForeignKey("guard_requests.id"), index=True)
    label: Mapped[str]=mapped_column(String(40))
    comment: Mapped[str|None]=mapped_column(Text, nullable=True)
    created_at: Mapped[datetime]=mapped_column(DateTime(timezone=True), default=now)

class UsageRecord(Base):
    __tablename__="usage_records"
    id: Mapped[str]=mapped_column(String(36), primary_key=True, default=uid)
    organization_id: Mapped[str]=mapped_column(ForeignKey("organizations.id"), index=True)
    request_type: Mapped[str]=mapped_column(String(20))
    latency_ms: Mapped[float]=mapped_column(Float)
    created_at: Mapped[datetime]=mapped_column(DateTime(timezone=True), default=now, index=True)

Index("ix_guard_requests_org_created", GuardRequest.organization_id, GuardRequest.created_at)
