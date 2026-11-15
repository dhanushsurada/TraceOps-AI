"""
TraceOps AI — Database Models and Complete Domain Ontology
Includes:
- Authentication & Tenants: User, UserSession, Integration, OAuthState
- Core Tasks & Projects: Project, Task
- Engineering Artifacts & Telemetry: Commit, FileChange, PullRequest, Build, Deployment, ErrorRecord, Decision
- AI Interactions: AISession, AIPrompt, AIProxyLog
- Knowledge & Execution Graph: GraphEdge
- Deterministic Observations: Observation
- Versioned Assessments: Assessment, Score
- Reports & Historic Audits: Report
"""
import uuid
from datetime import date as dt_date, datetime
from typing import Optional, List, Dict, Any

from sqlalchemy import (
    JSON, Boolean, Date, DateTime, Float, ForeignKey, Integer, Numeric,
    String, Text, UniqueConstraint, Index
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func

from app.core.database import Base


def gen_uuid() -> str:
    return str(uuid.uuid4())


# ── User & Sessions ───────────────────────────────────────────────────────────

class User(Base):
    __tablename__ = "users"

    id: Mapped[str]           = mapped_column(String, primary_key=True, default=gen_uuid)
    email: Mapped[str]        = mapped_column(String(255), unique=True, nullable=False, index=True)
    name: Mapped[str]         = mapped_column(String(255), nullable=True)
    avatar_url: Mapped[str]   = mapped_column(Text, nullable=True)
    github_id: Mapped[str]    = mapped_column(String(64), unique=True, nullable=True, index=True)
    google_id: Mapped[str]    = mapped_column(String(64), unique=True, nullable=True, index=True)
    github_username: Mapped[str] = mapped_column(String(128), nullable=True)
    is_active: Mapped[bool]   = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    integrations: Mapped[List["Integration"]] = relationship("Integration", back_populates="user", cascade="all, delete-orphan")
    sessions:     Mapped[List["UserSession"]] = relationship("UserSession", back_populates="user", cascade="all, delete-orphan")
    api_keys:     Mapped[List["ApiKey"]]      = relationship("ApiKey", back_populates="user", cascade="all, delete-orphan")
    projects:     Mapped[List["Project"]]     = relationship("Project", back_populates="user", cascade="all, delete-orphan")
    tasks:        Mapped[List["Task"]]        = relationship("Task", back_populates="user")
    events:       Mapped[List["Event"]]       = relationship("Event", back_populates="user")
    observations: Mapped[List["Observation"]] = relationship("Observation", back_populates="user")
    assessments:  Mapped[List["Assessment"]]  = relationship("Assessment", back_populates="user")


class ApiKey(Base):
    __tablename__ = "api_keys"
    __table_args__ = (
        Index("idx_api_keys_hash", "key_hash"),
        Index("idx_api_keys_user", "user_id"),
    )

    id: Mapped[str]           = mapped_column(String, primary_key=True, default=gen_uuid)
    user_id: Mapped[str]      = mapped_column(String, ForeignKey("users.id"), nullable=False, index=True)
    name: Mapped[str]         = mapped_column(String(128), default="Default Key")
    key_prefix: Mapped[str]   = mapped_column(String(16), nullable=False)
    key_hash: Mapped[str]     = mapped_column(String(64), unique=True, nullable=False, index=True)
    scopes: Mapped[str]       = mapped_column(String(256), default="read,write,mcp")
    revoked: Mapped[bool]     = mapped_column(Boolean, default=False)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_used_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    user: Mapped["User"]      = relationship("User", back_populates="api_keys")


class UserSession(Base):
    __tablename__ = "user_sessions"

    id: Mapped[str]           = mapped_column(String, primary_key=True, default=gen_uuid)
    user_id: Mapped[str]      = mapped_column(String, ForeignKey("users.id"), nullable=False, index=True)
    session_token: Mapped[str] = mapped_column(String(512), unique=True, nullable=False, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    ip_address: Mapped[str]   = mapped_column(String(64), nullable=True)
    user_agent: Mapped[str]   = mapped_column(Text, nullable=True)

    user: Mapped["User"] = relationship("User", back_populates="sessions")


class Integration(Base):
    __tablename__ = "integrations"
    __table_args__ = (UniqueConstraint("user_id", "provider", name="uq_user_provider"),)

    id: Mapped[str]            = mapped_column(String, primary_key=True, default=gen_uuid)
    user_id: Mapped[str]       = mapped_column(String, ForeignKey("users.id"), nullable=False, index=True)
    provider: Mapped[str]      = mapped_column(String(64), nullable=False)   # github|vercel|gitlab|render
    status: Mapped[str]        = mapped_column(String(32), default="connected") # connected|disconnected|error
    access_token: Mapped[str]  = mapped_column(Text, nullable=True)           # encrypted with Fernet
    refresh_token: Mapped[str] = mapped_column(Text, nullable=True)           # encrypted with Fernet
    token_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)
    scopes: Mapped[str]        = mapped_column(Text, nullable=True)
    provider_user_id: Mapped[str]  = mapped_column(String(128), nullable=True)
    provider_username: Mapped[str] = mapped_column(String(128), nullable=True)
    sync_cursor: Mapped[str]   = mapped_column(String(256), nullable=True)   # cursor for incremental sync
    metadata_: Mapped[dict]    = mapped_column("metadata", JSON, nullable=True)
    connected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_synced_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)

    user: Mapped["User"] = relationship("User", back_populates="integrations")


class OAuthState(Base):
    __tablename__ = "oauth_states"

    id: Mapped[str]         = mapped_column(String, primary_key=True, default=gen_uuid)
    state: Mapped[str]      = mapped_column(String(256), unique=True, nullable=False, index=True)
    provider: Mapped[str]   = mapped_column(String(64), nullable=False)
    user_id: Mapped[str]    = mapped_column(String, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


# ── Projects & Tasks ──────────────────────────────────────────────────────────

class Project(Base):
    __tablename__ = "projects"
    __table_args__ = (UniqueConstraint("user_id", "slug", name="uq_user_project_slug"),)

    id: Mapped[str]           = mapped_column(String, primary_key=True, default=gen_uuid)
    user_id: Mapped[str]      = mapped_column(String, ForeignKey("users.id"), nullable=False, index=True)
    name: Mapped[str]         = mapped_column(String(255), nullable=False)
    slug: Mapped[str]         = mapped_column(String(255), nullable=False, index=True)
    description: Mapped[str]  = mapped_column(Text, nullable=True)
    default_branch: Mapped[str] = mapped_column(String(64), default="main")
    visibility: Mapped[str]   = mapped_column(String(32), default="private") # public | private
    repository_url: Mapped[str] = mapped_column(Text, nullable=True)
    metadata_: Mapped[dict]   = mapped_column("metadata", JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    user:        Mapped["User"]            = relationship("User", back_populates="projects")
    tasks:       Mapped[List["Task"]]      = relationship("Task", back_populates="project", cascade="all, delete-orphan")
    commits:     Mapped[List["Commit"]]    = relationship("Commit", back_populates="project")
    deployments: Mapped[List["Deployment"]] = relationship("Deployment", back_populates="project")


class Task(Base):
    __tablename__ = "tasks"

    id: Mapped[str]           = mapped_column(String, primary_key=True, default=gen_uuid)
    user_id: Mapped[str]      = mapped_column(String, ForeignKey("users.id"), nullable=False, index=True)
    project_id: Mapped[str]   = mapped_column(String, ForeignKey("projects.id"), nullable=True, index=True)
    goal: Mapped[str]         = mapped_column(Text, nullable=False)
    target_level: Mapped[int] = mapped_column(Integer, nullable=False)
    final_level: Mapped[int]  = mapped_column(Integer, nullable=True)
    status: Mapped[str]       = mapped_column(String, default="active") # planned | active | completed | abandoned
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    ended_at: Mapped[datetime]   = mapped_column(DateTime(timezone=True), nullable=True)
    task_date: Mapped[dt_date]   = mapped_column("date", Date, default=dt_date.today, index=True)

    user:         Mapped["User"]               = relationship("User", back_populates="tasks")
    project:      Mapped[Optional["Project"]]  = relationship("Project", back_populates="tasks")
    events:       Mapped[List["Event"]]        = relationship("Event", back_populates="task")
    score:        Mapped[Optional["Score"]]    = relationship("Score", back_populates="task", uselist=False)
    commits:      Mapped[List["Commit"]]       = relationship("Commit", back_populates="task")
    ai_sessions:  Mapped[List["AISession"]]    = relationship("AISession", back_populates="task")
    observations: Mapped[List["Observation"]]  = relationship("Observation", back_populates="task")
    assessments:  Mapped[List["Assessment"]]   = relationship("Assessment", back_populates="task")
    decisions:    Mapped[List["Decision"]]     = relationship("Decision", back_populates="task")


# ── Engineering Telemetry Entities ───────────────────────────────────────────

class Commit(Base):
    __tablename__ = "commits"
    __table_args__ = (UniqueConstraint("project_id", "sha", name="uq_project_commit_sha"),)

    id: Mapped[str]                 = mapped_column(String, primary_key=True, default=gen_uuid)
    user_id: Mapped[str]            = mapped_column(String, ForeignKey("users.id"), nullable=False, index=True)
    project_id: Mapped[str]         = mapped_column(String, ForeignKey("projects.id"), nullable=False, index=True)
    task_id: Mapped[str]            = mapped_column(String, ForeignKey("tasks.id"), nullable=True, index=True)
    sha: Mapped[str]                = mapped_column(String(64), nullable=False, index=True)
    message: Mapped[str]            = mapped_column(Text, nullable=False)
    author_name: Mapped[str]        = mapped_column(String(255), nullable=True)
    author_email: Mapped[str]       = mapped_column(String(255), nullable=True)
    committed_at: Mapped[datetime]  = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    lines_added: Mapped[int]        = mapped_column(Integer, default=0)
    lines_deleted: Mapped[int]      = mapped_column(Integer, default=0)
    files_changed_count: Mapped[int] = mapped_column(Integer, default=0)
    is_merge: Mapped[bool]          = mapped_column(Boolean, default=False)
    url: Mapped[str]                = mapped_column(Text, nullable=True)
    raw_payload: Mapped[dict]       = mapped_column(JSON, nullable=True)

    project:      Mapped["Project"]          = relationship("Project", back_populates="commits")
    task:         Mapped[Optional["Task"]]   = relationship("Task", back_populates="commits")
    file_changes: Mapped[List["FileChange"]] = relationship("FileChange", back_populates="commit", cascade="all, delete-orphan")


class FileChange(Base):
    __tablename__ = "file_changes"

    id: Mapped[str]           = mapped_column(String, primary_key=True, default=gen_uuid)
    commit_id: Mapped[str]    = mapped_column(String, ForeignKey("commits.id"), nullable=False, index=True)
    file_path: Mapped[str]    = mapped_column(Text, nullable=False, index=True)
    change_type: Mapped[str]  = mapped_column(String(32), default="modified") # added|modified|deleted|renamed
    lines_added: Mapped[int]  = mapped_column(Integer, default=0)
    lines_deleted: Mapped[int]= mapped_column(Integer, default=0)
    patch_summary: Mapped[str]= mapped_column(Text, nullable=True)

    commit: Mapped["Commit"] = relationship("Commit", back_populates="file_changes")


class PullRequest(Base):
    __tablename__ = "pull_requests"
    __table_args__ = (UniqueConstraint("project_id", "external_pr_id", name="uq_project_external_pr"),)

    id: Mapped[str]                 = mapped_column(String, primary_key=True, default=gen_uuid)
    user_id: Mapped[str]            = mapped_column(String, ForeignKey("users.id"), nullable=False, index=True)
    project_id: Mapped[str]         = mapped_column(String, ForeignKey("projects.id"), nullable=False, index=True)
    task_id: Mapped[str]            = mapped_column(String, ForeignKey("tasks.id"), nullable=True, index=True)
    external_pr_id: Mapped[int]     = mapped_column(Integer, nullable=False)
    title: Mapped[str]              = mapped_column(Text, nullable=False)
    body: Mapped[str]               = mapped_column(Text, nullable=True)
    state: Mapped[str]              = mapped_column(String(32), default="open") # open|closed|merged
    source_branch: Mapped[str]      = mapped_column(String(128), nullable=True)
    target_branch: Mapped[str]      = mapped_column(String(128), default="main")
    url: Mapped[str]                = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime]    = mapped_column(DateTime(timezone=True), nullable=False)
    merged_at: Mapped[datetime]     = mapped_column(DateTime(timezone=True), nullable=True)
    closed_at: Mapped[datetime]     = mapped_column(DateTime(timezone=True), nullable=True)


class Deployment(Base):
    __tablename__ = "deployments"

    id: Mapped[str]                 = mapped_column(String, primary_key=True, default=gen_uuid)
    user_id: Mapped[str]            = mapped_column(String, ForeignKey("users.id"), nullable=False, index=True)
    project_id: Mapped[str]         = mapped_column(String, ForeignKey("projects.id"), nullable=False, index=True)
    environment: Mapped[str]        = mapped_column(String(64), default="production")
    status: Mapped[str]             = mapped_column(String(32), default="ready") # queued|building|ready|failed
    commit_sha: Mapped[str]         = mapped_column(String(64), nullable=True, index=True)
    url: Mapped[str]                = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime]    = mapped_column(DateTime(timezone=True), server_default=func.now())
    completed_at: Mapped[datetime]  = mapped_column(DateTime(timezone=True), nullable=True)
    error_message: Mapped[str]      = mapped_column(Text, nullable=True)
    raw_payload: Mapped[dict]       = mapped_column(JSON, nullable=True)

    project: Mapped["Project"] = relationship("Project", back_populates="deployments")


class ErrorRecord(Base):
    __tablename__ = "errors"

    id: Mapped[str]                 = mapped_column(String, primary_key=True, default=gen_uuid)
    user_id: Mapped[str]            = mapped_column(String, ForeignKey("users.id"), nullable=False, index=True)
    task_id: Mapped[str]            = mapped_column(String, ForeignKey("tasks.id"), nullable=True, index=True)
    project_id: Mapped[str]         = mapped_column(String, ForeignKey("projects.id"), nullable=True, index=True)
    fingerprint: Mapped[str]        = mapped_column(String(64), nullable=False, index=True)
    exception_type: Mapped[str]     = mapped_column(String(128), nullable=False)
    message: Mapped[str]            = mapped_column(Text, nullable=False)
    stack_trace: Mapped[str]        = mapped_column(Text, nullable=True)
    severity: Mapped[str]           = mapped_column(String(32), default="medium") # low|medium|high|critical
    occurred_at: Mapped[datetime]   = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)
    metadata_: Mapped[dict]         = mapped_column("metadata", JSON, nullable=True)


class Decision(Base):
    __tablename__ = "decisions"

    id: Mapped[str]                 = mapped_column(String, primary_key=True, default=gen_uuid)
    user_id: Mapped[str]            = mapped_column(String, ForeignKey("users.id"), nullable=False, index=True)
    task_id: Mapped[str]            = mapped_column(String, ForeignKey("tasks.id"), nullable=True, index=True)
    project_id: Mapped[str]         = mapped_column(String, ForeignKey("projects.id"), nullable=True, index=True)
    title: Mapped[str]              = mapped_column(String(255), nullable=False)
    context: Mapped[str]            = mapped_column(Text, nullable=False)
    chosen_path: Mapped[str]        = mapped_column(Text, nullable=False)
    alternatives: Mapped[dict]      = mapped_column(JSON, nullable=True) # list of alternative paths considered
    consequences: Mapped[str]       = mapped_column(Text, nullable=True)
    recorded_at: Mapped[datetime]   = mapped_column(DateTime(timezone=True), server_default=func.now())

    task: Mapped[Optional["Task"]] = relationship("Task", back_populates="decisions")


# ── AI Telemetry ──────────────────────────────────────────────────────────────

class AISession(Base):
    __tablename__ = "ai_sessions"

    id: Mapped[str]                 = mapped_column(String, primary_key=True, default=gen_uuid)
    user_id: Mapped[str]            = mapped_column(String, ForeignKey("users.id"), nullable=False, index=True)
    task_id: Mapped[str]            = mapped_column(String, ForeignKey("tasks.id"), nullable=True, index=True)
    session_name: Mapped[str]       = mapped_column(String(255), nullable=True)
    started_at: Mapped[datetime]    = mapped_column(DateTime(timezone=True), server_default=func.now())
    ended_at: Mapped[datetime]      = mapped_column(DateTime(timezone=True), nullable=True)

    task:    Mapped[Optional["Task"]]   = relationship("Task", back_populates="ai_sessions")
    prompts: Mapped[List["AIPrompt"]]   = relationship("AIPrompt", back_populates="session", cascade="all, delete-orphan")


class AIPrompt(Base):
    __tablename__ = "ai_prompts"

    id: Mapped[str]                 = mapped_column(String, primary_key=True, default=gen_uuid)
    session_id: Mapped[str]         = mapped_column(String, ForeignKey("ai_sessions.id"), nullable=False, index=True)
    provider: Mapped[str]           = mapped_column(String(64), nullable=False)
    prompt_text: Mapped[str]        = mapped_column(Text, nullable=False)
    response_text: Mapped[str]      = mapped_column(Text, nullable=True)
    prompt_tokens: Mapped[int]      = mapped_column(Integer, default=0)
    completion_tokens: Mapped[int]  = mapped_column(Integer, default=0)
    latency_ms: Mapped[int]         = mapped_column(Integer, default=0)
    prompt_hash: Mapped[str]        = mapped_column(String(64), nullable=True, index=True)
    classification: Mapped[str]     = mapped_column(String(64), default="general")
    created_at: Mapped[datetime]    = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)

    session: Mapped["AISession"] = relationship("AISession", back_populates="prompts")


class AIProxyLog(Base):
    __tablename__ = "ai_proxy_logs"

    id: Mapped[int]              = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[str]         = mapped_column(String, ForeignKey("users.id"), nullable=True, index=True)
    task_id: Mapped[str]         = mapped_column(String, nullable=True)
    provider: Mapped[str]        = mapped_column(String)
    prompt: Mapped[str]          = mapped_column(Text)
    response: Mapped[str]        = mapped_column(Text, nullable=True)
    prompt_tokens: Mapped[int]   = mapped_column(Integer, nullable=True)
    completion_tokens: Mapped[int] = mapped_column(Integer, nullable=True)
    latency_ms: Mapped[int]      = mapped_column(Integer, nullable=True)
    timestamp: Mapped[datetime]  = mapped_column(DateTime(timezone=True), server_default=func.now())
    error: Mapped[str]           = mapped_column(Text, nullable=True)


# ── Generic Events ───────────────────────────────────────────────────────────

class Event(Base):
    __tablename__ = "events"

    id: Mapped[int]          = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[str]     = mapped_column(String, ForeignKey("users.id"), nullable=True, index=True)
    task_id: Mapped[str]     = mapped_column(String, ForeignKey("tasks.id"), nullable=True)
    event_type: Mapped[str]  = mapped_column(String, nullable=False, index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)
    source: Mapped[str]      = mapped_column(String, nullable=True)
    raw_data: Mapped[dict]   = mapped_column(JSON, nullable=True)
    metadata_: Mapped[dict]  = mapped_column("metadata", JSON, nullable=True)

    user: Mapped[Optional["User"]] = relationship("User", back_populates="events")
    task: Mapped[Optional["Task"]] = relationship("Task", back_populates="events")


# ── Execution Graph Edges ─────────────────────────────────────────────────────

class GraphEdge(Base):
    __tablename__ = "graph_edges"
    __table_args__ = (
        UniqueConstraint("user_id", "source_type", "source_id", "edge_type", "target_type", "target_id", name="uq_graph_edge"),
        Index("idx_edges_source", "user_id", "source_type", "source_id"),
        Index("idx_edges_target", "user_id", "target_type", "target_id"),
    )

    id: Mapped[str]           = mapped_column(String, primary_key=True, default=gen_uuid)
    user_id: Mapped[str]      = mapped_column(String, ForeignKey("users.id"), nullable=False, index=True)
    source_type: Mapped[str]  = mapped_column(String(32), nullable=False) # Task|Commit|FileChange|AISession|Build|Deployment|Error
    source_id: Mapped[str]    = mapped_column(String, nullable=False)
    edge_type: Mapped[str]    = mapped_column(String(32), nullable=False) # CONTRIBUTES_TO|MODIFIES|RELEASES|ASSISTS|CAUSES|RESOLVES|PRECEDES
    target_type: Mapped[str]  = mapped_column(String(32), nullable=False)
    target_id: Mapped[str]    = mapped_column(String, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, default=1.0)
    evidence_source: Mapped[str] = mapped_column(String(64), default="explicit_tag") # explicit_tag|time_window|file_overlap|semantic
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


# ── Deterministic Observations ───────────────────────────────────────────────

class Observation(Base):
    __tablename__ = "observations"
    __table_args__ = (
        Index("idx_obs_window", "user_id", "window_start", "window_end"),
    )

    id: Mapped[str]               = mapped_column(String, primary_key=True, default=gen_uuid)
    user_id: Mapped[str]          = mapped_column(String, ForeignKey("users.id"), nullable=False, index=True)
    task_id: Mapped[str]          = mapped_column(String, ForeignKey("tasks.id"), nullable=True, index=True)
    project_id: Mapped[str]       = mapped_column(String, ForeignKey("projects.id"), nullable=True, index=True)
    window_start: Mapped[datetime]= mapped_column(DateTime(timezone=True), nullable=False)
    window_end: Mapped[datetime]  = mapped_column(DateTime(timezone=True), nullable=False)
    observation_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    metric_value: Mapped[float]   = mapped_column(Float, nullable=False)
    unit: Mapped[str]             = mapped_column(String(32), nullable=False)
    supporting_evidence: Mapped[dict] = mapped_column(JSON, nullable=False) # list of commit SHAs, prompt hashes, etc.
    evidence_hash: Mapped[str]    = mapped_column(String(64), nullable=False)
    computed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    user:    Mapped["User"]           = relationship("User", back_populates="observations")
    task:    Mapped[Optional["Task"]] = relationship("Task", back_populates="observations")


# ── Versioned Assessments & Scores ───────────────────────────────────────────

class Assessment(Base):
    __tablename__ = "assessments"
    __table_args__ = (
        Index("idx_assess_user_dim", "user_id", "assessment_dimension", "created_at"),
    )

    id: Mapped[str]                       = mapped_column(String, primary_key=True, default=gen_uuid)
    user_id: Mapped[str]                  = mapped_column(String, ForeignKey("users.id"), nullable=False, index=True)
    task_id: Mapped[str]                  = mapped_column(String, ForeignKey("tasks.id"), nullable=True, index=True)
    project_id: Mapped[str]               = mapped_column(String, ForeignKey("projects.id"), nullable=True, index=True)
    assessment_dimension: Mapped[str]     = mapped_column(String(64), nullable=False)
    algorithm_version: Mapped[str]        = mapped_column(String(16), default="v4.0.0")
    window_start: Mapped[datetime]        = mapped_column(DateTime(timezone=True), nullable=False)
    window_end: Mapped[datetime]          = mapped_column(DateTime(timezone=True), nullable=False)
    score: Mapped[float]                  = mapped_column(Float, nullable=False)
    confidence: Mapped[float]             = mapped_column(Float, default=1.0)
    input_observation_ids: Mapped[list]   = mapped_column(JSON, nullable=False)
    breakdown: Mapped[dict]               = mapped_column(JSON, nullable=False)
    limitations: Mapped[dict]             = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime]          = mapped_column(DateTime(timezone=True), server_default=func.now())

    user: Mapped["User"]           = relationship("User", back_populates="assessments")
    task: Mapped[Optional["Task"]] = relationship("Task", back_populates="assessments")


class Score(Base):
    __tablename__ = "scores"

    id: Mapped[int]              = mapped_column(Integer, primary_key=True, autoincrement=True)
    task_id: Mapped[str]         = mapped_column(String, ForeignKey("tasks.id"), unique=True)
    score_date: Mapped[dt_date]  = mapped_column("date", Date, default=dt_date.today)
    level: Mapped[int]           = mapped_column(Integer)
    velocity: Mapped[int]        = mapped_column(Integer)
    stability_penalty: Mapped[int] = mapped_column(Integer)
    ai_penalty: Mapped[int]      = mapped_column(Integer)
    final_score: Mapped[int]     = mapped_column(Integer)

    task: Mapped["Task"] = relationship("Task", back_populates="score")


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[int]              = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[str]         = mapped_column(String, ForeignKey("users.id"), nullable=True, index=True)
    report_date: Mapped[dt_date] = mapped_column("date", Date, default=dt_date.today)
    content: Mapped[dict]        = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
