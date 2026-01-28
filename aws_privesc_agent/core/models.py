"""Data models for privilege escalation paths."""

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Severity(str, Enum):
    """Severity levels for findings."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Principal(BaseModel):
    """An AWS IAM principal (user, role, etc)."""

    arn: str
    name: str
    principal_type: str  # user, role, group
    policies: list[str] = Field(default_factory=list)
    inline_policies: dict[str, Any] = Field(default_factory=dict)
    attached_policies: list[dict[str, str]] = Field(default_factory=list)
    permissions: set[str] = Field(default_factory=set)
    is_admin: bool = False
    trust_policy: dict[str, Any] | None = None


class PrivescPath(BaseModel):
    """A privilege escalation path."""

    id: str
    name: str
    description: str
    severity: Severity
    source_principal: str  # ARN of starting principal
    target_principal: str | None = None  # ARN of target (if role assumption)
    required_permissions: list[str]
    steps: list[str]
    exploit_commands: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    prerequisites: list[str] = Field(default_factory=list)
    detected_at: datetime = Field(default_factory=datetime.now)


class EnumerationResult(BaseModel):
    """Results from AWS enumeration."""

    account_id: str
    identity_arn: str
    users: list[Principal] = Field(default_factory=list)
    roles: list[Principal] = Field(default_factory=list)
    groups: list[dict[str, Any]] = Field(default_factory=list)
    policies: list[dict[str, Any]] = Field(default_factory=list)
    admin_principals: list[str] = Field(default_factory=list)
    enumerated_at: datetime = Field(default_factory=datetime.now)


class AgentState(BaseModel):
    """Current state of the agent."""

    current_identity: str | None = None
    account_id: str | None = None
    enumeration: EnumerationResult | None = None
    discovered_paths: list[PrivescPath] = Field(default_factory=list)
    exploited_paths: list[str] = Field(default_factory=list)
    current_permissions: set[str] = Field(default_factory=set)
    achieved_admin: bool = False
    iteration: int = 0
    max_iterations: int = 10


class ToolResult(BaseModel):
    """Result from running an external tool."""

    tool_name: str
    command: str
    exit_code: int
    stdout: str
    stderr: str
    execution_time_ms: float


class AgentAction(BaseModel):
    """An action the agent wants to take."""

    action_type: str  # enumerate, analyze, exploit, research, code, tool
    description: str
    parameters: dict[str, Any] = Field(default_factory=dict)
    reasoning: str = ""
