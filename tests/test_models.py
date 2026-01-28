"""Tests for data models."""

import pytest
from datetime import datetime

from aws_privesc_agent.core.models import (
    Principal,
    PrivescPath,
    Severity,
    EnumerationResult,
    AgentState,
)


def test_principal_creation():
    """Test creating a Principal."""
    principal = Principal(
        arn="arn:aws:iam::123456789012:user/test",
        name="test",
        principal_type="user",
    )

    assert principal.arn == "arn:aws:iam::123456789012:user/test"
    assert principal.name == "test"
    assert principal.principal_type == "user"
    assert principal.is_admin is False
    assert len(principal.permissions) == 0


def test_principal_with_permissions():
    """Test Principal with permissions."""
    principal = Principal(
        arn="arn:aws:iam::123456789012:user/admin",
        name="admin",
        principal_type="user",
        permissions={"iam:*", "ec2:*"},
        is_admin=True,
    )

    assert principal.is_admin is True
    assert "iam:*" in principal.permissions


def test_privesc_path_creation():
    """Test creating a PrivescPath."""
    path = PrivescPath(
        id="test-path",
        name="Test Path",
        description="A test privilege escalation path",
        severity=Severity.CRITICAL,
        source_principal="arn:aws:iam::123456789012:user/attacker",
        required_permissions=["iam:CreatePolicyVersion"],
        steps=["Create admin policy version"],
    )

    assert path.id == "test-path"
    assert path.severity == Severity.CRITICAL
    assert len(path.steps) == 1


def test_severity_enum():
    """Test Severity enum values."""
    assert Severity.CRITICAL.value == "critical"
    assert Severity.HIGH.value == "high"
    assert Severity.MEDIUM.value == "medium"
    assert Severity.LOW.value == "low"
    assert Severity.INFO.value == "info"


def test_enumeration_result():
    """Test EnumerationResult creation."""
    result = EnumerationResult(
        account_id="123456789012",
        identity_arn="arn:aws:iam::123456789012:user/test",
    )

    assert result.account_id == "123456789012"
    assert len(result.users) == 0
    assert len(result.roles) == 0
    assert len(result.admin_principals) == 0


def test_agent_state():
    """Test AgentState creation and defaults."""
    state = AgentState()

    assert state.current_identity is None
    assert state.iteration == 0
    assert state.max_iterations == 10
    assert state.achieved_admin is False
    assert len(state.discovered_paths) == 0
