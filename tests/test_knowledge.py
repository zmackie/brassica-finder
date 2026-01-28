"""Tests for the knowledge base."""

import pytest

from aws_privesc_agent.paths.knowledge import (
    ESCALATION_TECHNIQUES,
    get_known_techniques,
    get_technique_by_id,
    get_techniques_by_permission,
)


def test_escalation_techniques_not_empty():
    """Verify we have techniques defined."""
    assert len(ESCALATION_TECHNIQUES) > 0


def test_all_techniques_have_required_fields():
    """Verify all techniques have required fields."""
    required_fields = ["id", "name", "description", "required_permissions", "severity"]

    for tech in ESCALATION_TECHNIQUES:
        for field in required_fields:
            assert field in tech, f"Technique {tech.get('id', 'unknown')} missing {field}"


def test_get_known_techniques_all():
    """Test getting all techniques."""
    techniques = get_known_techniques()
    assert len(techniques) == len(ESCALATION_TECHNIQUES)


def test_get_known_techniques_filtered():
    """Test filtering techniques by query."""
    techniques = get_known_techniques("passrole")
    assert len(techniques) > 0
    for tech in techniques:
        assert "passrole" in tech["id"].lower() or "passrole" in tech["description"].lower()


def test_get_technique_by_id():
    """Test getting a technique by ID."""
    tech = get_technique_by_id("iam-create-policy-version")
    assert tech is not None
    assert tech["name"] == "Create Policy Version"


def test_get_technique_by_id_not_found():
    """Test getting a non-existent technique."""
    tech = get_technique_by_id("non-existent-technique")
    assert tech is None


def test_get_techniques_by_permission():
    """Test getting techniques by required permission."""
    techniques = get_techniques_by_permission("iam:PassRole")
    assert len(techniques) > 0
    for tech in techniques:
        assert any("passrole" in p.lower() for p in tech["required_permissions"])


def test_severity_values():
    """Verify all severity values are valid."""
    valid_severities = {"critical", "high", "medium", "low", "info"}

    for tech in ESCALATION_TECHNIQUES:
        assert tech["severity"] in valid_severities, f"Invalid severity in {tech['id']}"
