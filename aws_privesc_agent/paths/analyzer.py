"""Analyze enumeration results to find privilege escalation paths."""

import re
from typing import Any

from ..core.logger import get_logger
from ..core.models import EnumerationResult, Principal, PrivescPath, Severity
from .knowledge import ESCALATION_TECHNIQUES

logger = get_logger("paths.analyzer")


def analyze_paths(enumeration: EnumerationResult) -> list[PrivescPath]:
    """Analyze enumeration results to find privilege escalation paths.

    Args:
        enumeration: IAM enumeration results

    Returns:
        List of discovered privilege escalation paths
    """
    paths = []

    # Get all non-admin principals
    non_admin_users = [u for u in enumeration.users if not u.is_admin]
    non_admin_roles = [r for r in enumeration.roles if not r.is_admin]

    # Get admin principals for targeting
    admin_users = [u for u in enumeration.users if u.is_admin]
    admin_roles = [r for r in enumeration.roles if r.is_admin]

    logger.info(
        f"Analyzing {len(non_admin_users)} non-admin users, "
        f"{len(non_admin_roles)} non-admin roles"
    )
    logger.info(f"Target admins: {len(admin_users)} users, {len(admin_roles)} roles")

    # Check each non-admin principal for escalation paths
    for principal in non_admin_users + non_admin_roles:
        principal_paths = _analyze_principal(
            principal, admin_users, admin_roles, enumeration
        )
        paths.extend(principal_paths)

    # Sort by severity
    severity_order = {
        Severity.CRITICAL: 0,
        Severity.HIGH: 1,
        Severity.MEDIUM: 2,
        Severity.LOW: 3,
        Severity.INFO: 4,
    }
    paths.sort(key=lambda p: severity_order.get(p.severity, 99))

    logger.info(f"Found {len(paths)} potential privilege escalation paths")
    return paths


def _analyze_principal(
    principal: Principal,
    admin_users: list[Principal],
    admin_roles: list[Principal],
    enumeration: EnumerationResult,
) -> list[PrivescPath]:
    """Analyze a single principal for escalation paths."""
    paths = []
    permissions = principal.permissions

    logger.debug(f"Analyzing principal: {principal.name} ({len(permissions)} permissions)")

    # Check against known techniques
    for technique in ESCALATION_TECHNIQUES:
        required = set(technique["required_permissions"])

        # Check if principal has all required permissions
        if _has_permissions(permissions, required):
            path = _create_path_from_technique(
                technique, principal, admin_users, admin_roles, enumeration
            )
            if path:
                paths.append(path)
                logger.debug(f"Found path: {technique['name']} for {principal.name}")

    # Check for role assumption paths
    assumption_paths = _check_role_assumptions(principal, admin_roles)
    paths.extend(assumption_paths)

    return paths


def _has_permissions(
    principal_permissions: set[str], required_permissions: set[str]
) -> bool:
    """Check if a principal has the required permissions."""
    # Handle wildcard permissions
    if "*" in principal_permissions:
        return True

    for required in required_permissions:
        found = False

        # Check exact match
        if required in principal_permissions:
            found = True
        else:
            # Check service wildcards (e.g., "iam:*" covers "iam:CreateUser")
            service = required.split(":")[0] if ":" in required else ""
            if f"{service}:*" in principal_permissions:
                found = True
            else:
                # Check action wildcards (e.g., "iam:Create*" covers "iam:CreateUser")
                for perm in principal_permissions:
                    if _permission_matches(perm, required):
                        found = True
                        break

        if not found:
            return False

    return True


def _permission_matches(pattern: str, action: str) -> bool:
    """Check if a permission pattern matches an action."""
    if pattern == action:
        return True

    # Convert IAM wildcard to regex
    if "*" in pattern:
        regex = "^" + re.escape(pattern).replace(r"\*", ".*") + "$"
        return bool(re.match(regex, action, re.IGNORECASE))

    return False


def _create_path_from_technique(
    technique: dict[str, Any],
    source: Principal,
    admin_users: list[Principal],
    admin_roles: list[Principal],
    enumeration: EnumerationResult,
) -> PrivescPath | None:
    """Create a PrivescPath from a technique match."""

    # Determine target based on technique type
    target_arn = None
    steps = list(technique.get("steps", []))

    technique_id = technique["id"]

    # For techniques targeting users
    if "user" in technique_id.lower():
        if admin_users:
            target_arn = admin_users[0].arn
            steps = [s.replace("<user>", admin_users[0].name) for s in steps]

    # For techniques targeting roles
    elif "role" in technique_id.lower() or "assume" in technique_id.lower():
        # Find assumable admin role
        assumable = _find_assumable_roles(source, admin_roles)
        if assumable:
            target_arn = assumable[0].arn
            steps = [s.replace("<role>", assumable[0].name) for s in steps]
        elif admin_roles:
            target_arn = admin_roles[0].arn
            steps = [s.replace("<role>", admin_roles[0].name) for s in steps]

    # For PassRole techniques
    elif "passrole" in technique_id.lower():
        # Find roles that trust the relevant service
        service_trust_map = {
            "ec2": "ec2.amazonaws.com",
            "lambda": "lambda.amazonaws.com",
            "cloudformation": "cloudformation.amazonaws.com",
            "glue": "glue.amazonaws.com",
            "sagemaker": "sagemaker.amazonaws.com",
            "codebuild": "codebuild.amazonaws.com",
            "datapipeline": "datapipeline.amazonaws.com",
        }

        for service, trust_principal in service_trust_map.items():
            if service in technique_id:
                passable_roles = _find_passable_roles(
                    admin_roles + [r for r in enumeration.roles if r.is_admin],
                    trust_principal,
                )
                if passable_roles:
                    target_arn = passable_roles[0].arn
                    break

    severity = Severity(technique.get("severity", "medium"))

    return PrivescPath(
        id=f"{technique['id']}-{source.name}",
        name=technique["name"],
        description=technique["description"],
        severity=severity,
        source_principal=source.arn,
        target_principal=target_arn,
        required_permissions=technique["required_permissions"],
        steps=steps,
        exploit_commands=technique.get("exploit_commands", []),
        references=technique.get("references", []),
        prerequisites=technique.get("prerequisites", []),
    )


def _check_role_assumptions(
    principal: Principal, admin_roles: list[Principal]
) -> list[PrivescPath]:
    """Check if principal can assume any admin roles."""
    paths = []

    for role in admin_roles:
        if _can_assume_role(principal, role):
            paths.append(
                PrivescPath(
                    id=f"sts-assume-role-{principal.name}-{role.name}",
                    name="Direct Role Assumption",
                    description=f"Can directly assume admin role {role.name}",
                    severity=Severity.CRITICAL,
                    source_principal=principal.arn,
                    target_principal=role.arn,
                    required_permissions=["sts:AssumeRole"],
                    steps=[
                        f"Assume role {role.name}",
                        "Gain admin privileges",
                    ],
                    exploit_commands=[
                        f"aws sts assume-role --role-arn {role.arn} --role-session-name privesc",
                    ],
                )
            )

    return paths


def _can_assume_role(principal: Principal, role: Principal) -> bool:
    """Check if a principal can assume a role based on trust policy."""
    if not role.trust_policy:
        return False

    trust_policy = role.trust_policy

    for statement in trust_policy.get("Statement", []):
        if statement.get("Effect") != "Allow":
            continue

        if statement.get("Action") not in ["sts:AssumeRole", "sts:*"]:
            continue

        principal_spec = statement.get("Principal", {})

        # Check AWS principals
        aws_principals = principal_spec.get("AWS", [])
        if isinstance(aws_principals, str):
            aws_principals = [aws_principals]

        for allowed in aws_principals:
            if allowed == "*":
                return True
            if allowed == principal.arn:
                return True
            # Check account-level trust
            if ":root" in allowed:
                account = allowed.split(":")[4]
                if account in principal.arn:
                    return True

    return False


def _find_assumable_roles(
    source: Principal, roles: list[Principal]
) -> list[Principal]:
    """Find roles that the source principal can assume."""
    assumable = []

    for role in roles:
        if _can_assume_role(source, role):
            assumable.append(role)

    return assumable


def _find_passable_roles(
    roles: list[Principal], service_principal: str
) -> list[Principal]:
    """Find roles that trust a specific service principal."""
    passable = []

    for role in roles:
        if not role.trust_policy:
            continue

        for statement in role.trust_policy.get("Statement", []):
            if statement.get("Effect") != "Allow":
                continue

            principal_spec = statement.get("Principal", {})
            service_principals = principal_spec.get("Service", [])

            if isinstance(service_principals, str):
                service_principals = [service_principals]

            if service_principal in service_principals:
                passable.append(role)
                break

    return passable
