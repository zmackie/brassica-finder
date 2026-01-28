"""AWS IAM enumeration module."""

import json
from typing import Any

import boto3
from botocore.exceptions import ClientError, NoCredentialsError

from ..core.logger import get_logger, log_api_call
from ..core.models import EnumerationResult, Principal

logger = get_logger("aws.enumeration")

# Permissions that indicate admin access
ADMIN_ACTIONS = {
    "*",
    "iam:*",
    "iam:CreateUser",
    "iam:CreateRole",
    "iam:AttachUserPolicy",
    "iam:AttachRolePolicy",
    "iam:PutUserPolicy",
    "iam:PutRolePolicy",
}

ADMIN_POLICIES = {
    "arn:aws:iam::aws:policy/AdministratorAccess",
    "arn:aws:iam::aws:policy/IAMFullAccess",
    "arn:aws:iam::aws:policy/PowerUserAccess",
}


def get_caller_identity() -> dict[str, Any] | None:
    """Get the current AWS caller identity.

    Returns:
        Caller identity dict or None if not authenticated
    """
    try:
        sts = boto3.client("sts")
        log_api_call(logger, "sts", "GetCallerIdentity")
        identity = sts.get_caller_identity()
        logger.info(f"Authenticated as: {identity['Arn']}")
        return identity
    except NoCredentialsError:
        logger.error("No AWS credentials found")
        return None
    except ClientError as e:
        logger.error(f"Failed to get caller identity: {e}")
        return None


def check_admin() -> bool:
    """Check if current identity has admin privileges.

    Returns:
        True if current identity appears to have admin access
    """
    try:
        iam = boto3.client("iam")
        # Try to list users - requires admin-level access
        log_api_call(logger, "iam", "ListUsers")
        iam.list_users(MaxItems=1)

        # Try to simulate admin action
        log_api_call(logger, "iam", "SimulatePrincipalPolicy")
        sts = boto3.client("sts")
        identity = sts.get_caller_identity()

        response = iam.simulate_principal_policy(
            PolicySourceArn=identity["Arn"],
            ActionNames=["iam:CreateUser", "iam:CreateRole", "ec2:*"],
        )

        for result in response.get("EvaluationResults", []):
            if result.get("EvalDecision") != "allowed":
                return False

        return True
    except ClientError:
        return False


def enumerate_iam(target: str = "all") -> EnumerationResult:
    """Enumerate IAM resources.

    Args:
        target: What to enumerate - 'all', 'users', 'roles', 'policies'

    Returns:
        EnumerationResult with discovered resources
    """
    identity = get_caller_identity()
    if not identity:
        return EnumerationResult(
            account_id="unknown",
            identity_arn="unknown",
        )

    result = EnumerationResult(
        account_id=identity["Account"],
        identity_arn=identity["Arn"],
    )

    iam = boto3.client("iam")

    if target in ("all", "users"):
        result.users = _enumerate_users(iam)

    if target in ("all", "roles"):
        result.roles = _enumerate_roles(iam)

    if target in ("all", "policies"):
        result.policies = _enumerate_policies(iam)

    if target in ("all", "groups"):
        result.groups = _enumerate_groups(iam)

    # Identify admin principals
    result.admin_principals = _identify_admins(result)

    logger.info(
        f"Enumeration complete: {len(result.users)} users, "
        f"{len(result.roles)} roles, {len(result.admin_principals)} admins"
    )

    return result


def _enumerate_users(iam) -> list[Principal]:
    """Enumerate IAM users with their policies."""
    users = []

    try:
        log_api_call(logger, "iam", "ListUsers")
        paginator = iam.get_paginator("list_users")

        for page in paginator.paginate():
            for user_data in page["Users"]:
                user = _build_user_principal(iam, user_data)
                users.append(user)
                logger.debug(f"Enumerated user: {user.name}")

    except ClientError as e:
        logger.warning(f"Failed to list users: {e}")
        # Try to get just our own user info
        try:
            log_api_call(logger, "iam", "GetUser")
            user_data = iam.get_user()["User"]
            user = _build_user_principal(iam, user_data)
            users.append(user)
        except ClientError:
            pass

    return users


def _build_user_principal(iam, user_data: dict) -> Principal:
    """Build a Principal object for a user."""
    user_name = user_data["UserName"]
    arn = user_data["Arn"]

    # Get attached policies
    attached = []
    try:
        log_api_call(logger, "iam", "ListAttachedUserPolicies", user=user_name)
        response = iam.list_attached_user_policies(UserName=user_name)
        attached = response.get("AttachedPolicies", [])
    except ClientError:
        pass

    # Get inline policies
    inline = {}
    try:
        log_api_call(logger, "iam", "ListUserPolicies", user=user_name)
        response = iam.list_user_policies(UserName=user_name)
        for policy_name in response.get("PolicyNames", []):
            try:
                log_api_call(logger, "iam", "GetUserPolicy", user=user_name, policy=policy_name)
                policy = iam.get_user_policy(UserName=user_name, PolicyName=policy_name)
                inline[policy_name] = policy.get("PolicyDocument", {})
            except ClientError:
                pass
    except ClientError:
        pass

    # Get group memberships and their policies
    group_policies = []
    try:
        log_api_call(logger, "iam", "ListGroupsForUser", user=user_name)
        groups = iam.list_groups_for_user(UserName=user_name).get("Groups", [])
        for group in groups:
            group_policies.extend(_get_group_policies(iam, group["GroupName"]))
    except ClientError:
        pass

    # Determine permissions
    permissions = _extract_permissions(attached, inline, group_policies)
    is_admin = _is_admin_principal(attached, inline, permissions)

    return Principal(
        arn=arn,
        name=user_name,
        principal_type="user",
        attached_policies=attached,
        inline_policies=inline,
        permissions=permissions,
        is_admin=is_admin,
    )


def _enumerate_roles(iam) -> list[Principal]:
    """Enumerate IAM roles with their policies."""
    roles = []

    try:
        log_api_call(logger, "iam", "ListRoles")
        paginator = iam.get_paginator("list_roles")

        for page in paginator.paginate():
            for role_data in page["Roles"]:
                # Skip service-linked roles
                if "/aws-service-role/" in role_data.get("Path", ""):
                    continue

                role = _build_role_principal(iam, role_data)
                roles.append(role)
                logger.debug(f"Enumerated role: {role.name}")

    except ClientError as e:
        logger.warning(f"Failed to list roles: {e}")

    return roles


def _build_role_principal(iam, role_data: dict) -> Principal:
    """Build a Principal object for a role."""
    role_name = role_data["RoleName"]
    arn = role_data["Arn"]
    trust_policy = role_data.get("AssumeRolePolicyDocument")

    # Get attached policies
    attached = []
    try:
        log_api_call(logger, "iam", "ListAttachedRolePolicies", role=role_name)
        response = iam.list_attached_role_policies(RoleName=role_name)
        attached = response.get("AttachedPolicies", [])
    except ClientError:
        pass

    # Get inline policies
    inline = {}
    try:
        log_api_call(logger, "iam", "ListRolePolicies", role=role_name)
        response = iam.list_role_policies(RoleName=role_name)
        for policy_name in response.get("PolicyNames", []):
            try:
                log_api_call(logger, "iam", "GetRolePolicy", role=role_name, policy=policy_name)
                policy = iam.get_role_policy(RoleName=role_name, PolicyName=policy_name)
                inline[policy_name] = policy.get("PolicyDocument", {})
            except ClientError:
                pass
    except ClientError:
        pass

    permissions = _extract_permissions(attached, inline, [])
    is_admin = _is_admin_principal(attached, inline, permissions)

    return Principal(
        arn=arn,
        name=role_name,
        principal_type="role",
        attached_policies=attached,
        inline_policies=inline,
        permissions=permissions,
        is_admin=is_admin,
        trust_policy=trust_policy,
    )


def _enumerate_policies(iam) -> list[dict[str, Any]]:
    """Enumerate customer managed policies."""
    policies = []

    try:
        log_api_call(logger, "iam", "ListPolicies")
        paginator = iam.get_paginator("list_policies")

        for page in paginator.paginate(Scope="Local"):
            for policy in page["Policies"]:
                # Get policy document
                try:
                    log_api_call(logger, "iam", "GetPolicyVersion", policy=policy["PolicyName"])
                    version = iam.get_policy_version(
                        PolicyArn=policy["Arn"],
                        VersionId=policy["DefaultVersionId"],
                    )
                    policy["Document"] = version["PolicyVersion"]["Document"]
                except ClientError:
                    pass
                policies.append(policy)

    except ClientError as e:
        logger.warning(f"Failed to list policies: {e}")

    return policies


def _enumerate_groups(iam) -> list[dict[str, Any]]:
    """Enumerate IAM groups."""
    groups = []

    try:
        log_api_call(logger, "iam", "ListGroups")
        paginator = iam.get_paginator("list_groups")

        for page in paginator.paginate():
            for group in page["Groups"]:
                group["Policies"] = _get_group_policies(iam, group["GroupName"])
                groups.append(group)

    except ClientError as e:
        logger.warning(f"Failed to list groups: {e}")

    return groups


def _get_group_policies(iam, group_name: str) -> list[dict]:
    """Get policies attached to a group."""
    policies = []

    try:
        log_api_call(logger, "iam", "ListAttachedGroupPolicies", group=group_name)
        response = iam.list_attached_group_policies(GroupName=group_name)
        policies.extend(response.get("AttachedPolicies", []))
    except ClientError:
        pass

    try:
        log_api_call(logger, "iam", "ListGroupPolicies", group=group_name)
        response = iam.list_group_policies(GroupName=group_name)
        for policy_name in response.get("PolicyNames", []):
            policies.append({"PolicyName": policy_name, "Type": "inline"})
    except ClientError:
        pass

    return policies


def _extract_permissions(
    attached: list[dict],
    inline: dict[str, Any],
    group_policies: list[dict],
) -> set[str]:
    """Extract permissions from policies."""
    permissions = set()

    # From attached policies (we'd need to fetch the policy documents)
    for policy in attached:
        policy_arn = policy.get("PolicyArn", "")
        if policy_arn in ADMIN_POLICIES:
            permissions.add("*")

    # From inline policies
    for policy_doc in inline.values():
        if isinstance(policy_doc, str):
            policy_doc = json.loads(policy_doc)

        for statement in policy_doc.get("Statement", []):
            if statement.get("Effect") == "Allow":
                actions = statement.get("Action", [])
                if isinstance(actions, str):
                    actions = [actions]
                permissions.update(actions)

    return permissions


def _is_admin_principal(
    attached: list[dict],
    inline: dict[str, Any],
    permissions: set[str],
) -> bool:
    """Check if a principal has admin privileges."""
    # Check attached policies
    for policy in attached:
        if policy.get("PolicyArn") in ADMIN_POLICIES:
            return True

    # Check permissions
    if "*" in permissions:
        return True

    for perm in permissions:
        if perm in ADMIN_ACTIONS:
            return True

    return False


def _identify_admins(result: EnumerationResult) -> list[str]:
    """Identify admin principals from enumeration results."""
    admins = []

    for user in result.users:
        if user.is_admin:
            admins.append(user.arn)

    for role in result.roles:
        if role.is_admin:
            admins.append(role.arn)

    return admins
