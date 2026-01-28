"""Skill manager for downloading and executing skills."""

import json
import subprocess
import tempfile
from pathlib import Path
from typing import Any

import httpx

from ..core.logger import get_logger

logger = get_logger("skills.manager")

# Built-in skill repository
SKILL_REPO = {
    "enumerate-permissions": {
        "description": "Enumerate effective permissions for current identity",
        "url": "https://raw.githubusercontent.com/andresriancho/enumerate-iam/master/enumerate_iam.py",
        "type": "python",
    },
    "check-metadata-access": {
        "description": "Check if EC2 metadata service is accessible",
        "code": '''
import urllib.request
import json

def check_metadata():
    """Check EC2 instance metadata access."""
    endpoints = [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://169.254.169.254/latest/dynamic/instance-identity/document",
    ]

    results = {}
    for endpoint in endpoints:
        try:
            req = urllib.request.Request(endpoint, headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"})
            # Try IMDSv1 first
            response = urllib.request.urlopen(endpoint, timeout=2)
            results[endpoint] = {
                "accessible": True,
                "data": response.read().decode()[:500]
            }
        except Exception as e:
            results[endpoint] = {
                "accessible": False,
                "error": str(e)
            }

    return results

if __name__ == "__main__":
    print(json.dumps(check_metadata(), indent=2))
''',
        "type": "python",
    },
    "find-lambda-functions": {
        "description": "Find Lambda functions and their roles",
        "code": '''
import boto3
import json

def find_lambdas():
    """Find Lambda functions and their execution roles."""
    client = boto3.client("lambda")
    functions = []

    paginator = client.get_paginator("list_functions")
    for page in paginator.paginate():
        for func in page["Functions"]:
            functions.append({
                "name": func["FunctionName"],
                "role": func["Role"],
                "runtime": func.get("Runtime"),
                "last_modified": func.get("LastModified"),
            })

    return functions

if __name__ == "__main__":
    print(json.dumps(find_lambdas(), indent=2, default=str))
''',
        "type": "python",
    },
    "find-ec2-profiles": {
        "description": "Find EC2 instances and their instance profiles",
        "code": '''
import boto3
import json

def find_ec2_profiles():
    """Find EC2 instances with IAM roles."""
    ec2 = boto3.client("ec2")
    instances = []

    paginator = ec2.get_paginator("describe_instances")
    for page in paginator.paginate():
        for reservation in page["Reservations"]:
            for instance in reservation["Instances"]:
                profile = instance.get("IamInstanceProfile", {})
                instances.append({
                    "instance_id": instance["InstanceId"],
                    "state": instance["State"]["Name"],
                    "profile_arn": profile.get("Arn"),
                    "public_ip": instance.get("PublicIpAddress"),
                    "private_ip": instance.get("PrivateIpAddress"),
                })

    return instances

if __name__ == "__main__":
    print(json.dumps(find_ec2_profiles(), indent=2))
''',
        "type": "python",
    },
    "check-sts-credentials": {
        "description": "Verify current STS credentials and get identity info",
        "code": '''
import boto3
import json

def check_sts():
    """Check STS credentials and identity."""
    sts = boto3.client("sts")

    try:
        identity = sts.get_caller_identity()
        return {
            "valid": True,
            "account": identity["Account"],
            "arn": identity["Arn"],
            "user_id": identity["UserId"],
        }
    except Exception as e:
        return {
            "valid": False,
            "error": str(e),
        }

if __name__ == "__main__":
    print(json.dumps(check_sts(), indent=2))
''',
        "type": "python",
    },
    "find-assumable-roles": {
        "description": "Find roles that can be assumed by current identity",
        "code": '''
import boto3
import json

def find_assumable_roles():
    """Find roles assumable by current identity."""
    iam = boto3.client("iam")
    sts = boto3.client("sts")

    identity = sts.get_caller_identity()
    current_arn = identity["Arn"]
    account_id = identity["Account"]

    assumable = []

    paginator = iam.get_paginator("list_roles")
    for page in paginator.paginate():
        for role in page["Roles"]:
            trust_policy = role.get("AssumeRolePolicyDocument", {})

            for statement in trust_policy.get("Statement", []):
                if statement.get("Effect") != "Allow":
                    continue

                principal = statement.get("Principal", {})
                aws_principals = principal.get("AWS", [])

                if isinstance(aws_principals, str):
                    aws_principals = [aws_principals]

                for p in aws_principals:
                    if p == "*" or p == current_arn or f"{account_id}:root" in p:
                        assumable.append({
                            "role_name": role["RoleName"],
                            "role_arn": role["Arn"],
                            "trust_principal": p,
                        })
                        break

    return assumable

if __name__ == "__main__":
    print(json.dumps(find_assumable_roles(), indent=2))
''',
        "type": "python",
    },
}


class SkillManager:
    """Manager for downloading and executing skills."""

    def __init__(self, cache_dir: Path | None = None):
        """Initialize skill manager.

        Args:
            cache_dir: Directory to cache downloaded skills
        """
        self.cache_dir = cache_dir or Path(tempfile.gettempdir()) / "aws_privesc_skills"
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def list_skills(self) -> list[dict[str, str]]:
        """List available skills.

        Returns:
            List of skill info dicts
        """
        skills = []
        for name, info in SKILL_REPO.items():
            skills.append({
                "name": name,
                "description": info["description"],
                "type": info["type"],
            })
        return skills

    def get_skill(self, skill_name: str) -> dict[str, Any] | None:
        """Get a skill by name.

        Args:
            skill_name: Name of the skill

        Returns:
            Skill info dict or None if not found
        """
        return SKILL_REPO.get(skill_name)

    def download_skill(self, skill_name: str) -> Path | None:
        """Download a skill to cache.

        Args:
            skill_name: Name of the skill

        Returns:
            Path to downloaded skill or None if failed
        """
        skill = self.get_skill(skill_name)
        if not skill:
            logger.error(f"Unknown skill: {skill_name}")
            return None

        skill_path = self.cache_dir / f"{skill_name}.py"

        # If skill has embedded code, write it
        if "code" in skill:
            skill_path.write_text(skill["code"])
            return skill_path

        # If skill has URL, download it
        if "url" in skill:
            try:
                response = httpx.get(skill["url"], timeout=30)
                response.raise_for_status()
                skill_path.write_text(response.text)
                return skill_path
            except Exception as e:
                logger.error(f"Failed to download skill: {e}")
                return None

        return None

    def execute_skill(
        self, skill_name: str, timeout: int = 60
    ) -> dict[str, Any]:
        """Execute a skill.

        Args:
            skill_name: Name of the skill
            timeout: Execution timeout in seconds

        Returns:
            Result dict with output and status
        """
        skill_path = self.download_skill(skill_name)
        if not skill_path:
            return {"success": False, "error": f"Failed to get skill: {skill_name}"}

        logger.info(f"Executing skill: {skill_name}")

        try:
            result = subprocess.run(
                ["python", str(skill_path)],
                capture_output=True,
                text=True,
                timeout=timeout,
            )

            output = result.stdout
            # Try to parse as JSON
            try:
                output = json.loads(output)
            except json.JSONDecodeError:
                pass

            return {
                "success": result.returncode == 0,
                "exit_code": result.returncode,
                "output": output,
                "stderr": result.stderr,
            }
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "Skill execution timed out"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def execute_custom_code(
        self, code: str, timeout: int = 60
    ) -> dict[str, Any]:
        """Execute custom Python code.

        Args:
            code: Python code to execute
            timeout: Execution timeout in seconds

        Returns:
            Result dict with output and status
        """
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False
        ) as f:
            f.write(code)
            f.flush()

            try:
                result = subprocess.run(
                    ["python", f.name],
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                )

                output = result.stdout
                try:
                    output = json.loads(output)
                except json.JSONDecodeError:
                    pass

                return {
                    "success": result.returncode == 0,
                    "exit_code": result.returncode,
                    "output": output,
                    "stderr": result.stderr,
                }
            except subprocess.TimeoutExpired:
                return {"success": False, "error": "Code execution timed out"}
            except Exception as e:
                return {"success": False, "error": str(e)}
