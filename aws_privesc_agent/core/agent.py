"""Main AI agent for privilege escalation path discovery."""

import json
import subprocess
import tempfile
from pathlib import Path
from typing import Any

import anthropic

from .logger import get_logger, log_finding
from .models import AgentAction, AgentState, PrivescPath, Severity

logger = get_logger("agent")

SYSTEM_PROMPT = """You are an expert AWS security researcher specializing in IAM privilege escalation.
Your goal is to find a path from the current non-admin identity to admin privileges within the AWS account.

You have access to the following capabilities:
1. ENUMERATE - Gather information about IAM users, roles, policies, and permissions
2. ANALYZE - Analyze gathered data to identify potential privilege escalation paths
3. EXPLOIT - Execute a privilege escalation technique (in sandbox only)
4. RESEARCH - Search for known privilege escalation techniques
5. CODE - Write and execute Python code for custom analysis
6. TOOL - Run external security tools (pacu, enumerate-iam, etc)

Known privilege escalation vectors to look for:
- iam:CreatePolicyVersion - Create new policy version with admin perms
- iam:SetDefaultPolicyVersion - Switch to more permissive policy version
- iam:PassRole + ec2:RunInstances - Launch EC2 with privileged role
- iam:PassRole + lambda:CreateFunction + lambda:InvokeFunction - Create lambda with privileged role
- iam:CreateAccessKey - Create access keys for other users
- iam:AttachUserPolicy/AttachRolePolicy/AttachGroupPolicy - Attach admin policy
- iam:PutUserPolicy/PutRolePolicy/PutGroupPolicy - Add inline admin policy
- sts:AssumeRole - Assume a more privileged role
- iam:UpdateAssumeRolePolicy - Modify trust policy to allow assumption
- iam:CreateLoginProfile/UpdateLoginProfile - Create/change console passwords
- lambda:UpdateFunctionCode - Inject code into existing lambda with privs
- glue:CreateDevEndpoint + iam:PassRole - Create Glue endpoint with role
- cloudformation:CreateStack + iam:PassRole - Deploy stack with privileged role
- datapipeline:CreatePipeline + iam:PassRole - Create pipeline with role
- ssm:SendCommand - Execute commands on EC2 instances
- ec2:CreateKeyPair + ec2:RunInstances - Access to EC2 instances
- sagemaker:CreateNotebookInstance + iam:PassRole - Notebook with role

When analyzing, consider:
- Direct paths (single action to admin)
- Chained paths (multiple steps to admin)
- Cross-account trust relationships
- Service-linked roles
- Resource-based policies

Respond with JSON specifying your next action:
{
    "action_type": "enumerate|analyze|exploit|research|code|tool",
    "description": "What you're doing",
    "parameters": {...},
    "reasoning": "Why this action"
}
"""


class PrivescAgent:
    """AI agent for discovering AWS privilege escalation paths."""

    def __init__(
        self,
        model: str = "claude-sonnet-4-20250514",
        max_iterations: int = 10,
        sandbox: bool = True,
        dry_run: bool = False,
    ):
        """Initialize the agent.

        Args:
            model: Anthropic model to use
            max_iterations: Maximum agent iterations
            sandbox: Whether running in sandbox container
            dry_run: Don't execute exploits, just plan
        """
        self.client = anthropic.Anthropic()
        self.model = model
        self.sandbox = sandbox
        self.dry_run = dry_run
        self.state = AgentState(max_iterations=max_iterations)
        self.conversation: list[dict[str, str]] = []
        self.tools_dir = Path(__file__).parent.parent / "tools"

    def run(self) -> list[PrivescPath]:
        """Run the agent to find privilege escalation paths.

        Returns:
            List of discovered privilege escalation paths
        """
        logger.info("Starting privilege escalation path discovery")

        # Initial enumeration
        self._initialize()

        while (
            self.state.iteration < self.state.max_iterations
            and not self.state.achieved_admin
        ):
            self.state.iteration += 1
            logger.info(f"Iteration {self.state.iteration}/{self.state.max_iterations}")

            try:
                action = self._get_next_action()
                if action is None:
                    logger.warning("Agent returned no action, stopping")
                    break

                result = self._execute_action(action)
                self._update_conversation(action, result)

                if self.state.achieved_admin:
                    logger.info("Admin access achieved!")
                    break

            except Exception as e:
                logger.error(f"Error in iteration: {e}")
                if logger.isEnabledFor(10):  # DEBUG
                    import traceback
                    logger.debug(traceback.format_exc())
                break

        return self.state.discovered_paths

    def _initialize(self) -> None:
        """Initialize agent with current AWS identity info."""
        from ..aws.enumeration import get_caller_identity

        identity = get_caller_identity()
        if identity:
            self.state.current_identity = identity.get("Arn")
            self.state.account_id = identity.get("Account")
            logger.info(f"Current identity: {self.state.current_identity}")
        else:
            logger.warning("Could not determine current AWS identity")

    def _get_next_action(self) -> AgentAction | None:
        """Get the next action from the AI model."""
        messages = self._build_messages()

        logger.debug(f"Requesting next action from {self.model}")

        response = self.client.messages.create(
            model=self.model,
            max_tokens=4096,
            system=SYSTEM_PROMPT,
            messages=messages,
        )

        content = response.content[0].text
        logger.debug(f"Agent response: {content[:500]}...")

        try:
            # Extract JSON from response
            action_data = self._parse_action(content)
            return AgentAction(**action_data)
        except Exception as e:
            logger.error(f"Failed to parse agent action: {e}")
            return None

    def _build_messages(self) -> list[dict[str, str]]:
        """Build message history for the model."""
        messages = []

        # Add initial context
        context = self._get_context()
        messages.append({"role": "user", "content": context})

        # Add conversation history
        messages.extend(self.conversation)

        return messages

    def _get_context(self) -> str:
        """Get current context for the agent."""
        context_parts = [
            "Current AWS Security Assessment Context:",
            f"- Identity: {self.state.current_identity or 'Unknown'}",
            f"- Account: {self.state.account_id or 'Unknown'}",
            f"- Iteration: {self.state.iteration}/{self.state.max_iterations}",
            f"- Sandbox mode: {self.sandbox}",
            f"- Dry run: {self.dry_run}",
            f"- Discovered paths: {len(self.state.discovered_paths)}",
            f"- Admin achieved: {self.state.achieved_admin}",
        ]

        if self.state.enumeration:
            context_parts.extend([
                f"- Enumerated users: {len(self.state.enumeration.users)}",
                f"- Enumerated roles: {len(self.state.enumeration.roles)}",
                f"- Admin principals: {self.state.enumeration.admin_principals}",
            ])

        if self.state.current_permissions:
            perms = list(self.state.current_permissions)[:20]
            context_parts.append(f"- Current permissions (sample): {perms}")

        context_parts.append("\nWhat is your next action to achieve admin access?")

        return "\n".join(context_parts)

    def _parse_action(self, content: str) -> dict[str, Any]:
        """Parse action JSON from model response."""
        # Try to find JSON in the response
        import re

        # Look for JSON block
        json_match = re.search(r"\{[^{}]*\}", content, re.DOTALL)
        if json_match:
            return json.loads(json_match.group())

        # Try parsing the whole content
        return json.loads(content)

    def _execute_action(self, action: AgentAction) -> dict[str, Any]:
        """Execute an agent action.

        Args:
            action: The action to execute

        Returns:
            Result of the action
        """
        logger.info(f"Executing: {action.action_type} - {action.description}")

        handlers = {
            "enumerate": self._handle_enumerate,
            "analyze": self._handle_analyze,
            "exploit": self._handle_exploit,
            "research": self._handle_research,
            "code": self._handle_code,
            "tool": self._handle_tool,
        }

        handler = handlers.get(action.action_type)
        if handler:
            return handler(action)
        else:
            logger.warning(f"Unknown action type: {action.action_type}")
            return {"error": f"Unknown action type: {action.action_type}"}

    def _handle_enumerate(self, action: AgentAction) -> dict[str, Any]:
        """Handle enumeration actions."""
        from ..aws.enumeration import enumerate_iam

        target = action.parameters.get("target", "all")
        logger.debug(f"Enumerating: {target}")

        result = enumerate_iam(target)
        self.state.enumeration = result
        return result.model_dump()

    def _handle_analyze(self, action: AgentAction) -> dict[str, Any]:
        """Handle analysis actions."""
        from ..paths.analyzer import analyze_paths

        if not self.state.enumeration:
            return {"error": "No enumeration data available. Run enumerate first."}

        paths = analyze_paths(self.state.enumeration)
        self.state.discovered_paths.extend(paths)

        for path in paths:
            log_finding(
                logger,
                path.severity.value.upper(),
                f"Found privesc path: {path.name}",
                path.description,
            )

        return {
            "paths_found": len(paths),
            "paths": [p.model_dump() for p in paths],
        }

    def _handle_exploit(self, action: AgentAction) -> dict[str, Any]:
        """Handle exploit execution."""
        if self.dry_run:
            logger.info("Dry run mode - not executing exploit")
            return {"status": "skipped", "reason": "dry_run"}

        if not self.sandbox:
            logger.warning("Not in sandbox - refusing to execute exploit")
            return {"status": "blocked", "reason": "not_in_sandbox"}

        path_id = action.parameters.get("path_id")
        if not path_id:
            return {"error": "No path_id specified"}

        path = next(
            (p for p in self.state.discovered_paths if p.id == path_id), None
        )
        if not path:
            return {"error": f"Path not found: {path_id}"}

        from ..paths.exploiter import execute_exploit

        result = execute_exploit(path)
        if result.get("success"):
            self.state.exploited_paths.append(path_id)
            # Check if we achieved admin
            from ..aws.enumeration import check_admin

            if check_admin():
                self.state.achieved_admin = True
                logger.info("Successfully escalated to admin!")

        return result

    def _handle_research(self, action: AgentAction) -> dict[str, Any]:
        """Handle research actions - fetch known techniques."""
        from ..paths.knowledge import get_known_techniques

        query = action.parameters.get("query", "")
        techniques = get_known_techniques(query)
        return {"techniques": techniques}

    def _handle_code(self, action: AgentAction) -> dict[str, Any]:
        """Handle custom code execution."""
        code = action.parameters.get("code", "")
        if not code:
            return {"error": "No code provided"}

        if not self.sandbox:
            logger.warning("Not in sandbox - refusing to execute custom code")
            return {"status": "blocked", "reason": "not_in_sandbox"}

        # Write and execute code in sandbox
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
                    timeout=60,
                    cwd=str(self.tools_dir),
                )
                return {
                    "exit_code": result.returncode,
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                }
            except subprocess.TimeoutExpired:
                return {"error": "Code execution timed out"}
            except Exception as e:
                return {"error": str(e)}

    def _handle_tool(self, action: AgentAction) -> dict[str, Any]:
        """Handle external tool execution."""
        tool = action.parameters.get("tool", "")
        args = action.parameters.get("args", [])

        if not tool:
            return {"error": "No tool specified"}

        if not self.sandbox:
            logger.warning("Not in sandbox - refusing to run external tool")
            return {"status": "blocked", "reason": "not_in_sandbox"}

        # Allowed tools
        allowed_tools = ["pacu", "enumerate-iam", "pmapper", "cloudsplaining"]
        if tool not in allowed_tools:
            return {"error": f"Tool not allowed: {tool}. Allowed: {allowed_tools}"}

        try:
            result = subprocess.run(
                [tool, *args],
                capture_output=True,
                text=True,
                timeout=300,
            )
            return {
                "exit_code": result.returncode,
                "stdout": result.stdout[:10000],  # Limit output
                "stderr": result.stderr[:2000],
            }
        except FileNotFoundError:
            return {"error": f"Tool not found: {tool}. May need to install."}
        except subprocess.TimeoutExpired:
            return {"error": "Tool execution timed out"}
        except Exception as e:
            return {"error": str(e)}

    def _update_conversation(
        self, action: AgentAction, result: dict[str, Any]
    ) -> None:
        """Update conversation history with action and result."""
        self.conversation.append({
            "role": "assistant",
            "content": json.dumps({
                "action": action.model_dump(),
            }),
        })
        self.conversation.append({
            "role": "user",
            "content": f"Action result:\n{json.dumps(result, indent=2, default=str)}",
        })
