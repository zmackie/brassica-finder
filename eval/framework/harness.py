"""Infrastructure harness for eval suite.

Manages Terraform infrastructure lifecycle for running evaluations.
"""

import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from aws_privesc_agent.core.logger import get_logger

logger = get_logger("eval.harness")


@dataclass
class InfraState:
    """State of the evaluation infrastructure."""

    initialized: bool = False
    deployed: bool = False
    scenarios_enabled: list[str] | None = None
    account_id: str | None = None
    region: str | None = None
    error: str | None = None


class EvalHarness:
    """Manages eval infrastructure lifecycle."""

    def __init__(
        self,
        terraform_dir: Path | None = None,
        state_dir: Path | None = None,
        auto_approve: bool = False,
    ):
        """Initialize the harness.

        Args:
            terraform_dir: Path to Terraform configuration
            state_dir: Path for Terraform state
            auto_approve: Auto-approve Terraform changes
        """
        self.terraform_dir = terraform_dir or Path("eval/terraform/environments/dev")
        self.state_dir = state_dir or self.terraform_dir
        self.auto_approve = auto_approve
        self.state = InfraState()

        # Check for terraform
        if not shutil.which("terraform"):
            raise RuntimeError("Terraform not found in PATH")

    def init(self) -> bool:
        """Initialize Terraform.

        Returns:
            True if successful
        """
        logger.info("Initializing Terraform...")

        try:
            result = subprocess.run(
                ["terraform", "init"],
                cwd=self.terraform_dir,
                capture_output=True,
                text=True,
                check=True,
            )
            logger.debug(result.stdout)
            self.state.initialized = True
            return True

        except subprocess.CalledProcessError as e:
            logger.error(f"Terraform init failed: {e.stderr}")
            self.state.error = e.stderr
            return False

    def plan(self, scenarios: list[str] | None = None) -> dict[str, Any] | None:
        """Create Terraform plan.

        Args:
            scenarios: List of scenarios to enable

        Returns:
            Plan summary or None if failed
        """
        if not self.state.initialized:
            if not self.init():
                return None

        logger.info("Creating Terraform plan...")

        cmd = ["terraform", "plan", "-out=tfplan", "-json"]

        if scenarios:
            scenarios_var = json.dumps(scenarios)
            cmd.extend(["-var", f'enabled_scenarios={scenarios_var}'])

        try:
            result = subprocess.run(
                cmd,
                cwd=self.terraform_dir,
                capture_output=True,
                text=True,
            )

            # Parse JSON output lines
            changes = {"add": 0, "change": 0, "destroy": 0}
            for line in result.stdout.split("\n"):
                if not line.strip():
                    continue
                try:
                    data = json.loads(line)
                    if data.get("type") == "change_summary":
                        changes = data.get("changes", changes)
                except json.JSONDecodeError:
                    continue

            return changes

        except subprocess.CalledProcessError as e:
            logger.error(f"Terraform plan failed: {e.stderr}")
            self.state.error = e.stderr
            return None

    def deploy(self, scenarios: list[str] | None = None) -> bool:
        """Deploy the eval infrastructure.

        Args:
            scenarios: List of scenarios to enable

        Returns:
            True if successful
        """
        if not self.state.initialized:
            if not self.init():
                return False

        logger.info("Deploying eval infrastructure...")

        cmd = ["terraform", "apply"]
        if self.auto_approve:
            cmd.append("-auto-approve")

        if scenarios:
            scenarios_var = json.dumps(scenarios)
            cmd.extend(["-var", f'enabled_scenarios={scenarios_var}'])

        try:
            result = subprocess.run(
                cmd,
                cwd=self.terraform_dir,
                capture_output=True,
                text=True,
                check=True,
            )
            logger.debug(result.stdout)

            self.state.deployed = True
            self.state.scenarios_enabled = scenarios

            # Get outputs
            outputs = self.get_outputs()
            if outputs:
                self.state.account_id = outputs.get("account_id")
                self.state.region = outputs.get("region")

            return True

        except subprocess.CalledProcessError as e:
            logger.error(f"Terraform apply failed: {e.stderr}")
            self.state.error = e.stderr
            return False

    def destroy(self) -> bool:
        """Destroy the eval infrastructure.

        Returns:
            True if successful
        """
        logger.info("Destroying eval infrastructure...")

        cmd = ["terraform", "destroy"]
        if self.auto_approve:
            cmd.append("-auto-approve")

        try:
            result = subprocess.run(
                cmd,
                cwd=self.terraform_dir,
                capture_output=True,
                text=True,
                check=True,
            )
            logger.debug(result.stdout)

            self.state.deployed = False
            return True

        except subprocess.CalledProcessError as e:
            logger.error(f"Terraform destroy failed: {e.stderr}")
            self.state.error = e.stderr
            return False

    def get_outputs(self) -> dict[str, Any] | None:
        """Get Terraform outputs.

        Returns:
            Outputs dict or None if failed
        """
        try:
            result = subprocess.run(
                ["terraform", "output", "-json"],
                cwd=self.terraform_dir,
                capture_output=True,
                text=True,
                check=True,
            )

            outputs = json.loads(result.stdout)

            # Unwrap the values
            return {k: v.get("value") for k, v in outputs.items()}

        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to get outputs: {e.stderr}")
            return None
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse outputs: {e}")
            return None

    def get_scenario_credentials(self, scenario_id: str) -> dict[str, str] | None:
        """Get AWS credentials for a specific scenario.

        Args:
            scenario_id: The scenario identifier

        Returns:
            Credentials dict with access_key_id and secret_access_key
        """
        outputs = self.get_outputs()
        if not outputs:
            return None

        scenarios = outputs.get("scenarios", {})
        scenario = scenarios.get(scenario_id)

        if not scenario:
            logger.error(f"Scenario not found: {scenario_id}")
            return None

        attacker = scenario.get("attacker", {})
        return {
            "access_key_id": attacker.get("access_key_id"),
            "secret_access_key": attacker.get("secret_access_key"),
            "user_arn": attacker.get("user_arn"),
        }

    def export_credentials(self, scenario_id: str, env_file: Path | None = None) -> bool:
        """Export scenario credentials to environment or file.

        Args:
            scenario_id: The scenario identifier
            env_file: Optional file to write credentials to

        Returns:
            True if successful
        """
        creds = self.get_scenario_credentials(scenario_id)
        if not creds:
            return False

        if env_file:
            with open(env_file, "w") as f:
                f.write(f"export AWS_ACCESS_KEY_ID={creds['access_key_id']}\n")
                f.write(f"export AWS_SECRET_ACCESS_KEY={creds['secret_access_key']}\n")
                f.write("unset AWS_SESSION_TOKEN\n")
            logger.info(f"Credentials written to: {env_file}")
        else:
            os.environ["AWS_ACCESS_KEY_ID"] = creds["access_key_id"]
            os.environ["AWS_SECRET_ACCESS_KEY"] = creds["secret_access_key"]
            os.environ.pop("AWS_SESSION_TOKEN", None)
            logger.info(f"Credentials exported for: {scenario_id}")

        return True

    def validate(self) -> bool:
        """Validate Terraform configuration.

        Returns:
            True if valid
        """
        logger.info("Validating Terraform configuration...")

        try:
            result = subprocess.run(
                ["terraform", "validate", "-json"],
                cwd=self.terraform_dir,
                capture_output=True,
                text=True,
            )

            data = json.loads(result.stdout)
            valid = data.get("valid", False)

            if not valid:
                for diag in data.get("diagnostics", []):
                    severity = diag.get("severity", "error")
                    summary = diag.get("summary", "Unknown error")
                    detail = diag.get("detail", "")
                    logger.error(f"[{severity}] {summary}: {detail}")

            return valid

        except subprocess.CalledProcessError as e:
            logger.error(f"Terraform validate failed: {e.stderr}")
            return False
        except json.JSONDecodeError:
            return False


def main():
    """CLI for the eval harness."""
    import argparse

    parser = argparse.ArgumentParser(description="Manage eval infrastructure")
    parser.add_argument(
        "action",
        choices=["init", "plan", "deploy", "destroy", "outputs", "credentials"],
        help="Action to perform",
    )
    parser.add_argument(
        "--terraform-dir",
        type=Path,
        default=Path("eval/terraform/environments/dev"),
        help="Terraform directory",
    )
    parser.add_argument(
        "--scenarios",
        nargs="+",
        help="Scenarios to enable",
    )
    parser.add_argument(
        "--scenario-id",
        help="Scenario ID for credentials export",
    )
    parser.add_argument(
        "--auto-approve",
        action="store_true",
        help="Auto-approve Terraform changes",
    )
    parser.add_argument(
        "--env-file",
        type=Path,
        help="File to write credentials to",
    )

    args = parser.parse_args()

    harness = EvalHarness(
        terraform_dir=args.terraform_dir,
        auto_approve=args.auto_approve,
    )

    if args.action == "init":
        success = harness.init()
        sys.exit(0 if success else 1)

    elif args.action == "plan":
        plan = harness.plan(scenarios=args.scenarios)
        if plan:
            print(json.dumps(plan, indent=2))
            sys.exit(0)
        sys.exit(1)

    elif args.action == "deploy":
        success = harness.deploy(scenarios=args.scenarios)
        sys.exit(0 if success else 1)

    elif args.action == "destroy":
        success = harness.destroy()
        sys.exit(0 if success else 1)

    elif args.action == "outputs":
        outputs = harness.get_outputs()
        if outputs:
            print(json.dumps(outputs, indent=2, default=str))
            sys.exit(0)
        sys.exit(1)

    elif args.action == "credentials":
        if not args.scenario_id:
            print("Error: --scenario-id required for credentials action")
            sys.exit(1)
        success = harness.export_credentials(
            args.scenario_id,
            env_file=args.env_file,
        )
        sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
