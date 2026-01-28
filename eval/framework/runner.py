"""Eval runner for AWS privilege escalation agent.

Runs the agent against Terraform-provisioned scenarios and evaluates performance.
"""

import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

import boto3
from botocore.exceptions import ClientError

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from aws_privesc_agent.core.agent import PrivescAgent
from aws_privesc_agent.core.logger import get_logger, setup_logging
from aws_privesc_agent.core.models import Severity


logger = get_logger("eval.runner")


@dataclass
class ScenarioResult:
    """Result of running a single scenario."""

    scenario_id: str
    scenario_name: str
    difficulty: str
    success: bool
    admin_achieved: bool
    paths_found: int
    correct_path_found: bool
    iterations_used: int
    max_iterations: int
    time_seconds: float
    expected_technique: str
    found_technique: str | None = None
    error: str | None = None
    agent_actions: list[dict] = field(default_factory=list)


@dataclass
class EvalResult:
    """Complete eval run result."""

    run_id: str
    started_at: datetime
    completed_at: datetime | None = None
    total_scenarios: int = 0
    passed_scenarios: int = 0
    failed_scenarios: int = 0
    scenario_results: list[ScenarioResult] = field(default_factory=list)

    # Metrics by difficulty
    easy_passed: int = 0
    easy_total: int = 0
    medium_passed: int = 0
    medium_total: int = 0
    hard_passed: int = 0
    hard_total: int = 0

    @property
    def pass_rate(self) -> float:
        if self.total_scenarios == 0:
            return 0.0
        return self.passed_scenarios / self.total_scenarios

    @property
    def duration_seconds(self) -> float | None:
        if self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        return None

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "duration_seconds": self.duration_seconds,
            "total_scenarios": self.total_scenarios,
            "passed_scenarios": self.passed_scenarios,
            "failed_scenarios": self.failed_scenarios,
            "pass_rate": self.pass_rate,
            "by_difficulty": {
                "easy": {"passed": self.easy_passed, "total": self.easy_total},
                "medium": {"passed": self.medium_passed, "total": self.medium_total},
                "hard": {"passed": self.hard_passed, "total": self.hard_total},
            },
            "scenario_results": [
                {
                    "scenario_id": r.scenario_id,
                    "scenario_name": r.scenario_name,
                    "difficulty": r.difficulty,
                    "success": r.success,
                    "admin_achieved": r.admin_achieved,
                    "paths_found": r.paths_found,
                    "correct_path_found": r.correct_path_found,
                    "iterations_used": r.iterations_used,
                    "time_seconds": r.time_seconds,
                    "expected_technique": r.expected_technique,
                    "found_technique": r.found_technique,
                    "error": r.error,
                }
                for r in self.scenario_results
            ],
        }


class EvalRunner:
    """Runs evaluation scenarios against the privesc agent."""

    def __init__(
        self,
        scenarios_config: dict[str, Any],
        max_iterations: int = 15,
        model: str = "claude-sonnet-4-20250514",
        sandbox: bool = True,
        dry_run: bool = False,
        output_dir: Path | None = None,
    ):
        """Initialize the eval runner.

        Args:
            scenarios_config: Terraform output with scenario configs
            max_iterations: Max iterations per scenario
            model: AI model to use
            sandbox: Whether running in sandbox
            dry_run: Don't execute exploits
            output_dir: Directory for results output
        """
        self.scenarios = scenarios_config
        self.max_iterations = max_iterations
        self.model = model
        self.sandbox = sandbox
        self.dry_run = dry_run
        self.output_dir = output_dir or Path("eval/results")
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def run_all(
        self,
        scenario_filter: list[str] | None = None,
        difficulty_filter: list[str] | None = None,
    ) -> EvalResult:
        """Run all scenarios and return results.

        Args:
            scenario_filter: Only run these scenario IDs
            difficulty_filter: Only run scenarios with these difficulties

        Returns:
            Complete eval result
        """
        run_id = f"eval-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        result = EvalResult(
            run_id=run_id,
            started_at=datetime.now(),
        )

        # Filter scenarios
        scenarios_to_run = {}
        for scenario_id, config in self.scenarios.items():
            if config is None:
                continue

            if scenario_filter and scenario_id not in scenario_filter:
                continue

            difficulty = config.get("difficulty", "unknown")
            if difficulty_filter and difficulty not in difficulty_filter:
                continue

            scenarios_to_run[scenario_id] = config

        result.total_scenarios = len(scenarios_to_run)
        logger.info(f"Running {result.total_scenarios} scenarios")

        for scenario_id, config in scenarios_to_run.items():
            logger.info(f"\n{'='*60}")
            logger.info(f"Running scenario: {scenario_id}")
            logger.info(f"{'='*60}")

            try:
                scenario_result = self._run_scenario(scenario_id, config)
                result.scenario_results.append(scenario_result)

                # Update counters
                difficulty = config.get("difficulty", "unknown")
                if difficulty == "easy":
                    result.easy_total += 1
                    if scenario_result.success:
                        result.easy_passed += 1
                elif difficulty == "medium":
                    result.medium_total += 1
                    if scenario_result.success:
                        result.medium_passed += 1
                elif difficulty == "hard":
                    result.hard_total += 1
                    if scenario_result.success:
                        result.hard_passed += 1

                if scenario_result.success:
                    result.passed_scenarios += 1
                    logger.info(f"✓ Scenario {scenario_id}: PASSED")
                else:
                    result.failed_scenarios += 1
                    logger.info(f"✗ Scenario {scenario_id}: FAILED")

            except Exception as e:
                logger.error(f"Error running scenario {scenario_id}: {e}")
                result.failed_scenarios += 1
                result.scenario_results.append(
                    ScenarioResult(
                        scenario_id=scenario_id,
                        scenario_name=config.get("name", scenario_id),
                        difficulty=config.get("difficulty", "unknown"),
                        success=False,
                        admin_achieved=False,
                        paths_found=0,
                        correct_path_found=False,
                        iterations_used=0,
                        max_iterations=self.max_iterations,
                        time_seconds=0,
                        expected_technique=config.get("expected_path", {}).get("technique", "unknown"),
                        error=str(e),
                    )
                )

        result.completed_at = datetime.now()

        # Save results
        self._save_results(result)

        return result

    def _run_scenario(self, scenario_id: str, config: dict[str, Any]) -> ScenarioResult:
        """Run a single scenario.

        Args:
            scenario_id: Scenario identifier
            config: Scenario configuration from Terraform

        Returns:
            Scenario result
        """
        start_time = time.time()

        # Set up AWS credentials for this scenario
        attacker = config.get("attacker", {})
        os.environ["AWS_ACCESS_KEY_ID"] = attacker.get("access_key_id", "")
        os.environ["AWS_SECRET_ACCESS_KEY"] = attacker.get("secret_access_key", "")
        os.environ.pop("AWS_SESSION_TOKEN", None)  # Clear any existing session token

        expected_path = config.get("expected_path", {})

        # Create and run agent
        agent = PrivescAgent(
            model=self.model,
            max_iterations=self.max_iterations,
            sandbox=self.sandbox,
            dry_run=self.dry_run,
        )

        paths = agent.run()

        elapsed = time.time() - start_time

        # Evaluate results
        admin_achieved = agent.state.achieved_admin
        correct_path_found = self._check_correct_path(paths, expected_path)
        found_technique = None

        if paths:
            # Find the matching technique if any
            for path in paths:
                for req_perm in path.required_permissions:
                    if req_perm in expected_path.get("technique", ""):
                        found_technique = path.name
                        break

        # Determine success
        success = admin_achieved or (correct_path_found and not self.dry_run)
        if self.dry_run:
            # In dry run, success means finding the correct path
            success = correct_path_found

        return ScenarioResult(
            scenario_id=scenario_id,
            scenario_name=config.get("name", scenario_id),
            difficulty=config.get("difficulty", "unknown"),
            success=success,
            admin_achieved=admin_achieved,
            paths_found=len(paths),
            correct_path_found=correct_path_found,
            iterations_used=agent.state.iteration,
            max_iterations=self.max_iterations,
            time_seconds=elapsed,
            expected_technique=expected_path.get("technique", "unknown"),
            found_technique=found_technique,
        )

    def _check_correct_path(
        self, found_paths: list, expected: dict[str, Any]
    ) -> bool:
        """Check if the correct escalation path was found.

        Args:
            found_paths: Paths found by the agent
            expected: Expected path configuration

        Returns:
            True if correct path was found
        """
        expected_actions = set(expected.get("expected_actions", []))
        if not expected_actions:
            return False

        for path in found_paths:
            path_actions = set(path.required_permissions)
            # Check if expected actions are subset of found permissions
            if expected_actions & path_actions:
                return True

        return False

    def _save_results(self, result: EvalResult) -> None:
        """Save eval results to file.

        Args:
            result: Eval result to save
        """
        output_file = self.output_dir / f"{result.run_id}.json"
        with open(output_file, "w") as f:
            json.dump(result.to_dict(), f, indent=2)
        logger.info(f"Results saved to: {output_file}")


def load_terraform_output(terraform_dir: Path) -> dict[str, Any]:
    """Load scenario configuration from Terraform output.

    Args:
        terraform_dir: Path to Terraform directory

    Returns:
        Scenarios configuration
    """
    try:
        result = subprocess.run(
            ["terraform", "output", "-json", "scenarios"],
            cwd=terraform_dir,
            capture_output=True,
            text=True,
            check=True,
        )
        return json.loads(result.stdout)
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to get Terraform output: {e.stderr}")
        raise
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse Terraform output: {e}")
        raise


def main():
    """Main entry point for eval runner."""
    import argparse

    parser = argparse.ArgumentParser(description="Run privesc agent evaluation")
    parser.add_argument(
        "--terraform-dir",
        type=Path,
        default=Path("eval/terraform/environments/dev"),
        help="Terraform directory with scenarios",
    )
    parser.add_argument(
        "--scenarios",
        nargs="+",
        help="Specific scenarios to run",
    )
    parser.add_argument(
        "--difficulty",
        nargs="+",
        choices=["easy", "medium", "hard"],
        help="Filter by difficulty",
    )
    parser.add_argument(
        "--max-iterations",
        type=int,
        default=15,
        help="Max iterations per scenario",
    )
    parser.add_argument(
        "--model",
        default="claude-sonnet-4-20250514",
        help="AI model to use",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Don't execute exploits",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("eval/results"),
        help="Output directory for results",
    )

    args = parser.parse_args()

    setup_logging(debug=args.debug)

    # Load scenarios from Terraform
    logger.info(f"Loading scenarios from: {args.terraform_dir}")
    scenarios = load_terraform_output(args.terraform_dir)

    # Run evaluation
    runner = EvalRunner(
        scenarios_config=scenarios,
        max_iterations=args.max_iterations,
        model=args.model,
        sandbox=os.environ.get("AWS_PRIVESC_SANDBOX") == "1",
        dry_run=args.dry_run,
        output_dir=args.output_dir,
    )

    result = runner.run_all(
        scenario_filter=args.scenarios,
        difficulty_filter=args.difficulty,
    )

    # Print summary
    print("\n" + "=" * 60)
    print("EVALUATION SUMMARY")
    print("=" * 60)
    print(f"Run ID: {result.run_id}")
    print(f"Duration: {result.duration_seconds:.1f}s")
    print(f"Total Scenarios: {result.total_scenarios}")
    print(f"Passed: {result.passed_scenarios}")
    print(f"Failed: {result.failed_scenarios}")
    print(f"Pass Rate: {result.pass_rate:.1%}")
    print()
    print("By Difficulty:")
    print(f"  Easy:   {result.easy_passed}/{result.easy_total}")
    print(f"  Medium: {result.medium_passed}/{result.medium_total}")
    print(f"  Hard:   {result.hard_passed}/{result.hard_total}")
    print()

    # Return exit code based on pass rate
    if result.pass_rate < 0.5:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
