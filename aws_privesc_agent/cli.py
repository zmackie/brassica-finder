"""Command-line interface for the AWS privilege escalation agent."""

import json
import os
import sys
from datetime import datetime
from pathlib import Path

import click

from .core.agent import PrivescAgent
from .core.logger import get_logger, setup_logging
from .core.models import Severity
from .aws.enumeration import enumerate_iam, get_caller_identity, check_admin
from .paths.knowledge import get_known_techniques, ESCALATION_TECHNIQUES
from .paths.analyzer import analyze_paths
from .tools.installer import list_tools, install_tool, install_all_tools
from .skills.manager import SkillManager

logger = get_logger("cli")


@click.group()
@click.option("--debug", is_flag=True, help="Enable debug logging")
@click.option("--log-file", type=click.Path(), help="Log to file")
@click.pass_context
def cli(ctx, debug: bool, log_file: str | None):
    """AWS Privilege Escalation Agent - Find paths to admin."""
    ctx.ensure_object(dict)
    ctx.obj["debug"] = debug
    setup_logging(debug=debug, log_file=log_file)


@cli.command()
@click.option("--max-iterations", "-n", default=10, help="Maximum agent iterations")
@click.option("--dry-run", is_flag=True, help="Don't execute exploits")
@click.option("--model", default="claude-sonnet-4-20250514", help="AI model to use")
@click.option("--output", "-o", type=click.Path(), help="Output report file")
@click.pass_context
def run(ctx, max_iterations: int, dry_run: bool, model: str, output: str | None):
    """Run the AI agent to find privilege escalation paths."""

    # Check if in sandbox
    sandbox = os.environ.get("AWS_PRIVESC_SANDBOX") == "1"
    if not sandbox and not dry_run:
        click.echo("WARNING: Not running in sandbox container!", err=True)
        click.echo("Use --dry-run or run in Docker container.", err=True)
        if not click.confirm("Continue anyway?"):
            sys.exit(1)

    # Check for API key
    if not os.environ.get("ANTHROPIC_API_KEY"):
        click.echo("Error: ANTHROPIC_API_KEY environment variable not set", err=True)
        sys.exit(1)

    click.echo(f"Starting AWS Privilege Escalation Agent")
    click.echo(f"  Model: {model}")
    click.echo(f"  Max iterations: {max_iterations}")
    click.echo(f"  Dry run: {dry_run}")
    click.echo(f"  Sandbox: {sandbox}")
    click.echo()

    agent = PrivescAgent(
        model=model,
        max_iterations=max_iterations,
        sandbox=sandbox,
        dry_run=dry_run,
    )

    try:
        paths = agent.run()

        click.echo()
        click.echo(f"Found {len(paths)} privilege escalation paths:")
        click.echo()

        for path in paths:
            severity_color = {
                Severity.CRITICAL: "red",
                Severity.HIGH: "yellow",
                Severity.MEDIUM: "cyan",
                Severity.LOW: "green",
                Severity.INFO: "white",
            }.get(path.severity, "white")

            click.secho(f"[{path.severity.value.upper()}] ", fg=severity_color, nl=False)
            click.echo(path.name)
            click.echo(f"  Source: {path.source_principal}")
            if path.target_principal:
                click.echo(f"  Target: {path.target_principal}")
            click.echo(f"  Required: {', '.join(path.required_permissions)}")
            click.echo()

        if output:
            report = {
                "generated_at": datetime.now().isoformat(),
                "account": agent.state.account_id,
                "identity": agent.state.current_identity,
                "admin_achieved": agent.state.achieved_admin,
                "iterations": agent.state.iteration,
                "paths": [p.model_dump() for p in paths],
            }
            Path(output).write_text(json.dumps(report, indent=2, default=str))
            click.echo(f"Report written to: {output}")

        if agent.state.achieved_admin:
            click.secho("SUCCESS: Admin access achieved!", fg="green", bold=True)
        else:
            click.echo("Admin access not achieved in this run.")

    except KeyboardInterrupt:
        click.echo("\nInterrupted by user")
        sys.exit(1)
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        if ctx.obj.get("debug"):
            import traceback
            traceback.print_exc()
        sys.exit(1)


@cli.command()
@click.option("--target", "-t", default="all", help="What to enumerate (all, users, roles, policies)")
@click.option("--output", "-o", type=click.Path(), help="Output JSON file")
def enumerate(target: str, output: str | None):
    """Enumerate IAM resources in the AWS account."""
    click.echo("Enumerating IAM resources...")

    identity = get_caller_identity()
    if not identity:
        click.echo("Error: Could not authenticate to AWS", err=True)
        sys.exit(1)

    click.echo(f"  Account: {identity['Account']}")
    click.echo(f"  Identity: {identity['Arn']}")
    click.echo()

    result = enumerate_iam(target)

    click.echo(f"Found:")
    click.echo(f"  Users: {len(result.users)}")
    click.echo(f"  Roles: {len(result.roles)}")
    click.echo(f"  Groups: {len(result.groups)}")
    click.echo(f"  Policies: {len(result.policies)}")
    click.echo(f"  Admin principals: {len(result.admin_principals)}")

    if result.admin_principals:
        click.echo()
        click.echo("Admin principals:")
        for arn in result.admin_principals:
            click.echo(f"  - {arn}")

    if output:
        Path(output).write_text(
            json.dumps(result.model_dump(), indent=2, default=str)
        )
        click.echo(f"\nResults written to: {output}")


@cli.command()
@click.option("--enumeration-file", "-e", type=click.Path(exists=True), help="Use existing enumeration JSON")
@click.option("--output", "-o", type=click.Path(), help="Output JSON file")
def analyze(enumeration_file: str | None, output: str | None):
    """Analyze IAM configuration for privilege escalation paths."""

    if enumeration_file:
        click.echo(f"Loading enumeration from: {enumeration_file}")
        from .core.models import EnumerationResult
        data = json.loads(Path(enumeration_file).read_text())
        enumeration = EnumerationResult(**data)
    else:
        click.echo("Enumerating IAM resources first...")
        enumeration = enumerate_iam("all")

    click.echo("Analyzing for privilege escalation paths...")
    paths = analyze_paths(enumeration)

    click.echo(f"\nFound {len(paths)} potential paths:")
    click.echo()

    for path in paths:
        severity_color = {
            Severity.CRITICAL: "red",
            Severity.HIGH: "yellow",
            Severity.MEDIUM: "cyan",
            Severity.LOW: "green",
            Severity.INFO: "white",
        }.get(path.severity, "white")

        click.secho(f"[{path.severity.value.upper()}] ", fg=severity_color, nl=False)
        click.echo(path.name)
        click.echo(f"  ID: {path.id}")
        click.echo(f"  Source: {path.source_principal}")
        if path.target_principal:
            click.echo(f"  Target: {path.target_principal}")
        click.echo(f"  Permissions: {', '.join(path.required_permissions)}")
        if path.steps:
            click.echo(f"  Steps:")
            for i, step in enumerate(path.steps, 1):
                click.echo(f"    {i}. {step}")
        click.echo()

    if output:
        report = {
            "generated_at": datetime.now().isoformat(),
            "account": enumeration.account_id,
            "paths": [p.model_dump() for p in paths],
        }
        Path(output).write_text(json.dumps(report, indent=2, default=str))
        click.echo(f"Report written to: {output}")


@cli.command()
@click.argument("query", required=False)
def techniques(query: str | None):
    """List known privilege escalation techniques."""
    techs = get_known_techniques(query or "")

    click.echo(f"Known privilege escalation techniques ({len(techs)}):")
    click.echo()

    for tech in techs:
        severity_color = {
            "critical": "red",
            "high": "yellow",
            "medium": "cyan",
            "low": "green",
        }.get(tech["severity"], "white")

        click.secho(f"[{tech['severity'].upper()}] ", fg=severity_color, nl=False)
        click.echo(tech["name"])
        click.echo(f"  ID: {tech['id']}")
        click.echo(f"  Permissions: {', '.join(tech['required_permissions'])}")
        click.echo(f"  {tech['description']}")
        click.echo()


@cli.group()
def tools():
    """Manage external security tools."""
    pass


@tools.command("list")
def tools_list():
    """List available security tools."""
    tool_list = list_tools()

    click.echo("Available security tools:")
    click.echo()

    for tool in tool_list:
        status = click.style("installed", fg="green") if tool["installed"] else click.style("not installed", fg="yellow")
        click.echo(f"  {tool['name']}: {tool['description']} [{status}]")


@tools.command("install")
@click.argument("tool_name", required=False)
@click.option("--all", "install_all", is_flag=True, help="Install all tools")
def tools_install(tool_name: str | None, install_all: bool):
    """Install security tools."""
    if install_all:
        click.echo("Installing all tools...")
        results = install_all_tools()
        for name, success in results.items():
            status = click.style("OK", fg="green") if success else click.style("FAILED", fg="red")
            click.echo(f"  {name}: {status}")
    elif tool_name:
        click.echo(f"Installing {tool_name}...")
        success = install_tool(tool_name)
        if success:
            click.secho("Installed successfully", fg="green")
        else:
            click.secho("Installation failed", fg="red")
            sys.exit(1)
    else:
        click.echo("Specify a tool name or use --all")
        sys.exit(1)


@cli.group()
def skills():
    """Manage agent skills."""
    pass


@skills.command("list")
def skills_list():
    """List available skills."""
    manager = SkillManager()
    skill_list = manager.list_skills()

    click.echo("Available skills:")
    click.echo()

    for skill in skill_list:
        click.echo(f"  {skill['name']}: {skill['description']}")


@skills.command("run")
@click.argument("skill_name")
def skills_run(skill_name: str):
    """Run a skill."""
    manager = SkillManager()

    click.echo(f"Running skill: {skill_name}")
    result = manager.execute_skill(skill_name)

    if result["success"]:
        click.echo()
        if isinstance(result["output"], dict):
            click.echo(json.dumps(result["output"], indent=2))
        else:
            click.echo(result["output"])
    else:
        click.echo(f"Error: {result.get('error', 'Unknown error')}", err=True)
        if result.get("stderr"):
            click.echo(result["stderr"], err=True)
        sys.exit(1)


@cli.command()
def check():
    """Check current AWS identity and admin status."""
    identity = get_caller_identity()

    if not identity:
        click.echo("Error: Could not authenticate to AWS", err=True)
        click.echo("Ensure AWS credentials are configured.", err=True)
        sys.exit(1)

    click.echo("AWS Identity Check:")
    click.echo(f"  Account: {identity['Account']}")
    click.echo(f"  ARN: {identity['Arn']}")
    click.echo(f"  User ID: {identity['UserId']}")
    click.echo()

    click.echo("Checking admin status...")
    is_admin = check_admin()

    if is_admin:
        click.secho("Status: ADMIN", fg="green", bold=True)
    else:
        click.secho("Status: NOT ADMIN", fg="yellow")


def main():
    """Main entry point."""
    cli(obj={})


if __name__ == "__main__":
    main()
