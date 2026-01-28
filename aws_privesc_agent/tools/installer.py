"""Install and manage external security tools."""

import subprocess
import shutil
from pathlib import Path

from ..core.logger import get_logger

logger = get_logger("tools.installer")

# Tools and their installation methods
TOOLS = {
    "pacu": {
        "check": "pacu",
        "install": "pip install pacu",
        "description": "AWS exploitation framework",
    },
    "enumerate-iam": {
        "check": "enumerate-iam",
        "install": "pip install enumerate-iam",
        "description": "IAM permission enumeration",
    },
    "pmapper": {
        "check": "pmapper",
        "install": "pip install principalmapper",
        "description": "AWS IAM principal mapper",
    },
    "cloudsplaining": {
        "check": "cloudsplaining",
        "install": "pip install cloudsplaining",
        "description": "AWS IAM security assessment",
    },
    "prowler": {
        "check": "prowler",
        "install": "pip install prowler",
        "description": "AWS security assessment tool",
    },
    "scoutsuite": {
        "check": "scout",
        "install": "pip install scoutsuite",
        "description": "Multi-cloud security auditing",
    },
    "awscli": {
        "check": "aws",
        "install": "pip install awscli",
        "description": "AWS command line interface",
    },
}


def check_tool(tool_name: str) -> bool:
    """Check if a tool is installed.

    Args:
        tool_name: Name of the tool

    Returns:
        True if installed, False otherwise
    """
    if tool_name not in TOOLS:
        return False

    check_cmd = TOOLS[tool_name]["check"]
    return shutil.which(check_cmd) is not None


def install_tool(tool_name: str) -> bool:
    """Install a tool.

    Args:
        tool_name: Name of the tool

    Returns:
        True if installation successful, False otherwise
    """
    if tool_name not in TOOLS:
        logger.error(f"Unknown tool: {tool_name}")
        return False

    if check_tool(tool_name):
        logger.info(f"Tool already installed: {tool_name}")
        return True

    install_cmd = TOOLS[tool_name]["install"]
    logger.info(f"Installing {tool_name}: {install_cmd}")

    try:
        result = subprocess.run(
            install_cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=300,
        )
        if result.returncode == 0:
            logger.info(f"Successfully installed: {tool_name}")
            return True
        else:
            logger.error(f"Failed to install {tool_name}: {result.stderr}")
            return False
    except subprocess.TimeoutExpired:
        logger.error(f"Installation timed out: {tool_name}")
        return False
    except Exception as e:
        logger.error(f"Installation error: {e}")
        return False


def install_all_tools() -> dict[str, bool]:
    """Install all available tools.

    Returns:
        Dict mapping tool names to installation success
    """
    results = {}
    for tool_name in TOOLS:
        results[tool_name] = install_tool(tool_name)
    return results


def list_tools() -> list[dict[str, str]]:
    """List all available tools.

    Returns:
        List of tool info dicts
    """
    tools = []
    for name, info in TOOLS.items():
        tools.append({
            "name": name,
            "description": info["description"],
            "installed": check_tool(name),
        })
    return tools


def run_tool(tool_name: str, args: list[str], timeout: int = 300) -> dict:
    """Run an installed tool.

    Args:
        tool_name: Name of the tool
        args: Command line arguments
        timeout: Timeout in seconds

    Returns:
        Result dict with stdout, stderr, exit_code
    """
    if not check_tool(tool_name):
        return {
            "success": False,
            "error": f"Tool not installed: {tool_name}",
        }

    check_cmd = TOOLS[tool_name]["check"]
    cmd = [check_cmd] + args

    logger.debug(f"Running: {' '.join(cmd)}")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return {
            "success": result.returncode == 0,
            "exit_code": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "error": "Execution timed out",
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
        }
