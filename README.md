# AWS Privilege Escalation Agent

An AI-powered agent for discovering and analyzing AWS IAM privilege escalation paths. The agent uses Claude to autonomously enumerate IAM resources, analyze permissions, and find paths from non-admin identities to admin access.

**For authorized security testing only.**

## Features

- **AI-Driven Analysis**: Uses Claude to reason about privilege escalation paths
- **IAM Enumeration**: Automatically enumerate users, roles, groups, and policies
- **Path Discovery**: Find direct and chained privilege escalation paths
- **Knowledge Base**: 20+ known escalation techniques from pathfinding.cloud and Rhino Security Labs
- **Sandbox Execution**: Run exploits safely in a container environment
- **Extensible Skills**: Download and run custom analysis scripts
- **Tool Integration**: Works with Pacu, PMapper, Cloudsplaining, and more

## Quick Start

### Prerequisites

- Python 3.12+
- AWS credentials configured
- Anthropic API key

### Installation

```bash
# Clone the repository
git clone <repo-url>
cd aws-privesc-agent

# Install dependencies
pip install -r requirements.txt

# Set API key
export ANTHROPIC_API_KEY=your-api-key
```

### Usage

```bash
# Check current AWS identity
python -m aws_privesc_agent check

# Enumerate IAM resources
python -m aws_privesc_agent enumerate

# Analyze for privilege escalation paths
python -m aws_privesc_agent analyze

# Run the AI agent (dry-run mode)
python -m aws_privesc_agent run --dry-run

# Run with full execution in sandbox
docker-compose run agent run --max-iterations 15
```

## Running in Docker (Recommended)

The agent is designed to run in a sandbox container for safety:

```bash
# Build the container
docker-compose build

# Run with AWS credentials
docker-compose run agent run --dry-run

# Or with full execution
docker-compose run agent run
```

## CLI Commands

```
Usage: python -m aws_privesc_agent [OPTIONS] COMMAND [ARGS]...

Commands:
  run         Run the AI agent to find privilege escalation paths
  enumerate   Enumerate IAM resources in the AWS account
  analyze     Analyze IAM configuration for privilege escalation paths
  techniques  List known privilege escalation techniques
  tools       Manage external security tools
  skills      Manage agent skills
  check       Check current AWS identity and admin status
```

### Examples

```bash
# Run agent with debug logging
python -m aws_privesc_agent --debug run --dry-run

# Save enumeration results
python -m aws_privesc_agent enumerate --output enum.json

# Analyze existing enumeration
python -m aws_privesc_agent analyze -e enum.json --output paths.json

# List known techniques
python -m aws_privesc_agent techniques

# Search for specific techniques
python -m aws_privesc_agent techniques "passrole"

# Install security tools
python -m aws_privesc_agent tools install --all

# Run a skill
python -m aws_privesc_agent skills run find-assumable-roles
```

## Known Privilege Escalation Techniques

The agent knows about these escalation vectors:

| Technique | Required Permissions | Severity |
|-----------|---------------------|----------|
| Create Policy Version | `iam:CreatePolicyVersion` | Critical |
| Attach User Policy | `iam:AttachUserPolicy` | Critical |
| Attach Role Policy | `iam:AttachRolePolicy` | Critical |
| Put User Policy | `iam:PutUserPolicy` | Critical |
| PassRole to EC2 | `iam:PassRole`, `ec2:RunInstances` | Critical |
| PassRole to Lambda | `iam:PassRole`, `lambda:CreateFunction`, `lambda:InvokeFunction` | Critical |
| Update Assume Role Policy | `iam:UpdateAssumeRolePolicy` | Critical |
| Create Access Key | `iam:CreateAccessKey` | High |
| Assume Role | `sts:AssumeRole` | High |
| SSM Send Command | `ssm:SendCommand` | High |

See full list with `python -m aws_privesc_agent techniques`.

## Architecture

```
aws_privesc_agent/
├── core/
│   ├── agent.py      # Main AI agent with Claude integration
│   ├── models.py     # Data models (Principal, PrivescPath, etc.)
│   └── logger.py     # Logging with debug support
├── aws/
│   └── enumeration.py # IAM enumeration functions
├── paths/
│   ├── analyzer.py   # Path analysis logic
│   ├── exploiter.py  # Exploit execution (sandbox only)
│   └── knowledge.py  # Known techniques database
├── tools/
│   └── installer.py  # External tool management
├── skills/
│   └── manager.py    # Downloadable skills
└── cli.py            # Command-line interface
```

## Safety Features

- **Sandbox Mode**: Exploits only run when `AWS_PRIVESC_SANDBOX=1`
- **Dry Run**: Use `--dry-run` to analyze without executing exploits
- **Non-Root Container**: Docker runs as unprivileged user
- **Capability Restrictions**: Container drops all capabilities
- **Read-Only Credentials**: AWS credentials mounted read-only

## References

- [pathfinding.cloud](https://pathfinding.cloud/) - AWS IAM Privilege Escalation Path Library
- [Rhino Security Labs](https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/) - AWS Privilege Escalation Methods
- [IAM Vulnerable](https://github.com/BishopFox/iam-vulnerable) - Practice environment
- [Pacu](https://github.com/RhinoSecurityLabs/pacu) - AWS exploitation framework

## Disclaimer

This tool is for authorized security testing and educational purposes only. Only use against AWS accounts you own or have explicit permission to test. Unauthorized access to computer systems is illegal.

## License

MIT
