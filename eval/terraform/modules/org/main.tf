# AWS Organization and Account Structure for Eval Suite
# This creates a realistic multi-account environment for testing privilege escalation

terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# -----------------------------------------------------------------------------
# AWS Organization
# -----------------------------------------------------------------------------

resource "aws_organizations_organization" "eval" {
  count = var.create_organization ? 1 : 0

  aws_service_access_principals = [
    "cloudtrail.amazonaws.com",
    "config.amazonaws.com",
    "sso.amazonaws.com",
  ]

  feature_set = "ALL"

  enabled_policy_types = [
    "SERVICE_CONTROL_POLICY",
  ]
}

# -----------------------------------------------------------------------------
# Organizational Units
# -----------------------------------------------------------------------------

resource "aws_organizations_organizational_unit" "security" {
  count     = var.create_organization ? 1 : 0
  name      = "Security"
  parent_id = aws_organizations_organization.eval[0].roots[0].id
}

resource "aws_organizations_organizational_unit" "workloads" {
  count     = var.create_organization ? 1 : 0
  name      = "Workloads"
  parent_id = aws_organizations_organization.eval[0].roots[0].id
}

resource "aws_organizations_organizational_unit" "sandbox" {
  count     = var.create_organization ? 1 : 0
  name      = "Sandbox"
  parent_id = aws_organizations_organization.eval[0].roots[0].id
}

# -----------------------------------------------------------------------------
# Member Accounts (for cross-account scenarios)
# -----------------------------------------------------------------------------

resource "aws_organizations_account" "security" {
  count     = var.create_member_accounts ? 1 : 0
  name      = "${var.prefix}-security"
  email     = "${var.email_prefix}+security@${var.email_domain}"
  parent_id = aws_organizations_organizational_unit.security[0].id

  role_name = "OrganizationAccountAccessRole"

  tags = merge(var.tags, {
    Purpose = "Security tooling and audit logs"
  })

  lifecycle {
    ignore_changes = [role_name]
  }
}

resource "aws_organizations_account" "workload_dev" {
  count     = var.create_member_accounts ? 1 : 0
  name      = "${var.prefix}-workload-dev"
  email     = "${var.email_prefix}+workload-dev@${var.email_domain}"
  parent_id = aws_organizations_organizational_unit.workloads[0].id

  role_name = "OrganizationAccountAccessRole"

  tags = merge(var.tags, {
    Purpose     = "Development workloads"
    Environment = "dev"
  })

  lifecycle {
    ignore_changes = [role_name]
  }
}

resource "aws_organizations_account" "workload_prod" {
  count     = var.create_member_accounts ? 1 : 0
  name      = "${var.prefix}-workload-prod"
  email     = "${var.email_prefix}+workload-prod@${var.email_domain}"
  parent_id = aws_organizations_organizational_unit.workloads[0].id

  role_name = "OrganizationAccountAccessRole"

  tags = merge(var.tags, {
    Purpose     = "Production workloads"
    Environment = "prod"
  })

  lifecycle {
    ignore_changes = [role_name]
  }
}

# -----------------------------------------------------------------------------
# Cross-Account Roles for Eval
# -----------------------------------------------------------------------------

# Role in management account that can be assumed from workload accounts
resource "aws_iam_role" "cross_account_admin" {
  count = var.create_cross_account_roles ? 1 : 0
  name  = "${var.prefix}-cross-account-admin"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = var.create_member_accounts ? [
            "arn:aws:iam::${aws_organizations_account.workload_dev[0].id}:root",
            "arn:aws:iam::${aws_organizations_account.workload_prod[0].id}:root",
          ] : var.trusted_account_ids
        }
        Action = "sts:AssumeRole"
        Condition = {
          StringEquals = {
            "sts:ExternalId" = var.external_id
          }
        }
      }
    ]
  })

  tags = var.tags
}

resource "aws_iam_role_policy_attachment" "cross_account_admin" {
  count      = var.create_cross_account_roles ? 1 : 0
  role       = aws_iam_role.cross_account_admin[0].name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}
