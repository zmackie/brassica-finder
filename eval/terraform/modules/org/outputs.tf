# Outputs for AWS Organization module

output "organization_id" {
  description = "The ID of the AWS Organization"
  value       = var.create_organization ? aws_organizations_organization.eval[0].id : null
}

output "organization_arn" {
  description = "The ARN of the AWS Organization"
  value       = var.create_organization ? aws_organizations_organization.eval[0].arn : null
}

output "security_ou_id" {
  description = "The ID of the Security OU"
  value       = var.create_organization ? aws_organizations_organizational_unit.security[0].id : null
}

output "workloads_ou_id" {
  description = "The ID of the Workloads OU"
  value       = var.create_organization ? aws_organizations_organizational_unit.workloads[0].id : null
}

output "sandbox_ou_id" {
  description = "The ID of the Sandbox OU"
  value       = var.create_organization ? aws_organizations_organizational_unit.sandbox[0].id : null
}

output "security_account_id" {
  description = "The ID of the Security account"
  value       = var.create_member_accounts ? aws_organizations_account.security[0].id : null
}

output "workload_dev_account_id" {
  description = "The ID of the Workload Dev account"
  value       = var.create_member_accounts ? aws_organizations_account.workload_dev[0].id : null
}

output "workload_prod_account_id" {
  description = "The ID of the Workload Prod account"
  value       = var.create_member_accounts ? aws_organizations_account.workload_prod[0].id : null
}

output "cross_account_admin_role_arn" {
  description = "The ARN of the cross-account admin role"
  value       = var.create_cross_account_roles ? aws_iam_role.cross_account_admin[0].arn : null
}
