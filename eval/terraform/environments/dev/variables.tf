# Variables for dev environment

variable "aws_region" {
  description = "AWS region to deploy to"
  type        = string
  default     = "us-east-1"
}

variable "prefix" {
  description = "Prefix for all resources"
  type        = string
  default     = "privesc-eval-dev"
}

variable "enabled_scenarios" {
  description = "List of scenarios to enable"
  type        = list(string)
  default = [
    "create-policy-version",
    "attach-user-policy",
    "passrole-lambda",
    "assume-role-chain",
    "update-assume-role-policy",
    "passrole-ec2",
    "create-access-key-admin",
    "passrole-cloudformation",
    "put-role-policy",
    "ssm-send-command",
  ]
}

variable "tags" {
  description = "Additional tags"
  type        = map(string)
  default     = {}
}
