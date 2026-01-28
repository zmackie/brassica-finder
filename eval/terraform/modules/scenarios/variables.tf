# Variables for Privilege Escalation Scenarios

variable "prefix" {
  description = "Prefix for all resources"
  type        = string
  default     = "privesc-eval"
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

  validation {
    condition = alltrue([
      for s in var.enabled_scenarios : contains([
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
      ], s)
    ])
    error_message = "Invalid scenario name provided."
  }
}

variable "tags" {
  description = "Tags to apply to all resources"
  type        = map(string)
  default = {
    Project     = "privesc-eval"
    ManagedBy   = "terraform"
    Environment = "eval"
  }
}
