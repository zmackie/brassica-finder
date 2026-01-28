# Variables for AWS Organization module

variable "prefix" {
  description = "Prefix for all resources"
  type        = string
  default     = "privesc-eval"
}

variable "create_organization" {
  description = "Whether to create a new AWS Organization"
  type        = bool
  default     = false
}

variable "create_member_accounts" {
  description = "Whether to create member accounts"
  type        = bool
  default     = false
}

variable "create_cross_account_roles" {
  description = "Whether to create cross-account roles"
  type        = bool
  default     = true
}

variable "email_prefix" {
  description = "Email prefix for member accounts"
  type        = string
  default     = "aws-eval"
}

variable "email_domain" {
  description = "Email domain for member accounts"
  type        = string
  default     = "example.com"
}

variable "trusted_account_ids" {
  description = "Account IDs to trust for cross-account roles"
  type        = list(string)
  default     = []
}

variable "external_id" {
  description = "External ID for cross-account role assumption"
  type        = string
  default     = "privesc-eval-external-id"
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
