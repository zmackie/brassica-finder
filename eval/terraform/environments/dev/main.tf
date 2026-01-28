# Development environment for privesc eval suite
# Deploys scenarios in a single AWS account for testing

terraform {
  required_version = ">= 1.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.0"
    }
  }

  # Use local backend for dev
  backend "local" {
    path = "terraform.tfstate"
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "privesc-eval"
      Environment = "dev"
      ManagedBy   = "terraform"
    }
  }
}

# Deploy scenarios
module "scenarios" {
  source = "../../modules/scenarios"

  prefix            = var.prefix
  enabled_scenarios = var.enabled_scenarios
  tags              = var.tags
}

# Outputs for eval harness
output "account_id" {
  value = module.scenarios.account_id
}

output "region" {
  value = module.scenarios.region
}

output "scenarios" {
  value     = module.scenarios.scenarios
  sensitive = true
}

output "enabled_scenarios" {
  value = module.scenarios.enabled_scenarios
}
