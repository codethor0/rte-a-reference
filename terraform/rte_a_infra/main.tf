terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

locals {
  common_tags = {
    Owner        = var.operator_email
    Engagement   = var.engagement_id
    ExpiresAfter = var.expiration_rfc3339
    AutoTeardown = "true"
    CostCenter   = "rte-a"
    CreatedBy    = var.operator_email
    Purpose      = "rte-a-ephemeral"
    Layer        = "L5-infrastructure"
  }
}

resource "aws_instance" "rte_a_ephemeral" {
  ami           = data.aws_ami.amazon_linux_2023.id
  instance_type = "t3.micro"

  tags = merge(local.common_tags, {
    Name = "rte-a-${var.engagement_id}"
  })
}

data "aws_ami" "amazon_linux_2023" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }
}

resource "aws_cloudwatch_event_rule" "rte_a_ttl_check" {
  name                = "rte-a-ttl-check-${var.engagement_id}"
  description         = "Scheduled trigger for RTE-A TTL enforcement (expired instances)"
  schedule_expression = "rate(1 hour)"
}
