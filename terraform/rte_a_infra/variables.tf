variable "engagement_id" {
  description = "Unique identifier for the red team engagement (R4 lifecycle tracking)"
  type        = string
}

variable "expiration_rfc3339" {
  description = "Expiration timestamp in RFC3339 format for TTL enforcement"
  type        = string
}

variable "operator_email" {
  description = "Email of the operator responsible for this infrastructure (R5 multi-operator)"
  type        = string
}

variable "aws_region" {
  description = "AWS region for resources"
  type        = string
  default     = "us-east-1"
}
