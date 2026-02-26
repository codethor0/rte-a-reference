output "instance_id" {
  description = "ID of the ephemeral EC2 instance"
  value       = aws_instance.rte_a_ephemeral.id
}

output "simulation_node_id" {
  description = "ID of the simulation node (ephemeral instance)"
  value       = aws_instance.rte_a_ephemeral.id
}

output "instance_arn" {
  description = "ARN of the ephemeral EC2 instance"
  value       = aws_instance.rte_a_ephemeral.arn
}

output "ttl_rule_arn" {
  description = "ARN of the CloudWatch event rule for TTL enforcement"
  value       = aws_cloudwatch_event_rule.rte_a_ttl_check.arn
}
