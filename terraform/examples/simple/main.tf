module "rte_a_infra" {
  source = "../../rte_a_infra"

  engagement_id      = "example-engagement"
  expiration_rfc3339 = "2030-01-01T00:00:00Z"
  operator_email     = "operator@example.com"
}

output "simulation_node_id" {
  value = module.rte_a_infra.simulation_node_id
}
