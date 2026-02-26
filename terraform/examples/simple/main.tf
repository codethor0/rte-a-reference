module "rte_a_simple" {
  source = "../../rte_a_infra"

  engagement_id     = "eng-simple-example"
  expiration_rfc3339 = "2026-03-01T23:59:59Z"
  operator_email    = "operator@example.com"
  aws_region        = "us-east-1"
}

output "instance_id" {
  value = module.rte_a_simple.instance_id
}
