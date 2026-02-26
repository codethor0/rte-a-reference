#!/usr/bin/env sh
# Run from repo root. Requires go, python3, terraform.
# chmod +x scripts/dev_check.sh
set -eu

REPO_ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"

echo "Running Go tests..."
cd "$REPO_ROOT"
go test ./...
golangci-lint run --config .golangci.yml

echo "Running Python tests..."
cd "$REPO_ROOT/python"
if [ ! -d ".venv" ]; then
  python3 -m venv .venv
fi
. .venv/bin/activate
pip install -e ".[dev]" >/dev/null 2>&1 || pip install -e .
pytest
mypy rte_a_audit

echo "Running Terraform checks..."
cd "$REPO_ROOT"
terraform -chdir=terraform/rte_a_infra fmt -check
terraform -chdir=terraform/rte_a_infra init -backend=false -input=false
terraform -chdir=terraform/rte_a_infra validate
terraform -chdir=terraform/examples/simple fmt -check
terraform -chdir=terraform/examples/simple init -backend=false -input=false
terraform -chdir=terraform/examples/simple validate

echo "All checks passed."
