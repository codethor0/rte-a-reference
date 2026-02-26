#!/usr/bin/env bash
# Run from repo root. Assumes go, python3/pytest, terraform are installed.
# chmod +x scripts/dev_check.sh (optional)
set -e
cd "$(dirname "$0")/.."

echo "=== Go ==="
go test ./...

echo "=== Python ==="
cd python
if [ -d ".venv" ]; then
  . .venv/bin/activate
fi
pip install -e . pytest -q
pytest
cd ..

echo "=== Terraform ==="
cd terraform/rte_a_infra
terraform fmt -check -recursive
terraform init -backend=false -input=false 2>/dev/null || true
terraform validate
cd ../..
cd terraform/examples/simple
terraform fmt -check -recursive
terraform init -backend=false -input=false 2>/dev/null || true
terraform validate
cd ../..

echo "=== All checks passed ==="
