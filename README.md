# Red Team Engineering Algorithm (RTE-A) - Reference Implementation

[![CI](https://github.com/codethor0/rte-a-reference/actions/workflows/ci.yml/badge.svg)](https://github.com/codethor0/rte-a-reference/actions/workflows/ci.yml)
[![Go](https://img.shields.io/badge/Go-1.22+-00ADD8?logo=go)](https://golang.org/)
[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?logo=python)](https://python.org/)
[![License](https://img.shields.io/badge/License-TBD-lightgrey)](NOTICE.md)

Reference implementation of the Red Team Engineering Algorithm (RTE-A): typed tasking with cryptographic attribution (Go), tamper-evident audit logging (Python), and ephemeral, TTL-enforced infrastructure (Terraform) for governed adversary simulation.

## Repository Layout

```
rte-a-reference/
|-- .editorconfig
|-- .golangci.yml
|-- .gitignore
|-- .github/
|   |-- workflows/
|   |   |-- ci.yml
|-- NOTICE.md
|-- README.md
|-- SECURITY.md
|-- go.mod
|-- pkg/
|   |-- rte/
|   |   |-- task.go
|   |   |-- task_test.go
|-- python/
|   |-- mypy.ini
|   |-- pyproject.toml
|   |-- rte_a_audit/
|   |   |-- __init__.py
|   |   |-- audit_logger.py
|   |   |-- py.typed
|   |-- tests/
|   |   |-- test_audit_logger.py
|-- scripts/
|   |-- dev_check.sh
|-- terraform/
|   |-- rte_a_infra/
|   |   |-- main.tf
|   |   |-- outputs.tf
|   |   |-- variables.tf
|   |-- examples/
|   |   |-- simple/
|   |       |-- main.tf
```

## Getting Started

### Requirements

- Go 1.22+
- Python 3.10+
- Terraform 1.6+

### Clone

```bash
git clone https://github.com/codethor0/rte-a-reference.git
cd rte-a-reference
```

### Run All Checks

```bash
chmod +x scripts/dev_check.sh
./scripts/dev_check.sh
```

This runs: `go test ./...`, `pytest` in `python/`, and `terraform fmt -check` plus `terraform validate` in both the module and example directories.

## Go Module Usage

Create, sign, and verify a typed task:

```go
package main

import (
    "fmt"
    "time"
    "github.com/codethor0/rte-a-reference/pkg/rte"
)

func main() {
    now := time.Now().UTC()
    task := rte.Task{
        ID:         "task-001",
        Engagement: "eng-2026",
        Type:       rte.TaskSimulateLogin,
        CreatedAt:  now,
        TTLSeconds: 600,
        Operator:   "op-alice",
        ApprovedBy: "lead-bob",
        State:      rte.StatePending,
    }
    pub, priv, _ := rte.GenerateKeyPair()
    st, err := rte.SignTask(task, priv, pub)
    if err != nil {
        panic(err)
    }
    if err := rte.VerifyTask(st); err != nil {
        panic(err)
    }
    fmt.Println("Task verified:", st.Task.ID)
}
```

## Python Audit Logger Usage

```python
from rte_a_audit import AuditLogger

logger = AuditLogger(engagement_id="eng-001", operator_id="op-alice")
rec = logger.log_event(
    action="recon_scan",
    result={"hosts": 5, "open_ports": [22, 443]},
    authorization="task-001",
    task_id="task-001",
)
print(rec["chain_hash"])

records = [rec]
assert AuditLogger.verify_chain(records)
```

## Terraform Usage

From `terraform/examples/simple`:

```bash
terraform init
terraform plan
terraform apply
```

This provisions ephemeral EC2 infrastructure with engagement tags and TTL metadata. Run `terraform destroy` when done.

## Design Guarantees

This reference maps to RTE-A requirements as follows:

| Component | Requirements | Guarantee |
|-----------|--------------|-----------|
| Go typed tasking | R1, R2, R5 | Every task has Operator and ApprovedBy; Validate enforces type and TTL; SignTask/VerifyTask bind action to cryptographic identity; no shared accounts |
| Python audit logger | R1, R3 | Records include operator_id and authorization; hash chain provides tamper-evident, verifiable audit trail for detection engineering |
| Terraform module | R4 | Ephemeral EC2 tagged with ExpiresAfter, AutoTeardown, Engagement; infrastructure is discoverable and destructible via tags |

## Defender Outputs (R6)

Audit records from the Python logger are structured for defender consumption: action, result_hash, authorization, and sequence form a chain that threat hunters and detection engineers can verify. Terraform tags (Engagement, ExpiresAfter, Owner) make infrastructure traceable to engagements and operators, supporting measurement and recommendation generation in defender language rather than raw "access achieved" outputs.

## Security Considerations

- No secrets or credentials are stored in this repository
- Sample values (emails, engagement IDs) are for demonstration only
- Production use requires proper credential management and least-privilege IAM

## License

License: TBD. See [NOTICE.md](NOTICE.md) for ownership and terms.
