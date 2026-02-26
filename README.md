# Red Team Engineering Algorithm (RTE-A) Reference Implementation

[![CI](https://img.shields.io/badge/CI-github%20actions-blue)](https://github.com/codethor0/rte-a-reference/actions)
[![Go](https://img.shields.io/badge/Go-1.22+-00ADD8?logo=go)](https://golang.org/)
[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?logo=python)](https://python.org/)

RTE-A treats red team operations as a systems algorithm for governed adversary simulation, with typed tasking, cryptographic attribution, tamper-evident audit logging, and ephemeral infrastructure.

## Architecture Overview

### RTE-A Requirements (R1-R6)

| Req | Name | Description |
|-----|------|-------------|
| R1 | Attribution | Every action attributable to an authenticated operator and approved task |
| R2 | Policy Compliance | Each task stays within scope and rules of engagement |
| R3 | Observability | Execution produces structured, verifiable evidence for audit |
| R4 | Lifecycle Safety | Infrastructure discoverable and destructible, TTL enforced |
| R5 | Multi-operator | Multiple operators, no shared accounts, clear separation |
| R6 | Defender-Aligned | Outputs are measurements and recommendations in defender language |

### Layers (L1-L6)

- **L1 Identity**: Operator authentication and authorization
- **L2 Tasking**: Typed tasks with cryptographic attestation (Go library)
- **L3 Transport**: Task delivery and result collection
- **L4 Execution**: Task execution engines
- **L5 Infrastructure**: Ephemeral, tagged, TTL-enforced resources (Terraform)
- **L6 Observability**: Audit trail and measurements (Python library)

### Data Flow

```
Defender Objective
       |
       v
Control Plane (Task Approval, Signing)
       |
       v
Data Plane (Task Execution)
       |
       v
Infrastructure (Ephemeral EC2, Tags)
       |
       v
Audit Trail and Measurements (Hash-Chained Logs)
```

## Components

### Go Typed Tasking Library (`pkg/rte`)

Implements R1 (Attribution) and R2 (Policy Compliance):

- `Task` and `SignedTask` structs with ed25519 signatures
- `SignTask`, `VerifyTask` for cryptographic attestation
- `Task.Validate()` enforces TTL, allowed types, and required fields

### Python Audit Logger (`python/rte_a_audit`)

Implements R3 (Observability):

- `AuditLogger` with hash-chained records
- Tamper-evident: `verify_chain()` detects modifications or removals
- Structured output for detection engineering and threat hunting

### Terraform Infrastructure Module (`terraform/rte_a_infra`)

Implements R4 (Lifecycle Safety):

- Ephemeral EC2 (t3.micro) with mandatory tags
- `ExpiresAfter`, `AutoTeardown`, `Owner`, `Engagement`
- CloudWatch event rule stub for TTL enforcement

## Quickstart

### Go

Requires Go 1.22 or later.

```bash
cd rte-a-reference
go test ./...
```

Example usage:

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
        Type:       rte.TaskTypeRecon,
        CreatedAt:  now,
        TTLSeconds: 600,
        Operator:   "op-alice",
        ApprovedBy: "lead-bob",
        State:      rte.TaskStateApproved,
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

### Python

Requires Python 3.10+.

```bash
cd python
pip install -e .
pytest
```

Example usage:

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

### Terraform

Requires Terraform 1.6+ and AWS credentials.

```bash
cd terraform/examples/simple
terraform init
terraform plan
terraform apply   # creates ephemeral EC2 with tags
terraform destroy
```

## Testing and CI

Run all checks from the repo root:

```bash
./scripts/dev_check.sh
```

This runs:

- `go test ./...`
- `cd python && pytest`
- `terraform fmt -check` and `terraform validate` in `terraform/rte_a_infra` and `terraform/examples/simple`

The GitHub Actions workflow (`.github/workflows/ci.yml`) runs the same checks on push and pull requests to `main`.

## License

License: TBD. See [NOTICE.md](NOTICE.md) for ownership and terms.
