package rte

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// TaskType represents the kind of task in the red team engagement.
type TaskType string

const (
	TaskSimulateLogin  TaskType = "simulate_login"
	TaskSimulateBeacon TaskType = "simulate_beacon"
	TaskInventory     TaskType = "inventory"
	TaskEmitSynthetic  TaskType = "emit_synthetic"
)

// TaskState represents the lifecycle state of a task.
type TaskState string

const (
	StatePending    TaskState = "pending"
	StateExecuting  TaskState = "executing"
	StateCancelled  TaskState = "cancelled"
	StateCompleted  TaskState = "completed"
	StateFailed     TaskState = "failed"
)

const (
	maxTTLSeconds = 3600
	minTTLSeconds = 1
)

var (
	allowedTaskTypes = map[TaskType]struct{}{
		TaskSimulateLogin:  {},
		TaskSimulateBeacon: {},
		TaskInventory:     {},
		TaskEmitSynthetic: {},
	}

	validTaskStates = map[TaskState]struct{}{
		StatePending:   {},
		StateExecuting: {},
		StateCancelled: {},
		StateCompleted: {},
		StateFailed:    {},
	}
)

// Task represents a typed red team task with attribution and lifecycle metadata.
type Task struct {
	ID          string            `json:"id"`
	Engagement  string            `json:"engagement"`
	Type        TaskType          `json:"type"`
	CreatedAt   time.Time         `json:"created_at"`
	TTLSeconds  int               `json:"ttl_seconds"`
	Operator    string            `json:"operator"`
	ApprovedBy  string            `json:"approved_by"`
	State       TaskState         `json:"state"`
	CancelToken string            `json:"cancel_token,omitempty"`
	Params      map[string]string `json:"params,omitempty"`
}

// SignedTask wraps a Task with cryptographic attestation.
type SignedTask struct {
	Task      Task   `json:"task"`
	PublicKey []byte `json:"public_key"`
	Signature []byte `json:"signature"`
}

// Validate checks that the task meets RTE-A invariants (R1, R2).
// now is typically time.Now() for runtime validation.
func (t *Task) Validate(now time.Time) error {
	if t == nil {
		return errors.New("task is nil")
	}
	if t.ID == "" {
		return errors.New("task ID is required")
	}
	if t.Engagement == "" {
		return errors.New("engagement is required")
	}
	if t.Operator == "" {
		return errors.New("operator is required")
	}
	if t.ApprovedBy == "" {
		return errors.New("approved_by is required")
	}
	if _, ok := allowedTaskTypes[t.Type]; !ok {
		return fmt.Errorf("unsupported task type: %s", t.Type)
	}
	if t.TTLSeconds < minTTLSeconds || t.TTLSeconds > maxTTLSeconds {
		return fmt.Errorf("TTLSeconds must be between %d and %d, got %d", minTTLSeconds, maxTTLSeconds, t.TTLSeconds)
	}
	if _, ok := validTaskStates[t.State]; !ok {
		return fmt.Errorf("invalid task state: %s", t.State)
	}
	expiry := t.CreatedAt.Add(time.Duration(t.TTLSeconds) * time.Second)
	if now.After(expiry) || now.Equal(expiry) {
		return fmt.Errorf("task expired at %s (now: %s)", expiry.UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339))
	}
	return nil
}

// SignTask cryptographically signs a task with the given private key.
// Returns a SignedTask that attests to the task's integrity and provenance (R1).
func SignTask(task Task, priv ed25519.PrivateKey, pub ed25519.PublicKey) (*SignedTask, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid private key size")
	}
	if len(pub) != ed25519.PublicKeySize {
		return nil, errors.New("invalid public key size")
	}
	if err := task.Validate(time.Now().UTC()); err != nil {
		return nil, fmt.Errorf("task validation failed: %w", err)
	}
	payload, err := json.Marshal(task)
	if err != nil {
		return nil, fmt.Errorf("marshal task: %w", err)
	}
	sig := ed25519.Sign(priv, payload)
	return &SignedTask{
		Task:      task,
		PublicKey: pub,
		Signature: sig,
	}, nil
}

// VerifyTask verifies the signature and validates the task.
func VerifyTask(st *SignedTask) error {
	if st == nil {
		return errors.New("signed task is nil")
	}
	if len(st.PublicKey) != ed25519.PublicKeySize {
		return errors.New("invalid public key size")
	}
	if len(st.Signature) != ed25519.SignatureSize {
		return errors.New("invalid signature size")
	}
	payload, err := json.Marshal(st.Task)
	if err != nil {
		return fmt.Errorf("marshal task: %w", err)
	}
	if !ed25519.Verify(st.PublicKey, payload, st.Signature) {
		return errors.New("signature verification failed")
	}
	return st.Task.Validate(time.Now().UTC())
}

// GenerateKeyPair generates a new ed25519 key pair for task signing.
func GenerateKeyPair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}
