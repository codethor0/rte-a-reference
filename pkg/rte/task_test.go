package rte

import (
	"crypto/ed25519"
	"encoding/json"
	"testing"
	"time"
)

func validTask(t time.Time) Task {
	return Task{
		ID:         "task-001",
		Engagement: "eng-2026-q1",
		Type:       TaskTypeRecon,
		CreatedAt:  t,
		TTLSeconds: 600,
		Operator:   "op-alice",
		ApprovedBy: "lead-bob",
		State:      TaskStateApproved,
		Params:     map[string]string{"target": "192.168.1.0/24"},
	}
}

func TestTask_Validate_Valid(t *testing.T) {
	now := time.Now().UTC()
	task := validTask(now.Add(-5 * time.Minute))
	if err := task.Validate(now); err != nil {
		t.Fatalf("expected valid task, got: %v", err)
	}
}

func TestTask_Validate_Expired(t *testing.T) {
	now := time.Now().UTC()
	task := validTask(now.Add(-20 * time.Minute))
	task.TTLSeconds = 600
	if err := task.Validate(now); err == nil {
		t.Fatal("expected expired task to fail validation")
	}
}

func TestTask_Validate_UnsupportedType(t *testing.T) {
	now := time.Now().UTC()
	task := validTask(now)
	task.Type = TaskType("malware")
	if err := task.Validate(now); err == nil {
		t.Fatal("expected unsupported type to fail validation")
	}
}

func TestTask_Validate_EmptyID(t *testing.T) {
	now := time.Now().UTC()
	task := validTask(now)
	task.ID = ""
	if err := task.Validate(now); err == nil {
		t.Fatal("expected empty ID to fail validation")
	}
}

func TestTask_Validate_EmptyOperator(t *testing.T) {
	now := time.Now().UTC()
	task := validTask(now)
	task.Operator = ""
	if err := task.Validate(now); err == nil {
		t.Fatal("expected empty operator to fail validation")
	}
}

func TestTask_Validate_TTLOutOfRange(t *testing.T) {
	now := time.Now().UTC()
	task := validTask(now)
	task.TTLSeconds = 0
	if err := task.Validate(now); err == nil {
		t.Fatal("expected TTL 0 to fail validation")
	}
	task.TTLSeconds = 5000
	if err := task.Validate(now); err == nil {
		t.Fatal("expected TTL > 3600 to fail validation")
	}
}

func TestSignTask_Valid(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}
	now := time.Now().UTC()
	task := validTask(now)
	st, err := SignTask(task, priv, pub)
	if err != nil {
		t.Fatalf("SignTask: %v", err)
	}
	if st == nil {
		t.Fatal("expected non-nil SignedTask")
	}
	if len(st.Signature) != ed25519.SignatureSize {
		t.Errorf("signature size: got %d, want %d", len(st.Signature), ed25519.SignatureSize)
	}
}

func TestVerifyTask_Valid(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}
	now := time.Now().UTC()
	task := validTask(now)
	st, err := SignTask(task, priv, pub)
	if err != nil {
		t.Fatalf("SignTask: %v", err)
	}
	if err := VerifyTask(st); err != nil {
		t.Fatalf("VerifyTask: %v", err)
	}
}

func TestVerifyTask_InvalidSignature(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}
	now := time.Now().UTC()
	task := validTask(now)
	st, err := SignTask(task, priv, pub)
	if err != nil {
		t.Fatalf("SignTask: %v", err)
	}
	st.Signature[0] ^= 0xff
	if err := VerifyTask(st); err == nil {
		t.Fatal("expected tampered signature to fail verification")
	}
}

func TestVerifyTask_TamperedTask(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}
	now := time.Now().UTC()
	task := validTask(now)
	st, err := SignTask(task, priv, pub)
	if err != nil {
		t.Fatalf("SignTask: %v", err)
	}
	st.Task.ID = "tampered-id"
	if err := VerifyTask(st); err == nil {
		t.Fatal("expected tampered task to fail verification")
	}
}

func TestVerifyTask_NilSignedTask(t *testing.T) {
	if err := VerifyTask(nil); err == nil {
		t.Fatal("expected nil SignedTask to fail")
	}
}

func TestSignTask_InvalidKey(t *testing.T) {
	now := time.Now().UTC()
	task := validTask(now)
	_, err := SignTask(task, []byte("short"), make([]byte, ed25519.PublicKeySize))
	if err == nil {
		t.Fatal("expected invalid private key to fail")
	}
}

func TestMarshalUnmarshalConsistency(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}
	now := time.Now().UTC()
	task := validTask(now)
	st, err := SignTask(task, priv, pub)
	if err != nil {
		t.Fatalf("SignTask: %v", err)
	}
	data, err := json.Marshal(st)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var st2 SignedTask
	if err := json.Unmarshal(data, &st2); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if err := VerifyTask(&st2); err != nil {
		t.Fatalf("VerifyTask after roundtrip: %v", err)
	}
}
