//go:build integration

package integration

import (
	"bytes"
	"context"
	"os"
	"testing"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"

	"github.com/infrashift/garmr/internal/engine"
	"github.com/infrashift/garmr/internal/storage"

	"go.uber.org/zap"
)

const testBucket = "garmr-test-policies"

const s3TestPolicy = `package policy

s3_test: {
	apiVersion: "policy.garmr.io/v1"
	kind: "Policy"
	metadata: {
		name:      "s3-test"
		namespace: "default"
	}
	spec: {
		description: "Test policy from S3"
		target: resources: [{kind: "*"}]
		rules: [{
			id:          "s3-1"
			description: "check env"
			severity:    "high"
			expr: {match: {path: "env", equals: "prod"}}
			message: "env must be prod"
		}]
		enforcement: action: "deny"
	}
}
`

func minioEndpoint() string {
	ep := os.Getenv("MINIO_ENDPOINT")
	if ep == "" {
		return "localhost:9000"
	}
	return ep
}

func setupMinIO(t *testing.T) *minio.Client {
	t.Helper()

	client, err := minio.New(minioEndpoint(), &minio.Options{
		Creds:  credentials.NewStaticV4("minioadmin", "minioadmin", ""),
		Secure: false,
	})
	if err != nil {
		t.Fatalf("minio client: %v", err)
	}

	ctx := context.Background()

	// Create test bucket
	exists, err := client.BucketExists(ctx, testBucket)
	if err != nil {
		t.Fatalf("bucket exists: %v", err)
	}
	if !exists {
		if err := client.MakeBucket(ctx, testBucket, minio.MakeBucketOptions{}); err != nil {
			t.Fatalf("make bucket: %v", err)
		}
	}

	// Upload test policy
	reader := bytes.NewReader([]byte(s3TestPolicy))
	_, err = client.PutObject(ctx, testBucket, "policy.cue", reader, int64(len(s3TestPolicy)),
		minio.PutObjectOptions{ContentType: "text/plain"})
	if err != nil {
		t.Fatalf("put object: %v", err)
	}

	t.Cleanup(func() {
		// Clean up: remove objects and bucket
		objectCh := client.ListObjects(ctx, testBucket, minio.ListObjectsOptions{Recursive: true})
		for object := range objectCh {
			client.RemoveObject(ctx, testBucket, object.Key, minio.RemoveObjectOptions{})
		}
		client.RemoveBucket(ctx, testBucket)
	})

	return client
}

func newTestS3Backend(t *testing.T) storage.Backend {
	t.Helper()

	cfg := storage.Config{
		Type: "s3",
		Options: map[string]interface{}{
			"endpoint":        minioEndpoint(),
			"bucket":          testBucket,
			"region":          "us-east-1",
			"accessKeyId":     "minioadmin",
			"secretAccessKey": "minioadmin",
			"useSsl":          false,
			"pollInterval":    "1s",
		},
	}

	backend, err := storage.New(cfg)
	if err != nil {
		t.Fatalf("New(s3): %v", err)
	}
	t.Cleanup(func() { backend.Close() })
	return backend
}

func TestS3Backend_List(t *testing.T) {
	setupMinIO(t)
	backend := newTestS3Backend(t)

	files, err := backend.List(context.Background(), "**/*.cue")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(files) == 0 {
		t.Error("expected at least 1 file")
	}
}

func TestS3Backend_Get(t *testing.T) {
	setupMinIO(t)
	backend := newTestS3Backend(t)

	content, err := backend.Get(context.Background(), "policy.cue")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(content) != s3TestPolicy {
		t.Errorf("expected policy content, got %q", content)
	}
}

func TestS3Backend_Stat(t *testing.T) {
	setupMinIO(t)
	backend := newTestS3Backend(t)

	info, err := backend.Stat(context.Background(), "policy.cue")
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if info.Size == 0 {
		t.Error("expected non-zero file size")
	}
	if info.Path != "policy.cue" {
		t.Errorf("expected path=policy.cue, got %s", info.Path)
	}
}

func TestS3Backend_Checksum(t *testing.T) {
	setupMinIO(t)
	backend := newTestS3Backend(t)

	checksum, err := backend.Checksum(context.Background(), "policy.cue")
	if err != nil {
		t.Fatalf("Checksum: %v", err)
	}
	if checksum == "" {
		t.Error("expected non-empty checksum")
	}
}

func TestS3Backend_Watch_Polling(t *testing.T) {
	client := setupMinIO(t)
	backend := newTestS3Backend(t)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	events, err := backend.Watch(ctx, "**/*.cue")
	if err != nil {
		t.Fatalf("Watch: %v", err)
	}
	if events == nil {
		t.Fatal("expected non-nil events channel")
	}

	// Wait for initial scan
	time.Sleep(2 * time.Second)

	// Upload a new file
	newPolicy := `package policy
new_test: {
	apiVersion: "policy.garmr.io/v1"
	kind: "Policy"
	metadata: { name: "new-test", namespace: "default" }
	spec: {
		description: "new"
		target: resources: [{kind: "*"}]
		rules: [{id: "n1", description: "new", severity: "low", expr: {match: {path: "x", equals: 1}}, message: "fail"}]
		enforcement: action: "deny"
	}
}
`
	reader := bytes.NewReader([]byte(newPolicy))
	_, err = client.PutObject(ctx, testBucket, "new-policy.cue", reader, int64(len(newPolicy)),
		minio.PutObjectOptions{ContentType: "text/plain"})
	if err != nil {
		t.Fatalf("upload new policy: %v", err)
	}

	// Wait for create event
	select {
	case event := <-events:
		if event.Type != storage.EventCreate {
			t.Errorf("expected EventCreate, got %v", event.Type)
		}
	case <-time.After(10 * time.Second):
		t.Error("timed out waiting for S3 change event")
	}
}

func TestS3Backend_LoadPoliciesFromBackend(t *testing.T) {
	setupMinIO(t)
	backend := newTestS3Backend(t)

	eng, err := engine.NewEngine(zap.NewNop())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	err = eng.LoadPoliciesFromBackend(context.Background(), backend)
	if err != nil {
		t.Fatalf("LoadPoliciesFromBackend: %v", err)
	}

	policies := eng.ListPolicies("")
	if len(policies) == 0 {
		t.Error("expected at least 1 policy loaded from S3")
	}

	// Evaluate against the loaded policy
	result, err := eng.Evaluate(context.Background(), &engine.EvaluateRequest{
		Input: map[string]any{"env": "prod"},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if result.Decision != engine.DecisionAllow {
		t.Errorf("expected allow, got %s", result.Decision)
	}
}

func TestS3Backend_ReloadPoliciesFromBackend(t *testing.T) {
	setupMinIO(t)
	backend := newTestS3Backend(t)

	eng, err := engine.NewEngine(zap.NewNop())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	count, err := eng.ReloadPoliciesFromBackend(context.Background(), backend)
	if err != nil {
		t.Fatalf("ReloadPoliciesFromBackend: %v", err)
	}
	if count == 0 {
		t.Error("expected at least 1 policy reloaded from S3")
	}
}

func TestS3Backend_ErrorHandling(t *testing.T) {
	t.Run("missing_bucket", func(t *testing.T) {
		cfg := storage.Config{
			Type: "s3",
			Options: map[string]interface{}{
				"endpoint":        minioEndpoint(),
				"bucket":          "nonexistent-bucket-12345",
				"accessKeyId":     "minioadmin",
				"secretAccessKey": "minioadmin",
				"useSsl":          false,
			},
		}
		backend, err := storage.New(cfg)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		defer backend.Close()

		_, err = backend.List(context.Background(), "**/*.cue")
		if err == nil {
			t.Error("expected error for nonexistent bucket")
		}
	})

	t.Run("missing_object", func(t *testing.T) {
		setupMinIO(t)
		backend := newTestS3Backend(t)

		_, err := backend.Get(context.Background(), "nonexistent-file.cue")
		if err == nil {
			t.Error("expected error for missing object")
		}
	})

	t.Run("bad_credentials", func(t *testing.T) {
		cfg := storage.Config{
			Type: "s3",
			Options: map[string]interface{}{
				"endpoint":        minioEndpoint(),
				"bucket":          testBucket,
				"accessKeyId":     "wrong",
				"secretAccessKey": "wrong",
				"useSsl":          false,
			},
		}
		backend, err := storage.New(cfg)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		defer backend.Close()

		_, err = backend.List(context.Background(), "**/*.cue")
		if err == nil {
			t.Error("expected error for bad credentials")
		}
	})
}
