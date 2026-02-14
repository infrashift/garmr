//go:build integration

package integration

import (
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	// Wait for MinIO to be healthy
	endpoint := os.Getenv("MINIO_ENDPOINT")
	if endpoint == "" {
		endpoint = "localhost:9000"
	}

	healthURL := fmt.Sprintf("http://%s/minio/health/live", endpoint)
	fmt.Printf("Waiting for MinIO at %s...\n", healthURL)

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(healthURL)
		if err == nil && resp.StatusCode == http.StatusOK {
			resp.Body.Close()
			fmt.Println("MinIO is ready")
			os.Exit(m.Run())
		}
		if resp != nil {
			resp.Body.Close()
		}
		time.Sleep(1 * time.Second)
	}

	fmt.Fprintln(os.Stderr, "FATAL: MinIO did not become ready within 30s")
	os.Exit(1)
}
