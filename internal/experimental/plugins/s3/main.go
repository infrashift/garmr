// plugins/s3/main.go
// Package main provides the S3/MinIO storage plugin for Q Policy Agent.
// This is built as a shared library (.so/.dylib) and loaded at runtime.
//
// Build with:
//   go build -buildmode=plugin -o s3.so ./plugins/s3
package main

import (
	"context"
	"fmt"

	"github.com/infrashift/q-policy-agent/internal/plugin"
	"github.com/infrashift/q-policy-agent/internal/storage"
)

// S3Plugin implements the S3/MinIO storage backend.
type S3Plugin struct {
	backend storage.Backend
	config  S3Config
}

// S3Config configures the S3 plugin.
type S3Config struct {
	Endpoint        string `json:"endpoint"`
	Region          string `json:"region"`
	Bucket          string `json:"bucket"`
	AccessKeyID     string `json:"accessKeyId"`
	SecretAccessKey string `json:"secretAccessKey"`
	SessionToken    string `json:"sessionToken"`
	UseSSL          bool   `json:"useSsl"`
	PollInterval    string `json:"pollInterval"`
	UseSHA256       bool   `json:"useSha256"`
	Root            string `json:"root"`
}

func (p *S3Plugin) Metadata() plugin.Metadata {
	return plugin.Metadata{
		Name:        "s3",
		Type:        plugin.TypeStorage,
		Version:     "1.0.0",
		Description: "S3-compatible storage backend. Works with AWS S3, MinIO, and other S3-compatible services.",
		Author:      "Q Policy Agent",
		License:     "Apache-2.0",
		Homepage:    "https://github.com/infrashift/q-policy-agent",
		MinQVersion: "1.0.0",
		Capabilities: []string{
			"storage.read",
			"storage.poll",
			"storage.checksum",
		},
	}
}

func (p *S3Plugin) Init(ctx context.Context, config map[string]interface{}) error {
	// Parse config with defaults
	p.config = S3Config{
		Region:       "us-east-1",
		UseSSL:       true,
		PollInterval: "10s",
		Root:         "",
	}

	if v, ok := config["endpoint"].(string); ok {
		p.config.Endpoint = v
	}
	if v, ok := config["region"].(string); ok {
		p.config.Region = v
	}
	if v, ok := config["bucket"].(string); ok {
		p.config.Bucket = v
	}
	if v, ok := config["accessKeyId"].(string); ok {
		p.config.AccessKeyID = v
	}
	if v, ok := config["secretAccessKey"].(string); ok {
		p.config.SecretAccessKey = v
	}
	if v, ok := config["sessionToken"].(string); ok {
		p.config.SessionToken = v
	}
	if v, ok := config["useSsl"].(bool); ok {
		p.config.UseSSL = v
	}
	if v, ok := config["pollInterval"].(string); ok {
		p.config.PollInterval = v
	}
	if v, ok := config["useSha256"].(bool); ok {
		p.config.UseSHA256 = v
	}
	if v, ok := config["root"].(string); ok {
		p.config.Root = v
	}

	if p.config.Bucket == "" {
		return fmt.Errorf("s3: bucket is required")
	}

	// Create storage backend
	backend, err := storage.NewS3Backend(storage.Config{
		Type: "s3",
		Root: p.config.Root,
		Options: map[string]interface{}{
			"endpoint":        p.config.Endpoint,
			"region":          p.config.Region,
			"bucket":          p.config.Bucket,
			"accessKeyId":     p.config.AccessKeyID,
			"secretAccessKey": p.config.SecretAccessKey,
			"sessionToken":    p.config.SessionToken,
			"useSsl":          p.config.UseSSL,
			"pollInterval":    p.config.PollInterval,
		},
	})
	if err != nil {
		return fmt.Errorf("s3: creating backend: %w", err)
	}

	p.backend = backend
	return nil
}

func (p *S3Plugin) Health(ctx context.Context) error {
	// Try to list objects (validates credentials and bucket access)
	_, err := p.backend.List(ctx, "")
	return err
}

func (p *S3Plugin) Close() error {
	if p.backend != nil {
		return p.backend.Close()
	}
	return nil
}

func (p *S3Plugin) Backend() storage.Backend {
	return p.backend
}

// QPlugin is the symbol exported for plugin loading.
// The plugin manager looks for this symbol.
var QPlugin plugin.Plugin = &S3Plugin{}
