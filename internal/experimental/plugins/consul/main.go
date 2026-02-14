// plugins/consul/main.go
// Package main provides the Consul KV storage plugin for Garmr.
//
// Build with:
//   go build -buildmode=plugin -o consul.so ./plugins/consul
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/consul/api"
	
	"github.com/infrashift/garmr/internal/experimental/plugin"
	"github.com/infrashift/garmr/internal/experimental/storage"
)

// ConsulPlugin implements storage using Consul KV.
type ConsulPlugin struct {
	client  *api.Client
	config  ConsulConfig
	backend *ConsulBackend
}

// ConsulConfig configures the Consul plugin.
type ConsulConfig struct {
	Address    string `json:"address"`
	Prefix     string `json:"prefix"`
	Datacenter string `json:"datacenter"`
	Token      string `json:"token"`
	UseTLS     bool   `json:"useTls"`
	Watch      bool   `json:"watch"`
}

func (p *ConsulPlugin) Metadata() plugin.Metadata {
	return plugin.Metadata{
		Name:        "consul",
		Type:        plugin.TypeStorage,
		Version:     "1.0.0",
		Description: "Consul KV storage backend. Supports native watching via blocking queries.",
		Author:      "Garmr",
		License:     "Apache-2.0",
		MinQVersion: "1.0.0",
		Capabilities: []string{
			"storage.read",
			"storage.watch",
			"storage.checksum",
		},
	}
}

func (p *ConsulPlugin) Init(ctx context.Context, config map[string]interface{}) error {
	// Parse config with defaults
	p.config = ConsulConfig{
		Address: "localhost:8500",
		Prefix:  "q/policies",
		Watch:   true,
	}

	if v, ok := config["address"].(string); ok {
		p.config.Address = v
	}
	if v, ok := config["prefix"].(string); ok {
		p.config.Prefix = v
	}
	if v, ok := config["datacenter"].(string); ok {
		p.config.Datacenter = v
	}
	if v, ok := config["token"].(string); ok {
		p.config.Token = v
	}
	if v, ok := config["useTls"].(bool); ok {
		p.config.UseTLS = v
	}
	if v, ok := config["watch"].(bool); ok {
		p.config.Watch = v
	}

	// Create Consul client
	consulConfig := api.DefaultConfig()
	consulConfig.Address = p.config.Address
	if p.config.Datacenter != "" {
		consulConfig.Datacenter = p.config.Datacenter
	}
	if p.config.Token != "" {
		consulConfig.Token = p.config.Token
	}
	if p.config.UseTLS {
		consulConfig.Scheme = "https"
	}

	client, err := api.NewClient(consulConfig)
	if err != nil {
		return fmt.Errorf("consul: creating client: %w", err)
	}

	p.client = client
	p.backend = &ConsulBackend{
		client: client,
		prefix: p.config.Prefix,
		watch:  p.config.Watch,
	}

	return nil
}

func (p *ConsulPlugin) Health(ctx context.Context) error {
	// Check Consul connectivity
	_, err := p.client.Status().Leader()
	return err
}

func (p *ConsulPlugin) Close() error {
	if p.backend != nil {
		return p.backend.Close()
	}
	return nil
}

func (p *ConsulPlugin) Backend() storage.Backend {
	return p.backend
}

// ConsulBackend implements storage.Backend for Consul KV.
type ConsulBackend struct {
	client *api.Client
	prefix string
	watch  bool

	stopCh   chan struct{}
	watching bool
	mu       sync.Mutex
}

func (b *ConsulBackend) Type() string {
	return "consul"
}

func (b *ConsulBackend) List(ctx context.Context, pattern string) ([]storage.FileInfo, error) {
	kv := b.client.KV()

	pairs, _, err := kv.List(b.prefix, nil)
	if err != nil {
		return nil, fmt.Errorf("consul: listing keys: %w", err)
	}

	var files []storage.FileInfo
	for _, pair := range pairs {
		// Get relative path
		relPath := strings.TrimPrefix(pair.Key, b.prefix+"/")
		if relPath == "" {
			continue
		}

		// Skip non-.cue files
		if !strings.HasSuffix(relPath, ".cue") {
			continue
		}

		// Compute checksum
		hash := sha256.Sum256(pair.Value)

		files = append(files, storage.FileInfo{
			Path:     relPath,
			Size:     int64(len(pair.Value)),
			ModTime:  time.Now(), // Consul doesn't track mod time
			Checksum: hex.EncodeToString(hash[:]),
			Metadata: map[string]string{
				"modifyIndex": fmt.Sprintf("%d", pair.ModifyIndex),
			},
		})
	}

	return files, nil
}

func (b *ConsulBackend) Get(ctx context.Context, filePath string) ([]byte, error) {
	kv := b.client.KV()
	key := path.Join(b.prefix, filePath)

	pair, _, err := kv.Get(key, nil)
	if err != nil {
		return nil, fmt.Errorf("consul: getting key: %w", err)
	}

	if pair == nil {
		return nil, &storage.ErrNotFound{Path: filePath}
	}

	return pair.Value, nil
}

func (b *ConsulBackend) GetReader(ctx context.Context, filePath string) (io.ReadCloser, error) {
	content, err := b.Get(ctx, filePath)
	if err != nil {
		return nil, err
	}
	return io.NopCloser(strings.NewReader(string(content))), nil
}

func (b *ConsulBackend) Stat(ctx context.Context, filePath string) (*storage.FileInfo, error) {
	kv := b.client.KV()
	key := path.Join(b.prefix, filePath)

	pair, _, err := kv.Get(key, nil)
	if err != nil {
		return nil, fmt.Errorf("consul: getting key: %w", err)
	}

	if pair == nil {
		return nil, &storage.ErrNotFound{Path: filePath}
	}

	hash := sha256.Sum256(pair.Value)

	return &storage.FileInfo{
		Path:     filePath,
		Size:     int64(len(pair.Value)),
		ModTime:  time.Now(),
		Checksum: hex.EncodeToString(hash[:]),
	}, nil
}

func (b *ConsulBackend) Checksum(ctx context.Context, filePath string) (string, error) {
	content, err := b.Get(ctx, filePath)
	if err != nil {
		return "", err
	}

	hash := sha256.Sum256(content)
	return "sha256:" + hex.EncodeToString(hash[:]), nil
}

func (b *ConsulBackend) Watch(ctx context.Context, pattern string) (<-chan storage.Event, error) {
	if !b.watch {
		return nil, nil
	}

	b.mu.Lock()
	if b.watching {
		b.mu.Unlock()
		return nil, nil
	}
	b.watching = true
	b.stopCh = make(chan struct{})
	b.mu.Unlock()

	events := make(chan storage.Event, 100)
	go b.watchLoop(ctx, events)

	return events, nil
}

func (b *ConsulBackend) watchLoop(ctx context.Context, events chan<- storage.Event) {
	defer close(events)

	kv := b.client.KV()
	var lastIndex uint64
	known := make(map[string]uint64) // path -> modifyIndex

	for {
		select {
		case <-ctx.Done():
			return
		case <-b.stopCh:
			return
		default:
		}

		// Blocking query - waits until something changes
		opts := &api.QueryOptions{
			WaitIndex: lastIndex,
			WaitTime:  30 * time.Second,
		}

		pairs, meta, err := kv.List(b.prefix, opts)
		if err != nil {
			select {
			case events <- storage.Event{Type: storage.EventError, Error: err}:
			default:
			}
			time.Sleep(5 * time.Second) // Back off on error
			continue
		}

		if meta.LastIndex == lastIndex {
			continue // No changes
		}
		lastIndex = meta.LastIndex

		// Check for changes
		current := make(map[string]uint64)
		for _, pair := range pairs {
			relPath := strings.TrimPrefix(pair.Key, b.prefix+"/")
			if relPath == "" || !strings.HasSuffix(relPath, ".cue") {
				continue
			}

			current[relPath] = pair.ModifyIndex

			oldIndex, existed := known[relPath]
			if !existed {
				select {
				case events <- storage.Event{Type: storage.EventCreate, Path: relPath}:
				default:
				}
			} else if oldIndex != pair.ModifyIndex {
				select {
				case events <- storage.Event{Type: storage.EventModify, Path: relPath}:
				default:
				}
			}
		}

		// Check for deletions
		for path := range known {
			if _, exists := current[path]; !exists {
				select {
				case events <- storage.Event{Type: storage.EventDelete, Path: path}:
				default:
				}
			}
		}

		known = current
	}
}

func (b *ConsulBackend) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.watching {
		close(b.stopCh)
		b.watching = false
	}

	return nil
}

// Compile-time checks
var _ plugin.StoragePlugin = (*ConsulPlugin)(nil)
var _ storage.Backend = (*ConsulBackend)(nil)

// QPlugin is the exported symbol for plugin loading.
var QPlugin plugin.Plugin = &ConsulPlugin{}
