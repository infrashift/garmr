// plugins/audit-file/main.go
// Package main provides a file-based audit log plugin for Garmr.
// Simple decision logging to files - ideal for small deployments, debugging,
// and environments without Kafka infrastructure.
//
// This plugin is built-in and serves as the default audit logger.
package main

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/infrashift/garmr/internal/experimental/plugin"
)

// FileAuditPlugin logs policy decisions to files.
type FileAuditPlugin struct {
	config FileAuditConfig
	mu     sync.Mutex

	// Current log file
	file     *os.File
	writer   *bufio.Writer
	encoder  *json.Encoder
	fileSize int64

	// Rotation state
	lastRotate time.Time

	closed bool
}

// FileAuditConfig configures file-based audit logging.
type FileAuditConfig struct {
	// Enabled controls audit logging
	Enabled bool `json:"enabled"`

	// Path to audit log file
	Path string `json:"path"`

	// Format: json, jsonl (JSON lines), text
	Format string `json:"format"`

	// Rotation settings
	Rotation FileRotationConfig `json:"rotation"`

	// BufferSize for write buffering (0 = unbuffered)
	BufferSize int `json:"bufferSize"`

	// SyncOnWrite forces fsync after each write
	SyncOnWrite bool `json:"syncOnWrite"`

	// Privacy settings
	Privacy AuditPrivacyConfig `json:"privacy"`

	// IncludeFields controls which fields to include
	IncludeFields IncludeFieldsConfig `json:"includeFields"`
}

// FileRotationConfig configures log rotation.
type FileRotationConfig struct {
	// Enabled enables log rotation
	Enabled bool `json:"enabled"`

	// MaxSize in bytes before rotation (0 = no size limit)
	MaxSize int64 `json:"maxSize"`

	// MaxAge in hours before rotation (0 = no age limit)
	MaxAge int `json:"maxAge"`

	// MaxBackups is number of old files to keep (0 = keep all)
	MaxBackups int `json:"maxBackups"`

	// Compress old log files with gzip
	Compress bool `json:"compress"`

	// RotateOnStartup rotates existing file on startup
	RotateOnStartup bool `json:"rotateOnStartup"`
}

// AuditPrivacyConfig controls privacy in audit logs.
type AuditPrivacyConfig struct {
	// HashInput hashes input data
	HashInput bool `json:"hashInput"`

	// ExcludeInput removes input entirely
	ExcludeInput bool `json:"excludeInput"`

	// RedactFields removes specific fields
	RedactFields []string `json:"redactFields"`
}

// IncludeFieldsConfig controls which fields appear in audit logs.
type IncludeFieldsConfig struct {
	Timestamp  bool `json:"timestamp"`
	ID         bool `json:"id"`
	Policy     bool `json:"policy"`
	Namespace  bool `json:"namespace"`
	Decision   bool `json:"decision"`
	Violations bool `json:"violations"`
	Input      bool `json:"input"`
	Context    bool `json:"context"`
	Timing     bool `json:"timing"`
}

// AuditEntry is a single audit log entry.
type AuditEntry struct {
	Timestamp  string           `json:"timestamp,omitempty"`
	ID         string           `json:"id,omitempty"`
	Policy     string           `json:"policy,omitempty"`
	Namespace  string           `json:"namespace,omitempty"`
	Decision   string           `json:"decision,omitempty"`
	Violations []ViolationEntry `json:"violations,omitempty"`
	Input      interface{}      `json:"input,omitempty"`
	InputHash  string           `json:"inputHash,omitempty"`
	Context    *ContextEntry    `json:"context,omitempty"`
	Timing     *TimingEntry     `json:"timing,omitempty"`
}

// ViolationEntry represents a violation in audit logs.
type ViolationEntry struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	Message  string `json:"message,omitempty"`
}

// ContextEntry represents request context in audit logs.
type ContextEntry struct {
	Principal string `json:"principal,omitempty"`
	SourceIP  string `json:"sourceIp,omitempty"`
	TraceID   string `json:"traceId,omitempty"`
	RequestID string `json:"requestId,omitempty"`
}

// TimingEntry represents timing information.
type TimingEntry struct {
	DurationMs int64 `json:"durationMs"`
}

func (p *FileAuditPlugin) Metadata() plugin.Metadata {
	return plugin.Metadata{
		Name:        "audit-file",
		Type:        plugin.TypeNotifier,
		Version:     "1.0.0",
		Description: "File-based audit logging for policy decisions. Simple, no external dependencies.",
		Author:      "Garmr",
		License:     "Apache-2.0",
		Builtin:     true,
		Capabilities: []string{
			"audit.file",
			"audit.local",
		},
	}
}

func (p *FileAuditPlugin) Init(ctx context.Context, config map[string]interface{}) error {
	// Parse config with defaults
	p.config = FileAuditConfig{
		Enabled:    true,
		Path:       "/var/log/garmr/audit.log",
		Format:     "jsonl",
		BufferSize: 4096,
		Rotation: FileRotationConfig{
			Enabled:    true,
			MaxSize:    100 * 1024 * 1024, // 100MB
			MaxAge:     168,               // 7 days
			MaxBackups: 10,
			Compress:   true,
		},
		IncludeFields: IncludeFieldsConfig{
			Timestamp:  true,
			ID:         true,
			Policy:     true,
			Namespace:  true,
			Decision:   true,
			Violations: true,
			Input:      false, // Off by default for privacy
			Context:    true,
			Timing:     true,
		},
	}

	// Parse enabled
	if v, ok := config["enabled"].(bool); ok {
		p.config.Enabled = v
	}
	if v, ok := config["path"].(string); ok {
		p.config.Path = v
	}
	if v, ok := config["format"].(string); ok {
		p.config.Format = v
	}
	if v, ok := config["bufferSize"].(float64); ok {
		p.config.BufferSize = int(v)
	}
	if v, ok := config["syncOnWrite"].(bool); ok {
		p.config.SyncOnWrite = v
	}

	// Parse rotation config
	if rot, ok := config["rotation"].(map[string]interface{}); ok {
		if v, ok := rot["enabled"].(bool); ok {
			p.config.Rotation.Enabled = v
		}
		if v, ok := rot["maxSize"].(float64); ok {
			p.config.Rotation.MaxSize = int64(v)
		}
		if v, ok := rot["maxAge"].(float64); ok {
			p.config.Rotation.MaxAge = int(v)
		}
		if v, ok := rot["maxBackups"].(float64); ok {
			p.config.Rotation.MaxBackups = int(v)
		}
		if v, ok := rot["compress"].(bool); ok {
			p.config.Rotation.Compress = v
		}
	}

	// Parse privacy config
	if priv, ok := config["privacy"].(map[string]interface{}); ok {
		if v, ok := priv["hashInput"].(bool); ok {
			p.config.Privacy.HashInput = v
		}
		if v, ok := priv["excludeInput"].(bool); ok {
			p.config.Privacy.ExcludeInput = v
		}
	}

	// Parse include fields
	if inc, ok := config["includeFields"].(map[string]interface{}); ok {
		if v, ok := inc["timestamp"].(bool); ok {
			p.config.IncludeFields.Timestamp = v
		}
		if v, ok := inc["id"].(bool); ok {
			p.config.IncludeFields.ID = v
		}
		if v, ok := inc["policy"].(bool); ok {
			p.config.IncludeFields.Policy = v
		}
		if v, ok := inc["namespace"].(bool); ok {
			p.config.IncludeFields.Namespace = v
		}
		if v, ok := inc["decision"].(bool); ok {
			p.config.IncludeFields.Decision = v
		}
		if v, ok := inc["violations"].(bool); ok {
			p.config.IncludeFields.Violations = v
		}
		if v, ok := inc["input"].(bool); ok {
			p.config.IncludeFields.Input = v
		}
		if v, ok := inc["context"].(bool); ok {
			p.config.IncludeFields.Context = v
		}
		if v, ok := inc["timing"].(bool); ok {
			p.config.IncludeFields.Timing = v
		}
	}

	if !p.config.Enabled {
		return nil
	}

	// Create directory if needed
	dir := filepath.Dir(p.config.Path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("creating log directory: %w", err)
	}

	// Rotate on startup if configured
	if p.config.Rotation.RotateOnStartup {
		if _, err := os.Stat(p.config.Path); err == nil {
			p.rotate()
		}
	}

	// Open log file
	if err := p.openFile(); err != nil {
		return fmt.Errorf("opening log file: %w", err)
	}

	p.lastRotate = time.Now()

	return nil
}

func (p *FileAuditPlugin) openFile() error {
	f, err := os.OpenFile(p.config.Path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}

	info, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}

	p.file = f
	p.fileSize = info.Size()

	if p.config.BufferSize > 0 {
		p.writer = bufio.NewWriterSize(f, p.config.BufferSize)
		p.encoder = json.NewEncoder(p.writer)
	} else {
		p.encoder = json.NewEncoder(f)
	}

	return nil
}

func (p *FileAuditPlugin) Health(ctx context.Context) error {
	if !p.config.Enabled {
		return nil
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if p.file == nil {
		return fmt.Errorf("log file not open")
	}

	return nil
}

func (p *FileAuditPlugin) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return nil
	}
	p.closed = true

	if p.writer != nil {
		p.writer.Flush()
	}
	if p.file != nil {
		return p.file.Close()
	}

	return nil
}

// LogDecision logs a policy decision.
func (p *FileAuditPlugin) LogDecision(entry *AuditEntry) error {
	if !p.config.Enabled {
		return nil
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed || p.file == nil {
		return fmt.Errorf("audit log not open")
	}

	// Check rotation
	if p.shouldRotate() {
		if err := p.rotate(); err != nil {
			// Log rotation error but continue
			fmt.Fprintf(os.Stderr, "audit log rotation error: %v\n", err)
		}
	}

	// Apply field filtering
	filtered := p.filterFields(entry)

	// Write entry
	var err error
	switch p.config.Format {
	case "json":
		p.encoder.SetIndent("", "  ")
		err = p.encoder.Encode(filtered)
	case "jsonl", "json-lines":
		err = p.encoder.Encode(filtered)
	case "text":
		_, err = fmt.Fprintf(p.getWriter(), "%s [%s] policy=%s namespace=%s decision=%s violations=%d\n",
			entry.Timestamp, entry.ID, entry.Policy, entry.Namespace, entry.Decision, len(entry.Violations))
	default:
		err = p.encoder.Encode(filtered)
	}

	if err != nil {
		return fmt.Errorf("writing audit entry: %w", err)
	}

	// Update file size estimate
	p.fileSize += 500 // Approximate

	// Sync if configured
	if p.config.SyncOnWrite {
		if p.writer != nil {
			p.writer.Flush()
		}
		p.file.Sync()
	}

	return nil
}

func (p *FileAuditPlugin) getWriter() io.Writer {
	if p.writer != nil {
		return p.writer
	}
	return p.file
}

func (p *FileAuditPlugin) filterFields(entry *AuditEntry) *AuditEntry {
	filtered := &AuditEntry{}

	if p.config.IncludeFields.Timestamp {
		filtered.Timestamp = entry.Timestamp
	}
	if p.config.IncludeFields.ID {
		filtered.ID = entry.ID
	}
	if p.config.IncludeFields.Policy {
		filtered.Policy = entry.Policy
	}
	if p.config.IncludeFields.Namespace {
		filtered.Namespace = entry.Namespace
	}
	if p.config.IncludeFields.Decision {
		filtered.Decision = entry.Decision
	}
	if p.config.IncludeFields.Violations {
		filtered.Violations = entry.Violations
	}
	if p.config.IncludeFields.Input && !p.config.Privacy.ExcludeInput {
		if p.config.Privacy.HashInput {
			filtered.InputHash = entry.InputHash
		} else {
			filtered.Input = entry.Input
		}
	}
	if p.config.IncludeFields.Context {
		filtered.Context = entry.Context
	}
	if p.config.IncludeFields.Timing {
		filtered.Timing = entry.Timing
	}

	return filtered
}

func (p *FileAuditPlugin) shouldRotate() bool {
	if !p.config.Rotation.Enabled {
		return false
	}

	// Size-based rotation
	if p.config.Rotation.MaxSize > 0 && p.fileSize >= p.config.Rotation.MaxSize {
		return true
	}

	// Age-based rotation
	if p.config.Rotation.MaxAge > 0 {
		age := time.Since(p.lastRotate)
		if age >= time.Duration(p.config.Rotation.MaxAge)*time.Hour {
			return true
		}
	}

	return false
}

func (p *FileAuditPlugin) rotate() error {
	// Flush and close current file
	if p.writer != nil {
		p.writer.Flush()
	}
	if p.file != nil {
		p.file.Close()
	}

	// Generate rotated filename
	timestamp := time.Now().Format("20060102-150405")
	rotatedPath := fmt.Sprintf("%s.%s", p.config.Path, timestamp)

	// Rename current file
	if err := os.Rename(p.config.Path, rotatedPath); err != nil {
		// File might not exist, which is OK
		if !os.IsNotExist(err) {
			return fmt.Errorf("renaming log file: %w", err)
		}
	}

	// Compress if configured
	if p.config.Rotation.Compress {
		go p.compressFile(rotatedPath)
	}

	// Clean up old backups
	if p.config.Rotation.MaxBackups > 0 {
		go p.cleanupBackups()
	}

	// Open new file
	if err := p.openFile(); err != nil {
		return fmt.Errorf("opening new log file: %w", err)
	}

	p.lastRotate = time.Now()

	return nil
}

func (p *FileAuditPlugin) compressFile(path string) {
	// Read original file
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}

	// Create gzip file
	gzPath := path + ".gz"
	gzFile, err := os.Create(gzPath)
	if err != nil {
		return
	}
	defer gzFile.Close()

	// Write compressed data
	gzWriter := gzip.NewWriter(gzFile)
	gzWriter.Write(data)
	gzWriter.Close()

	// Remove original
	os.Remove(path)
}

func (p *FileAuditPlugin) cleanupBackups() {
	dir := filepath.Dir(p.config.Path)
	base := filepath.Base(p.config.Path)

	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}

	var backups []string
	for _, entry := range entries {
		name := entry.Name()
		if name != base && len(name) > len(base) && name[:len(base)] == base {
			backups = append(backups, filepath.Join(dir, name))
		}
	}

	// Sort by modification time (oldest first)
	// Remove excess backups
	if len(backups) > p.config.Rotation.MaxBackups {
		toRemove := len(backups) - p.config.Rotation.MaxBackups
		for i := 0; i < toRemove; i++ {
			os.Remove(backups[i])
		}
	}
}

// Flush flushes the write buffer.
func (p *FileAuditPlugin) Flush() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.writer != nil {
		return p.writer.Flush()
	}
	return nil
}

// QPlugin is the exported symbol for plugin loading.
var QPlugin plugin.Plugin = &FileAuditPlugin{}
