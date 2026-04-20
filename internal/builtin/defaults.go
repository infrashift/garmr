// internal/builtin/defaults.go
// Package builtin provides built-in plugins and default configuration.
// These plugins are compiled into Garmr and serve as defaults.
package builtin

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"time"
)

// ============================================
// DEFAULT LOGGING (slog-based, always available)
// ============================================

// DefaultLogger provides structured logging using slog.
// This is the default logger and is always available.
type DefaultLogger struct {
	logger *slog.Logger
	level  slog.Level
}

// LoggingConfig configures the default logger.
type LoggingConfig struct {
	Level      string            // debug, info, warn, error
	Format     string            // json, text
	Output     string            // stdout, stderr, or file path
	AddSource  bool              // Include source location
	TimeFormat string            // Timestamp format
	Fields     map[string]string // Default fields
}

// DefaultLoggingConfig returns sensible defaults.
func DefaultLoggingConfig() LoggingConfig {
	return LoggingConfig{
		Level:      "info",
		Format:     "json",
		Output:     "stdout",
		AddSource:  false,
		TimeFormat: time.RFC3339,
	}
}

// NewDefaultLogger creates the default slog-based logger.
func NewDefaultLogger(cfg LoggingConfig) *DefaultLogger {
	level := parseLevel(cfg.Level)
	output := parseOutput(cfg.Output)

	opts := &slog.HandlerOptions{
		Level:     level,
		AddSource: cfg.AddSource,
	}

	var handler slog.Handler
	if cfg.Format == "text" {
		handler = slog.NewTextHandler(output, opts)
	} else {
		handler = slog.NewJSONHandler(output, opts)
	}

	logger := slog.New(handler)

	// Add default fields
	if len(cfg.Fields) > 0 {
		attrs := make([]any, 0, len(cfg.Fields)*2)
		for k, v := range cfg.Fields {
			attrs = append(attrs, k, v)
		}
		logger = logger.With(attrs...)
	}

	return &DefaultLogger{
		logger: logger,
		level:  level,
	}
}

func parseLevel(level string) slog.Level {
	switch level {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func parseOutput(output string) io.Writer {
	switch output {
	case "stdout", "":
		return os.Stdout
	case "stderr":
		return os.Stderr
	default:
		f, err := os.OpenFile(output, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to open log file %s: %v, using stdout\n", output, err)
			return os.Stdout
		}
		return f
	}
}

// Logger returns the underlying slog.Logger.
func (l *DefaultLogger) Logger() *slog.Logger {
	return l.logger
}

// Debug logs at debug level.
func (l *DefaultLogger) Debug(msg string, args ...any) {
	l.logger.Debug(msg, args...)
}

// Info logs at info level.
func (l *DefaultLogger) Info(msg string, args ...any) {
	l.logger.Info(msg, args...)
}

// Warn logs at warn level.
func (l *DefaultLogger) Warn(msg string, args ...any) {
	l.logger.Warn(msg, args...)
}

// Error logs at error level.
func (l *DefaultLogger) Error(msg string, args ...any) {
	l.logger.Error(msg, args...)
}

// With returns a logger with additional context.
func (l *DefaultLogger) With(args ...any) *slog.Logger {
	return l.logger.With(args...)
}

// LogEvaluation logs a policy evaluation event.
func (l *DefaultLogger) LogEvaluation(ctx context.Context, policy, namespace, decision string, duration time.Duration) {
	l.logger.InfoContext(ctx, "policy evaluation",
		"event", "evaluation",
		"policy", policy,
		"namespace", namespace,
		"decision", decision,
		"durationMs", duration.Milliseconds(),
	)
}

// LogViolation logs a policy violation.
func (l *DefaultLogger) LogViolation(ctx context.Context, policy, ruleID, severity, message string) {
	lvl := slog.LevelWarn
	if severity == "critical" || severity == "high" {
		lvl = slog.LevelError
	}

	l.logger.Log(ctx, lvl, "policy violation",
		"event", "violation",
		"policy", policy,
		"ruleId", ruleID,
		"severity", severity,
		"message", message,
	)
}

// LogPolicyLoad logs a policy load event.
func (l *DefaultLogger) LogPolicyLoad(ctx context.Context, policy, namespace, path string, err error) {
	if err != nil {
		l.logger.ErrorContext(ctx, "policy load failed",
			"event", "policy.load.error",
			"policy", policy,
			"namespace", namespace,
			"path", path,
			"error", err.Error(),
		)
	} else {
		l.logger.InfoContext(ctx, "policy loaded",
			"event", "policy.load",
			"policy", policy,
			"namespace", namespace,
			"path", path,
		)
	}
}

// ============================================
// DEFAULT FILE AUDIT LOGGER
// ============================================

// DefaultAuditLogger writes audit entries to a file.
// This is a simplified version for built-in use.
type DefaultAuditLogger struct {
	file   *os.File
	logger *slog.Logger
}

// AuditConfig configures the default audit logger.
type AuditConfig struct {
	Enabled bool
	Path    string
	Format  string // json, jsonl
}

// DefaultAuditConfig returns sensible defaults.
func DefaultAuditConfig() AuditConfig {
	return AuditConfig{
		Enabled: true,
		Path:    "/var/log/garmr/audit.log",
		Format:  "jsonl",
	}
}

// NewDefaultAuditLogger creates the default file-based audit logger.
func NewDefaultAuditLogger(cfg AuditConfig) (*DefaultAuditLogger, error) {
	if !cfg.Enabled {
		return nil, nil
	}

	// Create directory
	if err := os.MkdirAll(filepath.Dir(cfg.Path), 0755); err != nil {
		return nil, fmt.Errorf("creating audit log directory: %w", err)
	}

	// Open file
	f, err := os.OpenFile(cfg.Path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("opening audit log: %w", err)
	}

	// Create JSON logger for the file
	handler := slog.NewJSONHandler(f, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})
	logger := slog.New(handler)

	return &DefaultAuditLogger{
		file:   f,
		logger: logger,
	}, nil
}

// LogDecision logs an audit decision.
func (a *DefaultAuditLogger) LogDecision(
	id, policy, namespace, decision string,
	violations int,
	principal, sourceIP, traceID string,
	durationMs int64,
) {
	a.logger.Info("audit",
		"id", id,
		"timestamp", time.Now().UTC().Format(time.RFC3339),
		"policy", policy,
		"namespace", namespace,
		"decision", decision,
		"violations", violations,
		"principal", principal,
		"sourceIp", sourceIP,
		"traceId", traceID,
		"durationMs", durationMs,
	)
}

// Close closes the audit log file.
func (a *DefaultAuditLogger) Close() error {
	if a.file != nil {
		return a.file.Close()
	}
	return nil
}

// ============================================
// DEFAULTS REGISTRY
// ============================================

// Defaults holds default plugin configurations.
var Defaults = struct {
	// Storage backend
	StorageBackend string
	StorageConfig  map[string]interface{}

	// Audit logging
	AuditBackend string
	AuditConfig  map[string]interface{}

	// Logging
	LoggingConfig LoggingConfig
}{
	StorageBackend: "filesystem",
	StorageConfig: map[string]interface{}{
		"root": "/etc/garmr/policies",
	},

	AuditBackend: "audit-file",
	AuditConfig: map[string]interface{}{
		"enabled": true,
		"path":    "/var/log/garmr/audit.log",
		"format":  "jsonl",
		"rotation": map[string]interface{}{
			"enabled":    true,
			"maxSize":    104857600, // 100MB
			"maxBackups": 10,
			"compress":   true,
		},
	},

	LoggingConfig: LoggingConfig{
		Level:  "info",
		Format: "json",
		Output: "stdout",
	},
}

// RequiredPlugins lists plugins that must be loaded.
var RequiredPlugins = []string{
	"filesystem", // Storage - built-in
	"audit-file", // Audit - built-in
}

// OptionalPlugins lists plugins that enhance Garmr but aren't required.
var OptionalPlugins = []string{
	"prometheus", // Metrics
	"otel",       // Tracing
	"kafka",      // Enterprise audit
}
