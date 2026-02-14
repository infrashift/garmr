// plugins/logging/main.go
// Package main provides the structured logging plugin for Garmr.
// Uses Go's slog for structured, leveled logging.
//
// Build with:
//   go build -buildmode=plugin -o logging.so ./plugins/logging
package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/infrashift/garmr/internal/experimental/plugin"
)

// LoggingPlugin provides structured logging using slog.
type LoggingPlugin struct {
	config  LoggingConfig
	logger  *slog.Logger
	handler slog.Handler
	output  io.WriteCloser
	mu      sync.RWMutex
}

// LoggingConfig configures the logging plugin.
type LoggingConfig struct {
	// Enabled controls whether logging is active
	Enabled bool `json:"enabled"`

	// Level: debug, info, warn, error
	Level string `json:"level"`

	// Format: json, text
	Format string `json:"format"`

	// Output: stdout, stderr, file path
	Output string `json:"output"`

	// AddSource includes source file/line in logs
	AddSource bool `json:"addSource"`

	// TimeFormat for log timestamps
	TimeFormat string `json:"timeFormat"`

	// Fields to include in all log entries
	DefaultFields map[string]string `json:"defaultFields"`

	// File rotation settings (when Output is a file)
	Rotation RotationConfig `json:"rotation"`
}

// RotationConfig configures log file rotation.
type RotationConfig struct {
	// MaxSize in megabytes before rotation
	MaxSize int `json:"maxSize"`

	// MaxAge in days to retain old logs
	MaxAge int `json:"maxAge"`

	// MaxBackups is the number of old log files to keep
	MaxBackups int `json:"maxBackups"`

	// Compress old log files
	Compress bool `json:"compress"`
}

func (p *LoggingPlugin) Metadata() plugin.Metadata {
	return plugin.Metadata{
		Name:        "logging",
		Type:        plugin.TypeNotifier,
		Version:     "1.0.0",
		Description: "Structured logging with slog for policy evaluation events",
		Author:      "Garmr",
		License:     "Apache-2.0",
		Capabilities: []string{
			"logging.structured",
			"logging.json",
			"logging.levels",
		},
	}
}

func (p *LoggingPlugin) Init(ctx context.Context, config map[string]interface{}) error {
	// Parse config with defaults
	p.config = LoggingConfig{
		Enabled:       true,
		Level:         "info",
		Format:        "json",
		Output:        "stdout",
		AddSource:     false,
		TimeFormat:    time.RFC3339,
		DefaultFields: make(map[string]string),
		Rotation: RotationConfig{
			MaxSize:    100,
			MaxAge:     30,
			MaxBackups: 5,
			Compress:   true,
		},
	}

	if v, ok := config["enabled"].(bool); ok {
		p.config.Enabled = v
	}
	if v, ok := config["level"].(string); ok {
		p.config.Level = v
	}
	if v, ok := config["format"].(string); ok {
		p.config.Format = v
	}
	if v, ok := config["output"].(string); ok {
		p.config.Output = v
	}
	if v, ok := config["addSource"].(bool); ok {
		p.config.AddSource = v
	}
	if v, ok := config["timeFormat"].(string); ok {
		p.config.TimeFormat = v
	}
	if v, ok := config["defaultFields"].(map[string]interface{}); ok {
		for k, val := range v {
			if s, ok := val.(string); ok {
				p.config.DefaultFields[k] = s
			}
		}
	}

	// Parse rotation config
	if rot, ok := config["rotation"].(map[string]interface{}); ok {
		if v, ok := rot["maxSize"].(float64); ok {
			p.config.Rotation.MaxSize = int(v)
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

	if !p.config.Enabled {
		// Create a no-op logger
		p.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
		return nil
	}

	// Setup output
	if err := p.setupOutput(); err != nil {
		return fmt.Errorf("setting up output: %w", err)
	}

	// Create handler
	p.handler = p.createHandler()

	// Create logger with default fields
	p.logger = slog.New(p.handler)
	if len(p.config.DefaultFields) > 0 {
		attrs := make([]any, 0, len(p.config.DefaultFields)*2)
		for k, v := range p.config.DefaultFields {
			attrs = append(attrs, k, v)
		}
		p.logger = p.logger.With(attrs...)
	}

	// Set as default logger
	slog.SetDefault(p.logger)

	return nil
}

func (p *LoggingPlugin) setupOutput() error {
	switch p.config.Output {
	case "stdout":
		p.output = os.Stdout
	case "stderr":
		p.output = os.Stderr
	default:
		// File output
		dir := filepath.Dir(p.config.Output)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("creating log directory: %w", err)
		}

		f, err := os.OpenFile(p.config.Output, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			return fmt.Errorf("opening log file: %w", err)
		}
		p.output = f
	}
	return nil
}

func (p *LoggingPlugin) createHandler() slog.Handler {
	level := p.parseLevel(p.config.Level)

	opts := &slog.HandlerOptions{
		Level:     level,
		AddSource: p.config.AddSource,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			// Custom time formatting
			if a.Key == slog.TimeKey {
				if t, ok := a.Value.Any().(time.Time); ok {
					a.Value = slog.StringValue(t.Format(p.config.TimeFormat))
				}
			}
			return a
		},
	}

	switch p.config.Format {
	case "json":
		return slog.NewJSONHandler(p.output, opts)
	case "text":
		return slog.NewTextHandler(p.output, opts)
	default:
		return slog.NewJSONHandler(p.output, opts)
	}
}

func (p *LoggingPlugin) parseLevel(level string) slog.Level {
	switch strings.ToLower(level) {
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

func (p *LoggingPlugin) Health(ctx context.Context) error {
	if !p.config.Enabled {
		return nil
	}
	if p.logger == nil {
		return fmt.Errorf("logger not initialized")
	}
	return nil
}

func (p *LoggingPlugin) Close() error {
	if p.output != nil && p.output != os.Stdout && p.output != os.Stderr {
		return p.output.Close()
	}
	return nil
}

// Logger returns the underlying slog.Logger.
func (p *LoggingPlugin) Logger() *slog.Logger {
	return p.logger
}

// SetLevel dynamically changes the log level.
func (p *LoggingPlugin) SetLevel(level string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.config.Level = level
	p.handler = p.createHandler()
	p.logger = slog.New(p.handler)

	if len(p.config.DefaultFields) > 0 {
		attrs := make([]any, 0, len(p.config.DefaultFields)*2)
		for k, v := range p.config.DefaultFields {
			attrs = append(attrs, k, v)
		}
		p.logger = p.logger.With(attrs...)
	}

	slog.SetDefault(p.logger)
}

// Logging methods for policy events

// LogEvaluationStart logs the start of a policy evaluation.
func (p *LoggingPlugin) LogEvaluationStart(ctx context.Context, policy, namespace, traceID string) {
	p.logger.InfoContext(ctx, "policy evaluation started",
		"event", "evaluation.start",
		"policy", policy,
		"namespace", namespace,
		"traceId", traceID,
	)
}

// LogEvaluationComplete logs the completion of a policy evaluation.
func (p *LoggingPlugin) LogEvaluationComplete(ctx context.Context, policy, namespace, decision string, duration time.Duration, violationCount int) {
	p.logger.InfoContext(ctx, "policy evaluation completed",
		"event", "evaluation.complete",
		"policy", policy,
		"namespace", namespace,
		"decision", decision,
		"durationMs", duration.Milliseconds(),
		"violations", violationCount,
	)
}

// LogViolation logs a policy violation.
func (p *LoggingPlugin) LogViolation(ctx context.Context, policy, namespace, ruleID, severity, message string) {
	level := p.severityToLevel(severity)

	p.logger.Log(ctx, level, "policy violation detected",
		"event", "violation",
		"policy", policy,
		"namespace", namespace,
		"ruleId", ruleID,
		"severity", severity,
		"message", message,
	)
}

// LogPolicyLoad logs a policy load event.
func (p *LoggingPlugin) LogPolicyLoad(ctx context.Context, policy, namespace, path string, success bool, err error) {
	if success {
		p.logger.InfoContext(ctx, "policy loaded",
			"event", "policy.load",
			"policy", policy,
			"namespace", namespace,
			"path", path,
		)
	} else {
		p.logger.ErrorContext(ctx, "policy load failed",
			"event", "policy.load.error",
			"policy", policy,
			"namespace", namespace,
			"path", path,
			"error", err.Error(),
		)
	}
}

// LogPolicyReload logs a policy reload event.
func (p *LoggingPlugin) LogPolicyReload(ctx context.Context, namespace string, count int) {
	p.logger.InfoContext(ctx, "policies reloaded",
		"event", "policy.reload",
		"namespace", namespace,
		"count", count,
	)
}

// LogInputValidationError logs an input validation error.
func (p *LoggingPlugin) LogInputValidationError(ctx context.Context, policy, field, expected, actual string) {
	p.logger.WarnContext(ctx, "input validation failed",
		"event", "validation.error",
		"policy", policy,
		"field", field,
		"expected", expected,
		"actual", actual,
	)
}

// LogRateLimitHit logs a rate limit hit.
func (p *LoggingPlugin) LogRateLimitHit(ctx context.Context, client, policy string) {
	p.logger.WarnContext(ctx, "rate limit exceeded",
		"event", "ratelimit.hit",
		"client", client,
		"policy", policy,
	)
}

// LogPluginEvent logs a plugin lifecycle event.
func (p *LoggingPlugin) LogPluginEvent(ctx context.Context, pluginName, event string, err error) {
	if err != nil {
		p.logger.ErrorContext(ctx, "plugin event failed",
			"event", "plugin."+event,
			"plugin", pluginName,
			"error", err.Error(),
		)
	} else {
		p.logger.InfoContext(ctx, "plugin event",
			"event", "plugin."+event,
			"plugin", pluginName,
		)
	}
}

// LogAuditDecision logs an audit decision (for compliance).
func (p *LoggingPlugin) LogAuditDecision(ctx context.Context, decision AuditDecision) {
	p.logger.InfoContext(ctx, "audit decision recorded",
		"event", "audit.decision",
		"id", decision.ID,
		"policy", decision.Policy,
		"namespace", decision.Namespace,
		"decision", decision.Decision,
		"principal", decision.Principal,
		"sourceIp", decision.SourceIP,
		"traceId", decision.TraceID,
		"timestamp", decision.Timestamp.Format(time.RFC3339),
	)
}

// AuditDecision represents an auditable policy decision.
type AuditDecision struct {
	ID         string
	Policy     string
	Namespace  string
	Decision   string
	Principal  string
	SourceIP   string
	TraceID    string
	Timestamp  time.Time
	Violations []string
}

func (p *LoggingPlugin) severityToLevel(severity string) slog.Level {
	switch strings.ToLower(severity) {
	case "critical", "error":
		return slog.LevelError
	case "high", "warning", "warn":
		return slog.LevelWarn
	case "medium", "info":
		return slog.LevelInfo
	case "low", "debug":
		return slog.LevelDebug
	default:
		return slog.LevelInfo
	}
}

// Debug logs at debug level.
func (p *LoggingPlugin) Debug(msg string, args ...any) {
	p.logger.Debug(msg, args...)
}

// Info logs at info level.
func (p *LoggingPlugin) Info(msg string, args ...any) {
	p.logger.Info(msg, args...)
}

// Warn logs at warn level.
func (p *LoggingPlugin) Warn(msg string, args ...any) {
	p.logger.Warn(msg, args...)
}

// Error logs at error level.
func (p *LoggingPlugin) Error(msg string, args ...any) {
	p.logger.Error(msg, args...)
}

// With returns a logger with additional context.
func (p *LoggingPlugin) With(args ...any) *slog.Logger {
	return p.logger.With(args...)
}

// QPlugin is the exported symbol for plugin loading.
var QPlugin plugin.Plugin = &LoggingPlugin{}
