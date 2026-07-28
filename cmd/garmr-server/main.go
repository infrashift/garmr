// cmd/garmr-server/main.go
// Package main provides the Garmr server.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/infrashift/garmr/internal/engine"
	"github.com/infrashift/garmr/internal/observability"
	"github.com/infrashift/garmr/internal/server"
)

// version is injected at link time via the Makefile's `-X main.version=...`
// ldflag. "dev" is the fallback for un-injected local builds.
var (
	version = "dev"
	commit  = "unknown"
	cfgFile string
)

var rootCmd = &cobra.Command{
	Use:   "garmr-server",
	Short: "Garmr Server",
	Long: `Garmr Server provides a REST API for policy evaluation.

The server loads policies from CUE files and evaluates input against them,
returning decisions and violations.

Examples:
  # Start with default settings
  garmr-server

  # Start with custom config
  garmr-server --config /etc/garmr/config.yaml

  # Start with specific policy directory
  garmr-server --policy-dir /policies

  # Start in development mode
  garmr-server --dev`,
	// A runtime failure (port in use, unloadable policy directory) is not a
	// usage error; printing the full flag list buries the actual reason.
	SilenceUsage: true,
	RunE:         runServer,
}

func init() {
	cobra.OnInitialize(initConfig)

	// Config file
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file")

	// Server flags
	rootCmd.Flags().String("http-addr", ":8080", "HTTP listen address")
	rootCmd.Flags().String("policy-dir", "", "directory containing policies")

	// TLS flags
	rootCmd.Flags().Bool("tls", false, "enable TLS")
	rootCmd.Flags().String("tls-cert", "", "TLS certificate file")
	rootCmd.Flags().String("tls-key", "", "TLS key file")

	// Logging flags
	rootCmd.Flags().String("log-level", "info", "log level (debug, info, warn, error)")
	rootCmd.Flags().String("log-format", "json", "log format (json, console)")

	// Development flags
	rootCmd.Flags().Bool("dev", false, "development mode")

	// Lifecycle flags
	rootCmd.Flags().Duration("shutdown-timeout", 30*time.Second, "max time to wait for in-flight requests to drain on SIGTERM")
	viper.BindPFlag("shutdown_timeout", rootCmd.Flags().Lookup("shutdown-timeout"))

	// Evaluation posture: fail-closed when no policy matches (default true)
	rootCmd.Flags().Bool("require-match", true, "return DENY when no policy matches the evaluation (fail-closed)")
	viper.BindPFlag("evaluation.require_match", rootCmd.Flags().Lookup("require-match"))
	viper.SetDefault("evaluation.require_match", true)

	// Bind to viper
	viper.BindPFlag("http_addr", rootCmd.Flags().Lookup("http-addr"))
	viper.BindPFlag("policy_dir", rootCmd.Flags().Lookup("policy-dir"))
	viper.BindPFlag("tls.enabled", rootCmd.Flags().Lookup("tls"))
	viper.BindPFlag("tls.cert", rootCmd.Flags().Lookup("tls-cert"))
	viper.BindPFlag("tls.key", rootCmd.Flags().Lookup("tls-key"))
	viper.BindPFlag("log.level", rootCmd.Flags().Lookup("log-level"))
	viper.BindPFlag("log.format", rootCmd.Flags().Lookup("log-format"))
	viper.BindPFlag("dev", rootCmd.Flags().Lookup("dev"))

	// Audit flags
	rootCmd.Flags().Bool("audit", true, "enable audit logging")
	rootCmd.Flags().String("audit-path", "/var/log/garmr/audit.log", "audit log file path")
	rootCmd.Flags().Int("audit-max-size", 100, "max audit log file size in MB before rotation")
	rootCmd.Flags().Int("audit-max-backups", 10, "max number of old audit log files to retain")
	rootCmd.Flags().Int("audit-max-age", 30, "max age in days for old audit log files")
	viper.BindPFlag("audit.enabled", rootCmd.Flags().Lookup("audit"))
	viper.BindPFlag("audit.path", rootCmd.Flags().Lookup("audit-path"))
	viper.BindPFlag("audit.max_size", rootCmd.Flags().Lookup("audit-max-size"))
	viper.BindPFlag("audit.max_backups", rootCmd.Flags().Lookup("audit-max-backups"))
	viper.BindPFlag("audit.max_age", rootCmd.Flags().Lookup("audit-max-age"))

	// Auth flags
	rootCmd.Flags().String("api-key", "", "API key for authentication (empty = no auth)")
	rootCmd.Flags().String("api-key-header", "X-API-Key", "header name for API key")
	rootCmd.Flags().String("identity-header", "X-Forwarded-Client-Cert", "header carrying mesh-verified client identity (XFCC format)")
	viper.BindPFlag("auth.api_key", rootCmd.Flags().Lookup("api-key"))
	viper.BindPFlag("auth.api_key_header", rootCmd.Flags().Lookup("api-key-header"))
	viper.BindPFlag("auth.identity_header", rootCmd.Flags().Lookup("identity-header"))

	// CORS flags
	rootCmd.Flags().StringSlice("cors-origins", nil, "allowed CORS origins (empty = allow all)")
	viper.BindPFlag("cors.allowed_origins", rootCmd.Flags().Lookup("cors-origins"))

	// Rate limiting flags
	rootCmd.Flags().Bool("rate-limit", false, "enable rate limiting")
	rootCmd.Flags().Float64("rate-limit-rps", 100, "requests per second limit")
	rootCmd.Flags().Int("rate-limit-burst", 200, "rate limit burst size")
	rootCmd.Flags().StringSlice("rate-limit-trusted-proxies", nil,
		"CIDRs whose X-Forwarded-For is trusted for per-client rate limiting (default: none, header ignored)")
	viper.BindPFlag("rate_limit.enabled", rootCmd.Flags().Lookup("rate-limit"))
	viper.BindPFlag("rate_limit.rps", rootCmd.Flags().Lookup("rate-limit-rps"))
	viper.BindPFlag("rate_limit.burst", rootCmd.Flags().Lookup("rate-limit-burst"))
	viper.BindPFlag("rate_limit.trusted_proxies", rootCmd.Flags().Lookup("rate-limit-trusted-proxies"))

	// Storage backend flags
	rootCmd.Flags().String("storage-type", "", "storage backend type (filesystem)")
	rootCmd.Flags().String("storage-root", "", "storage backend root path/prefix")
	viper.BindPFlag("storage.type", rootCmd.Flags().Lookup("storage-type"))
	viper.BindPFlag("storage.root", rootCmd.Flags().Lookup("storage-root"))
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		viper.AddConfigPath("/etc/garmr")
		viper.AddConfigPath("$HOME/.garmr")
		viper.AddConfigPath(".")
		viper.SetConfigName("config")
		viper.SetConfigType("yaml")
	}

	viper.SetEnvPrefix("GARMR")
	// Map nested config keys to underscore-delimited env vars, e.g.
	// audit.enabled -> GARMR_AUDIT_ENABLED. Without this replacer the
	// documented env vars never resolve (audit.enabled would only match
	// the impossible variable "GARMR_AUDIT.ENABLED").
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err == nil {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
	}
}

func runServer(cmd *cobra.Command, args []string) error {
	// Initialize logger
	logger, err := initLogger()
	if err != nil {
		return fmt.Errorf("initializing logger: %w", err)
	}
	defer logger.Sync()

	logger.Info("starting Garmr server",
		zap.String("version", version),
	)

	// Initialize OpenTelemetry tracing. No-op if OTEL env vars are unset.
	ctxInit := context.Background()
	shutdownTracing, err := observability.InitTracing(ctxInit, "garmr-server", version)
	if err != nil {
		return fmt.Errorf("initializing tracing: %w", err)
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := shutdownTracing(shutdownCtx); err != nil {
			logger.Warn("tracing shutdown returned error", zap.Error(err))
		}
	}()

	// Create engine
	eng, err := engine.NewEngine(logger)
	if err != nil {
		return fmt.Errorf("creating engine: %w", err)
	}

	// Create server config
	requireMatch := viper.GetBool("evaluation.require_match")
	cfg := server.Config{
		HTTPAddr:           viper.GetString("http_addr"),
		PolicyDir:          viper.GetString("policy_dir"),
		TLSCert:            viper.GetString("tls.cert"),
		TLSKey:             viper.GetString("tls.key"),
		EnableTLS:          viper.GetBool("tls.enabled"),
		MaxRecvSize:        16 * 1024 * 1024, // 16MB
		ShutdownTimeout:    viper.GetDuration("shutdown_timeout"),
		Version:            version,
		AuditEnabled:       viper.GetBool("audit.enabled"),
		AuditPath:          viper.GetString("audit.path"),
		AuditMaxSizeMB:     viper.GetInt("audit.max_size"),
		AuditMaxBackups:    viper.GetInt("audit.max_backups"),
		AuditMaxAgeDays:    viper.GetInt("audit.max_age"),
		APIKey:             viper.GetString("auth.api_key"),
		APIKeyHeader:       viper.GetString("auth.api_key_header"),
		IdentityHeader:     viper.GetString("auth.identity_header"),
		AuthExemptPaths:    []string{"/health", "/ready", "/healthz", "/readyz", "/livez", "/metrics"},
		CORSAllowedOrigins: viper.GetStringSlice("cors.allowed_origins"),
		RateLimitEnabled:   viper.GetBool("rate_limit.enabled"),
		RateLimitPerSecond: viper.GetFloat64("rate_limit.rps"),
		RateLimitBurst:     viper.GetInt("rate_limit.burst"),

		RateLimitTrustedProxies: viper.GetStringSlice("rate_limit.trusted_proxies"),
		StorageType:             viper.GetString("storage.type"),
		StorageRoot:             viper.GetString("storage.root"),
		RequireMatch:            &requireMatch,
	}

	// Create server
	srv, err := server.NewServer(cfg, eng, logger)
	if err != nil {
		return fmt.Errorf("creating server: %w", err)
	}

	// Wire Prometheus metrics recorder (served at /metrics).
	srv.Observability().SetMetrics(observability.NewPrometheusMetrics())

	// Handle shutdown signals
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigCh
		logger.Info("received shutdown signal", zap.String("signal", sig.String()))
		cancel()
	}()

	// Start server
	logger.Info("server listening",
		zap.String("http", cfg.HTTPAddr),
	)

	if err := srv.Start(ctx); err != nil {
		return fmt.Errorf("server error: %w", err)
	}

	logger.Info("server stopped")
	return nil
}

func initLogger() (*zap.Logger, error) {
	var config zap.Config

	if viper.GetBool("dev") {
		config = zap.NewDevelopmentConfig()
		config.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	} else {
		config = zap.NewProductionConfig()
	}

	// Set log level
	level := viper.GetString("log.level")
	switch level {
	case "debug":
		config.Level.SetLevel(zap.DebugLevel)
	case "info":
		config.Level.SetLevel(zap.InfoLevel)
	case "warn":
		config.Level.SetLevel(zap.WarnLevel)
	case "error":
		config.Level.SetLevel(zap.ErrorLevel)
	}

	// Set format
	if viper.GetString("log.format") == "console" {
		config.Encoding = "console"
	}

	return config.Build()
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
