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
	"github.com/spf13/pflag"
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

// mustBind panics on a BindPFlag error. It can only fail when the named flag
// does not exist — a programming error that should abort startup, not be
// silently discarded.
func mustBind(key string, flag *pflag.Flag) {
	if err := viper.BindPFlag(key, flag); err != nil {
		panic(fmt.Sprintf("binding %s: %v", key, err))
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	// Config file
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file")

	// Server flags
	rootCmd.Flags().String("http-addr", ":8080", "HTTP listen address")
	rootCmd.Flags().String("policy-dir", "", "directory containing policies")

	// Logging flags
	rootCmd.Flags().String("log-level", "info", "log level (debug, info, warn, error)")
	rootCmd.Flags().String("log-format", "json", "log format (json, console)")

	// Development flags
	rootCmd.Flags().Bool("dev", false, "development mode")

	// Lifecycle flags
	rootCmd.Flags().Duration("shutdown-timeout", 30*time.Second, "max time to wait for in-flight requests to drain on SIGTERM")
	mustBind("shutdown_timeout", rootCmd.Flags().Lookup("shutdown-timeout"))

	// HTTP limits. Reconcile the timeouts with any sidecar proxy in front
	// (Envoy applies its own request/idle timeouts; the shorter side wins).
	rootCmd.Flags().Int("max-recv-size", 16*1024*1024,
		"max request body size in bytes (evaluate buffers the whole body; size together with the memory limit)")
	rootCmd.Flags().Duration("read-timeout", 30*time.Second, "HTTP server read timeout")
	rootCmd.Flags().Duration("write-timeout", 60*time.Second, "HTTP server write timeout")
	rootCmd.Flags().Duration("idle-timeout", 120*time.Second, "HTTP server idle-connection timeout")
	rootCmd.Flags().Duration("evaluation-timeout", 10*time.Second,
		"max time for one evaluate/validate request, including waiting for an evaluation slot (keep below the sidecar's request timeout)")
	rootCmd.Flags().Int("max-validate-size", 1024*1024,
		"max CUE source size in bytes accepted by /v1/validate (validation compiles caller-supplied source; keep well below max-recv-size)")
	mustBind("max_recv_size", rootCmd.Flags().Lookup("max-recv-size"))
	mustBind("read_timeout", rootCmd.Flags().Lookup("read-timeout"))
	mustBind("write_timeout", rootCmd.Flags().Lookup("write-timeout"))
	mustBind("idle_timeout", rootCmd.Flags().Lookup("idle-timeout"))
	mustBind("evaluation.timeout", rootCmd.Flags().Lookup("evaluation-timeout"))
	mustBind("max_validate_size", rootCmd.Flags().Lookup("max-validate-size"))

	// Evaluation posture: fail-closed when no policy matches (default true)
	rootCmd.Flags().Bool("require-match", true, "return DENY when no policy matches the evaluation (fail-closed)")
	mustBind("evaluation.require_match", rootCmd.Flags().Lookup("require-match"))
	viper.SetDefault("evaluation.require_match", true)

	// Bind to viper
	mustBind("http_addr", rootCmd.Flags().Lookup("http-addr"))
	mustBind("policy_dir", rootCmd.Flags().Lookup("policy-dir"))
	mustBind("log.level", rootCmd.Flags().Lookup("log-level"))
	mustBind("log.format", rootCmd.Flags().Lookup("log-format"))
	mustBind("dev", rootCmd.Flags().Lookup("dev"))

	// Audit flags
	rootCmd.Flags().Bool("audit", true, "enable audit logging")
	rootCmd.Flags().String("audit-path", "/var/log/garmr/audit.log", "audit log file path")
	rootCmd.Flags().Int("audit-max-size", 100, "max audit log file size in MB before rotation")
	rootCmd.Flags().Int("audit-max-backups", 10, "max number of old audit log files to retain")
	rootCmd.Flags().Int("audit-max-age", 30, "max age in days for old audit log files")
	mustBind("audit.enabled", rootCmd.Flags().Lookup("audit"))
	mustBind("audit.path", rootCmd.Flags().Lookup("audit-path"))
	mustBind("audit.max_size", rootCmd.Flags().Lookup("audit-max-size"))
	mustBind("audit.max_backups", rootCmd.Flags().Lookup("audit-max-backups"))
	mustBind("audit.max_age", rootCmd.Flags().Lookup("audit-max-age"))

	// Auth flags
	rootCmd.Flags().String("api-key", "", "API key for authentication (empty = no auth)")
	rootCmd.Flags().String("api-key-header", "X-API-Key", "header name for API key")
	rootCmd.Flags().String("identity-header", "X-Forwarded-Client-Cert", "header carrying mesh-verified client identity (XFCC format)")
	mustBind("auth.api_key", rootCmd.Flags().Lookup("api-key"))
	mustBind("auth.api_key_header", rootCmd.Flags().Lookup("api-key-header"))
	mustBind("auth.identity_header", rootCmd.Flags().Lookup("identity-header"))

	// CORS flags
	rootCmd.Flags().StringSlice("cors-origins", nil, "allowed CORS origins (empty = allow all)")
	mustBind("cors.allowed_origins", rootCmd.Flags().Lookup("cors-origins"))

	// Rate limiting flags
	rootCmd.Flags().Bool("rate-limit", false, "enable rate limiting")
	rootCmd.Flags().Float64("rate-limit-rps", 100, "requests per second limit")
	rootCmd.Flags().Int("rate-limit-burst", 200, "rate limit burst size")
	rootCmd.Flags().Bool("rate-limit-per-client", true, "track a separate bucket per client")
	rootCmd.Flags().String("rate-limit-identifier", "ip",
		"how per-client buckets are keyed: ip, header, or identity (mesh-verified SPIFFE URI from the XFCC header — use behind a Consul/Envoy sidecar)")
	rootCmd.Flags().String("rate-limit-header", "X-Client-ID", "header read by the 'header' identifier")
	rootCmd.Flags().Float64("rate-limit-client-rps", 1000, "per-client requests per second")
	rootCmd.Flags().Int("rate-limit-client-burst", 100, "per-client burst size")
	rootCmd.Flags().Int("rate-limit-max-clients", 10000, "bound on tracked per-client buckets (LRU eviction beyond it)")
	rootCmd.Flags().StringSlice("rate-limit-trusted-proxies", nil,
		"CIDRs whose X-Forwarded-For is trusted for per-client rate limiting (default: none, header ignored)")
	mustBind("rate_limit.enabled", rootCmd.Flags().Lookup("rate-limit"))
	mustBind("rate_limit.rps", rootCmd.Flags().Lookup("rate-limit-rps"))
	mustBind("rate_limit.burst", rootCmd.Flags().Lookup("rate-limit-burst"))
	mustBind("rate_limit.per_client", rootCmd.Flags().Lookup("rate-limit-per-client"))
	mustBind("rate_limit.client_identifier", rootCmd.Flags().Lookup("rate-limit-identifier"))
	mustBind("rate_limit.header_name", rootCmd.Flags().Lookup("rate-limit-header"))
	mustBind("rate_limit.client_rps", rootCmd.Flags().Lookup("rate-limit-client-rps"))
	mustBind("rate_limit.client_burst", rootCmd.Flags().Lookup("rate-limit-client-burst"))
	mustBind("rate_limit.max_clients", rootCmd.Flags().Lookup("rate-limit-max-clients"))
	mustBind("rate_limit.trusted_proxies", rootCmd.Flags().Lookup("rate-limit-trusted-proxies"))
	viper.SetDefault("rate_limit.per_client", true)

	// Storage backend flags
	rootCmd.Flags().String("storage-type", "", "storage backend type (filesystem)")
	rootCmd.Flags().String("storage-root", "", "storage backend root path/prefix")
	mustBind("storage.type", rootCmd.Flags().Lookup("storage-type"))
	mustBind("storage.root", rootCmd.Flags().Lookup("storage-root"))
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
	// Sync flushes on exit; its error is expected on stderr sinks and has
	// nowhere useful to go this late.
	defer func() { _ = logger.Sync() }()

	logger.Info("starting Garmr server",
		zap.String("version", version),
		zap.String("commit", commit),
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
		if shutErr := shutdownTracing(shutdownCtx); shutErr != nil {
			logger.Warn("tracing shutdown returned error", zap.Error(shutErr))
		}
	}()

	// Create engine
	eng, err := engine.NewEngine(logger)
	if err != nil {
		return fmt.Errorf("creating engine: %w", err)
	}

	// Create server config
	requireMatch := viper.GetBool("evaluation.require_match")
	rateLimitPerClient := viper.GetBool("rate_limit.per_client")
	cfg := server.Config{
		HTTPAddr:           viper.GetString("http_addr"),
		PolicyDir:          viper.GetString("policy_dir"),
		MaxRecvSize:        viper.GetInt("max_recv_size"),
		ShutdownTimeout:    viper.GetDuration("shutdown_timeout"),
		ReadTimeout:        viper.GetDuration("read_timeout"),
		WriteTimeout:       viper.GetDuration("write_timeout"),
		IdleTimeout:        viper.GetDuration("idle_timeout"),
		EvaluationTimeout:  viper.GetDuration("evaluation.timeout"),
		MaxValidateSize:    viper.GetInt("max_validate_size"),
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

		RateLimitPerClient:        &rateLimitPerClient,
		RateLimitClientIdentifier: viper.GetString("rate_limit.client_identifier"),
		RateLimitHeaderName:       viper.GetString("rate_limit.header_name"),
		RateLimitClientRPS:        viper.GetFloat64("rate_limit.client_rps"),
		RateLimitClientBurst:      viper.GetInt("rate_limit.client_burst"),
		RateLimitMaxClients:       viper.GetInt("rate_limit.max_clients"),
		RateLimitTrustedProxies:   viper.GetStringSlice("rate_limit.trusted_proxies"),
		StorageType:               viper.GetString("storage.type"),
		StorageRoot:               viper.GetString("storage.root"),
		RequireMatch:              &requireMatch,
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
