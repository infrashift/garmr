// cmd/garmr-server/main.go
// Package main provides the Garmr server.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/infrashift/garmr/internal/engine"
	"github.com/infrashift/garmr/internal/server"
)

var (
	version = "0.1.0"
	cfgFile string
)

var rootCmd = &cobra.Command{
	Use:   "garmr-server",
	Short: "Garmr Server",
	Long: `Garmr Server provides gRPC and REST APIs for policy evaluation.

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
	RunE: runServer,
}

func init() {
	cobra.OnInitialize(initConfig)

	// Config file
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file")

	// Server flags
	rootCmd.Flags().String("grpc-addr", "", "gRPC listen address (e.g., :9090; empty = disabled)")
	rootCmd.Flags().String("http-addr", ":8080", "HTTP listen address")
	rootCmd.Flags().String("policy-dir", "", "directory containing policies")
	rootCmd.Flags().String("data-dir", "", "directory containing data files")

	// TLS flags
	rootCmd.Flags().Bool("tls", false, "enable TLS")
	rootCmd.Flags().String("tls-cert", "", "TLS certificate file")
	rootCmd.Flags().String("tls-key", "", "TLS key file")

	// Logging flags
	rootCmd.Flags().String("log-level", "info", "log level (debug, info, warn, error)")
	rootCmd.Flags().String("log-format", "json", "log format (json, console)")

	// Development flags
	rootCmd.Flags().Bool("dev", false, "development mode")

	// Bind to viper
	viper.BindPFlag("grpc_addr", rootCmd.Flags().Lookup("grpc-addr"))
	viper.BindPFlag("http_addr", rootCmd.Flags().Lookup("http-addr"))
	viper.BindPFlag("policy_dir", rootCmd.Flags().Lookup("policy-dir"))
	viper.BindPFlag("data_dir", rootCmd.Flags().Lookup("data-dir"))
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
	viper.BindPFlag("auth.api_key", rootCmd.Flags().Lookup("api-key"))
	viper.BindPFlag("auth.api_key_header", rootCmd.Flags().Lookup("api-key-header"))

	// CORS flags
	rootCmd.Flags().StringSlice("cors-origins", nil, "allowed CORS origins (empty = allow all)")
	viper.BindPFlag("cors.allowed_origins", rootCmd.Flags().Lookup("cors-origins"))

	// Rate limiting flags
	rootCmd.Flags().Bool("rate-limit", false, "enable rate limiting")
	rootCmd.Flags().Float64("rate-limit-rps", 100, "requests per second limit")
	rootCmd.Flags().Int("rate-limit-burst", 200, "rate limit burst size")
	viper.BindPFlag("rate_limit.enabled", rootCmd.Flags().Lookup("rate-limit"))
	viper.BindPFlag("rate_limit.rps", rootCmd.Flags().Lookup("rate-limit-rps"))
	viper.BindPFlag("rate_limit.burst", rootCmd.Flags().Lookup("rate-limit-burst"))

	// Storage backend flags
	rootCmd.Flags().String("storage-type", "", "storage backend type (filesystem, s3, minio)")
	rootCmd.Flags().String("storage-root", "", "storage backend root path/prefix")
	rootCmd.Flags().String("s3-endpoint", "", "S3-compatible endpoint (e.g., localhost:9000)")
	rootCmd.Flags().String("s3-bucket", "", "S3 bucket name")
	rootCmd.Flags().String("s3-region", "us-east-1", "S3 region")
	rootCmd.Flags().String("s3-access-key", "", "S3 access key ID")
	rootCmd.Flags().String("s3-secret-key", "", "S3 secret access key")
	rootCmd.Flags().Bool("s3-use-ssl", true, "use SSL for S3 connections")
	rootCmd.Flags().String("s3-poll-interval", "10s", "S3 polling interval for change detection")
	rootCmd.Flags().String("plugin-dir", "", "directory containing external plugins")
	viper.BindPFlag("storage.type", rootCmd.Flags().Lookup("storage-type"))
	viper.BindPFlag("storage.root", rootCmd.Flags().Lookup("storage-root"))
	viper.BindPFlag("storage.s3.endpoint", rootCmd.Flags().Lookup("s3-endpoint"))
	viper.BindPFlag("storage.s3.bucket", rootCmd.Flags().Lookup("s3-bucket"))
	viper.BindPFlag("storage.s3.region", rootCmd.Flags().Lookup("s3-region"))
	viper.BindPFlag("storage.s3.access_key", rootCmd.Flags().Lookup("s3-access-key"))
	viper.BindPFlag("storage.s3.secret_key", rootCmd.Flags().Lookup("s3-secret-key"))
	viper.BindPFlag("storage.s3.use_ssl", rootCmd.Flags().Lookup("s3-use-ssl"))
	viper.BindPFlag("storage.s3.poll_interval", rootCmd.Flags().Lookup("s3-poll-interval"))
	viper.BindPFlag("plugin_dir", rootCmd.Flags().Lookup("plugin-dir"))
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

	// Create engine
	eng, err := engine.NewEngine(logger)
	if err != nil {
		return fmt.Errorf("creating engine: %w", err)
	}

	// Build S3 storage options from viper if storage type is set
	storageOpts := make(map[string]interface{})
	if viper.GetString("storage.s3.endpoint") != "" {
		storageOpts["endpoint"] = viper.GetString("storage.s3.endpoint")
	}
	if viper.GetString("storage.s3.bucket") != "" {
		storageOpts["bucket"] = viper.GetString("storage.s3.bucket")
	}
	if viper.GetString("storage.s3.region") != "" {
		storageOpts["region"] = viper.GetString("storage.s3.region")
	}
	if viper.GetString("storage.s3.access_key") != "" {
		storageOpts["accessKeyId"] = viper.GetString("storage.s3.access_key")
	}
	if viper.GetString("storage.s3.secret_key") != "" {
		storageOpts["secretAccessKey"] = viper.GetString("storage.s3.secret_key")
	}
	storageOpts["useSsl"] = viper.GetBool("storage.s3.use_ssl")
	if viper.GetString("storage.s3.poll_interval") != "" {
		storageOpts["pollInterval"] = viper.GetString("storage.s3.poll_interval")
	}

	// Create server config
	cfg := server.Config{
		GRPCAddr:           viper.GetString("grpc_addr"),
		HTTPAddr:           viper.GetString("http_addr"),
		PolicyDir:          viper.GetString("policy_dir"),
		TLSCert:            viper.GetString("tls.cert"),
		TLSKey:             viper.GetString("tls.key"),
		EnableTLS:          viper.GetBool("tls.enabled"),
		MaxRecvSize:        16 * 1024 * 1024, // 16MB
		AuditEnabled:       viper.GetBool("audit.enabled"),
		AuditPath:          viper.GetString("audit.path"),
		AuditMaxSizeMB:     viper.GetInt("audit.max_size"),
		AuditMaxBackups:    viper.GetInt("audit.max_backups"),
		AuditMaxAgeDays:    viper.GetInt("audit.max_age"),
		APIKey:             viper.GetString("auth.api_key"),
		APIKeyHeader:       viper.GetString("auth.api_key_header"),
		AuthExemptPaths:    []string{"/health", "/ready", "/healthz", "/readyz", "/livez", "/metrics"},
		CORSAllowedOrigins: viper.GetStringSlice("cors.allowed_origins"),
		RateLimitEnabled:   viper.GetBool("rate_limit.enabled"),
		RateLimitPerSecond: viper.GetFloat64("rate_limit.rps"),
		RateLimitBurst:     viper.GetInt("rate_limit.burst"),
		StorageType:        viper.GetString("storage.type"),
		StorageRoot:        viper.GetString("storage.root"),
		StorageOptions:     storageOpts,
		PluginDir:          viper.GetString("plugin_dir"),
	}

	// Create server
	srv, err := server.NewServer(cfg, eng, logger)
	if err != nil {
		return fmt.Errorf("creating server: %w", err)
	}

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
		zap.String("grpc", cfg.GRPCAddr),
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
