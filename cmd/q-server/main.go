// cmd/q-server/main.go
// Package main provides the Q Policy Agent server.
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

	"github.com/infrashift/q-policy-agent/internal/engine"
	"github.com/infrashift/q-policy-agent/internal/server"
)

var (
	version = "0.1.0"
	cfgFile string
)

var rootCmd = &cobra.Command{
	Use:   "q-server",
	Short: "Q Policy Agent Server",
	Long: `Q Policy Agent Server provides gRPC and REST APIs for policy evaluation.

The server loads policies from CUE files and evaluates input against them,
returning decisions and violations.

Examples:
  # Start with default settings
  q-server

  # Start with custom config
  q-server --config /etc/q/config.yaml

  # Start with specific policy directory
  q-server --policy-dir /policies

  # Start in development mode
  q-server --dev`,
	RunE: runServer,
}

func init() {
	cobra.OnInitialize(initConfig)

	// Config file
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file")

	// Server flags
	rootCmd.Flags().String("grpc-addr", ":9090", "gRPC listen address")
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
	rootCmd.Flags().String("audit-path", "/var/log/q/audit.log", "audit log file path")
	viper.BindPFlag("audit.enabled", rootCmd.Flags().Lookup("audit"))
	viper.BindPFlag("audit.path", rootCmd.Flags().Lookup("audit-path"))
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		viper.AddConfigPath("/etc/q")
		viper.AddConfigPath("$HOME/.q")
		viper.AddConfigPath(".")
		viper.SetConfigName("config")
		viper.SetConfigType("yaml")
	}

	viper.SetEnvPrefix("Q")
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

	logger.Info("starting Q Policy Agent server",
		zap.String("version", version),
	)

	// Create engine
	eng, err := engine.NewEngine(logger)
	if err != nil {
		return fmt.Errorf("creating engine: %w", err)
	}

	// Create server config
	cfg := server.Config{
		GRPCAddr:     viper.GetString("grpc_addr"),
		HTTPAddr:     viper.GetString("http_addr"),
		PolicyDir:    viper.GetString("policy_dir"),
		TLSCert:      viper.GetString("tls.cert"),
		TLSKey:       viper.GetString("tls.key"),
		EnableTLS:    viper.GetBool("tls.enabled"),
		MaxRecvSize:  16 * 1024 * 1024, // 16MB
		AuditEnabled: viper.GetBool("audit.enabled"),
		AuditPath:    viper.GetString("audit.path"),
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
