// cmd/garmr/commands.go
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/infrashift/garmr/internal/client"
)

// healthCmd checks server health
var healthCmd = &cobra.Command{
	Use:   "health",
	Short: "Check server health",
	Long: `Check the health and readiness of the Garmr server.

Examples:
  garmr health
  garmr health --wait`,
	RunE: runHealth,
}

func init() {
	healthCmd.Flags().Bool("wait", false, "wait for server to be ready")
	healthCmd.Flags().Duration("timeout", 30*time.Second, "timeout when waiting")
}

// clientConfig is the client configuration for addr: the address plus the
// global TLS options (--ca-cert, --client-cert, --client-key). Every command
// that talks to a server builds its client from this, so TLS settings apply
// uniformly — including to each instance in a reload fan-out.
func clientConfig(addr string) client.Config {
	return client.Config{
		Address:        addr,
		CACertFile:     viper.GetString("tls.ca_cert"),
		ClientCertFile: viper.GetString("tls.client_cert"),
		ClientKeyFile:  viper.GetString("tls.client_key"),
	}
}

// newServerClient builds the REST client from the configured --server
// address together with the standard 30-second request context shared by
// every server-backed command. The returned cleanup releases both; callers
// defer it immediately.
func newServerClient() (*client.Client, context.Context, func(), error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	c, err := client.NewClient(clientConfig(viper.GetString("server")))
	if err != nil {
		cancel()
		return nil, nil, nil, fmt.Errorf("connecting to server: %w", err)
	}
	return c, ctx, func() {
		cancel()
		_ = c.Close()
	}, nil
}

func runHealth(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cfg := clientConfig(viper.GetString("server"))

	wait, _ := cmd.Flags().GetBool("wait")
	timeout, _ := cmd.Flags().GetDuration("timeout")

	if wait {
		ctx, cancel = context.WithTimeout(context.Background(), timeout)
		defer cancel()
	}

	// A bad address is a configuration error: waiting will never fix it.
	c, err := client.NewClient(cfg)
	if err != nil {
		fmt.Printf("✗ %v\n", err)
		osExit(exitError)
	}
	defer c.Close()

	// --wait applies to the health check, not to client construction. It used
	// to be checked only on a NewClient error, which could never happen, so
	// `garmr health --wait` against a down server exited immediately.
	result, err := c.Health(ctx)
	if err != nil {
		if wait {
			return waitForHealth(ctx, c)
		}
		fmt.Printf("✗ Health check failed: %v\n", err)
		osExit(exitNegative)
	}

	format := viper.GetString("output")
	switch {
	case format == "json":
		data, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(data))
	case result.Healthy:
		fmt.Printf("✓ Server healthy (version %s)\n", result.Version)
	default:
		fmt.Printf("✗ Server unhealthy\n")
	}

	// The exit code must not depend on the output format: -o json used to
	// exit 0 for an unhealthy server.
	if !result.Healthy {
		osExit(exitNegative)
	}
	return nil
}

// waitForHealth polls c until the server reports healthy or ctx ends. The
// client is reused across attempts, so its connections are pooled rather
// than rebuilt (and its TLS files re-read) every second. Every failure is
// retried, TLS ones included: an expired certificate may be renewed and
// hot-reloaded, and a proxy may refuse handshakes until its backend is up.
// The timeout error carries the last failure, so the reason is not lost.
func waitForHealth(ctx context.Context, c *client.Client) error {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	lastErr := errors.New("server unreachable")
	for {
		select {
		case <-ctx.Done():
			return resultError{fmt.Errorf("timeout waiting for server: %w", lastErr)}
		case <-ticker.C:
			result, err := c.Health(ctx)
			switch {
			case err == nil && result.Healthy:
				fmt.Printf("✓ Server healthy (version %s)\n", result.Version)
				return nil
			case err == nil:
				lastErr = errors.New("server unhealthy")
			case ctx.Err() == nil:
				lastErr = err
			}
		}
	}
}

// versionCmd prints version information
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Long:  `Print the version information for the Garmr CLI.`,
	Run: func(cmd *cobra.Command, args []string) {
		format := viper.GetString("output")

		info := map[string]string{
			"version":    version,
			"go_version": runtime.Version(),
			"platform":   runtime.GOOS + "/" + runtime.GOARCH,
		}

		if format == "json" {
			data, _ := json.MarshalIndent(info, "", "  ")
			fmt.Println(string(data))
		} else {
			fmt.Printf("Garmr CLI\n")
			fmt.Printf("  Version:    %s\n", version)
			fmt.Printf("  Go Version: %s\n", info["go_version"])
			fmt.Printf("  Platform:   %s\n", info["platform"])
		}
	},
}
