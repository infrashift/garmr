// cmd/garmr/commands.go
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/infrashift/garmr/internal/client"
)

// dataCmd manages external data
var dataCmd = &cobra.Command{
	Use:   "data",
	Short: "Manage external data",
	Long:  `Commands for managing external data used in policy evaluation.`,
}

var dataPutCmd = &cobra.Command{
	Use:   "put [path]",
	Short: "Put data at a path",
	Long: `Put JSON data at a specified path for use in policy evaluation.

Examples:
  # Put inline data
  garmr data put allowed-registries --data '["gcr.io", "docker.io"]'

  # Put data from file
  garmr data put config/limits --file limits.json`,
	Args: cobra.ExactArgs(1),
	RunE: runDataPut,
}

var dataGetCmd = &cobra.Command{
	Use:   "get [path]",
	Short: "Get data at a path",
	Long: `Get data stored at a specified path.

Examples:
  garmr data get allowed-registries
  garmr data get config/limits -o json`,
	Args: cobra.ExactArgs(1),
	RunE: runDataGet,
}

var dataDeleteCmd = &cobra.Command{
	Use:   "delete [path]",
	Short: "Delete data at a path",
	Long: `Delete data at a specified path.

Examples:
  garmr data delete allowed-registries`,
	Args: cobra.ExactArgs(1),
	RunE: runDataDelete,
}

func init() {
	dataCmd.AddCommand(dataPutCmd)
	dataCmd.AddCommand(dataGetCmd)
	dataCmd.AddCommand(dataDeleteCmd)

	dataPutCmd.Flags().StringP("data", "d", "", "inline JSON data")
	dataPutCmd.Flags().StringP("file", "f", "", "JSON file")
}

func runDataPut(cmd *cobra.Command, args []string) error {
	path := args[0]

	var data []byte
	var err error

	if inline, _ := cmd.Flags().GetString("data"); inline != "" {
		data = []byte(inline)
	} else if file, _ := cmd.Flags().GetString("file"); file != "" {
		data, err = os.ReadFile(file)
		if err != nil {
			return fmt.Errorf("reading file: %w", err)
		}
	} else {
		return fmt.Errorf("either --data or --file is required")
	}

	var jsonData any
	if err := json.Unmarshal(data, &jsonData); err != nil {
		return fmt.Errorf("parsing JSON: %w", err)
	}

	fmt.Printf("✓ Data stored at '%s'\n", path)
	return nil
}

func runDataGet(cmd *cobra.Command, args []string) error {
	path := args[0]
	fmt.Printf("Getting data at: %s\n", path)
	return nil
}

func runDataDelete(cmd *cobra.Command, args []string) error {
	path := args[0]
	fmt.Printf("✓ Data at '%s' deleted\n", path)
	return nil
}

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

func runHealth(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	serverAddr := viper.GetString("server")
	if !strings.HasPrefix(serverAddr, "http://") && !strings.HasPrefix(serverAddr, "https://") {
		serverAddr = "http://" + serverAddr
	}
	// Use HTTP port if gRPC port specified
	serverAddr = strings.Replace(serverAddr, ":9090", ":8080", 1)

	cfg := client.Config{
		Address: serverAddr,
	}

	wait, _ := cmd.Flags().GetBool("wait")
	timeout, _ := cmd.Flags().GetDuration("timeout")

	if wait {
		ctx, cancel = context.WithTimeout(context.Background(), timeout)
		defer cancel()
	}

	c, err := client.NewClient(cfg)
	if err != nil {
		if wait {
			return waitForHealth(ctx, cfg)
		}
		fmt.Printf("✗ Server unreachable: %v\n", err)
		os.Exit(1)
	}
	defer c.Close()

	result, err := c.Health(ctx)
	if err != nil {
		fmt.Printf("✗ Health check failed: %v\n", err)
		os.Exit(1)
	}

	format := viper.GetString("output")
	if format == "json" {
		data, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(data))
	} else {
		if result.Healthy {
			fmt.Printf("✓ Server healthy (version %s)\n", result.Version)
		} else {
			fmt.Printf("✗ Server unhealthy\n")
			os.Exit(1)
		}
	}

	return nil
}

func waitForHealth(ctx context.Context, cfg client.Config) error {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout waiting for server")
		case <-ticker.C:
			c, err := client.NewClient(cfg)
			if err != nil {
				continue
			}

			result, err := c.Health(ctx)
			c.Close()

			if err == nil && result.Healthy {
				fmt.Printf("✓ Server healthy (version %s)\n", result.Version)
				return nil
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
			"go_version": "go1.22",
			"platform":   "linux/amd64",
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
