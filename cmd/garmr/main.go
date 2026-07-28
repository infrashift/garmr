// cmd/garmr/main.go
// Package main provides the Garmr CLI.
package main

import (
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	// version is injected at build time via -ldflags (see Makefile).
	version = "dev"
	cfgFile string
	osExit  = os.Exit
)

// rootCmd is the base command for the Garmr CLI.
var rootCmd = &cobra.Command{
	Use:   "garmr",
	Short: "Garmr - CUE-based policy evaluation",
	Long: `Garmr is a policy-as-code agent that uses CUE for schema validation,
constraint evaluation, and policy enforcement.

Garmr provides a drop-in replacement for Open Policy Agent and HashiCorp Sentinel
with the power of CUE's type system and constraint solving.

Examples:
  # Evaluate a resource against policies
  garmr eval --input resource.json

  # Validate a policy file
  garmr validate policy.cue

  # List loaded policies
  garmr policy list

  # Start the server
  garmr-server --config config.yaml`,
	SilenceUsage: true,
}

func init() {
	cobra.OnInitialize(initConfig)

	// Global flags
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.garmr.yaml)")
	rootCmd.PersistentFlags().String("server", "http://localhost:8080", "Garmr server URL")
	rootCmd.PersistentFlags().StringP("output", "o", "table", "output format (table, json, yaml)")
	rootCmd.PersistentFlags().BoolP("quiet", "q", false, "suppress non-essential output")
	rootCmd.PersistentFlags().BoolP("verbose", "v", false, "show rule details (default: show on fail, hide on pass; use --verbose=false to always hide)")

	// Bind flags to viper. BindPFlag only fails when the flag does not
	// exist, which is a programming error worth aborting on.
	for key, name := range map[string]string{"server": "server", "output": "output"} {
		if err := viper.BindPFlag(key, rootCmd.PersistentFlags().Lookup(name)); err != nil {
			panic(err)
		}
	}

	// Add subcommands
	rootCmd.AddCommand(evalCmd)
	rootCmd.AddCommand(validateCmd)
	rootCmd.AddCommand(policyCmd)
	rootCmd.AddCommand(healthCmd)
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(docsCmd)
	rootCmd.AddCommand(testCmd)
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		home, err := os.UserHomeDir()
		cobra.CheckErr(err)

		viper.AddConfigPath(home)
		viper.AddConfigPath(".")
		viper.SetConfigType("yaml")
		viper.SetConfigName(".garmr")
	}

	viper.SetEnvPrefix("GARMR")
	viper.AutomaticEnv()

	// A missing config file is fine — flags and env vars carry the defaults.
	_ = viper.ReadInConfig()
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
