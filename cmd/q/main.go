// cmd/q/main.go
// Package main provides the Q Policy Agent CLI.
package main

import (
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	version = "0.1.0"
	cfgFile string
)

// rootCmd is the base command for the Q CLI.
var rootCmd = &cobra.Command{
	Use:   "q",
	Short: "Q Policy Agent - CUE-based policy evaluation",
	Long: `Q is a policy-as-code agent that uses CUE for schema validation,
constraint evaluation, and policy enforcement.

Q provides a drop-in replacement for Open Policy Agent and HashiCorp Sentinel
with the power of CUE's type system and constraint solving.

Examples:
  # Evaluate a resource against policies
  q eval --input resource.json

  # Validate a policy file
  q validate policy.cue

  # List loaded policies
  q policy list

  # Start the server
  q-server --config config.yaml`,
	SilenceUsage: true,
}

func init() {
	cobra.OnInitialize(initConfig)

	// Global flags
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.q.yaml)")
	rootCmd.PersistentFlags().String("server", "localhost:9090", "Q server address")
	rootCmd.PersistentFlags().Bool("insecure", false, "disable TLS")
	rootCmd.PersistentFlags().String("tls-cert", "", "TLS certificate file")
	rootCmd.PersistentFlags().StringP("output", "o", "table", "output format (table, json, yaml)")
	rootCmd.PersistentFlags().BoolP("quiet", "q", false, "suppress non-essential output")
	rootCmd.PersistentFlags().BoolP("verbose", "v", false, "verbose output")

	// Bind flags to viper
	viper.BindPFlag("server", rootCmd.PersistentFlags().Lookup("server"))
	viper.BindPFlag("insecure", rootCmd.PersistentFlags().Lookup("insecure"))
	viper.BindPFlag("tls-cert", rootCmd.PersistentFlags().Lookup("tls-cert"))
	viper.BindPFlag("output", rootCmd.PersistentFlags().Lookup("output"))

	// Add subcommands
	rootCmd.AddCommand(evalCmd)
	rootCmd.AddCommand(validateCmd)
	rootCmd.AddCommand(policyCmd)
	rootCmd.AddCommand(dataCmd)
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
		viper.SetConfigName(".q")
	}

	viper.SetEnvPrefix("Q")
	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err == nil {
		// Config file found and loaded
	}
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
