package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/z4ce/snyk-api-cli/cmd"
)

var cfgFile string

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "snyk-api-cli",
	Short: "A CLI tool for exploring the Snyk API",
	Long: `snyk-api-cli is a command-line tool designed to help you explore and interact 
with the Snyk API. It provides curl-like functionality with automatic handling 
of Snyk-specific parameters and endpoints.`,
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	// Register subcommands
	rootCmd.AddCommand(cmd.CurlCmd)

	// Global flags
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.snyk-api-cli.yaml)")
	rootCmd.PersistentFlags().String("endpoint", "api.snyk.io", "Snyk API endpoint")
	rootCmd.PersistentFlags().String("version", "2024-10-15", "API version for REST endpoints")

	// Bind flags to viper
	viper.BindPFlag("endpoint", rootCmd.PersistentFlags().Lookup("endpoint"))
	viper.BindPFlag("version", rootCmd.PersistentFlags().Lookup("version"))
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := os.UserHomeDir()
		cobra.CheckErr(err)

		// Search config in home directory with name ".snyk-api-cli" (without extension).
		viper.AddConfigPath(home)
		viper.SetConfigType("yaml")
		viper.SetConfigName(".snyk-api-cli")
	}

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
	}
}

func main() {
	Execute()
}
