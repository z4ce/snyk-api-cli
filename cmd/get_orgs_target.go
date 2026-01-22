package cmd

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// GetOrgsTargetCmd represents the get-orgs-target command
var GetOrgsTargetCmd = &cobra.Command{
	Use:   "get-orgs-target [org_id] [target_id]",
	Short: "Get target by target ID from Snyk",
	Long: `Get target by target ID from the Snyk API.

This command retrieves detailed information about a specific target by its ID within an organization.
Both the organization ID and target ID must be provided as required arguments.

Required permissions: View Projects (org.project.read)

Examples:
  snyk-api-cli get-orgs-target 12345678-1234-1234-1234-123456789012 87654321-4321-8765-2109-876543210987
  snyk-api-cli get-orgs-target 12345678-1234-1234-1234-123456789012 87654321-4321-8765-2109-876543210987 --verbose
  snyk-api-cli get-orgs-target 12345678-1234-1234-1234-123456789012 87654321-4321-8765-2109-876543210987 --include`,
	Args: cobra.ExactArgs(2),
	RunE: runGetOrgsTarget,
}

var (
	getOrgsTargetVerbose     bool
	getOrgsTargetSilent      bool
	getOrgsTargetIncludeResp bool
	getOrgsTargetUserAgent   string
)

func init() {
	// Add standard flags like other commands
	GetOrgsTargetCmd.Flags().BoolVarP(&getOrgsTargetVerbose, "verbose", "v", false, "Make the operation more talkative")
	GetOrgsTargetCmd.Flags().BoolVarP(&getOrgsTargetSilent, "silent", "s", false, "Silent mode")
	GetOrgsTargetCmd.Flags().BoolVarP(&getOrgsTargetIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	GetOrgsTargetCmd.Flags().StringVarP(&getOrgsTargetUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runGetOrgsTarget(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	targetID := args[1]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL
	fullURL, err := buildGetOrgsTargetURL(endpoint, version, orgID, targetID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "GET",
		URL:         fullURL,
		Verbose:     getOrgsTargetVerbose,
		Silent:      getOrgsTargetSilent,
		IncludeResp: getOrgsTargetIncludeResp,
		UserAgent:   getOrgsTargetUserAgent,
	})
}

func buildGetOrgsTargetURL(endpoint, version, orgID, targetID string) (string, error) {
	// Validate the required parameters
	if strings.TrimSpace(orgID) == "" {
		return "", fmt.Errorf("org_id cannot be empty")
	}
	if strings.TrimSpace(targetID) == "" {
		return "", fmt.Errorf("target_id cannot be empty")
	}

	// Build base URL with organization ID and target ID path parameters
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/targets/%s", endpoint, orgID, targetID)

	// Parse URL to handle query parameters properly
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}

	// Add query parameters
	q := u.Query()

	// Version is required
	q.Set("version", version)

	u.RawQuery = q.Encode()
	return u.String(), nil
}
