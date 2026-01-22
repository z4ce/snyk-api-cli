package cmd

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// GetOrgCmd represents the get-org command
var GetOrgCmd = &cobra.Command{
	Use:   "get-org [org_id]",
	Short: "Get details of a specific organization from Snyk",
	Long: `Get details of a specific organization from the Snyk API.

This command retrieves detailed information about a specific organization by its ID.
The organization ID must be provided as a required argument.

Examples:
  snyk-api-cli get-org 12345678-1234-1234-1234-123456789012
  snyk-api-cli get-org 12345678-1234-1234-1234-123456789012 --verbose
  snyk-api-cli get-org 12345678-1234-1234-1234-123456789012 --expand tenant
  snyk-api-cli get-org 12345678-1234-1234-1234-123456789012 --include`,
	Args: cobra.ExactArgs(1),
	RunE: runGetOrg,
}

var (
	getOrgVerbose     bool
	getOrgSilent      bool
	getOrgIncludeResp bool
	getOrgUserAgent   string
	getOrgExpand      []string
)

func init() {
	// Add standard flags like other commands
	GetOrgCmd.Flags().BoolVarP(&getOrgVerbose, "verbose", "v", false, "Make the operation more talkative")
	GetOrgCmd.Flags().BoolVarP(&getOrgSilent, "silent", "s", false, "Silent mode")
	GetOrgCmd.Flags().BoolVarP(&getOrgIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	GetOrgCmd.Flags().StringVarP(&getOrgUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
	
	// Add expand flag based on API spec
	GetOrgCmd.Flags().StringSliceVar(&getOrgExpand, "expand", []string{}, "Expand the specified related resources in the response (allowed values: tenant)")
}

func runGetOrg(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL
	fullURL, err := buildGetOrgURL(endpoint, version, orgID, getOrgExpand)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "GET",
		URL:         fullURL,
		Verbose:     getOrgVerbose,
		Silent:      getOrgSilent,
		IncludeResp: getOrgIncludeResp,
		UserAgent:   getOrgUserAgent,
	})
}

func buildGetOrgURL(endpoint, version, orgID string, expand []string) (string, error) {
	// Build base URL with org ID path parameter
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s", endpoint, orgID)

	// Parse URL to handle query parameters properly
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}

	// Add query parameters
	q := u.Query()

	// Version is required
	q.Set("version", version)

	// Add expand parameter if specified
	if len(expand) > 0 {
		// Validate expand values
		for _, value := range expand {
			if value != "tenant" {
				return "", fmt.Errorf("invalid expand value: %s (allowed values: tenant)", value)
			}
		}
		q.Set("expand", strings.Join(expand, ","))
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}
