package cmd

import (
	"fmt"
	"net/url"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// GetCollectionCmd represents the get-collection command
var GetCollectionCmd = &cobra.Command{
	Use:   "get-collection [org_id] [collection_id]",
	Short: "Get a specific collection from Snyk",
	Long: `Get a specific collection from the Snyk API for a specific organization and collection ID.

This command retrieves a single collection by its ID that can be used to organize and manage projects.

Examples:
  snyk-api-cli get-collection 12345678-1234-5678-9012-123456789012 87654321-4321-8765-2109-876543210987
  snyk-api-cli get-collection 12345678-1234-5678-9012-123456789012 87654321-4321-8765-2109-876543210987 --verbose`,
	Args: cobra.ExactArgs(2),
	RunE: runGetCollection,
}

var (
	getCollectionVerbose     bool
	getCollectionSilent      bool
	getCollectionIncludeResp bool
	getCollectionUserAgent   string
)

func init() {
	// Add standard flags like curl command
	GetCollectionCmd.Flags().BoolVarP(&getCollectionVerbose, "verbose", "v", false, "Make the operation more talkative")
	GetCollectionCmd.Flags().BoolVarP(&getCollectionSilent, "silent", "s", false, "Silent mode")
	GetCollectionCmd.Flags().BoolVarP(&getCollectionIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	GetCollectionCmd.Flags().StringVarP(&getCollectionUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runGetCollection(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	collectionID := args[1]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL
	fullURL, err := buildGetCollectionURL(endpoint, orgID, collectionID, version)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "GET",
		URL:         fullURL,
		Verbose:     getCollectionVerbose,
		Silent:      getCollectionSilent,
		IncludeResp: getCollectionIncludeResp,
		UserAgent:   getCollectionUserAgent,
	})
}

func buildGetCollectionURL(endpoint, orgID, collectionID, version string) (string, error) {
	// Build base URL
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/collections/%s", endpoint, orgID, collectionID)

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
