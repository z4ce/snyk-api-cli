package cmd

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// DeleteCollectionCmd represents the delete-collection command
var DeleteCollectionCmd = &cobra.Command{
	Use:   "delete-collection [org_id] [collection_id]",
	Short: "Delete a collection by ID from Snyk",
	Long: `Delete a collection by ID from the Snyk API.

This command deletes a specific collection using its unique identifier within an organization.
Both org_id and collection_id parameters are required and must be valid UUIDs.

Examples:
  snyk-api-cli delete-collection 12345678-1234-5678-9012-123456789012 87654321-4321-8765-2109-876543210987
  snyk-api-cli delete-collection --verbose 12345678-1234-5678-9012-123456789012 87654321-4321-8765-2109-876543210987
  snyk-api-cli delete-collection --include 12345678-1234-5678-9012-123456789012 87654321-4321-8765-2109-876543210987`,
	Args: cobra.ExactArgs(2),
	RunE: runDeleteCollection,
}

var (
	deleteCollectionVerbose     bool
	deleteCollectionSilent      bool
	deleteCollectionIncludeResp bool
	deleteCollectionUserAgent   string
)

func init() {
	// Add standard flags like curl command
	DeleteCollectionCmd.Flags().BoolVarP(&deleteCollectionVerbose, "verbose", "v", false, "Make the operation more talkative")
	DeleteCollectionCmd.Flags().BoolVarP(&deleteCollectionSilent, "silent", "s", false, "Silent mode")
	DeleteCollectionCmd.Flags().BoolVarP(&deleteCollectionIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	DeleteCollectionCmd.Flags().StringVarP(&deleteCollectionUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runDeleteCollection(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	collectionID := args[1]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with the org_id and collection_id path parameters
	fullURL, err := buildDeleteCollectionURL(endpoint, orgID, collectionID, version)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "DELETE",
		URL:         fullURL,
		Verbose:     deleteCollectionVerbose,
		Silent:      deleteCollectionSilent,
		IncludeResp: deleteCollectionIncludeResp,
		UserAgent:   deleteCollectionUserAgent,
	})
}

func buildDeleteCollectionURL(endpoint, orgID, collectionID, version string) (string, error) {
	// Validate the org_id parameter
	if strings.TrimSpace(orgID) == "" {
		return "", fmt.Errorf("org_id cannot be empty")
	}

	// Validate the collection_id parameter
	if strings.TrimSpace(collectionID) == "" {
		return "", fmt.Errorf("collection_id cannot be empty")
	}

	// Build base URL with the path parameters
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/collections/%s", endpoint, orgID, collectionID)

	// Parse URL to handle query parameters properly
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}

	// Add required version query parameter
	q := u.Query()
	q.Set("version", version)
	u.RawQuery = q.Encode()

	return u.String(), nil
}
