package cmd

import (
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// UpdateCollectionCmd represents the update-collection command
var UpdateCollectionCmd = &cobra.Command{
	Use:   "update-collection [org_id] [collection_id]",
	Short: "Update a collection in a Snyk organization",
	Long: `Update a collection in a Snyk organization.

This command updates a collection in the specified organization using the Snyk API.
Both org_id and collection_id parameters are required and should be valid UUIDs.

Examples:
  snyk-api-cli update-collection 12345678-1234-5678-9012-123456789012 87654321-4321-8765-2109-876543210987 --name "Updated Collection Name"`,
	Args: cobra.ExactArgs(2),
	RunE: runUpdateCollection,
}

var (
	updateCollectionName          string
	updateCollectionVerboseFlag   bool
	updateCollectionSilentFlag    bool
	updateCollectionIncludeFlag   bool
	updateCollectionUserAgentFlag string
)

func init() {
	// Add flags for request body attributes
	UpdateCollectionCmd.Flags().StringVar(&updateCollectionName, "name", "", "Name of the collection (required)")
	
	// Add standard flags like curl command
	UpdateCollectionCmd.Flags().BoolVarP(&updateCollectionVerboseFlag, "verbose", "v", false, "Make the operation more talkative")
	UpdateCollectionCmd.Flags().BoolVarP(&updateCollectionSilentFlag, "silent", "s", false, "Silent mode")
	UpdateCollectionCmd.Flags().BoolVarP(&updateCollectionIncludeFlag, "include", "i", false, "Include HTTP response headers in output")
	UpdateCollectionCmd.Flags().StringVarP(&updateCollectionUserAgentFlag, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
	
	// Mark required flags
	UpdateCollectionCmd.MarkFlagRequired("name")
}

func runUpdateCollection(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	collectionID := args[1]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL
	fullURL, err := buildUpdateCollectionURL(endpoint, orgID, collectionID, version)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	// Build request body
	requestBody, err := buildUpdateCollectionRequestBody()
	if err != nil {
		return fmt.Errorf("failed to build request body: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "PATCH",
		URL:         fullURL,
		Body:        requestBody,
		Verbose:     updateCollectionVerboseFlag,
		Silent:      updateCollectionSilentFlag,
		IncludeResp: updateCollectionIncludeFlag,
		UserAgent:   updateCollectionUserAgentFlag,
	})
}

func buildUpdateCollectionURL(endpoint, orgID, collectionID, version string) (string, error) {
	// Build base URL
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/collections/%s", endpoint, orgID, collectionID)

	// Parse URL to handle query parameters properly
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}

	// Add version parameter
	q := u.Query()
	q.Set("version", version)
	u.RawQuery = q.Encode()

	return u.String(), nil
}

func buildUpdateCollectionRequestBody() (string, error) {
	// Build JSON:API format request body
	data := map[string]interface{}{
		"type": "collection",
	}

	// Build attributes object
	attributes := make(map[string]interface{})
	
	if updateCollectionName != "" {
		attributes["name"] = updateCollectionName
	}

	// Add attributes if any were provided
	if len(attributes) > 0 {
		data["attributes"] = attributes
	}

	requestData := map[string]interface{}{
		"data": data,
	}

	// Convert to JSON
	jsonData, err := json.Marshal(requestData)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request body: %w", err)
	}

	return string(jsonData), nil
}
