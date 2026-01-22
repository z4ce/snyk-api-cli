package cmd

import (
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// CreateCollectionCmd represents the create-collection command
var CreateCollectionCmd = &cobra.Command{
	Use:   "create-collection [org_id]",
	Short: "Create a collection in a Snyk organization",
	Long: `Create a collection in a Snyk organization.

This command creates a collection in the specified organization using the Snyk API.
The org_id parameter is required and should be a valid organization UUID.

Examples:
  snyk-api-cli create-collection 12345678-1234-5678-9012-123456789012 --name "My Collection"
  snyk-api-cli create-collection 12345678-1234-5678-9012-123456789012 --name "Security Collection" --type "collection"`,
	Args: cobra.ExactArgs(1),
	RunE: runCreateCollection,
}

var (
	createCollectionName        string
	createCollectionType        string
	createCollectionVerbose     bool
	createCollectionSilent      bool
	createCollectionIncludeResp bool
	createCollectionUserAgent   string
)

func init() {
	// Add flags for request body attributes
	CreateCollectionCmd.Flags().StringVar(&createCollectionName, "name", "", "Name of the collection (required)")
	CreateCollectionCmd.Flags().StringVar(&createCollectionType, "type", "collection", "Type of the collection")

	// Add standard flags like curl command
	CreateCollectionCmd.Flags().BoolVarP(&createCollectionVerbose, "verbose", "v", false, "Make the operation more talkative")
	CreateCollectionCmd.Flags().BoolVarP(&createCollectionSilent, "silent", "s", false, "Silent mode")
	CreateCollectionCmd.Flags().BoolVarP(&createCollectionIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	CreateCollectionCmd.Flags().StringVarP(&createCollectionUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")

	// Mark required flags
	CreateCollectionCmd.MarkFlagRequired("name")
}

func runCreateCollection(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL
	fullURL, err := buildCreateCollectionURL(endpoint, orgID, version)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	// Build request body
	requestBody, err := buildCreateCollectionRequestBody()
	if err != nil {
		return fmt.Errorf("failed to build request body: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "POST",
		URL:         fullURL,
		Body:        requestBody,
		ContentType: "application/vnd.api+json",
		Verbose:     createCollectionVerbose,
		Silent:      createCollectionSilent,
		IncludeResp: createCollectionIncludeResp,
		UserAgent:   createCollectionUserAgent,
	})
}

func buildCreateCollectionURL(endpoint, orgID, version string) (string, error) {
	// Build base URL
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/collections", endpoint, orgID)

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

func buildCreateCollectionRequestBody() (string, error) {
	// Build JSON:API format request body
	data := map[string]interface{}{
		"type": createCollectionType,
	}

	// Build attributes object
	attributes := make(map[string]interface{})

	if createCollectionName != "" {
		attributes["name"] = createCollectionName
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
