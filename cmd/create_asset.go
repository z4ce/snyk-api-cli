package cmd

import (
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// CreateAssetCmd represents the create-asset command
var CreateAssetCmd = &cobra.Command{
	Use:   "create-asset [org_id]",
	Short: "Create an asset in a Snyk organization",
	Long: `Create an asset in a Snyk organization.

This command creates an asset in the specified organization using the Snyk API.
The org_id parameter is required and should be a valid organization UUID.

Examples:
  snyk-api-cli create-asset 12345678-1234-5678-9012-123456789012
  snyk-api-cli create-asset 12345678-1234-5678-9012-123456789012 --asset-id 87654321-4321-8765-2109-876543210987
  snyk-api-cli create-asset 12345678-1234-5678-9012-123456789012 --name "My Asset" --asset-class "repository" --type "git"`,
	Args: cobra.ExactArgs(1),
	RunE: runCreateAsset,
}

var (
	createAssetID          string
	createAssetName        string
	createAssetClass       string
	createAssetType        string
	createAssetURL         string
	createAssetDescription string
	createAssetTags        []string
	createAssetMetadata    string
	createAssetVerbose     bool
	createAssetSilent      bool
	createAssetIncludeResp bool
	createAssetUserAgent   string
)

func init() {
	// Add flags for request body attributes
	CreateAssetCmd.Flags().StringVar(&createAssetID, "asset-id", "", "Asset ID (optional UUID)")
	CreateAssetCmd.Flags().StringVar(&createAssetName, "name", "", "Name of the asset")
	CreateAssetCmd.Flags().StringVar(&createAssetClass, "asset-class", "", "Asset class (e.g., repository, package, image)")
	CreateAssetCmd.Flags().StringVar(&createAssetType, "type", "", "Asset type (e.g., git, npm, docker)")
	CreateAssetCmd.Flags().StringVar(&createAssetURL, "url", "", "URL of the asset")
	CreateAssetCmd.Flags().StringVar(&createAssetDescription, "description", "", "Description of the asset")
	CreateAssetCmd.Flags().StringSliceVar(&createAssetTags, "tags", []string{}, "Tags associated with the asset")
	CreateAssetCmd.Flags().StringVar(&createAssetMetadata, "metadata", "", "Additional metadata as JSON string")

	// Add standard flags like curl command
	CreateAssetCmd.Flags().BoolVarP(&createAssetVerbose, "verbose", "v", false, "Make the operation more talkative")
	CreateAssetCmd.Flags().BoolVarP(&createAssetSilent, "silent", "s", false, "Silent mode")
	CreateAssetCmd.Flags().BoolVarP(&createAssetIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	CreateAssetCmd.Flags().StringVarP(&createAssetUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runCreateAsset(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL
	fullURL, err := buildCreateAssetURL(endpoint, orgID, version)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	// Build request body
	requestBody, err := buildCreateAssetRequestBody()
	if err != nil {
		return fmt.Errorf("failed to build request body: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "POST",
		URL:         fullURL,
		Body:        requestBody,
		ContentType: "application/vnd.api+json",
		Verbose:     createAssetVerbose,
		Silent:      createAssetSilent,
		IncludeResp: createAssetIncludeResp,
		UserAgent:   createAssetUserAgent,
	})
}

func buildCreateAssetURL(endpoint, orgID, version string) (string, error) {
	// Build base URL
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/assets", endpoint, orgID)

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

func buildCreateAssetRequestBody() (string, error) {
	// Build JSON:API format request body
	data := map[string]interface{}{
		"type": "assets",
	}

	// Add asset ID if provided
	if createAssetID != "" {
		data["id"] = createAssetID
	}

	// Build attributes object
	attributes := make(map[string]interface{})

	if createAssetName != "" {
		attributes["name"] = createAssetName
	}

	if createAssetClass != "" {
		attributes["asset_class"] = createAssetClass
	}

	if createAssetType != "" {
		attributes["type"] = createAssetType
	}

	if createAssetURL != "" {
		attributes["url"] = createAssetURL
	}

	if createAssetDescription != "" {
		attributes["description"] = createAssetDescription
	}

	if len(createAssetTags) > 0 {
		attributes["tags"] = createAssetTags
	}

	// Handle metadata JSON string
	if createAssetMetadata != "" {
		var metadata interface{}
		err := json.Unmarshal([]byte(createAssetMetadata), &metadata)
		if err != nil {
			return "", fmt.Errorf("failed to parse metadata JSON: %w", err)
		}
		attributes["metadata"] = metadata
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
