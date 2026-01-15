package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

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
	createAssetID           string
	createAssetName         string
	createAssetClass        string
	createAssetType         string
	createAssetURL          string
	createAssetDescription  string
	createAssetTags         []string
	createAssetMetadata     string
	createAssetVerbose      bool
	createAssetSilent       bool
	createAssetIncludeResp  bool
	createAssetUserAgent    string
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

	if createAssetVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting POST %s\n", fullURL)
	}

	// Build request body
	requestBody, err := buildCreateAssetRequestBody()
	if err != nil {
		return fmt.Errorf("failed to build request body: %w", err)
	}

	if createAssetVerbose {
		fmt.Fprintf(os.Stderr, "* Request body: %s\n", requestBody)
	}

	// Create the HTTP request
	req, err := http.NewRequest("POST", fullURL, strings.NewReader(requestBody))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set content type for JSON:API
	req.Header.Set("Content-Type", "application/vnd.api+json")

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if createAssetVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if createAssetVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if createAssetVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if createAssetVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", createAssetUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if createAssetVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as curl
	return handleCreateAssetResponse(resp, createAssetIncludeResp, createAssetVerbose, createAssetSilent)
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

func handleCreateAssetResponse(resp *http.Response, includeResp, verbose, silent bool) error {
	if verbose {
		fmt.Fprintf(os.Stderr, "* Response: %s\n", resp.Status)
	}

	// Print response headers if requested
	if includeResp {
		fmt.Printf("%s %s\n", resp.Proto, resp.Status)
		for key, values := range resp.Header {
			for _, value := range values {
				fmt.Printf("%s: %s\n", key, value)
			}
		}
		fmt.Println()
	}

	// Read and print response body
	if !silent {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("failed to read response body: %w", err)
		}
		fmt.Print(string(body))
	}

	// Return error for non-2xx status codes if verbose
	if verbose && (resp.StatusCode < 200 || resp.StatusCode >= 300) {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
	}

	return nil
}