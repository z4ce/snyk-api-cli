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
	updateCollectionName         string
	updateCollectionVerboseFlag  bool
	updateCollectionSilentFlag   bool
	updateCollectionIncludeFlag  bool
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

	if updateCollectionVerboseFlag {
		fmt.Fprintf(os.Stderr, "* Requesting PATCH %s\n", fullURL)
	}

	// Build request body
	requestBody, err := buildUpdateCollectionRequestBody()
	if err != nil {
		return fmt.Errorf("failed to build request body: %w", err)
	}

	if updateCollectionVerboseFlag {
		fmt.Fprintf(os.Stderr, "* Request body: %s\n", requestBody)
	}

	// Create the HTTP request
	req, err := http.NewRequest("PATCH", fullURL, strings.NewReader(requestBody))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set content type for JSON:API
	req.Header.Set("Content-Type", "application/vnd.api+json")

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if updateCollectionVerboseFlag {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if updateCollectionVerboseFlag {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if updateCollectionVerboseFlag {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if updateCollectionVerboseFlag {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", updateCollectionUserAgentFlag)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if updateCollectionVerboseFlag {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as curl
	return handleUpdateCollectionResponse(resp, updateCollectionIncludeFlag, updateCollectionVerboseFlag, updateCollectionSilentFlag)
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

func handleUpdateCollectionResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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