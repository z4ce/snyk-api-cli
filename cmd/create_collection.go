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
	createCollectionName         string
	createCollectionType         string
	createCollectionVerbose      bool
	createCollectionSilent       bool
	createCollectionIncludeResp  bool
	createCollectionUserAgent    string
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

	if createCollectionVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting POST %s\n", fullURL)
	}

	// Build request body
	requestBody, err := buildCreateCollectionRequestBody()
	if err != nil {
		return fmt.Errorf("failed to build request body: %w", err)
	}

	if createCollectionVerbose {
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
	if createCollectionVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if createCollectionVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if createCollectionVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if createCollectionVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", createCollectionUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if createCollectionVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as curl
	return handleCreateCollectionResponse(resp, createCollectionIncludeResp, createCollectionVerbose, createCollectionSilent)
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

func handleCreateCollectionResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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