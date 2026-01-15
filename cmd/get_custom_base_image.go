package cmd

import (
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

// GetCustomBaseImageCmd represents the get-custom-base-image command
var GetCustomBaseImageCmd = &cobra.Command{
	Use:   "get-custom-base-image [custombaseimage_id]",
	Short: "Get a custom base image by ID from Snyk",
	Long: `Get a custom base image by ID from the Snyk API.

This command retrieves a specific custom base image using its unique identifier.
The custombaseimage_id parameter is required and must be a valid UUID.

Examples:
  snyk-api-cli get-custom-base-image 12345678-1234-5678-9012-123456789012
  snyk-api-cli get-custom-base-image --verbose 12345678-1234-5678-9012-123456789012
  snyk-api-cli get-custom-base-image --include 12345678-1234-5678-9012-123456789012`,
	Args: cobra.ExactArgs(1),
	RunE: runGetCustomBaseImage,
}

var (
	getCustomBaseImageVerbose      bool
	getCustomBaseImageSilent       bool
	getCustomBaseImageIncludeResp  bool
	getCustomBaseImageUserAgent    string
)

func init() {
	// Add standard flags like curl command
	GetCustomBaseImageCmd.Flags().BoolVarP(&getCustomBaseImageVerbose, "verbose", "v", false, "Make the operation more talkative")
	GetCustomBaseImageCmd.Flags().BoolVarP(&getCustomBaseImageSilent, "silent", "s", false, "Silent mode")
	GetCustomBaseImageCmd.Flags().BoolVarP(&getCustomBaseImageIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	GetCustomBaseImageCmd.Flags().StringVarP(&getCustomBaseImageUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runGetCustomBaseImage(cmd *cobra.Command, args []string) error {
	customBaseImageID := args[0]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with the custombaseimage_id path parameter
	fullURL, err := buildGetCustomBaseImageURL(endpoint, customBaseImageID, version)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if getCustomBaseImageVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting GET %s\n", fullURL)
	}

	// Create the HTTP request
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if getCustomBaseImageVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if getCustomBaseImageVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if getCustomBaseImageVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if getCustomBaseImageVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", getCustomBaseImageUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if getCustomBaseImageVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as curl
	return handleGetCustomBaseImageResponse(resp, getCustomBaseImageIncludeResp, getCustomBaseImageVerbose, getCustomBaseImageSilent)
}

func buildGetCustomBaseImageURL(endpoint, customBaseImageID, version string) (string, error) {
	// Validate the custombaseimage_id parameter
	if strings.TrimSpace(customBaseImageID) == "" {
		return "", fmt.Errorf("custombaseimage_id cannot be empty")
	}

	// Build base URL with the path parameter
	baseURL := fmt.Sprintf("https://%s/rest/custom_base_images/%s", endpoint, customBaseImageID)

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

func handleGetCustomBaseImageResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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