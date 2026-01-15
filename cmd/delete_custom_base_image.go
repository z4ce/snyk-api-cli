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

// DeleteCustomBaseImageCmd represents the delete-custom-base-image command
var DeleteCustomBaseImageCmd = &cobra.Command{
	Use:   "delete-custom-base-image [custombaseimage_id]",
	Short: "Delete a custom base image by ID from Snyk",
	Long: `Delete a custom base image by ID from the Snyk API.

This command deletes a specific custom base image using its unique identifier.
The custombaseimage_id parameter is required and must be a valid UUID.
Note: This does not affect the related container project.

Examples:
  snyk-api-cli delete-custom-base-image 12345678-1234-5678-9012-123456789012
  snyk-api-cli delete-custom-base-image --verbose 12345678-1234-5678-9012-123456789012
  snyk-api-cli delete-custom-base-image --include 12345678-1234-5678-9012-123456789012`,
	Args: cobra.ExactArgs(1),
	RunE: runDeleteCustomBaseImage,
}

var (
	deleteCustomBaseImageVerbose     bool
	deleteCustomBaseImageSilent      bool
	deleteCustomBaseImageIncludeResp bool
	deleteCustomBaseImageUserAgent   string
)

func init() {
	// Add standard flags like curl command
	DeleteCustomBaseImageCmd.Flags().BoolVarP(&deleteCustomBaseImageVerbose, "verbose", "v", false, "Make the operation more talkative")
	DeleteCustomBaseImageCmd.Flags().BoolVarP(&deleteCustomBaseImageSilent, "silent", "s", false, "Silent mode")
	DeleteCustomBaseImageCmd.Flags().BoolVarP(&deleteCustomBaseImageIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	DeleteCustomBaseImageCmd.Flags().StringVarP(&deleteCustomBaseImageUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runDeleteCustomBaseImage(cmd *cobra.Command, args []string) error {
	customBaseImageID := args[0]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with the custombaseimage_id path parameter
	fullURL, err := buildDeleteCustomBaseImageURL(endpoint, customBaseImageID, version)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if deleteCustomBaseImageVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting DELETE %s\n", fullURL)
	}

	// Create the HTTP request
	req, err := http.NewRequest("DELETE", fullURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if deleteCustomBaseImageVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if deleteCustomBaseImageVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if deleteCustomBaseImageVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if deleteCustomBaseImageVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", deleteCustomBaseImageUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if deleteCustomBaseImageVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as curl
	return handleDeleteCustomBaseImageResponse(resp, deleteCustomBaseImageIncludeResp, deleteCustomBaseImageVerbose, deleteCustomBaseImageSilent)
}

func buildDeleteCustomBaseImageURL(endpoint, customBaseImageID, version string) (string, error) {
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

func handleDeleteCustomBaseImageResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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