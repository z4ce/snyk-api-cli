package cmd

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// GetIacSettingsForGroupCmd represents the get-iac-settings-for-group command
var GetIacSettingsForGroupCmd = &cobra.Command{
	Use:   "get-iac-settings-for-group [group_id]",
	Short: "Get Infrastructure as Code settings for a group",
	Long: `Get Infrastructure as Code settings for a group from the Snyk API.

This command retrieves the Infrastructure as Code settings for a specific group by its ID.
The group ID must be provided as a required argument.

Examples:
  snyk-api-cli get-iac-settings-for-group 12345678-1234-1234-1234-123456789012
  snyk-api-cli get-iac-settings-for-group 12345678-1234-1234-1234-123456789012 --verbose
  snyk-api-cli get-iac-settings-for-group 12345678-1234-1234-1234-123456789012 --include`,
	Args: cobra.ExactArgs(1),
	RunE: runGetIacSettingsForGroup,
}

var (
	getIacSettingsForGroupVerbose     bool
	getIacSettingsForGroupSilent      bool
	getIacSettingsForGroupIncludeResp bool
	getIacSettingsForGroupUserAgent   string
)

func init() {
	// Add standard flags like other commands
	GetIacSettingsForGroupCmd.Flags().BoolVarP(&getIacSettingsForGroupVerbose, "verbose", "v", false, "Make the operation more talkative")
	GetIacSettingsForGroupCmd.Flags().BoolVarP(&getIacSettingsForGroupSilent, "silent", "s", false, "Silent mode")
	GetIacSettingsForGroupCmd.Flags().BoolVarP(&getIacSettingsForGroupIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	GetIacSettingsForGroupCmd.Flags().StringVarP(&getIacSettingsForGroupUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runGetIacSettingsForGroup(cmd *cobra.Command, args []string) error {
	groupID := args[0]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL
	fullURL, err := buildGetIacSettingsForGroupURL(endpoint, version, groupID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if getIacSettingsForGroupVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting GET %s\n", fullURL)
	}

	// Create the HTTP request
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if getIacSettingsForGroupVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if getIacSettingsForGroupVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if getIacSettingsForGroupVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if getIacSettingsForGroupVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", getIacSettingsForGroupUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if getIacSettingsForGroupVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as other commands
	return handleGetIacSettingsForGroupResponse(resp, getIacSettingsForGroupIncludeResp, getIacSettingsForGroupVerbose, getIacSettingsForGroupSilent)
}

func buildGetIacSettingsForGroupURL(endpoint, version, groupID string) (string, error) {
	// Build base URL with group ID path parameter
	baseURL := fmt.Sprintf("https://%s/rest/groups/%s/settings/iac", endpoint, groupID)

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

func handleGetIacSettingsForGroupResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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