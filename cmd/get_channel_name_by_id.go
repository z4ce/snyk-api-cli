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

// GetChannelNameByIdCmd represents the get-channel-name-by-id command
var GetChannelNameByIdCmd = &cobra.Command{
	Use:   "get-channel-name-by-id [org_id] [tenant_id] [channel_id]",
	Short: "Get Slack Channel name by Slack Channel ID",
	Long: `Get Slack Channel name by Slack Channel ID from the Snyk API.

This command retrieves the name and type of a specific Slack channel by its ID
for a given organization and tenant. The organization ID, tenant ID, and channel ID 
must all be provided.

Examples:
  snyk-api-cli get-channel-name-by-id 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 C1234567890
  snyk-api-cli get-channel-name-by-id 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 C0987654321 --verbose
  snyk-api-cli get-channel-name-by-id 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 C1122334455 --include`,
	Args: cobra.ExactArgs(3),
	RunE: runGetChannelNameById,
}

var (
	getChannelNameByIdVerbose     bool
	getChannelNameByIdSilent      bool
	getChannelNameByIdIncludeResp bool
	getChannelNameByIdUserAgent   string
)

func init() {
	// Add standard flags like other commands
	GetChannelNameByIdCmd.Flags().BoolVarP(&getChannelNameByIdVerbose, "verbose", "v", false, "Make the operation more talkative")
	GetChannelNameByIdCmd.Flags().BoolVarP(&getChannelNameByIdSilent, "silent", "s", false, "Silent mode")
	GetChannelNameByIdCmd.Flags().BoolVarP(&getChannelNameByIdIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	GetChannelNameByIdCmd.Flags().StringVarP(&getChannelNameByIdUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runGetChannelNameById(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	tenantID := args[1]
	channelID := args[2]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL
	fullURL, err := buildGetChannelNameByIdURL(endpoint, version, orgID, tenantID, channelID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if getChannelNameByIdVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting GET %s\n", fullURL)
	}

	// Create the HTTP request
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if getChannelNameByIdVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if getChannelNameByIdVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if getChannelNameByIdVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if getChannelNameByIdVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", getChannelNameByIdUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if getChannelNameByIdVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as other commands
	return handleGetChannelNameByIdResponse(resp, getChannelNameByIdIncludeResp, getChannelNameByIdVerbose, getChannelNameByIdSilent)
}

func buildGetChannelNameByIdURL(endpoint, version, orgID, tenantID, channelID string) (string, error) {
	// Build base URL with org ID, tenant ID, and channel ID path parameters
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/slack_app/%s/channels/%s", endpoint, orgID, tenantID, channelID)

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

func handleGetChannelNameByIdResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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