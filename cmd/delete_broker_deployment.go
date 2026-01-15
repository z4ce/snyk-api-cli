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

// DeleteBrokerDeploymentCmd represents the delete-broker-deployment command
var DeleteBrokerDeploymentCmd = &cobra.Command{
	Use:   "delete-broker-deployment [tenant_id] [install_id] [deployment_id]",
	Short: "Deletes Broker deployment",
	Long: `Deletes Broker deployment from the Snyk API.

This command deletes an existing broker deployment for a specific tenant, install ID, and deployment ID.

Examples:
  snyk-api-cli delete-broker-deployment 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 11111111-1111-1111-1111-111111111111
  snyk-api-cli delete-broker-deployment 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 11111111-1111-1111-1111-111111111111 --verbose`,
	Args: cobra.ExactArgs(3),
	RunE: runDeleteBrokerDeployment,
}

var (
	deleteBrokerDeploymentVerbose     bool
	deleteBrokerDeploymentSilent      bool
	deleteBrokerDeploymentIncludeResp bool
	deleteBrokerDeploymentUserAgent   string
)

func init() {
	// Add standard flags like other commands
	DeleteBrokerDeploymentCmd.Flags().BoolVarP(&deleteBrokerDeploymentVerbose, "verbose", "v", false, "Make the operation more talkative")
	DeleteBrokerDeploymentCmd.Flags().BoolVarP(&deleteBrokerDeploymentSilent, "silent", "s", false, "Silent mode")
	DeleteBrokerDeploymentCmd.Flags().BoolVarP(&deleteBrokerDeploymentIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	DeleteBrokerDeploymentCmd.Flags().StringVarP(&deleteBrokerDeploymentUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runDeleteBrokerDeployment(cmd *cobra.Command, args []string) error {
	tenantID := args[0]
	installID := args[1]
	deploymentID := args[2]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with query parameters
	fullURL, err := buildDeleteBrokerDeploymentURL(endpoint, version, tenantID, installID, deploymentID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if deleteBrokerDeploymentVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting DELETE %s\n", fullURL)
	}

	// Create the HTTP request
	req, err := http.NewRequest("DELETE", fullURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if deleteBrokerDeploymentVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if deleteBrokerDeploymentVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if deleteBrokerDeploymentVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if deleteBrokerDeploymentVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", deleteBrokerDeploymentUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if deleteBrokerDeploymentVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as other commands
	return handleDeleteBrokerDeploymentResponse(resp, deleteBrokerDeploymentIncludeResp, deleteBrokerDeploymentVerbose, deleteBrokerDeploymentSilent)
}

func buildDeleteBrokerDeploymentURL(endpoint, version, tenantID, installID, deploymentID string) (string, error) {
	// Build base URL
	baseURL := fmt.Sprintf("https://%s/rest/tenants/%s/brokers/installs/%s/deployments/%s", endpoint, tenantID, installID, deploymentID)

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

func handleDeleteBrokerDeploymentResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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