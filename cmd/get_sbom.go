package cmd

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// GetSbomCmd represents the get-sbom command
var GetSbomCmd = &cobra.Command{
	Use:   "get-sbom [org_id] [project_id]",
	Short: "Get a project's SBOM document from Snyk",
	Long: `Get a project's SBOM document from the Snyk API.

This command retrieves the Software Bill of Materials (SBOM) document for a specific project
within an organization. Both the organization ID and project ID must be provided as required arguments.

Required permissions: View Project history (org.project.snapshot.read)

Examples:
  snyk-api-cli get-sbom 12345678-1234-1234-1234-123456789012 87654321-4321-8765-2109-876543210987
  snyk-api-cli get-sbom 12345678-1234-1234-1234-123456789012 87654321-4321-8765-2109-876543210987 --format "cyclonedx1.6+json"
  snyk-api-cli get-sbom 12345678-1234-1234-1234-123456789012 87654321-4321-8765-2109-876543210987 --format "spdx2.3+json"
  snyk-api-cli get-sbom 12345678-1234-1234-1234-123456789012 87654321-4321-8765-2109-876543210987 --format "cyclonedx1.5+xml"
  snyk-api-cli get-sbom 12345678-1234-1234-1234-123456789012 87654321-4321-8765-2109-876543210987 --exclude "licenses"
  snyk-api-cli get-sbom 12345678-1234-1234-1234-123456789012 87654321-4321-8765-2109-876543210987 --format "cyclonedx1.6+json" --exclude "licenses" --verbose`,
	Args: cobra.ExactArgs(2),
	RunE: runGetSbom,
}

var (
	getSbomFormat      string
	getSbomExclude     []string
	getSbomVerbose     bool
	getSbomSilent      bool
	getSbomIncludeResp bool
	getSbomUserAgent   string
)

func init() {
	// Add flags for query parameters
	GetSbomCmd.Flags().StringVar(&getSbomFormat, "format", "", "SBOM format (cyclonedx1.6+json, cyclonedx1.6+xml, cyclonedx1.5+json, cyclonedx1.5+xml, cyclonedx1.4+json, cyclonedx1.4+xml, spdx2.3+json)")
	GetSbomCmd.Flags().StringSliceVar(&getSbomExclude, "exclude", []string{}, "Features to exclude from SBOM (e.g., 'licenses')")

	// Add standard flags like other commands
	GetSbomCmd.Flags().BoolVarP(&getSbomVerbose, "verbose", "v", false, "Make the operation more talkative")
	GetSbomCmd.Flags().BoolVarP(&getSbomSilent, "silent", "s", false, "Silent mode")
	GetSbomCmd.Flags().BoolVarP(&getSbomIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	GetSbomCmd.Flags().StringVarP(&getSbomUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runGetSbom(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	projectID := args[1]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL
	fullURL, err := buildGetSbomURL(endpoint, version, orgID, projectID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "GET",
		URL:         fullURL,
		Verbose:     getSbomVerbose,
		Silent:      getSbomSilent,
		IncludeResp: getSbomIncludeResp,
		UserAgent:   getSbomUserAgent,
	})
}

func buildGetSbomURL(endpoint, version, orgID, projectID string) (string, error) {
	// Validate the required parameters
	if strings.TrimSpace(orgID) == "" {
		return "", fmt.Errorf("org_id cannot be empty")
	}
	if strings.TrimSpace(projectID) == "" {
		return "", fmt.Errorf("project_id cannot be empty")
	}

	// Build base URL with organization ID and project ID path parameters
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/projects/%s/sbom", endpoint, orgID, projectID)

	// Parse URL to handle query parameters properly
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}

	// Add query parameters
	q := u.Query()

	// Version is required
	q.Set("version", version)

	// Add optional parameters if provided
	if getSbomFormat != "" {
		q.Set("format", getSbomFormat)
	}
	if len(getSbomExclude) > 0 {
		for _, exclude := range getSbomExclude {
			q.Add("exclude", exclude)
		}
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}
