package cmd

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// GetOrgProjectCmd represents the get-org-project command
var GetOrgProjectCmd = &cobra.Command{
	Use:   "get-org-project [org_id] [project_id]",
	Short: "Get a project by ID from a Snyk organization",
	Long: `Get a project by ID from a Snyk organization.

This command retrieves detailed information about a specific project by its ID within an organization.
Both the organization ID and project ID must be provided as required arguments.

Required permissions: View Projects (org.project.read)

Examples:
  snyk-api-cli get-org-project 12345678-1234-1234-1234-123456789012 87654321-4321-8765-2109-876543210987
  snyk-api-cli get-org-project 12345678-1234-1234-1234-123456789012 87654321-4321-8765-2109-876543210987 --expand "target"
  snyk-api-cli get-org-project 12345678-1234-1234-1234-123456789012 87654321-4321-8765-2109-876543210987 --meta-latest-issue-counts --meta-latest-dependency-total
  snyk-api-cli get-org-project 12345678-1234-1234-1234-123456789012 87654321-4321-8765-2109-876543210987 --verbose
  snyk-api-cli get-org-project 12345678-1234-1234-1234-123456789012 87654321-4321-8765-2109-876543210987 --include`,
	Args: cobra.ExactArgs(2),
	RunE: runGetOrgProject,
}

var (
	getOrgProjectExpand                    []string
	getOrgProjectMetaLatestIssueCounts     bool
	getOrgProjectMetaLatestDependencyTotal bool
	getOrgProjectVerbose                   bool
	getOrgProjectSilent                    bool
	getOrgProjectIncludeResp               bool
	getOrgProjectUserAgent                 string
)

func init() {
	// Add flags for query parameters
	GetOrgProjectCmd.Flags().StringSliceVar(&getOrgProjectExpand, "expand", []string{}, "Expand relationships (e.g., 'target')")
	GetOrgProjectCmd.Flags().BoolVar(&getOrgProjectMetaLatestIssueCounts, "meta-latest-issue-counts", false, "Include latest issue count summary")
	GetOrgProjectCmd.Flags().BoolVar(&getOrgProjectMetaLatestDependencyTotal, "meta-latest-dependency-total", false, "Include total dependencies count")

	// Add standard flags like other commands
	GetOrgProjectCmd.Flags().BoolVarP(&getOrgProjectVerbose, "verbose", "v", false, "Make the operation more talkative")
	GetOrgProjectCmd.Flags().BoolVarP(&getOrgProjectSilent, "silent", "s", false, "Silent mode")
	GetOrgProjectCmd.Flags().BoolVarP(&getOrgProjectIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	GetOrgProjectCmd.Flags().StringVarP(&getOrgProjectUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runGetOrgProject(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	projectID := args[1]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL
	fullURL, err := buildGetOrgProjectURL(endpoint, version, orgID, projectID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "GET",
		URL:         fullURL,
		Verbose:     getOrgProjectVerbose,
		Silent:      getOrgProjectSilent,
		IncludeResp: getOrgProjectIncludeResp,
		UserAgent:   getOrgProjectUserAgent,
	})
}

func buildGetOrgProjectURL(endpoint, version, orgID, projectID string) (string, error) {
	// Validate the required parameters
	if strings.TrimSpace(orgID) == "" {
		return "", fmt.Errorf("org_id cannot be empty")
	}
	if strings.TrimSpace(projectID) == "" {
		return "", fmt.Errorf("project_id cannot be empty")
	}

	// Build base URL with organization ID and project ID path parameters
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/projects/%s", endpoint, orgID, projectID)

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
	if len(getOrgProjectExpand) > 0 {
		for _, expand := range getOrgProjectExpand {
			q.Add("expand", expand)
		}
	}
	if getOrgProjectMetaLatestIssueCounts {
		q.Set("meta.latest_issue_counts", "true")
	}
	if getOrgProjectMetaLatestDependencyTotal {
		q.Set("meta.latest_dependency_total", "true")
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}
