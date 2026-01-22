package cmd

import (
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// CreateGroupExportCmd represents the create-group-export command
var CreateGroupExportCmd = &cobra.Command{
	Use:   "create-group-export [group_id]",
	Short: "Create a group export for a specific group in Snyk",
	Long: `Create a group export for a specific group in the Snyk API.

This command creates a group export for a specific group by its ID.
The group ID must be provided as a required argument, and the dataset,
destination, and formats must be provided as flags.

Examples:
  snyk-api-cli create-group-export 12345678-1234-1234-1234-123456789012 --dataset "issues" --destination-type "snyk" --destination-file-name "export.csv" --formats "csv"
  snyk-api-cli create-group-export 12345678-1234-1234-1234-123456789012 --dataset "issues" --destination-type "snyk" --destination-file-name "export.csv" --formats "csv" --columns "id,title,severity" --include-deleted --include-deactivated --verbose`,
	Args: cobra.ExactArgs(1),
	RunE: runCreateGroupExport,
}

var (
	createGroupExportDataset            string
	createGroupExportDestinationType    string
	createGroupExportDestinationFile    string
	createGroupExportFormats            []string
	createGroupExportColumns            []string
	createGroupExportIncludeDeleted     bool
	createGroupExportIncludeDeactivated bool
	createGroupExportVerbose            bool
	createGroupExportSilent             bool
	createGroupExportIncludeResp        bool
	createGroupExportUserAgent          string
)

func init() {
	// Add flags for request body attributes
	CreateGroupExportCmd.Flags().StringVar(&createGroupExportDataset, "dataset", "", "Dataset to export (required)")
	CreateGroupExportCmd.Flags().StringVar(&createGroupExportDestinationType, "destination-type", "snyk", "Destination type (default: snyk)")
	CreateGroupExportCmd.Flags().StringVar(&createGroupExportDestinationFile, "destination-file-name", "", "Destination file name (required)")
	CreateGroupExportCmd.Flags().StringSliceVar(&createGroupExportFormats, "formats", []string{}, "Export formats (required, e.g., csv)")
	CreateGroupExportCmd.Flags().StringSliceVar(&createGroupExportColumns, "columns", []string{}, "Columns to include in export (optional)")

	// Add query parameter flags
	CreateGroupExportCmd.Flags().BoolVar(&createGroupExportIncludeDeleted, "include-deleted", false, "Include deleted issues")
	CreateGroupExportCmd.Flags().BoolVar(&createGroupExportIncludeDeactivated, "include-deactivated", false, "Include disabled issues")

	// Add standard flags like other commands
	CreateGroupExportCmd.Flags().BoolVarP(&createGroupExportVerbose, "verbose", "v", false, "Make the operation more talkative")
	CreateGroupExportCmd.Flags().BoolVarP(&createGroupExportSilent, "silent", "s", false, "Silent mode")
	CreateGroupExportCmd.Flags().BoolVarP(&createGroupExportIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	CreateGroupExportCmd.Flags().StringVarP(&createGroupExportUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")

	// Mark required flags
	CreateGroupExportCmd.MarkFlagRequired("dataset")
	CreateGroupExportCmd.MarkFlagRequired("destination-file-name")
	CreateGroupExportCmd.MarkFlagRequired("formats")
}

func runCreateGroupExport(cmd *cobra.Command, args []string) error {
	groupID := args[0]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL
	fullURL, err := buildCreateGroupExportURL(endpoint, version, groupID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	// Build request body
	requestBody, err := buildCreateGroupExportRequestBody()
	if err != nil {
		return fmt.Errorf("failed to build request body: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "POST",
		URL:         fullURL,
		Body:        requestBody,
		ContentType: "application/json",
		Verbose:     createGroupExportVerbose,
		Silent:      createGroupExportSilent,
		IncludeResp: createGroupExportIncludeResp,
		UserAgent:   createGroupExportUserAgent,
	})
}

func buildCreateGroupExportURL(endpoint, version, groupID string) (string, error) {
	// Build base URL with group ID path parameter
	baseURL := fmt.Sprintf("https://%s/rest/groups/%s/export", endpoint, groupID)

	// Parse URL to handle query parameters properly
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}

	// Add version parameter
	q := u.Query()
	q.Set("version", version)

	// Add optional query parameters
	if createGroupExportIncludeDeleted {
		q.Set("include_deleted", "true")
	}
	if createGroupExportIncludeDeactivated {
		q.Set("include_deactivated", "true")
	}

	u.RawQuery = q.Encode()

	return u.String(), nil
}

func buildCreateGroupExportRequestBody() (string, error) {
	// Build request body according to the API specification
	attributes := map[string]interface{}{
		"dataset": createGroupExportDataset,
		"destination": map[string]interface{}{
			"type":      createGroupExportDestinationType,
			"file_name": createGroupExportDestinationFile,
		},
		"formats": createGroupExportFormats,
	}

	// Add optional columns if provided
	if len(createGroupExportColumns) > 0 {
		attributes["columns"] = createGroupExportColumns
	}

	requestData := map[string]interface{}{
		"data": map[string]interface{}{
			"type":       "export",
			"attributes": attributes,
		},
	}

	// Convert to JSON
	jsonData, err := json.Marshal(requestData)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request body: %w", err)
	}

	return string(jsonData), nil
}
