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

// CreateExportCmd represents the create-export command
var CreateExportCmd = &cobra.Command{
	Use:   "create-export [org_id]",
	Short: "Create an export for a specific organization in Snyk",
	Long: `Create an export for a specific organization in the Snyk API.

This command creates an export for a specific organization by its ID.
The organization ID must be provided as a required argument, and the dataset,
destination, and formats must be provided as flags.

Examples:
  snyk-api-cli create-export 12345678-1234-1234-1234-123456789012 --dataset "issues" --destination-type "snyk" --destination-file-name "export.csv" --formats "csv"
  snyk-api-cli create-export 12345678-1234-1234-1234-123456789012 --dataset "issues" --destination-type "snyk" --destination-file-name "export.csv" --formats "csv" --columns "id,title,severity" --include-deleted --include-deactivated --verbose`,
	Args: cobra.ExactArgs(1),
	RunE: runCreateExport,
}

var (
	createExportDataset             string
	createExportDestinationType     string
	createExportDestinationFile     string
	createExportFormats             []string
	createExportColumns             []string
	createExportType                string
	createExportFilterEnvironment   []string
	createExportFilterLifecycle     []string
	createExportFilterIntroducedFrom string
	createExportFilterIntroducedTo   string
	createExportFilterUpdatedFrom    string
	createExportFilterUpdatedTo      string
	createExportIncludeDeleted      bool
	createExportIncludeDeactivated  bool
	createExportVerbose             bool
	createExportSilent              bool
	createExportIncludeResp         bool
	createExportUserAgent           string
)

func init() {
	// Add flags for request body attributes
	CreateExportCmd.Flags().StringVar(&createExportDataset, "dataset", "", "Dataset to export (required)")
	CreateExportCmd.Flags().StringVar(&createExportDestinationType, "destination-type", "snyk", "Destination type (default: snyk)")
	CreateExportCmd.Flags().StringVar(&createExportDestinationFile, "destination-file-name", "", "Destination file name (required)")
	CreateExportCmd.Flags().StringSliceVar(&createExportFormats, "formats", []string{}, "Export formats (required, e.g., csv)")
	CreateExportCmd.Flags().StringSliceVar(&createExportColumns, "columns", []string{}, "Columns to include in export (optional)")
	CreateExportCmd.Flags().StringVar(&createExportType, "type", "export", "Export type (default: export)")
	
	// Add filter flags
	CreateExportCmd.Flags().StringSliceVar(&createExportFilterEnvironment, "filter-environment", []string{}, "Filter by environment (optional)")
	CreateExportCmd.Flags().StringSliceVar(&createExportFilterLifecycle, "filter-lifecycle", []string{}, "Filter by lifecycle (optional)")
	CreateExportCmd.Flags().StringVar(&createExportFilterIntroducedFrom, "filter-introduced-from", "", "Filter by introduced from date (RFC3339 format)")
	CreateExportCmd.Flags().StringVar(&createExportFilterIntroducedTo, "filter-introduced-to", "", "Filter by introduced to date (RFC3339 format)")
	CreateExportCmd.Flags().StringVar(&createExportFilterUpdatedFrom, "filter-updated-from", "", "Filter by updated from date (RFC3339 format)")
	CreateExportCmd.Flags().StringVar(&createExportFilterUpdatedTo, "filter-updated-to", "", "Filter by updated to date (RFC3339 format)")
	
	// Add query parameter flags
	CreateExportCmd.Flags().BoolVar(&createExportIncludeDeleted, "include-deleted", false, "Include deleted issues")
	CreateExportCmd.Flags().BoolVar(&createExportIncludeDeactivated, "include-deactivated", false, "Include disabled issues")
	
	// Add standard flags like other commands
	CreateExportCmd.Flags().BoolVarP(&createExportVerbose, "verbose", "v", false, "Make the operation more talkative")
	CreateExportCmd.Flags().BoolVarP(&createExportSilent, "silent", "s", false, "Silent mode")
	CreateExportCmd.Flags().BoolVarP(&createExportIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	CreateExportCmd.Flags().StringVarP(&createExportUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")

	// Mark required flags
	CreateExportCmd.MarkFlagRequired("dataset")
	CreateExportCmd.MarkFlagRequired("destination-file-name")
	CreateExportCmd.MarkFlagRequired("formats")
}

func runCreateExport(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL
	fullURL, err := buildCreateExportURL(endpoint, version, orgID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if createExportVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting POST %s\n", fullURL)
	}

	// Build request body
	requestBody, err := buildCreateExportRequestBody()
	if err != nil {
		return fmt.Errorf("failed to build request body: %w", err)
	}

	if createExportVerbose {
		fmt.Fprintf(os.Stderr, "* Request body: %s\n", requestBody)
	}

	// Create the HTTP request
	req, err := http.NewRequest("POST", fullURL, strings.NewReader(requestBody))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set content type for JSON
	req.Header.Set("Content-Type", "application/json")

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if createExportVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if createExportVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if createExportVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if createExportVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", createExportUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if createExportVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as other commands
	return handleCreateExportResponse(resp, createExportIncludeResp, createExportVerbose, createExportSilent)
}

func buildCreateExportURL(endpoint, version, orgID string) (string, error) {
	// Build base URL with organization ID path parameter
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/export", endpoint, orgID)

	// Parse URL to handle query parameters properly
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}

	// Add version parameter
	q := u.Query()
	q.Set("version", version)
	
	// Add optional query parameters
	if createExportIncludeDeleted {
		q.Set("include_deleted", "true")
	}
	if createExportIncludeDeactivated {
		q.Set("include_deactivated", "true")
	}
	
	u.RawQuery = q.Encode()

	return u.String(), nil
}

func buildCreateExportRequestBody() (string, error) {
	// Build request body according to the API specification
	attributes := map[string]interface{}{
		"dataset": createExportDataset,
		"destination": map[string]interface{}{
			"type":      createExportDestinationType,
			"file_name": createExportDestinationFile,
		},
		"formats": createExportFormats,
	}

	// Add optional columns if provided
	if len(createExportColumns) > 0 {
		attributes["columns"] = createExportColumns
	}

	// Add optional filters if provided
	filters := make(map[string]interface{})
	
	if len(createExportFilterEnvironment) > 0 {
		filters["environment"] = createExportFilterEnvironment
	}
	
	if len(createExportFilterLifecycle) > 0 {
		filters["lifecycle"] = createExportFilterLifecycle
	}
	
	// Add introduced date filter if provided
	if createExportFilterIntroducedFrom != "" || createExportFilterIntroducedTo != "" {
		introduced := make(map[string]interface{})
		if createExportFilterIntroducedFrom != "" {
			introduced["from"] = createExportFilterIntroducedFrom
		}
		if createExportFilterIntroducedTo != "" {
			introduced["to"] = createExportFilterIntroducedTo
		}
		filters["introduced"] = introduced
	}
	
	// Add updated date filter if provided
	if createExportFilterUpdatedFrom != "" || createExportFilterUpdatedTo != "" {
		updated := make(map[string]interface{})
		if createExportFilterUpdatedFrom != "" {
			updated["from"] = createExportFilterUpdatedFrom
		}
		if createExportFilterUpdatedTo != "" {
			updated["to"] = createExportFilterUpdatedTo
		}
		filters["updated"] = updated
	}
	
	// Add filters to attributes if any filters were specified
	if len(filters) > 0 {
		attributes["filters"] = filters
	}

	requestData := map[string]interface{}{
		"data": map[string]interface{}{
			"type":       createExportType,
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

func handleCreateExportResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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