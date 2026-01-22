package cmd

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// CreateSbomTestRunCmd represents the create-sbom-test-run command
var CreateSbomTestRunCmd = &cobra.Command{
	Use:   "create-sbom-test-run [org_id]",
	Short: "Create an SBOM test run for a specific organization in Snyk",
	Long: `Create an SBOM test run for a specific organization in the Snyk API.

This command creates an SBOM test run for a specific organization by its ID.
The organization ID must be provided as a required argument, and the SBOM format
and data must be provided as flags or files.

Required permissions: Test Projects (org.project.test)

Supported SBOM formats:
- CycloneDX 1.4, 1.5, 1.6 JSON
- SPDX 2.3 JSON

Supported purl types:
apk, cargo, cocoapods, composer, conan, deb, gem, generic, golang, hex, maven, npm, nuget, pub, pypi, rpm, swift

Examples:
  snyk-api-cli create-sbom-test-run 12345678-1234-1234-1234-123456789012 --format "cyclonedx1.6+json" --sbom-file "/path/to/sbom.json"
  snyk-api-cli create-sbom-test-run 12345678-1234-1234-1234-123456789012 --format "spdx2.3+json" --sbom-data '{"spdxVersion":"SPDX-2.3",...}'
  snyk-api-cli create-sbom-test-run 12345678-1234-1234-1234-123456789012 --format "cyclonedx1.5+json" --sbom-file "sbom.json" --type "sbom_test" --verbose`,
	Args: cobra.ExactArgs(1),
	RunE: runCreateSbomTestRun,
}

var (
	createSbomTestRunFormat      string
	createSbomTestRunSbomFile    string
	createSbomTestRunSbomData    string
	createSbomTestRunType        string
	createSbomTestRunVerbose     bool
	createSbomTestRunSilent      bool
	createSbomTestRunIncludeResp bool
	createSbomTestRunUserAgent   string
)

func init() {
	// Add flags for request body attributes
	CreateSbomTestRunCmd.Flags().StringVar(&createSbomTestRunFormat, "format", "", "SBOM format (required)")
	CreateSbomTestRunCmd.Flags().StringVar(&createSbomTestRunSbomFile, "sbom-file", "", "Path to SBOM JSON file")
	CreateSbomTestRunCmd.Flags().StringVar(&createSbomTestRunSbomData, "sbom-data", "", "SBOM data as JSON string")
	CreateSbomTestRunCmd.Flags().StringVar(&createSbomTestRunType, "type", "sbom_test", "Test run type (default: sbom_test)")

	// Add standard flags like other commands
	CreateSbomTestRunCmd.Flags().BoolVarP(&createSbomTestRunVerbose, "verbose", "v", false, "Make the operation more talkative")
	CreateSbomTestRunCmd.Flags().BoolVarP(&createSbomTestRunSilent, "silent", "s", false, "Silent mode")
	CreateSbomTestRunCmd.Flags().BoolVarP(&createSbomTestRunIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	CreateSbomTestRunCmd.Flags().StringVarP(&createSbomTestRunUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")

	// Mark required flags
	CreateSbomTestRunCmd.MarkFlagRequired("format")
}

func runCreateSbomTestRun(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Validate that either sbom-file or sbom-data is provided
	if createSbomTestRunSbomFile == "" && createSbomTestRunSbomData == "" {
		return fmt.Errorf("either --sbom-file or --sbom-data must be provided")
	}
	if createSbomTestRunSbomFile != "" && createSbomTestRunSbomData != "" {
		return fmt.Errorf("only one of --sbom-file or --sbom-data can be provided")
	}

	// Build the URL
	fullURL, err := buildCreateSbomTestRunURL(endpoint, version, orgID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	// Build request body
	requestBody, err := buildCreateSbomTestRunRequestBody()
	if err != nil {
		return fmt.Errorf("failed to build request body: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "POST",
		URL:         fullURL,
		Body:        requestBody,
		ContentType: "application/vnd.api+json",
		Verbose:     createSbomTestRunVerbose,
		Silent:      createSbomTestRunSilent,
		IncludeResp: createSbomTestRunIncludeResp,
		UserAgent:   createSbomTestRunUserAgent,
	})
}

func buildCreateSbomTestRunURL(endpoint, version, orgID string) (string, error) {
	// Build base URL with organization ID path parameter
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/sbom_tests", endpoint, orgID)

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

func buildCreateSbomTestRunRequestBody() (string, error) {
	// Read SBOM data from file or use provided data
	var sbomData interface{}
	var err error

	if createSbomTestRunSbomFile != "" {
		// Read SBOM from file
		fileContent, err := os.ReadFile(createSbomTestRunSbomFile)
		if err != nil {
			return "", fmt.Errorf("failed to read SBOM file: %w", err)
		}
		err = json.Unmarshal(fileContent, &sbomData)
		if err != nil {
			return "", fmt.Errorf("failed to parse SBOM file JSON: %w", err)
		}
	} else {
		// Parse SBOM data from string
		err = json.Unmarshal([]byte(createSbomTestRunSbomData), &sbomData)
		if err != nil {
			return "", fmt.Errorf("failed to parse SBOM data JSON: %w", err)
		}
	}

	// Build request body according to the API specification
	attributes := map[string]interface{}{
		"format": createSbomTestRunFormat,
		"sbom":   sbomData,
	}

	requestData := map[string]interface{}{
		"data": map[string]interface{}{
			"type":       createSbomTestRunType,
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
