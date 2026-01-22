package cmd

import (
	"fmt"
	"io"
	"net/http"
	"os"
)

// SnykRequestIDHeader is the header name for Snyk's request tracking ID
const SnykRequestIDHeader = "Snyk-Request-Id"

// isErrorStatusCode returns true if the HTTP status code indicates an error (non-2xx)
func isErrorStatusCode(statusCode int) bool {
	return statusCode < 200 || statusCode >= 300
}

// printSnykRequestID prints the Snyk-Request-Id header value to stderr if present
// This is useful for debugging API errors with Snyk support
func printSnykRequestID(resp *http.Response) {
	requestID := resp.Header.Get(SnykRequestIDHeader)
	if requestID != "" {
		fmt.Fprintf(os.Stderr, "Snyk-Request-Id: %s\n", requestID)
	}
}

// HandleHTTPResponse is a shared response handler that prints the snyk-request-id
// header when an error status code is returned. This helps with debugging API issues.
func HandleHTTPResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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

	// Print snyk-request-id on error responses (always, not just in verbose mode)
	// This helps users report issues to Snyk support
	if isErrorStatusCode(resp.StatusCode) {
		printSnykRequestID(resp)
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
	if verbose && isErrorStatusCode(resp.StatusCode) {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
	}

	return nil
}
