package cmd

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// DefaultTimeout is the default HTTP client timeout
const DefaultTimeout = 30 * time.Second

// DefaultUserAgent is the default user agent string
const DefaultUserAgent = "snyk-api-cli/1.0"

// DefaultContentType is the default content type for JSON:API requests
const DefaultContentType = "application/vnd.api+json"

// RequestOptions contains all options for executing an API request
type RequestOptions struct {
	Method      string        // HTTP method (GET, POST, PUT, PATCH, DELETE)
	URL         string        // Full URL to request
	Body        string        // Optional request body
	ContentType string        // Content type header (defaults to application/vnd.api+json for POST/PUT/PATCH)
	UserAgent   string        // User agent string (defaults to snyk-api-cli/1.0)
	Verbose     bool          // Enable verbose output
	Silent      bool          // Suppress response body output
	IncludeResp bool          // Include response headers in output
	Timeout     time.Duration // Request timeout (defaults to 30s)
}

// NewHTTPClient creates an HTTP client with the specified timeout
// If timeout is 0, DefaultTimeout is used
func NewHTTPClient(timeout time.Duration) *http.Client {
	if timeout == 0 {
		timeout = DefaultTimeout
	}
	return &http.Client{
		Timeout: timeout,
	}
}

// ExecuteAPIRequest executes an HTTP request to the Snyk API with standard
// authentication, logging, and response handling
func ExecuteAPIRequest(opts RequestOptions) error {
	// Apply defaults
	if opts.UserAgent == "" {
		opts.UserAgent = DefaultUserAgent
	}
	if opts.Timeout == 0 {
		opts.Timeout = DefaultTimeout
	}

	// Verbose: log request
	if opts.Verbose {
		fmt.Fprintf(os.Stderr, "* Requesting %s %s\n", opts.Method, opts.URL)
	}

	// Create the HTTP request
	var bodyReader io.Reader
	if opts.Body != "" {
		bodyReader = strings.NewReader(opts.Body)
		if opts.Verbose {
			fmt.Fprintf(os.Stderr, "* Request body: %s\n", opts.Body)
		}
	}

	req, err := http.NewRequest(opts.Method, opts.URL, bodyReader)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set content type for requests with body
	if opts.Body != "" {
		contentType := opts.ContentType
		if contentType == "" {
			contentType = DefaultContentType
		}
		req.Header.Set("Content-Type", contentType)
	}

	// Handle authentication
	if opts.Verbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{})
	if err != nil {
		if opts.Verbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if opts.Verbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if opts.Verbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", opts.UserAgent)

	// Create client and execute request
	client := NewHTTPClient(opts.Timeout)

	if opts.Verbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the shared response handler
	return HandleHTTPResponse(resp, opts.IncludeResp, opts.Verbose, opts.Silent)
}
