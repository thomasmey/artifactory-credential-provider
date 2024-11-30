package main

import (
	"fmt"
	"io"

	"net/http"
	"net/url"
)

type GoogleMetadataProvider struct{}

// https://cloud.google.com/docs/authentication/get-id-token
// https://cloud.google.com/compute/docs/instances/verifying-instance-identity#request_signature
func (g GoogleMetadataProvider) GetIDToken(audience, format string) (string, error) {
	// Base URL for the Metadata Server
	baseURL := "http://metadata/computeMetadata/v1/instance/service-accounts/default/identity"

	// Add query parameters
	params := url.Values{}
	params.Add("audience", audience)
	params.Add("format", format)

	// Construct the full URL
	fullURL := fmt.Sprintf("%s?%s", baseURL, params.Encode())

	// Create a new HTTP request
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return "", fmt.Errorf("error creating request: %w", err)
	}

	// Add the required header
	req.Header.Add("Metadata-Flavor", "Google")

	// Send the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("error making request: %w", err)
	}
	defer resp.Body.Close()

	// Check for non-200 status codes
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// Read and return the response body (ID token)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("error reading response: %w", err)
	}

	return string(body), nil
}
