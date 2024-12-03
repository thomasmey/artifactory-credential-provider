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
func (g GoogleMetadataProvider) GetIDToken(audience string) (string, error) {
	// Base URL for the Metadata Server
	baseURL := "http://metadata/computeMetadata/v1/instance/service-accounts/default/identity"

	// Add query parameters
	params := url.Values{}
	params.Add("audience", audience)
	// gives more claims, e.g.:
	//   {"aud":"artifactory-gcp","azp":"104479897743394244856","email":"405721773632-compute@developer.gserviceaccount.com","email_verified":true,"exp":1733256730,"google":{"compute_engine":{"instance_creation_timestamp":1733252450,"instance_id":"6140691338085198734","instance_name":"gke-cluster-1-default-pool-17bba0ee-w929","project_id":"gcp-tests-306319","project_number":405721773632,"zone":"europe-west10-a"}},"iat":1733253130,"iss":"https://accounts.google.com","sub":"104479897743394244856"}
	params.Add("format", "full")

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

	// Read and return the response body (ID token)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("error reading response: %w", err)
	}

	// Check for non-200 status codes
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status code: %d and body %s", resp.StatusCode, body)
	}

	return string(body), nil
}
