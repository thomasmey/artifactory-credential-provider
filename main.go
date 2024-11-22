package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"

	"net/http"
	"net/url"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	cp "k8s.io/kubelet/pkg/apis/credentialprovider/v1"
)

// Define an interface for ID token providers
type IDTokenProvider interface {
	// Fetches an ID token from the Google Cloud Metadata Server.
	// Parameters:
	// - audience: The intended recipient of the token.
	// - format: Token format ("full" for a standard JWT).
	// Returns the ID token or an error.
	GetIDToken(audience, format string) (string, error)
}

type GoogleMetadataProvider struct{}

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

// JfrogCredentials holds JFrog connection details and the access token
type JfrogCredentials struct {
	JfrogURL    string
	AccessToken string
	Username    string
	Password    string
}

// TokenExchangeRequest represents the JSON payload for the JFrog token exchange request
type TokenExchangeRequest struct {
	GrantType        string `json:"grant_type"`
	SubjectTokenType string `json:"subject_token_type"`
	SubjectToken     string `json:"subject_token"`
	ProviderName     string `json:"provider_name"`
	ProjectKey       string `json:"project_key,omitempty"`
}

// TokenExchangeResponse represents the JSON response from JFrog's token exchange API
type TokenExchangeResponse struct {
	AccessToken string `json:"access_token"`
	Errors      []struct {
		Message string `json:"message"`
	} `json:"errors,omitempty"`
}

// Exchanges an idToken for a JFrog access token
// see https://jfrog.com/help/r/jfrog-rest-apis/oidc-token-exchange
func getJfrogAccessToken(jfrogCredentials JfrogCredentials, jsonWebToken, oidcProviderName, projectKey string) (string, error) {
	// Construct the exchange URL
	exchangeURL := strings.TrimRight(jfrogCredentials.JfrogURL, "/") + "/access/api/v1/oidc/token"

	// Prepare the request payload
	payload := TokenExchangeRequest{
		GrantType:        "urn:ietf:params:oauth:grant-type:token-exchange",
		SubjectTokenType: "urn:ietf:params:oauth:token-type:id_token",
		SubjectToken:     jsonWebToken,
		ProviderName:     oidcProviderName,
		ProjectKey:       projectKey,
	}

	// Encode payload to JSON
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to encode payload: %v", err)
	}

	// Create the HTTP POST request
	req, err := http.NewRequest("POST", exchangeURL, bytes.NewBuffer(payloadBytes))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// Send the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %v", err)
	}

	// Handle non-200 status codes
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Parse the response JSON
	var response TokenExchangeResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return "", fmt.Errorf("failed to parse response: %v", err)
	}

	// Check for errors in the response
	if len(response.Errors) > 0 {
		return "", fmt.Errorf("error from JFrog: %v", response.Errors[0].Message)
	}

	return response.AccessToken, nil
}

func main() {
	// Create a new CredentialProviderRequest instance
	var request cp.CredentialProviderRequest

	// Read input from stdin
	decoder := json.NewDecoder(os.Stdin)
	err := decoder.Decode(&request)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error decoding JSON: %v\n", err)
		os.Exit(1)
	}

	targetAudience := os.Getenv("TARGET_AUDIENCE") // ID token audience/target
	artifactoryUrl := os.Getenv("ARTIFACTORY_URL")
	artifactoryProviderName := os.Getenv("ARTIFACTORY_OIDC_PROVIDER")
	artifactoryProjectKey := os.Getenv("ARTIFACTORY_PROJECT_KEY")

	var idTokenProvider IDTokenProvider = GoogleMetadataProvider{}
	idToken, err := idTokenProvider.GetIDToken(targetAudience, "full")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting id token: %v\n", err)
		os.Exit(1)
	}

	jfrogCreds := JfrogCredentials{
		JfrogURL: artifactoryUrl,
	}

	// Call the function to exchange the token
	accessToken, err := getJfrogAccessToken(jfrogCreds, idToken, artifactoryProviderName, artifactoryProjectKey)
	if err != nil {
		log.Fatalf("Failed to get JFrog access token: %v", err)
	}

	response := cp.CredentialProviderResponse{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "credentialprovider.k8s.io/v1",
			Kind:       "CredentialProviderResponse",
		},
		CacheKeyType: cp.ImagePluginCacheKeyType,
		CacheDuration: &metav1.Duration{
			Duration: 10 * time.Minute, // TODO: deduce from access token
		},
		Auth: map[string]cp.AuthConfig{
			request.Image: {
				Username: "example-user", // TODO: set to what?
				Password: accessToken,
			},
		},
	}

	// Convert the response object to JSON
	jsonData, err := json.Marshal(response)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling JSON: %v\n", err)
		os.Exit(1)
	}

	// Write the JSON to stdout
	fmt.Println(string(jsonData))
}
