package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"net/http"
	"net/url"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	cp "k8s.io/kubelet/pkg/apis/credentialprovider/v1"

	jwt "github.com/golang-jwt/jwt/v5"
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

type GithubIdTokenResponse struct {
	Value string `json:"value"`
}

type GithubActionsProvider struct{}

// https://docs.github.com/en/actions/security-for-github-actions/security-hardening-your-deployments/about-security-hardening-with-openid-connect
// https://token.actions.githubusercontent.com/.well-known/openid-configuration
func (provider GithubActionsProvider) GetIDToken(audience, format string) (string, error) {
	if audience == "" {
		return "", errors.New("audience parameter is required")
	}

	idpUrl := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL")
	idpAccessToken := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")

	// Prepare URL with query parameters
	query := url.Values{}
	query.Set("audience", audience)

	// Construct the final URL
	// see https://github.com/actions/toolkit/blob/main/packages/core/src/oidc-utils.ts#L72
	fullURL := fmt.Sprintf("%s&%s", idpUrl, query.Encode())

	// Create HTTP request with appropriate headers
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create HTTP request: %v", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer " + idpAccessToken)

	// Perform the HTTP request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to fetch ID token: %v", err)
	}
	defer resp.Body.Close()

	// Handle response
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// Read the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %v", err)
	}

	var response GithubIdTokenResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return "", fmt.Errorf("failed to parse response: %v", err)
	}

	return response.Value, nil
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

	// Check if Kind and APIVersion match certain values
	if request.Kind != "CredentialProviderRequest" || request.APIVersion != cp.SchemeGroupVersion.String() {
		fmt.Println("Unsupported API version!")
		os.Exit(1)
	}

	artifactoryUrl := os.Getenv("ARTIFACTORY_URL")
	artifactoryProviderName := os.Getenv("ARTIFACTORY_OIDC_PROVIDER")
	artifactoryProjectKey := os.Getenv("ARTIFACTORY_PROJECT_KEY")

	idTokenTargetAudience := os.Getenv("ID_TOKEN_TARGET_AUDIENCE")
	idTokenProvider, ok := os.LookupEnv("ID_TOKEN_PROVIDER")
	if !ok {
		idTokenProvider = "GCP-GCE"
	}

	var idp IDTokenProvider
	switch idTokenProvider {
	case "GCP-GCE":
		idp = GoogleMetadataProvider{}
	case "GitHub":
		idp = GithubActionsProvider{}
	default:
		fmt.Fprintf(os.Stderr, "Unsupported id token provider: %s\n", idTokenProvider)
		os.Exit(1)
	}

	idToken, err := idp.GetIDToken(idTokenTargetAudience, "full")
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

	jp := jwt.NewParser()
	claims := jwt.RegisteredClaims{}
	jwt, _, err := jp.ParseUnverified(accessToken, &claims)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing access token: %v\n", err)
		os.Exit(1)
	}

	// TODO: Or use time.Now()?
	issuedAt, _ := jwt.Claims.GetIssuedAt()
	expirationTime, _ := jwt.Claims.GetExpirationTime()
	duration := expirationTime.Time.Sub(issuedAt.Time)

	// TODO: set username to what? JWT sub?
	// I need to see a real Jfrog token exchange token
	username, _ := jwt.Claims.GetSubject()

	response := cp.CredentialProviderResponse{
		TypeMeta: metav1.TypeMeta{
			APIVersion: cp.SchemeGroupVersion.String(),
			Kind:       "CredentialProviderResponse",
		},
		CacheKeyType: cp.ImagePluginCacheKeyType,
		CacheDuration: &metav1.Duration{
			Duration: duration,
		},
		Auth: map[string]cp.AuthConfig{
			request.Image: {
				Username: username,
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
