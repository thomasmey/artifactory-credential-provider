package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"

	"net/http"
	"net/url"
)

type GithubIdTokenResponse struct {
	Value string `json:"value"`
}

type GithubActionsProvider struct{}

// https://docs.github.com/en/actions/security-for-github-actions/security-hardening-your-deployments/about-security-hardening-with-openid-connect
// https://token.actions.githubusercontent.com/.well-known/openid-configuration
func (provider GithubActionsProvider) GetIDToken(audience string) (string, error) {
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
	req.Header.Set("Authorization", "Bearer "+idpAccessToken)

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
