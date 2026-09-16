package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/gophercloud/gophercloud/v2"
	"github.com/gophercloud/gophercloud/v2/openstack/identity/v3/tokens"
)

type discoveryDocument struct {
	TokenEndpoint       string   `json:"token_endpoint"`
	GrantTypesSupported []string `json:"grant_types_supported"`
}

// V3OIDCClientCredentialsOpts contains OIDC client-credentials authentication options.
type V3OIDCClientCredentialsOpts struct {
	// AuthURL is the Keystone identity endpoint.
	AuthURL string
	// IdentityProviderName is the Keystone federation identity provider.
	IdentityProviderName string `required:"true"`

	// Protocol is the Keystone federation protocol.
	Protocol string `required:"true"`

	// ClientID is the OAuth 2.0 client identifier.
	ClientID string `required:"true"`

	// ClientSecret is the OAuth 2.0 client secret.
	ClientSecret string

	// AccessTokenEndpoint is the identity provider's token endpoint.
	AccessTokenEndpoint string `or:"DiscoveryEndpoint"`

	// AccessTokenType selects the token response field. It defaults to "access_token".
	AccessTokenType string

	// DiscoveryEndpoint is used when AccessTokenEndpoint is empty.
	DiscoveryEndpoint string

	// OIDCScope is the OAuth 2.0 scope. It defaults to "openid".
	OIDCScope string

	// AllowReauth enables automatic reauthentication.
	AllowReauth bool

	// Scope controls the resulting Keystone token scope.
	Scope *Scope
}

// Create authenticates with OIDC client credentials.
func authenticateOIDC(ctx context.Context, c *gophercloud.ServiceClient, oidcOpts *V3OIDCClientCredentialsOpts) (r tokens.CreateResult) {
	if oidcOpts == nil {
		r.Err = fmt.Errorf("oidc: expected non-nil options")
		return
	}

	if _, err := gophercloud.BuildRequestBody(oidcOpts, ""); err != nil {
		r.Err = err
		return
	}
	if c == nil || c.ProviderClient == nil {
		r.Err = fmt.Errorf("oidc: ServiceClient or ProviderClient is nil")
		return
	}

	accessTokenEndpoint, err := resolveAccessTokenEndpoint(ctx, c, oidcOpts)
	if err != nil {
		r.Err = fmt.Errorf("OIDC access token endpoint resolution failed: %w", err)
		return
	}

	accessToken, err := fetchAccessToken(ctx, c, oidcOpts, accessTokenEndpoint)
	if err != nil {
		r.Err = fmt.Errorf("OIDC IdP token request failed: %w", err)
		return
	}

	unscopedToken, unscopedBody, unscopedHeader, err := exchangeForKeystoneToken(ctx, c, oidcOpts, accessToken)
	if err != nil {
		r.Err = fmt.Errorf("OIDC federation auth failed: %w", err)
		return
	}

	scope, err := oidcOpts.Scope.ToScopeMap()
	if err != nil {
		r.Err = err
		return
	}

	if scope != nil {
		rescope := AuthOptionsV3{AuthURL: c.Endpoint, Auth: V3RescopeTokenOpts{Token: unscopedToken, Scope: oidcOpts.Scope}}
		r.Result, r.Err = rescope.create(ctx, &c.HTTPClient)
	} else {
		r.Body = unscopedBody
		r.Header = unscopedHeader
	}

	return
}

func resolveAccessTokenEndpoint(ctx context.Context, c *gophercloud.ServiceClient, opts *V3OIDCClientCredentialsOpts) (string, error) {
	if opts.AccessTokenEndpoint != "" {
		return opts.AccessTokenEndpoint, nil
	}

	discovery, err := fetchDiscoveryDocument(ctx, c, opts.DiscoveryEndpoint)
	if err != nil {
		return "", err
	}

	if len(discovery.GrantTypesSupported) > 0 && !slices.Contains(discovery.GrantTypesSupported, "client_credentials") {
		return "", fmt.Errorf("IdP does not support client_credentials grant type (supported: %v)", discovery.GrantTypesSupported)
	}

	if discovery.TokenEndpoint == "" {
		return "", fmt.Errorf("discovery document does not contain a valid token_endpoint")
	}

	return discovery.TokenEndpoint, nil
}

func fetchDiscoveryDocument(ctx context.Context, c *gophercloud.ServiceClient, discoveryURL string) (discoveryDocument, error) {
	var doc discoveryDocument
	if c == nil || c.ProviderClient == nil {
		return doc, fmt.Errorf("service client or provider client is nil")
	}

	req, err := http.NewRequestWithContext(ctx, "GET", discoveryURL, nil)
	if err != nil {
		return doc, fmt.Errorf("failed to create discovery request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	httpClient := c.HTTPClient
	resp, err := httpClient.Do(req)
	if err != nil {
		return doc, fmt.Errorf("failed to fetch discovery document from %s: %w", discoveryURL, err)
	}
	defer resp.Body.Close()

	const maxDiscoverySize = 1 << 20 // 1 MiB
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDiscoverySize+1))
	if err != nil {
		return doc, fmt.Errorf("failed to read discovery document response: %w", err)
	}
	if int64(len(body)) > maxDiscoverySize {
		return doc, fmt.Errorf("discovery document exceeds maximum allowed size of %d bytes", maxDiscoverySize)
	}

	if resp.StatusCode != http.StatusOK {
		return doc, fmt.Errorf("discovery endpoint returned HTTP %d", resp.StatusCode)
	}

	if err := json.Unmarshal(body, &doc); err != nil {
		return doc, fmt.Errorf("discovery document is not valid JSON: %w", err)
	}
	return doc, nil
}

func fetchAccessToken(ctx context.Context, c *gophercloud.ServiceClient, opts *V3OIDCClientCredentialsOpts, accessTokenEndpoint string) (string, error) {
	if c == nil || c.ProviderClient == nil {
		return "", fmt.Errorf("service client or provider client is nil")
	}

	scope := opts.OIDCScope
	if scope == "" {
		scope = "openid"
	}

	formData := url.Values{
		"grant_type": {"client_credentials"},
		"scope":      {scope},
	}
	if opts.ClientSecret == "" {
		formData.Set("client_id", opts.ClientID)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", accessTokenEndpoint, strings.NewReader(formData.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	if opts.ClientSecret != "" {
		req.SetBasicAuth(url.QueryEscape(opts.ClientID), url.QueryEscape(opts.ClientSecret))
	}

	httpClient := c.HTTPClient
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	const maxIDPResponseSize = 1 << 20 // 1 MiB
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxIDPResponseSize+1))
	if err != nil {
		return "", fmt.Errorf("failed to read IdP response: %w", err)
	}
	if int64(len(body)) > maxIDPResponseSize {
		return "", fmt.Errorf("IdP response body exceeded %d bytes", maxIDPResponseSize)
	}

	if resp.StatusCode != http.StatusOK {
		snippet := string(body)
		if len(snippet) > 512 {
			snippet = snippet[:512] + "..."
		}
		return "", fmt.Errorf("IdP returned HTTP %d: %s", resp.StatusCode, snippet)
	}

	var tokenResponse map[string]any
	if err := json.Unmarshal(body, &tokenResponse); err != nil {
		return "", fmt.Errorf("failed to parse IdP token response: %w", err)
	}

	tokenField := opts.AccessTokenType
	if tokenField == "" {
		tokenField = "access_token"
	}

	accessToken, ok := tokenResponse[tokenField].(string)
	if !ok || accessToken == "" {
		return "", fmt.Errorf("IdP response missing %q field", tokenField)
	}
	if tokenField == "access_token" {
		tokenType, ok := tokenResponse["token_type"].(string)
		if !ok || !strings.EqualFold(tokenType, "Bearer") {
			return "", fmt.Errorf("IdP response has unsupported token_type %q", tokenType)
		}
	}

	return accessToken, nil
}

func exchangeForKeystoneToken(ctx context.Context, c *gophercloud.ServiceClient, opts *V3OIDCClientCredentialsOpts, accessToken string) (string, any, http.Header, error) {
	federationURL := oidcAuthURL(c, opts.IdentityProviderName, opts.Protocol)

	var body any
	resp, err := c.Post(ctx, federationURL, nil, &body, &gophercloud.RequestOpts{
		MoreHeaders: map[string]string{
			"Authorization": "Bearer " + accessToken,
		},
		OkCodes:     []int{201},
		OmitHeaders: []string{"X-Auth-Token"},
	})
	if err != nil {
		return "", nil, nil, err
	}

	unscopedToken := resp.Header.Get("X-Subject-Token")
	if unscopedToken == "" {
		return "", nil, nil, fmt.Errorf("federation auth response missing X-Subject-Token header")
	}

	return unscopedToken, body, resp.Header, nil
}

// GetAuthURL returns the versioned Keystone endpoint.
func (opts *V3OIDCClientCredentialsOpts) GetAuthURL() string {
	return (AuthOptionsV3{AuthURL: opts.AuthURL}).GetAuthURL()
}

// Authenticate exchanges OIDC client credentials for a Keystone token.
func (opts *V3OIDCClientCredentialsOpts) Authenticate(ctx context.Context, httpClient *http.Client) (*AuthResult, error) {
	if opts == nil {
		return nil, fmt.Errorf("oidc: expected non-nil options")
	}
	if opts.AuthURL == "" {
		return nil, gophercloud.ErrMissingInput{Argument: "AuthURL"}
	}
	client := &gophercloud.ServiceClient{ProviderClient: &gophercloud.ProviderClient{}, Endpoint: opts.GetAuthURL()}
	if httpClient != nil {
		client.HTTPClient = *httpClient
	}
	result := authenticateOIDC(ctx, client, opts)
	return v3AuthResult(result.Result, opts.AllowReauth)
}
