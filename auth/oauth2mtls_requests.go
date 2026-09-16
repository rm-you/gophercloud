package auth

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/gophercloud/gophercloud/v2"
	"github.com/gophercloud/gophercloud/v2/openstack/identity/v3/tokens"
)

// V3OAuth2MTLSOpts contains OAuth2 mTLS client-credentials options.
type V3OAuth2MTLSOpts struct {
	// AuthURL is the Keystone identity endpoint.
	AuthURL string
	// OAuth2Endpoint specifies Keystone's OS-OAUTH2 token endpoint. When empty,
	// it is derived from the identity ServiceClient endpoint.
	OAuth2Endpoint string

	// ClientID is the Keystone user ID associated with the client certificate.
	ClientID string `required:"true"`

	// AllowReauth enables automatic reauthentication.
	AllowReauth bool
}

type oauth2TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
}

// Create authenticates with OAuth2 mTLS client credentials.
func authenticateOAuth2MTLS(ctx context.Context, c *gophercloud.ServiceClient, mtlsOpts *V3OAuth2MTLSOpts) (r tokens.CreateResult) {
	if mtlsOpts == nil {
		r.Err = fmt.Errorf("oauth2mtls: expected non-nil options")
		return
	}

	if _, err := gophercloud.BuildRequestBody(mtlsOpts, ""); err != nil {
		r.Err = err
		return
	}

	if c == nil || c.ProviderClient == nil {
		r.Err = fmt.Errorf("oauth2mtls: ServiceClient or ProviderClient is nil")
		return
	}

	oauth2Endpoint := mtlsOpts.OAuth2Endpoint
	if oauth2Endpoint == "" {
		oauth2Endpoint = tokenURL(c)
	}

	formData := url.Values{
		"grant_type": {"client_credentials"},
		"client_id":  {mtlsOpts.ClientID},
	}

	var tokenResp oauth2TokenResponse
	authClient := unauthenticatedClient(c)
	resp, err := authClient.Post(ctx, oauth2Endpoint, strings.NewReader(formData.Encode()), &tokenResp, &gophercloud.RequestOpts{
		MoreHeaders: map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
		OkCodes:     []int{http.StatusOK},
	})
	_, _, r.Err = gophercloud.ParseResponse(resp, err)
	if r.Err != nil {
		return
	}

	if tokenResp.AccessToken == "" {
		r.Err = fmt.Errorf("oauth2mtls: token response missing access_token field")
		return
	}
	if !strings.EqualFold(tokenResp.TokenType, "Bearer") {
		r.Err = fmt.Errorf("oauth2mtls: token response has unsupported token_type %q", tokenResp.TokenType)
		return
	}

	// The OS-OAUTH2 response has no catalog, so retrieve the full token.
	resp, err = authClient.Get(ctx, validateURL(authClient), &r.Body, &gophercloud.RequestOpts{
		MoreHeaders: map[string]string{
			"X-Auth-Token":    tokenResp.AccessToken,
			"X-Subject-Token": tokenResp.AccessToken,
		},
	})
	_, r.Header, r.Err = gophercloud.ParseResponse(resp, err)
	if r.Err != nil {
		return
	}
	r.Header.Set("X-Subject-Token", tokenResp.AccessToken)

	return
}

func unauthenticatedClient(c *gophercloud.ServiceClient) *gophercloud.ServiceClient {
	client := *c
	provider := *c.ProviderClient
	provider.Throwaway = true
	provider.ReauthFunc = nil
	client.ProviderClient = &provider
	return &client
}

// GetAuthURL returns the versioned Keystone endpoint.
func (opts *V3OAuth2MTLSOpts) GetAuthURL() string {
	return (AuthOptionsV3{AuthURL: opts.AuthURL}).GetAuthURL()
}

// Authenticate uses the HTTP client's certificate to obtain a bearer token.
func (opts *V3OAuth2MTLSOpts) Authenticate(ctx context.Context, httpClient *http.Client) (*AuthResult, error) {
	if opts == nil {
		return nil, fmt.Errorf("oauth2mtls: expected non-nil options")
	}
	if opts.AuthURL == "" {
		return nil, gophercloud.ErrMissingInput{Argument: "AuthURL"}
	}
	client := &gophercloud.ServiceClient{ProviderClient: &gophercloud.ProviderClient{}, Endpoint: opts.GetAuthURL()}
	if httpClient != nil {
		client.HTTPClient = *httpClient
	}
	raw := authenticateOAuth2MTLS(ctx, client, opts)
	result, err := v3AuthResult(raw.Result, opts.AllowReauth)
	if err != nil {
		return nil, err
	}
	result.TokenType = "Bearer"
	return result, nil
}
