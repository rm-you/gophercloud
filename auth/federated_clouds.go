package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gophercloud/gophercloud/v2"
	"github.com/gophercloud/gophercloud/v2/auth/tokencache"
)

const (
	// AuthV3WebSSO selects browser-based Keystone federation.
	AuthV3WebSSO AuthType = "v3websso"
	// AuthV3OIDCClientCredentials selects OIDC client credentials.
	AuthV3OIDCClientCredentials AuthType = "v3oidcclientcredentials"
	// AuthV3OAuth2MTLSClientCredential selects Keystone OS-OAUTH2 mTLS.
	AuthV3OAuth2MTLSClientCredential AuthType = "v3oauth2mtlsclientcredential"
)

// WithTokenCache supplies shared token storage without choosing a backend.
func WithTokenCache(cache tokencache.Cache) CloudOption {
	return func(co *CloudOptions) { co.TokenCache = cache }
}

// WithTokenCacheNamespace identifies the expected browser login profile.
// Reusing a namespace explicitly shares unscoped tokens across cloud entries.
func WithTokenCacheNamespace(namespace string) CloudOption {
	return func(co *CloudOptions) { co.TokenCacheNamespace = namespace }
}

// WithWebSSOBrowserOpener overrides the system browser launcher.
func WithWebSSOBrowserOpener(open func(string) error) CloudOption {
	return func(co *CloudOptions) { co.WebSSOBrowserOpener = open }
}

// WithWebSSOTimeout limits the browser callback wait.
func WithWebSSOTimeout(timeout time.Duration) CloudOption {
	return func(co *CloudOptions) { co.WebSSOTimeout = timeout }
}

func federatedAuthOptions(c CloudSource, options ...CloudOption) (Authenticator, error) {
	m, endpoint := mergedAuth(c, options)
	if endpoint == "" {
		return nil, gophercloud.ErrMissingInput{Argument: "AuthURL"}
	}
	co := ResolveCloudOptions(options...)
	var settings struct {
		AllowReauth bool `json:"allow_reauth"`
	}
	raw, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, &settings); err != nil {
		return nil, err
	}
	if c.GetAuthType() == AuthV3OAuth2MTLSClientCredential {
		return &V3OAuth2MTLSOpts{
			AuthURL: endpoint, OAuth2Endpoint: str(m, "oauth2_endpoint"),
			ClientID:    coalesce(str(m, "oauth2_client_id"), str(m, "client_id")),
			AllowReauth: settings.AllowReauth,
		}, nil
	}
	scope, err := cloudScope(m, co)
	if err != nil {
		return nil, err
	}
	if c.GetAuthType() == AuthV3OIDCClientCredentials {
		return &V3OIDCClientCredentialsOpts{
			AuthURL: endpoint, ClientID: str(m, "client_id"), ClientSecret: str(m, "client_secret"),
			AccessTokenEndpoint: str(m, "access_token_endpoint"), DiscoveryEndpoint: str(m, "discovery_endpoint"),
			AccessTokenType: str(m, "access_token_type"), OIDCScope: str(m, "openid_scope"),
			IdentityProviderName: str(m, "identity_provider"), Protocol: str(m, "protocol"),
			AllowReauth: settings.AllowReauth, Scope: scope,
		}, nil
	}
	var redirectPort int
	if value, ok := m["redirect_port"]; ok && value != "" {
		redirectPort, err = strconv.Atoi(fmt.Sprint(value))
		if err != nil || redirectPort < 0 || redirectPort > 65535 {
			return nil, errors.New("redirect_port must be 0 or between 1 and 65535")
		}
	}
	return &V3WebSSOOpts{
		AuthURL: endpoint, IdentityProviderName: str(m, "identity_provider"), Protocol: str(m, "protocol"),
		RedirectHost: str(m, "redirect_host"), RedirectPort: redirectPort,
		AllowReauth: settings.AllowReauth, Scope: scope, Timeout: co.WebSSOTimeout,
		BrowserOpener: co.WebSSOBrowserOpener, TokenCache: co.TokenCache,
		CacheNamespace: coalesce(co.TokenCacheNamespace, str(m, "cache_namespace")),
	}, nil
}

func cloudScope(m map[string]any, co CloudOptions) (*Scope, error) {
	if co.Scope != nil {
		return co.Scope, nil
	}
	system := str(m, "system_scope")
	if system != "" && system != "all" {
		return nil, errors.New("only system scope of all is supported")
	}
	_, _, domainID, domainName := resolveDomains(m)
	scope := &Scope{
		DomainID: str(m, "domain_id"), DomainName: str(m, "domain_name"),
		ProjectID: str(m, "project_id"), ProjectName: str(m, "project_name"),
		ProjectDomainID: domainID, ProjectDomainName: domainName,
		System: system == "all", TrustID: str(m, "trust_id"),
	}
	return scope, nil
}

// environmentAuth supplies fallback credentials; cloud entries and options win.
func environmentAuth() map[string]any {
	m := make(map[string]any)
	for _, key := range []string{
		"auth_url", "username", "password", "passcode", "user_domain_id", "user_domain_name",
		"domain_id", "domain_name", "default_domain", "project_domain_id", "project_domain_name",
		"application_credential_id", "application_credential_name", "application_credential_secret",
		"system_scope", "trust_id", "identity_provider", "protocol", "client_id", "client_secret",
		"access_token_endpoint", "access_token_type", "discovery_endpoint", "openid_scope",
		"oauth2_endpoint", "oauth2_client_id", "redirect_host", "redirect_port",
	} {
		if value := os.Getenv("OS_" + strings.ToUpper(key)); value != "" {
			m[key] = value
		}
	}
	setIfNotEmpty(m, "user_id", coalesce(os.Getenv("OS_USER_ID"), os.Getenv("OS_USERID")))
	setIfNotEmpty(m, "project_id", coalesce(os.Getenv("OS_PROJECT_ID"), os.Getenv("OS_TENANT_ID")))
	setIfNotEmpty(m, "project_name", coalesce(os.Getenv("OS_PROJECT_NAME"), os.Getenv("OS_TENANT_NAME")))
	setIfNotEmpty(m, "token", coalesce(os.Getenv("OS_AUTH_TOKEN"), os.Getenv("OS_TOKEN")))
	if value := os.Getenv("OS_AUTH_METHODS"); value != "" {
		m["auth_methods"] = strings.Split(value, ",")
	}
	return m
}

type environmentCloud struct{ data map[string]any }

func (c environmentCloud) GetAuthType() AuthType         { return AuthType(os.Getenv("OS_AUTH_TYPE")) }
func (c environmentCloud) GetIdentityAPIVersion() string { return os.Getenv("OS_IDENTITY_API_VERSION") }
func (c environmentCloud) GetAuthData() map[string]any   { return c.data }
