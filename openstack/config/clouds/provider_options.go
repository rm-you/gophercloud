package clouds

import (
	"fmt"
	"os"
	"strconv"

	"github.com/gophercloud/gophercloud/v2/openstack/identity/v3/oauth2mtls"
	"github.com/gophercloud/gophercloud/v2/openstack/identity/v3/oidc"
	tokens3 "github.com/gophercloud/gophercloud/v2/openstack/identity/v3/tokens"
	"github.com/gophercloud/gophercloud/v2/openstack/identity/v3/websso"
)

// ParseV3 fetches a clouds.yaml file and returns Identity v3 authentication,
// endpoint, and TLS options. Its IdentityEndpoint and AuthOptions fields can
// be passed to config.NewProviderClientV3.
func ParseV3(opts ...ParseOption) (CloudConfig, error) {
	parsed, err := parseCloud(opts...)
	if err != nil {
		return CloudConfig{}, err
	}

	cloudConfig, err := providerOptions(parsed)
	if err != nil {
		return CloudConfig{}, err
	}

	return cloudConfig, nil
}

func providerOptions(parsed *parsedCloud) (CloudConfig, error) {
	cloud := parsed.cloud
	authInfo := cloud.AuthInfo
	authType := AuthType(coalesce(os.Getenv("OS_AUTH_TYPE"), string(cloud.AuthType)))
	identityEndpoint := coalesce(parsed.options.authURL, authInfo.AuthURL, os.Getenv("OS_AUTH_URL"))

	var authOptions tokens3.AuthOptionsBuilder
	switch authType {
	case AuthV3OIDCClientCredentials:
		authOptions = oidcAuthOptions(authInfo, cloud)
	case AuthV3WebSSO:
		redirectPort, err := webSSORedirectPort(authInfo.RedirectPort)
		if err != nil {
			return CloudConfig{}, err
		}
		namespace := parsed.options.tokenCacheNamespace
		if parsed.options.tokenCache != nil && namespace == "" {
			namespace = parsed.options.cloudName
		}
		authOptions = &websso.AuthOptions{
			IdentityProviderName: coalesce(authInfo.IdentityProvider, cloud.IdentityProvider, os.Getenv("OS_IDENTITY_PROVIDER")),
			Protocol:             coalesce(authInfo.Protocol, cloud.Protocol, os.Getenv("OS_PROTOCOL")),
			Scope:                authScope(authInfo),
			AllowReauth:          authInfo.AllowReauth,
			RedirectPort:         redirectPort,
			RedirectHost:         coalesce(authInfo.RedirectHost, os.Getenv("OS_REDIRECT_HOST")),
			Timeout:              parsed.options.webSSOTimeout,
			BrowserOpener:        parsed.options.webSSOBrowserOpener,
			TokenCache:           parsed.options.tokenCache,
			CacheNamespace:       namespace,
		}
	case AuthV3OAuth2MTLSClientCredential:
		authOptions = &oauth2mtls.AuthOptions{
			OAuth2Endpoint: coalesce(authInfo.OAuth2Endpoint, os.Getenv("OS_OAUTH2_ENDPOINT")),
			ClientID:       coalesce(authInfo.OAuth2ClientID, authInfo.ClientID, os.Getenv("OS_OAUTH2_CLIENT_ID"), os.Getenv("OS_CLIENT_ID")),
			AllowReauth:    authInfo.AllowReauth,
		}
	case "", AuthPassword, AuthToken, AuthV3Password, AuthV3Token, AuthV3ApplicationCredential:
		authOptions = standardV3AuthOptions(parsed)
	case AuthV2Password, AuthV2Token:
		return CloudConfig{}, fmt.Errorf("auth type %q requires Identity v2", authType)
	default:
		return CloudConfig{}, fmt.Errorf("unsupported auth type %q", authType)
	}

	return CloudConfig{
		Cloud:            cloud,
		IdentityEndpoint: identityEndpoint,
		AuthOptions:      authOptions,
		EndpointOptions:  parsed.endpointOpts,
		TLSConfig:        parsed.tlsConfig,
	}, nil
}

func standardV3AuthOptions(parsed *parsedCloud) *tokens3.AuthOptions {
	authInfo := parsed.cloud.AuthInfo
	return &tokens3.AuthOptions{
		Username:                    coalesce(parsed.options.username, authInfo.Username),
		UserID:                      coalesce(parsed.options.userID, authInfo.UserID),
		Password:                    coalesce(parsed.options.password, authInfo.Password),
		DomainID:                    coalesce(parsed.options.domainID, authInfo.UserDomainID, authInfo.DomainID, authInfo.DefaultDomain),
		DomainName:                  coalesce(parsed.options.domainName, authInfo.UserDomainName, authInfo.DomainName),
		AllowReauth:                 authInfo.AllowReauth,
		TokenID:                     coalesce(parsed.options.token, authInfo.Token),
		ApplicationCredentialID:     coalesce(parsed.options.applicationCredentialID, authInfo.ApplicationCredentialID),
		ApplicationCredentialName:   coalesce(parsed.options.applicationCredentialName, authInfo.ApplicationCredentialName),
		ApplicationCredentialSecret: coalesce(parsed.options.applicationCredentialSecret, authInfo.ApplicationCredentialSecret),
		Scope:                       authScope(authInfo),
	}
}

func oidcAuthOptions(authInfo *AuthInfo, cloud Cloud) *oidc.AuthOptions {
	return &oidc.AuthOptions{
		ClientID:             coalesce(authInfo.ClientID, os.Getenv("OS_CLIENT_ID")),
		ClientSecret:         coalesce(authInfo.ClientSecret, os.Getenv("OS_CLIENT_SECRET")),
		AccessTokenEndpoint:  coalesce(authInfo.AccessTokenEndpoint, os.Getenv("OS_ACCESS_TOKEN_ENDPOINT")),
		DiscoveryEndpoint:    coalesce(authInfo.DiscoveryEndpoint, os.Getenv("OS_DISCOVERY_ENDPOINT")),
		IdentityProviderName: coalesce(authInfo.IdentityProvider, cloud.IdentityProvider, os.Getenv("OS_IDENTITY_PROVIDER")),
		Protocol:             coalesce(authInfo.Protocol, cloud.Protocol, os.Getenv("OS_PROTOCOL")),
		AccessTokenType:      coalesce(authInfo.AccessTokenType, os.Getenv("OS_ACCESS_TOKEN_TYPE")),
		Scope:                authScope(authInfo),
		AllowReauth:          authInfo.AllowReauth,
		OIDCScope:            coalesce(authInfo.OpenIDScope, os.Getenv("OS_OPENID_SCOPE")),
	}
}

func authScope(authInfo *AuthInfo) tokens3.Scope {
	if authInfo.TrustID != "" {
		return tokens3.Scope{TrustID: authInfo.TrustID}
	}
	if authInfo.ProjectID != "" {
		return tokens3.Scope{ProjectID: authInfo.ProjectID}
	}
	if authInfo.ProjectName != "" {
		return tokens3.Scope{
			ProjectName: authInfo.ProjectName,
			DomainID:    coalesce(authInfo.ProjectDomainID, authInfo.DomainID, authInfo.DefaultDomain),
			DomainName:  coalesce(authInfo.ProjectDomainName, authInfo.DomainName),
		}
	}
	if authInfo.DomainID != "" {
		return tokens3.Scope{DomainID: authInfo.DomainID}
	}
	if authInfo.DomainName != "" {
		return tokens3.Scope{DomainName: authInfo.DomainName}
	}
	if authInfo.SystemScope != "" {
		return tokens3.Scope{System: true}
	}
	return tokens3.Scope{}
}

func webSSORedirectPort(configured int) (int, error) {
	if configured != 0 {
		return configured, nil
	}
	value := os.Getenv("OS_REDIRECT_PORT")
	if value == "" {
		return 0, nil
	}
	port, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("failed to parse OS_REDIRECT_PORT: %w", err)
	}
	return port, nil
}
