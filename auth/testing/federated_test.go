package testing

import (
	"errors"
	"testing"
	"time"

	"github.com/gophercloud/gophercloud/v2"
	"github.com/gophercloud/gophercloud/v2/auth"
	th "github.com/gophercloud/gophercloud/v2/testhelper"
)

type federatedCache struct{}

func (federatedCache) Get(string) (string, error) { return "", nil }
func (federatedCache) Set(string, string) error   { return nil }
func (federatedCache) Delete(string) error        { return nil }

func TestAuthOptionsFromCloudWebSSO(t *testing.T) {
	openerErr := errors.New("browser opener")
	opts, err := auth.AuthOptionsFromCloud(cloudSource{
		authType: auth.AuthV3WebSSO,
		authData: map[string]any{
			"auth_url":            "https://identity.example/v3",
			"identity_provider":   "idp",
			"protocol":            "openid",
			"redirect_host":       "::1",
			"redirect_port":       9991,
			"project_name":        "project",
			"project_domain_name": "projects",
		},
	},
		auth.WithTokenCache(federatedCache{}),
		auth.WithTokenCacheNamespace("personal"),
		auth.WithWebSSOTimeout(time.Minute),
		auth.WithWebSSOBrowserOpener(func(string) error { return openerErr }),
	)
	th.AssertNoErr(t, err)

	websso, ok := opts.(*auth.V3WebSSOOpts)
	if !ok {
		t.Fatalf("unexpected authenticator %T", opts)
	}
	th.AssertEquals(t, "https://identity.example/v3", websso.AuthURL)
	th.AssertEquals(t, "idp", websso.IdentityProviderName)
	th.AssertEquals(t, "openid", websso.Protocol)
	th.AssertEquals(t, "::1", websso.RedirectHost)
	th.AssertEquals(t, 9991, websso.RedirectPort)
	th.AssertEquals(t, time.Minute, websso.Timeout)
	th.AssertEquals(t, "personal", websso.CacheNamespace)
	th.AssertEquals(t, federatedCache{}, websso.TokenCache)
	th.AssertEquals(t, openerErr, websso.BrowserOpener(""))
	th.AssertEquals(t, true, websso.AllowReauth)
	th.AssertDeepEquals(t, &auth.Scope{ProjectName: "project", ProjectDomainName: "projects"}, websso.Scope)
}

func TestAuthOptionsFromCloudOIDCClientCredentials(t *testing.T) {
	opts, err := auth.AuthOptionsFromCloud(cloudSource{
		authType: auth.AuthV3OIDCClientCredentials,
		authData: map[string]any{
			"auth_url":              "https://identity.example/v3",
			"identity_provider":     "idp",
			"protocol":              "openid",
			"client_id":             "client",
			"client_secret":         "secret",
			"access_token_endpoint": "https://idp.example/token",
			"access_token_type":     "id_token",
			"discovery_endpoint":    "https://idp.example/discovery",
			"openid_scope":          "openid profile",
			"project_id":            "project",
			"allow_reauth":          false,
		},
	})
	th.AssertNoErr(t, err)
	th.AssertDeepEquals(t, &auth.V3OIDCClientCredentialsOpts{
		AuthURL:              "https://identity.example/v3",
		IdentityProviderName: "idp",
		Protocol:             "openid",
		ClientID:             "client",
		ClientSecret:         "secret",
		AccessTokenEndpoint:  "https://idp.example/token",
		AccessTokenType:      "id_token",
		DiscoveryEndpoint:    "https://idp.example/discovery",
		OIDCScope:            "openid profile",
		Scope:                &auth.Scope{ProjectID: "project"},
	}, opts)
}

func TestAuthOptionsFromCloudOAuth2MTLS(t *testing.T) {
	opts, err := auth.AuthOptionsFromCloud(cloudSource{
		authType: auth.AuthV3OAuth2MTLSClientCredential,
		authData: map[string]any{
			"auth_url":         "https://identity.example/v3",
			"oauth2_endpoint":  "https://identity.example/v3/OS-OAUTH2/token",
			"oauth2_client_id": "user",
		},
	})
	th.AssertNoErr(t, err)
	th.AssertDeepEquals(t, &auth.V3OAuth2MTLSOpts{
		AuthURL:        "https://identity.example/v3",
		OAuth2Endpoint: "https://identity.example/v3/OS-OAUTH2/token",
		ClientID:       "user",
		AllowReauth:    true,
	}, opts)
}

func TestAuthOptionsFromCloudFederatedScope(t *testing.T) {
	tests := []struct {
		name    string
		data    map[string]any
		options []auth.CloudOption
		want    *auth.Scope
		err     error
	}{
		{"project ID", map[string]any{"project_id": "project"}, nil, &auth.Scope{ProjectID: "project"}, nil},
		{"project name with domain", map[string]any{"project_name": "project", "project_domain_name": "domain"}, nil, &auth.Scope{ProjectName: "project", ProjectDomainName: "domain"}, nil},
		{"domain", map[string]any{"domain_name": "domain"}, nil, &auth.Scope{DomainName: "domain"}, nil},
		{"system", map[string]any{"system_scope": "all"}, nil, &auth.Scope{System: true}, nil},
		{"trust", map[string]any{"trust_id": "trust"}, nil, &auth.Scope{TrustID: "trust"}, nil},
		{"project override", map[string]any{"project_id": "project"}, []auth.CloudOption{auth.WithProjectID("override")}, &auth.Scope{ProjectID: "override"}, nil},
		{"scope override", map[string]any{"system_scope": "invalid"}, []auth.CloudOption{auth.WithScope(&auth.Scope{DomainID: "domain"})}, &auth.Scope{DomainID: "domain"}, nil},
		{"invalid system", map[string]any{"system_scope": "invalid"}, nil, nil, gophercloud.ErrInvalidSystemScope{}},
	}

	for _, authType := range []auth.AuthType{auth.AuthV3WebSSO, auth.AuthV3OIDCClientCredentials} {
		for _, test := range tests {
			t.Run(string(authType)+"/"+test.name, func(t *testing.T) {
				data := map[string]any{"auth_url": "https://identity.example/v3"}
				for k, v := range test.data {
					data[k] = v
				}
				opts, err := auth.AuthOptionsFromCloud(cloudSource{authType: authType, authData: data}, test.options...)
				if test.err != nil {
					th.AssertEquals(t, test.err, err)
					return
				}
				th.AssertNoErr(t, err)

				var scope *auth.Scope
				switch opts := opts.(type) {
				case *auth.V3WebSSOOpts:
					scope = opts.Scope
				case *auth.V3OIDCClientCredentialsOpts:
					scope = opts.Scope
				default:
					t.Fatalf("unexpected authenticator %T", opts)
				}
				th.AssertDeepEquals(t, test.want, scope)
			})
		}
	}
}

func TestAuthOptionsFromCloudWebSSORedirectPort(t *testing.T) {
	for _, test := range []struct {
		port any
		want int
		ok   bool
	}{
		{9991, 9991, true},
		{float64(9991), 9991, true},
		{"9991", 9991, true},
		{"invalid", 0, false},
		{1.5, 0, false},
	} {
		opts, err := auth.AuthOptionsFromCloud(cloudSource{
			authType: auth.AuthV3WebSSO,
			authData: map[string]any{"auth_url": "https://identity.example/v3", "redirect_port": test.port},
		})
		if !test.ok {
			if err == nil {
				t.Errorf("expected an error for redirect_port %v", test.port)
			}
			continue
		}
		th.AssertNoErr(t, err)
		th.AssertEquals(t, test.want, opts.(*auth.V3WebSSOOpts).RedirectPort)
	}
}

func TestAuthOptionsFromEnvFederated(t *testing.T) {
	CleanupEnv(t)
	for key, value := range map[string]string{
		"OS_AUTH_URL":              "https://identity.example/v3",
		"OS_IDENTITY_PROVIDER":     "idp",
		"OS_PROTOCOL":              "openid",
		"OS_CLIENT_ID":             "client",
		"OS_CLIENT_SECRET":         "secret",
		"OS_DISCOVERY_ENDPOINT":    "https://idp.example/discovery",
		"OS_OAUTH2_CLIENT_ID":      "user",
		"OS_REDIRECT_PORT":         "9991",
		"OS_PROJECT_NAME":          "project",
		"OS_PROJECT_DOMAIN_NAME":   "projects",
		"OS_ACCESS_TOKEN_ENDPOINT": "",
	} {
		t.Setenv(key, value)
	}
	scope := &auth.Scope{ProjectName: "project", ProjectDomainName: "projects"}

	t.Setenv("OS_AUTH_TYPE", string(auth.AuthV3WebSSO))
	opts, err := auth.AuthOptionsFromEnv()
	th.AssertNoErr(t, err)
	th.AssertDeepEquals(t, &auth.V3WebSSOOpts{
		AuthURL:              "https://identity.example/v3",
		IdentityProviderName: "idp",
		Protocol:             "openid",
		RedirectPort:         9991,
		AllowReauth:          true,
		Scope:                scope,
	}, opts)

	t.Setenv("OS_AUTH_TYPE", string(auth.AuthV3OIDCClientCredentials))
	opts, err = auth.AuthOptionsFromEnv()
	th.AssertNoErr(t, err)
	th.AssertDeepEquals(t, &auth.V3OIDCClientCredentialsOpts{
		AuthURL:              "https://identity.example/v3",
		IdentityProviderName: "idp",
		Protocol:             "openid",
		ClientID:             "client",
		ClientSecret:         "secret",
		DiscoveryEndpoint:    "https://idp.example/discovery",
		AllowReauth:          true,
		Scope:                scope,
	}, opts)

	t.Setenv("OS_AUTH_TYPE", string(auth.AuthV3OAuth2MTLSClientCredential))
	opts, err = auth.AuthOptionsFromEnv()
	th.AssertNoErr(t, err)
	th.AssertDeepEquals(t, &auth.V3OAuth2MTLSOpts{
		AuthURL:     "https://identity.example/v3",
		ClientID:    "user",
		AllowReauth: true,
	}, opts)

	// OAuth2 mTLS has no scope, so it ignores scope settings.
	t.Setenv("OS_SYSTEM_SCOPE", "invalid")
	_, err = auth.AuthOptionsFromEnv()
	th.AssertNoErr(t, err)

	t.Setenv("OS_AUTH_TYPE", string(auth.AuthV3OIDCClientCredentials))
	_, err = auth.AuthOptionsFromEnv()
	th.AssertEquals(t, gophercloud.ErrInvalidSystemScope{}, err)
}

func TestAuthOptionsFromEnvFederatedNormalizesGenericDomain(t *testing.T) {
	CleanupEnv(t)
	t.Setenv("OS_AUTH_URL", "https://identity.example/v3")
	t.Setenv("OS_AUTH_TYPE", string(auth.AuthV3OIDCClientCredentials))
	t.Setenv("OS_DOMAIN_NAME", "domain")

	t.Setenv("OS_PROJECT_NAME", "project")
	opts, err := auth.AuthOptionsFromEnv()
	th.AssertNoErr(t, err)
	th.AssertDeepEquals(t, &auth.Scope{ProjectName: "project", ProjectDomainName: "domain"}, opts.(*auth.V3OIDCClientCredentialsOpts).Scope)

	t.Setenv("OS_PROJECT_NAME", "")
	opts, err = auth.AuthOptionsFromEnv()
	th.AssertNoErr(t, err)
	th.AssertDeepEquals(t, &auth.Scope{DomainName: "domain"}, opts.(*auth.V3OIDCClientCredentialsOpts).Scope)
}
