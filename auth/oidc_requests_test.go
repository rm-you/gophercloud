package auth

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/gophercloud/gophercloud/v2"
	th "github.com/gophercloud/gophercloud/v2/testhelper"
)

func TestOIDCCreateUnscoped(t *testing.T) {
	fakeServer := th.SetupHTTP()
	defer fakeServer.Teardown()

	expectedBasicAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("my-client-id:my-client-secret"))
	HandleIdPTokenSuccessfully(t, fakeServer, expectedBasicAuth)
	HandleFederationAuthSuccessfully(t, fakeServer, "test-idp-access-token-abc123")

	client := gophercloud.ServiceClient{
		ProviderClient: &gophercloud.ProviderClient{},
		Endpoint:       fakeServer.Endpoint(),
	}

	opts := &V3OIDCClientCredentialsOpts{
		IdentityProviderName: "my-idp",
		Protocol:             "openid",
		ClientID:             "my-client-id",
		ClientSecret:         "my-client-secret",
		AccessTokenEndpoint:  fakeServer.Endpoint() + "oauth2/token",
	}

	result, err := authenticateOIDC(context.TODO(), &client, opts)
	th.AssertNoErr(t, err)
	th.CheckEquals(t, UnscopedTokenID, result.TokenID)
}

func TestOIDCCreateScoped(t *testing.T) {
	fakeServer := th.SetupHTTP()
	defer fakeServer.Teardown()

	expectedBasicAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("my-client-id:my-client-secret"))
	HandleIdPTokenSuccessfully(t, fakeServer, expectedBasicAuth)
	HandleFederationAuthSuccessfully(t, fakeServer, "test-idp-access-token-abc123")
	HandleRescopeSuccessfully(t, fakeServer, UnscopedTokenID)

	client := gophercloud.ServiceClient{
		ProviderClient: &gophercloud.ProviderClient{},
		Endpoint:       fakeServer.Endpoint(),
	}

	opts := &V3OIDCClientCredentialsOpts{
		IdentityProviderName: "my-idp",
		Protocol:             "openid",
		ClientID:             "my-client-id",
		ClientSecret:         "my-client-secret",
		AccessTokenEndpoint:  fakeServer.Endpoint() + "oauth2/token",
		Scope: &Scope{
			ProjectName:       "my-project",
			ProjectDomainName: "Default",
		},
	}

	result, err := authenticateOIDC(context.TODO(), &client, opts)
	th.AssertNoErr(t, err)
	th.CheckEquals(t, ScopedTokenID, result.TokenID)
}

func TestOIDCCreateScopedByProjectID(t *testing.T) {
	fakeServer := th.SetupHTTP()
	defer fakeServer.Teardown()

	expectedBasicAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("my-client-id:my-client-secret"))
	HandleIdPTokenSuccessfully(t, fakeServer, expectedBasicAuth)
	HandleFederationAuthSuccessfully(t, fakeServer, "test-idp-access-token-abc123")
	HandleRescopeSuccessfully(t, fakeServer, UnscopedTokenID)

	client := gophercloud.ServiceClient{
		ProviderClient: &gophercloud.ProviderClient{},
		Endpoint:       fakeServer.Endpoint(),
	}

	opts := &V3OIDCClientCredentialsOpts{
		IdentityProviderName: "my-idp",
		Protocol:             "openid",
		ClientID:             "my-client-id",
		ClientSecret:         "my-client-secret",
		AccessTokenEndpoint:  fakeServer.Endpoint() + "oauth2/token",
		Scope: &Scope{
			ProjectID: "project-id-001",
		},
	}

	result, err := authenticateOIDC(context.TODO(), &client, opts)
	th.AssertNoErr(t, err)
	th.CheckEquals(t, ScopedTokenID, result.TokenID)
}

func TestOIDCCreateScopedByDomainID(t *testing.T) {
	fakeServer := th.SetupHTTP()
	defer fakeServer.Teardown()

	expectedBasicAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("my-client-id:my-client-secret"))
	HandleIdPTokenSuccessfully(t, fakeServer, expectedBasicAuth)
	HandleFederationAuthSuccessfully(t, fakeServer, "test-idp-access-token-abc123")
	HandleRescopeSuccessfully(t, fakeServer, UnscopedTokenID)

	client := gophercloud.ServiceClient{
		ProviderClient: &gophercloud.ProviderClient{},
		Endpoint:       fakeServer.Endpoint(),
	}

	opts := &V3OIDCClientCredentialsOpts{
		IdentityProviderName: "my-idp",
		Protocol:             "openid",
		ClientID:             "my-client-id",
		ClientSecret:         "my-client-secret",
		AccessTokenEndpoint:  fakeServer.Endpoint() + "oauth2/token",
		Scope: &Scope{
			DomainID: "default",
		},
	}

	result, err := authenticateOIDC(context.TODO(), &client, opts)
	th.AssertNoErr(t, err)
	th.CheckEquals(t, ScopedTokenID, result.TokenID)
}

func TestOIDCCreateScopedByDomainName(t *testing.T) {
	fakeServer := th.SetupHTTP()
	defer fakeServer.Teardown()

	expectedBasicAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("my-client-id:my-client-secret"))
	HandleIdPTokenSuccessfully(t, fakeServer, expectedBasicAuth)
	HandleFederationAuthSuccessfully(t, fakeServer, "test-idp-access-token-abc123")
	HandleRescopeSuccessfully(t, fakeServer, UnscopedTokenID)

	client := gophercloud.ServiceClient{
		ProviderClient: &gophercloud.ProviderClient{},
		Endpoint:       fakeServer.Endpoint(),
	}

	opts := &V3OIDCClientCredentialsOpts{
		IdentityProviderName: "my-idp",
		Protocol:             "openid",
		ClientID:             "my-client-id",
		ClientSecret:         "my-client-secret",
		AccessTokenEndpoint:  fakeServer.Endpoint() + "oauth2/token",
		Scope: &Scope{
			DomainName: "Default",
		},
	}

	result, err := authenticateOIDC(context.TODO(), &client, opts)
	th.AssertNoErr(t, err)
	th.CheckEquals(t, ScopedTokenID, result.TokenID)
}

func TestOIDCCreateWithIDToken(t *testing.T) {
	fakeServer := th.SetupHTTP()
	defer fakeServer.Teardown()

	HandleIdPTokenIDTokenSuccessfully(t, fakeServer)
	HandleFederationAuthSuccessfully(t, fakeServer, "test-idp-id-token-xyz789")

	client := gophercloud.ServiceClient{
		ProviderClient: &gophercloud.ProviderClient{},
		Endpoint:       fakeServer.Endpoint(),
	}

	opts := &V3OIDCClientCredentialsOpts{
		IdentityProviderName: "my-idp",
		Protocol:             "openid",
		ClientID:             "my-client-id",
		ClientSecret:         "my-client-secret",
		AccessTokenEndpoint:  fakeServer.Endpoint() + "oauth2/token",
		AccessTokenType:      "id_token",
	}

	result, err := authenticateOIDC(context.TODO(), &client, opts)
	th.AssertNoErr(t, err)
	th.CheckEquals(t, UnscopedTokenID, result.TokenID)
}

func TestOIDCCreateRejectsUnsupportedAccessTokenType(t *testing.T) {
	fakeServer := th.SetupHTTP()
	defer fakeServer.Teardown()

	fakeServer.Mux.HandleFunc("/oauth2/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"access_token":"opaque-token","token_type":"MAC"}`)
	})
	client := gophercloud.ServiceClient{
		ProviderClient: &gophercloud.ProviderClient{},
		Endpoint:       fakeServer.Endpoint(),
	}
	_, err := authenticateOIDC(context.Background(), &client, &V3OIDCClientCredentialsOpts{
		IdentityProviderName: "my-idp",
		Protocol:             "openid",
		ClientID:             "my-client-id",
		ClientSecret:         "my-client-secret",
		AccessTokenEndpoint:  fakeServer.Endpoint() + "oauth2/token",
	})
	if err == nil || !strings.Contains(err.Error(), "unsupported token_type") {
		t.Fatalf("expected unsupported token_type error, got %v", err)
	}
}

func TestOIDCCreateScopedBySystemScope(t *testing.T) {
	fakeServer := th.SetupHTTP()
	defer fakeServer.Teardown()

	expectedBasicAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("my-client-id:my-client-secret"))
	HandleIdPTokenSuccessfully(t, fakeServer, expectedBasicAuth)
	HandleFederationAuthSuccessfully(t, fakeServer, "test-idp-access-token-abc123")
	HandleRescopeSuccessfully(t, fakeServer, UnscopedTokenID)

	client := gophercloud.ServiceClient{
		ProviderClient: &gophercloud.ProviderClient{},
		Endpoint:       fakeServer.Endpoint(),
	}

	opts := &V3OIDCClientCredentialsOpts{
		IdentityProviderName: "my-idp",
		Protocol:             "openid",
		ClientID:             "my-client-id",
		ClientSecret:         "my-client-secret",
		AccessTokenEndpoint:  fakeServer.Endpoint() + "oauth2/token",
		Scope: &Scope{
			System: true,
		},
	}

	result, err := authenticateOIDC(context.TODO(), &client, opts)
	th.AssertNoErr(t, err)
	th.CheckEquals(t, ScopedTokenID, result.TokenID)
}

func TestOIDCValidationMissingInput(t *testing.T) {
	tests := []struct {
		argument string
		omit     func(*V3OIDCClientCredentialsOpts)
	}{
		{"IdentityProviderName", func(opts *V3OIDCClientCredentialsOpts) { opts.IdentityProviderName = "" }},
		{"Protocol", func(opts *V3OIDCClientCredentialsOpts) { opts.Protocol = "" }},
		{"ClientID", func(opts *V3OIDCClientCredentialsOpts) { opts.ClientID = "" }},
		{"AccessTokenEndpoint/DiscoveryEndpoint", func(opts *V3OIDCClientCredentialsOpts) { opts.AccessTokenEndpoint = "" }},
	}
	validators := map[string]func(*V3OIDCClientCredentialsOpts) error{
		"ToTokenV3CreateMap": func(opts *V3OIDCClientCredentialsOpts) error {
			_, err := gophercloud.BuildRequestBody(opts, "")
			return err
		},
		"Authenticate": func(opts *V3OIDCClientCredentialsOpts) error {
			opts.AuthURL = "https://identity.example.com"
			_, err := opts.Authenticate(context.Background(), nil)
			return err
		},
	}
	for _, test := range tests {
		t.Run(test.argument, func(t *testing.T) {
			for name, validate := range validators {
				t.Run(name, func(t *testing.T) {
					opts := &V3OIDCClientCredentialsOpts{
						IdentityProviderName: "my-idp",
						Protocol:             "openid",
						ClientID:             "my-client-id",
						AccessTokenEndpoint:  "https://idp.example.com/oauth2/token",
					}
					test.omit(opts)
					err := validate(opts)
					var missing gophercloud.ErrMissingInput
					if !errors.As(err, &missing) {
						t.Fatalf("Expected ErrMissingInput, got %v", err)
					}
					th.CheckEquals(t, test.argument, missing.Argument)
				})
			}
		})
	}
}

func TestOIDCCreateUnscopedWithDiscovery(t *testing.T) {
	fakeServer := th.SetupHTTP()
	defer fakeServer.Teardown()

	tokenEndpointURL := fakeServer.Endpoint() + "oauth2/token"
	HandleDiscoverySuccessfully(t, fakeServer, tokenEndpointURL)

	expectedBasicAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("my-client-id:my-client-secret"))
	HandleIdPTokenSuccessfully(t, fakeServer, expectedBasicAuth)
	HandleFederationAuthSuccessfully(t, fakeServer, "test-idp-access-token-abc123")

	client := gophercloud.ServiceClient{
		ProviderClient: &gophercloud.ProviderClient{},
		Endpoint:       fakeServer.Endpoint(),
	}

	opts := &V3OIDCClientCredentialsOpts{
		IdentityProviderName: "my-idp",
		Protocol:             "openid",
		ClientID:             "my-client-id",
		ClientSecret:         "my-client-secret",
		DiscoveryEndpoint:    fakeServer.Endpoint() + ".well-known/openid-configuration",
	}

	result, err := authenticateOIDC(context.TODO(), &client, opts)
	th.AssertNoErr(t, err)
	th.CheckEquals(t, UnscopedTokenID, result.TokenID)
}

func TestOIDCCreateScopedWithDiscovery(t *testing.T) {
	fakeServer := th.SetupHTTP()
	defer fakeServer.Teardown()

	tokenEndpointURL := fakeServer.Endpoint() + "oauth2/token"
	HandleDiscoverySuccessfully(t, fakeServer, tokenEndpointURL)

	expectedBasicAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("my-client-id:my-client-secret"))
	HandleIdPTokenSuccessfully(t, fakeServer, expectedBasicAuth)
	HandleFederationAuthSuccessfully(t, fakeServer, "test-idp-access-token-abc123")
	HandleRescopeSuccessfully(t, fakeServer, UnscopedTokenID)

	client := gophercloud.ServiceClient{
		ProviderClient: &gophercloud.ProviderClient{},
		Endpoint:       fakeServer.Endpoint(),
	}

	opts := &V3OIDCClientCredentialsOpts{
		IdentityProviderName: "my-idp",
		Protocol:             "openid",
		ClientID:             "my-client-id",
		ClientSecret:         "my-client-secret",
		DiscoveryEndpoint:    fakeServer.Endpoint() + ".well-known/openid-configuration",
		Scope: &Scope{
			ProjectName:       "my-project",
			ProjectDomainName: "Default",
		},
	}

	result, err := authenticateOIDC(context.TODO(), &client, opts)
	th.AssertNoErr(t, err)
	th.CheckEquals(t, ScopedTokenID, result.TokenID)
}

func TestOIDCAccessTokenEndpointOverridesDiscovery(t *testing.T) {
	fakeServer := th.SetupHTTP()
	defer fakeServer.Teardown()

	expectedBasicAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("my-client-id:my-client-secret"))
	HandleIdPTokenSuccessfully(t, fakeServer, expectedBasicAuth)
	HandleFederationAuthSuccessfully(t, fakeServer, "test-idp-access-token-abc123")

	client := gophercloud.ServiceClient{
		ProviderClient: &gophercloud.ProviderClient{},
		Endpoint:       fakeServer.Endpoint(),
	}

	opts := &V3OIDCClientCredentialsOpts{
		IdentityProviderName: "my-idp",
		Protocol:             "openid",
		ClientID:             "my-client-id",
		ClientSecret:         "my-client-secret",
		AccessTokenEndpoint:  fakeServer.Endpoint() + "oauth2/token",
		DiscoveryEndpoint:    "http://should-not-be-called.example.com/.well-known/openid-configuration",
	}

	result, err := authenticateOIDC(context.TODO(), &client, opts)
	th.AssertNoErr(t, err)
	th.CheckEquals(t, UnscopedTokenID, result.TokenID)
}

func TestOIDCDiscoveryWithNoGrantTypesField(t *testing.T) {
	fakeServer := th.SetupHTTP()
	defer fakeServer.Teardown()

	tokenEndpointURL := fakeServer.Endpoint() + "oauth2/token"
	HandleDiscoveryNoGrantTypesSuccessfully(t, fakeServer, tokenEndpointURL)

	expectedBasicAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("my-client-id:my-client-secret"))
	HandleIdPTokenSuccessfully(t, fakeServer, expectedBasicAuth)
	HandleFederationAuthSuccessfully(t, fakeServer, "test-idp-access-token-abc123")

	client := gophercloud.ServiceClient{
		ProviderClient: &gophercloud.ProviderClient{},
		Endpoint:       fakeServer.Endpoint(),
	}

	opts := &V3OIDCClientCredentialsOpts{
		IdentityProviderName: "my-idp",
		Protocol:             "openid",
		ClientID:             "my-client-id",
		ClientSecret:         "my-client-secret",
		DiscoveryEndpoint:    fakeServer.Endpoint() + ".well-known/openid-configuration",
	}

	result, err := authenticateOIDC(context.TODO(), &client, opts)
	th.AssertNoErr(t, err)
	th.CheckEquals(t, UnscopedTokenID, result.TokenID)
}

func TestOIDCDiscoveryUnsupportedGrantType(t *testing.T) {
	fakeServer := th.SetupHTTP()
	defer fakeServer.Teardown()

	HandleDiscoveryUnsupportedGrantType(t, fakeServer)

	client := gophercloud.ServiceClient{
		ProviderClient: &gophercloud.ProviderClient{},
		Endpoint:       fakeServer.Endpoint(),
	}

	opts := &V3OIDCClientCredentialsOpts{
		IdentityProviderName: "my-idp",
		Protocol:             "openid",
		ClientID:             "my-client-id",
		ClientSecret:         "my-client-secret",
		DiscoveryEndpoint:    fakeServer.Endpoint() + ".well-known/openid-configuration",
	}

	_, err := authenticateOIDC(context.TODO(), &client, opts)
	th.AssertErr(t, err)
}

func TestOIDCDiscoveryNoTokenEndpoint(t *testing.T) {
	fakeServer := th.SetupHTTP()
	defer fakeServer.Teardown()

	HandleDiscoveryNoTokenEndpoint(t, fakeServer)

	client := gophercloud.ServiceClient{
		ProviderClient: &gophercloud.ProviderClient{},
		Endpoint:       fakeServer.Endpoint(),
	}

	opts := &V3OIDCClientCredentialsOpts{
		IdentityProviderName: "my-idp",
		Protocol:             "openid",
		ClientID:             "my-client-id",
		ClientSecret:         "my-client-secret",
		DiscoveryEndpoint:    fakeServer.Endpoint() + ".well-known/openid-configuration",
	}

	_, err := authenticateOIDC(context.TODO(), &client, opts)
	th.AssertErr(t, err)
}

func TestOIDCDiscoveryHTTPError(t *testing.T) {
	fakeServer := th.SetupHTTP()
	defer fakeServer.Teardown()

	HandleDiscoveryHTTPError(t, fakeServer)

	client := gophercloud.ServiceClient{
		ProviderClient: &gophercloud.ProviderClient{},
		Endpoint:       fakeServer.Endpoint(),
	}

	opts := &V3OIDCClientCredentialsOpts{
		IdentityProviderName: "my-idp",
		Protocol:             "openid",
		ClientID:             "my-client-id",
		ClientSecret:         "my-client-secret",
		DiscoveryEndpoint:    fakeServer.Endpoint() + ".well-known/openid-configuration",
	}

	_, err := authenticateOIDC(context.TODO(), &client, opts)
	th.AssertErr(t, err)
}

func TestOIDCDiscoveryInvalidJSON(t *testing.T) {
	fakeServer := th.SetupHTTP()
	defer fakeServer.Teardown()

	HandleDiscoveryInvalidJSON(t, fakeServer)

	client := gophercloud.ServiceClient{
		ProviderClient: &gophercloud.ProviderClient{},
		Endpoint:       fakeServer.Endpoint(),
	}

	opts := &V3OIDCClientCredentialsOpts{
		IdentityProviderName: "my-idp",
		Protocol:             "openid",
		ClientID:             "my-client-id",
		ClientSecret:         "my-client-secret",
		DiscoveryEndpoint:    fakeServer.Endpoint() + ".well-known/openid-configuration",
	}

	_, err := authenticateOIDC(context.TODO(), &client, opts)
	th.AssertErr(t, err)
}

func TestOIDCDiscoveryRejectsPlainHTTPTokenEndpoint(t *testing.T) {
	fakeServer := th.SetupHTTP()
	defer fakeServer.Teardown()

	HandleDiscoverySuccessfully(t, fakeServer, "http://idp.example.com/oauth2/token")

	client := gophercloud.ServiceClient{
		ProviderClient: &gophercloud.ProviderClient{},
		Endpoint:       fakeServer.Endpoint(),
	}

	opts := &V3OIDCClientCredentialsOpts{
		IdentityProviderName: "my-idp",
		Protocol:             "openid",
		ClientID:             "my-client-id",
		ClientSecret:         "my-client-secret",
		DiscoveryEndpoint:    fakeServer.Endpoint() + ".well-known/openid-configuration",
	}

	_, err := authenticateOIDC(context.TODO(), &client, opts)
	th.AssertErr(t, err)
	th.AssertEquals(t, true, strings.Contains(err.Error(), "does not use https"))
}

func TestCheckTokenEndpoint(t *testing.T) {
	for endpoint, ok := range map[string]bool{
		"https://idp.example.com/token": true,
		"http://127.0.0.1:8080/token":   true,
		"http://[::1]:8080/token":       true,
		"http://localhost/token":        true,
		"http://idp.example.com/token":  false,
		"ftp://idp.example.com/token":   false,
	} {
		err := checkTokenEndpoint(endpoint)
		th.AssertEquals(t, ok, err == nil)
	}
}
