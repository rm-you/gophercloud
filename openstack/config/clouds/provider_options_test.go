package clouds

import (
	"strings"
	"testing"
	"time"

	"github.com/gophercloud/gophercloud/v2"
	"github.com/gophercloud/gophercloud/v2/openstack/identity/v3/oauth2mtls"
	"github.com/gophercloud/gophercloud/v2/openstack/identity/v3/oidc"
	"github.com/gophercloud/gophercloud/v2/openstack/identity/v3/tokens"
	"github.com/gophercloud/gophercloud/v2/openstack/identity/v3/websso"
)

type testTokenCache struct{}

func (testTokenCache) Get(string) (string, error) { return "", nil }
func (testTokenCache) Set(string, string) error   { return nil }
func (testTokenCache) Delete(string) error        { return nil }

func TestParseV3PasswordPreservesProjectDomain(t *testing.T) {
	cloudConfig, err := ParseV3(
		WithCloudName("password"),
		WithCloudsYAML(strings.NewReader(`
clouds:
  password:
    auth_type: v3password
    auth:
      auth_url: https://identity.example/v3
      username: user
      password: secret
      user_domain_name: users
      project_name: project
      project_domain_name: projects
`)),
	)
	if err != nil {
		t.Fatal(err)
	}

	opts, ok := cloudConfig.AuthOptions.(*tokens.AuthOptions)
	if !ok {
		t.Fatalf("unexpected auth options type: %T", cloudConfig.AuthOptions)
	}
	if opts.DomainName != "users" {
		t.Fatalf("unexpected user domain: %q", opts.DomainName)
	}
	if opts.Scope.ProjectName != "project" || opts.Scope.DomainName != "projects" {
		t.Fatalf("unexpected project scope: %#v", opts.Scope)
	}
}

func TestParseV3PasswordOptionsSetScope(t *testing.T) {
	tests := map[string]struct {
		options []ParseOption
		scope   tokens.Scope
	}{
		"project ID": {
			options: []ParseOption{WithProjectID("override-project-id")},
			scope:   tokens.Scope{ProjectID: "override-project-id"},
		},
		"project name": {
			options: []ParseOption{
				WithProjectName("override-project"),
				WithDomainName("override-domain"),
			},
			scope: tokens.Scope{
				ProjectName: "override-project",
				DomainName:  "override-domain",
			},
		},
		"explicit scope": {
			options: []ParseOption{WithScope(&gophercloud.AuthScope{
				DomainID: "scope-domain-id",
			})},
			scope: tokens.Scope{DomainID: "scope-domain-id"},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			options := []ParseOption{
				WithCloudName("password"),
				WithCloudsYAML(strings.NewReader(`
clouds:
  password:
    auth_type: v3password
    auth:
      auth_url: https://identity.example/v3
      username: user
      password: secret
      user_domain_name: users
`)),
			}
			cloudConfig, err := ParseV3(append(options, test.options...)...)
			if err != nil {
				t.Fatal(err)
			}

			opts, ok := cloudConfig.AuthOptions.(*tokens.AuthOptions)
			if !ok {
				t.Fatalf("unexpected auth options type: %T", cloudConfig.AuthOptions)
			}
			if opts.Scope != test.scope {
				t.Fatalf("unexpected scope: %#v", opts.Scope)
			}
		})
	}
}

func TestParseV3PasswordDomainDoesNotImplyScope(t *testing.T) {
	cloudConfig, err := ParseV3(
		WithCloudName("password"),
		WithCloudsYAML(strings.NewReader(`
clouds:
  password:
    auth_type: v3password
    auth:
      auth_url: https://identity.example/v3
      username: user
      password: secret
      domain_name: users
`)),
	)
	if err != nil {
		t.Fatal(err)
	}

	opts, ok := cloudConfig.AuthOptions.(*tokens.AuthOptions)
	if !ok {
		t.Fatalf("unexpected auth options type: %T", cloudConfig.AuthOptions)
	}
	if opts.DomainName != "users" {
		t.Fatalf("unexpected user domain: %q", opts.DomainName)
	}
	if opts.Scope != (tokens.Scope{}) {
		t.Fatalf("unexpected scope: %#v", opts.Scope)
	}
}

func TestParseV3OIDC(t *testing.T) {
	cloudConfig, err := ParseV3(
		WithCloudName("oidc"),
		WithCloudsYAML(strings.NewReader(`
clouds:
  oidc:
    auth_type: v3oidcclientcredentials
    region_name: RegionOne
    auth:
      auth_url: https://identity.example/v3
      client_id: client-id
      client_secret: client-secret
      discovery_endpoint: https://idp.example/.well-known/openid-configuration
      identity_provider: example-idp
      protocol: openid
      project_name: project
      project_domain_name: project-domain
      allow_reauth: true
`)),
	)
	if err != nil {
		t.Fatal(err)
	}

	if cloudConfig.IdentityEndpoint != "https://identity.example/v3" {
		t.Fatalf("unexpected identity endpoint: %q", cloudConfig.IdentityEndpoint)
	}
	if cloudConfig.EndpointOptions.Region != "RegionOne" {
		t.Fatalf("unexpected region: %q", cloudConfig.EndpointOptions.Region)
	}

	opts, ok := cloudConfig.AuthOptions.(*oidc.AuthOptions)
	if !ok {
		t.Fatalf("unexpected auth options type: %T", cloudConfig.AuthOptions)
	}
	if opts.ClientID != "client-id" || opts.ClientSecret != "client-secret" {
		t.Fatalf("unexpected OIDC client credentials: %#v", opts)
	}
	if opts.IdentityProviderName != "example-idp" || opts.Protocol != "openid" {
		t.Fatalf("unexpected federation target: %#v", opts)
	}
	if opts.Scope.ProjectName != "project" || opts.Scope.DomainName != "project-domain" {
		t.Fatalf("unexpected scope: %#v", opts.Scope)
	}
	if !opts.AllowReauth {
		t.Fatal("AllowReauth was not preserved")
	}
}

func TestParseV3WebSSO(t *testing.T) {
	cache := testTokenCache{}
	cloudConfig, err := ParseV3(
		WithCloudName("websso"),
		WithCloudsYAML(strings.NewReader(`
clouds:
  websso:
    auth_type: v3websso
    identity_provider: example-idp
    protocol: saml2
    auth:
      auth_url: https://identity.example/v3
      redirect_host: ::1
      redirect_port: 9991
      project_id: project-id
`)),
		WithTokenCache(cache, ""),
		WithWebSSOTimeout(time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}

	opts, ok := cloudConfig.AuthOptions.(*websso.AuthOptions)
	if !ok {
		t.Fatalf("unexpected auth options type: %T", cloudConfig.AuthOptions)
	}
	if opts.IdentityProviderName != "example-idp" || opts.Protocol != "saml2" {
		t.Fatalf("unexpected federation target: %#v", opts)
	}
	if opts.RedirectHost != "::1" || opts.RedirectPort != 9991 {
		t.Fatalf("unexpected redirect address: %#v", opts)
	}
	if opts.Scope.ProjectID != "project-id" {
		t.Fatalf("unexpected scope: %#v", opts.Scope)
	}
	if opts.TokenCache != cache || opts.CacheNamespace != "websso" {
		t.Fatalf("unexpected cache configuration: %#v", opts)
	}
	if opts.Timeout != time.Minute {
		t.Fatalf("unexpected timeout: %s", opts.Timeout)
	}
}

func TestParseV3OAuth2MTLS(t *testing.T) {
	cloudConfig, err := ParseV3(
		WithCloudName("oauth2"),
		WithCloudsYAML(strings.NewReader(`
clouds:
  oauth2:
    auth_type: v3oauth2mtlsclientcredential
    auth:
      auth_url: https://identity.example/v3
      client_id: client-id
      oauth2_endpoint: https://identity.example/OS-OAUTH2/token
      allow_reauth: true
`)),
	)
	if err != nil {
		t.Fatal(err)
	}

	opts, ok := cloudConfig.AuthOptions.(*oauth2mtls.AuthOptions)
	if !ok {
		t.Fatalf("unexpected auth options type: %T", cloudConfig.AuthOptions)
	}
	if opts.ClientID != "client-id" || opts.OAuth2Endpoint != "https://identity.example/OS-OAUTH2/token" {
		t.Fatalf("unexpected OAuth2 mTLS options: %#v", opts)
	}
	if !opts.AllowReauth {
		t.Fatal("AllowReauth was not preserved")
	}
}
