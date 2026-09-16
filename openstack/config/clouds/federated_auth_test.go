package clouds_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/gophercloud/gophercloud/v2"
	"github.com/gophercloud/gophercloud/v2/auth"
	"github.com/gophercloud/gophercloud/v2/openstack/config/clouds"
	th "github.com/gophercloud/gophercloud/v2/testhelper"
)

type federatedCache struct{}

func (federatedCache) Get(string) (string, error) { return "", nil }
func (federatedCache) Set(string, string) error   { return nil }
func (federatedCache) Delete(string) error        { return nil }

func parseFederatedCloud(t *testing.T, kind, fields string) clouds.Cloud {
	t.Helper()
	cloud, endpoint, _, err := clouds.Parse(
		clouds.WithCloudName("personal"),
		clouds.WithCloudsYAML(strings.NewReader(fmt.Sprintf(`
clouds:
  personal:
    auth_type: %s
    region_name: RegionOne
    identity_provider: top-level-idp
    protocol: saml2
    auth: {auth_url: "https://identity.example/v3", %s}
`, kind, fields))),
	)
	th.AssertNoErr(t, err)
	th.AssertEquals(t, "RegionOne", endpoint.Region)
	return cloud
}

func TestFederatedCloudSettings(t *testing.T) {
	t.Setenv("OS_AUTH_TYPE", "")
	cloud := parseFederatedCloud(t, "v3websso", "redirect_host: '::1', redirect_port: 9991, project_id: project")
	openerError := errors.New("browser hook")
	plugin, err := cloud.ToAuthOptions(
		auth.WithTokenCache(federatedCache{}), auth.WithWebSSOTimeout(time.Minute),
		auth.WithWebSSOBrowserOpener(func(string) error { return openerError }),
	)
	th.AssertNoErr(t, err)
	websso := plugin.(*auth.V3WebSSOOpts)
	th.AssertEquals(t, "top-level-idp", websso.IdentityProviderName)
	th.AssertEquals(t, "saml2", websso.Protocol)
	th.AssertEquals(t, "::1", websso.RedirectHost)
	th.AssertEquals(t, 9991, websso.RedirectPort)
	th.AssertEquals(t, "personal", websso.CacheNamespace)
	th.AssertEquals(t, time.Minute, websso.Timeout)
	th.AssertEquals(t, "project", websso.Scope.ProjectID)
	th.AssertEquals(t, true, websso.AllowReauth)
	th.AssertEquals(t, openerError, websso.BrowserOpener(""))
	if websso.TokenCache == nil {
		t.Fatal("missing cache")
	}
	plugin, err = cloud.ToAuthOptions(auth.WithTokenCacheNamespace("shared-login"))
	th.AssertNoErr(t, err)
	th.AssertEquals(t, "shared-login", plugin.(*auth.V3WebSSOOpts).CacheNamespace)

	cloud = parseFederatedCloud(t, "v3oidcclientcredentials", `client_id: client, client_secret: secret, discovery_endpoint: "https://idp.example/discovery", access_token_endpoint: "https://idp.example/token", identity_provider: nested-idp, protocol: openid, access_token_type: id_token, openid_scope: custom, project_name: project, project_domain_name: projects, allow_reauth: false`)
	plugin, err = cloud.ToAuthOptions()
	th.AssertNoErr(t, err)
	oidc := plugin.(*auth.V3OIDCClientCredentialsOpts)
	th.AssertEquals(t, "client", oidc.ClientID)
	th.AssertEquals(t, "secret", oidc.ClientSecret)
	th.AssertEquals(t, "https://idp.example/discovery", oidc.DiscoveryEndpoint)
	th.AssertEquals(t, "https://idp.example/token", oidc.AccessTokenEndpoint)
	th.AssertEquals(t, "nested-idp", oidc.IdentityProviderName)
	th.AssertEquals(t, "openid", oidc.Protocol)
	th.AssertEquals(t, "id_token", oidc.AccessTokenType)
	th.AssertEquals(t, "custom", oidc.OIDCScope)
	th.AssertEquals(t, false, oidc.AllowReauth)
	th.AssertEquals(t, "projects", oidc.Scope.ProjectDomainName)

	cloud = parseFederatedCloud(t, "v3oauth2mtlsclientcredential", `oauth2_client_id: certificate-user, client_id: fallback, oauth2_endpoint: "https://identity.example/custom"`)
	plugin, err = cloud.ToAuthOptions()
	th.AssertNoErr(t, err)
	mtls := plugin.(*auth.V3OAuth2MTLSOpts)
	th.AssertEquals(t, "certificate-user", mtls.ClientID)
	th.AssertEquals(t, "https://identity.example/custom", mtls.OAuth2Endpoint)
	th.AssertEquals(t, true, mtls.AllowReauth)
}

func pluginScope(t *testing.T, plugin auth.Authenticator) *auth.Scope {
	t.Helper()
	switch p := plugin.(type) {
	case *auth.V3WebSSOOpts:
		return p.Scope
	case *auth.V3OIDCClientCredentialsOpts:
		return p.Scope
	case auth.AuthOptionsV3:
		switch opts := p.Auth.(type) {
		case auth.V3PasswordOpts:
			return opts.Scope
		case auth.V3TokenOpts:
			return opts.Scope
		}
	}
	t.Fatalf("unexpected plugin: %T", plugin)
	return nil
}

func TestFederatedScopeOverridesAndPrecedence(t *testing.T) {
	t.Setenv("OS_AUTH_TYPE", "")
	for _, kind := range []string{"v3password", "v3token", "v3websso", "v3oidcclientcredentials"} {
		for _, test := range []struct {
			name, fields, environment string
			options                   []auth.CloudOption
			want                      map[string]any
			fail                      bool
			scopeError                bool
		}{
			{name: "system", fields: "system_scope: all, project_id: ignored", want: map[string]any{"system": map[string]any{"all": true}}},
			{name: "invalid system", fields: "system_scope: admin, project_id: project", fail: true},
			{name: "environment system", environment: "all", want: map[string]any{"system": map[string]any{"all": true}}},
			{name: "invalid environment", environment: "admin", fail: true},
			{name: "explicit", fields: "system_scope: admin", options: []auth.CloudOption{auth.WithScope(&auth.Scope{System: true})}, want: map[string]any{"system": map[string]any{"all": true}}},
			{name: "project override", fields: "project_id: cloud", options: []auth.CloudOption{auth.WithProjectID("override")}, want: map[string]any{"project": map[string]any{"id": "override"}}},
			{name: "project name override", fields: "project_domain_name: domain", options: []auth.CloudOption{auth.WithProjectName("project")}, want: map[string]any{"project": map[string]any{"name": "project", "domain": map[string]any{"name": "domain"}}}},
			{name: "domain", fields: "user_domain_name: users, domain_id: scope-domain", want: map[string]any{"domain": map[string]any{"id": "scope-domain"}}},
			{name: "conflicting scopes", fields: "project_id: project, domain_id: domain", scopeError: true},
		} {
			t.Run(kind+"/"+test.name, func(t *testing.T) {
				t.Setenv("OS_SYSTEM_SCOPE", test.environment)
				cloud := parseFederatedCloud(t, kind, test.fields)
				plugin, err := cloud.ToAuthOptions(test.options...)
				if test.fail {
					if err == nil {
						t.Fatal("expected invalid system scope")
					}
					return
				}
				th.AssertNoErr(t, err)
				scope, err := pluginScope(t, plugin).ToScopeMap()
				if test.scopeError {
					var conflict gophercloud.ErrProjectScopeAndDomainScope
					if !errors.As(err, &conflict) {
						t.Fatalf("expected conflicting scopes, got %v", err)
					}
					return
				}
				th.AssertNoErr(t, err)
				expected, err := json.Marshal(test.want)
				th.AssertNoErr(t, err)
				th.AssertJSONEquals(t, string(expected), scope)
			})
		}
	}
}

func TestCloudCredentialsOverrideEnvironment(t *testing.T) {
	t.Setenv("OS_AUTH_TYPE", "")
	t.Setenv("OS_USERNAME", "environment-user")
	t.Setenv("OS_PASSWORD", "environment-password")
	t.Setenv("OS_USER_DOMAIN_NAME", "environment-users")
	t.Setenv("OS_PROJECT_NAME", "environment-project")
	t.Setenv("OS_PROJECT_DOMAIN_NAME", "environment-projects")
	for _, source := range []string{"environment", "cloud", "options"} {
		t.Run(source, func(t *testing.T) {
			fields := ""
			if source != "environment" {
				fields = "username: cloud-user, password: cloud-password, user_domain_name: cloud-users, project_name: cloud-project, project_domain_name: cloud-projects"
			}
			cloud := parseFederatedCloud(t, "v3password", fields)
			var options []auth.CloudOption
			if source == "options" {
				options = []auth.CloudOption{auth.WithUsername("options-user"), auth.WithPassword("options-password"), auth.WithProjectName("options-project")}
			}
			plugin, err := cloud.ToAuthOptions(options...)
			th.AssertNoErr(t, err)
			opts := plugin.(auth.AuthOptionsV3).Auth.(auth.V3PasswordOpts)
			th.AssertEquals(t, source+"-user", opts.Username)
			th.AssertEquals(t, source+"-password", opts.Password)
			th.AssertEquals(t, source+"-project", opts.Scope.ProjectName)
			userDomain, projectDomain := source+"-users", source+"-projects"
			if source == "options" {
				userDomain, projectDomain = "cloud-users", "cloud-projects"
			}
			th.AssertEquals(t, userDomain, opts.UserDomainName)
			th.AssertEquals(t, projectDomain, opts.Scope.ProjectDomainName)
		})
	}
}

func TestPasswordUserDomainDoesNotAuthorizeDomain(t *testing.T) {
	t.Setenv("OS_AUTH_TYPE", "")
	cloud := parseFederatedCloud(t, "v3password", "username: user, password: secret, user_domain_name: users")
	plugin, err := cloud.ToAuthOptions()
	th.AssertNoErr(t, err)
	opts := plugin.(auth.AuthOptionsV3).Auth.(auth.V3PasswordOpts)
	th.AssertEquals(t, "users", opts.UserDomainName)
	scope, err := opts.ToAuthScope()
	th.AssertNoErr(t, err)
	if scope != nil {
		t.Fatalf("unexpected authorization scope: %#v", scope)
	}
}

func TestWebSSORedirectPortValidation(t *testing.T) {
	t.Setenv("OS_AUTH_TYPE", "")
	for _, port := range []string{"-1", "65536", "abc", "1.5"} {
		t.Run(port, func(t *testing.T) {
			cloud := parseFederatedCloud(t, "v3websso", "redirect_port: "+port)
			_, err := cloud.ToAuthOptions()
			if err == nil {
				t.Fatal("expected invalid redirect port")
			}
		})
	}
}
