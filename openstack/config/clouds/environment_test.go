package clouds

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/gophercloud/gophercloud/v2/openstack/identity/v3/oidc"
)

func TestParseV3EnvironmentCredentialsAndPrecedence(t *testing.T) {
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
				fields = "      username: cloud-user\n      password: cloud-password\n      user_domain_name: cloud-users\n      project_name: cloud-project\n      project_domain_name: cloud-projects\n"
			}
			opts := []ParseOption{WithCloudName("test"), WithCloudsYAML(strings.NewReader(`
clouds:
  test:
    auth_type: v3password
    auth:
      auth_url: https://identity.example/v3
` + fields))}
			if source == "options" {
				opts = append(opts, WithUsername("options-user"), WithPassword("options-password"), WithDomainName("options-domain"), WithProjectName("options-project"))
			}
			cloud, err := ParseV3(opts...)
			if err != nil {
				t.Fatal(err)
			}
			scope, err := cloud.AuthOptions.ToTokenV3ScopeMap()
			if err != nil {
				t.Fatal(err)
			}
			body, err := cloud.AuthOptions.ToTokenV3CreateMap(scope)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
			var request struct {
				Auth struct {
					Identity struct {
						Password struct {
							User struct {
								Name, Password string
								Domain         struct{ Name string }
							}
						}
					}
					Scope struct {
						Project struct {
							Name   string
							Domain struct{ Name string }
						}
					}
				}
			}
			if err := json.Unmarshal(raw, &request); err != nil {
				t.Fatal(err)
			}
			user, project := request.Auth.Identity.Password.User, request.Auth.Scope.Project
			userDomain, projectDomain := source+"-users", source+"-projects"
			if source == "options" {
				userDomain = "options-domain"
				projectDomain = "options-domain"
			}
			if user.Name != source+"-user" || user.Password != source+"-password" || user.Domain.Name != userDomain || project.Name != source+"-project" || project.Domain.Name != projectDomain {
				t.Fatalf("incorrect %s precedence: %s", source, raw)
			}
		})
	}
}

func TestParseV3FederatedScopeFromEnvironment(t *testing.T) {
	t.Setenv("OS_AUTH_TYPE", "")
	t.Setenv("OS_PROJECT_ID", "environment-project")
	cloud, err := ParseV3(WithCloudName("test"), WithCloudsYAML(strings.NewReader(`
clouds:
  test:
    auth_type: v3oidcclientcredentials
    auth:
      auth_url: https://identity.example/v3
      client_id: client
      client_secret: secret
      access_token_endpoint: https://idp.example/token
      identity_provider: idp
      protocol: openid
`)))
	if err != nil {
		t.Fatal(err)
	}
	opts, ok := cloud.AuthOptions.(*oidc.AuthOptions)
	if !ok {
		t.Fatalf("unexpected auth type %T", cloud.AuthOptions)
	}
	scope, err := opts.ToTokenV3ScopeMap()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(scope)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != `{"project":{"id":"environment-project"}}` {
		t.Fatalf("missing environment scope: %s", raw)
	}
}
