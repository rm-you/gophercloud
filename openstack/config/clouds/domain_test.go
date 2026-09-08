package clouds

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestParseV3DefaultDomainIsFallback(t *testing.T) {
	t.Setenv("OS_AUTH_TYPE", "")
	for _, named := range []bool{false, true} {
		name := "default"
		extra := ""
		if named {
			name = "named"
			extra = "      user_domain_name: users\n      project_domain_name: projects\n"
		}
		t.Run(name, func(t *testing.T) {
			cloud, err := ParseV3(WithCloudName("test"), WithCloudsYAML(strings.NewReader(`
clouds:
  test:
    auth_type: v3password
    auth:
      auth_url: https://identity.example/v3
      username: user
      password: password
      project_name: project
      default_domain: default
`+extra)))
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
							User struct{ Domain map[string]string }
						}
					}
					Scope struct {
						Project struct{ Domain map[string]string }
					}
				}
			}
			if err := json.Unmarshal(raw, &request); err != nil {
				t.Fatal(err)
			}
			userDomain, projectDomain := request.Auth.Identity.Password.User.Domain, request.Auth.Scope.Project.Domain
			if named {
				if userDomain["name"] != "users" || projectDomain["name"] != "projects" || userDomain["id"] != "" || projectDomain["id"] != "" {
					t.Fatalf("named domains replaced: %s", raw)
				}
			} else if userDomain["id"] != "default" || projectDomain["id"] != "default" {
				t.Fatalf("default domains missing: %s", raw)
			}
		})
	}
}
