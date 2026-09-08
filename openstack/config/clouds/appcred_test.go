package clouds

import (
	"strings"
	"testing"

	"github.com/gophercloud/gophercloud/v2"
)

func TestParseV3ApplicationCredentialHasImplicitScope(t *testing.T) {
	t.Setenv("OS_AUTH_TYPE", "")
	for name, fields := range map[string]string{
		"ID":   "      application_credential_id: app-id\n",
		"name": "      application_credential_name: app-name\n      username: user\n      user_domain_id: default\n",
	} {
		t.Run(name, func(t *testing.T) {
			for _, explicit := range []bool{false, true} {
				options := []ParseOption{WithCloudName("test"), WithCloudsYAML(strings.NewReader(`
clouds:
  test:
    auth_type: v3applicationcredential
    auth:
      auth_url: https://identity.example/v3
      project_id: project
      application_credential_secret: secret
` + fields))}
				if explicit {
					options = append(options, WithScope(&gophercloud.AuthScope{ProjectID: "override"}))
				}
				cloud, err := ParseV3(options...)
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
				if _, ok := body["auth"].(map[string]any)["scope"]; ok {
					t.Fatalf("application credential sent an explicit scope (WithScope=%t)", explicit)
				}
			}
		})
	}
}
