package clouds

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseV3SelectsAuthenticationMethod(t *testing.T) {
	t.Setenv("OS_AUTH_TYPE", "")
	for authType, method := range map[string]string{
		"": "token", "token": "token", "v3token": "token", "password": "password",
		"v3password": "password", "v3applicationcredential": "application_credential",
	} {
		t.Run(authType, func(t *testing.T) {
			cloud, err := ParseV3(WithCloudName("test"), WithCloudsYAML(strings.NewReader(`
clouds:
  test:
    auth_type: `+authType+`
    auth:
      auth_url: https://identity.example/v3
      token: restricted-token
      username: user
      password: password
      user_domain_id: default
      application_credential_id: app-id
      application_credential_secret: app-secret
`)))
			if err != nil {
				t.Fatal(err)
			}
			body, err := cloud.AuthOptions.ToTokenV3CreateMap(nil)
			if err != nil {
				t.Fatal(err)
			}
			identity := body["auth"].(map[string]any)["identity"].(map[string]any)
			if !reflect.DeepEqual(identity["methods"], []any{method}) {
				t.Fatalf("auth_type %s selected %v", authType, identity["methods"])
			}
		})
	}
}

func TestParseV3DoesNotFallBackFromMissingToken(t *testing.T) {
	t.Setenv("OS_TOKEN", "")
	t.Setenv("OS_AUTH_TOKEN", "")
	t.Setenv("OS_AUTH_TYPE", "")
	cloud, err := ParseV3(WithCloudName("test"), WithCloudsYAML(strings.NewReader(`
clouds:
  test:
    auth_type: v3token
    auth:
      auth_url: https://identity.example/v3
      username: user
      password: password
      user_domain_id: default
`)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cloud.AuthOptions.ToTokenV3CreateMap(nil); err == nil {
		t.Fatal("missing token must not fall back to password authentication")
	}
}
