package testing

import (
	"testing"
	"time"

	"github.com/gophercloud/gophercloud/v2/auth"
	th "github.com/gophercloud/gophercloud/v2/testhelper"
)

func TestFederatedEnvironmentOptions(t *testing.T) {
	CleanupEnv(t)
	defer CleanupEnv(t)
	t.Setenv("OS_AUTH_URL", "https://identity.example/v3")
	t.Setenv("OS_IDENTITY_PROVIDER", "idp")
	t.Setenv("OS_PROTOCOL", "openid")
	t.Setenv("OS_PROJECT_ID", "project")
	t.Setenv("OS_CLIENT_ID", "client")
	t.Setenv("OS_CLIENT_SECRET", "secret")
	t.Setenv("OS_DISCOVERY_ENDPOINT", "https://idp.example/discovery")
	t.Setenv("OS_REDIRECT_PORT", "9991")
	for _, kind := range []auth.AuthType{auth.AuthV3WebSSO, auth.AuthV3OIDCClientCredentials, auth.AuthV3OAuth2MTLSClientCredential} {
		t.Run(string(kind), func(t *testing.T) {
			t.Setenv("OS_AUTH_TYPE", string(kind))
			plugin, err := auth.AuthOptionsFromEnv(auth.WithWebSSOTimeout(time.Minute), auth.WithTokenCacheNamespace("personal"))
			th.AssertNoErr(t, err)
			switch opts := plugin.(type) {
			case *auth.V3WebSSOOpts:
				th.AssertEquals(t, "idp", opts.IdentityProviderName)
				th.AssertEquals(t, 9991, opts.RedirectPort)
				th.AssertEquals(t, time.Minute, opts.Timeout)
				th.AssertEquals(t, "personal", opts.CacheNamespace)
				th.AssertEquals(t, "project", opts.Scope.ProjectID)
			case *auth.V3OIDCClientCredentialsOpts:
				th.AssertEquals(t, "client", opts.ClientID)
				th.AssertEquals(t, "secret", opts.ClientSecret)
				th.AssertEquals(t, "https://idp.example/discovery", opts.DiscoveryEndpoint)
				th.AssertEquals(t, "project", opts.Scope.ProjectID)
			case *auth.V3OAuth2MTLSOpts:
				th.AssertEquals(t, "client", opts.ClientID)
			default:
				t.Fatalf("unexpected plugin: %T", plugin)
			}
		})
	}
}

func TestEnvironmentUserIDAndScope(t *testing.T) {
	CleanupEnv(t)
	defer CleanupEnv(t)
	t.Setenv("OS_AUTH_URL", "https://identity.example/v3")
	t.Setenv("OS_AUTH_TYPE", "v3password")
	t.Setenv("OS_USER_ID", "user")
	t.Setenv("OS_PASSWORD", "secret")
	t.Setenv("OS_PROJECT_ID", "ignored")
	t.Setenv("OS_SYSTEM_SCOPE", "all")
	plugin, err := auth.AuthOptionsFromEnv()
	th.AssertNoErr(t, err)
	opts := plugin.(auth.AuthOptionsV3).Auth.(auth.V3PasswordOpts)
	th.AssertEquals(t, "user", opts.UserID)
	scope, err := opts.ToAuthScope()
	th.AssertNoErr(t, err)
	th.AssertJSONEquals(t, `{"system":{"all":true}}`, scope)
}
