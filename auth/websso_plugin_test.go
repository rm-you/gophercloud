package auth

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gophercloud/gophercloud/v2"
	"github.com/gophercloud/gophercloud/v2/auth/tokencache"
	th "github.com/gophercloud/gophercloud/v2/testhelper"
)

var _ Authenticator = (*V3WebSSOOpts)(nil)

func TestWebSSOPluginRescopesCachedToken(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		th.CheckEquals(t, "/v3/auth/tokens", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			th.CheckEquals(t, "unscoped", r.Header.Get("X-Subject-Token"))
			fmt.Fprint(w, `{"token":{"expires_at":"2099-01-01T00:00:00Z"}}`)
			return
		}
		th.TestMethod(t, r, http.MethodPost)
		th.TestJSONRequest(t, r, `{"auth":{"identity":{"methods":["token"],"token":{"id":"unscoped"}},"scope":{"project":{"id":"project"}}}}`)
		w.Header().Set("X-Subject-Token", "scoped")
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, `{"token":{"expires_at":"2099-01-01T00:00:00Z","project":{"id":"project"},"catalog":[{"type":"compute","endpoints":[{"interface":"public","url":"https://compute.example/"}]}]}}`)
	}))
	defer server.Close()
	opts := &V3WebSSOOpts{
		AuthURL: server.URL, IdentityProviderName: "idp", Protocol: "openid",
		AllowReauth: true, Scope: &Scope{ProjectID: "project"},
		TokenCache: newMemoryCache(), CacheNamespace: "personal",
		BrowserOpener: func(string) error { t.Fatal("unexpected browser on cache hit"); return nil },
	}
	endpoint := opts.GetAuthURL()
	tokencache.Persist(opts.TokenCache, WebSSOCacheKey(endpoint, opts), endpoint, "unscoped", time.Now().Add(time.Hour))
	result, err := opts.Authenticate(context.Background(), server.Client())
	th.AssertNoErr(t, err)
	th.AssertEquals(t, "scoped", result.TokenID)
	th.AssertEquals(t, true, result.CanReauth)
	th.AssertEquals(t, "project", result.Project.ID)
	endpoint, err = result.Endpoint(gophercloud.EndpointOpts{Type: "compute"})
	th.AssertNoErr(t, err)
	th.AssertEquals(t, "https://compute.example/", endpoint)
}
