package testing

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/gophercloud/gophercloud/v2"
	"github.com/gophercloud/gophercloud/v2/auth"
	"github.com/gophercloud/gophercloud/v2/openstack/config"
	th "github.com/gophercloud/gophercloud/v2/testhelper"
)

var _ auth.Authenticator = (*auth.V3OIDCClientCredentialsOpts)(nil)

func TestOIDCPluginRefreshesScopedToken(t *testing.T) {
	var logins atomic.Int32
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/discovery":
			fmt.Fprintf(w, `{"token_endpoint":%q,"grant_types_supported":["client_credentials"]}`, server.URL+"/idp")
		case "/idp":
			th.TestMethod(t, r, http.MethodPost)
			th.AssertNoErr(t, r.ParseForm())
			th.CheckEquals(t, "client_credentials", r.Form.Get("grant_type"))
			th.CheckEquals(t, "client", r.Form.Get("client_id"))
			logins.Add(1)
			fmt.Fprint(w, `{"access_token":"idp-token","token_type":"Bearer"}`)
		case "/v3/OS-FEDERATION/identity_providers/idp/protocols/openid/auth":
			th.CheckEquals(t, "Bearer idp-token", r.Header.Get("Authorization"))
			w.Header().Set("X-Subject-Token", "unscoped")
			w.WriteHeader(http.StatusCreated)
			fmt.Fprint(w, `{"token":{"expires_at":"2099-01-01T00:00:00Z"}}`)
		case "/v3/auth/tokens":
			th.TestJSONRequest(t, r, `{"auth":{"identity":{"methods":["token"],"token":{"id":"unscoped"}},"scope":{"project":{"id":"project"}}}}`)
			w.Header().Set("X-Subject-Token", fmt.Sprintf("scoped-%d", logins.Load()))
			w.WriteHeader(http.StatusCreated)
			fmt.Fprintf(w, `{"token":{"project":{"id":"project"},"catalog":[{"type":"compute","endpoints":[{"interface":"public","url":%q}]}]}}`, server.URL+"/service/")
		case "/service/":
			if r.Header.Get("X-Auth-Token") != "scoped-2" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected path: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	opts := &auth.V3OIDCClientCredentialsOpts{
		AuthURL: server.URL, IdentityProviderName: "idp", Protocol: "openid",
		ClientID: "client", DiscoveryEndpoint: server.URL + "/discovery",
		Scope: &auth.Scope{ProjectID: "project"}, AllowReauth: true,
	}
	ctx := context.Background()
	provider, err := config.NewProviderClient(ctx, opts, config.WithHTTPClient(*server.Client()))
	th.AssertNoErr(t, err)
	endpoint, err := provider.EndpointLocator(ctx, gophercloud.EndpointOpts{Type: "compute"})
	th.AssertNoErr(t, err)
	_, err = provider.Request(ctx, http.MethodGet, endpoint, &gophercloud.RequestOpts{OkCodes: []int{http.StatusNoContent}})
	th.AssertNoErr(t, err)
	th.AssertEquals(t, int32(2), logins.Load())
	th.AssertEquals(t, "scoped-2", provider.Token())
}
