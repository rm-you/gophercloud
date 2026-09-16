package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/gophercloud/gophercloud/v2"
	th "github.com/gophercloud/gophercloud/v2/testhelper"
)

func TestOIDCRedirects(t *testing.T) {
	for _, tt := range []struct {
		name, redirect    string
		discovery, reject bool
	}{
		{"token same origin", "relative", false, false},
		{"token different origin", "https", false, true},
		{"token downgrade", "http", false, true},
		{"discovery same origin", "relative", true, false},
		{"discovery downgrade", "http", true, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var targetRequests atomic.Int32
			other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				targetRequests.Add(1)
				fmt.Fprint(w, `{"access_token":"token","token_type":"Bearer"}`)
			}))
			defer other.Close()
			plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				targetRequests.Add(1)
				fmt.Fprint(w, `{}`)
			}))
			defer plain.Close()
			var source *httptest.Server
			source = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/metadata":
					fmt.Fprintf(w, `{"token_endpoint":%q}`, source.URL+"/token")
				case "/discovery", "/token":
					location := r.URL.Path + "-final"
					if tt.redirect == "https" {
						location = other.URL
					}
					if tt.redirect == "http" {
						location = plain.URL
					}
					http.Redirect(w, r, location, http.StatusTemporaryRedirect)
				case "/discovery-final":
					fmt.Fprintf(w, `{"token_endpoint":%q}`, source.URL+"/token-final")
				case "/token-final":
					user, password, ok := r.BasicAuth()
					th.CheckEquals(t, true, ok)
					th.CheckEquals(t, "client", user)
					th.CheckEquals(t, "secret", password)
					th.TestMethod(t, r, http.MethodPost)
					th.AssertNoErr(t, r.ParseForm())
					th.CheckEquals(t, "client_credentials", r.Form.Get("grant_type"))
					fmt.Fprint(w, `{"access_token":"token","token_type":"Bearer"}`)
				}
			}))
			defer source.Close()
			c := &gophercloud.ServiceClient{ProviderClient: &gophercloud.ProviderClient{HTTPClient: *source.Client()}}
			opts := &V3OIDCClientCredentialsOpts{ClientID: "client", ClientSecret: "secret"}
			opts.DiscoveryEndpoint = source.URL + "/metadata"
			if tt.discovery {
				opts.DiscoveryEndpoint = source.URL + "/discovery"
			}
			endpoint, err := resolveAccessTokenEndpoint(context.Background(), c, opts)
			if err == nil {
				_, err = fetchAccessToken(context.Background(), c, opts, endpoint)
			}
			if tt.reject && err == nil {
				t.Error("unsafe redirect was accepted")
			}
			if !tt.reject {
				th.CheckNoErr(t, err)
			}
			th.CheckEquals(t, int32(0), targetRequests.Load())
			if c.HTTPClient.CheckRedirect != nil {
				t.Error("provider redirect policy was modified")
			}
		})
	}
}

func TestOIDCPreservesCallerRedirectPolicy(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/again", http.StatusTemporaryRedirect)
	}))
	defer server.Close()
	want := errors.New("caller rejected redirect")
	c := &gophercloud.ServiceClient{ProviderClient: &gophercloud.ProviderClient{HTTPClient: http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return want },
	}}}
	_, err := fetchAccessToken(context.Background(), c, &V3OIDCClientCredentialsOpts{ClientID: "client", ClientSecret: "secret"}, server.URL)
	if !errors.Is(err, want) {
		t.Fatalf("expected caller's error, got %v", err)
	}
}
