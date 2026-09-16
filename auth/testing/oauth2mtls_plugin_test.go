package testing

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/gophercloud/gophercloud/v2"
	"github.com/gophercloud/gophercloud/v2/auth"
	"github.com/gophercloud/gophercloud/v2/openstack"
	"github.com/gophercloud/gophercloud/v2/openstack/config"
	th "github.com/gophercloud/gophercloud/v2/testhelper"
)

func TestMTLSPluginUsesConfiguredCertificate(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			t.Error("missing client certificate")
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v3/OS-OAUTH2/token":
			fmt.Fprint(w, mtlsTokenResponse)
		case "/v3/auth/tokens":
			th.CheckEquals(t, mtlsTokenID, r.Header.Get("X-Subject-Token"))
			fmt.Fprint(w, mtlsValidateTokenResponse)
		case "/service":
			th.CheckEquals(t, "Bearer "+mtlsTokenID, r.Header.Get("Authorization"))
			th.CheckEquals(t, "", r.Header.Get("X-Auth-Token"))
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected path: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	server.TLS = &tls.Config{ClientAuth: tls.RequireAnyClientCert}
	server.StartTLS()
	defer server.Close()
	transport := server.Client().Transport.(*http.Transport).Clone()
	defer transport.CloseIdleConnections()
	transport.TLSClientConfig.Certificates = server.TLS.Certificates
	client := http.Client{Transport: transport}
	provider, err := config.NewProviderClient(context.Background(), &auth.V3OAuth2MTLSOpts{
		AuthURL: server.URL, ClientID: mtlsTestClientID,
	}, config.WithHTTPClient(client))
	th.AssertNoErr(t, err)
	_, err = provider.Request(context.Background(), http.MethodGet, server.URL+"/service", &gophercloud.RequestOpts{OkCodes: []int{http.StatusNoContent}})
	th.AssertNoErr(t, err)
	th.AssertEquals(t, int32(3), requests.Load())
}

const (
	mtlsTokenID       = "gAAAAABl-mTLS-token-abc123"
	mtlsTestClientID  = "6c3145f4-313d-4910-b3a8-9dfc72da9e75"
	mtlsTokenResponse = `{
		"access_token": "gAAAAABl-mTLS-token-abc123",
		"token_type": "Bearer",
		"expires_in": 3600
	}`
	mtlsValidateTokenResponse = `{
		"token": {
			"catalog": [{
				"type": "compute",
				"name": "nova",
				"endpoints": [{
					"interface": "public",
					"region": "iad1",
					"url": "http://127.0.0.1:8774/v2.1"
				}]
			}],
			"expires_at": "2030-06-15T18:00:00.000000Z"
		}
	}`
)

func TestAuthenticateV3UsesBearerToken(t *testing.T) {
	fakeServer := th.SetupHTTP()
	defer fakeServer.Teardown()

	fakeServer.Mux.HandleFunc("/v3/OS-OAUTH2/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, mtlsTokenResponse)
	})
	fakeServer.Mux.HandleFunc("/v3/auth/tokens", func(w http.ResponseWriter, r *http.Request) {
		th.TestHeader(t, r, "X-Auth-Token", mtlsTokenID)
		th.TestHeader(t, r, "X-Subject-Token", mtlsTokenID)
		w.Header().Set("X-Subject-Token", mtlsTokenID)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, mtlsValidateTokenResponse)
	})
	fakeServer.Mux.HandleFunc("/service", func(w http.ResponseWriter, r *http.Request) {
		th.TestHeader(t, r, "Authorization", "Bearer "+mtlsTokenID)
		th.TestHeaderUnset(t, r, "X-Auth-Token")
		w.WriteHeader(http.StatusNoContent)
	})

	provider, err := openstack.NewClient(fakeServer.Endpoint() + "v3/")
	th.AssertNoErr(t, err)
	th.AssertNoErr(t, openstack.Authenticate(context.Background(), provider, &auth.V3OAuth2MTLSOpts{
		AuthURL:  fakeServer.Endpoint(),
		ClientID: mtlsTestClientID,
	}))

	_, err = provider.Request(context.Background(), http.MethodGet, fakeServer.Endpoint()+"service", &gophercloud.RequestOpts{
		OkCodes: []int{http.StatusNoContent},
	})
	th.AssertNoErr(t, err)
}

func TestAuthenticateV3Reauthenticates(t *testing.T) {
	const refreshedToken = "refreshed-token"

	fakeServer := th.SetupHTTP()
	defer fakeServer.Teardown()

	var tokenRequests atomic.Int32
	fakeServer.Mux.HandleFunc("/v3/OS-OAUTH2/token", func(w http.ResponseWriter, r *http.Request) {
		token := mtlsTokenID
		if tokenRequests.Add(1) > 1 {
			token = refreshedToken
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"access_token":%q,"token_type":"Bearer"}`, token)
	})
	fakeServer.Mux.HandleFunc("/v3/auth/tokens", func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("X-Subject-Token")
		th.TestHeader(t, r, "X-Auth-Token", token)
		w.Header().Set("X-Subject-Token", token)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, mtlsValidateTokenResponse)
	})
	fakeServer.Mux.HandleFunc("/service", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+refreshedToken {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	provider, err := openstack.NewClient(fakeServer.Endpoint() + "v3/")
	th.AssertNoErr(t, err)
	th.AssertNoErr(t, openstack.Authenticate(context.Background(), provider, &auth.V3OAuth2MTLSOpts{
		AuthURL:     fakeServer.Endpoint(),
		ClientID:    mtlsTestClientID,
		AllowReauth: true,
	}))

	_, err = provider.Request(context.Background(), http.MethodGet, fakeServer.Endpoint()+"service", &gophercloud.RequestOpts{
		OkCodes: []int{http.StatusNoContent},
	})
	th.AssertNoErr(t, err)
	th.AssertEquals(t, int32(2), tokenRequests.Load())
}
