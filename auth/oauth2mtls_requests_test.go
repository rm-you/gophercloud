package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/gophercloud/gophercloud/v2"
	th "github.com/gophercloud/gophercloud/v2/testhelper"
)

func mtlsNewClient(fakeServer th.FakeServer) *gophercloud.ServiceClient {
	return &gophercloud.ServiceClient{
		ProviderClient: &gophercloud.ProviderClient{},
		Endpoint:       fakeServer.Endpoint(),
	}
}

func TestMTLSCreate(t *testing.T) {
	fakeServer := th.SetupHTTP()
	defer fakeServer.Teardown()
	mtlsHandleTokenSuccessfully(t, fakeServer)
	mtlsHandleValidateTokenSuccessfully(t, fakeServer)

	result, err := authenticateOAuth2MTLS(context.Background(), mtlsNewClient(fakeServer), &V3OAuth2MTLSOpts{
		ClientID: mtlsTestClientID,
	})
	th.AssertNoErr(t, err)
	th.AssertEquals(t, mtlsTokenID, result.TokenID)
	th.AssertEquals(t, 1, len(result.Catalog.Entries))
}

func TestMTLSCreateUsesExplicitOAuth2Endpoint(t *testing.T) {
	fakeServer := th.SetupHTTP()
	defer fakeServer.Teardown()

	fakeServer.Mux.HandleFunc("/custom/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, mtlsTokenResponse)
	})
	mtlsHandleValidateTokenSuccessfully(t, fakeServer)

	_, err := authenticateOAuth2MTLS(context.Background(), mtlsNewClient(fakeServer), &V3OAuth2MTLSOpts{
		OAuth2Endpoint: fakeServer.Endpoint() + "custom/token",
		ClientID:       mtlsTestClientID,
	})
	th.AssertNoErr(t, err)
}

func TestMTLSCreateUsesProviderUserAgent(t *testing.T) {
	fakeServer := th.SetupHTTP()
	defer fakeServer.Teardown()

	userAgent := "oauth2mtls-test " + gophercloud.DefaultUserAgent
	fakeServer.Mux.HandleFunc("/OS-OAUTH2/token", func(w http.ResponseWriter, r *http.Request) {
		th.TestHeader(t, r, "User-Agent", userAgent)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, mtlsTokenResponse)
	})
	fakeServer.Mux.HandleFunc("/auth/tokens", func(w http.ResponseWriter, r *http.Request) {
		th.TestHeader(t, r, "User-Agent", userAgent)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, mtlsValidateTokenResponse)
	})
	client := mtlsNewClient(fakeServer)
	client.UserAgent.Prepend("oauth2mtls-test")

	_, err := authenticateOAuth2MTLS(context.Background(), client, &V3OAuth2MTLSOpts{ClientID: mtlsTestClientID})
	th.AssertNoErr(t, err)
}

func TestMTLSCreateRejectsInvalidResponses(t *testing.T) {
	tests := map[string]struct {
		response string
		err      string
	}{
		"invalid JSON":         {response: "not JSON", err: "invalid character"},
		"missing access token": {response: `{"token_type":"Bearer"}`, err: "missing access_token"},
		"unsupported type":     {response: `{"access_token":"token","token_type":"MAC"}`, err: "unsupported token_type"},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			fakeServer := th.SetupHTTP()
			defer fakeServer.Teardown()
			fakeServer.Mux.HandleFunc("/OS-OAUTH2/token", func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprint(w, tt.response)
			})

			_, err := authenticateOAuth2MTLS(context.Background(), mtlsNewClient(fakeServer), &V3OAuth2MTLSOpts{ClientID: mtlsTestClientID})
			if err == nil || !strings.Contains(err.Error(), tt.err) {
				t.Fatalf("expected error containing %q, got %v", tt.err, err)
			}
		})
	}
}

func TestMTLSCreateReturnsResponseErrors(t *testing.T) {
	for _, status := range []int{http.StatusBadRequest, http.StatusUnauthorized} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			fakeServer := th.SetupHTTP()
			defer fakeServer.Teardown()
			fakeServer.Mux.HandleFunc("/OS-OAUTH2/token", func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(status)
			})

			_, err := authenticateOAuth2MTLS(context.Background(), mtlsNewClient(fakeServer), &V3OAuth2MTLSOpts{ClientID: mtlsTestClientID})
			if !gophercloud.ResponseCodeIs(err, status) {
				t.Fatalf("expected a %d response error, got %v", status, err)
			}
		})
	}
}

func TestMTLSCreateReturnsValidationError(t *testing.T) {
	fakeServer := th.SetupHTTP()
	defer fakeServer.Teardown()
	mtlsHandleTokenSuccessfully(t, fakeServer)
	fakeServer.Mux.HandleFunc("/auth/tokens", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})

	_, err := authenticateOAuth2MTLS(context.Background(), mtlsNewClient(fakeServer), &V3OAuth2MTLSOpts{ClientID: mtlsTestClientID})
	if !gophercloud.ResponseCodeIs(err, http.StatusUnauthorized) {
		t.Fatalf("expected a 401 response error, got %v", err)
	}
}

func TestMTLSCreateValidatesInputs(t *testing.T) {
	client := &gophercloud.ServiceClient{ProviderClient: &gophercloud.ProviderClient{}}
	_, err := authenticateOAuth2MTLS(context.Background(), client, &V3OAuth2MTLSOpts{})
	var missing gophercloud.ErrMissingInput
	if !errors.As(err, &missing) {
		t.Fatalf("expected ErrMissingInput, got %v", err)
	}
	th.CheckEquals(t, "ClientID", missing.Argument)

	var opts *V3OAuth2MTLSOpts
	if _, err = opts.Authenticate(context.Background(), nil); err == nil {
		t.Fatal("expected typed nil options to fail")
	}
}
