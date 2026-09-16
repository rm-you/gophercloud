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

	result := authenticateOAuth2MTLS(context.Background(), mtlsNewClient(fakeServer), &V3OAuth2MTLSOpts{
		ClientID: mtlsTestClientID,
	})
	th.AssertNoErr(t, result.Err)

	token, err := result.ExtractTokenID()
	th.AssertNoErr(t, err)
	th.AssertEquals(t, mtlsTokenID, token)
	catalog, err := result.ExtractServiceCatalog()
	th.AssertNoErr(t, err)
	th.AssertEquals(t, 1, len(catalog.Entries))
}

func TestMTLSCreateUsesExplicitOAuth2Endpoint(t *testing.T) {
	fakeServer := th.SetupHTTP()
	defer fakeServer.Teardown()

	fakeServer.Mux.HandleFunc("/custom/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, mtlsTokenResponse)
	})
	mtlsHandleValidateTokenSuccessfully(t, fakeServer)

	result := authenticateOAuth2MTLS(context.Background(), mtlsNewClient(fakeServer), &V3OAuth2MTLSOpts{
		OAuth2Endpoint: fakeServer.Endpoint() + "custom/token",
		ClientID:       mtlsTestClientID,
	})
	th.AssertNoErr(t, result.Err)
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

	result := authenticateOAuth2MTLS(context.Background(), client, &V3OAuth2MTLSOpts{ClientID: mtlsTestClientID})
	th.AssertNoErr(t, result.Err)
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

			result := authenticateOAuth2MTLS(context.Background(), mtlsNewClient(fakeServer), &V3OAuth2MTLSOpts{ClientID: mtlsTestClientID})
			if result.Err == nil || !strings.Contains(result.Err.Error(), tt.err) {
				t.Fatalf("expected error containing %q, got %v", tt.err, result.Err)
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

			result := authenticateOAuth2MTLS(context.Background(), mtlsNewClient(fakeServer), &V3OAuth2MTLSOpts{ClientID: mtlsTestClientID})
			if !gophercloud.ResponseCodeIs(result.Err, status) {
				t.Fatalf("expected a %d response error, got %v", status, result.Err)
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

	result := authenticateOAuth2MTLS(context.Background(), mtlsNewClient(fakeServer), &V3OAuth2MTLSOpts{ClientID: mtlsTestClientID})
	if !gophercloud.ResponseCodeIs(result.Err, http.StatusUnauthorized) {
		t.Fatalf("expected a 401 response error, got %v", result.Err)
	}
}

func TestMTLSCreateValidatesInputs(t *testing.T) {
	client := &gophercloud.ServiceClient{ProviderClient: &gophercloud.ProviderClient{}}
	result := authenticateOAuth2MTLS(context.Background(), client, &V3OAuth2MTLSOpts{})
	var missing gophercloud.ErrMissingInput
	if !errors.As(result.Err, &missing) {
		t.Fatalf("expected ErrMissingInput, got %v", result.Err)
	}
	th.CheckEquals(t, "ClientID", missing.Argument)

	var opts *V3OAuth2MTLSOpts
	result = authenticateOAuth2MTLS(context.Background(), client, opts)
	if result.Err == nil {
		t.Fatal("expected typed nil options to fail")
	}

	result = authenticateOAuth2MTLS(context.Background(), nil, &V3OAuth2MTLSOpts{ClientID: mtlsTestClientID})
	if result.Err == nil {
		t.Fatal("expected nil client to fail")
	}
}
