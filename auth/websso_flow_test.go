package auth

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gophercloud/gophercloud/v2"
	th "github.com/gophercloud/gophercloud/v2/testhelper"
)

type webSSOResult struct {
	result *AuthResult
	err    error
}

func startWebSSO(t *testing.T, ctx context.Context, client *gophercloud.ServiceClient, opts *V3WebSSOOpts) <-chan webSSOResult {
	t.Helper()
	ready := make(chan struct{})
	opts.BrowserOpener = func(string) error {
		close(ready)
		return nil
	}
	results := make(chan webSSOResult, 1)
	go func() {
		result, err := authenticateWebSSO(ctx, client, opts)
		results <- webSSOResult{result, err}
	}()
	select {
	case <-ready:
	case result := <-results:
		t.Fatalf("authentication returned before opening the browser: %v", result.err)
	}
	return results
}

func TestWebSSOTokenValidationAccepts203(t *testing.T) {
	fakeKeystone := th.SetupHTTP()
	defer fakeKeystone.Teardown()

	fakeKeystone.Mux.HandleFunc("/auth/tokens", func(w http.ResponseWriter, r *http.Request) {
		th.TestMethod(t, r, http.MethodGet)
		th.TestHeader(t, r, "X-Subject-Token", unscopedTokenID)
		w.Header().Set("X-Subject-Token", unscopedTokenID)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNonAuthoritativeInfo)
		fmt.Fprint(w, federationAuthResponse())
	})

	client := gophercloud.ServiceClient{
		ProviderClient: &gophercloud.ProviderClient{},
		Endpoint:       fakeKeystone.Endpoint(),
	}
	port := findAvailablePort(t)
	results := startWebSSO(t, context.Background(), &client, &V3WebSSOOpts{
		IdentityProviderName: "my-idp",
		Protocol:             "openid",
		RedirectPort:         port,
		Timeout:              10 * time.Second,
	})

	response, err := http.DefaultClient.Do(newWebSSOCallbackRequest(t, fmt.Sprintf("http://127.0.0.1:%d/auth/websso/", port), url.Values{"token": {unscopedTokenID}}))
	th.AssertNoErr(t, err)
	response.Body.Close()

	result := <-results
	th.AssertNoErr(t, result.err)
}

func TestWebSSOTokenValidationFailurePreservesProviderToken(t *testing.T) {
	fakeKeystone := th.SetupHTTP()
	defer fakeKeystone.Teardown()

	fakeKeystone.Mux.HandleFunc("/auth/tokens", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "validation failed", http.StatusInternalServerError)
	})

	provider := newTestProviderClient()
	provider.SetToken("existing-token")
	client := gophercloud.ServiceClient{
		ProviderClient: provider,
		Endpoint:       fakeKeystone.Endpoint(),
	}
	port := findAvailablePort(t)
	results := startWebSSO(t, context.Background(), &client, &V3WebSSOOpts{
		IdentityProviderName: "my-idp",
		Protocol:             "openid",
		RedirectPort:         port,
		Timeout:              10 * time.Second,
	})

	response, err := http.DefaultClient.Do(newWebSSOCallbackRequest(t, fmt.Sprintf("http://127.0.0.1:%d/auth/websso/", port), url.Values{"token": {unscopedTokenID}}))
	th.AssertNoErr(t, err)
	response.Body.Close()

	result := <-results
	if result.err == nil {
		t.Fatal("expected token validation error")
	}
	if provider.TokenID != "existing-token" {
		t.Fatalf("provider token changed after validation failure: got %q", provider.TokenID)
	}
}

func TestWebSSOCallbackRejectsWrongMethod(t *testing.T) {
	port := findAvailablePort(t)

	client := gophercloud.ServiceClient{
		ProviderClient: &gophercloud.ProviderClient{},
		Endpoint:       "http://localhost/v3/",
	}

	opts := &V3WebSSOOpts{
		IdentityProviderName: "my-idp",
		Protocol:             "openid",
		RedirectPort:         port,
		Timeout:              3 * time.Second,
	}

	ctx, cancel := context.WithCancel(context.Background())
	startWebSSO(t, ctx, &client, opts)
	defer cancel()

	callbackURL := fmt.Sprintf("http://127.0.0.1:%d/auth/websso/", port)
	resp, err := http.Get(callbackURL) //nolint:gosec
	th.AssertNoErr(t, err)
	resp.Body.Close()
	th.CheckEquals(t, http.StatusMethodNotAllowed, resp.StatusCode)
}

func TestWebSSOCallbackIgnoresMissingTokenThenAcceptsValidToken(t *testing.T) {
	fakeKeystone := th.SetupHTTP()
	defer fakeKeystone.Teardown()

	handleWebSSOTokenValidation(t, fakeKeystone, unscopedTokenID)

	port := findAvailablePort(t)

	client := gophercloud.ServiceClient{
		ProviderClient: &gophercloud.ProviderClient{},
		Endpoint:       fakeKeystone.Endpoint(),
	}

	opts := &V3WebSSOOpts{
		IdentityProviderName: "my-idp",
		Protocol:             "openid",
		RedirectPort:         port,
		Timeout:              10 * time.Second,
	}

	results := startWebSSO(t, context.Background(), &client, opts)

	callbackURL := fmt.Sprintf("http://127.0.0.1:%d/auth/websso/", port)

	resp, err := http.DefaultClient.Do(newWebSSOCallbackRequest(t, callbackURL+"?token="+unscopedTokenID, nil))
	th.AssertNoErr(t, err)
	resp.Body.Close()
	th.CheckEquals(t, http.StatusBadRequest, resp.StatusCode)

	resp, err = http.DefaultClient.Do(newWebSSOCallbackRequest(t, callbackURL, url.Values{"nottoken": {"abc"}}))
	th.AssertNoErr(t, err)
	resp.Body.Close()
	th.CheckEquals(t, http.StatusBadRequest, resp.StatusCode)

	resp, err = http.DefaultClient.Do(newWebSSOCallbackRequest(t, callbackURL, url.Values{"token": {unscopedTokenID}}))
	th.AssertNoErr(t, err)
	resp.Body.Close()
	th.CheckEquals(t, http.StatusOK, resp.StatusCode)

	result := <-results
	th.AssertNoErr(t, result.err)
}

func TestWebSSOCancellationDoesNotWaitForSlowCallback(t *testing.T) {
	port := findAvailablePort(t)
	client := gophercloud.ServiceClient{
		ProviderClient: &gophercloud.ProviderClient{},
		Endpoint:       "http://localhost/v3/",
	}
	opts := &V3WebSSOOpts{
		IdentityProviderName: "my-idp",
		Protocol:             "openid",
		RedirectPort:         port,
		Timeout:              10 * time.Second,
	}

	ctx, cancel := context.WithCancel(context.Background())
	results := startWebSSO(t, ctx, &client, opts)
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	th.AssertNoErr(t, err)

	const slowRequest = "POST /auth/websso/ HTTP/1.1\r\n" +
		"Host: localhost\r\n" +
		"Content-Type: application/x-www-form-urlencoded\r\n" +
		"Content-Length: 1000\r\n" +
		"Sec-Fetch-Mode: navigate\r\n" +
		"Sec-Fetch-Dest: document\r\n" +
		"Sec-Fetch-Site: cross-site\r\n" +
		"Origin: null\r\n\r\n" +
		"token="
	_, err = fmt.Fprint(conn, slowRequest)
	th.AssertNoErr(t, err)
	select {
	case result := <-results:
		t.Fatalf("authentication returned before cancellation: %v", result.err)
	case <-time.After(50 * time.Millisecond):
	}
	cancel()

	select {
	case result := <-results:
		if result.err == nil || !strings.Contains(result.err.Error(), "cancelled") {
			t.Fatalf("expected cancellation error, got %v", result.err)
		}
	case <-time.After(500 * time.Millisecond):
		conn.Close()
		<-results
		t.Fatal("WebSSO cancellation waited for a slow callback connection")
	}
	conn.Close()
}

func TestWebSSOTimeout(t *testing.T) {
	client := gophercloud.ServiceClient{
		ProviderClient: &gophercloud.ProviderClient{},
		Endpoint:       "http://localhost/v3/",
	}

	port := findAvailablePort(t)
	opts := &V3WebSSOOpts{
		IdentityProviderName: "my-idp",
		Protocol:             "openid",
		RedirectPort:         port,
		Timeout:              500 * time.Millisecond,
		BrowserOpener:        func(string) error { return nil },
	}

	_, err := authenticateWebSSO(context.TODO(), &client, opts)
	if err == nil {
		t.Fatal("Expected timeout error")
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Errorf("Expected timeout error, got: %v", err)
	}
}

func TestWebSSOContextCancellation(t *testing.T) {
	client := gophercloud.ServiceClient{
		ProviderClient: &gophercloud.ProviderClient{},
		Endpoint:       "http://localhost/v3/",
	}

	port := findAvailablePort(t)
	ctx, cancel := context.WithCancel(context.Background())

	opts := &V3WebSSOOpts{
		IdentityProviderName: "my-idp",
		Protocol:             "openid",
		RedirectPort:         port,
		Timeout:              30 * time.Second,
	}

	results := startWebSSO(t, ctx, &client, opts)
	cancel()

	res := <-results
	if res.err == nil {
		t.Fatal("Expected cancellation error")
	}
	if !strings.Contains(res.err.Error(), "cancel") {
		t.Errorf("Expected cancellation error, got: %v", res.err)
	}
}

func TestWebSSOCallbackListensOnIPv6Loopback(t *testing.T) {
	probe, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skip("IPv6 loopback is unavailable")
	}
	probe.Close()

	fakeKeystone := th.SetupHTTP()
	defer fakeKeystone.Teardown()
	handleWebSSOTokenValidation(t, fakeKeystone, unscopedTokenID)

	port := findAvailablePort(t)
	results := startWebSSO(t, context.Background(), serviceClient(fakeKeystone.Endpoint()), &V3WebSSOOpts{
		IdentityProviderName: "my-idp",
		Protocol:             "openid",
		RedirectPort:         port,
		Timeout:              10 * time.Second,
	})
	response, err := http.DefaultClient.Do(newWebSSOCallbackRequest(t, fmt.Sprintf("http://[::1]:%d/auth/websso/", port), url.Values{"token": {unscopedTokenID}}))
	th.AssertNoErr(t, err)
	response.Body.Close()
	th.CheckEquals(t, http.StatusOK, response.StatusCode)

	result := <-results
	th.AssertNoErr(t, result.err)
}

func TestWebSSORejectsOccupiedIPv6Loopback(t *testing.T) {
	port := findAvailablePort(t)
	squatter, err := net.Listen("tcp", net.JoinHostPort("::1", strconv.Itoa(port)))
	if err != nil {
		t.Skip("IPv6 loopback is unavailable")
	}
	defer squatter.Close()

	_, err = authenticateWebSSO(context.Background(), serviceClient("http://identity.example/v3/"), &V3WebSSOOpts{
		IdentityProviderName: "my-idp",
		Protocol:             "openid",
		RedirectPort:         port,
		Timeout:              time.Second,
		BrowserOpener: func(string) error {
			t.Error("browser opened while another process listens on the callback port")
			return nil
		},
	})
	if err == nil || !strings.Contains(err.Error(), "callback server") {
		t.Fatalf("expected a callback listener error, got %v", err)
	}
}

func TestWebSSOCancelledContextDoesNotOpenBrowser(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := authenticateWebSSO(ctx, serviceClient("http://identity.example/v3/"), &V3WebSSOOpts{
		IdentityProviderName: "my-idp",
		Protocol:             "openid",
		RedirectPort:         findAvailablePort(t),
		BrowserOpener: func(string) error {
			t.Error("browser opened after cancellation")
			return nil
		},
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation, got %v", err)
	}
}
