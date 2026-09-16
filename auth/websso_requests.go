package auth

import (
	"context"
	"fmt"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gophercloud/gophercloud/v2"
	"github.com/gophercloud/gophercloud/v2/auth/tokencache"
	"github.com/gophercloud/gophercloud/v2/openstack/identity/v3/tokens"
)

const (
	defaultRedirectPort = 9990
	defaultTimeout      = 5 * time.Minute
)

// V3WebSSOOpts contains WebSSO authentication options.
type V3WebSSOOpts struct {
	// AuthURL is the Keystone identity endpoint.
	AuthURL string
	// IdentityProviderName is the Keystone federation identity provider.
	IdentityProviderName string `required:"true"`

	// Protocol is the Keystone federation protocol.
	Protocol string `required:"true"`

	// AllowReauth allows Gophercloud to reauthenticate automatically when the
	// token expires.
	AllowReauth bool

	// Scope controls the resulting Keystone token scope.
	Scope *Scope

	// RedirectHost is the loopback callback host. It defaults to localhost.
	RedirectHost string

	// RedirectPort is the callback listener port. It defaults to 9990.
	RedirectPort int

	// Timeout limits the browser flow. It defaults to five minutes.
	Timeout time.Duration

	// BrowserOpener opens the WebSSO URL. It defaults to the OS browser.
	BrowserOpener func(string) error `json:"-"`

	// TokenCache enables unscoped token reuse and requires CacheNamespace.
	TokenCache tokencache.Cache `json:"-"`

	// CacheNamespace identifies the expected browser login profile.
	CacheNamespace string
}

// WebSSOCacheKey returns the identity-isolated cache key for opts.
func WebSSOCacheKey(identityEndpoint string, opts *V3WebSSOOpts) string {
	return tokencache.Key(tokencache.KeyOptions{
		Flow:             "websso",
		Principal:        opts.CacheNamespace,
		IdentityEndpoint: identityEndpoint,
		IdentityProvider: opts.IdentityProviderName,
		Protocol:         opts.Protocol,
	})
}

// Authenticate performs browser-based WebSSO authentication.
func authenticateWebSSO(ctx context.Context, client *gophercloud.ServiceClient, opts *V3WebSSOOpts) (r tokens.CreateResult) {
	if opts == nil {
		r.Err = fmt.Errorf("websso: expected non-nil options")
		return
	}
	if err := opts.validate(); err != nil {
		r.Err = err
		return
	}
	if client == nil || client.ProviderClient == nil {
		r.Err = fmt.Errorf("websso: ServiceClient or ProviderClient is nil")
		return
	}
	scope, err := opts.Scope.ToScopeMap()
	if err != nil {
		r.Err = err
		return
	}

	var unscoped tokens.CreateResult
	var unscopedToken string
	haveUnscoped := false
	cacheKey := ""
	if opts.TokenCache != nil {
		cacheKey = WebSSOCacheKey(client.Endpoint, opts)
		cachedToken, ok := tokencache.Load(opts.TokenCache, cacheKey, client.Endpoint)
		if ok {
			cached := validateToken(ctx, client, cachedToken)
			if cached.Err == nil {
				unscoped = cached
				unscopedToken = cachedToken
				haveUnscoped = true
			} else if gophercloud.ResponseCodeIs(cached.Err, http.StatusUnauthorized) ||
				gophercloud.ResponseCodeIs(cached.Err, http.StatusNotFound) {
				_ = opts.TokenCache.Delete(cacheKey)
			} else {
				return cached
			}
		}
	}
	if !haveUnscoped {
		port := opts.RedirectPort
		if port == 0 {
			port = defaultRedirectPort
		}
		timeout := opts.Timeout
		if timeout == 0 {
			timeout = defaultTimeout
		}

		unscopedToken, err = captureToken(ctx, client, opts, port, timeout)
		if err != nil {
			r.Err = err
			return
		}
		unscoped = validateToken(ctx, client, unscopedToken)
		if unscoped.Err != nil {
			return unscoped
		}
		if opts.TokenCache != nil {
			token, err := unscoped.ExtractToken()
			if err == nil && token != nil {
				tokencache.Persist(opts.TokenCache, cacheKey, client.Endpoint, unscopedToken, token.ExpiresAt)
			}
		}
	}

	if scope == nil {
		return unscoped
	}
	rescope := AuthOptionsV3{AuthURL: client.Endpoint, Auth: V3RescopeTokenOpts{Token: unscopedToken, Scope: opts.Scope}}
	r.Result, r.Err = rescope.create(ctx, &client.HTTPClient)
	return r
}

func validateToken(ctx context.Context, client *gophercloud.ServiceClient, tokenID string) (r tokens.CreateResult) {
	validationClient := *client
	validationClient.ProviderClient = &gophercloud.ProviderClient{
		TokenID:           tokenID,
		HTTPClient:        client.HTTPClient,
		UserAgent:         client.UserAgent,
		RetryBackoffFunc:  client.RetryBackoffFunc,
		MaxBackoffRetries: client.MaxBackoffRetries,
		RetryFunc:         client.RetryFunc,
	}
	result := tokens.Get(ctx, &validationClient, tokenID, nil)
	r.Body = result.Body
	r.Header = result.Header
	r.Err = result.Err
	if r.Err == nil {
		r.Header.Set("X-Subject-Token", tokenID)
	}
	return
}

func (opts *V3WebSSOOpts) validate() error {
	if _, err := gophercloud.BuildRequestBody(opts, ""); err != nil {
		return err
	}
	if opts.RedirectPort < 0 || opts.RedirectPort > 65535 {
		return fmt.Errorf("websso: RedirectPort must be 0 or between 1 and 65535")
	}
	if opts.Timeout < 0 {
		return fmt.Errorf("websso: Timeout must not be negative")
	}
	if opts.TokenCache != nil && opts.CacheNamespace == "" {
		return fmt.Errorf("websso: CacheNamespace is required when TokenCache is enabled")
	}
	if opts.RedirectHost != "" && opts.RedirectHost != "localhost" {
		ip := net.ParseIP(opts.RedirectHost)
		if ip == nil || !ip.IsLoopback() {
			return fmt.Errorf("websso: RedirectHost must be a loopback address")
		}
	}
	return nil
}

func captureToken(ctx context.Context, client *gophercloud.ServiceClient, opts *V3WebSSOOpts, port int, timeout time.Duration) (string, error) {
	const callbackPath = "/auth/websso/"
	keystoneOrigin, err := endpointOrigin(client.Endpoint)
	if err != nil {
		return "", fmt.Errorf("websso: invalid identity endpoint: %w", err)
	}
	host := opts.RedirectHost
	if host == "" {
		host = "localhost"
	}
	origin := "http://" + net.JoinHostPort(host, fmt.Sprintf("%d", port)) + callbackPath
	webSSOURL := webSSOAuthURL(client, opts.IdentityProviderName, opts.Protocol) + "?origin=" + url.QueryEscape(origin)

	tokenCh := make(chan string, 1)
	errCh := make(chan error, 1)
	var accepted atomic.Bool
	mux := http.NewServeMux()
	mux.HandleFunc(callbackPath, func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path != callbackPath {
			http.NotFound(w, request)
			return
		}
		if request.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
		if err != nil || mediaType != "application/x-www-form-urlencoded" {
			http.Error(w, "Unsupported Content-Type", http.StatusUnsupportedMediaType)
			return
		}
		if !validCallbackContext(request, keystoneOrigin) {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}
		request.Body = http.MaxBytesReader(w, request.Body, 64<<10)
		if err := request.ParseForm(); err != nil {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}
		token := request.PostFormValue("token")
		if token == "" {
			http.Error(w, "Missing token", http.StatusBadRequest)
			return
		}
		if !accepted.CompareAndSwap(false, true) {
			http.Error(w, "Token already received", http.StatusConflict)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "<html><body><script>window.close()</script><h2>Authentication successful</h2><p>You may close this window.</p></body></html>")
		tokenCh <- token
	})

	listener, err := net.Listen("tcp", net.JoinHostPort(host, fmt.Sprintf("%d", port)))
	if err != nil {
		return "", fmt.Errorf("websso: failed to start callback server on %s: %w", net.JoinHostPort(host, fmt.Sprintf("%d", port)), err)
	}
	if !isLoopbackAddr(listener.Addr()) {
		_ = listener.Close()
		return "", fmt.Errorf("websso: callback listener is not bound to a loopback address")
	}
	server := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	go func() {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			errCh <- fmt.Errorf("websso: callback server error: %w", err)
		}
	}()
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			_ = server.Close()
		}
	}()

	opener := opts.BrowserOpener
	if opener == nil {
		opener = openBrowser
	}
	if err := opener(webSSOURL); err != nil {
		return "", fmt.Errorf("websso: failed to open browser: %w", err)
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case token := <-tokenCh:
		return token, nil
	case err := <-errCh:
		return "", err
	case <-timer.C:
		return "", fmt.Errorf("websso: authentication timed out after %s", timeout)
	case <-ctx.Done():
		return "", fmt.Errorf("websso: authentication cancelled: %w", ctx.Err())
	}
}

func endpointOrigin(rawURL string) (string, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return "", fmt.Errorf("url must include a scheme and host")
	}
	return strings.ToLower(parsed.Scheme + "://" + parsed.Host), nil
}

func validCallbackContext(request *http.Request, keystoneOrigin string) bool {
	if request.Header.Get("Sec-Fetch-Mode") != "navigate" ||
		request.Header.Get("Sec-Fetch-Dest") != "document" ||
		request.Header.Get("Sec-Fetch-Site") == "none" {
		return false
	}

	origin := request.Header.Get("Origin")
	if origin != "" && origin != "null" && !sameOrigin(origin, keystoneOrigin) {
		return false
	}
	referer := request.Header.Get("Referer")
	return referer == "" || sameOrigin(referer, keystoneOrigin)
}

func isLoopbackAddr(addr net.Addr) bool {
	tcpAddr, ok := addr.(*net.TCPAddr)
	return ok && tcpAddr.IP.IsLoopback()
}

func sameOrigin(rawURL, expected string) bool {
	origin, err := endpointOrigin(rawURL)
	return err == nil && origin == expected
}

func openBrowser(target string) error {
	var command *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		command = exec.Command("open", target)
	case "linux":
		command = exec.Command("xdg-open", target)
	case "windows":
		command = exec.Command("rundll32", "url.dll,FileProtocolHandler", target)
	default:
		return fmt.Errorf("unsupported operating system %q", runtime.GOOS)
	}
	if err := command.Start(); err != nil {
		return err
	}
	go func() {
		_ = command.Wait()
	}()
	return nil
}

// GetAuthURL returns the versioned Keystone endpoint.
func (opts *V3WebSSOOpts) GetAuthURL() string {
	return (AuthOptionsV3{AuthURL: opts.AuthURL}).GetAuthURL()
}

// Authenticate opens the browser when no reusable unscoped token is available.
func (opts *V3WebSSOOpts) Authenticate(ctx context.Context, httpClient *http.Client) (*AuthResult, error) {
	if opts == nil {
		return nil, fmt.Errorf("websso: expected non-nil options")
	}
	if opts.AuthURL == "" {
		return nil, gophercloud.ErrMissingInput{Argument: "AuthURL"}
	}
	client := &gophercloud.ServiceClient{ProviderClient: &gophercloud.ProviderClient{}, Endpoint: opts.GetAuthURL()}
	if httpClient != nil {
		client.HTTPClient = *httpClient
	}
	result := authenticateWebSSO(ctx, client, opts)
	return v3AuthResult(result.Result, opts.AllowReauth)
}
