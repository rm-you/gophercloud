package testing

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/gophercloud/gophercloud/v2/auth"
)

func TestDiscoveryUsesAuthenticationClientAndContext(t *testing.T) {
	for _, source := range []string{"cloud", "environment"} {
		t.Run(source, func(t *testing.T) {
			var calls atomic.Int32
			var server *httptest.Server
			server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/":
					fmt.Fprintf(w, `{"versions":{"values":[{"id":"v3.0","status":"stable","links":[{"rel":"self","href":%q}]}]}}`, server.URL+"/identity/v3/")
				case "/identity/v3/auth/tokens":
					w.Header().Set("X-Subject-Token", "discovered-token")
					w.WriteHeader(http.StatusCreated)
					fmt.Fprint(w, `{"token":{"user":{"id":"user"},"expires_at":"2099-01-01T00:00:00Z"}}`)
				default:
					t.Errorf("unexpected path: %s", r.URL.Path)
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer server.Close()
			var plugin auth.Authenticator
			var err error
			if source == "cloud" {
				plugin, err = auth.AuthOptionsFromCloud(cloudSource{authType: auth.AuthPassword, authData: map[string]any{
					"auth_url": server.URL, "user_id": "user", "password": "password",
				}})
			} else {
				t.Setenv("OS_AUTH_TYPE", "password")
				t.Setenv("OS_AUTH_URL", server.URL)
				t.Setenv("OS_USERID", "user")
				t.Setenv("OS_PASSWORD", "password")
				plugin, err = auth.AuthOptionsFromEnv()
			}
			if err != nil {
				t.Fatal(err)
			}
			if calls.Load() != 0 {
				t.Fatal("factory performed network I/O")
			}
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			if _, err = plugin.Authenticate(ctx, server.Client()); !errors.Is(err, context.Canceled) {
				t.Fatalf("expected cancellation, got %v", err)
			}
			result, err := plugin.Authenticate(context.Background(), server.Client())
			if err != nil {
				t.Fatal(err)
			}
			if result.TokenID != "discovered-token" || calls.Load() != 2 {
				t.Fatalf("result=%+v requests=%d", result, calls.Load())
			}
		})
	}
}
