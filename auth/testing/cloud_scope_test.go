package testing

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/gophercloud/gophercloud/v2/auth"
	th "github.com/gophercloud/gophercloud/v2/testhelper"
)

func TestLoadedPasswordScope(t *testing.T) {
	tests := []struct {
		name      string
		data      map[string]string
		options   []auth.CloudOption
		wantUser  string
		wantScope string
	}{
		{
			name:      "domain ID",
			data:      map[string]string{"user_domain_id": "user-domain", "domain_id": "scope-domain"},
			wantUser:  `{"name":"user","password":"secret","domain":{"id":"user-domain"}}`,
			wantScope: `{"domain":{"id":"scope-domain"}}`,
		},
		{
			name:      "domain name",
			data:      map[string]string{"user_domain_name": "UserDomain", "domain_name": "ScopeDomain"},
			wantUser:  `{"name":"user","password":"secret","domain":{"name":"UserDomain"}}`,
			wantScope: `{"domain":{"name":"ScopeDomain"}}`,
		},
		{
			name:      "domain ID with user domain name",
			data:      map[string]string{"user_domain_name": "UserDomain", "domain_id": "scope-domain"},
			wantUser:  `{"name":"user","password":"secret","domain":{"name":"UserDomain"}}`,
			wantScope: `{"domain":{"id":"scope-domain"}}`,
		},
		{
			name:      "domain name with user domain ID",
			data:      map[string]string{"user_domain_id": "user-domain", "domain_name": "ScopeDomain"},
			wantUser:  `{"name":"user","password":"secret","domain":{"id":"user-domain"}}`,
			wantScope: `{"domain":{"name":"ScopeDomain"}}`,
		},
		{
			name:     "user domain only",
			data:     map[string]string{"user_domain_id": "user-domain"},
			wantUser: `{"name":"user","password":"secret","domain":{"id":"user-domain"}}`,
		},
		{
			name:     "default domain only",
			data:     map[string]string{"default_domain": "default"},
			wantUser: `{"name":"user","password":"secret","domain":{"id":"default"}}`,
		},
		{
			name:      "separate user and project domains",
			data:      map[string]string{"user_domain_id": "user-domain", "project_domain_name": "ProjectDomain", "project_name": "project"},
			wantUser:  `{"name":"user","password":"secret","domain":{"id":"user-domain"}}`,
			wantScope: `{"project":{"name":"project","domain":{"name":"ProjectDomain"}}}`,
		},
		{
			name:      "default user and project domains",
			data:      map[string]string{"default_domain": "default", "project_name": "project"},
			wantUser:  `{"name":"user","password":"secret","domain":{"id":"default"}}`,
			wantScope: `{"project":{"name":"project","domain":{"id":"default"}}}`,
		},
		{
			name:      "user ID with domain scope",
			data:      map[string]string{"username": "", "user_id": "user-id", "domain_id": "scope-domain"},
			wantUser:  `{"id":"user-id","password":"secret"}`,
			wantScope: `{"domain":{"id":"scope-domain"}}`,
		},
		{
			name:      "system scope",
			data:      map[string]string{"user_domain_id": "user-domain", "system_scope": "all", "project_id": "ignored"},
			wantUser:  `{"name":"user","password":"secret","domain":{"id":"user-domain"}}`,
			wantScope: `{"system":{"all":true}}`,
		},
		{
			name:      "trust scope",
			data:      map[string]string{"user_domain_id": "user-domain", "trust_id": "trust", "project_id": "ignored"},
			wantUser:  `{"name":"user","password":"secret","domain":{"id":"user-domain"}}`,
			wantScope: `{"OS-TRUST:trust":{"id":"trust"}}`,
		},
		{
			name:      "domain override preserves user domain",
			data:      map[string]string{"user_domain_name": "UserDomain", "domain_id": "original-scope"},
			options:   []auth.CloudOption{auth.WithDomainID("overridden-scope")},
			wantUser:  `{"name":"user","password":"secret","domain":{"name":"UserDomain"}}`,
			wantScope: `{"domain":{"id":"overridden-scope"}}`,
		},
		{
			name:      "explicit scope override",
			data:      map[string]string{"user_domain_id": "user-domain", "domain_id": "ignored"},
			options:   []auth.CloudOption{auth.WithScope(&auth.Scope{ProjectID: "project"})},
			wantUser:  `{"name":"user","password":"secret","domain":{"id":"user-domain"}}`,
			wantScope: `{"project":{"id":"project"}}`,
		},
		{
			name:     "explicitly unscoped",
			data:     map[string]string{"user_domain_id": "user-domain", "domain_id": "ignored"},
			options:  []auth.CloudOption{auth.WithScope(&auth.Scope{})},
			wantUser: `{"name":"user","password":"secret","domain":{"id":"user-domain"}}`,
		},
	}
	for _, test := range tests {
		for _, source := range []string{"cloud", "environment"} {
			t.Run(test.name+"/"+source, func(t *testing.T) {
				CleanupEnv(t)
				for _, key := range []string{"OS_SYSTEM_SCOPE", "OS_TRUST_ID", "OS_DEFAULT_DOMAIN", "OS_USER_ID", "OS_AUTH_TOKEN"} {
					t.Setenv(key, "")
				}
				server := th.SetupHTTP()
				defer server.Teardown()
				server.Mux.HandleFunc("/v3/auth/tokens", func(w http.ResponseWriter, r *http.Request) {
					th.TestMethod(t, r, http.MethodPost)
					var body struct {
						Auth struct {
							Identity struct {
								Methods  []string `json:"methods"`
								Password struct {
									User map[string]any `json:"user"`
								} `json:"password"`
							} `json:"identity"`
							Scope map[string]any `json:"scope"`
						} `json:"auth"`
					}
					th.AssertNoErr(t, json.NewDecoder(r.Body).Decode(&body))
					th.CheckDeepEquals(t, []string{"password"}, body.Auth.Identity.Methods)
					th.CheckJSONEquals(t, test.wantUser, body.Auth.Identity.Password.User)
					if test.wantScope == "" {
						if body.Auth.Scope != nil {
							t.Errorf("unexpected authorization scope: %v", body.Auth.Scope)
						}
					} else {
						th.CheckJSONEquals(t, test.wantScope, body.Auth.Scope)
					}
					w.Header().Set("Content-Type", "application/json")
					w.Header().Set("X-Subject-Token", "token")
					w.WriteHeader(http.StatusCreated)
					fmt.Fprint(w, `{"token":{"user":{"id":"user"},"expires_at":"2099-01-01T00:00:00Z"}}`)
				})
				data := map[string]any{"auth_url": server.Endpoint() + "v3/", "username": "user", "password": "secret"}
				for key, value := range test.data {
					data[key] = value
				}
				var plugin auth.Authenticator
				var err error
				if source == "cloud" {
					plugin, err = auth.AuthOptionsFromCloud(cloudSource{authType: auth.AuthV3Password, authData: data}, test.options...)
				} else {
					t.Setenv("OS_AUTH_TYPE", "v3password")
					for key, value := range data {
						t.Setenv("OS_"+strings.ToUpper(key), value.(string))
					}
					plugin, err = auth.AuthOptionsFromEnv(test.options...)
				}
				th.AssertNoErr(t, err)
				_, err = plugin.Authenticate(context.Background(), nil)
				th.AssertNoErr(t, err)
			})
		}
	}
}
