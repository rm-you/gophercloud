package clouds

import (
	"strings"
	"testing"

	"github.com/gophercloud/gophercloud/v2"
	"github.com/gophercloud/gophercloud/v2/openstack/identity/v3/oidc"
	"github.com/gophercloud/gophercloud/v2/openstack/identity/v3/tokens"
	"github.com/gophercloud/gophercloud/v2/openstack/identity/v3/websso"
)

func TestParseV3SystemScope(t *testing.T) {
	for _, authType := range []string{"v3password", "v3token", "v3websso", "v3oidcclientcredentials"} {
		for _, tt := range []struct {
			name, fields, env string
			explicit          *gophercloud.AuthScope
			want              tokens.Scope
			wantError         bool
		}{
			{name: "invalid", fields: "system_scope: admin", wantError: true},
			{name: "system", fields: "system_scope: all", want: tokens.Scope{System: true}},
			{name: "system before project", fields: "system_scope: all, project_id: project", want: tokens.Scope{System: true}},
			{name: "invalid before project", fields: "system_scope: admin, project_id: project", wantError: true},
			{name: "trust before system", fields: "trust_id: trust, system_scope: all, project_id: project", want: tokens.Scope{TrustID: "trust"}},
			{name: "explicit scope", fields: "system_scope: all", explicit: &gophercloud.AuthScope{ProjectID: "explicit"}, want: tokens.Scope{ProjectID: "explicit"}},
			{name: "environment", env: "all", want: tokens.Scope{System: true}},
			{name: "invalid environment", env: "admin", wantError: true},
		} {
			t.Run(authType+"/"+tt.name, func(t *testing.T) {
				t.Setenv("OS_SYSTEM_SCOPE", tt.env)
				opts := []ParseOption{WithCloudName("test"), WithCloudsYAML(strings.NewReader(
					"clouds:\n  test:\n    auth_type: " + authType + "\n    auth: {" + tt.fields + "}\n"))}
				if tt.explicit != nil {
					opts = append(opts, WithScope(tt.explicit))
				}
				cfg, err := ParseV3(opts...)
				if tt.wantError {
					if err == nil || !strings.Contains(err.Error(), "system scope") {
						t.Fatalf("expected system scope error, got %v", err)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				var scope tokens.Scope
				switch auth := cfg.AuthOptions.(type) {
				case *tokens.AuthOptions:
					scope = auth.Scope
				case *oidc.AuthOptions:
					scope = auth.Scope
				case *websso.AuthOptions:
					scope = auth.Scope
				default:
					t.Fatalf("unexpected auth type %T", auth)
				}
				if scope != tt.want {
					t.Fatalf("scope = %+v, want %+v", scope, tt.want)
				}
			})
		}
	}
}
