package clouds

import (
	"maps"
	"os"

	"github.com/gophercloud/gophercloud/v2/auth"
)

// Implement the CloudSource interface in the auth package
func (c Cloud) GetAuthType() auth.AuthType {
	return auth.AuthType(coalesce(os.Getenv("OS_AUTH_TYPE"), string(c.AuthType)))
}

func (c Cloud) GetIdentityAPIVersion() string {
	return c.IdentityAPIVersion
}

func (c Cloud) GetAuthData() map[string]any {
	m := make(map[string]any, len(c.Auth)+3)
	maps.Copy(m, c.Auth)
	if value, ok := m["identity_provider"]; !ok || value == "" {
		m["identity_provider"] = c.IdentityProvider
	}
	if value, ok := m["protocol"]; !ok || value == "" {
		m["protocol"] = c.Protocol
	}
	if value, ok := m["cache_namespace"]; !ok || value == "" {
		m["cache_namespace"] = c.Name
	}
	return m
}

// Build an Authenticator using parsed clouds.yaml
func (c Cloud) ToAuthOptions(opts ...auth.CloudOption) (auth.Authenticator, error) {
	return auth.AuthOptionsFromCloud(c, opts...)
}
