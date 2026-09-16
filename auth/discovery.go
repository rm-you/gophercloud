package auth

import (
	"context"
	"net/http"

	"github.com/gophercloud/gophercloud/v2"
	"github.com/gophercloud/gophercloud/v2/openstack/utils"
)

// Defer discovery until the caller's transport and context are available.
type versionedAuthenticator struct {
	v2 AuthOptionsV2
	v3 AuthOptionsV3
}

func (a versionedAuthenticator) GetAuthURL() string { return a.v3.AuthURL }

func (a versionedAuthenticator) Authenticate(ctx context.Context, httpClient *http.Client) (*AuthResult, error) {
	base, err := utils.BaseEndpoint(a.GetAuthURL())
	if err != nil {
		return nil, err
	}
	client := &gophercloud.ProviderClient{
		IdentityBase:     gophercloud.NormalizeURL(base),
		IdentityEndpoint: gophercloud.NormalizeURL(a.GetAuthURL()),
	}
	if httpClient != nil {
		client.HTTPClient = *httpClient
	}
	version, endpoint, err := utils.ChooseVersion(ctx, client, []*utils.Version{
		{ID: "v2.0", Priority: 20, Suffix: "/v2.0/"},
		{ID: "v3", Priority: 30, Suffix: "/v3/"},
	})
	if err != nil {
		return nil, err
	}
	if version.ID == "v2.0" {
		a.v2.AuthURL = endpoint
		return a.v2.Authenticate(ctx, httpClient)
	}
	a.v3.AuthURL = endpoint
	return a.v3.Authenticate(ctx, httpClient)
}
