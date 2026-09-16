package auth

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/gophercloud/gophercloud/v2"
	th "github.com/gophercloud/gophercloud/v2/testhelper"
)

func TestOIDCCreateWithUnencodedBasicCredentials(t *testing.T) {
	fakeServer := th.SetupHTTP()
	defer fakeServer.Teardown()

	// Like keystoneauth, the credentials are sent without form encoding.
	expected := "Basic " + base64.StdEncoding.EncodeToString([]byte("client+with/reserved:secret+with%reserved/="))
	HandleIdPTokenSuccessfully(t, fakeServer, expected)
	HandleFederationAuthSuccessfully(t, fakeServer, "test-idp-access-token-abc123")

	client := &gophercloud.ServiceClient{
		ProviderClient: &gophercloud.ProviderClient{},
		Endpoint:       fakeServer.Endpoint(),
	}
	result, err := authenticateOIDC(context.Background(), client, &V3OIDCClientCredentialsOpts{
		IdentityProviderName: "my-idp",
		Protocol:             "openid",
		ClientID:             "client+with/reserved",
		ClientSecret:         "secret+with%reserved/=",
		AccessTokenEndpoint:  fakeServer.Endpoint() + "oauth2/token",
	})
	th.AssertNoErr(t, err)
	th.CheckEquals(t, UnscopedTokenID, result.TokenID)
}
