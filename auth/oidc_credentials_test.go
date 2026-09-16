package auth

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/gophercloud/gophercloud/v2"
	th "github.com/gophercloud/gophercloud/v2/testhelper"
)

func TestOIDCCreateWithEncodedBasicCredentials(t *testing.T) {
	fakeServer := th.SetupHTTP()
	defer fakeServer.Teardown()

	// OAuth client credentials are form-encoded before HTTP Basic encoding.
	expected := "Basic " + base64.StdEncoding.EncodeToString([]byte("client%3Awith%2Breserved:secret%2Bwith%25reserved"))
	HandleIdPTokenSuccessfully(t, fakeServer, expected)
	HandleFederationAuthSuccessfully(t, fakeServer, "test-idp-access-token-abc123")

	client := &gophercloud.ServiceClient{
		ProviderClient: &gophercloud.ProviderClient{},
		Endpoint:       fakeServer.Endpoint(),
	}
	result := authenticateOIDC(context.Background(), client, &V3OIDCClientCredentialsOpts{
		IdentityProviderName: "my-idp",
		Protocol:             "openid",
		ClientID:             "client:with+reserved",
		ClientSecret:         "secret+with%reserved",
		AccessTokenEndpoint:  fakeServer.Endpoint() + "oauth2/token",
	})
	th.AssertNoErr(t, result.Err)
	token, err := result.ExtractTokenID()
	th.AssertNoErr(t, err)
	th.CheckEquals(t, UnscopedTokenID, token)
}
