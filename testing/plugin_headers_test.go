package testing

import (
	"context"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/gophercloud/gophercloud/v2"
	th "github.com/gophercloud/gophercloud/v2/testhelper"
)

type bearerAuthResult string

func TestBearerRequestSkipsRedundantReauthentication(t *testing.T) {
	const (
		oldToken = "old-token"
		newToken = "new-token"
	)

	p := new(gophercloud.ProviderClient)
	p.UseTokenLock()
	th.AssertNoErr(t, p.SetTokenAndAuthResult(bearerAuthResult(oldToken)))

	var reauths atomic.Int32
	p.ReauthFunc = func(context.Context) error {
		reauths.Add(1)
		if err := p.SetTokenAndAuthResult(bearerAuthResult(newToken)); err != nil {
			return err
		}
		return nil
	}

	firstRequest := make(chan struct{})
	releaseFirst := make(chan struct{})
	var oldRequests atomic.Int32
	fakeServer := th.SetupHTTP()
	defer fakeServer.Teardown()
	fakeServer.Mux.HandleFunc("/route", func(w http.ResponseWriter, r *http.Request) {
		switch r.Header.Get("Authorization") {
		case "Bearer " + oldToken:
			if oldRequests.Add(1) == 1 {
				close(firstRequest)
				<-releaseFirst
			}
			w.WriteHeader(http.StatusUnauthorized)
		case "Bearer " + newToken:
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	})

	request := func(errs chan<- error) {
		_, err := p.Request(context.Background(), http.MethodGet, fakeServer.Endpoint()+"route", &gophercloud.RequestOpts{
			OkCodes: []int{http.StatusNoContent},
		})
		errs <- err
	}

	errs := make(chan error, 2)
	go request(errs)
	<-firstRequest
	go request(errs)
	if err := <-errs; err != nil {
		t.Fatal(err)
	}
	close(releaseFirst)
	if err := <-errs; err != nil {
		t.Fatal(err)
	}

	th.AssertEquals(t, int32(1), reauths.Load())
}

func (r bearerAuthResult) ExtractTokenID() (string, error) { return string(r), nil }
func (r bearerAuthResult) AuthenticatedHeaders() map[string]string {
	return map[string]string{"Authorization": "Bearer " + string(r)}
}

func TestPluginAuthenticationHeaders(t *testing.T) {
	for _, test := range []struct {
		name string
		more map[string]string
		omit []string
		want string
	}{
		{"generated", nil, nil, "Bearer token"},
		{"override", map[string]string{"Authorization": "caller"}, nil, "caller"},
		{"omit", nil, []string{"Authorization"}, ""},
		{"omit override", map[string]string{"Authorization": "caller"}, []string{"Authorization"}, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := th.SetupHTTP()
			defer server.Teardown()
			server.Mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
				th.CheckEquals(t, test.want, r.Header.Get("Authorization"))
				th.CheckEquals(t, "", r.Header.Get("X-Auth-Token"))
				w.WriteHeader(http.StatusNoContent)
			})
			p := new(gophercloud.ProviderClient)
			p.UseTokenLock()
			th.AssertNoErr(t, p.SetTokenAndAuthResult(bearerAuthResult("token")))
			_, err := p.Request(context.Background(), http.MethodGet, server.Endpoint(), &gophercloud.RequestOpts{
				MoreHeaders: test.more, OmitHeaders: test.omit, OkCodes: []int{http.StatusNoContent},
			})
			th.AssertNoErr(t, err)
		})
	}
}
