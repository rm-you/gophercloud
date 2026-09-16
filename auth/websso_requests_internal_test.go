package auth

import "testing"

func TestEndpointOrigin(t *testing.T) {
	tests := map[string]string{
		"https://Keystone.Example/identity/v3": "https://keystone.example",
		"https://keystone.example:443/v3":      "https://keystone.example",
		"http://keystone.example:80/v3":        "http://keystone.example",
		"https://keystone.example:5000/v3":     "https://keystone.example:5000",
		"http://keystone.example:443/v3":       "http://keystone.example:443",
		"https://[::1]:443/v3":                 "https://[::1]",
		"https://[::1]:5000/v3":                "https://[::1]:5000",
	}
	for rawURL, want := range tests {
		got, err := endpointOrigin(rawURL)
		if err != nil {
			t.Fatalf("endpointOrigin(%q): %v", rawURL, err)
		}
		if got != want {
			t.Errorf("endpointOrigin(%q) = %q, want %q", rawURL, got, want)
		}
	}
	if !sameOrigin("https://keystone.example/v3/auth/OS-FEDERATION/websso", "https://keystone.example") {
		t.Error("expected a referer without the default port to match")
	}
}
