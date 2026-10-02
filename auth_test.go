package httpDigestAuth

import (
	"crypto/tls"
	"net/http"
	"testing"
	"time"
)

func TestDefaultHTTPClientConfiguresSecureTLSAndTimeout(t *testing.T) {
	client := defaultHTTPClient()

	if client.Timeout == 0 {
		t.Fatal("expected default timeout to be set")
	}

	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatal("expected a *http.Transport")
	}
	if transport.TLSClientConfig == nil {
		t.Fatal("expected TLS configuration to be initialized")
	}
	if transport.TLSClientConfig.MinVersion < tls.VersionTLS12 {
		t.Fatalf("expected minimum TLS version to be TLS 1.2 or higher, got %d", transport.TLSClientConfig.MinVersion)
	}
}

func TestDigestHeadersHonorConfiguredClientTimeout(t *testing.T) {
	digest := &DigestHeaders{
		Client: &http.Client{Timeout: 12 * time.Second},
	}

	client := digest.client()
	if client.Timeout != 12*time.Second {
		t.Fatalf("expected custom timeout to be preserved, got %s", client.Timeout)
	}
}
