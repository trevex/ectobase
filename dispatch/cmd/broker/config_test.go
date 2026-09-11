package main

import "testing"

func TestDispatchConfigFromCertFiles(t *testing.T) {
	cfg, err := dispatchConfig(dispatchAuth{
		server:   "https://[fd00:db8:0:1::1]:6443",
		caFile:   "/secrets/dispatch-ca/tls.crt",
		certFile: "/secrets/broker-cert/tls.crt",
		keyFile:  "/secrets/broker-cert/tls.key",
	})
	if err != nil {
		t.Fatalf("dispatchConfig: %v", err)
	}
	if cfg.Host != "https://[fd00:db8:0:1::1]:6443" {
		t.Fatalf("host = %q", cfg.Host)
	}
	if cfg.CertFile != "/secrets/broker-cert/tls.crt" ||
		cfg.KeyFile != "/secrets/broker-cert/tls.key" ||
		cfg.CAFile != "/secrets/dispatch-ca/tls.crt" {
		t.Fatalf("tls files not set from paths: %+v", cfg.TLSClientConfig)
	}
	if cfg.Insecure {
		t.Fatal("must not be insecure when a CA file is provided")
	}
}

func TestDispatchConfigRequiresServer(t *testing.T) {
	if _, err := dispatchConfig(dispatchAuth{certFile: "a", keyFile: "b", caFile: "c"}); err == nil {
		t.Fatal("expected error when server is empty")
	}
}
