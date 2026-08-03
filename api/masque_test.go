package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

func TestPrepareTlsConfigKeepsVerificationEnabledByDefault(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	peerPubKey := &privKey.PublicKey
	cfg, err := PrepareTlsConfig(privKey, peerPubKey, [][]byte{{0x01, 0x02, 0x03}}, "example.com", false)
	if err != nil {
		t.Fatalf("PrepareTlsConfig returned error: %v", err)
	}

	if cfg.InsecureSkipVerify {
		t.Fatal("expected TLS verification to remain enabled by default")
	}

	if cfg.VerifyPeerCertificate == nil {
		t.Fatal("expected TLS peer certificate verification to be configured")
	}
}

func TestPrepareTlsConfigAllowsInsecureMode(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	peerPubKey := &privKey.PublicKey
	cfg, err := PrepareTlsConfig(privKey, peerPubKey, [][]byte{{0x01, 0x02, 0x03}}, "example.com", true)
	if err != nil {
		t.Fatalf("PrepareTlsConfig returned error: %v", err)
	}

	if !cfg.InsecureSkipVerify {
		t.Fatal("expected insecure mode to disable certificate verification")
	}
}
