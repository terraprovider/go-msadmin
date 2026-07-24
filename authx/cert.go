package authx

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// certPEM returns an unencrypted PEM (cert + key) plus the password to pass to the
// PEM loader. Accepts a PEM or PKCS#12 bundle, from a file path or base64 string
// (matching azuread's client_certificate / client_certificate_path).
func (c Config) certPEM() ([]byte, string, error) {
	var raw []byte
	switch {
	case c.ClientCertificatePath != "":
		b, err := os.ReadFile(c.ClientCertificatePath)
		if err != nil {
			return nil, "", fmt.Errorf("authx: read client_certificate_path: %w", err)
		}
		raw = b
	case c.ClientCertificate != "":
		if dec, err := base64.StdEncoding.DecodeString(strings.TrimSpace(c.ClientCertificate)); err == nil {
			raw = dec
		} else {
			raw = []byte(c.ClientCertificate)
		}
	default:
		return nil, "", fmt.Errorf("authx: no certificate provided")
	}

	// Already PEM — hand off as-is (the loader applies the password if the key is encrypted).
	if bytes.Contains(raw, []byte("-----BEGIN")) {
		return raw, c.ClientCertificatePassword, nil
	}

	// PKCS#12 → decrypt here and emit an unencrypted PEM (so the loader needs no password).
	key, cert, caCerts, err := pkcs12.DecodeChain(raw, c.ClientCertificatePassword)
	if err != nil {
		return nil, "", fmt.Errorf("authx: parse certificate (expected PEM or PKCS#12): %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, "", fmt.Errorf("authx: marshal private key: %w", err)
	}
	var out bytes.Buffer
	_ = pem.Encode(&out, &pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	_ = pem.Encode(&out, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	for _, ca := range caCerts {
		_ = pem.Encode(&out, &pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw})
	}
	return out.Bytes(), "", nil
}
