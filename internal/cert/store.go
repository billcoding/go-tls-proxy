package cert

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
)

func loadOrCreateAccountKey(dir string) (crypto.Signer, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "account.key")
	data, err := os.ReadFile(path)
	if err == nil {
		return parseSigner(data)
	}
	if !os.IsNotExist(err) {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	encoded, err := marshalSigner(key)
	if err != nil {
		return nil, err
	}
	if err := writeFile(path, encoded); err != nil {
		return nil, err
	}
	return key, nil
}

func saveCertificate(dir string, cert *tls.Certificate) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := writeFile(filepath.Join(dir, "cert.pem"), encodeCertPEM(cert.Certificate)); err != nil {
		return err
	}
	keyPEM, err := marshalSigner(cert.PrivateKey.(crypto.Signer))
	if err != nil {
		return err
	}
	return writeFile(filepath.Join(dir, "key.pem"), keyPEM)
}

func loadCertificate(dir string) (*tls.Certificate, error) {
	certPEM, err := os.ReadFile(filepath.Join(dir, "cert.pem"))
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(filepath.Join(dir, "key.pem"))
	if err != nil {
		return nil, err
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	if len(pair.Certificate) == 0 {
		return nil, fmt.Errorf("证书文件是空的")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, err
	}
	pair.Leaf = leaf
	return &pair, nil
}

func encodeCertPEM(ders [][]byte) []byte {
	var out []byte
	for _, der := range ders {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	return out
}

func marshalSigner(key crypto.Signer) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

func parseSigner(data []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("账户私钥不是 PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		if key, ecErr := x509.ParseECPrivateKey(block.Bytes); ecErr == nil {
			return key, nil
		}
		return nil, err
	}
	signer, ok := parsed.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("账户私钥不能用于签名")
	}
	return signer, nil
}

func writeFile(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
