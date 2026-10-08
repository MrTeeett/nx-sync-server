package tlsutil

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"nx-sync-server/internal/fsutil"
	"os"
	"sync"
	"time"
)

func fingerprint(cert *x509.Certificate) string {
	hash := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(hash[:])
}

func Create(keyPath, certPath, host string, now time.Time) (string, error) {
	if _, err := os.Lstat(keyPath); !errors.Is(err, os.ErrNotExist) {
		return "", errors.New("TLS identity already exists or cannot be inspected")
	}
	if _, err := os.Lstat(certPath); !errors.Is(err, os.ErrNotExist) {
		return "", errors.New("TLS certificate already exists or cannot be inspected")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", err
	}
	if err = fsutil.AtomicWrite(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0600); err != nil {
		return "", err
	}
	return renew(key, certPath, host, now)
}

func renew(key *ecdsa.PrivateKey, certPath, host string, now time.Time) (string, error) {
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return "", err
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "NX Sync"}, NotBefore: now.Add(-5 * time.Minute), NotAfter: now.Add(90 * 24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return "", err
	}
	if err = fsutil.AtomicWrite(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0640); err != nil {
		return "", err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return "", err
	}
	return fingerprint(cert), nil
}

func ReadFingerprint(certPath string) (string, error) {
	data, err := os.ReadFile(certPath)
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return "", errors.New("invalid certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", err
	}
	return fingerprint(cert), nil
}

// RestoreCertificate completes an interrupted initial installation while
// retaining the already generated key. It never rotates the TLS identity.
func RestoreCertificate(keyPath, certPath, host string, now time.Time) error {
	data, err := os.ReadFile(keyPath)
	if err != nil {
		return err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" {
		return errors.New("invalid private key")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return err
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return errors.New("unsupported private key")
	}
	_, err = renew(key, certPath, host, now)
	return err
}

type Manager struct {
	mu                      sync.RWMutex
	certificate             *tls.Certificate
	keyPath, certPath, host string
}

func Load(keyPath, certPath, host string) (*Manager, error) {
	info, err := os.Lstat(keyPath)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0007 != 0 {
		return nil, errors.New("TLS key must be private and regular")
	}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, err
	}
	cert.Leaf = leaf
	if err = leaf.VerifyHostname(host); err != nil {
		return nil, err
	}
	return &Manager{certificate: &cert, keyPath: keyPath, certPath: certPath, host: host}, nil
}

func (m *Manager) Config() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS13, GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		m.mu.RLock()
		defer m.mu.RUnlock()
		return m.certificate, nil
	}}
}

func (m *Manager) RenewIfNeeded(now time.Time) error {
	m.mu.RLock()
	cert := m.certificate
	m.mu.RUnlock()
	if now.Before(cert.Leaf.NotAfter.Add(-30 * 24 * time.Hour)) {
		return nil
	}
	key, ok := cert.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		return errors.New("unsupported private TLS key type")
	}
	oldPin := fingerprint(cert.Leaf)
	newPin, err := renew(key, m.certPath, m.host, now)
	if err != nil {
		return err
	}
	if oldPin != newPin {
		return errors.New("TLS identity changed during renewal")
	}
	loaded, err := tls.LoadX509KeyPair(m.certPath, m.keyPath)
	if err != nil {
		return err
	}
	loaded.Leaf, err = x509.ParseCertificate(loaded.Certificate[0])
	if err != nil {
		return err
	}
	m.mu.Lock()
	m.certificate = &loaded
	m.mu.Unlock()
	return nil
}

func (m *Manager) RunRenewal(ctx context.Context, onError func()) {
	ticker := time.NewTicker(12 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			if m.RenewIfNeeded(now) != nil {
				onError()
			}
		}
	}
}

// PinnedConfig uses the pinned SPKI as the endpoint's trust anchor. All checks
// normally provided by PKI for this self-signed endpoint are performed below.
// InsecureSkipVerify bypasses only the unrelated public-CA chain verification.
func PinnedConfig(host, pin string) (*tls.Config, error) {
	want, err := hex.DecodeString(pin)
	if err != nil || len(want) != 32 {
		return nil, errors.New("invalid SHA-256 SPKI pin")
	}
	return &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS13, InsecureSkipVerify: true, VerifyConnection: func(state tls.ConnectionState) error {
		if len(state.PeerCertificates) == 0 {
			return errors.New("no peer certificate")
		}
		leaf := state.PeerCertificates[0]
		got := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
		if subtle.ConstantTimeCompare(want, got[:]) != 1 {
			return errors.New("TLS fingerprint mismatch")
		}
		now := time.Now()
		if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
			return errors.New("certificate is expired or not yet valid")
		}
		if err := leaf.VerifyHostname(host); err != nil {
			return fmt.Errorf("certificate host mismatch: %w", err)
		}
		allowed := false
		for _, usage := range leaf.ExtKeyUsage {
			if usage == x509.ExtKeyUsageServerAuth {
				allowed = true
			}
		}
		if !allowed || leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
			return errors.New("certificate is not valid for server authentication")
		}
		return leaf.CheckSignature(leaf.SignatureAlgorithm, leaf.RawTBSCertificate, leaf.Signature)
	}}, nil
}
