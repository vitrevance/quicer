package quicer

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	mrand "math/rand"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"
)

type ParentCertificateConfig struct {
	Cert *x509.Certificate
	Key  crypto.PrivateKey
}

func GenerateCertificate(dnsNames []string, isCA bool, parentCert *ParentCertificateConfig) (*tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate private key")
	}
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate serial number")
	}
	notBefore := time.Now().AddDate(0, -1, 0)
	notAfter := time.Now().Add(90 * 24 * time.Hour)
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Quicer Co"},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		IsCA:                  isCA,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
	}
	if isCA {
		template.KeyUsage |= x509.KeyUsageCertSign
	}
	if parentCert == nil {
		parentCert = &ParentCertificateConfig{
			Cert: &template,
			Key:  priv,
		}
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, parentCert.Cert, &priv.PublicKey, parentCert.Key)
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate certificate")
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal private key")
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyBytes})
	tlsCert, err := tls.X509KeyPair(certPEM, privPEM)
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate key pair")
	}
	return &tlsCert, nil
}

func LoadCertificate(certFile, keyFile string) (*x509.Certificate, crypto.PrivateKey, error) {
	// Read certificate file
	certData, err := os.ReadFile(certFile)
	if err != nil {
		return nil, nil, err
	}

	// Decode PEM certificate
	certBlock, _ := pem.Decode(certData)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return nil, nil, errors.New("failed to decode PEM certificate")
	}

	// Parse X.509 certificate
	certificate, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}

	// Read private key file
	keyData, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, nil, err
	}

	// Decode PEM private key
	keyBlock, _ := pem.Decode(keyData)
	if keyBlock == nil {
		return nil, nil, errors.New("failed to decode PEM private key")
	}

	// Parse private key
	privateKey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		// Try legacy PKCS1 format if PKCS8 fails
		privateKey, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
		if err != nil {
			return nil, nil, errors.New("failed to parse private key")
		}
	}

	return certificate, privateKey, nil
}

type CertificateProvider interface {
	Get(domain string) (*tls.Certificate, error)
}

type CachedCertificateProvider struct {
	StoragePath string
	CA          ParentCertificateConfig
	cache       map[string]*tls.Certificate
	mux         sync.Mutex
}

func (p *CachedCertificateProvider) Get(domain string) (*tls.Certificate, error) {
	parts := strings.Split(domain, ".")
	parts = parts[len(parts)-2:]
	topLevelDomain := strings.Join(parts, ".")
	wildcardDomain := "*." + topLevelDomain
	p.mux.Lock()
	defer p.mux.Unlock()
	if p.cache == nil {
		p.cache = make(map[string]*tls.Certificate)
		err := p.loadCertificates()
		if err != nil {
			log.Printf("Failed to load certificates from cache: %v\n", err)
		}
	}
	if cert := p.cache[topLevelDomain]; cert != nil {
		return cert, nil
	}
	log.Printf("Genereating certificate for %v as %v\n", domain, wildcardDomain)
	tlsCert, err := GenerateCertificate([]string{topLevelDomain, wildcardDomain}, false, &p.CA)
	if err != nil {
		log.Fatalf("Failed to generate key pair: %v", err)
	}
	p.cache[topLevelDomain] = tlsCert
	go p.saveToFile(topLevelDomain, tlsCert)
	return tlsCert, nil
}

func (p *CachedCertificateProvider) saveToFile(topLevelDomain string, cert *tls.Certificate) {
	// Create storage directory if it doesn't exist
	storageDir := filepath.Join(p.StoragePath, topLevelDomain)
	if err := os.MkdirAll(storageDir, 0755); err != nil {
		log.Printf("Error creating directory for %s: %v", topLevelDomain, err)
		return
	}

	keyPEMData, err := encodePrivateKeyToPEM(cert.PrivateKey)
	if err != nil {
		log.Printf("Error marshaling private key: %v", err)
		return
	}

	// Generate filenames
	certPath := filepath.Join(storageDir, "cert.pem")
	keyPath := filepath.Join(storageDir, "key.pem")

	// Save certificate
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Leaf.Raw,
	}), 0644); err != nil {
		log.Printf("Error saving certificate for %s: %v", topLevelDomain, err)
		return
	}

	// Save private key
	if err := os.WriteFile(keyPath, keyPEMData, 0600); err != nil {
		log.Printf("Error saving key for %s: %v", topLevelDomain, err)
		return
	}

	// Update in-memory cache
	p.cache[topLevelDomain] = cert
}

func (p *CachedCertificateProvider) loadCertificates() error {
	// Read all directories in StoragePath
	dirEntries, err := os.ReadDir(p.StoragePath)
	if err != nil {
		return errors.Wrap(err, "failed to read storage directory")
	}

	for _, entry := range dirEntries {
		if !entry.IsDir() {
			continue // Skip non-directory entries
		}

		topLevelDomain := entry.Name()
		certPath := filepath.Join(p.StoragePath, topLevelDomain, "cert.pem")
		keyPath := filepath.Join(p.StoragePath, topLevelDomain, "key.pem")

		// Load certificate from files
		certBytes, err := os.ReadFile(certPath)
		if err != nil {
			log.Printf("Skipping %s: failed to read certificate: %v", topLevelDomain, err)
			continue
		}

		keyBytes, err := os.ReadFile(keyPath)
		if err != nil {
			log.Printf("Skipping %s: failed to read private key: %v", topLevelDomain, err)
			continue
		}

		// Load certificate and private key
		cert, err := tls.X509KeyPair(certBytes, keyBytes)
		if err != nil {
			log.Printf("Skipping %s: failed to load certificate: %v", topLevelDomain, err)
			continue
		}

		// Store in cache
		p.cache[topLevelDomain] = &cert
	}

	return nil
}

func encodePrivateKeyToPEM(privateKey any) ([]byte, error) {
	var pemBlock *pem.Block

	switch key := privateKey.(type) {
	case *rsa.PrivateKey:
		pemBlock = &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(key),
		}
	case *ecdsa.PrivateKey:
		bytes, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return nil, err
		}
		pemBlock = &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: bytes,
		}
	default:
		return nil, x509.ErrUnsupportedAlgorithm
	}

	return pem.EncodeToMemory(pemBlock), nil
}

type SeedCertificateProvider struct {
	CA    ParentCertificateConfig
	cache map[string]*tls.Certificate
	mux   sync.Mutex
}

func (p *SeedCertificateProvider) Get(domain string) (*tls.Certificate, error) {
	parts := strings.Split(domain, ".")
	parts = parts[len(parts)-2:]
	topLevelDomain := strings.Join(parts, ".")
	wildcardDomain := "*." + topLevelDomain
	p.mux.Lock()
	defer p.mux.Unlock()

	if p.cache == nil {
		p.cache = make(map[string]*tls.Certificate)
	}
	if cert := p.cache[topLevelDomain]; cert != nil {
		return cert, nil
	}
	log.Printf("Genereating certificate for %v as %v\n", domain, wildcardDomain)
	hash := md5.Sum([]byte(topLevelDomain))
	serialNumber := new(big.Int).SetBytes(hash[:])
	notBefore := time.Date(2025, 1, 1, 1, 1, 1, 1, time.UTC)
	notAfter := notBefore.AddDate(10, 0, 0)
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Quicer Co"},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		IsCA:                  false,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{topLevelDomain, wildcardDomain},
	}
	seed := new(big.Int)
	seed = seed.Rsh(serialNumber, 64)

	priv, err := generateKeyWithSessionSeed(seed.Int64())
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate private key")
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, p.CA.Cert, &priv.PublicKey, p.CA.Key)
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate certificate")
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	privPEM, err := encodePrivateKeyToPEM(priv)
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal private key")
	}

	tlsCert, err := tls.X509KeyPair(certPEM, privPEM)
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate key pair")
	}
	p.cache[topLevelDomain] = &tlsCert
	return &tlsCert, nil
}

func generateKeyWithSessionSeed(seed int64) (key *ecdsa.PrivateKey, err error) {
	var privA *ecdsa.PrivateKey
	{
		randSrc := mrand.NewSource(seed)
		privA, err = ecdsa.GenerateKey(elliptic.P256(), mrand.New(randSrc))
		if err != nil {
			return nil, errors.Wrap(err, "failed to generate private key")
		}
	}
	for {
		randSrc := mrand.NewSource(seed)
		privB, err := ecdsa.GenerateKey(elliptic.P256(), mrand.New(randSrc))
		if err != nil {
			return nil, errors.Wrap(err, "failed to generate private key")
		}
		if !privA.Equal(privB) {
			if privA.D.Cmp(privB.D)*9+privA.X.Cmp(privB.X)*3+privA.Y.Cmp(privB.Y) < 0 {
				return privA, nil
			} else {
				return privB, nil
			}
		}
	}
}
