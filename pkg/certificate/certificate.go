// Package certificate contains functions for generating shared secrets and certificates.
// Copyright 2023-2024 The MathWorks, Inc.
package certificate

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"time"
)

// Mockable interface for creation of shared secrets and certificates
type Creator interface {
	CreateSharedSecret() (*SharedSecret, error)
	GenerateCertificate(*SharedSecret) (*Certificate, error)
	GenerateCertificateWithHostname(*SharedSecret, string) (*Certificate, error)
	LoadSharedSecret([]byte) (*SharedSecret, error)
}

// Struct to store a shared secret key pair, plus the PEM-encoded key and cert
type SharedSecret struct {
	cert    *x509.Certificate
	key     *rsa.PrivateKey
	CertPEM string `json:"serverCert"`
	KeyPEM  string `json:"serverKey"`
}

// Struct to store a certificate key-pair plus the CA certificate that was used to sign it
type Certificate struct {
	ClientCert string `json:"clientCert"`
	ClientKey  string `json:"clientKey"`
	ServerCert string `json:"serverCert"`
}

// Implementation of Creator
type creatorImpl struct{}

// Construct new Creator
func New() Creator {
	return &creatorImpl{}
}

// Define constants used in certificate creation
const (
	expiryDays = 3650 // 10 years
	keySize    = 4096
	keyType    = "PRIVATE KEY"
	certType   = "CERTIFICATE"
)

// Create a shared secret and return it as a struct and a byte array
func (*creatorImpl) CreateSharedSecret() (*SharedSecret, error) {
	cert, key, err := generateCertAndKey(true, "server", "")
	if err != nil {
		return nil, err
	}
	certBytes, err := selfSignCertificate(cert, key)
	if err != nil {
		return nil, err
	}
	selfSignedCert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, err
	}

	// PEM-encode the key pair
	certPEM := encodeCert(certBytes)
	keyPEM, err := encodeKey(key)
	if err != nil {
		return nil, err
	}

	return &SharedSecret{
		cert:    selfSignedCert,
		key:     key,
		CertPEM: certPEM,
		KeyPEM:  keyPEM,
	}, nil
}

// Generate a certificate from a shared secret
func (c *creatorImpl) GenerateCertificate(secret *SharedSecret) (*Certificate, error) {
	return c.GenerateCertificateWithHostname(secret, "")
}

// Generate a certificate from a shared secret with a specific hostname in DNSNames
func (c *creatorImpl) GenerateCertificateWithHostname(secret *SharedSecret, hostname string) (*Certificate, error) {
	if secret.cert == nil {
		return nil, errors.New("shared secret does not contain a certificate")
	}
	if secret.key == nil {
		return nil, errors.New("shared secret does not contain a private key")
	}
	cert, key, err := generateCertAndKey(false, "client", hostname)
	if err != nil {
		return nil, err
	}
	certBytes, err := signCertificate(cert, key, secret.cert, secret.key)
	if err != nil {
		return nil, err
	}
	keyPEM, err := encodeKey(key)
	if err != nil {
		return nil, err
	}
	return &Certificate{
		ClientKey:  keyPEM,
		ClientCert: encodeCert(certBytes),
		ServerCert: string(secret.CertPEM),
	}, nil
}

// Load a shared secret struct from marshalled bytes
func (c *creatorImpl) LoadSharedSecret(data []byte) (*SharedSecret, error) {
	var secret SharedSecret
	err := json.Unmarshal(data, &secret)
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling shared secret: %v", err)
	}

	// Decode PEM
	cert, err := decodeCert(secret.CertPEM)
	if err != nil {
		return nil, err
	}
	key, err := decodeKey(secret.KeyPEM)
	if err != nil {
		return nil, err
	}
	secret.cert = cert
	secret.key = key
	return &secret, nil
}

// Generate a private key and certificate template
func generateCertAndKey(isCA bool, commonName string, hostname string) (*x509.Certificate, *rsa.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		return nil, nil, fmt.Errorf("error generating private key: %v", err)
	}
	serialNum, err := generateSerialNumber()
	if err != nil {
		return nil, nil, err
	}
	certTemplate := &x509.Certificate{
		SerialNumber: serialNum,
		Subject: pkix.Name{
			CommonName:         commonName,
			Organization:       []string{"The MathWorks, Inc."},
			OrganizationalUnit: []string{"MJS"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(0, 0, expiryDays),
		BasicConstraintsValid: true,
		IsCA:                  isCA,
		SignatureAlgorithm:    x509.SHA512WithRSA,
	}
	if hostname != "" {
		ip := net.ParseIP(hostname)
		if ip != nil {
			certTemplate.IPAddresses = append(certTemplate.IPAddresses, ip)
		} else {
			certTemplate.DNSNames = append(certTemplate.DNSNames, hostname)
		}
	}
	return certTemplate, key, nil
}

// Self-sign a certificate
func selfSignCertificate(cert *x509.Certificate, key *rsa.PrivateKey) ([]byte, error) {
	certBytes, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		return []byte{}, fmt.Errorf("failed to self-sign certificate: %v", err)
	}
	return certBytes, nil
}

// Sign a certificate using a CA certificate
func signCertificate(cert *x509.Certificate, key *rsa.PrivateKey, caCert *x509.Certificate, caKey *rsa.PrivateKey) ([]byte, error) {
	certBytes := []byte{}
	if isExpired(caCert) {
		return certBytes, errors.New("signing certificate is expired")
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, cert, caCert, &key.PublicKey, caKey)
	if err != nil {
		return certBytes, fmt.Errorf("failed to sign certificate: %v", err)
	}
	return certBytes, nil
}

// PEM-encode a certificate
func encodeCert(certBytes []byte) string {
	pemBlock := &pem.Block{
		Type:  certType,
		Bytes: certBytes,
	}
	pemKey := pem.EncodeToMemory(pemBlock)
	return string(pemKey)
}

// PEM-encode a private key
func encodeKey(key *rsa.PrivateKey) (string, error) {
	keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", err
	}
	pemBlock := &pem.Block{
		Type:  keyType,
		Bytes: keyBytes,
	}
	pemKey := pem.EncodeToMemory(pemBlock)
	return string(pemKey), nil
}

func isExpired(cert *x509.Certificate) bool {
	return time.Now().After(cert.NotAfter)
}

func generateSerialNumber() (*big.Int, error) {
	serialNum, err := rand.Int(rand.Reader, new(big.Int).SetBit(new(big.Int), 64, 1))
	if err != nil {
		return nil, fmt.Errorf("error generating certificate serial number: %v", err)
	}
	return serialNum, nil
}

// Decode a PEM-encoded certificate
func decodeCert(certPEM string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to decode certificate")
	}
	if block.Type != certType {
		return nil, fmt.Errorf("unexpected block type for certificate: %s", block.Type)
	}
	return x509.ParseCertificate(block.Bytes)
}

// Decode a PEM-encoded private key
func decodeKey(keyPEM string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(keyPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to decode private key")
	}
	if block.Type != keyType {
		return nil, fmt.Errorf("unexpected block type for private key: %s", block.Type)
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	return key.(*rsa.PrivateKey), err
}
