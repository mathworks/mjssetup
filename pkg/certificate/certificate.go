// Copyright 2023 The MathWorks, Inc.
package certificate

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"time"

	"github.com/mathworks/mjssetup/internal/json"
)

// Mockable interface for creation of shared secrets and certificates
type Creator interface {
	CreateSharedSecret(*CreateSharedSecretInputs) error
	GenerateCertificate(*GenerateCertificateInputs) error
}

// Implementation of Creator that writes output to real files
type FileCreator struct{}

// Input arguments for CreateSharedSecret
type CreateSharedSecretInputs struct {
	Outfile string
}

var expiryDays = 3650 // 10 years
var keySize = 4096

// Create a shared secret JSON file containing a self-signed CA key pair
func (c *FileCreator) CreateSharedSecret(inputs *CreateSharedSecretInputs) error {
	file, err := os.Create(inputs.Outfile)
	if err != nil {
		return fmt.Errorf("error opening output file: %v", err)
	}
	defer file.Close()
	_, err = CreateAndWriteSharedSecret(file)
	if err != nil {
		return fmt.Errorf("error creating shared secret: %v", err)
	}
	fmt.Printf("Wrote shared secret to %s\n", inputs.Outfile)
	return nil
}

// Create a new self-signed CA key-pair and write it in JSON format using the Writer interface
func CreateAndWriteSharedSecret(writer io.Writer) (*SharedSecret, error) {
	cert, key, err := generateCertAndKey(true, "server")
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
	certPEM, err := writeSharedSecret(certBytes, key, writer)
	if err != nil {
		return nil, err
	}
	return &SharedSecret{
		Cert:    selfSignedCert,
		Key:     key,
		CertPEM: certPEM,
	}, nil
}

// Output struct for CreateSharedSecret
type sharedSecretOutput struct {
	Cert string `json:"serverCert"`
	Key  string `json:"serverKey"`
}

// Write out a self-signed certificate and private key
func writeSharedSecret(certBytes []byte, key *rsa.PrivateKey, writer io.Writer) (string, error) {
	keyPEM, err := encodeKey(key)
	if err != nil {
		return "", err
	}
	certPEM := encodeCert(certBytes)
	secret := sharedSecretOutput{
		Key:  keyPEM,
		Cert: certPEM,
	}
	err = json.WriteJSONFile(writer, &secret)
	return certPEM, err
}

// Input arguments for GenerateCertificate
type GenerateCertificateInputs struct {
	Outfile    string
	SecretFile string
}

// Create a JSON file containing a signed key pair
func (c *FileCreator) GenerateCertificate(inputs *GenerateCertificateInputs) error {
	secret, err := c.ReadSharedSecret(inputs.SecretFile)
	if err != nil {
		return err
	}

	file, err := os.Create(inputs.Outfile)
	if err != nil {
		return fmt.Errorf("error opening output file: %v", err)
	}
	defer file.Close()

	err = GenerateAndWriteCertificate(secret, file)
	if err != nil {
		return err
	}
	fmt.Printf("Wrote certificate to %s\n", inputs.Outfile)
	return nil
}

// Create a signed key pair from a shared secret
func GenerateCertificate(secret *SharedSecret) (*Certificate, error) {
	cert, key, err := generateCertAndKey(false, "client")
	if err != nil {
		return nil, err
	}
	certBytes, err := signCertificate(cert, key, secret.Cert, secret.Key)
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

// Generate a certificate and write it using the io.Writer interface
func GenerateAndWriteCertificate(secret *SharedSecret, writer io.Writer) error {
	certOutput, err := GenerateCertificate(secret)
	if err != nil {
		return err
	}
	return json.WriteJSONFile(writer, &certOutput)
}

// Output struct for GenerateCertificate
type Certificate struct {
	ClientCert string `json:"clientCert"`
	ClientKey  string `json:"clientKey"`
	ServerCert string `json:"serverCert"`
}

var keyType = "PRIVATE KEY"
var certType = "CERTIFICATE"

// Generate a private key and certificate template
func generateCertAndKey(isCA bool, commonName string) (*x509.Certificate, *rsa.PrivateKey, error) {
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

// Struct to store a shared secret key pair, plus the PEM-encoded cert
type SharedSecret struct {
	Cert    *x509.Certificate
	Key     *rsa.PrivateKey
	CertPEM string
}

// Load a shared secret from a JSON file
func (c *FileCreator) ReadSharedSecret(secretfile string) (*SharedSecret, error) {
	file, err := os.Open(secretfile)
	if err != nil {
		return nil, fmt.Errorf("error opening shared secret file: %v", err)
	}
	defer file.Close()
	return ReadSharedSecret(file)
}

// Load a shared secret using the io.Reader interface
func ReadSharedSecret(reader io.Reader) (*SharedSecret, error) {
	secretContents, err := json.ReadJSONFile[sharedSecretOutput](reader)
	if err != nil {
		return nil, fmt.Errorf("error reading shared secret: %v", err)
	}

	// Load the certificate
	certStr := secretContents.Cert
	if certStr == "" {
		return nil, errors.New(`field "Cert" missing from shared secret`)
	}
	cert, err := decodeCert([]byte(certStr))
	if err != nil {
		return nil, fmt.Errorf("error decoding certificate from shared secret: %v", err)
	}

	// Load the private key
	keyStr := secretContents.Key
	if keyStr == "" {
		return nil, errors.New(`field "Key" missing from shared secret`)
	}
	key, err := decodeKey(keyStr)
	if err != nil {
		return nil, fmt.Errorf("error loading private key from shared secret: %v", err)
	}
	return &SharedSecret{
		Cert:    cert,
		Key:     key,
		CertPEM: certStr,
	}, nil
}

// Decode a PEM-encoded certificate
func decodeCert(certBytes []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to decode certificate")
	}
	if block.Type != certType {
		return nil, fmt.Errorf("unexpected block type for certificate: %s", block.Type)
	}
	return x509.ParseCertificate(block.Bytes)
}

// Decode a PEM-encoded private key
func decodeKey(keyStr string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(keyStr))
	if block == nil {
		return nil, fmt.Errorf("failed to decode private key")
	}
	if block.Type != keyType {
		return nil, fmt.Errorf("unexpected block type for private key: %s", block.Type)
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	return key.(*rsa.PrivateKey), err
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

// Read a shared secret from a real input file
func readSharedSecretFromFile(secretfile string) (*sharedSecretOutput, error) {
	file, err := os.Open(secretfile)
	if err != nil {
		return nil, fmt.Errorf("error opening shared secret file: %v", err)
	}
	defer file.Close()
	secret, err := json.ReadJSONFile[sharedSecretOutput](file)
	if err != nil {
		return nil, fmt.Errorf("error parsing shared secret from file \"%s\": %v", secretfile, err)
	}
	return secret, nil
}
