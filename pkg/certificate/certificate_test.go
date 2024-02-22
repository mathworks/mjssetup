// Copyright 2023-2024 The MathWorks, Inc.
package certificate

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mathworks/mjssetup/internal/json"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test the CreateSharedSecret and GenerateCertificate functions, which use the Writer interface
func TestCreateCertificatesWithWriter(t *testing.T) {
	secret := verifyCreateSharedSecret(t)
	verifyGenerateCertificate(t, secret)
}

// Test the FileCreator struct, which writes secrets and certificates to a real file
func TestFileCreator(t *testing.T) {
	// Create a shared secret file
	tempDir := t.TempDir()
	secretFile := filepath.Join(tempDir, "testSecret.json")
	gotSecret := verifyCreateSharedSecretFile(t, secretFile)

	// Create a certificate from the shared secret file
	certFile := filepath.Join(tempDir, "testCert.json")
	fileCreator := FileCreator{}
	err := fileCreator.GenerateCertificate(&GenerateCertificateInputs{
		Outfile:    certFile,
		SecretFile: secretFile,
	})
	assert.NoError(t, err, "error running FileCreator.GenerateCertificate")

	// Verify the contents of the certificate file
	file, err := os.Open(certFile)
	assert.NoError(t, err, "error opening certificate file")
	defer file.Close()
	certContents, err := json.ReadJSONFile[Certificate](file)
	assert.NoError(t, err, "error loading certificate file contents")
	verifyCertificateContents(t, certContents, gotSecret)
}

// Check that CreateSharedSecret errors when writing the output file errors
func TestCreateSharedSecretWriteError(t *testing.T) {
	invalidDir := filepath.Join("this", "dir", "does", "not", "exist")
	assert.NoDirExists(t, invalidDir, "invalid directory should not exist")
	secretFile := filepath.Join(invalidDir, "testSecret.json")
	fileCreator := FileCreator{}
	err := fileCreator.CreateSharedSecret(&CreateSharedSecretInputs{
		Outfile: secretFile,
	})
	require.Error(t, err, "expected error when shared secret file is not writeable")
}

// Check that GenerateCertificate errors when reading the shared secret errors
func TestGenerateCertificateReadError(t *testing.T) {
	secretFile := "/this/is/not/a/file.json"
	assert.NoFileExists(t, secretFile, "secret file should not exist")
	fileCreator := FileCreator{}
	err := fileCreator.GenerateCertificate(&GenerateCertificateInputs{
		Outfile:    "test.json",
		SecretFile: secretFile,
	})
	require.Error(t, err, "Expected error when reading shared secret errors")
}

// Check that GenerateCertificate errors when writing the certificate errors
func TestGenerateCertificateWriteError(t *testing.T) {
	// First, create a valid shared secret file
	tempDir := t.TempDir()
	secretFile := filepath.Join(tempDir, "secret.json")
	verifyCreateSharedSecretFile(t, secretFile)

	// Check for an error when writing to a non-writeable file
	invalidDir := filepath.Join("this", "dir", "does", "not", "exist")
	assert.NoDirExists(t, invalidDir, "invalid directory should not exist")
	certFile := filepath.Join(invalidDir, "cert.json")
	fileCreator := FileCreator{}
	err := fileCreator.GenerateCertificate(&GenerateCertificateInputs{
		Outfile:    certFile,
		SecretFile: secretFile,
	})
	require.Error(t, err, "expected error when certificate file is not writeable")
}

// Check we get an error from GenerateCertificate if the shared secret certificate has expired
func TestGenerateCertificateExpiredSecret(t *testing.T) {
	// Create valid secret and set its expiry date to be in the past
	secret := verifyCreateSharedSecret(t)
	finalDate := time.Now().AddDate(0, 0, -10)
	initDate := finalDate.AddDate(0, 0, -10)
	secret.Cert.NotBefore = initDate
	secret.Cert.NotAfter = finalDate

	var buffer bytes.Buffer
	err := GenerateAndWriteCertificate(secret, &buffer)
	assert.Errorf(t, err, "should get error from GenerateCertificate when secret cert has expired")
	assert.Empty(t, buffer, "buffer should be empty when certificate generation failed")
}

// Check we get an error from GenerateCertificate if the shared secret contains an unparsable certificate
func TestGenerateCertificateInvalidSecretCert(t *testing.T) {
	modifier := func(secret *sharedSecretOutput) {
		secret.Cert = "not-valid-pem"
	}
	secretFile := createModifiedSecret(t, modifier)
	fileCreator := FileCreator{}
	err := fileCreator.GenerateCertificate(&GenerateCertificateInputs{
		SecretFile: secretFile,
		Outfile:    filepath.Join(t.TempDir(), "cert.json"),
	})
	assert.Error(t, err, "expected error when shared secret contains a cert that is not valid PEM")
}

// Check we get an error from GenerateCertificate if the shared secret contains an unparsable certificate
func TestGenerateCertificateInvalidSecretKey(t *testing.T) {
	modifier := func(secret *sharedSecretOutput) {
		secret.Key = "not-valid-pem"
	}
	secretFile := createModifiedSecret(t, modifier)
	fileCreator := FileCreator{}
	err := fileCreator.GenerateCertificate(&GenerateCertificateInputs{
		SecretFile: secretFile,
		Outfile:    filepath.Join(t.TempDir(), "cert.json"),
	})
	assert.Error(t, err, "expected error when shared secret contains a key that is not valid PEM")
}

// Create a shared secret and verify that it was created correctly
func verifyCreateSharedSecret(t *testing.T) *SharedSecret {
	var buffer bytes.Buffer
	secret, err := CreateAndWriteSharedSecret(&buffer)
	assert.NoError(t, err, "error creating shared secret")

	// Check the certificate and key are as expected
	// They should have been written into the byte buffer by the dummy certificate creator
	secretContents, err := json.ReadJSONFile[sharedSecretOutput](&buffer)
	assert.NoError(t, err, "error reading secret from buffer")
	gotSecret := verifySecretContents(t, secretContents)

	// Check the returned secret matches what was written to the buffer
	require.Equal(t, secret.Cert, gotSecret.Cert, "certificate written to buffer does not match return value of CreateSharedSecret")
	require.Equal(t, secret.Key, gotSecret.Key, "private key written to buffer does not match return value of CreateSharedSecret")
	require.Equal(t, secret.CertPEM, gotSecret.CertPEM, "certificate PEM written to buffer does not match return value of CreateSharedSecret")
	return secret
}

// Create a shared secret file and verify its contents
func verifyCreateSharedSecretFile(t *testing.T, secretFile string) *SharedSecret {
	fileCreator := FileCreator{}
	err := fileCreator.CreateSharedSecret(&CreateSharedSecretInputs{
		Outfile: secretFile,
	})
	assert.NoError(t, err, "error running FileCreator.CreateSharedSecret")

	// Verify the contents of the secret file
	secretContents, err := readSharedSecretFromFile(secretFile)
	assert.NoError(t, err, "error reading shared secret from file")
	return verifySecretContents(t, secretContents)
}

// Verify the contents of a written shared secret
func verifySecretContents(t *testing.T, secret *sharedSecretOutput) *SharedSecret {
	key := decodeKeyNoError(t, secret.Key)
	cert := decodeCertNoError(t, secret.Cert)
	require.True(t, cert.IsCA, "certificate should be a CA certificate")
	require.NoError(t, cert.CheckSignatureFrom(cert), "certificate should be self-signed")
	verifyExpiryDate(t, cert, expiryDays)
	return &SharedSecret{
		Cert:    cert,
		Key:     key,
		CertPEM: secret.Cert,
	}
}

// Generate a certificate and verify that it was created correctly
func verifyGenerateCertificate(t *testing.T, secret *SharedSecret) {
	var buffer bytes.Buffer
	err := GenerateAndWriteCertificate(secret, &buffer)
	assert.NoError(t, err, "error running GenerateCertificate")

	// Check the certificate and key are as expected
	// They should have been written into the byte buffer by the dummy certificate creator
	certContents, err := json.ReadJSONFile[Certificate](&buffer)
	assert.NoError(t, err, "error reading certificate from buffer")
	verifyCertificateContents(t, certContents, secret)
}

// Verify the contents of a written certificate
func verifyCertificateContents(t *testing.T, certContents *Certificate, secret *SharedSecret) {
	decodeKeyNoError(t, certContents.ClientKey)
	cert := decodeCertNoError(t, certContents.ClientCert)
	require.False(t, cert.IsCA, "certificate should not be a CA certificate")
	verifyExpiryDate(t, cert, expiryDays)

	// Check the CA certificate PEM matches the certificate PEM of the original shared secret
	require.Equal(t, secret.CertPEM, certContents.ServerCert, "serverCert in signed certificate file should match CA cert")

	// Check the client certificate was signed by the CA certificate
	require.NoError(t, cert.CheckSignatureFrom(secret.Cert), "certificate should be signed by CA certificate")
}

func verifyExpiryDate(t *testing.T, cert *x509.Certificate, expectedDays int) {
	expiryLength := cert.NotAfter.Sub(cert.NotBefore)
	expiryLengthInDays := int(expiryLength.Hours() / 24)
	require.Equal(t, expiryLengthInDays, expectedDays, "certificate does not have the expected expiry date")
}

// Decode certificate and check there was no error
func decodeCertNoError(t *testing.T, certString string) *x509.Certificate {
	cert, err := decodeCert([]byte(certString))
	assert.NoError(t, err, "error decoding certificate")
	assert.NotNil(t, cert, "certificate should not be nil")
	return cert
}

// Decode private key and check there was no error
func decodeKeyNoError(t *testing.T, keyStr string) *rsa.PrivateKey {
	key, err := decodeKey(keyStr)
	assert.NoError(t, err, "error decoding private key")
	assert.NotNil(t, key, "private key should not be nil")
	return key
}

// Create a valid shared secret, then apply a modification function to the contents and create a new file, then return its path
func createModifiedSecret(t *testing.T, modifier func(*sharedSecretOutput)) string {
	// Write an initial, valid secret to a buffer
	var buffer bytes.Buffer
	_, err := CreateAndWriteSharedSecret(&buffer)
	assert.NoError(t, err)

	// Modify the contents
	secret, err := json.ReadJSONFile[sharedSecretOutput](&buffer)
	assert.NoError(t, err)
	modifier(secret)

	// Write the modified secret to a file
	tempDir := t.TempDir()
	secretFile := filepath.Join(tempDir, "modified_secret.json")
	file, err := os.Create(secretFile)
	assert.NoError(t, err)
	defer file.Close()
	err = json.WriteJSONFile(file, secret)
	assert.NoError(t, err, "error writing modified secret to file")
	return secretFile
}
