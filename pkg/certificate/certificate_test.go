// Copyright 2023-2024 The MathWorks, Inc.
package certificate

import (
	"crypto/x509"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateSharedSecret(t *testing.T) {
	verifyCreateSharedSecret(t)
}

func TestGenerateCertificate(t *testing.T) {
	secret := verifyCreateSharedSecret(t)
	verifyGenerateCertificate(t, secret)
}

// Check for errors if the shared secret has no key
func TestGenerateCertificateMissingKey(t *testing.T) {
	secret := verifyCreateSharedSecret(t)
	secret.key = nil
	_, err := New().GenerateCertificate(secret)
	assert.Error(t, err, "expected error when shared secret has no key")
}

// Check for errors if the shared secret has no certificate
func TestGenerateCertificateMissingCert(t *testing.T) {
	secret := verifyCreateSharedSecret(t)
	secret.cert = nil
	_, err := New().GenerateCertificate(secret)
	assert.Error(t, err, "expected error when shared secret has no cert")
}

// Check we get an error if the shared secret is expired
func TestGenerateCertificateExpiredSecret(t *testing.T) {
	secret := verifyCreateSharedSecret(t)
	finalDate := time.Now().AddDate(0, 0, -10)
	initDate := finalDate.AddDate(0, 0, -10)
	secret.cert.NotBefore = initDate
	secret.cert.NotAfter = finalDate
	_, err := New().GenerateCertificate(secret)
	assert.Error(t, err, "expected error when shared secret certificate is expired")
}

// Check for error when attempting to load a shared secret with an unparsable key
func TestLoadSharedSecretErrorBadKey(t *testing.T) {
	secret := verifyCreateSharedSecret(t)
	secret.KeyPEM = "invalid"
	secretBytes, err := json.Marshal(secret)
	require.NoError(t, err, "error marshaling shared secret")
	_, err = New().LoadSharedSecret(secretBytes)
	assert.Error(t, err, "should get an error when loading shared secret with invalid key PEM")
}

// Check for error when attempting to load a shared secret with an unparsable certificate
func TestLoadSharedSecretErrorBadCert(t *testing.T) {
	secret := verifyCreateSharedSecret(t)
	secret.CertPEM = "invalid"
	secretBytes, err := json.Marshal(secret)
	require.NoError(t, err, "error marshaling shared secret")
	_, err = New().LoadSharedSecret(secretBytes)
	assert.Error(t, err, "should get an error when loading shared secret with invalid cert PEM")
}

// Create a shared secret and verify that it was created correctly
func verifyCreateSharedSecret(t *testing.T) *SharedSecret {
	secret, err := New().CreateSharedSecret()
	require.NoError(t, err, "error creating shared secret")

	// Check the contents of the certificate
	assert.True(t, secret.cert.IsCA, "certificate should be a CA certificate")
	require.NoError(t, secret.cert.CheckSignatureFrom(secret.cert), "certificate should be self-signed")
	verifyExpiryDate(t, secret.cert, expiryDays)

	// Verify that we can marshal the secret and load it back in
	secretBytes, err := json.Marshal(secret)
	require.NoError(t, err, "error marshaling shared secret")
	loadedSecret, err := New().LoadSharedSecret(secretBytes)
	require.NoError(t, err, "error loading shared secret from bytes")

	// Check that the loaded secret matches the original secret
	assert.Equal(t, secret.cert, loadedSecret.cert, "loaded secret certificate does not match original secret")
	assert.Equal(t, secret.key, loadedSecret.key, "loaded secret key does not match original secret")
	assert.Equal(t, secret.CertPEM, loadedSecret.CertPEM, "loaded secret certificate PEM does not match original secret")
	assert.Equal(t, secret.KeyPEM, loadedSecret.KeyPEM, "loaded secret key PEM does not match original secret")

	return secret
}

// Generate a certificate and verify that it was created correctly
func verifyGenerateCertificate(t *testing.T, secret *SharedSecret) {
	cert, err := New().GenerateCertificate(secret)
	require.NoError(t, err, "error running GenerateCertificate")

	_, err = decodeKey(cert.ClientKey)
	require.NoError(t, err, "error decoding certificate key")
	certificate, err := decodeCert(cert.ClientCert)
	require.NoError(t, err, "error decoding certificate")
	require.False(t, certificate.IsCA, "certificate should not be a CA certificate")
	verifyExpiryDate(t, certificate, expiryDays)

	// Check the CA certificate PEM matches the certificate PEM of the original shared secret
	require.Equal(t, secret.CertPEM, cert.ServerCert, "serverCert in signed certificate file should match CA cert")

	// Check the client certificate was signed by the CA certificate
	require.NoError(t, certificate.CheckSignatureFrom(secret.cert), "certificate should be signed by CA certificate in shared secret")
}

// Verify that a certificate has the expected expiry date
func verifyExpiryDate(t *testing.T, cert *x509.Certificate, expectedDays int) {
	expiryLength := cert.NotAfter.Sub(cert.NotBefore)
	expiryLengthInDays := int(expiryLength.Hours() / 24)
	require.Equal(t, expiryLengthInDays, expectedDays, "certificate does not have the expected expiry date")
}
