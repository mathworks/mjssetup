// Copyright 2024-2025 The MathWorks, Inc.
package filekeytool_test

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/mathworks/mjssetup/internal/filekeytool"
	"github.com/mathworks/mjssetup/internal/keytool"
	mockCertCreator "github.com/mathworks/mjssetup/mocks/certificate"
	mockFileKeytool "github.com/mathworks/mjssetup/mocks/filekeytool"
	"github.com/mathworks/mjssetup/pkg/certificate"
	"github.com/mathworks/mjssetup/pkg/profile"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestCreateSharedSecret(t *testing.T) {
	outfile := "secret.json"
	kt, mocks := newWithMocks(t)

	// Set up mock secret creation
	secret := &certificate.SharedSecret{
		CertPEM: "test-cert",
		KeyPEM:  "test-key",
	}
	mocks.certCreator.EXPECT().CreateSharedSecret().Once().Return(secret, nil)

	// Verify that the expected secret gets written
	mocks.fileHandler.EXPECT().WriteJSON(outfile, secret).Once().Return(nil)
	err := kt.CreateSharedSecret(&keytool.CreateSharedSecretInputs{Outfile: outfile})
	require.NoError(t, err)
}

// Test the case where certificate creation errors
func TestCreateSharedSecretError(t *testing.T) {
	kt, mocks := newWithMocks(t)
	errMsg := "error creating shared secret"
	mocks.certCreator.EXPECT().CreateSharedSecret().Once().Return(nil, errors.New(errMsg))
	err := kt.CreateSharedSecret(&keytool.CreateSharedSecretInputs{Outfile: "secret.json"})
	assert.Error(t, err, "should get an error when secret creation errors")
	assert.Contains(t, err.Error(), errMsg, "error returned by CreateSharedSecret should contain the original error message")
}

// Test the case where writing to the output file errors
func TestCreateSharedSecretFileError(t *testing.T) {
	kt, mocks := newWithMocks(t)
	mocks.certCreator.EXPECT().CreateSharedSecret().Once().Return(&certificate.SharedSecret{}, nil)
	errMsg := "could not open secret file"
	mocks.fileHandler.EXPECT().WriteJSON(mock.Anything, mock.Anything).Once().Return(errors.New(errMsg))
	err := kt.CreateSharedSecret(&keytool.CreateSharedSecretInputs{Outfile: "secret.json"})
	assert.Error(t, err, "should get an error when opening the secret file errors")
	assert.Contains(t, err.Error(), errMsg, "error returned by CreateSharedSecret should contain the original error message")
}

func TestGenerateCertificate(t *testing.T) {
	outfile := "cert.json"
	secretfile := "secret.json"
	secret := &certificate.SharedSecret{
		CertPEM: "test",
		KeyPEM:  "test",
	}
	kt, mocks := newWithMocks(t)
	secretBytes := []byte("dummybytes")
	mocks.fileHandler.EXPECT().ReadFile(secretfile).Return(secretBytes, nil).Once()
	mocks.certCreator.EXPECT().LoadSharedSecret(secretBytes).Once().Return(secret, nil)

	// Set up mock certificate creation
	cert := &certificate.Certificate{
		ClientCert: "test-cert",
		ClientKey:  "test-key",
		ServerCert: "test-server-cert",
	}
	mocks.certCreator.EXPECT().GenerateCertificate(secret).Once().Return(cert, nil)

	// Verify that the expected certificate gets written
	mocks.fileHandler.EXPECT().WriteJSON(outfile, cert).Once().Return(nil)
	err := kt.GenerateCertificate(&keytool.GenerateCertificateInputs{
		Outfile:    outfile,
		SecretFile: secretfile,
	})
	require.NoError(t, err)
}

// Test the case where certificate generation fails because we could not read the shared secret
func TestGenerateCertificateSecretFileError(t *testing.T) {
	kt, mocks := newWithMocks(t)
	errMsg := "error reading secret file"
	mocks.fileHandler.EXPECT().ReadFile(mock.Anything).Return(nil, errors.New(errMsg))
	err := kt.GenerateCertificate(&keytool.GenerateCertificateInputs{SecretFile: "secret.json"})
	assert.Error(t, err, "should get an error when certificate generation errors")
	assert.Contains(t, err.Error(), errMsg, "error returned by GenerateCertificate should contain the original error message")
}

// Test the case where certificate generation fails because we could not load a shared secret from the file contents
func TestGenerateCertificateLoadSecretError(t *testing.T) {
	kt, mocks := newWithMocks(t)
	badSecret := []byte("invalid secret")
	secretFile := "secret.json"
	mocks.fileHandler.EXPECT().ReadFile(secretFile).Return(badSecret, nil).Once()

	errMsg := "error loading secret from file contents"
	mocks.certCreator.EXPECT().LoadSharedSecret(badSecret).Once().Return(nil, errors.New(errMsg))

	err := kt.GenerateCertificate(&keytool.GenerateCertificateInputs{SecretFile: "secret.json"})
	assert.Error(t, err, "should get an error when certificate generation errors")
	assert.Contains(t, err.Error(), errMsg, "error returned by GenerateCertificate should contain the original error message")
}

// Test the case where the GenerateCertificate call fails
func TestGenerateCertificateError(t *testing.T) {
	secretfile := "secret.json"

	// Ensure the previous steps succeed
	kt, mocks := newWithMocks(t)
	mocks.fileHandler.EXPECT().ReadFile(mock.Anything).Once().Return([]byte("secret"), nil)
	mocks.certCreator.EXPECT().LoadSharedSecret(mock.Anything).Once().Return(&certificate.SharedSecret{}, nil)

	// Expect the GenerateCertificate call to return an error
	errMsg := "failed to generate a certificate"
	mocks.certCreator.EXPECT().GenerateCertificate(mock.Anything).Once().Return(nil, errors.New(errMsg))
	err := kt.GenerateCertificate(&keytool.GenerateCertificateInputs{SecretFile: secretfile})
	assert.Error(t, err, "should get an error when certificate generation errors")
	assert.Contains(t, err.Error(), errMsg, "error returned by GenerateCertificate should contain the original error message")
}

// Test the case where certificate generation fails because we cannot open the certificate file
func TestGenerateCertificateWriteError(t *testing.T) {
	// Ensure the previous steps succeed
	secretfile := "secret.json"
	kt, mocks := newWithMocks(t)
	mocks.fileHandler.EXPECT().ReadFile(secretfile).Once().Return([]byte("secret"), nil)
	mocks.certCreator.EXPECT().LoadSharedSecret(mock.Anything).Once().Return(&certificate.SharedSecret{}, nil)
	mocks.certCreator.EXPECT().GenerateCertificate(mock.Anything).Once().Return(&certificate.Certificate{}, nil)

	// Expect writing the certificate file to error
	errMsg := "failed to open output file"
	mocks.fileHandler.EXPECT().WriteJSON(mock.Anything, mock.Anything).Return(errors.New(errMsg))
	err := kt.GenerateCertificate(&keytool.GenerateCertificateInputs{SecretFile: secretfile})
	assert.Error(t, err, "should get an error when certificate generation errors")
	assert.Contains(t, err.Error(), errMsg, "error returned by GenerateCertificate should contain the original error message")
}

func TestCreateProfileNoCert(t *testing.T) {
	name := "my-profile"
	host := "localhost"
	metadata := map[string]string{
		"field1": "value1",
	}
	expectedProfile := profile.CreateProfileWithMetadata(name, host, nil, metadata)

	outfile := "test-profile.json"
	kt, mocks := newWithMocks(t)
	mocks.fileHandler.EXPECT().WriteJSON(outfile, expectedProfile).Once().Return(nil)
	err := kt.CreateProfile(&keytool.CreateProfileInputs{
		Outfile:  outfile,
		Name:     name,
		Host:     host,
		Metadata: metadata,
	})
	require.NoError(t, err, "error creating profile")
}

func TestCreateProfileFromCert(t *testing.T) {
	// Create a mock certificate
	cert := &certificate.Certificate{
		ServerCert: "test-server",
		ClientCert: "test-cert",
		ClientKey:  "test-key",
	}

	// Set up mocks to load this certificate
	outfile := "test-profile.json"
	certfile := "cert.json"
	certBytes := []byte("dummy-cert-bytes")
	kt, mocks := newWithMocks(t)
	mocks.fileHandler.EXPECT().ReadFile(certfile).Return(certBytes, nil).Once()
	mocks.certCreator.EXPECT().LoadCertificate(certBytes).Return(cert, nil).Once()

	// Verify that the created profile contains this certificate
	name := "my-profile"
	host := "localhost"
	expectedProfile := profile.CreateProfile(name, host, cert)
	mocks.fileHandler.EXPECT().WriteJSON(outfile, expectedProfile).Once().Return(nil)
	err := kt.CreateProfile(&keytool.CreateProfileInputs{
		Outfile:  outfile,
		Name:     name,
		Host:     host,
		CertFile: certfile,
	})
	require.NoError(t, err, "error creating profile")
}

func TestCreateProfileFromSecret(t *testing.T) {
	// Create a mock secret
	secret := &certificate.SharedSecret{
		CertPEM: "test-cert",
		KeyPEM:  "test-key",
	}

	// Set up mock reader to load this secret
	outfile := "test-profile.json"
	secretfile := "secret.json"
	secretBytes := []byte("dummy-secret-bytes")
	kt, mocks := newWithMocks(t)
	mocks.fileHandler.EXPECT().ReadFile(secretfile).Return(secretBytes, nil).Once()

	// Set expected calls to generate a certificate for the profile
	cert := &certificate.Certificate{
		ServerCert: "test-server-cert",
		ClientCert: "test-client-cert",
		ClientKey:  "test-client-key",
	}
	mocks.certCreator.EXPECT().LoadSharedSecret(secretBytes).Once().Return(secret, nil)
	mocks.certCreator.EXPECT().GenerateCertificate(secret).Once().Return(cert, nil)

	// Verify that the created profile contains the generated certificate
	name := "my-profile"
	host := "localhost"
	expectedProfile := profile.CreateProfile(name, host, cert)
	mocks.fileHandler.EXPECT().WriteJSON(outfile, expectedProfile).Return(nil).Once()
	err := kt.CreateProfile(&keytool.CreateProfileInputs{
		Outfile:    outfile,
		Name:       name,
		Host:       host,
		SecretFile: secretfile,
		UseSecret:  true,
	})
	require.NoError(t, err, "error creating profile")
}

func TestGenerateMetricsCertificatesAndKeys(t *testing.T) {
	tmpDir := t.TempDir()
	outDir := filepath.Join(tmpDir, "outdir") // Should be created automatically!
	kt, mocks := newWithMocks(t)
	mocks.fileHandler.EXPECT().EnsureDirExists(outDir).Return(nil).Once()
	verifyGenerateMetricsCertificatesAndKeys(t, kt, mocks, outDir, outDir)
}

// When no outdir is provided, use the current working directory
func TestGenerateMetricsCertificatesAndKeysNoOutdir(t *testing.T) {
	kt, mocks := newWithMocks(t)
	cwd := "my/current/dir"
	mocks.fileHandler.EXPECT().GetCwd().Return(cwd, nil).Once()
	verifyGenerateMetricsCertificatesAndKeys(t, kt, mocks, "", cwd)
}

func verifyGenerateMetricsCertificatesAndKeys(t *testing.T, kt keytool.Keytool, mocks *mocks, inputOutdir, expectedOutdir string) {
	jobManagerHost := "dummyhostname"

	// Set up mock secret creation
	secret := &certificate.SharedSecret{
		CertPEM: "test-ca-cert",
		KeyPEM:  "test-ca-key",
	}

	// Set up mock certificates
	jobManagerCert := &certificate.Certificate{
		ClientCert: "test-jobmanager-cert",
		ClientKey:  "test-jobmanager-key",
		ServerCert: "test-server-cert",
	}
	prometheusCert := &certificate.Certificate{
		ClientCert: "test-prometheus-cert",
		ClientKey:  "test-prometheus-key",
		ServerCert: "test-server-cert",
	}

	// Expect that the certCreator will generate the CA, job manager, and prometheus cert/key
	// with a call to GenerateMetricsCertificatesAndKeys
	mocks.certCreator.EXPECT().CreateSharedSecret().Once().Return(secret, nil)
	mocks.certCreator.EXPECT().GenerateCertificateWithHostname(secret, jobManagerHost).Once().Return(jobManagerCert, nil)
	mocks.certCreator.EXPECT().GenerateCertificate(secret).Once().Return(prometheusCert, nil)

	// Expect files to be written
	mocks.fileHandler.EXPECT().WriteText(filepath.Join(expectedOutdir, "ca.crt"), secret.CertPEM).Return(nil).Once()
	mocks.fileHandler.EXPECT().WriteText(filepath.Join(expectedOutdir, "ca.key"), secret.KeyPEM).Return(nil).Once()
	mocks.fileHandler.EXPECT().WriteText(filepath.Join(expectedOutdir, "jobmanager.crt"), jobManagerCert.ClientCert).Return(nil).Once()
	mocks.fileHandler.EXPECT().WriteText(filepath.Join(expectedOutdir, "jobmanager.key"), jobManagerCert.ClientKey).Return(nil).Once()
	mocks.fileHandler.EXPECT().WriteText(filepath.Join(expectedOutdir, "prometheus.crt"), prometheusCert.ClientCert).Return(nil).Once()
	mocks.fileHandler.EXPECT().WriteText(filepath.Join(expectedOutdir, "prometheus.key"), prometheusCert.ClientKey).Return(nil).Once()

	err := kt.GenerateMetricsCertificatesAndKeys(&keytool.GenerateMetricsCertificatesAndKeysInputs{
		OutDir:         inputOutdir,
		JobManagerHost: jobManagerHost,
	})
	require.NoError(t, err)
}

type mocks struct {
	certCreator *mockCertCreator.Creator
	fileHandler *mockFileKeytool.FileHandler
}

// Create a dummy Keytool that use mocks
func newWithMocks(t *testing.T) (keytool.Keytool, *mocks) {
	mockCert := mockCertCreator.NewCreator(t)
	mockFileHandler := mockFileKeytool.NewFileHandler(t)
	return filekeytool.New(mockFileHandler, mockCert), &mocks{
		certCreator: mockCert,
		fileHandler: mockFileHandler,
	}
}
