// Copyright 2024 The MathWorks, Inc.
package keytool

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	mockCertCreator "github.com/mathworks/mjssetup/mocks/certificate"
	"github.com/mathworks/mjssetup/pkg/certificate"
	"github.com/mathworks/mjssetup/pkg/profile"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	keytool := New()
	require.NotNil(t, keytool, "object returned by New should not be nil")
}

func TestCreateSharedSecret(t *testing.T) {
	outfile := "secret.json"
	keytool, byteWriter, certCreator := getKeytoolWithMockWriter(t, outfile)

	// Set up mock secret creation
	secret := &certificate.SharedSecret{
		CertPEM: "test-cert",
		KeyPEM:  "test-key",
	}
	certCreator.EXPECT().CreateSharedSecret().Once().Return(secret, nil)

	// Verify that the expected secret gets written
	err := keytool.CreateSharedSecret(&CreateSharedSecretInputs{Outfile: outfile})
	require.NoError(t, err)
	verifyStructWritten(t, secret, byteWriter)
}

// Test the case where certificate creation errors
func TestCreateSharedSecretError(t *testing.T) {
	keytool, _, certCreator := getKeytoolWithMockWriter(t, "")
	errMsg := "error creating shared secret"
	certCreator.EXPECT().CreateSharedSecret().Once().Return(nil, errors.New(errMsg))
	err := keytool.CreateSharedSecret(&CreateSharedSecretInputs{Outfile: "secret.json"})
	assert.Error(t, err, "should get an error when secret creation errors")
	assert.Contains(t, err.Error(), errMsg, "error returned by CreateSharedSecret should contain the original error message")
}

// Test the case where opening the output file errors
func TestCreateSharedSecretFileError(t *testing.T) {
	keytool, _, certCreator := getKeytoolWithMockWriter(t, "")
	certCreator.EXPECT().CreateSharedSecret().Once().Return(&certificate.SharedSecret{}, nil)
	errMsg := "could not open secret file"
	keytool.openFileForWrite = func(string) (io.WriteCloser, error) {
		return nil, errors.New(errMsg)
	}
	err := keytool.CreateSharedSecret(&CreateSharedSecretInputs{Outfile: "secret.json"})
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
	secretBytes, err := json.Marshal(secret)
	require.NoError(t, err, "error marshalling secret")
	keytool, byteWriter, certCreator := getKeytoolWithMockReader(t, outfile, secretfile, secretBytes)
	certCreator.EXPECT().LoadSharedSecret(secretBytes).Once().Return(secret, nil)

	// Set up mock certificate creation
	cert := &certificate.Certificate{
		ClientCert: "test-cert",
		ClientKey:  "test-key",
		ServerCert: "test-server-cert",
	}
	certCreator.EXPECT().GenerateCertificate(secret).Once().Return(cert, nil)

	// Verify that the expected certificate gets written
	err = keytool.GenerateCertificate(&GenerateCertificateInputs{
		Outfile:    outfile,
		SecretFile: secretfile,
	})
	require.NoError(t, err)
	verifyStructWritten(t, cert, byteWriter)
}

// Test the case where certificate generation fails because we could not read the shared secret
func TestGenerateCertificateSecretFileError(t *testing.T) {
	keytool, _, _ := getKeytoolWithMockWriter(t, "")
	errMsg := "error reading secret file"
	keytool.readFromFile = func(string) ([]byte, error) {
		return []byte{}, errors.New(errMsg)
	}
	err := keytool.GenerateCertificate(&GenerateCertificateInputs{SecretFile: "secret.json"})
	assert.Error(t, err, "should get an error when certificate generation errors")
	assert.Contains(t, err.Error(), errMsg, "error returned by GenerateCertificate should contain the original error message")
}

// Test the case where certificate generation fails because we could not load a shared secret from the file contents
func TestGenerateCertificateLoadSecretError(t *testing.T) {
	keytool, _, certCreator := getKeytoolWithMockWriter(t, "")
	badSecret := []byte("invalid secret")
	keytool.readFromFile = func(string) ([]byte, error) {
		return badSecret, nil
	}
	errMsg := "error loading secret from file contents"
	certCreator.EXPECT().LoadSharedSecret(badSecret).Once().Return(nil, errors.New(errMsg))
	err := keytool.GenerateCertificate(&GenerateCertificateInputs{SecretFile: "secret.json"})
	assert.Error(t, err, "should get an error when certificate generation errors")
	assert.Contains(t, err.Error(), errMsg, "error returned by GenerateCertificate should contain the original error message")
}

// Test the case where the GenerateCertificate call fails
func TestGenerateCertificateError(t *testing.T) {
	outfile := "cert.json"
	secretfile := "secret.json"

	// Ensure the previous steps succeed
	keytool, _, certCreator := getKeytoolWithMockReader(t, outfile, secretfile, []byte("test"))
	certCreator.EXPECT().LoadSharedSecret(mock.Anything).Once().Return(&certificate.SharedSecret{}, nil)

	// Expect the GenerateCertificate call to return an error
	errMsg := "failed to generate a certificate"
	certCreator.EXPECT().GenerateCertificate(mock.Anything).Once().Return(nil, errors.New(errMsg))
	err := keytool.GenerateCertificate(&GenerateCertificateInputs{SecretFile: secretfile})
	assert.Error(t, err, "should get an error when certificate generation errors")
	assert.Contains(t, err.Error(), errMsg, "error returned by GenerateCertificate should contain the original error message")
}

// Test the case where certificate generation fails because we cannot open the certificate file
func TestGenerateCertificateWriteError(t *testing.T) {
	outfile := "cert.json"
	secretfile := "secret.json"

	// Ensure the previous steps succeed
	keytool, _, certCreator := getKeytoolWithMockReader(t, outfile, secretfile, []byte("test"))
	certCreator.EXPECT().LoadSharedSecret(mock.Anything).Once().Return(&certificate.SharedSecret{}, nil)
	certCreator.EXPECT().GenerateCertificate(mock.Anything).Once().Return(&certificate.Certificate{}, nil)

	// Expect openFileForWrite to error
	errMsg := "failed to open output file"
	keytool.openFileForWrite = func(string) (io.WriteCloser, error) {
		return nil, errors.New(errMsg)
	}
	err := keytool.GenerateCertificate(&GenerateCertificateInputs{SecretFile: secretfile})
	assert.Error(t, err, "should get an error when certificate generation errors")
	assert.Contains(t, err.Error(), errMsg, "error returned by GenerateCertificate should contain the original error message")
}

func TestCreateProfileNoCert(t *testing.T) {
	name := "my-profile"
	host := "localhost"
	expectedProfile := profile.CreateProfile(name, host, nil)

	outfile := "test-profile.json"
	keytool, byteWriter, _ := getKeytoolWithMockWriter(t, outfile)
	err := keytool.CreateProfile(&CreateProfileInputs{
		Outfile: outfile,
		Name:    name,
		Host:    host,
	})
	require.NoError(t, err, "error creating profile")
	verifyStructWritten(t, expectedProfile, byteWriter)
}

func TestCreateProfileFromCert(t *testing.T) {
	// Create a mock certificate
	cert := &certificate.Certificate{
		ServerCert: "test-server",
		ClientCert: "test-cert",
		ClientKey:  "test-key",
	}

	// Set up mock reader to load this certificate
	outfile := "test-profile.json"
	certfile := "cert.json"
	certBytes, err := json.Marshal(cert)
	require.NoError(t, err, "error marshaling certificate")
	keytool, byteWriter, _ := getKeytoolWithMockReader(t, outfile, certfile, certBytes)

	// Verify that the created profile contains this certificate
	name := "my-profile"
	host := "localhost"
	expectedProfile := profile.CreateProfile(name, host, cert)
	err = keytool.CreateProfile(&CreateProfileInputs{
		Outfile:  outfile,
		Name:     name,
		Host:     host,
		CertFile: certfile,
	})
	require.NoError(t, err, "error creating profile")
	verifyStructWritten(t, expectedProfile, byteWriter)
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
	secretBytes, err := json.Marshal(secret)
	require.NoError(t, err, "error marshaling secret")
	keytool, byteWriter, certCreator := getKeytoolWithMockReader(t, outfile, secretfile, secretBytes)

	// Set expected calls to generate a certificate for the profile
	cert := &certificate.Certificate{
		ServerCert: "test-server-cert",
		ClientCert: "test-client-cert",
		ClientKey:  "test-client-key",
	}
	certCreator.EXPECT().LoadSharedSecret(secretBytes).Once().Return(secret, nil)
	certCreator.EXPECT().GenerateCertificate(secret).Once().Return(cert, nil)

	// Verify that the created profile contains the generated certificate
	name := "my-profile"
	host := "localhost"
	expectedProfile := profile.CreateProfile(name, host, cert)
	err = keytool.CreateProfile(&CreateProfileInputs{
		Outfile:    outfile,
		Name:       name,
		Host:       host,
		SecretFile: secretfile,
		UseSecret:  true,
	})
	require.NoError(t, err, "error creating profile")
	verifyStructWritten(t, expectedProfile, byteWriter)
}

func TestGenerateMetricsCertificatesAndKeys(t *testing.T) {
	tmpDir := t.TempDir()
	outDir := filepath.Join(tmpDir, "outdir") // Should be created automatically!
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
	keytool, certCreator := getKeytoolWithMockCertCreator(t)
	certCreator.EXPECT().CreateSharedSecret().Once().Return(secret, nil)
	certCreator.EXPECT().GenerateCertificateWithHostname(secret, jobManagerHost).Once().Return(jobManagerCert, nil)
	certCreator.EXPECT().GenerateCertificate(secret).Once().Return(prometheusCert, nil)
	err := keytool.GenerateMetricsCertificatesAndKeys(&GenerateMetricsCertificatesAndKeysInputs{
		OutDir:         outDir,
		JobManagerHost: jobManagerHost,
	})
	require.NoError(t, err)

	// Verify that the expected certificate/key files get written
	verifyTextWritten(t, filepath.Join(outDir, "ca.crt"), secret.CertPEM)
	verifyTextWritten(t, filepath.Join(outDir, "ca.key"), secret.KeyPEM)
	verifyTextWritten(t, filepath.Join(outDir, "jobmanager.crt"), jobManagerCert.ClientCert)
	verifyTextWritten(t, filepath.Join(outDir, "jobmanager.key"), jobManagerCert.ClientKey)
	verifyTextWritten(t, filepath.Join(outDir, "prometheus.crt"), prometheusCert.ClientCert)
	verifyTextWritten(t, filepath.Join(outDir, "prometheus.key"), prometheusCert.ClientKey)
}

// Test the readFromFile function
func TestReadFromFile(t *testing.T) {
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test.txt")
	fileContent := "my file contents"
	err := os.WriteFile(tmpFile, []byte(fileContent), 0600)
	require.NoError(t, err, "error writing test file")
	gotBytes, err := readFromFile(tmpFile)
	require.NoError(t, err, "error reading from file")
	assert.Equal(t, fileContent, string(gotBytes), "readFromFile returned unexpected file contents")
}

func TestReadFromFileError(t *testing.T) {
	tmpDir := t.TempDir()
	nonExistentPath := filepath.Join(tmpDir, "test.txt")
	_, err := readFromFile(nonExistentPath)
	assert.Error(t, err, "expected an error when running readFromFile on nonexistent file")
}

// Test the openFileForWrite function
func TestOpenFileForWrite(t *testing.T) {
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "to-write.txt")
	gotWriter, err := openFileForWrite(tmpFile)
	require.NoError(t, err, "error opening file for write")
	t.Cleanup(func() {
		err := gotWriter.Close()
		require.NoError(t, err, "error closing file")
	})
	require.NotNil(t, gotWriter, "writer returned from openFileForWrite should not be nil")
}

// Test the writeTextFile function
func TestWriteTextFile(t *testing.T) {
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "to-write.txt")
	textToWrite := "This is a test string"
	err := writeTextFile(tmpFile, textToWrite)
	require.NoError(t, err, "error writing text file")
	verifyTextWritten(t, tmpFile, textToWrite)
}

// Verify that the expected text is written to a file
func verifyTextWritten(t *testing.T, file string, text string) {
	content, err := os.ReadFile(file)
	require.NoError(t, err, "error reading text file")
	assert.Equalf(t, text, string(content), "wrong text written to file %s", file)
}

// Verify that the expected struct was written to a byte buffer
func verifyStructWritten[T any](t *testing.T, expectedStruct *T, byteWriter *bytes.Buffer) {
	var gotStruct T
	err := json.Unmarshal(byteWriter.Bytes(), &gotStruct)
	require.NoError(t, err, "error unmarshalling written bytes")
	assert.Equal(t, expectedStruct, &gotStruct, "written struct did not match expected struct")
}

// Create a dummy Keytool that writes to a byte buffer instead of a real file and uses mocked-out certificate and profile creators
func getKeytoolWithMockWriter(t *testing.T, expectedOutfile string) (*keytoolImpl, *bytes.Buffer, *mockCertCreator.Creator) {
	byteWriter := bytes.NewBuffer([]byte{})
	mockCert := mockCertCreator.NewCreator(t)
	return &keytoolImpl{
		openFileForWrite: func(filename string) (io.WriteCloser, error) {
			assert.Equal(t, expectedOutfile, filename, "received call to write to unexpected filename")
			return newByteBufferCloser(byteWriter), nil
		},
		certCreator: mockCert,
	}, byteWriter, mockCert
}

// Create a dummy Keytool that writes to a byte buffer and has a mocked-out readFromFile function
func getKeytoolWithMockReader(t *testing.T, expectedOutfile, expectedInFile string, readBytes []byte) (*keytoolImpl, *bytes.Buffer, *mockCertCreator.Creator) {
	keytool, byteWriter, mockCert := getKeytoolWithMockWriter(t, expectedOutfile)

	// Mock out the file reading function to return the given data
	keytool.readFromFile = func(filename string) ([]byte, error) {
		assert.Equal(t, expectedInFile, filename, "received call to read from unexpected input file")
		return readBytes, nil
	}

	return keytool, byteWriter, mockCert
}

// Create a dummy Keytool that uses a mocked-out certificate creator
func getKeytoolWithMockCertCreator(t *testing.T) (*keytoolImpl, *mockCertCreator.Creator) {
	mockCert := mockCertCreator.NewCreator(t)
	return &keytoolImpl{
		certCreator: mockCert,
	}, mockCert
}

// Byte buffer that implements the io.WriteCloser interface; this can be used in place of a real file writer
type byteBufferCloser struct {
	byteWriter *bytes.Buffer
}

func newByteBufferCloser(byteWriter *bytes.Buffer) *byteBufferCloser {
	return &byteBufferCloser{
		byteWriter: byteWriter,
	}
}
func (b *byteBufferCloser) Write(data []byte) (int, error) {
	return b.byteWriter.Write(data)
}
func (b *byteBufferCloser) Close() error {
	// No-op
	return nil
}
