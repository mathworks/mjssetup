// Copyright 2023 The MathWorks, Inc.
package profile

import (
	"bytes"
	"errors"
	"testing"

	"github.com/mathworks/mjssetup/internal/json"
	"github.com/mathworks/mjssetup/pkg/certificate"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateProfile(t *testing.T) {
	certfile := "test_cert.json"
	cert := certificate.Certificate{
		ClientCert: "mycert",
		ClientKey:  "mykey",
		ServerCert: "servercert",
	}

	// Create a dummy FileCreator that writes the profile to a byte buffer
	var profileBuffer bytes.Buffer
	profileFile := "test_profile.json"
	profileCreator := newDummyProfileCreator(t, certfile, profileFile, &profileBuffer, &cert)

	// Verify that we can successfully create the profile
	inputs := CreateProfileInputs{
		Name:     "my-profile",
		Host:     "test-host",
		CertFile: certfile,
		Outfile:  "test_profile.json",
	}
	createdProfile := verifyCreateProfile(t, profileCreator, &inputs, &profileBuffer)
	verifyProfileCertificate(t, &cert, createdProfile)

	// Check that if a secret file is provided but UseSecret is false, the secret gets ignored in favour of the certificate
	inputsWithSecret := CreateProfileInputs{
		Name:       "my-profile",
		Host:       "test-host",
		CertFile:   certfile,
		SecretFile: "my-secret.json",
		Outfile:    "test_profile.json",
		UseSecret:  false,
	}
	profileBuffer.Reset()
	verifyCreateProfile(t, profileCreator, &inputsWithSecret, &profileBuffer)
}

// Create a FileCreator that writes the profile to a buffer instead of writing to a file
func newDummyProfileCreator(t *testing.T, certfile, profileFile string, profileBuffer *bytes.Buffer, cert *certificate.Certificate) *FileCreator {
	return &FileCreator{
		readCertificateFromFile: func(infile string) (*certificate.Certificate, error) {
			assert.Equal(t, certfile, infile, "Unexpected certificate input file")
			return cert, nil
		},
		writeProfileToFile: func(outfile string, outputProfile *profile) error {
			assert.Equal(t, profileFile, outfile, "Unexpected profile output file")
			return json.WriteJSONFile(profileBuffer, outputProfile)
		},
		generateCertificateFromSecret: func(string) (*certificate.Certificate, error) {
			t.Error("generateCertificateFromSecret should not have been called")
			return nil, nil
		},
	}
}

// Check we get an error in CreateProfile when there is an error reading the certificate file
func TestCreateProfileCertificateReadError(t *testing.T) {
	// Create a dummy profile creator that errors when we try to read the certificate
	errMsg := "error reading certificate"
	profileCreator := FileCreator{
		readCertificateFromFile: func(_ string) (*certificate.Certificate, error) {
			return nil, errors.New(errMsg)
		},
	}
	err := profileCreator.CreateProfile(&CreateProfileInputs{
		CertFile: "mycert.json",
	})
	require.Error(t, err, "Expected an error when certificate reading fails")
	require.Contains(t, err.Error(), errMsg, "Error message should contain error from file reading")
}

// Check we get an error in CreateProfile when there is an error writing the profile
func TestCreateProfileWriteError(t *testing.T) {
	certfile := "test_cert.json"
	cert := certificate.Certificate{
		ClientCert: "mycert",
		ClientKey:  "mykey",
		ServerCert: "servercert",
	}

	// Create a dummy FileCreator that can successfully return the certificate
	var profileBuffer bytes.Buffer
	profileFile := "test_profile.json"
	profileCreator := newDummyProfileCreator(t, certfile, profileFile, &profileBuffer, &cert)

	// Modify the write function to error when we try to write the profile
	errMsg := "error writing profile"
	profileCreator.writeProfileToFile = func(_ string, _ *profile) error {
		return errors.New(errMsg)
	}

	err := profileCreator.CreateProfile(&CreateProfileInputs{
		Outfile:  "test",
		CertFile: certfile,
		Name:     "test",
		Host:     "test",
	})
	require.Error(t, err, "Expected an error when profile writing fails")
	require.Contains(t, err.Error(), errMsg, "Error message should contain error from file writing")
}

// Check we can create a profile without a certificate
func TestCreateProfileNoCertificate(t *testing.T) {

	// Create a dummy FileCreator that writes the profile to a byte buffer
	var profileBuffer bytes.Buffer
	outfile := "profile_without_cert.json"
	profileCreator := newDummyProfileCreator(t, "", outfile, &profileBuffer, &certificate.Certificate{})

	inputs := CreateProfileInputs{
		Outfile: outfile,
		Host:    "myhost",
		Name:    "mycluster",
	}
	profile := verifyCreateProfile(t, profileCreator, &inputs, &profileBuffer)

	// Certificate fields on the profile object should be empty
	require.Empty(t, profile.SchedulerComponent.Certificate, "Certificate field should be empty")
	require.Empty(t, profile.SchedulerComponent.ClientCertificate, "ClientCertificate field should be empty")
	require.Empty(t, profile.SchedulerComponent.ClientPrivateKey, "ClientPrivateKey field should be empty")
}

func verifyCreateProfile(t *testing.T, profileCreator *FileCreator, inputs *CreateProfileInputs, profileBuffer *bytes.Buffer) *profile {
	err := profileCreator.CreateProfile(inputs)
	assert.NoError(t, err, "error creating profile")

	// Check the profile has the expected contents
	loadedProfile, err := json.ReadJSONFile[profile](profileBuffer)
	assert.NoErrorf(t, err, "error loading profile from JSON file %s", inputs.Outfile)
	require.Equal(t, loadedProfile.Name, inputs.Name, "unexpected profile name")
	require.Equal(t, loadedProfile.ClusterType, "MJS", "unexpected profile cluster type")
	require.Equal(t, loadedProfile.SchedulerComponent.Host, inputs.Host, "unexpected profile host")
	return loadedProfile
}

func verifyProfileCertificate(t *testing.T, cert *certificate.Certificate, createdProfile *profile) {
	require.Equal(t, createdProfile.SchedulerComponent.ClientCertificate, cert.ClientCert, "client certificate in profile should match input client certifcate")
	require.Equal(t, createdProfile.SchedulerComponent.ClientPrivateKey, cert.ClientKey, "client key in profile should match input client key")
	require.Equal(t, createdProfile.SchedulerComponent.Certificate, cert.ServerCert, "certificate in profile should match input server certificate")
}

func TestCreateProfileFromSecret(t *testing.T) {
	inputFile := "test_cert.json"
	cert := certificate.Certificate{
		ClientCert: "mycert",
		ClientKey:  "mykey",
		ServerCert: "servercert",
	}

	// Create a dummy FileCreator that mocks generating a certificate from a secret
	var profileBuffer bytes.Buffer
	profileFile := "test_profile.json"
	profileCreator := newDummySecretProfileCreator(t, inputFile, profileFile, &profileBuffer, &cert)

	// Verify that we can successfully create the profile
	inputs := CreateProfileInputs{
		Name:       "my-profile",
		Host:       "test-host",
		SecretFile: inputFile,
		Outfile:    "test_profile.json",
		UseSecret:  true,
	}
	createdProfile := verifyCreateProfile(t, profileCreator, &inputs, &profileBuffer)
	verifyProfileCertificate(t, &cert, createdProfile)
}

// Create a FileCreator that mocks generating a certificate from a shared secret file and writes the profile to a byte buffer
func newDummySecretProfileCreator(t *testing.T, secretfile, profileFile string, profileBuffer *bytes.Buffer, cert *certificate.Certificate) *FileCreator {
	return &FileCreator{
		readCertificateFromFile: func(infile string) (*certificate.Certificate, error) {
			t.Error("readCertificateFromFile should not have been called")
			return nil, nil
		},
		writeProfileToFile: func(outfile string, outputProfile *profile) error {
			assert.Equal(t, profileFile, outfile, "Unexpected profile output file")
			return json.WriteJSONFile(profileBuffer, outputProfile)
		},
		generateCertificateFromSecret: func(inputFile string) (*certificate.Certificate, error) {
			assert.Equal(t, secretfile, inputFile, "Unexpected secret input file")
			return cert, nil
		},
	}
}
