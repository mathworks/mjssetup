// Copyright 2023-2024 The MathWorks, Inc.
package profile

import (
	"testing"

	"github.com/mathworks/mjssetup/pkg/certificate"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateProfileNoCert(t *testing.T) {
	name := "my-profile"
	host := "localhost:8000"
	prof := CreateProfile(name, host, nil)
	verifyProfileFields(t, prof, name, host)
	assert.Empty(t, prof.SchedulerComponent.Certificate, "certificate field should be empty when no cert provided")
	assert.Empty(t, prof.SchedulerComponent.ClientPrivateKey, "client private key field should be empty when no cert provided")
	assert.Empty(t, prof.SchedulerComponent.ClientCertificate, "client certificate field should be empty when no cert provided")
}

func TestCreateProfileWithCert(t *testing.T) {
	name := "my-profile"
	host := "localhost:8000"

	// Create a certificate to use
	secret, err := certificate.New().CreateSharedSecret()
	require.NoError(t, err, "error creating shared secret")
	cert, err := certificate.New().GenerateCertificate(secret)
	require.NoError(t, err, "error creating certificate")

	prof := CreateProfile(name, host, cert)
	verifyProfileFields(t, prof, name, host)
	assert.Equal(t, cert.ServerCert, prof.SchedulerComponent.Certificate, "profile certificate does not match input server certificate")
	assert.Equal(t, cert.ClientCert, prof.SchedulerComponent.ClientCertificate, "profile client certificate does not match input client certificate")
	assert.Equal(t, cert.ClientKey, prof.SchedulerComponent.ClientPrivateKey, "profile client private key does not match input client private key")
}

func verifyProfileFields(t *testing.T, prof *Profile, expectedName, expectedHost string) {
	assert.Equal(t, 1, prof.Version, "profile version should be 1")
	assert.Equal(t, "MJS", prof.ClusterType, "cluster type should be MJS")
	assert.Equal(t, expectedName, prof.Name, "profile does not have expected Name field")
	assert.Equal(t, expectedHost, prof.SchedulerComponent.Host, "profile does not have expected Host field")
}
