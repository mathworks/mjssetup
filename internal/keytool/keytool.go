// Copyright 2025 The MathWorks, Inc.
package keytool

// Interface for creating certificates and profiles
type Keytool interface {
	CreateSharedSecret(inputs *CreateSharedSecretInputs) error
	GenerateCertificate(inputs *GenerateCertificateInputs) error
	CreateProfile(inputs *CreateProfileInputs) error
	GenerateMetricsCertificatesAndKeys(inputs *GenerateMetricsCertificatesAndKeysInputs) error
}

// Input arguments for CreateSharedSecret
type CreateSharedSecretInputs struct {
	Outfile string
}

// Input arguments for GenerateCertificate
type GenerateCertificateInputs struct {
	Outfile    string
	SecretFile string
}

// Input arguments for CreateProfile
type CreateProfileInputs struct {
	Outfile    string
	Name       string
	Host       string
	CertFile   string
	SecretFile string
	UseSecret  bool
	Metadata   map[string]string
}

// Input arguments for GenerateMetricsCertificatesAndKeys
type GenerateMetricsCertificatesAndKeysInputs struct {
	OutDir         string
	JobManagerHost string
}
