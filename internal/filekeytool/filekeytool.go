// Implementation of FileKeytool that uses the filesystem.
// Copyright 2025 The MathWorks, Inc.
package filekeytool

import (
	"path/filepath"

	"github.com/mathworks/mjssetup/internal/keytool"
	"github.com/mathworks/mjssetup/pkg/certificate"
	"github.com/mathworks/mjssetup/pkg/profile"
)

type FileHandler interface {
	ReadFile(filename string) ([]byte, error)
	WriteText(filename string, txt string) error
	WriteJSON(filenames string, objToWrite any) error
	EnsureDirExists(dirname string) error
	GetCwd() (string, error)
}

type FileKeytool struct {
	fileHandler FileHandler
	certCreator certificate.Creator
}

// Construct new FileKeytool
func New(fileHandler FileHandler, certCreator certificate.Creator) *FileKeytool {
	return &FileKeytool{
		fileHandler: fileHandler,
		certCreator: certCreator,
	}
}

// Create a shared secret file
func (k *FileKeytool) CreateSharedSecret(inputs *keytool.CreateSharedSecretInputs) error {
	secret, err := k.certCreator.CreateSharedSecret()
	if err != nil {
		return err
	}
	return k.fileHandler.WriteJSON(inputs.Outfile, secret)
}

// Create a certificate file
func (k *FileKeytool) GenerateCertificate(inputs *keytool.GenerateCertificateInputs) error {
	cert, err := k.generateCertificateFromSecretfile(inputs.SecretFile)
	if err != nil {
		return err
	}
	return k.fileHandler.WriteJSON(inputs.Outfile, cert)
}

// Create a cluster profile file
func (k *FileKeytool) CreateProfile(inputs *keytool.CreateProfileInputs) error {
	var cert *certificate.Certificate
	var err error
	if inputs.UseSecret {
		cert, err = k.generateCertificateFromSecretfile(inputs.SecretFile)
	} else if inputs.CertFile != "" {
		certData, err := k.fileHandler.ReadFile(inputs.CertFile)
		if err != nil {
			return err
		}
		cert, err = k.certCreator.LoadCertificate(certData)
		if err != nil {
			return err
		}
	}
	if err != nil {
		return err
	}
	var prof *profile.Profile
	if inputs.Metadata == nil {
		prof = profile.CreateProfile(inputs.Name, inputs.Host, cert)
	} else {
		prof = profile.CreateProfileWithMetadata(inputs.Name, inputs.Host, cert, inputs.Metadata)
	}
	return k.fileHandler.WriteJSON(inputs.Outfile, prof)
}

// Generate metrics certificates and keys
func (k *FileKeytool) GenerateMetricsCertificatesAndKeys(inputs *keytool.GenerateMetricsCertificatesAndKeysInputs) error {
	if inputs.OutDir == "" {
		// If no output directory was specified, use the current working directory
		cwd, err := k.fileHandler.GetCwd()
		if err != nil {
			return err
		}
		inputs.OutDir = cwd
	} else {
		// Ensure the output directory exists
		if err := k.fileHandler.EnsureDirExists(inputs.OutDir); err != nil {
			return err
		}
	}

	// Generate the certificates and keys
	secret, err := k.certCreator.CreateSharedSecret()
	if err != nil {
		return err
	}
	jobManagerCert, err := k.certCreator.GenerateCertificateWithHostname(secret, inputs.JobManagerHost)
	if err != nil {
		return err
	}
	prometheusCert, err := k.certCreator.GenerateCertificate(secret)
	if err != nil {
		return err
	}
	// Write all certificates and keys to files on disk
	toWrite := map[string]string{
		"ca.crt":         secret.CertPEM,
		"ca.key":         secret.KeyPEM,
		"jobmanager.crt": jobManagerCert.ClientCert,
		"jobmanager.key": jobManagerCert.ClientKey,
		"prometheus.crt": prometheusCert.ClientCert,
		"prometheus.key": prometheusCert.ClientKey,
	}
	for filename, content := range toWrite {
		err = k.fileHandler.WriteText(filepath.Join(inputs.OutDir, filename), content)
		if err != nil {
			return err
		}
	}
	return nil
}

// Load a shared secret from a file and use it to generate a certificate
func (k *FileKeytool) generateCertificateFromSecretfile(filename string) (*certificate.Certificate, error) {
	secretData, err := k.fileHandler.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	secret, err := k.certCreator.LoadSharedSecret(secretData)
	if err != nil {
		return nil, err
	}
	return k.certCreator.GenerateCertificate(secret)
}
