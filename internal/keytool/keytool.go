// Package keytool contains methods for creating files containing shared secrets, certificates and profiles.
// Copyright 2024 The MathWorks, Inc.
package keytool

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/mathworks/mjssetup/pkg/certificate"
	"github.com/mathworks/mjssetup/pkg/profile"
)

// Mockable interface for creating files
type Keytool interface {
	CreateSharedSecret(*CreateSharedSecretInputs) error
	GenerateCertificate(*GenerateCertificateInputs) error
	CreateProfile(*CreateProfileInputs) error
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
}

// Implementation of Keytool
type keytoolImpl struct {
	readFromFile     func(string) ([]byte, error)
	openFileForWrite func(string) (io.WriteCloser, error)
	certCreator      certificate.Creator
}

// Construct new Keytool
func New() Keytool {
	return &keytoolImpl{
		readFromFile:     readFromFile,
		openFileForWrite: openFileForWrite,
		certCreator:      certificate.New(),
	}
}

// Create a shared secret file
func (k *keytoolImpl) CreateSharedSecret(inputs *CreateSharedSecretInputs) error {
	secret, err := k.certCreator.CreateSharedSecret()
	if err != nil {
		return err
	}
	file, err := k.openFileForWrite(inputs.Outfile)
	if err != nil {
		return err
	}
	defer file.Close()
	return writeJSON(file, &secret)
}

// Create a certificate file
func (k *keytoolImpl) GenerateCertificate(inputs *GenerateCertificateInputs) error {
	cert, err := k.generateCertificateFromSecretfile(inputs.SecretFile)
	if err != nil {
		return err
	}
	file, err := k.openFileForWrite(inputs.Outfile)
	if err != nil {
		return err
	}
	defer file.Close()
	return writeJSON(file, &cert)
}

// Create a cluster profile file
func (k *keytoolImpl) CreateProfile(inputs *CreateProfileInputs) error {
	var cert *certificate.Certificate
	var err error
	if inputs.UseSecret {
		cert, err = k.generateCertificateFromSecretfile(inputs.SecretFile)
	} else if inputs.CertFile != "" {
		cert, err = k.loadCertificate(inputs.CertFile)
	}
	if err != nil {
		return err
	}
	prof := profile.CreateProfile(inputs.Name, inputs.Host, cert)
	file, err := k.openFileForWrite(inputs.Outfile)
	if err != nil {
		return err
	}
	defer file.Close()
	return writeJSON(file, &prof)
}

// Open a real file for writing
func openFileForWrite(filename string) (io.WriteCloser, error) {
	file, err := os.Create(filename)
	if err != nil {
		return nil, fmt.Errorf("error opening output file: %v", err)
	}
	return file, nil
}

// Read data from a real file
func readFromFile(filename string) ([]byte, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("error opening input file: %v", err)
	}
	defer file.Close()
	return io.ReadAll(file)
}

// Write out a struct as JSON
func writeJSON[T any](writer io.Writer, content *T) error {
	encoder := json.NewEncoder(writer)
	err := encoder.Encode(content)
	if err != nil {
		return fmt.Errorf("error encoding JSON: %v", err)
	}
	return nil
}

// Load a shared secret from a file and use it to generate a certificate
func (k *keytoolImpl) generateCertificateFromSecretfile(filename string) (*certificate.Certificate, error) {
	secretData, err := k.readFromFile(filename)
	if err != nil {
		return nil, err
	}
	secret, err := k.certCreator.LoadSharedSecret(secretData)
	if err != nil {
		return nil, err
	}
	return k.certCreator.GenerateCertificate(secret)
}

// Load a certificate from a file
func (k *keytoolImpl) loadCertificate(filename string) (*certificate.Certificate, error) {
	certData, err := k.readFromFile(filename)
	if err != nil {
		return nil, err
	}
	var cert certificate.Certificate
	err = json.Unmarshal(certData, &cert)
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling certificate: %v", err)
	}
	return &cert, nil
}
