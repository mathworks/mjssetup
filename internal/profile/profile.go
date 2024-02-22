// Copyright 2023 The MathWorks, Inc.
package profile

import (
	"errors"
	"fmt"
	"os"

	"github.com/mathworks/mjssetup/internal/json"
	"github.com/mathworks/mjssetup/pkg/certificate"
)

// Interface for creation of profiles
type Creator interface {
	CreateProfile(*CreateProfileInputs) error
}

// Implementation of Creator
type FileCreator struct {
	readCertificateFromFile       func(string) (*certificate.Certificate, error)
	writeProfileToFile            func(string, *profile) error
	generateCertificateFromSecret func(string) (*certificate.Certificate, error)
}

func NewFileCreator() *FileCreator {
	return &FileCreator{
		readCertificateFromFile:       readCertificateFromFile,
		writeProfileToFile:            writeProfileToFile,
		generateCertificateFromSecret: generateCertificateFromSecret,
	}
}

// Input arguments for Create
type CreateProfileInputs struct {
	Outfile    string
	Name       string
	Host       string
	CertFile   string
	SecretFile string
	UseSecret  bool
}

// Create a JSON cluster profile containing a certificate
func (p *FileCreator) CreateProfile(inputs *CreateProfileInputs) error {
	profileOutput := profile{
		Version:     1,
		Name:        inputs.Name,
		ClusterType: "MJS",
		SchedulerComponent: schedComp{
			Host: inputs.Host,
		},
	}
	if inputs.UseSecret {
		if inputs.SecretFile == "" {
			return errors.New("error: secret file path was empty")
		}
		cert, err := p.generateCertificateFromSecret(inputs.SecretFile)
		if err != nil {
			return err
		}
		addCertToProfile(&profileOutput, cert)
	} else if inputs.CertFile != "" {
		cert, err := p.readCertificateFromFile(inputs.CertFile)
		if err != nil {
			return err
		}
		addCertToProfile(&profileOutput, cert)
	}
	return p.writeProfileToFile(inputs.Outfile, &profileOutput)
}

func addCertToProfile(profileToEdit *profile, cert *certificate.Certificate) {
	profileToEdit.SchedulerComponent.Certificate = cert.ServerCert
	profileToEdit.SchedulerComponent.ClientCertificate = cert.ClientCert
	profileToEdit.SchedulerComponent.ClientPrivateKey = cert.ClientKey
}

// Struct for JSON cluster profile
type profile struct {
	Version            int
	Name               string
	ClusterType        string
	SchedulerComponent schedComp
	ProjectComponent   projComp
}

type schedComp struct {
	Host              string
	Certificate       string
	ClientCertificate string
	ClientPrivateKey  string
}

type projComp struct{}

// Read a certificate from a real input file
func readCertificateFromFile(certfile string) (*certificate.Certificate, error) {
	file, err := os.Open(certfile)
	if err != nil {
		return nil, fmt.Errorf("error opening certificate file: %v", err)
	}
	defer file.Close()
	cert, err := json.ReadJSONFile[certificate.Certificate](file)
	if err != nil {
		return nil, fmt.Errorf("error parsing certificate from file \"%s\": %v", certfile, err)
	}
	return cert, nil
}

// Write a profile to a real output file
func writeProfileToFile(outfile string, outputProfile *profile) error {
	file, err := os.Create(outfile)
	if err != nil {
		return fmt.Errorf("error opening output file: %v", err)
	}
	defer file.Close()
	err = json.WriteJSONFile(file, outputProfile)
	if err != nil {
		return fmt.Errorf("error writing to output file: %s", err)
	}
	fmt.Printf("Wrote profile to %s\n", outfile)
	return nil
}

func generateCertificateFromSecret(secretfile string) (*certificate.Certificate, error) {
	certCreator := certificate.FileCreator{}
	secret, err := certCreator.ReadSharedSecret(secretfile)
	if err != nil {
		return nil, err
	}
	return certificate.GenerateCertificate(secret)
}
