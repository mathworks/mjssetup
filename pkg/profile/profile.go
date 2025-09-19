// Package profile contains a function for creating a cluster profile.
// Copyright 2023-2025 The MathWorks, Inc.
package profile

import (
	"github.com/mathworks/mjssetup/pkg/certificate"
)

// Struct for JSON cluster profile
type Profile struct {
	Version            int
	Name               string
	ClusterType        string
	SchedulerComponent SchedComp
	ProjectComponent   ProjComp
}

type SchedComp struct {
	Host              string
	Name              string
	Certificate       string
	ClientCertificate string
	ClientPrivateKey  string
	Metadata          map[string]string `json:",omitempty"`
}

type ProjComp struct{}

// Create a cluster profile
func CreateProfile(name, host string, cert *certificate.Certificate) *Profile {
	profile := Profile{
		Version:     1,
		Name:        name,
		ClusterType: "MJS",
		SchedulerComponent: SchedComp{
			Host: host,
			Name: name,
		},
	}
	if cert != nil {
		addCertToProfile(&profile, cert)
	}
	return &profile
}

// Create a cluster profile containing metadata
func CreateProfileWithMetadata(name, host string, cert *certificate.Certificate, metadata map[string]string) *Profile {
	profile := Profile{
		Version:     1,
		Name:        name,
		ClusterType: "MJS",
		SchedulerComponent: SchedComp{
			Host:     host,
			Name:     name,
			Metadata: metadata,
		},
	}
	if cert != nil {
		addCertToProfile(&profile, cert)
	}
	return &profile
}

func addCertToProfile(profileToEdit *Profile, cert *certificate.Certificate) {
	profileToEdit.SchedulerComponent.Certificate = cert.ServerCert
	profileToEdit.SchedulerComponent.ClientCertificate = cert.ClientCert
	profileToEdit.SchedulerComponent.ClientPrivateKey = cert.ClientKey
}
