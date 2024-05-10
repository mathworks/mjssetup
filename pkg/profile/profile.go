// Package profile contains a function for creating a cluster profile.
// Copyright 2023-2024 The MathWorks, Inc.
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
	Certificate       string
	ClientCertificate string
	ClientPrivateKey  string
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
