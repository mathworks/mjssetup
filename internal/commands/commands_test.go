// Copyright 2023 The MathWorks, Inc.
package commands

import (
	"flag"
	"fmt"
	"testing"

	"github.com/mathworks/mjssetup/internal/profile"
	"github.com/mathworks/mjssetup/pkg/certificate"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var allCmds = []string{
	createSharedSecretCmd,
	generateCertificateCmd,
	createProfileCmd,
}

// Check we get an error when no command name is provided
func TestGetCommandFuncNoCommand(t *testing.T) {
	cmdFunc, err := NewCommandGetter().GetCommandFunc([]string{})
	require.Error(t, err, "expected error when no command name was provided")
	require.Nil(t, cmdFunc, "command function should be nil when no command name was provided")
}

// Check that the usage text contains all commands
func TestGetAllUsageText(t *testing.T) {
	txt := getAllUsageText()
	for _, cmd := range allCmds {
		require.Contains(t, txt, cmd, "command name missing from available commands string")
	}
}

// Check behaviour when a help flag is passed instead of a valid command
// e.g. mjssetup -h
func TestHelpFlagNoCommand(t *testing.T) {
	for _, h := range helpFlags {
		t.Run(h, func(t *testing.T) {
			cmdFunc, err := NewCommandGetter().GetCommandFunc([]string{h})
			assert.NoError(t, err, "should not get an error when running mjssetup with a help flag")
			assert.NotNil(t, cmdFunc, "should get a valid function when running mjssetup with a help flag")
			err = cmdFunc() // run the print help command
			assert.NoError(t, err, "command function returned for help flag should not error")
		})
	}
}

// Test that showHelpIfNeeded correctly shows help text when there is a help flag in the command-line arguments along with a valid command
// e.g. mjssetup create-profile -h
func TestHelpFlagWithCommand(t *testing.T) {
	argSets := map[string][]string{
		"-h":                 {"-h"},
		"--help with others": {"-somearg", "10", "--help"},
		"-help with others":  {"-help", "-otherarg"},
	}
	for name, args := range argSets {
		t.Run(name, func(t *testing.T) {
			flags := flag.NewFlagSet("test", 1)
			showedHelp := showHelpIfNeeded(createProfileCmd, args, flags)
			require.True(t, showedHelp, "help text should have been displayed when args contained help flag")
		})
	}

	// Check we did not display help when no help arg was included
	showedHelp := showHelpIfNeeded("test", []string{"-arg1", "test", "-arg2", "test"}, nil)
	require.False(t, showedHelp, "help text should not have been displayed when no help arg was provided")
}

func TestParseCreateSharedSecretInputs(t *testing.T) {
	testCases := []struct {
		name                 string
		outfile              string
		expectedInputOutfile string
	}{
		{"JSON outfile", "test.json", "test.json"},
		{"non-JSON outfile", "test", "test.json"},
		{"default outfile", "", "secret.json"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			args := []string{}
			if tc.outfile != "" {
				args = []string{"-outfile", tc.outfile}
			}
			expectedInputs := certificate.CreateSharedSecretInputs{
				Outfile: tc.expectedInputOutfile,
			}
			verifyInputParsing(t, createSharedSecretCmd, args, &expectedInputs, parseCreateSharedSecretInputs)
		})
	}
}

func TestParseGenerateCertificateInputs(t *testing.T) {
	testCases := []struct {
		name                 string
		outfile              string
		expectedInputOutfile string
	}{
		{"JSON outfile", "test.json", "test.json"},
		{"non-JSON outfile", "test", "test.json"},
		{"default outfile", "", "certificate.json"},
	}

	secretfile := "secret.json"
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			args := []string{"-secretfile", secretfile}
			if tc.outfile != "" {
				args = append(args, "-outfile", tc.outfile)
			}
			expectedInputs := certificate.GenerateCertificateInputs{
				Outfile:    tc.expectedInputOutfile,
				SecretFile: secretfile,
			}
			verifyInputParsing(t, generateCertificateCmd, args, &expectedInputs, parseGenerateCertificateInputs)
		})
	}
}

// Check that the correct functions get called for each command
func TestCommandFuncsCalled(t *testing.T) {
	testCases := []struct {
		command                           string
		createSharedSecretShouldBeCalled  bool
		generateCertificateShouldBeCalled bool
		createProfileShouldBeCalled       bool
		args                              []string
	}{
		{createSharedSecretCmd, true, false, false, []string{}},
		{generateCertificateCmd, false, true, false, []string{"-secretfile", "test"}},
		{createProfileCmd, false, false, true, []string{"-host", "test", "-name", "test"}},
	}
	for _, tc := range testCases {
		t.Run(tc.command, func(t *testing.T) {
			args := append([]string{tc.command}, tc.args...)
			certCreator := &dummyCertCreator{false, false}
			profileCreator := &dummyProfileCreator{false}
			cmdGetter := CommandGetter{
				certificateCreator: certCreator,
				profileCreator:     profileCreator,
			}
			cmdFunc, err := cmdGetter.GetCommandFunc(args)
			assert.NoError(t, err)
			err = cmdFunc()
			assert.NoError(t, err, "error running dummy command")
			assert.Equal(t, tc.createSharedSecretShouldBeCalled, certCreator.createSharedSecretWasCalled, "Mismatch in whether createSharedSecret was called")
			assert.Equal(t, tc.generateCertificateShouldBeCalled, certCreator.generateCertificateWasCalled, "Mismatch in whether generateCertificate was called")
			assert.Equal(t, tc.createProfileShouldBeCalled, profileCreator.createProfileWasCalled, "Mismatch in whether createProfile was called")
		})
	}
}

// Dummy certificate creator that records when methods were called
type dummyCertCreator struct {
	createSharedSecretWasCalled  bool
	generateCertificateWasCalled bool
}

func (d *dummyCertCreator) CreateSharedSecret(_ *certificate.CreateSharedSecretInputs) error {
	d.createSharedSecretWasCalled = true
	return nil
}

func (d *dummyCertCreator) GenerateCertificate(_ *certificate.GenerateCertificateInputs) error {
	d.generateCertificateWasCalled = true
	return nil
}

// Test parsing the create-profile inputs
func TestParseCreateProfileInputs(t *testing.T) {
	clusterName := "my-cluster"
	host := "test-host"
	certfile := "cert.json"
	secretfile := "secret.json"

	// Test all combinations of passing in a secret file and certificate file
	testCases := []struct {
		name                 string
		passSecretFile       bool
		passCertFile         bool
		expectToUseSecret    bool
		outfile              string
		expectedInputOutfile string
	}{
		{"just_certfile", false, true, false, "test.json", "test.json"},
		{"just_secretfile", true, false, true, "test.json", "test.json"},
		{"certfile_and_secretfile", true, true, false, "test.json", "test.json"},
		{"non_json_outfile", false, false, false, "test", "test.json"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			args := []string{
				"-outfile",
				tc.outfile,
				"-name",
				clusterName,
				"-host",
				host,
			}
			expectedInputs := profile.CreateProfileInputs{
				Outfile:   tc.expectedInputOutfile,
				Host:      host,
				Name:      clusterName,
				UseSecret: tc.expectToUseSecret,
			}
			if tc.passCertFile {
				args = append(args, "-certificate", certfile)
				expectedInputs.CertFile = certfile
			}
			if tc.passSecretFile {
				args = append(args, "-secretfile", secretfile)
				expectedInputs.SecretFile = secretfile
			}

			verifyInputParsing(t, createProfileCmd, args, &expectedInputs, parseCreateProfileInputs)
		})
	}
}

// Check that the default output file matches the cluster name
func TestCreateProfileDefaultOutfile(t *testing.T) {
	clusterName := "my-cluster"
	host := "test-host"
	args := []string{
		"-name",
		clusterName,
		"-host",
		host,
	}
	expectedInputs := profile.CreateProfileInputs{
		Outfile: fmt.Sprintf("%s.json", clusterName),
		Host:    host,
		Name:    clusterName,
	}
	verifyInputParsing(t, "create profile no outfile", args, &expectedInputs, parseCreateProfileInputs)
}

type dummyProfileCreator struct {
	createProfileWasCalled bool
}

func (d *dummyProfileCreator) CreateProfile(_ *profile.CreateProfileInputs) error {
	d.createProfileWasCalled = true
	return nil
}
func TestGenerateCertificateMissingArgs(t *testing.T) {
	fullArgs := []string{
		generateCertificateCmd,
		"-outfile",
		"test.json",
		"-secretfile",
		"secret.json",
	}
	verifyErrorWhenRunningWithoutArg(t, fullArgs, "secretfile")
}

func TestCreateProfileMissingArgs(t *testing.T) {
	fullArgs := []string{
		createProfileCmd,
		"-outfile",
		"profile.json",
		"-certificate",
		"cert.json",
		"-name",
		"myMJS",
		"-host",
		"myHost",
	}
	requiredArgs := []string{
		"name",
		"host",
	}
	for _, r := range requiredArgs {
		t.Run(r, func(t *testing.T) {

			verifyErrorWhenRunningWithoutArg(t, fullArgs, r)
		})
	}
}

// Check we get an error when a required argument is missing from the input arguments for a command
func verifyErrorWhenRunningWithoutArg(t *testing.T, fullArgs []string, toRemove string) {
	args := removeArg(fullArgs, toRemove)
	cmdFunc, err := NewCommandGetter().GetCommandFunc(args)
	assert.NoError(t, err)
	err = cmdFunc()
	require.Errorf(t, err, "expected error when running command with missing arg %s", toRemove)
	require.Contains(t, err.Error(), toRemove, "expected error string to contain the missing arg")
}

// Remove an argument from an array
func removeArg(fullArgs []string, toRemove string) []string {
	removeNext := false
	toKeep := []string{}
	for _, arg := range fullArgs {
		if arg == "-"+toRemove {
			removeNext = true
		} else {
			if !removeNext {
				toKeep = append(toKeep, arg)
			}
			removeNext = false
		}
	}
	return toKeep
}

// Check we get an error when attempting to use an invalid mjssetup command
func TestErrorInvalidCommand(t *testing.T) {
	cmdFunc, err := NewCommandGetter().GetCommandFunc([]string{"this-is-not-a-command"})
	require.Error(t, err, "should get error when command is invalid")
	require.Nil(t, cmdFunc, "command function should be nil when command is invalid")
}

// Check that a parsing function returns the expected input struct for a given array of input arguments
func verifyInputParsing[T any](t *testing.T, desc string, args []string, expectedInputs *T, parseFunc func([]string, *flag.FlagSet) (*T, error)) {
	gotInputs, err := parseFunc(args, flag.NewFlagSet("test", 1))
	assert.NoErrorf(t, err, "Error parsing inputs (%s)", desc)
	require.Equalf(t, *gotInputs, *expectedInputs, "Unexpected inputs (%s)", desc)
}
