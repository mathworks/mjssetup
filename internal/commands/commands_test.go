// Copyright 2023-2024 The MathWorks, Inc.
package commands

import (
	"flag"
	"fmt"
	"os"
	"testing"

	"github.com/mathworks/mjssetup/internal/keytool"
	mockkeytool "github.com/mathworks/mjssetup/mocks/keytool"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var allCmds = []string{
	createSharedSecretCmd,
	generateCertificateCmd,
	createProfileCmd,
	generateMetricsCertificatesAndKeysCmd,
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

// Check that the longHelpStrings contains all commands
func TestLongHelpStrings(t *testing.T) {
	for _, cmd := range allCmds {
		_, ok := longHelpStrings[cmd]
		require.True(t, ok, "long help strings is missing an entry for "+cmd)
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
			expectedInputs := keytool.CreateSharedSecretInputs{
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
			expectedInputs := keytool.GenerateCertificateInputs{
				Outfile:    tc.expectedInputOutfile,
				SecretFile: secretfile,
			}
			verifyInputParsing(t, generateCertificateCmd, args, &expectedInputs, parseGenerateCertificateInputs)
		})
	}
}

// Verify that the CreateSharedSecret method gets called when we run a create-shared-secret command
func TestCreateSharedSecret(t *testing.T) {
	mockkeytool := mockkeytool.NewKeytool(t)
	cmdGetter := CommandGetter{
		keytool: mockkeytool,
	}
	outfile := "test.json"
	args := []string{createSharedSecretCmd, "-outfile", outfile}
	mockkeytool.EXPECT().CreateSharedSecret(&keytool.CreateSharedSecretInputs{Outfile: outfile}).Return(nil)

	cmdFunc, err := cmdGetter.GetCommandFunc(args)
	require.NoError(t, err, "error getting command func")
	err = cmdFunc()
	require.NoError(t, err, "error running command")
}

// Verify that the GenerateCertificate method gets called when we run a generate-certificate command
func TestGenerateCertificate(t *testing.T) {
	mockkeytool := mockkeytool.NewKeytool(t)
	cmdGetter := CommandGetter{
		keytool: mockkeytool,
	}
	outfile := "test.json"
	secretfile := "secret.json"
	args := []string{generateCertificateCmd, "-outfile", outfile, "-secretfile", secretfile}
	mockkeytool.EXPECT().GenerateCertificate(&keytool.GenerateCertificateInputs{
		Outfile:    outfile,
		SecretFile: secretfile,
	}).Return(nil)

	cmdFunc, err := cmdGetter.GetCommandFunc(args)
	require.NoError(t, err, "error getting command func")
	err = cmdFunc()
	require.NoError(t, err, "error running command")
}

// Verify that the CreateProfile method gets called when we run a create-profile command
func TestCreateProfile(t *testing.T) {
	mockkeytool := mockkeytool.NewKeytool(t)
	cmdGetter := CommandGetter{
		keytool: mockkeytool,
	}
	outfile := "test.json"
	certfile := "secret.json"
	name := "my-profile"
	host := "localhost"
	args := []string{createProfileCmd, "-outfile", outfile, "-certificate", certfile, "-name", name, "-host", host}
	mockkeytool.EXPECT().CreateProfile(&keytool.CreateProfileInputs{
		Outfile:   outfile,
		CertFile:  certfile,
		Name:      name,
		UseSecret: false,
		Host:      host,
	}).Return(nil)

	cmdFunc, err := cmdGetter.GetCommandFunc(args)
	require.NoError(t, err, "error getting command func")
	err = cmdFunc()
	require.NoError(t, err, "error running command")
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
			expectedInputs := keytool.CreateProfileInputs{
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
	expectedInputs := keytool.CreateProfileInputs{
		Outfile: fmt.Sprintf("%s.json", clusterName),
		Host:    host,
		Name:    clusterName,
	}
	verifyInputParsing(t, "create profile no outfile", args, &expectedInputs, parseCreateProfileInputs)
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

func TestParseGenerateMetricsCertificatesAndKeys(t *testing.T) {
	testCases := []struct {
		name           string
		outDir         string
		jobManagerHost string
	}{
		{"outdir specified", "/dummy/outdir", "dummyhostname"},
		{"outdir not specified", "", "dummyhostname"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			args := []string{}
			expectedInputs := keytool.GenerateMetricsCertificatesAndKeysInputs{
				OutDir:         tc.outDir,
				JobManagerHost: tc.jobManagerHost,
			}
			if tc.outDir == "" {
				var err error
				expectedInputs.OutDir, err = os.Getwd()
				require.NoError(t, err)
			} else {
				args = append(args, "-outdir", tc.outDir)
			}
			args = append(args, "-jobmanagerhost", tc.jobManagerHost)
			verifyInputParsing(t, generateMetricsCertificatesAndKeysCmd, args, &expectedInputs, parseGenerateMetricsCertificatesAndKeysInputs)
		})
	}
}

func TestGenerateMetricsCertificatesAndKeysMissingArgs(t *testing.T) {
	fullArgs := []string{
		generateMetricsCertificatesAndKeysCmd,
		"-jobmanagerhost",
		"dummyhostname",
		"-outdir",
		"/dummy/outdir",
	}
	requiredArgs := []string{
		"jobmanagerhost",
	}
	for _, r := range requiredArgs {
		t.Run(r, func(t *testing.T) {
			verifyErrorWhenRunningWithoutArg(t, fullArgs, r)
		})
	}
}

// Verify that the GenerateMetricsCertificatesAndKeys method gets called when we run a generate-metrics-certificates-and-keys command
func TestGenerateMetricsCertificatesAndKeys(t *testing.T) {
	mockkeytool := mockkeytool.NewKeytool(t)
	cmdGetter := CommandGetter{
		keytool: mockkeytool,
	}
	outDir := "/tmp/outdir"
	jobManagerHost := "dummyhostname"
	args := []string{generateMetricsCertificatesAndKeysCmd, "-outdir", outDir, "-jobmanagerhost", jobManagerHost}
	mockkeytool.EXPECT().GenerateMetricsCertificatesAndKeys(&keytool.GenerateMetricsCertificatesAndKeysInputs{
		OutDir:         outDir,
		JobManagerHost: jobManagerHost,
	}).Return(nil)

	cmdFunc, err := cmdGetter.GetCommandFunc(args)
	require.NoError(t, err, "error getting command func")
	err = cmdFunc()
	require.NoError(t, err, "error running command")
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
