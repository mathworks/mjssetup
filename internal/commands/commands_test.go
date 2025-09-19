// Copyright 2023-2025 The MathWorks, Inc.
package commands_test

import (
	"strings"
	"testing"

	"github.com/mathworks/mjssetup/internal/commands"
	"github.com/mathworks/mjssetup/internal/keytool"
	mockKeytool "github.com/mathworks/mjssetup/mocks/keytool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestErrorNoCommand(t *testing.T) {
	cr, _ := newWithMocks(t)
	err := cr.RunCommand([]string{})
	assert.Error(t, err, "Expected error when no command is provided")
}

func TestErrorUnknownCommand(t *testing.T) {
	cr, _ := newWithMocks(t)
	badCmd := "not-a-valid-command"
	err := cr.RunCommand([]string{badCmd})
	assert.Error(t, err, "Expected error when an unknown command is provided")
	assert.Contains(t, err.Error(), badCmd, "Error should contain the unknown command")
}

// Test printing general help text for mjssetup
func TestPrintAllHelp(t *testing.T) {
	for _, flag := range commands.HelpFlags {
		cr, mocks := newWithMocks(t)
		verifyCommandSuccess(t, cr, []string{flag})

		// Check the text that was written
		gotTxt := mocks.writer.content
		for _, cmd := range commands.AllCommands {
			assert.Contains(t, gotTxt, cmd, "General help text should mention command")
		}
	}
}

func TestCreateSharedSecretHelp(t *testing.T) {
	verifyPrintCommandHelp(t, commands.CreateSharedSecretCmd, []string{commands.OutfileArg}, []string{})
}

func TestGenerateCertificateHelp(t *testing.T) {
	verifyPrintCommandHelp(t, commands.GenerateCertificateCmd, []string{commands.OutfileArg, commands.SecretfileArg}, []string{})
}

func TestCreateProfileHelp(t *testing.T) {
	verifyPrintCommandHelp(t, commands.CreateProfileCmd, []string{
		commands.OutfileArg,
		commands.SecretfileArg,
		commands.HostArg,
		commands.NameArg,
		commands.CertificateArg,
	}, []string{commands.MetadataArg})
}

func TestGenerateMetricsCertificatesAndKeysHelp(t *testing.T) {
	verifyPrintCommandHelp(t, commands.GenerateMetricsCertificatesAndKeysCmd, []string{commands.OutdirArg, commands.JobManagerHostArg}, []string{})
}

func TestCreateSharedSecretNoArgs(t *testing.T) {
	cr, mocks := newWithMocks(t)
	args := []string{commands.CreateSharedSecretCmd}

	// Calling create-shaerd-secret with no args should request secret file be written to the default location
	expectedInputs := &keytool.CreateSharedSecretInputs{
		Outfile: commands.DefaultSecretFile,
	}
	mocks.keytool.EXPECT().CreateSharedSecret(expectedInputs).Return(nil)
	verifyCommandSuccess(t, cr, args)
}

func TestCreateSharedSecretWithOutfile(t *testing.T) {
	outfileJson := "my_outfile.json"
	verifyCreateSharedSecretOutfile(t, outfileJson, outfileJson)
}

func TestCreateSharedSecretNoExtension(t *testing.T) {
	outfileNoExt := "my_outfile"
	verifyCreateSharedSecretOutfile(t, outfileNoExt, outfileNoExt+".json")
}

func TestCreateSharedSecretCapitalJSONExtension(t *testing.T) {
	outfile := "my_outfile.JSON"
	verifyCreateSharedSecretOutfile(t, outfile, outfile)
}

func TestGenerateCertificateWithOutfile(t *testing.T) {
	outfile := "my-cert.json"
	verifyGenerateCertificateOutfile(t, outfile, outfile)
}

func TestGenerateCertificateNoExtension(t *testing.T) {
	outfileNoExt := "my-cert"
	verifyGenerateCertificateOutfile(t, outfileNoExt, outfileNoExt+".json")
}

func TestGenerateCertificateDefaultOutfile(t *testing.T) {
	secretFile := "my-secret.json"
	cr, mocks := newWithMocks(t)
	args := []string{commands.GenerateCertificateCmd, "-" + commands.SecretfileArg, secretFile}
	expectedInputs := &keytool.GenerateCertificateInputs{
		Outfile:    commands.DefaultCertificateFile,
		SecretFile: secretFile,
	}
	mocks.keytool.EXPECT().GenerateCertificate(expectedInputs).Return(nil)
	verifyCommandSuccess(t, cr, args)
}

func TestGenerateCertificateErrorNoSecretFile(t *testing.T) {
	cr, _ := newWithMocks(t)
	args := []string{commands.GenerateCertificateCmd} // Do not specify a secret file
	err := cr.RunCommand(args)
	assert.Error(t, err, "Expected error when generate-certificate is called without specifying a secret file")
	assert.Contains(t, err.Error(), commands.SecretfileArg, "Error should mention secret file argument")
}

func TestCreateProfileMissingHost(t *testing.T) {
	cr, _ := newWithMocks(t)
	args := []string{commands.CreateProfileCmd, "-" + commands.NameArg, "my-profile"}
	err := cr.RunCommand(args)
	assert.Error(t, err, "Expected error when create-profile is called without specifying a host")
	assert.Contains(t, err.Error(), commands.HostArg, "Error should mention host argument")
}

func TestCreateProfileMissingName(t *testing.T) {
	cr, _ := newWithMocks(t)
	args := []string{commands.CreateProfileCmd, "-" + commands.HostArg, "myhost"}
	err := cr.RunCommand(args)
	assert.Error(t, err, "Expected error when create-profile is called without specifying a name")
	assert.Contains(t, err.Error(), commands.NameArg, "Error should mention name argument")
}

func TestCreateProfileNoCerts(t *testing.T) {
	cr, mocks := newWithMocks(t)
	host := "myhost"
	name := "my-profile-name"
	args := []string{commands.CreateProfileCmd, "-" + commands.HostArg, host, "-" + commands.NameArg, name}

	mocks.keytool.EXPECT().CreateProfile(&keytool.CreateProfileInputs{
		Host:    host,
		Name:    name,
		Outfile: name + ".json",
	}).Return(nil)
	err := cr.RunCommand(args)
	require.NoError(t, err)
}

func TestCreateProfileWithCertfile(t *testing.T) {
	cr, mocks := newWithMocks(t)
	host := "myhost"
	name := "my-profile-name"
	certFile := "my-cert.json"
	args := []string{commands.CreateProfileCmd, "-" + commands.HostArg, host, "-" + commands.NameArg, name, "-" + commands.CertificateArg, certFile}

	mocks.keytool.EXPECT().CreateProfile(&keytool.CreateProfileInputs{
		Host:      host,
		Name:      name,
		Outfile:   name + ".json",
		CertFile:  certFile,
		UseSecret: false,
	}).Return(nil)
	err := cr.RunCommand(args)
	require.NoError(t, err)
}

func TestCreateProfileWithSecret(t *testing.T) {
	cr, mocks := newWithMocks(t)
	host := "myhost"
	name := "my-profile-name"
	secretFile := "my-shared-secret.json"
	args := []string{commands.CreateProfileCmd,
		"-" + commands.HostArg, host,
		"-" + commands.NameArg, name,
		"-" + commands.SecretfileArg, secretFile}

	mocks.keytool.EXPECT().CreateProfile(&keytool.CreateProfileInputs{
		Host:       host,
		Name:       name,
		Outfile:    name + ".json",
		SecretFile: secretFile,
		UseSecret:  true,
	}).Return(nil)
	err := cr.RunCommand(args)
	require.NoError(t, err)
}

func TestCreateProfileBothSecretAndCert(t *testing.T) {
	cr, mocks := newWithMocks(t)
	host := "myhost"
	name := "my-profile-name"
	secretFile := "secret.json"
	certFile := "cert.json"
	args := []string{commands.CreateProfileCmd,
		"-" + commands.HostArg, host,
		"-" + commands.NameArg, name,
		"-" + commands.SecretfileArg, secretFile,
		"-" + commands.CertificateArg, certFile}

	// Calling this command should succeed, but print a warning
	mocks.keytool.EXPECT().CreateProfile(&keytool.CreateProfileInputs{
		Host:       host,
		Name:       name,
		Outfile:    name + ".json",
		SecretFile: secretFile,
		CertFile:   certFile,
		UseSecret:  false, // Expect UseSecret=false in this scenario
	}).Return(nil)
	err := cr.RunCommand(args)
	require.NoError(t, err)
	gotTxt := mocks.writer.content
	assert.Contains(t, gotTxt, "Warning", "Expected a warning message when both secret and certificate are provided")
}

func TestCreateProfileWithOutfile(t *testing.T) {
	outfile := "profile.json"
	verifyCreateProfileOutfile(t, outfile, outfile)
}

func TestCreateProfileNoExtension(t *testing.T) {
	outfileNoExt := "profile"
	verifyCreateProfileOutfile(t, outfileNoExt, outfileNoExt+".json")
}

func TestCreateProfileMetadataSingleKVPair(t *testing.T) {
	key := "mykey"
	value := "myval"
	input := key + "=" + value
	verifyCreateProfileMetadata(t, input, map[string]string{key: value})
}

func TestCreateProfileMetadataMultipleKVPairs(t *testing.T) {
	pairs := []string{}
	expectedMetadata := map[string]string{
		"key1": "val1",
		"key2": "val2",
		"key3": "val3",
	}
	for k, v := range expectedMetadata {
		pairs = append(pairs, k+"="+v)
	}
	input := strings.Join(pairs, ",")
	verifyCreateProfileMetadata(t, input, expectedMetadata)
}

func TestCreateProfileEmptyMetadata(t *testing.T) {
	verifyCreateProfileMetadata(t, "", nil)
}

func TestCreateProfileMetadataErrorNoKey(t *testing.T) {
	metadataArg := "key1=val1,=val2"
	name := "myname"
	host := "myhost"

	cr, _ := newWithMocks(t)
	args := []string{commands.CreateProfileCmd,
		"-" + commands.MetadataArg, metadataArg,
		"-" + commands.NameArg, name,
		"-" + commands.HostArg, host}

	err := cr.RunCommand(args)
	assert.Error(t, err, "Expected error when metadata key-value pair is missing a key")
	assert.Contains(t, err.Error(), "val2", "Error should mention value with missing key")
}

func TestCreateProfileMetadataBadKVFormat(t *testing.T) {
	metadataArg := "key1=val1=test"
	name := "myname"
	host := "myhost"

	cr, _ := newWithMocks(t)
	args := []string{commands.CreateProfileCmd,
		"-" + commands.MetadataArg, metadataArg,
		"-" + commands.NameArg, name,
		"-" + commands.HostArg, host}

	err := cr.RunCommand(args)
	assert.Error(t, err, "Expected an error when metadata key-value pair is malformed")
	assert.Contains(t, err.Error(), metadataArg, "Error message should indicate the problematic input")
}

func TestGenerateMetricsCertificatesAndKeys(t *testing.T) {
	cr, mocks := newWithMocks(t)
	jmHost := "jmhost"
	outdir := "my-outdir"
	args := []string{commands.GenerateMetricsCertificatesAndKeysCmd,
		"-" + commands.JobManagerHostArg, jmHost,
		"-" + commands.OutdirArg, outdir,
	}

	mocks.keytool.EXPECT().GenerateMetricsCertificatesAndKeys(&keytool.GenerateMetricsCertificatesAndKeysInputs{
		JobManagerHost: jmHost,
		OutDir:         outdir,
	}).Return(nil)
	verifyCommandSuccess(t, cr, args)
}

func TestGenerateMetricsCertificatesAndKeysMissingJMHost(t *testing.T) {
	cr, _ := newWithMocks(t)
	outdir := "my-outdir"
	args := []string{commands.GenerateMetricsCertificatesAndKeysCmd,
		"-" + commands.OutdirArg, outdir,
	}

	err := cr.RunCommand(args)
	assert.Error(t, err, "Expected error when Job Manager host is missing")
	assert.Contains(t, err.Error(), commands.JobManagerHostArg, "Error should mention job manager host argument")
}

// If the -outdir argument is not provided, we should just pass the keytool an empty string for the outdir
func TestGenerateMetricsCertificatesAndKeysNoOutdir(t *testing.T) {
	cr, mocks := newWithMocks(t)
	jmHost := "jmhost"
	args := []string{commands.GenerateMetricsCertificatesAndKeysCmd,
		"-" + commands.JobManagerHostArg, jmHost,
	}

	mocks.keytool.EXPECT().GenerateMetricsCertificatesAndKeys(&keytool.GenerateMetricsCertificatesAndKeysInputs{
		JobManagerHost: jmHost,
		OutDir:         "",
	}).Return(nil)
	verifyCommandSuccess(t, cr, args)
}

func verifyCommandSuccess(t *testing.T, cr *commands.CommandRunner, args []string) {
	err := cr.RunCommand(args)
	assert.NoErrorf(t, err, "Got error from running command with args: %v", args)
}

func verifyCreateSharedSecretOutfile(t *testing.T, outfileArg, expectedOutfile string) {
	cr, mocks := newWithMocks(t)
	args := []string{commands.CreateSharedSecretCmd, "-" + commands.OutfileArg, outfileArg}
	expectedInputs := &keytool.CreateSharedSecretInputs{
		Outfile: expectedOutfile,
	}
	mocks.keytool.EXPECT().CreateSharedSecret(expectedInputs).Return(nil)
	verifyCommandSuccess(t, cr, args)
}

func verifyGenerateCertificateOutfile(t *testing.T, outfileArg, expectedOutfile string) {
	secretFile := "my-secret.json"
	cr, mocks := newWithMocks(t)
	args := []string{commands.GenerateCertificateCmd,
		"-" + commands.OutfileArg, outfileArg,
		"-" + commands.SecretfileArg, secretFile}
	expectedInputs := &keytool.GenerateCertificateInputs{
		Outfile:    expectedOutfile,
		SecretFile: secretFile,
	}
	mocks.keytool.EXPECT().GenerateCertificate(expectedInputs).Return(nil)
	verifyCommandSuccess(t, cr, args)
}

func verifyCreateProfileOutfile(t *testing.T, outfileArg, expectedOutfile string) {
	name := "myname"
	host := "myhost"
	cr, mocks := newWithMocks(t)
	args := []string{commands.CreateProfileCmd,
		"-" + commands.OutfileArg, outfileArg,
		"-" + commands.NameArg, name,
		"-" + commands.HostArg, host}
	expectedInputs := &keytool.CreateProfileInputs{
		Outfile: expectedOutfile,
		Name:    name,
		Host:    host,
	}
	mocks.keytool.EXPECT().CreateProfile(expectedInputs).Return(nil)
	verifyCommandSuccess(t, cr, args)
}

func verifyCreateProfileMetadata(t *testing.T, metadataArg string, expectedMetadata map[string]string) {
	name := "myname"
	host := "myhost"
	cr, mocks := newWithMocks(t)
	args := []string{commands.CreateProfileCmd,
		"-" + commands.MetadataArg, metadataArg,
		"-" + commands.NameArg, name,
		"-" + commands.HostArg, host}
	expectedInputs := &keytool.CreateProfileInputs{
		Outfile:  name + ".json",
		Name:     name,
		Host:     host,
		Metadata: expectedMetadata,
	}
	mocks.keytool.EXPECT().CreateProfile(expectedInputs).Return(nil)
	verifyCommandSuccess(t, cr, args)
}

func verifyPrintCommandHelp(t *testing.T, cmd string, documentedArgs, undocumentedArgs []string) {
	for _, flag := range commands.HelpFlags {
		cr, mocks := newWithMocks(t)
		verifyCommandSuccess(t, cr, []string{cmd, flag})

		// Check the text that was written
		gotTxt := mocks.writer.content
		assert.Containsf(t, gotTxt, cmd, "Help text for '%s' should mention command", cmd)
		for _, arg := range documentedArgs {
			assert.Containsf(t, gotTxt, arg, "Help text for '%s' should mention argument '%s'", cmd, arg)
		}
		for _, arg := range undocumentedArgs {
			assert.NotContainsf(t, gotTxt, arg, "Help text for '%s' should not mention undocumented argument '%s'", cmd, arg)
		}
	}
}

type mocks struct {
	keytool *mockKeytool.Keytool
	writer  *testStringWriter
}

func newWithMocks(t *testing.T) (*commands.CommandRunner, *mocks) {
	mockKeytool := mockKeytool.NewKeytool(t)
	fakeWriter := &testStringWriter{}
	return commands.NewCommandRunner(mockKeytool, fakeWriter), &mocks{
		keytool: mockKeytool,
		writer:  fakeWriter,
	}
}

type testStringWriter struct {
	content string
}

func (w *testStringWriter) WriteString(input string) {
	w.content += input
}
