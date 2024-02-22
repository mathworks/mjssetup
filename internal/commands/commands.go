// Copyright 2023 The MathWorks, Inc.
// The commands package contains logic for running commands based on input arguments.
package commands

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/mathworks/mjssetup/internal/profile"
	"github.com/mathworks/mjssetup/pkg/certificate"
)

var createSharedSecretCmd = "create-shared-secret"
var generateCertificateCmd = "generate-certificate"
var createProfileCmd = "create-profile"

type CommandGetter struct {
	certificateCreator certificate.Creator
	profileCreator     profile.Creator
}

func NewCommandGetter() *CommandGetter {
	return &CommandGetter{
		certificateCreator: &certificate.FileCreator{},
		profileCreator:     profile.NewFileCreator(),
	}
}

// Get function to run based on the command name
func (c *CommandGetter) GetCommandFunc(args []string) (func() error, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("error: must provide a command.\n%s", getAllUsageText())
	}

	funcs := map[string]func([]string, *flag.FlagSet) error{
		createSharedSecretCmd:  c.runCreateSharedSecret,
		generateCertificateCmd: c.runGenerateCertificate,
		createProfileCmd:       c.runCreateProfile,
	}

	cmdName := args[0]
	cmdFunc, ok := funcs[cmdName]
	if !ok {
		if isHelpFlag(cmdName) {
			return func() error {
				printAllHelp()
				return nil
			}, nil
		}
		return nil, fmt.Errorf("error: command '%s' is not a valid mjssetup command.\n%s", cmdName, getAllUsageText())
	}

	// Inject input arguments into the function to run
	flags := flag.NewFlagSet(args[0], 1)
	funcWithArgs := func() error {
		return cmdFunc(args[1:], flags)
	}
	return funcWithArgs, nil
}

// If any command-line argument is a help flag, show help text for a given command
func showHelpIfNeeded(cmdName string, args []string, flags *flag.FlagSet) bool {
	for _, arg := range args {
		if isHelpFlag(arg) {
			printCommandHelp(cmdName, flags)
			return true
		}
	}
	return false
}

func (c *CommandGetter) runCreateSharedSecret(args []string, flags *flag.FlagSet) error {
	inputs, err := parseCreateSharedSecretInputs(args, flags)
	if err != nil || inputs == nil {
		return err
	}
	return c.certificateCreator.CreateSharedSecret(inputs)
}

func parseCreateSharedSecretInputs(args []string, flags *flag.FlagSet) (*certificate.CreateSharedSecretInputs, error) {
	inputs := certificate.CreateSharedSecretInputs{}
	flags.StringVar(&inputs.Outfile, "outfile", "secret.json", "Location to write the shared secret file to")
	if showHelpIfNeeded(createSharedSecretCmd, args, flags) {
		return nil, nil
	}
	err := flags.Parse(args)
	if err != nil {
		return nil, err
	}
	inputs.Outfile = ensureJSON(inputs.Outfile)
	return &inputs, nil
}

func (c *CommandGetter) runGenerateCertificate(args []string, flags *flag.FlagSet) error {
	inputs, err := parseGenerateCertificateInputs(args, flags)
	if err != nil || inputs == nil {
		return err
	}
	return c.certificateCreator.GenerateCertificate(inputs)
}

func parseGenerateCertificateInputs(args []string, flags *flag.FlagSet) (*certificate.GenerateCertificateInputs, error) {
	inputs := certificate.GenerateCertificateInputs{}
	flags.StringVar(&inputs.Outfile, "outfile", "certificate.json", "Location to write the certificate file to")
	flags.StringVar(&inputs.SecretFile, "secretfile", "", "Location of the shared secret file to generate the certificate from")
	if showHelpIfNeeded(generateCertificateCmd, args, flags) {
		return nil, nil
	}
	err := flags.Parse(args)
	if err != nil {
		return nil, err
	}
	if inputs.SecretFile == "" {
		return nil, getErrorForMissingArg(generateCertificateCmd, "must provide path to shared secret file (-secretfile)")
	}
	inputs.Outfile = ensureJSON(inputs.Outfile)
	return &inputs, nil
}

func (c *CommandGetter) runCreateProfile(args []string, flags *flag.FlagSet) error {
	inputs, err := parseCreateProfileInputs(args, flags)
	if err != nil || inputs == nil {
		return err
	}
	return c.profileCreator.CreateProfile(inputs)
}

func parseCreateProfileInputs(args []string, flags *flag.FlagSet) (*profile.CreateProfileInputs, error) {
	inputs := profile.CreateProfileInputs{}
	flags.StringVar(&inputs.Name, "name", "", "Name of the cluster profile")
	flags.StringVar(&inputs.Host, "host", "", "Name of the host on which the MJS job manager is running")
	flags.StringVar(&inputs.Outfile, "outfile", "", "Location to write the profile file to")
	flags.StringVar(&inputs.CertFile, "certificate", "", "Location of the certificate to embed in the profile")
	flags.StringVar(&inputs.SecretFile, "secretfile", "", "Location of a shared secret file to use to generate a new certificate to inject into the profile")
	if showHelpIfNeeded(createProfileCmd, args, flags) {
		return nil, nil
	}
	err := flags.Parse(args)
	if err != nil {
		return nil, err
	}

	// Check for required input arguments
	if inputs.Name == "" {
		return nil, getErrorForMissingArg(createProfileCmd, "must provide a cluster name (-name)")
	}
	if inputs.Host == "" {
		return nil, getErrorForMissingArg(createProfileCmd, "must provide a cluster host (-host)")
	}

	// If an output file was not provided, use the cluster name
	if inputs.Outfile == "" {
		inputs.Outfile = ensureJSON(inputs.Name)
	} else {
		inputs.Outfile = ensureJSON(inputs.Outfile)
	}

	// Check whether a secret file was provided
	inputs.UseSecret = false
	if inputs.SecretFile != "" {
		if inputs.CertFile != "" {
			fmt.Println("Warning: a certificate file and a secret file were both provided. The certificate file will be used and the secret file will be ignored.")
		} else {
			inputs.UseSecret = true // Use the secret only if a certificate file was not provided
		}
	}
	return &inputs, nil
}

var longHelpStrings = map[string]string{
	createSharedSecretCmd: `Create a shared secret to establish trust within a cluster.

Before passing sensitive data from one service to
another (e.g., between job manager and workers), these
services must establish a trust relationship using a
shared secret.  This script creates a file that serves
as a shared secret between the services.  Each service
must gain access to the secret file in order to establish
a trust relationship.

Create the secret file only once per cluster on one
machine, then copy it into the location specified by
SHARED_SECRET_FILE in mjs_def.sh on each machine
before you start any job managers or workers.  You can
reuse shared secrets in subsequent sessions.`,
	generateCertificateCmd: `Generate a certificate using the shared secret file
of the MJS cluster you want to connect to.
The certificate is required by clients when the
REQUIRE_CLIENT_CERTIFICATE flag is set to 'true'
on the job manager.`,
	createProfileCmd: `Create a profile for an MJS cluster. This must contain
the name and the host name of the MJS cluster. If the
cluster is started with the REQUIRE_CLIENT_CERTIFICATE
flag set to 'true', you must specify the location of the
correct certificate file to authenticate the connection
to the cluster.`,
}

type usageExample struct {
	description string
	command     string
}

// Usage examples for each command
var usageExamples = map[string][]usageExample{
	createSharedSecretCmd: {
		{"Create a shared secret to establish trust within a cluster", "%s %s [-outfile <output-file>]"},
	},
	generateCertificateCmd: {
		{"Generate a signed client certificate from a shared secret", "%s %s -secretfile <secret-file> [-outfile <output-file>]"},
	},
	createProfileCmd: {
		{"Create a profile for a cluster started with the REQUIRE_CLIENT_CERTIFICATE flag set to 'false'", "%s %s -name <cluster-name> -host <cluster-host> [-outfile <output-file>]"},
		{"Create a profile for a cluster started with the REQUIRE_CLIENT_CERTIFICATE flag set to 'true' by injecting a client certificate", "%s %s -name <cluster-name> -host <cluster-host> -certificate <certificate-file> [-outfile <output-file>]"},
		{"Create a profile for a cluster started with the REQUIRE_CLIENT_CERTIFICATE flag set to 'true' by generating a new signed client certificate and injecting it into the profile", "%s %s -name <cluster-name> -host <cluster-host> -secretfile <secret-file> [-outfile <output-file>]"},
	},
}

// Print general help text
func printAllHelp() {
	fmt.Printf("mjssetup: Tool for performing setup tasks for an MJS cluster.\n%s\n", getAllUsageText())
}

// Create a string containing usage text for all commands
func getAllUsageText() string {
	allCmds := []string{
		createSharedSecretCmd,
		generateCertificateCmd,
		createProfileCmd,
	}
	txt := fmt.Sprintf("Usage: %s <command> [<args>]", getExecutableName())
	for _, cmd := range allCmds {
		txt = fmt.Sprintf("%s\n\n%s", txt, getUsageText(cmd, true))
	}
	return txt
}

// Get formatted usage text for a single command
// If forcePrintDescription is false, descriptions are only printed if this command has multiple examples
func getUsageText(cmd string, forcePrintDescription bool) string {
	txt := ""
	examples := usageExamples[cmd]
	for idx, example := range examples {
		if idx > 0 {
			txt = txt + "\n\n"
		}
		if len(examples) > 1 || forcePrintDescription {
			txt = txt + example.description + ":\n"
		}
		txt = txt + "  " + fmt.Sprintf(example.command, getExecutableName(), cmd)
	}
	return txt
}

// Print help text for a single command
func printCommandHelp(cmd string, flags *flag.FlagSet) {
	longHelpTxt := longHelpStrings[cmd]
	fmt.Printf("%s\n\n", longHelpTxt)
	fmt.Printf("Usage:\n%s\n", getUsageText(cmd, false))
	fmt.Printf("\nInput arguments:\n")
	flags.PrintDefaults()
}

var helpFlags = []string{"-h", "-help", "--help"}

func isHelpFlag(arg string) bool {
	for _, h := range helpFlags {
		if arg == h {
			return true
		}
	}
	return false
}

func getErrorForMissingArg(cmd, msg string) error {
	return fmt.Errorf("error: %s\n\nUsage:\n%s", msg, getUsageText(cmd, false))
}

func ensureJSON(filename string) string {
	jsonExt := ".json"
	if !strings.HasSuffix(filename, jsonExt) {
		filename = filename + jsonExt
	}
	return filename
}

func getExecutableName() string {
	return filepath.Base(os.Args[0])
}
