// Copyright 2023-2025 The MathWorks, Inc.
// The commands package contains logic for running commands based on input arguments.
package commands

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/mathworks/mjssetup/internal/keytool"
)

// Mockable string writer interface
type StringWriter interface {
	WriteString(s string)
}

const (
	// Commands
	CreateSharedSecretCmd                 = "create-shared-secret"
	GenerateCertificateCmd                = "generate-certificate"
	CreateProfileCmd                      = "create-profile"
	GenerateMetricsCertificatesAndKeysCmd = "generate-metrics-certificates-and-keys"

	// Input arguments for commands
	OutfileArg        = "outfile"
	SecretfileArg     = "secretfile"
	NameArg           = "name"
	HostArg           = "host"
	CertificateArg    = "certificate"
	MetadataArg       = "metadata"
	JobManagerHostArg = "jobmanagerhost"
	OutdirArg         = "outdir"

	// Default values for args
	DefaultSecretFile      = "secret.json"
	DefaultCertificateFile = "certificate.json"
)

var AllCommands = []string{
	CreateSharedSecretCmd,
	GenerateCertificateCmd,
	CreateProfileCmd,
	GenerateMetricsCertificatesAndKeysCmd,
}

var HelpFlags = []string{"-h", "-help", "--help"}

type CommandRunner struct {
	keytool keytool.Keytool
	writer  StringWriter
}

func NewCommandRunner(keytool keytool.Keytool, writer StringWriter) *CommandRunner {
	return &CommandRunner{
		keytool: keytool,
		writer:  writer,
	}
}

// Run a command based on input arguments
func (c *CommandRunner) RunCommand(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("error: must provide a command.\n%s", getAllUsageText())
	}

	cmdName := args[0]
	var cmdFunc func([]string, *flag.FlagSet) error
	switch cmdName {
	case CreateSharedSecretCmd:
		cmdFunc = c.runCreateSharedSecret
	case GenerateCertificateCmd:
		cmdFunc = c.runGenerateCertificate
	case CreateProfileCmd:
		cmdFunc = c.runCreateProfile
	case GenerateMetricsCertificatesAndKeysCmd:
		cmdFunc = c.runGenerateMetricsCertificatesAndKeys
	default:
		if isHelpFlag(cmdName) {
			printAllHelp(c.writer)
			return nil
		}
		return fmt.Errorf("error: command '%s' is not a valid mjssetup command.\n%s", cmdName, getAllUsageText())
	}

	// Inject input arguments into the function to run
	flags := flag.NewFlagSet(args[0], 1)
	return cmdFunc(args[1:], flags)
}

// If any command-line argument is a help flag, show help text for a given command
func (c *CommandRunner) showHelpIfNeeded(cmdName string, args []string, flags *flag.FlagSet) bool {
	for _, arg := range args {
		if isHelpFlag(arg) {
			c.printCommandHelp(cmdName, flags)
			return true
		}
	}
	return false
}

func (c *CommandRunner) runCreateSharedSecret(args []string, flags *flag.FlagSet) error {
	inputs, err := c.parseCreateSharedSecretInputs(args, flags)
	if err != nil {
		return err
	}
	if inputs == nil {
		return nil // Already printed help text
	}
	return c.keytool.CreateSharedSecret(inputs)
}

func (c *CommandRunner) parseCreateSharedSecretInputs(args []string, flags *flag.FlagSet) (*keytool.CreateSharedSecretInputs, error) {
	inputs := keytool.CreateSharedSecretInputs{}
	flags.StringVar(&inputs.Outfile, OutfileArg, DefaultSecretFile, "Location to write the shared secret file to")
	if c.showHelpIfNeeded(CreateSharedSecretCmd, args, flags) {
		return nil, nil
	}
	err := flags.Parse(args)
	if err != nil {
		return nil, err
	}
	inputs.Outfile = ensureJSON(inputs.Outfile)
	return &inputs, nil
}

func (c *CommandRunner) runGenerateCertificate(args []string, flags *flag.FlagSet) error {
	inputs, err := c.parseGenerateCertificateInputs(args, flags)
	if err != nil {
		return err
	}
	if inputs == nil {
		return nil // Already printed help text
	}
	return c.keytool.GenerateCertificate(inputs)
}

func (c *CommandRunner) parseGenerateCertificateInputs(args []string, flags *flag.FlagSet) (*keytool.GenerateCertificateInputs, error) {
	inputs := keytool.GenerateCertificateInputs{}
	flags.StringVar(&inputs.Outfile, OutfileArg, DefaultCertificateFile, "Location to write the certificate file to")
	flags.StringVar(&inputs.SecretFile, SecretfileArg, "", "Location of the shared secret file to generate the certificate from")
	if c.showHelpIfNeeded(GenerateCertificateCmd, args, flags) {
		return nil, nil
	}
	err := flags.Parse(args)
	if err != nil {
		return nil, err
	}
	if inputs.SecretFile == "" {
		return nil, getErrorForMissingArg(GenerateCertificateCmd, "must provide path to shared secret file (-secretfile)")
	}
	inputs.Outfile = ensureJSON(inputs.Outfile)
	return &inputs, nil
}

func (c *CommandRunner) runCreateProfile(args []string, flags *flag.FlagSet) error {
	inputs, err := c.parseCreateProfileInputs(args, flags)
	if err != nil {
		return err
	}
	if inputs == nil {
		return nil // Already printed help text
	}
	return c.keytool.CreateProfile(inputs)
}

func (c *CommandRunner) parseCreateProfileInputs(args []string, flags *flag.FlagSet) (*keytool.CreateProfileInputs, error) {
	inputs := keytool.CreateProfileInputs{}
	flags.StringVar(&inputs.Name, NameArg, "", "Name of the cluster profile")
	flags.StringVar(&inputs.Host, HostArg, "", "Name of the host on which the MJS job manager is running")
	flags.StringVar(&inputs.Outfile, OutfileArg, "", "Location to write the profile file to")
	flags.StringVar(&inputs.CertFile, CertificateArg, "", "Location of the certificate to embed in the profile")
	flags.StringVar(&inputs.SecretFile, SecretfileArg, "", "Location of a shared secret file to use to generate a new certificate to inject into the profile")
	var metadataStr string
	flags.StringVar(&metadataStr, MetadataArg, "", "")

	if c.showHelpIfNeeded(CreateProfileCmd, args, flags) {
		return nil, nil
	}
	err := flags.Parse(args)
	if err != nil {
		return nil, err
	}

	// Check for required input arguments
	if inputs.Name == "" {
		return nil, getErrorForMissingArg(CreateProfileCmd, "must provide a cluster name (-name)")
	}
	if inputs.Host == "" {
		return nil, getErrorForMissingArg(CreateProfileCmd, "must provide a cluster host (-host)")
	}

	// Parse metadata argument if provided
	if metadataStr != "" {
		metadata, err := getMetadataFromString(metadataStr)
		if err != nil {
			return nil, err
		}
		inputs.Metadata = metadata
	}

	// If an output file was not provided, use the cluster name
	if inputs.Outfile == "" {
		inputs.Outfile = inputs.Name
	}
	inputs.Outfile = ensureJSON(inputs.Outfile)

	// Check whether a secret file was provided
	inputs.UseSecret = false
	if inputs.SecretFile != "" {
		if inputs.CertFile != "" {
			c.writer.WriteString("Warning: a certificate file and a secret file were both provided. The certificate file will be used and the secret file will be ignored.")
		} else {
			inputs.UseSecret = true // Use the secret only if a certificate file was not provided
		}
	}
	return &inputs, nil
}

func (c *CommandRunner) runGenerateMetricsCertificatesAndKeys(args []string, flags *flag.FlagSet) error {
	inputs, err := c.parseGenerateMetricsCertificatesAndKeysInputs(args, flags)
	if err != nil {
		return err
	}
	if inputs == nil {
		return nil // Already printed help text
	}
	return c.keytool.GenerateMetricsCertificatesAndKeys(inputs)
}

func (c *CommandRunner) parseGenerateMetricsCertificatesAndKeysInputs(args []string, flags *flag.FlagSet) (*keytool.GenerateMetricsCertificatesAndKeysInputs, error) {
	inputs := keytool.GenerateMetricsCertificatesAndKeysInputs{}
	flags.StringVar(&inputs.JobManagerHost, JobManagerHostArg, "", "Hostname of the job manager")
	flags.StringVar(&inputs.OutDir, OutdirArg, "", "Directory to write the certificate and key files to")
	if c.showHelpIfNeeded(GenerateMetricsCertificatesAndKeysCmd, args, flags) {
		return nil, nil
	}
	err := flags.Parse(args)
	if err != nil {
		return nil, err
	}

	// Check for required input arguments
	if inputs.JobManagerHost == "" {
		return nil, getErrorForMissingArg(GenerateMetricsCertificatesAndKeysCmd, "must provide a job manager hostname (-jobmanagerhost)")
	}
	return &inputs, nil
}

var longHelpStrings = map[string]string{
	CreateSharedSecretCmd: `Create a shared secret to establish trust within a cluster.

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
	GenerateCertificateCmd: `Generate a certificate using the shared secret file
of the MJS cluster you want to connect to.
The certificate is required by clients when the
REQUIRE_CLIENT_CERTIFICATE flag is set to 'true'
on the job manager.`,
	CreateProfileCmd: `Create a profile for an MJS cluster. This must contain
the name and the host name of the MJS cluster. If the
cluster is started with the REQUIRE_CLIENT_CERTIFICATE
flag set to 'true', you must specify the location of the
correct certificate file to authenticate the connection
to the cluster.`,
	GenerateMetricsCertificatesAndKeysCmd: `Generate the following certificate and key files for encrypted metrics:
  - A self-signed CA certificate file 'ca.crt' and corresponding
    key file 'ca.key'.  Both the job manager and Prometheus use
	'ca.crt' as their CA file.
  - A certificate file 'jobmanager.crt', which has the job manager's
    hostname embedded in it and is signed by the CA, along with the
	corresponding key file 'jobmanager.key'.  The job manager uses
	these for its certificate and key files, respectively.
  - A certificate file 'prometheus.crt', which is signed by the CA,
    and the corresponding key file 'prometheus.key'.  Prometheus uses
	these for its certificate and key files, respectively.
The command generates the files in the folder specified by '-outdir'.
If you do not specify '-outdir', the command generates the files in
the current folder.`,
}

type usageExample struct {
	description string
	command     string
}

// Usage examples for each command
var usageExamples = map[string][]usageExample{
	CreateSharedSecretCmd: {
		{"Create a shared secret to establish trust within a cluster", "%s %s [-outfile <output-file>]"},
	},
	GenerateCertificateCmd: {
		{"Generate a signed client certificate from a shared secret", "%s %s -secretfile <secret-file> [-outfile <output-file>]"},
	},
	CreateProfileCmd: {
		{"Create a profile for a cluster started with the REQUIRE_CLIENT_CERTIFICATE flag set to 'false'", "%s %s -name <cluster-name> -host <cluster-host> [-outfile <output-file>]"},
		{"Create a profile for a cluster started with the REQUIRE_CLIENT_CERTIFICATE flag set to 'true' by injecting a client certificate", "%s %s -name <cluster-name> -host <cluster-host> -certificate <certificate-file> [-outfile <output-file>]"},
		{"Create a profile for a cluster started with the REQUIRE_CLIENT_CERTIFICATE flag set to 'true' by generating a new signed client certificate and injecting it into the profile", "%s %s -name <cluster-name> -host <cluster-host> -secretfile <secret-file> [-outfile <output-file>]"},
	},
	GenerateMetricsCertificatesAndKeysCmd: {
		{"Generate a self-signed CA certificate and a pair of certificates signed by the CA (along with the corresponding keys) for use with metrics", "%s %s -jobmanagerhost <hostname> [-outdir <dir>]"},
	},
}

// Print general help text
func printAllHelp(writer StringWriter) {
	writer.WriteString(fmt.Sprintf("mjssetup: Tool for performing setup tasks for an MJS cluster.\n%s\n", getAllUsageText()))
}

// Create a string containing usage text for all commands
func getAllUsageText() string {
	txt := fmt.Sprintf("Usage: %s <command> [<args>]", getExecutableName())
	for _, cmd := range AllCommands {
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
func (c *CommandRunner) printCommandHelp(cmd string, flags *flag.FlagSet) {
	longHelpTxt := longHelpStrings[cmd]
	c.writer.WriteString(fmt.Sprintf("%s\n\n", longHelpTxt))
	c.writer.WriteString(fmt.Sprintf("Usage:\n%s\n", getUsageText(cmd, false)))
	c.writer.WriteString("\nInput arguments:\n")
	flags.VisitAll(func(f *flag.Flag) {
		printFlag(c.writer, f)
	})
}

func isHelpFlag(arg string) bool {
	for _, h := range HelpFlags {
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
	if !strings.HasSuffix(strings.ToLower(filename), jsonExt) {
		filename = filename + jsonExt
	}
	return filename
}

func getExecutableName() string {
	return filepath.Base(os.Args[0])
}

// Parse cluster metadata from a string. The string should contain key-value pairs with
// format: "key1=value1,key2=value2"
func getMetadataFromString(input string) (map[string]string, error) {
	metadata := map[string]string{}
	if input == "" {
		return metadata, nil
	}
	kvPairs := strings.Split(input, ",")
	for _, kvPair := range kvPairs {
		parts := strings.Split(kvPair, "=")
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid metadata format: %s", kvPair)
		}
		key := parts[0]
		value := parts[1]
		if key == "" {
			return nil, fmt.Errorf("empty metadata key: %s", kvPair)
		}
		metadata[key] = value
	}
	return metadata, nil
}

func printFlag(writer StringWriter, f *flag.Flag) {
	flagType, usage := flag.UnquoteUsage(f)

	// Skip flags with an empty usage string
	if usage == "" {
		return
	}

	writer.WriteString(fmt.Sprintf("  -%s %s\n", f.Name, flagType))
	writer.WriteString(fmt.Sprintf("\t%s\n", usage))
}
