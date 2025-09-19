# Setup Tool for MATLAB Job Scheduler

Use the mjssetup tool to create shared secrets, signed client certificates, and cluster profiles when you configure a MATLAB&reg; Job Scheduler cluster with secure communication.
You do not require access to a MATLAB installation.
For information about security configurations for MATLAB Job Scheduler clusters, see [MATLAB Job Scheduler Cluster Security](https://www.mathworks.com/help/matlab-parallel-server/set-matlab-job-scheduler-cluster-security.html).

## Installation

You can download pre-compiled binaries for Linux&reg; and Windows&reg; from the [Releases](https://github.com/mathworks/mjssetup/releases) page.

### Installation on Linux

1. Navigate to the [Releases](https://github.com/mathworks/mjssetup/releases) page.
2. Download the latest `mjssetup-glnxa64.tar.gz` file from the assets section of the latest release.
3. To extract the binary, in the terminal, run `tar -xzf mjssetup-glnxa64.tar.gz`.

### Installation on Windows

1. Navigate to the [Releases](https://github.com/mathworks/mjssetup/releases) page.
2. Download the latest `mjssetup-win64.zip` file from the assets section of the latest release.
3. To extract the binary, unzip the `mjssetup-win64.zip` file.

## Usage

`mjssetup <command> [<args>]` executes the specified command using the specified input arguments.
- `command` - Command to execute.
- `args` - Inputs to the command to execute. The types of the inputs depend on the command.

To display the help text for mjssetup, run
```
mjssetup -help
```

You can also display help text for a specific command.
For example, display the help text for the `create-shared-secret` command:
```
mjssetup create-shared-secret -help
```

### Examples

Create a shared secret to establish trust within a cluster.
Specify the `create-shared-secret` command and a name for the shared secret file.
For example, create a shared secret file with the name "secret.json".
```
mjssetup create-shared-secret -outfile "secret.json"
```

Generate a signed client certificate from a shared secret.
Specify the `generate-certificate` command, the path to the shared secret file, and the name of the certificate.
For example, generate a client certificate from the shared secret file "secret.json".
The command generates a client certificate with the name "client-certificate.json".
```
mjssetup generate-certificate -secretfile "secret.json" -outfile "client-certificate.json"
```

Create a cluster profile for a cluster that does not require client verification (REQUIRE_CLIENT_CERTIFICATE flag set to 'false').
Specify the `create-profile` command, the name and hostname of the cluster, and an output file for the profile.
For example, create a cluster profile for the cluster "cluster-name" and host name "cluster-host".
The command creates a cluster profile, "mjs-profile.json".
```
mjssetup create-profile -name "cluster-name" -host "cluster-host" -outfile "mjs-profile.json"
```

Use a client certificate to create a certified cluster profile for a cluster that requires client verification (REQUIRE_CLIENT_CERTIFICATE flag set to 'true').
Specify the `create-profile` command, the name and hostname of the cluster, the path of the client certificate file, and a name for the profile.
For example, create a cluster profile for the cluster "cluster-name", cluster hostname "cluster-host", and client certificate file "client-certificate.json".
The command creates a cluster profile file, "mjs-profile.json".
```
mjssetup create-profile -name "cluster-name" -host "cluster-host" -certificate "client-certificate.json" -outfile "mjs-profile.json"
```

Use the shared secret to create a certified cluster profile for a cluster that requires client verification (REQUIRE_CLIENT_CERTIFICATE flag set to 'true').
Specify the `create-profile` command, the name and hostname of the cluster, the path of the shared secret file, and a name for the profile.
For example, create a cluster profile for the cluster "cluster-name", cluster hostname "cluster-host", and shared secret file "secret.json".
The command creates a cluster profile file, "mjs-profile.json".
```
mjssetup create-profile -name "cluster-name" -host "cluster-host" -secretfile "secret.json" -outfile "mjs-profile.json"
```

Generate certificate and key files for use with encrypted metrics.
Specify the `generate-metrics-certificates-and-keys` command, the hostname of the job manager, and the output folder for the certificate and key files.
For example, generate metrics certificate and key files for a job manager with hostname "jobmanager-host" in a folder named "metrics".
```
mjssetup generate-metrics-certificates-and-keys -jobmanagerhost "jobmanager-host" -outdir "metrics"
```

## Build Setup Tool from Source Code

To download a zip file of this repository, at the top of this repository page, select Code > Download ZIP.
Alternatively, to clone this repository to your computer with Git installed, run the following command on your operating system's command line:

```
git clone https://github.com/mathworks/mjssetup
```

To compile the mjssetup executable from the source code, you must use Go version 1.23 or later.
Use Go to compile the mjssetup executable:
```
go build -o mjssetup cmd/mjssetup/main.go
```

## License

The license is available in the [license.txt](license.txt) file in this repository.

## Community Support

[MATLAB Central](https://www.mathworks.com/matlabcentral)

## Technical Support

If you require assistance or have a request for additional features or capabilities, contact [MathWorks Technical Support](https://www.mathworks.com/support/contact_us.html).

Copyright 2024-2025 The MathWorks, Inc.

