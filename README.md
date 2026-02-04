# OPC UA NodeSet2 Exporter

[![Build and Test](https://github.com/your-org/OpcUaNodesetExporter/actions/workflows/build.yml/badge.svg)](https://github.com/your-org/OpcUaNodesetExporter/actions/workflows/build.yml)
[![NuGet](https://img.shields.io/nuget/v/OpcUaNodesetExporter.svg)](https://www.nuget.org/packages/OpcUaNodesetExporter/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A .NET global tool that connects to an OPC UA server and exports all custom namespaces into separate NodeSet2 XML files.

## Features

- 🔗 Connect to any OPC UA server
- 📦 Export namespaces to NodeSet2 XML format
- 🔒 Support for multiple security modes (None, Sign, SignAndEncrypt)
- 🔐 Multiple authentication methods (Anonymous, Username/Password, X.509 Certificate)
- 🔄 Automatic reconnection with configurable retry logic
- 🖥️ Cross-platform (Windows, Linux, macOS)
- 📝 Credential input via stdin for CI/CD pipelines

## Installation

```bash
dotnet tool install --global OpcUaNodesetExporter
```

## Quick Start

```bash
# Export namespaces with anonymous authentication
opcua-nodeset-export --endpoint opc.tcp://localhost:4840

# Export with username/password authentication
opcua-nodeset-export --endpoint opc.tcp://server:4840 --auth-mode UserName --username admin --password secret

# Export with environment variables
export OPCUA_ENDPOINT=opc.tcp://server:4840
export OPCUA_USERNAME=admin
export OPCUA_PASSWORD=secret
opcua-nodeset-export --auth-mode UserName
```

## Usage

```
opcua-nodeset-export [options]

Options:
  -e, --endpoint <endpoint>           OPC UA server endpoint URL (e.g., opc.tcp://localhost:4840)
  -m, --security-mode <mode>          Security mode: None, Sign, SignAndEncrypt [default: None]
  -p, --security-policy <policy>      Security policy: None, Basic256Sha256, Aes128_Sha256_RsaOaep, Aes256_Sha256_RsaPss [default: None]
  -a, --auth-mode <mode>              Authentication mode: Anonymous, UserName, Certificate [default: Anonymous]
  -u, --username <username>           Username for UserName authentication
      --password <password>           Password for UserName authentication
      --password-from-stdin           Read password from stdin (for piping)
  -c, --certificate-path <path>       Path to client X.509 certificate (PFX format)
      --certificate-password <pwd>    Password for the client certificate
      --certificate-from-stdin        Read certificate (base64 PFX) from stdin
  -o, --output <directory>            Output directory for NodeSet2 XML files [default: ./output]
      --retry-count <count>           Number of reconnection attempts on disconnect [default: 3]
      --retry-delay <seconds>         Delay between retries in seconds [default: 5]
  -v, --verbose                       Enable verbose logging
  -?, -h, --help                      Show help and usage information
```

## Environment Variables

The following environment variables can be used to configure the tool:

| Variable | Description | CLI Equivalent |
|----------|-------------|----------------|
| `OPCUA_ENDPOINT` | OPC UA server endpoint URL | `--endpoint` |
| `OPCUA_USERNAME` | Username for authentication | `--username` |
| `OPCUA_PASSWORD` | Password for authentication | `--password` |
| `OPCUA_CERTIFICATE_PATH` | Path to client certificate | `--certificate-path` |
| `OPCUA_CERTIFICATE_PASSWORD` | Client certificate password | `--certificate-password` |

## Examples

### Basic Export

```bash
# Export to default output directory (./output)
opcua-nodeset-export -e opc.tcp://localhost:4840

# Export to custom directory
opcua-nodeset-export -e opc.tcp://localhost:4840 -o ./my-nodesets
```

### Secure Connection

```bash
# Sign messages
opcua-nodeset-export -e opc.tcp://localhost:4840 \
  --security-mode Sign \
  --security-policy Basic256Sha256

# Sign and encrypt messages
opcua-nodeset-export -e opc.tcp://localhost:4840 \
  --security-mode SignAndEncrypt \
  --security-policy Aes256_Sha256_RsaPss
```

### Authentication

```bash
# Username and password
opcua-nodeset-export -e opc.tcp://localhost:4840 \
  --auth-mode UserName \
  --username admin \
  --password secret

# X.509 certificate
opcua-nodeset-export -e opc.tcp://localhost:4840 \
  --auth-mode Certificate \
  --certificate-path ./client.pfx \
  --certificate-password certpass
```

### CI/CD Pipeline Integration

```bash
# Password from stdin (Linux/macOS)
echo "$OPC_PASSWORD" | opcua-nodeset-export -e opc.tcp://server:4840 \
  --auth-mode UserName \
  --username admin \
  --password-from-stdin

# Certificate from stdin (base64 encoded PFX)
cat client.pfx | base64 | opcua-nodeset-export -e opc.tcp://server:4840 \
  --auth-mode Certificate \
  --certificate-from-stdin \
  --certificate-password certpass

# Using environment variables in GitHub Actions
env:
  OPCUA_ENDPOINT: opc.tcp://server:4840
  OPCUA_USERNAME: ${{ secrets.OPC_USERNAME }}
  OPCUA_PASSWORD: ${{ secrets.OPC_PASSWORD }}
run: opcua-nodeset-export --auth-mode UserName
```

### PowerShell (Windows)

```powershell
# Password from stdin
$env:OPC_PASSWORD | opcua-nodeset-export -e opc.tcp://server:4840 `
  --auth-mode UserName `
  --username admin `
  --password-from-stdin

# Using environment variables
$env:OPCUA_ENDPOINT = "opc.tcp://server:4840"
$env:OPCUA_USERNAME = "admin"
$env:OPCUA_PASSWORD = "secret"
opcua-nodeset-export --auth-mode UserName
```

## Output

The tool creates one NodeSet2 XML file per namespace in the output directory:

```
./output/
├── my.company.com_machines_ns2.xml
├── my.company.com_sensors_ns3.xml
└── vendor.example.com_devices_ns4.xml
```

**Notes:**
- Namespace 0 (OPC UA base types) is excluded
- OPC Foundation companion specifications (`http://opcfoundation.org/UA/*`) are excluded
- File names are derived from namespace URIs with invalid characters replaced

## Certificate Management

The tool uses a directory-based certificate store for cross-platform compatibility:

```
~/.opcua-nodeset-export/pki/
├── own/
│   ├── certs/      # Application certificate
│   └── private/    # Private key
├── trusted/
│   └── certs/      # Trusted server certificates
├── rejected/       # Rejected certificates
└── issuers/        # CA certificates
```

**Certificate Trust Policy:**
- Server certificates are automatically trusted (for development/testing)
- SHA1 signatures and 1024-bit keys are accepted (for legacy server compatibility)

For production environments, consider implementing proper certificate validation.

## Reconnection Handling

The tool automatically handles connection interruptions:

- Retries on transient errors (network issues, server restarts)
- Exponential backoff between retry attempts
- Configurable retry count and delay

```bash
# Custom retry settings
opcua-nodeset-export -e opc.tcp://server:4840 \
  --retry-count 5 \
  --retry-delay 10
```

## Building from Source

```bash
# Clone the repository
git clone https://github.com/your-org/OpcUaNodesetExporter.git
cd OpcUaNodesetExporter

# Build
dotnet build

# Run tests
dotnet test

# Pack as tool
dotnet pack -c Release

# Install locally
dotnet tool install --global --add-source ./src/OpcUaNodesetExporter/nupkg OpcUaNodesetExporter
```

## Running Integration Tests

Integration tests use .NET Aspire to run an OPC UA server simulation:

```bash
# Run integration tests (requires Docker)
dotnet test --filter "Category=Integration"
```

## Troubleshooting

### Connection Issues

```bash
# Enable verbose logging
opcua-nodeset-export -e opc.tcp://server:4840 --verbose
```

### Certificate Errors

If you see certificate-related errors:
1. Check that the PKI directory exists: `~/.opcua-nodeset-export/pki/`
2. Verify the server certificate is accessible
3. For secure connections, ensure your client certificate is valid

### Timeout Issues

Increase retry settings for slow networks or large servers:

```bash
opcua-nodeset-export -e opc.tcp://server:4840 \
  --retry-count 10 \
  --retry-delay 30
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Built on the [OPC Foundation UA .NET Standard](https://github.com/OPCFoundation/UA-.NETStandard) stack
- Reference implementation based on [ClientSamples.ExportNodesToNodeSet2PerNamespaceAsync](https://github.com/OPCFoundation/UA-.NETStandard/blob/master/Applications/ConsoleReferenceClient/ClientSamples.cs)
