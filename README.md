# OPC UA NodeSet2 Exporter

[![Build and Test](https://github.com/koepalex/OpcUaNodesetExporter/actions/workflows/build.yml/badge.svg?branch=main)](https://github.com/koepalex/OpcUaNodesetExporter/actions/workflows/build.yml)
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
- 🩺 Optional attribute diagnostics (`--export-attributes`): JSON sidecar with
  every standard attribute (incl. `Value`) and its `StatusCode` per node

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
  -s, --start-node <node>             Export subtree from this ExpandedNodeId (e.g., nsu=example.com/opcua/;i=5)
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
      --keep-alive <seconds>          Keep-alive interval in seconds [default: 5]
      --session-timeout <seconds>     Session timeout in seconds [default: 120]
      --keep-alive-threshold <count>  Missed keep-alives before reconnect [default: 3]
      --export-attributes             Read all standard attributes (incl. Value) and write a JSON
                                      sidecar per NodeSet2 file with attribute values and status codes
      --log-file <path>               Also append all log output to this file (Debug level when
                                      --verbose is set, otherwise Information). Parent directories
                                      are created on demand.
  -v, --verbose                       Enable verbose logging
  -?, -h, --help                      Show help and usage information
```

## Environment Variables

The following environment variables can be used to configure the tool:

| Variable | Description | CLI Equivalent |
|----------|-------------|----------------|
| `OPCUA_ENDPOINT` | OPC UA server endpoint URL | `--endpoint` |
| `OPCUA_START_NODE` | ExpandedNodeId for subtree export | `--start-node` |
| `OPCUA_USERNAME` | Username for authentication | `--username` |
| `OPCUA_PASSWORD` | Password for authentication | `--password` |
| `OPCUA_CERTIFICATE_PATH` | Path to client certificate | `--certificate-path` |
| `OPCUA_CERTIFICATE_PASSWORD` | Client certificate password | `--certificate-password` |
| `OPCUA_LOG_FILE` | Optional log file path | `--log-file` |

## Examples

### Basic Export

```bash
# Export to default output directory (./output)
opcua-nodeset-export -e opc.tcp://localhost:4840

# Export to custom directory
opcua-nodeset-export -e opc.tcp://localhost:4840 -o ./my-nodesets
```

### Subtree Export

Export a specific subtree starting from a given node. Only type definitions in the same namespace as the start node are included; types from other namespaces are referenced but not exported.

```bash
# Export subtree starting from a specific node (ExpandedNodeId format)
opcua-nodeset-export -e opc.tcp://localhost:4840 -s "ns=4;i=5"

# Export subtree with custom output directory
opcua-nodeset-export -e opc.tcp://localhost:4840 -s "ns=4;i=5" -o ./subtree-export

# Export subtree using a string node ID
opcua-nodeset-export -e opc.tcp://localhost:4840 -s "ns=3;s=MyDevice"
```

The output is a single NodeSet2 XML file containing:
- The start node and all its subnodes (via hierarchical references)
- Type definitions used by the subtree that are in the same namespace as the start node
- Supertypes of included types (if also in the same namespace)

### Diagnostic Attribute Export (`--export-attributes`)

By default the exporter populates only the attributes that the OPC UA Browse
service returns. Every other attribute (such as `Value`, `ValueRank`,
`MinimumSamplingInterval`, `DataType`, `AccessLevel`, ...) is re-read from
the server before serialization, so the produced NodeSet2 XML reflects the
real address space — `ValueRank="-2"` and `MinimumSamplingInterval="-1"` no
longer leak through as the SDK's in-memory defaults.

`--export-attributes` additionally:

- Reads the `Value` attribute of every Variable / VariableType node, so the
  NodeSet2 XML contains a `<Value>` element when the server returned data.
- Writes a JSON diagnostic file alongside each NodeSet2 XML named
  `<namespace>_attributes.json`. The file records every attribute relevant to
  each node's `NodeClass` together with the OPC UA `StatusCode` returned by
  the server. This makes it easy to spot variables that have an empty value,
  return `BadAttributeIdInvalid`, or otherwise fail to read.

```bash
# Full export with attribute diagnostics
opcua-nodeset-export -e opc.tcp://localhost:4840 --export-attributes

# Subtree export with diagnostics (works in both modes)
opcua-nodeset-export -e opc.tcp://localhost:4840 -s "ns=4;i=5" --export-attributes
```

Example excerpt of `<namespace>_attributes.json`:

```json
{
  "namespaceUri": "http://example.com/devices/",
  "namespaceIndex": 4,
  "exportedAt": "2026-06-10T18:42:00Z",
  "nodes": [
    {
      "nodeId": "ns=4;i=1234",
      "browseName": "4:MyVar",
      "displayName": "MyVar",
      "nodeClass": "Variable",
      "attributes": {
        "Value":                   { "status": "Good",             "statusCode": "0x00000000", "value": 42 },
        "DataType":                { "status": "Int32",            "statusCode": "0x00000000", "value": "i=6" },
        "ValueRank":               { "status": "Good",             "statusCode": "0x00000000", "value": -1 },
        "AccessLevel":             { "status": "Good",             "statusCode": "0x00000000", "value": 3 },
        "MinimumSamplingInterval": { "status": "BadNotReadable",   "statusCode": "0x803A0000", "value": null }
      }
    }
  ]
}
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
- Keep-alive monitoring with automatic reconnection on failure

```bash
# Custom retry settings
opcua-nodeset-export -e opc.tcp://server:4840 \
  --retry-count 5 \
  --retry-delay 10
```

### Keep-Alive Configuration

The client sends periodic keep-alive requests to detect connection issues early. If the server doesn't respond, the client automatically attempts to reconnect.

| Option | Default | Description |
|--------|---------|-------------|
| `--keep-alive` | 5 | Interval between keep-alive requests (seconds) |
| `--session-timeout` | 120 | Maximum time server keeps session alive without communication (seconds) |
| `--keep-alive-threshold` | 3 | Number of missed keep-alives before triggering reconnection |

**For slow or unreliable networks:**

```bash
opcua-nodeset-export -e opc.tcp://server:4840 \
  --session-timeout 300 \
  --keep-alive 10 \
  --keep-alive-threshold 5
```

This configuration gives more tolerance for temporary network issues by extending the session timeout to 5 minutes and allowing up to 5 missed keep-alives (~50 seconds) before reconnecting.

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

# Capture verbose log output to a file (in addition to the console)
opcua-nodeset-export -e opc.tcp://server:4840 --verbose --log-file ./logs/export.log
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

### Keep-Alive Errors

If you see errors like `Keep-alive error: [80310000] 'Server not responding to keep alive requests.'`:

1. **Increase session timeout** for slow networks:
   ```bash
   opcua-nodeset-export -e opc.tcp://server:4840 --session-timeout 300
   ```

2. **Reduce keep-alive frequency** if the server is overloaded:
   ```bash
   opcua-nodeset-export -e opc.tcp://server:4840 --keep-alive 15
   ```

3. **Increase failure tolerance** for unstable connections:
   ```bash
   opcua-nodeset-export -e opc.tcp://server:4840 --keep-alive-threshold 5
   ```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Built on the [OPC Foundation UA .NET Standard](https://github.com/OPCFoundation/UA-.NETStandard) stack
- Uses the SDK's verified `CoreClientUtils.ExportNodesToNodeSet2` for NodeSet2 export functionality
