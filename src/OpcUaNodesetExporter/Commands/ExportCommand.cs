using System.CommandLine;
using System.CommandLine.Invocation;
using System.CommandLine.Parsing;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Opc.Ua;
using OpcUaNodesetExporter.Configuration;
using OpcUaNodesetExporter.OpcUa;

namespace OpcUaNodesetExporter.Commands;

/// <summary>
/// The main export command for the OPC UA NodeSet2 exporter tool.
/// </summary>
public class ExportCommand : RootCommand
{
    public ExportCommand() : base("Exports OPC UA server namespaces to NodeSet2 XML files.")
    {
        // Required options
        var endpointOption = new Option<string?>(
            name: "--endpoint",
            aliases: new[] { "-e" })
        {
            Description = "OPC UA server endpoint URL (e.g., opc.tcp://localhost:4840)",
            DefaultValueFactory = (_) => EnvironmentVariables.GetValue(EnvironmentVariables.Endpoint)
        };

        // Security options
        var securityModeOption = new Option<string>(
            name: "--security-mode",
            aliases: new[] { "-m" })
        {
            Description = "Security mode: None, Sign, SignAndEncrypt",
            DefaultValueFactory = (_) => "None"
        };

        var securityPolicyOption = new Option<string>(
            name: "--security-policy",
            aliases: new[] { "-p" })
        {
            Description = "Security policy: None, Basic256Sha256, Aes128_Sha256_RsaOaep, Aes256_Sha256_RsaPss",
            DefaultValueFactory = (_) => "None"
        };

        // Authentication options
        var authModeOption = new Option<string>(
            name: "--auth-mode",
            aliases: new[] { "-a" })
        {
            Description = "Authentication mode: Anonymous, UserName, Certificate",
            DefaultValueFactory = (_) => "Anonymous"
        };

        var usernameOption = new Option<string?>(
            name: "--username",
            aliases: new[] { "-u" })
        {
            Description = "Username for UserName authentication",
            DefaultValueFactory = (_) => EnvironmentVariables.GetValue(EnvironmentVariables.Username)
        };

        var passwordOption = new Option<string?>(
            name: "--password")
        {
            Description = "Password for UserName authentication",
            DefaultValueFactory = (_) => EnvironmentVariables.GetValue(EnvironmentVariables.Password)
        };

        var passwordFromStdinOption = new Option<bool>(
            name: "--password-from-stdin")
        {
            Description = "Read password from stdin (for piping)",
            DefaultValueFactory = (_) => false
        };

        // Certificate options
        var certificatePathOption = new Option<string?>(
            name: "--certificate-path",
            aliases: new[] { "-c" })
        {
            Description = "Path to client X.509 certificate (PFX format)",
            DefaultValueFactory = (_) => EnvironmentVariables.GetValue(EnvironmentVariables.CertificatePath)
        };

        var certificatePasswordOption = new Option<string?>(
            name: "--certificate-password")
        {
            Description = "Password for the client certificate",
            DefaultValueFactory = (_) => EnvironmentVariables.GetValue(EnvironmentVariables.CertificatePassword)
        };

        var certificateFromStdinOption = new Option<bool>(
            name: "--certificate-from-stdin")
        {
            Description = "Read certificate (base64 PFX) from stdin",
            DefaultValueFactory = (_) => false
        };

        // Output options
        var outputOption = new Option<string>(
            name: "--output",
            aliases: new[] { "-o" })
        {
            Description = "Output directory for NodeSet2 XML files",
            DefaultValueFactory = (_) => "./output"
        };

        // Retry options
        var retryCountOption = new Option<int>(
            name: "--retry-count")
        {
            Description = "Number of reconnection attempts on disconnect",
            DefaultValueFactory = (_) => 3
        };

        var retryDelayOption = new Option<int>(
            name: "--retry-delay")
        {
            Description = "Delay between retries in seconds",
            DefaultValueFactory = (_) => 5
        };

        // Other options
        var verboseOption = new Option<bool>(
            name: "--verbose",
            aliases: new[] { "-v" })
        {
            Description = "Enable verbose logging",
            DefaultValueFactory = (_) => false
        };

        // Add all options
        Options.Add(endpointOption);
        Options.Add(securityModeOption);
        Options.Add(securityPolicyOption);
        Options.Add(authModeOption);
        Options.Add(usernameOption);
        Options.Add(passwordOption);
        Options.Add(passwordFromStdinOption);
        Options.Add(certificatePathOption);
        Options.Add(certificatePasswordOption);
        Options.Add(certificateFromStdinOption);
        Options.Add(outputOption);
        Options.Add(retryCountOption);
        Options.Add(retryDelayOption);
        Options.Add(verboseOption);

        this.SetAction(async (parseResult, cancellationToken) =>
        {
            var endpoint = parseResult.GetValue(endpointOption);
            var securityMode = parseResult.GetValue(securityModeOption)!;
            var securityPolicy = parseResult.GetValue(securityPolicyOption)!;
            var authMode = parseResult.GetValue(authModeOption)!;
            var username = parseResult.GetValue(usernameOption);
            var password = parseResult.GetValue(passwordOption);
            var passwordFromStdin = parseResult.GetValue(passwordFromStdinOption);
            var certificatePath = parseResult.GetValue(certificatePathOption);
            var certificatePassword = parseResult.GetValue(certificatePasswordOption);
            var certificateFromStdin = parseResult.GetValue(certificateFromStdinOption);
            var output = parseResult.GetValue(outputOption)!;
            var retryCount = parseResult.GetValue(retryCountOption);
            var retryDelay = parseResult.GetValue(retryDelayOption);
            var verbose = parseResult.GetValue(verboseOption);

            return await ExecuteAsync(
                endpoint,
                securityMode,
                securityPolicy,
                authMode,
                username,
                password,
                passwordFromStdin,
                certificatePath,
                certificatePassword,
                certificateFromStdin,
                output,
                retryCount,
                retryDelay,
                verbose,
                cancellationToken);
        });
    }

    private static async Task<int> ExecuteAsync(
        string? endpoint,
        string securityMode,
        string securityPolicy,
        string authMode,
        string? username,
        string? password,
        bool passwordFromStdin,
        string? certificatePath,
        string? certificatePassword,
        bool certificateFromStdin,
        string output,
        int retryCount,
        int retryDelay,
        bool verbose,
        CancellationToken cancellationToken)
    {
        // Configure logging
        using var loggerFactory = LoggerFactory.Create(builder =>
        {
            builder.AddConsole();
            builder.SetMinimumLevel(verbose ? LogLevel.Debug : LogLevel.Information);
        });

        var logger = loggerFactory.CreateLogger<ExportCommand>();

        try
        {
            // Validate endpoint
            if (string.IsNullOrWhiteSpace(endpoint))
            {
                logger.LogError("Endpoint is required. Provide via --endpoint or OPCUA_ENDPOINT environment variable.");
                return 1;
            }

            // Handle password from stdin
            if (passwordFromStdin)
            {
                logger.LogDebug("Reading password from stdin...");
                password = await StdinReader.ReadLineAsync(cancellationToken);
                if (string.IsNullOrEmpty(password))
                {
                    logger.LogError("No password provided via stdin.");
                    return 1;
                }
            }

            // Handle certificate from stdin
            X509Certificate2? certificate = null;
            if (certificateFromStdin)
            {
                logger.LogDebug("Reading certificate from stdin (base64 PFX)...");
                var certBytes = await StdinReader.ReadBase64CertificateAsync(cancellationToken);
                if (certBytes == null)
                {
                    logger.LogError("No certificate provided via stdin.");
                    return 1;
                }
                certificate = X509CertificateLoader.LoadPkcs12(certBytes, certificatePassword,
                    X509KeyStorageFlags.Exportable | X509KeyStorageFlags.MachineKeySet);
                logger.LogInformation("Loaded certificate from stdin: {Subject}", certificate.Subject);
            }
            else if (!string.IsNullOrEmpty(certificatePath))
            {
                var certManager = new CertificateManager(loggerFactory.CreateLogger<CertificateManager>());
                certificate = certManager.LoadCertificateFromFile(certificatePath, certificatePassword);
            }

            // Build options
            var options = new OpcUaClientOptions
            {
                Endpoint = endpoint,
                SecurityMode = ParseSecurityMode(securityMode),
                SecurityPolicy = ParseSecurityPolicy(securityPolicy),
                AuthMode = ParseAuthMode(authMode),
                Username = username,
                Password = password,
                Certificate = certificate,
                OutputDirectory = output,
                RetryCount = retryCount,
                RetryDelaySeconds = retryDelay,
                Verbose = verbose
            };

            // Validate authentication requirements
            if (options.AuthMode == AuthenticationMode.UserName)
            {
                if (string.IsNullOrEmpty(options.Username) || string.IsNullOrEmpty(options.Password))
                {
                    logger.LogError("Username and password are required for UserName authentication.");
                    return 1;
                }
            }
            else if (options.AuthMode == AuthenticationMode.Certificate)
            {
                if (options.Certificate == null)
                {
                    logger.LogError("Certificate is required for Certificate authentication.");
                    return 1;
                }
            }

            logger.LogInformation("OPC UA NodeSet2 Exporter");
            logger.LogInformation("========================");
            logger.LogInformation("Endpoint: {Endpoint}", options.Endpoint);
            logger.LogInformation("Security Mode: {SecurityMode}", options.SecurityMode);
            logger.LogInformation("Security Policy: {SecurityPolicy}", options.SecurityPolicy);
            logger.LogInformation("Authentication: {AuthMode}", options.AuthMode);
            logger.LogInformation("Output Directory: {Output}", options.OutputDirectory);
            logger.LogInformation("");

            // Connect to server
            logger.LogInformation("Connecting to OPC UA server...");

            await using var client = await OpcUaClientBuilder
                .Create(loggerFactory)
                .FromOptions(options)
                .TrustAllServerCertificates()
                .ConnectAsync(cancellationToken);

            logger.LogInformation("Connected successfully!");

            // Export namespaces
            var exporter = new NodeSetExporter(
                loggerFactory.CreateLogger<NodeSetExporter>(),
                loggerFactory,
                client,
                options.Verbose);

            var exportedFiles = await exporter.ExportAllNamespacesAsync(
                options.OutputDirectory,
                cancellationToken);

            // Print summary
            logger.LogInformation("");
            logger.LogInformation("Export Summary");
            logger.LogInformation("==============");
            foreach (var kvp in exportedFiles)
            {
                logger.LogInformation("  {Namespace} -> {File}", kvp.Key, Path.GetFileName(kvp.Value));
            }
            logger.LogInformation("");
            logger.LogInformation("Successfully exported {Count} namespace(s) to {Directory}",
                exportedFiles.Count, Path.GetFullPath(options.OutputDirectory));

            return 0;
        }
        catch (OperationCanceledException)
        {
            logger.LogWarning("Operation cancelled.");
            return 130;
        }
        catch (OpcUaConnectionException ex)
        {
            logger.LogError(ex, "Failed to connect to OPC UA server.");
            return 2;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "An unexpected error occurred.");
            return 1;
        }
    }

    private static MessageSecurityMode ParseSecurityMode(string mode)
    {
        return mode.ToLowerInvariant() switch
        {
            "none" => MessageSecurityMode.None,
            "sign" => MessageSecurityMode.Sign,
            "signandencrypt" => MessageSecurityMode.SignAndEncrypt,
            _ => throw new ArgumentException($"Invalid security mode: {mode}. Valid values: None, Sign, SignAndEncrypt")
        };
    }

    private static string ParseSecurityPolicy(string policy)
    {
        return policy.ToLowerInvariant() switch
        {
            "none" => SecurityPolicies.None,
            "basic256sha256" => SecurityPolicies.Basic256Sha256,
            "aes128_sha256_rsaoaep" => SecurityPolicies.Aes128_Sha256_RsaOaep,
            "aes256_sha256_rsapss" => SecurityPolicies.Aes256_Sha256_RsaPss,
            _ => throw new ArgumentException($"Invalid security policy: {policy}. Valid values: None, Basic256Sha256, Aes128_Sha256_RsaOaep, Aes256_Sha256_RsaPss")
        };
    }

    private static AuthenticationMode ParseAuthMode(string mode)
    {
        return mode.ToLowerInvariant() switch
        {
            "anonymous" => AuthenticationMode.Anonymous,
            "username" => AuthenticationMode.UserName,
            "certificate" => AuthenticationMode.Certificate,
            _ => throw new ArgumentException($"Invalid authentication mode: {mode}. Valid values: Anonymous, UserName, Certificate")
        };
    }
}
