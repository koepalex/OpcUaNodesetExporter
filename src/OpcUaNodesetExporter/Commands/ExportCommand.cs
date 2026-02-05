using System.CommandLine;
using System.CommandLine.Invocation;
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
            aliases: ["--endpoint", "-e"],
            description: "OPC UA server endpoint URL (e.g., opc.tcp://localhost:4840)")
        {
            IsRequired = false // Can come from environment variable
        };
        endpointOption.SetDefaultValueFactory(() => EnvironmentVariables.GetValue(EnvironmentVariables.Endpoint));

        // Security options
        var securityModeOption = new Option<string>(
            aliases: ["--security-mode", "-m"],
            description: "Security mode: None, Sign, SignAndEncrypt",
            getDefaultValue: () => "None");

        var securityPolicyOption = new Option<string>(
            aliases: ["--security-policy", "-p"],
            description: "Security policy: None, Basic256Sha256, Aes128_Sha256_RsaOaep, Aes256_Sha256_RsaPss",
            getDefaultValue: () => "None");

        // Authentication options
        var authModeOption = new Option<string>(
            aliases: ["--auth-mode", "-a"],
            description: "Authentication mode: Anonymous, UserName, Certificate",
            getDefaultValue: () => "Anonymous");

        var usernameOption = new Option<string?>(
            aliases: ["--username", "-u"],
            description: "Username for UserName authentication");
        usernameOption.SetDefaultValueFactory(() => EnvironmentVariables.GetValue(EnvironmentVariables.Username));

        var passwordOption = new Option<string?>(
            name: "--password",
            description: "Password for UserName authentication");
        passwordOption.SetDefaultValueFactory(() => EnvironmentVariables.GetValue(EnvironmentVariables.Password));

        var passwordFromStdinOption = new Option<bool>(
            name: "--password-from-stdin",
            description: "Read password from stdin (for piping)",
            getDefaultValue: () => false);

        // Certificate options
        var certificatePathOption = new Option<string?>(
            aliases: ["--certificate-path", "-c"],
            description: "Path to client X.509 certificate (PFX format)");
        certificatePathOption.SetDefaultValueFactory(() => EnvironmentVariables.GetValue(EnvironmentVariables.CertificatePath));

        var certificatePasswordOption = new Option<string?>(
            name: "--certificate-password",
            description: "Password for the client certificate");
        certificatePasswordOption.SetDefaultValueFactory(() => EnvironmentVariables.GetValue(EnvironmentVariables.CertificatePassword));

        var certificateFromStdinOption = new Option<bool>(
            name: "--certificate-from-stdin",
            description: "Read certificate (base64 PFX) from stdin",
            getDefaultValue: () => false);

        // Output options
        var outputOption = new Option<string>(
            aliases: ["--output", "-o"],
            description: "Output directory for NodeSet2 XML files",
            getDefaultValue: () => "./output");

        // Retry options
        var retryCountOption = new Option<int>(
            name: "--retry-count",
            description: "Number of reconnection attempts on disconnect",
            getDefaultValue: () => 3);

        var retryDelayOption = new Option<int>(
            name: "--retry-delay",
            description: "Delay between retries in seconds",
            getDefaultValue: () => 5);

        // Other options
        var verboseOption = new Option<bool>(
            aliases: ["--verbose", "-v"],
            description: "Enable verbose logging",
            getDefaultValue: () => false);

        // Add all options
        AddOption(endpointOption);
        AddOption(securityModeOption);
        AddOption(securityPolicyOption);
        AddOption(authModeOption);
        AddOption(usernameOption);
        AddOption(passwordOption);
        AddOption(passwordFromStdinOption);
        AddOption(certificatePathOption);
        AddOption(certificatePasswordOption);
        AddOption(certificateFromStdinOption);
        AddOption(outputOption);
        AddOption(retryCountOption);
        AddOption(retryDelayOption);
        AddOption(verboseOption);

        this.SetHandler(async (context) =>
        {
            var endpoint = context.ParseResult.GetValueForOption(endpointOption);
            var securityMode = context.ParseResult.GetValueForOption(securityModeOption)!;
            var securityPolicy = context.ParseResult.GetValueForOption(securityPolicyOption)!;
            var authMode = context.ParseResult.GetValueForOption(authModeOption)!;
            var username = context.ParseResult.GetValueForOption(usernameOption);
            var password = context.ParseResult.GetValueForOption(passwordOption);
            var passwordFromStdin = context.ParseResult.GetValueForOption(passwordFromStdinOption);
            var certificatePath = context.ParseResult.GetValueForOption(certificatePathOption);
            var certificatePassword = context.ParseResult.GetValueForOption(certificatePasswordOption);
            var certificateFromStdin = context.ParseResult.GetValueForOption(certificateFromStdinOption);
            var output = context.ParseResult.GetValueForOption(outputOption)!;
            var retryCount = context.ParseResult.GetValueForOption(retryCountOption);
            var retryDelay = context.ParseResult.GetValueForOption(retryDelayOption);
            var verbose = context.ParseResult.GetValueForOption(verboseOption);

            context.ExitCode = await ExecuteAsync(
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
                context.GetCancellationToken());
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
