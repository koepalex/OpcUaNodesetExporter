using Opc.Ua;

namespace OpcUaNodesetExporter.OpcUa;

/// <summary>
/// Configuration options for the OPC UA client connection.
/// </summary>
public class OpcUaClientOptions
{
    /// <summary>
    /// The OPC UA server endpoint URL (e.g., opc.tcp://localhost:4840).
    /// </summary>
    public required string Endpoint { get; set; }

    /// <summary>
    /// The security mode for the connection.
    /// </summary>
    public MessageSecurityMode SecurityMode { get; set; } = MessageSecurityMode.None;

    /// <summary>
    /// The security policy URI for the connection.
    /// </summary>
    public string SecurityPolicy { get; set; } = SecurityPolicies.None;

    /// <summary>
    /// The authentication mode to use.
    /// </summary>
    public AuthenticationMode AuthMode { get; set; } = AuthenticationMode.Anonymous;

    /// <summary>
    /// Username for UserName authentication.
    /// </summary>
    public string? Username { get; set; }

    /// <summary>
    /// Password for UserName authentication.
    /// </summary>
    public string? Password { get; set; }

    /// <summary>
    /// Path to the client X.509 certificate file (PFX format).
    /// </summary>
    public string? CertificatePath { get; set; }

    /// <summary>
    /// Password for the client certificate.
    /// </summary>
    public string? CertificatePassword { get; set; }

    /// <summary>
    /// The loaded client certificate (populated from file or stdin).
    /// </summary>
    public System.Security.Cryptography.X509Certificates.X509Certificate2? Certificate { get; set; }

    /// <summary>
    /// Output directory for NodeSet2 XML files.
    /// </summary>
    public string OutputDirectory { get; set; } = "./output";

    /// <summary>
    /// Enable verbose logging output.
    /// </summary>
    public bool Verbose { get; set; }

    /// <summary>
    /// Number of reconnection attempts on disconnect.
    /// </summary>
    public int RetryCount { get; set; } = 3;

    /// <summary>
    /// Delay between retry attempts in seconds.
    /// </summary>
    public int RetryDelaySeconds { get; set; } = 5;

    /// <summary>
    /// Application name used for the OPC UA client.
    /// </summary>
    public string ApplicationName { get; set; } = "OpcUaNodesetExporter";

    /// <summary>
    /// Application URI used for the OPC UA client.
    /// </summary>
    public string ApplicationUri => $"urn:{Environment.MachineName}:{ApplicationName}";
}

/// <summary>
/// Authentication modes supported by the client.
/// </summary>
public enum AuthenticationMode
{
    /// <summary>
    /// Anonymous authentication (no credentials required).
    /// </summary>
    Anonymous,

    /// <summary>
    /// Username and password authentication.
    /// </summary>
    UserName,

    /// <summary>
    /// X.509 certificate-based authentication.
    /// </summary>
    Certificate
}
