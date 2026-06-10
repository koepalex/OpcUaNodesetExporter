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
    /// When true, the exporter reads all standard attributes (including the
    /// <c>Value</c> attribute for Variable and VariableType nodes) and writes
    /// a JSON sidecar file per produced NodeSet2 XML that records every
    /// attribute and its <see cref="StatusCode"/>. This is primarily intended
    /// for detecting nodes with empty values or unreadable attributes.
    /// </summary>
    public bool ExportAttributes { get; set; }

    /// <summary>
    /// Number of reconnection attempts on disconnect.
    /// </summary>
    public int RetryCount { get; set; } = 3;

    /// <summary>
    /// Delay between retry attempts in seconds.
    /// </summary>
    public int RetryDelaySeconds { get; set; } = 5;

    /// <summary>
    /// Keep-alive interval in seconds. The client sends periodic requests to check 
    /// if the server is still responsive. Lower values detect disconnects faster 
    /// but increase network traffic.
    /// </summary>
    public int KeepAliveIntervalSeconds { get; set; } = 5;

    /// <summary>
    /// Session timeout in seconds. This is the maximum time the server will keep 
    /// the session alive without communication. Should be higher than KeepAliveInterval.
    /// Increase this value for slow or unreliable networks.
    /// </summary>
    public int SessionTimeoutSeconds { get; set; } = 120;

    /// <summary>
    /// Number of consecutive missed keep-alive responses before triggering automatic 
    /// reconnection. Default is 3 (reconnect after ~15 seconds with default keep-alive interval).
    /// </summary>
    public int KeepAliveFailureThreshold { get; set; } = 3;

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
