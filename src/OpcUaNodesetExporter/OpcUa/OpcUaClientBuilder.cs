using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Opc.Ua;
using Opc.Ua.Client;
using Opc.Ua.Configuration;

namespace OpcUaNodesetExporter.OpcUa;

/// <summary>
/// Fluent builder for creating and configuring OPC UA client connections.
/// </summary>
public class OpcUaClientBuilder
{
    private readonly ILoggerFactory _loggerFactory;
    private readonly ILogger<OpcUaClientBuilder> _logger;
    private string _endpoint = string.Empty;
    private MessageSecurityMode _securityMode = MessageSecurityMode.None;
    private string _securityPolicy = SecurityPolicies.None;
    private AuthenticationMode _authMode = AuthenticationMode.Anonymous;
    private string? _username;
    private string? _password;
    private X509Certificate2? _clientCertificate;
    private bool _trustAllCertificates = true;
    private int _retryCount = 3;
    private TimeSpan _retryDelay = TimeSpan.FromSeconds(5);
    private string _applicationName = "OpcUaNodesetExporter";
    private CertificateManager? _certificateManager;

    private OpcUaClientBuilder(ILoggerFactory loggerFactory)
    {
        _loggerFactory = loggerFactory;
        _logger = loggerFactory.CreateLogger<OpcUaClientBuilder>();
    }

    /// <summary>
    /// Creates a new OPC UA client builder instance.
    /// </summary>
    /// <param name="loggerFactory">The logger factory to use.</param>
    /// <returns>A new builder instance.</returns>
    public static OpcUaClientBuilder Create(ILoggerFactory loggerFactory)
    {
        return new OpcUaClientBuilder(loggerFactory);
    }

    /// <summary>
    /// Sets the OPC UA server endpoint URL.
    /// </summary>
    public OpcUaClientBuilder WithEndpoint(string endpoint)
    {
        _endpoint = endpoint ?? throw new ArgumentNullException(nameof(endpoint));
        return this;
    }

    /// <summary>
    /// Sets the security mode for the connection.
    /// </summary>
    public OpcUaClientBuilder WithSecurityMode(MessageSecurityMode securityMode)
    {
        _securityMode = securityMode;
        return this;
    }

    /// <summary>
    /// Sets the security policy for the connection.
    /// </summary>
    public OpcUaClientBuilder WithSecurityPolicy(string securityPolicy)
    {
        _securityPolicy = securityPolicy ?? SecurityPolicies.None;
        return this;
    }

    /// <summary>
    /// Configures anonymous authentication.
    /// </summary>
    public OpcUaClientBuilder WithAnonymousAuthentication()
    {
        _authMode = AuthenticationMode.Anonymous;
        return this;
    }

    /// <summary>
    /// Configures username/password authentication.
    /// </summary>
    public OpcUaClientBuilder WithUserNameAuthentication(string username, string password)
    {
        _authMode = AuthenticationMode.UserName;
        _username = username ?? throw new ArgumentNullException(nameof(username));
        _password = password ?? throw new ArgumentNullException(nameof(password));
        return this;
    }

    /// <summary>
    /// Configures certificate-based authentication.
    /// </summary>
    public OpcUaClientBuilder WithCertificateAuthentication(X509Certificate2 certificate)
    {
        _authMode = AuthenticationMode.Certificate;
        _clientCertificate = certificate ?? throw new ArgumentNullException(nameof(certificate));
        return this;
    }

    /// <summary>
    /// Sets the client certificate to use (for signing/encryption, not necessarily authentication).
    /// </summary>
    public OpcUaClientBuilder WithClientCertificate(X509Certificate2? certificate)
    {
        _clientCertificate = certificate;
        return this;
    }

    /// <summary>
    /// Configures the client to trust all server certificates.
    /// </summary>
    public OpcUaClientBuilder TrustAllServerCertificates(bool trust = true)
    {
        _trustAllCertificates = trust;
        return this;
    }

    /// <summary>
    /// Configures reconnection behavior on disconnect.
    /// </summary>
    public OpcUaClientBuilder WithReconnectOnDisconnect(int retryCount = 3, TimeSpan? retryDelay = null)
    {
        _retryCount = retryCount;
        _retryDelay = retryDelay ?? TimeSpan.FromSeconds(5);
        return this;
    }

    /// <summary>
    /// Sets the application name for the OPC UA client.
    /// </summary>
    public OpcUaClientBuilder WithApplicationName(string applicationName)
    {
        _applicationName = applicationName ?? throw new ArgumentNullException(nameof(applicationName));
        return this;
    }

    /// <summary>
    /// Sets the certificate manager to use.
    /// </summary>
    public OpcUaClientBuilder WithCertificateManager(CertificateManager certificateManager)
    {
        _certificateManager = certificateManager ?? throw new ArgumentNullException(nameof(certificateManager));
        return this;
    }

    /// <summary>
    /// Configures the builder from options.
    /// </summary>
    public OpcUaClientBuilder FromOptions(OpcUaClientOptions options)
    {
        _endpoint = options.Endpoint;
        _securityMode = options.SecurityMode;
        _securityPolicy = options.SecurityPolicy;
        _authMode = options.AuthMode;
        _username = options.Username;
        _password = options.Password;
        _clientCertificate = options.Certificate;
        _retryCount = options.RetryCount;
        _retryDelay = TimeSpan.FromSeconds(options.RetryDelaySeconds);
        _applicationName = options.ApplicationName;
        return this;
    }

    /// <summary>
    /// Builds and connects the OPC UA client.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A connected OPC UA client wrapper.</returns>
    public async Task<OpcUaClient> ConnectAsync(CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(_endpoint))
        {
            throw new InvalidOperationException("Endpoint must be specified.");
        }

        var certManager = _certificateManager ??
            new CertificateManager(_loggerFactory.CreateLogger<CertificateManager>());

        // Build application configuration
        var config = await BuildApplicationConfigurationAsync(certManager).ConfigureAwait(false);

        // Create and connect with retry logic
        var session = await ConnectWithRetryAsync(config, cancellationToken).ConfigureAwait(false);

        return new OpcUaClient(session, config, _loggerFactory, _retryCount, _retryDelay);
    }

    private async Task<ApplicationConfiguration> BuildApplicationConfigurationAsync(CertificateManager certManager)
    {
        var applicationUri = $"urn:{Environment.MachineName}:{_applicationName}";

        var config = new ApplicationConfiguration
        {
            ApplicationName = _applicationName,
            ApplicationType = ApplicationType.Client,
            ApplicationUri = applicationUri,
            ProductUri = "https://github.com/OpcUaNodesetExporter",
            SecurityConfiguration = certManager.CreateSecurityConfiguration(_applicationName),
            TransportConfigurations = new TransportConfigurationCollection(),
            TransportQuotas = new TransportQuotas
            {
                OperationTimeout = 120000,
                MaxStringLength = 4 * 1024 * 1024,
                MaxByteStringLength = 4 * 1024 * 1024,
                MaxArrayLength = 65535,
                MaxMessageSize = 16 * 1024 * 1024,
                MaxBufferSize = 65535,
                ChannelLifetime = 300000,
                SecurityTokenLifetime = 3600000
            },
            ClientConfiguration = new ClientConfiguration
            {
                DefaultSessionTimeout = 60000,
                MinSubscriptionLifetime = 10000
            },
            TraceConfiguration = new TraceConfiguration()
        };

        // Validate and update configuration
        await config.Validate(ApplicationType.Client).ConfigureAwait(false);

        // Get or create application certificate
        if (_clientCertificate == null && _securityMode != MessageSecurityMode.None)
        {
            _clientCertificate = await certManager.GetOrCreateApplicationCertificateAsync(
                _applicationName, applicationUri).ConfigureAwait(false);
        }

        if (_clientCertificate != null)
        {
            config.SecurityConfiguration.ApplicationCertificate.Certificate = _clientCertificate;
        }

        // Configure certificate validation
        if (_trustAllCertificates)
        {
            config.CertificateValidator.CertificateValidation += (sender, e) =>
            {
                _logger.LogDebug("Auto-accepting certificate: {Subject} (Status: {Status})",
                    e.Certificate.Subject, e.Error?.StatusCode);
                e.Accept = true;
            };
        }

        return config;
    }

    private async Task<ISession> ConnectWithRetryAsync(
        ApplicationConfiguration config,
        CancellationToken cancellationToken)
    {
        Exception? lastException = null;

        for (int attempt = 0; attempt <= _retryCount; attempt++)
        {
            try
            {
                if (attempt > 0)
                {
                    var delay = TimeSpan.FromSeconds(_retryDelay.TotalSeconds * Math.Pow(2, attempt - 1));
                    _logger.LogWarning("Connection attempt {Attempt}/{Total} failed. Retrying in {Delay}s...",
                        attempt, _retryCount + 1, delay.TotalSeconds);
                    await Task.Delay(delay, cancellationToken).ConfigureAwait(false);
                }

                _logger.LogInformation("Connecting to {Endpoint} (attempt {Attempt}/{Total})...",
                    _endpoint, attempt + 1, _retryCount + 1);

                return await CreateSessionAsync(config, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex) when (IsTransientError(ex))
            {
                lastException = ex;
                _logger.LogWarning(ex, "Transient connection error on attempt {Attempt}", attempt + 1);

                if (attempt == _retryCount)
                {
                    throw new OpcUaConnectionException(
                        $"Failed to connect to {_endpoint} after {_retryCount + 1} attempts.",
                        lastException);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Non-transient connection error");
                throw;
            }
        }

        throw new OpcUaConnectionException(
            $"Failed to connect to {_endpoint} after {_retryCount + 1} attempts.",
            lastException);
    }

    private async Task<ISession> CreateSessionAsync(
        ApplicationConfiguration config,
        CancellationToken cancellationToken)
    {
        // Discover endpoints
        var selectedEndpoint = CoreClientUtils.SelectEndpoint(config, _endpoint, _securityMode != MessageSecurityMode.None);

        // Apply security settings if specified
        if (_securityMode != MessageSecurityMode.None)
        {
            selectedEndpoint.SecurityMode = _securityMode;
            selectedEndpoint.SecurityPolicyUri = _securityPolicy;
        }

        var endpointConfiguration = EndpointConfiguration.Create(config);
        var endpoint = new ConfiguredEndpoint(null, selectedEndpoint, endpointConfiguration);

        // Create user identity
        var userIdentity = CreateUserIdentity();

        // Create session
        var session = await Session.Create(
            config,
            endpoint,
            false,
            false,
            _applicationName,
            60000,
            userIdentity,
            null,
            cancellationToken).ConfigureAwait(false);

        _logger.LogInformation("Connected to {Endpoint}. Session ID: {SessionId}",
            _endpoint, session.SessionId);

        return session;
    }

    private UserIdentity CreateUserIdentity()
    {
        return _authMode switch
        {
            AuthenticationMode.Anonymous => new UserIdentity(),
            AuthenticationMode.UserName => new UserIdentity(_username, System.Text.Encoding.UTF8.GetBytes(_password ?? string.Empty)),
            AuthenticationMode.Certificate => _clientCertificate != null
                ? new UserIdentity(_clientCertificate)
                : throw new InvalidOperationException("Certificate is required for certificate authentication."),
            _ => new UserIdentity()
        };
    }

    private static bool IsTransientError(Exception ex)
    {
        if (ex is ServiceResultException sre)
        {
            var code = sre.StatusCode;
            return code == StatusCodes.BadServerNotConnected ||
                   code == StatusCodes.BadConnectionClosed ||
                   code == StatusCodes.BadCommunicationError ||
                   code == StatusCodes.BadTimeout ||
                   code == StatusCodes.BadRequestTimeout ||
                   code == StatusCodes.BadSecureChannelClosed ||
                   code == StatusCodes.BadTcpServerTooBusy;
        }

        return ex is TimeoutException ||
               ex is System.Net.Sockets.SocketException ||
               ex is System.IO.IOException;
    }
}

/// <summary>
/// Exception thrown when OPC UA connection fails.
/// </summary>
public class OpcUaConnectionException : Exception
{
    public OpcUaConnectionException(string message) : base(message) { }
    public OpcUaConnectionException(string message, Exception? innerException) : base(message, innerException) { }
}
