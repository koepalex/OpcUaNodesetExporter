using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Opc.Ua;

namespace OpcUaNodesetExporter.OpcUa;

/// <summary>
/// Manages X.509 certificates for OPC UA client authentication.
/// Uses directory-based certificate store for cross-platform compatibility.
/// </summary>
public class CertificateManager
{
    private readonly ILogger<CertificateManager> _logger;
    private readonly string _pkiRoot;

    /// <summary>
    /// Creates a new instance of the CertificateManager.
    /// </summary>
    /// <param name="logger">Logger instance.</param>
    /// <param name="pkiRoot">Optional custom PKI root directory. Defaults to ~/.opcua-nodeset-export/pki</param>
    public CertificateManager(ILogger<CertificateManager> logger, string? pkiRoot = null)
    {
        _logger = logger;
        _pkiRoot = pkiRoot ?? GetDefaultPkiRoot();
        EnsurePkiDirectoriesExist();
    }

    /// <summary>
    /// Gets the default PKI root directory path.
    /// </summary>
    public static string GetDefaultPkiRoot()
    {
        return Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            ".opcua-nodeset-export",
            "pki");
    }

    /// <summary>
    /// Gets the path to the own certificates directory.
    /// </summary>
    public string OwnCertsPath => Path.Combine(_pkiRoot, "own", "certs");

    /// <summary>
    /// Gets the path to the own private keys directory.
    /// </summary>
    public string OwnPrivatePath => Path.Combine(_pkiRoot, "own", "private");

    /// <summary>
    /// Gets the path to the trusted certificates directory.
    /// </summary>
    public string TrustedCertsPath => Path.Combine(_pkiRoot, "trusted", "certs");

    /// <summary>
    /// Gets the path to the rejected certificates directory.
    /// </summary>
    public string RejectedCertsPath => Path.Combine(_pkiRoot, "rejected");

    /// <summary>
    /// Gets the path to the issuer certificates directory.
    /// </summary>
    public string IssuerCertsPath => Path.Combine(_pkiRoot, "issuers", "certs");

    /// <summary>
    /// Loads an X.509 certificate from a file.
    /// </summary>
    /// <param name="path">Path to the certificate file (PFX format).</param>
    /// <param name="password">Password for the certificate file.</param>
    /// <returns>The loaded certificate.</returns>
    public X509Certificate2 LoadCertificateFromFile(string path, string? password = null)
    {
        _logger.LogDebug("Loading certificate from file: {Path}", path);

        if (!File.Exists(path))
        {
            throw new FileNotFoundException($"Certificate file not found: {path}", path);
        }

        var cert = X509CertificateLoader.LoadPkcs12FromFile(
            path,
            password,
            X509KeyStorageFlags.Exportable | X509KeyStorageFlags.MachineKeySet);

        _logger.LogInformation("Loaded certificate: Subject={Subject}, Thumbprint={Thumbprint}",
            cert.Subject, cert.Thumbprint);

        return cert;
    }

    /// <summary>
    /// Loads an X.509 certificate from raw bytes (e.g., from stdin).
    /// </summary>
    /// <param name="pfxBytes">The PFX certificate bytes.</param>
    /// <param name="password">Password for the certificate.</param>
    /// <returns>The loaded certificate.</returns>
    public X509Certificate2 LoadCertificateFromBytes(byte[] pfxBytes, string? password = null)
    {
        _logger.LogDebug("Loading certificate from byte array ({Length} bytes)", pfxBytes.Length);

        var cert = X509CertificateLoader.LoadPkcs12(
            pfxBytes,
            password,
            X509KeyStorageFlags.Exportable | X509KeyStorageFlags.MachineKeySet);

        _logger.LogInformation("Loaded certificate: Subject={Subject}, Thumbprint={Thumbprint}",
            cert.Subject, cert.Thumbprint);

        return cert;
    }

    /// <summary>
    /// Gets or creates an application certificate for the OPC UA client.
    /// </summary>
    /// <param name="applicationName">The application name.</param>
    /// <param name="applicationUri">The application URI.</param>
    /// <returns>The application certificate.</returns>
    public async Task<X509Certificate2> GetOrCreateApplicationCertificateAsync(
        string applicationName,
        string applicationUri)
    {
        var certificateIdentifier = new CertificateIdentifier
        {
            StoreType = CertificateStoreType.Directory,
            StorePath = OwnCertsPath,
            SubjectName = $"CN={applicationName}, O=OpcUaNodesetExporter, DC={Environment.MachineName}"
        };

        // Try to find existing certificate
        var existingCert = await certificateIdentifier.FindAsync().ConfigureAwait(false);
        if (existingCert != null)
        {
            _logger.LogDebug("Found existing application certificate: {Thumbprint}", existingCert.Thumbprint);
            return existingCert;
        }

        // Create new self-signed certificate
        _logger.LogInformation("Creating new self-signed application certificate for {ApplicationName}", applicationName);

        var certificate = CertificateFactory.CreateCertificate(
            applicationUri,
            applicationName,
            $"CN={applicationName}, O=OpcUaNodesetExporter, DC={Environment.MachineName}",
            null)
            .SetNotBefore(DateTime.UtcNow.AddDays(-1))
            .SetNotAfter(DateTime.UtcNow.AddYears(5))
            .SetRSAKeySize(2048)
            .CreateForRSA();

        // Save to directory store
        await SaveCertificateToStoreAsync(certificate).ConfigureAwait(false);

        _logger.LogInformation("Created application certificate: Subject={Subject}, Thumbprint={Thumbprint}",
            certificate.Subject, certificate.Thumbprint);

        return certificate;
    }

    /// <summary>
    /// Saves a certificate to the own certificates directory store.
    /// </summary>
    /// <param name="certificate">The certificate to save.</param>
    private async Task SaveCertificateToStoreAsync(X509Certificate2 certificate)
    {
        var thumbprint = certificate.Thumbprint;

        // Save public certificate
        var certPath = Path.Combine(OwnCertsPath, $"{thumbprint}.der");
        await File.WriteAllBytesAsync(certPath, certificate.RawData).ConfigureAwait(false);
        _logger.LogDebug("Saved certificate to: {Path}", certPath);

        // Save private key if available
        if (certificate.HasPrivateKey)
        {
            var pfxPath = Path.Combine(OwnPrivatePath, $"{thumbprint}.pfx");
            var pfxBytes = certificate.Export(X509ContentType.Pfx);
            await File.WriteAllBytesAsync(pfxPath, pfxBytes).ConfigureAwait(false);
            _logger.LogDebug("Saved private key to: {Path}", pfxPath);
        }
    }

    /// <summary>
    /// Creates a security configuration for the OPC UA application.
    /// </summary>
    /// <param name="applicationName">The application name.</param>
    /// <returns>The security configuration.</returns>
    public SecurityConfiguration CreateSecurityConfiguration(string applicationName)
    {
        return new SecurityConfiguration
        {
            ApplicationCertificate = new CertificateIdentifier
            {
                StoreType = CertificateStoreType.Directory,
                StorePath = OwnCertsPath,
                SubjectName = $"CN={applicationName}, O=OpcUaNodesetExporter, DC={Environment.MachineName}"
            },
            TrustedIssuerCertificates = new CertificateTrustList
            {
                StoreType = CertificateStoreType.Directory,
                StorePath = IssuerCertsPath
            },
            TrustedPeerCertificates = new CertificateTrustList
            {
                StoreType = CertificateStoreType.Directory,
                StorePath = TrustedCertsPath
            },
            RejectedCertificateStore = new CertificateTrustList
            {
                StoreType = CertificateStoreType.Directory,
                StorePath = RejectedCertsPath
            },
            AutoAcceptUntrustedCertificates = true,
            RejectSHA1SignedCertificates = false,
            MinimumCertificateKeySize = 1024
        };
    }

    /// <summary>
    /// Ensures all PKI directories exist.
    /// </summary>
    private void EnsurePkiDirectoriesExist()
    {
        var directories = new[]
        {
            OwnCertsPath,
            OwnPrivatePath,
            TrustedCertsPath,
            RejectedCertsPath,
            IssuerCertsPath
        };

        foreach (var dir in directories)
        {
            if (!Directory.Exists(dir))
            {
                Directory.CreateDirectory(dir);
                _logger.LogDebug("Created PKI directory: {Path}", dir);
            }
        }
    }
}
