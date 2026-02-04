using Microsoft.Extensions.Logging;
using OpcUaNodesetExporter.OpcUa;
using OpcUaNodesetExporter.Configuration;

namespace OpcUaNodesetExporter.Tests;

/// <summary>
/// Integration tests that require an OPC UA server.
/// Set OPCUA_TEST_ENDPOINT environment variable to enable these tests.
/// </summary>
[Trait("Category", "Integration")]
public class IntegrationTests
{
    private readonly string? _opcUaEndpoint;

    public IntegrationTests()
    {
        _opcUaEndpoint = Environment.GetEnvironmentVariable("OPCUA_TEST_ENDPOINT");
    }

    [SkippableFact]
    public async Task CanConnectToOpcUaServer()
    {
        Skip.If(string.IsNullOrEmpty(_opcUaEndpoint), "OPCUA_TEST_ENDPOINT not set");

        // Arrange
        using var loggerFactory = LoggerFactory.Create(builder =>
        {
            builder.AddConsole();
            builder.SetMinimumLevel(LogLevel.Debug);
        });

        var options = new OpcUaClientOptions
        {
            Endpoint = _opcUaEndpoint!,
            RetryCount = 3,
            RetryDelaySeconds = 5
        };

        // Act
        await using var client = await OpcUaClientBuilder
            .Create(loggerFactory)
            .FromOptions(options)
            .TrustAllServerCertificates()
            .ConnectAsync();

        // Assert
        Assert.True(client.IsConnected);
    }

    [SkippableFact]
    public async Task CanExportNamespaces()
    {
        Skip.If(string.IsNullOrEmpty(_opcUaEndpoint), "OPCUA_TEST_ENDPOINT not set");

        // Arrange
        using var loggerFactory = LoggerFactory.Create(builder =>
        {
            builder.AddConsole();
            builder.SetMinimumLevel(LogLevel.Information);
        });

        var tempDir = Path.Combine(Path.GetTempPath(), "opcua-test-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);

        try
        {
            var options = new OpcUaClientOptions
            {
                Endpoint = _opcUaEndpoint!,
                OutputDirectory = tempDir,
                RetryCount = 3,
                RetryDelaySeconds = 5
            };

            // Act
            await using var client = await OpcUaClientBuilder
                .Create(loggerFactory)
                .FromOptions(options)
                .TrustAllServerCertificates()
                .ConnectAsync();

            var exporter = new NodeSetExporter(
                loggerFactory.CreateLogger<NodeSetExporter>(),
                client,
                verbose: true);

            var exportedFiles = await exporter.ExportAllNamespacesAsync(tempDir);

            // Assert
            Assert.NotNull(exportedFiles);
            Assert.True(Directory.Exists(tempDir));
        }
        finally
        {
            // Cleanup
            if (Directory.Exists(tempDir))
            {
                Directory.Delete(tempDir, true);
            }
        }
    }
}
