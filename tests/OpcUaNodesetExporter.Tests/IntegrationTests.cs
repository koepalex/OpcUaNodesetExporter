using Aspire.Hosting;
using Aspire.Hosting.ApplicationModel;
using Aspire.Hosting.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using OpcUaNodesetExporter.OpcUa;

namespace OpcUaNodesetExporter.Tests;

/// <summary>
/// Integration tests that use .NET Aspire to spin up the OPC UA server container.
/// </summary>
[Trait("Category", "Integration")]
public class IntegrationTests : IAsyncLifetime
{
    private DistributedApplication? _app;
    private string? _opcUaEndpoint;

    public async Task InitializeAsync()
    {
        // Allow unsecured transport for testing
        Environment.SetEnvironmentVariable("ASPIRE_ALLOW_UNSECURED_TRANSPORT", "true");

        var appHost = await DistributedApplicationTestingBuilder
            .CreateAsync<Projects.OpcUaNodesetExporter_AppHost>();

        // Don't start the exporter project - we just want the OPC UA server container
        appHost.Services.ConfigureHttpClientDefaults(clientBuilder =>
        {
            clientBuilder.AddStandardResilienceHandler();
        });

        _app = await appHost.BuildAsync();
        await _app.StartAsync();

        // Wait for the OPC UA server container to be running
        await _app.ResourceNotifications.WaitForResourceAsync(
            "opcplc",
            KnownResourceStates.Running);

        // Get the OPC UA endpoint URL
        var endpoint = _app.GetEndpoint("opcplc", "opcua");
        _opcUaEndpoint = endpoint.ToString();
    }

    public async Task DisposeAsync()
    {
        if (_app is not null)
        {
            await _app.DisposeAsync();
        }
    }

    [Fact]
    public async Task CanConnectToOpcUaServer()
    {
        Assert.NotNull(_opcUaEndpoint);

        // Arrange
        using var loggerFactory = LoggerFactory.Create(builder =>
        {
            builder.AddConsole();
            builder.SetMinimumLevel(LogLevel.Debug);
        });

        var options = new OpcUaClientOptions
        {
            Endpoint = _opcUaEndpoint,
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

    [Fact]
    public async Task CanExportNamespaces()
    {
        Assert.NotNull(_opcUaEndpoint);

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
                Endpoint = _opcUaEndpoint,
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
                loggerFactory,
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

    [Fact]
    public async Task CanExportSubtree()
    {
        Assert.NotNull(_opcUaEndpoint);

        // Arrange
        using var loggerFactory = LoggerFactory.Create(builder =>
        {
            builder.AddConsole();
            builder.SetMinimumLevel(LogLevel.Information);
        });

        var tempDir = Path.Combine(Path.GetTempPath(), "opcua-subtree-test-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);

        try
        {
            var options = new OpcUaClientOptions
            {
                Endpoint = _opcUaEndpoint,
                RetryCount = 3,
                RetryDelaySeconds = 5
            };

            await using var client = await OpcUaClientBuilder
                .Create(loggerFactory)
                .FromOptions(options)
                .TrustAllServerCertificates()
                .ConnectAsync();

            var exporter = new NodeSetExporter(
                loggerFactory.CreateLogger<NodeSetExporter>(),
                loggerFactory,
                client,
                verbose: true);

            // Use the Boiler namespace's "Boilers" folder node (ns=4;i=5) as start node
            // This is a known node in the OPC PLC simulator
            var startNodeId = Opc.Ua.ExpandedNodeId.Parse("ns=4;i=5", client.Session.NamespaceUris);

            // Act
            var exportedFile = await exporter.ExportSubtreeAsync(startNodeId, tempDir);

            // Assert
            Assert.NotNull(exportedFile);
            Assert.True(File.Exists(exportedFile));

            // Verify the output is valid XML with UANodeSet root element
            var xmlContent = await File.ReadAllTextAsync(exportedFile);
            Assert.Contains("<UANodeSet", xmlContent);
            Assert.Contains("</UANodeSet>", xmlContent);

            // Verify it contains at least one node from the subtree
            Assert.Contains("Boiler", xmlContent);
        }
        finally
        {
            if (Directory.Exists(tempDir))
            {
                Directory.Delete(tempDir, true);
            }
        }
    }

    [Fact]
    public async Task SubtreeExportExcludesTypesFromOtherNamespaces()
    {
        Assert.NotNull(_opcUaEndpoint);

        // Arrange
        using var loggerFactory = LoggerFactory.Create(builder =>
        {
            builder.AddConsole();
            builder.SetMinimumLevel(LogLevel.Information);
        });

        var tempDir = Path.Combine(Path.GetTempPath(), "opcua-subtree-filter-test-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);

        try
        {
            var options = new OpcUaClientOptions
            {
                Endpoint = _opcUaEndpoint,
                RetryCount = 3,
                RetryDelaySeconds = 5
            };

            await using var client = await OpcUaClientBuilder
                .Create(loggerFactory)
                .FromOptions(options)
                .TrustAllServerCertificates()
                .ConnectAsync();

            var exporter = new NodeSetExporter(
                loggerFactory.CreateLogger<NodeSetExporter>(),
                loggerFactory,
                client,
                verbose: true);

            // Use the Boiler namespace's "Boilers" folder node (ns=4;i=5)
            var startNodeId = Opc.Ua.ExpandedNodeId.Parse("ns=4;i=5", client.Session.NamespaceUris);

            // Act
            var exportedFile = await exporter.ExportSubtreeAsync(startNodeId, tempDir);

            // Assert
            Assert.True(File.Exists(exportedFile));
            var xmlContent = await File.ReadAllTextAsync(exportedFile);

            // The export should reference other namespaces in the NamespaceUris section
            // but should NOT include UAObjectType/UAVariableType nodes from namespace 0
            // (OPC UA base types like BaseObjectType are ns=0 and should not be exported as nodes)
            Assert.DoesNotContain("NodeId=\"i=", xmlContent); // No ns=0 node definitions
        }
        finally
        {
            if (Directory.Exists(tempDir))
            {
                Directory.Delete(tempDir, true);
            }
        }
    }
}
