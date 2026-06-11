using System.Text.Json;
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

    [Fact]
    public async Task DefaultExport_VariablesHaveRealValueRankAndMinimumSamplingInterval()
    {
        // Regression test for the bug where every exported variable had
        // ValueRank="-2" and MinimumSamplingInterval="-1" — those are the
        // SDK's in-memory defaults that leak through when only Browse is used.
        // After the HydrateNodeAttributes step, real server values must be
        // emitted (or the attributes must be omitted entirely, taking the
        // NodeSet2 XML defaults of ValueRank=-1 and MinimumSamplingInterval=0).
        Assert.NotNull(_opcUaEndpoint);

        using var loggerFactory = LoggerFactory.Create(builder =>
        {
            builder.AddConsole();
            builder.SetMinimumLevel(LogLevel.Information);
        });

        var tempDir = Path.Combine(Path.GetTempPath(), "opcua-hydrate-test-" + Guid.NewGuid().ToString("N"));
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

            await using var client = await OpcUaClientBuilder
                .Create(loggerFactory)
                .FromOptions(options)
                .TrustAllServerCertificates()
                .ConnectAsync();

            var exporter = new NodeSetExporter(
                loggerFactory.CreateLogger<NodeSetExporter>(),
                loggerFactory,
                client,
                verbose: false);

            var exportedFiles = await exporter.ExportAllNamespacesAsync(tempDir);

            Assert.NotEmpty(exportedFiles);

            // Inspect every NodeSet2 XML file: the placeholder defaults must
            // not be present on any UAVariable element. The SDK only writes
            // attributes that differ from the schema default, so seeing
            // ValueRank="-2" or MinimumSamplingInterval="-1" indicates the bug
            // has regressed (those are SDK in-memory defaults, not legal server
            // values).
            foreach (var xmlPath in exportedFiles.Values)
            {
                var xml = await File.ReadAllTextAsync(xmlPath);
                Assert.DoesNotContain("ValueRank=\"-2\"", xml);
                Assert.DoesNotContain("MinimumSamplingInterval=\"-1\"", xml);
            }
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
    public async Task DefaultExport_PreservesReferences()
    {
        // Regression test: the attribute-hydration pass must not strip the
        // node references collected via Browse. Earlier versions replaced the
        // cached INode with a freshly-read Node that had no references, which
        // caused CoreClientUtils.ExportNodesToNodeSet2 to emit a NodeSet2 XML
        // with no <References> blocks at all.
        Assert.NotNull(_opcUaEndpoint);

        using var loggerFactory = LoggerFactory.Create(builder =>
        {
            builder.AddConsole();
            builder.SetMinimumLevel(LogLevel.Information);
        });

        var tempDir = Path.Combine(Path.GetTempPath(), "opcua-refs-test-" + Guid.NewGuid().ToString("N"));
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

            await using var client = await OpcUaClientBuilder
                .Create(loggerFactory)
                .FromOptions(options)
                .TrustAllServerCertificates()
                .ConnectAsync();

            var exporter = new NodeSetExporter(
                loggerFactory.CreateLogger<NodeSetExporter>(),
                loggerFactory,
                client,
                verbose: false);

            var exportedFiles = await exporter.ExportAllNamespacesAsync(tempDir);

            Assert.NotEmpty(exportedFiles);

            bool anyReferences = false;
            foreach (var xmlPath in exportedFiles.Values)
            {
                var xml = await File.ReadAllTextAsync(xmlPath);
                if (xml.Contains("<References>") || xml.Contains("<Reference "))
                {
                    anyReferences = true;
                    break;
                }
            }

            Assert.True(anyReferences,
                "Expected at least one exported NodeSet2 file to contain <References>/<Reference> blocks.");
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
    public async Task ExportAttributes_ProducesJsonSidecarPerNamespace()
    {
        Assert.NotNull(_opcUaEndpoint);

        using var loggerFactory = LoggerFactory.Create(builder =>
        {
            builder.AddConsole();
            builder.SetMinimumLevel(LogLevel.Information);
        });

        var tempDir = Path.Combine(Path.GetTempPath(), "opcua-attrs-test-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);

        try
        {
            var options = new OpcUaClientOptions
            {
                Endpoint = _opcUaEndpoint,
                OutputDirectory = tempDir,
                RetryCount = 3,
                RetryDelaySeconds = 5,
                ExportAttributes = true
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
                verbose: false,
                exportAttributes: true);

            var exportedFiles = await exporter.ExportAllNamespacesAsync(tempDir);

            Assert.NotEmpty(exportedFiles);

            foreach (var xmlPath in exportedFiles.Values)
            {
                var sidecarPath = Path.ChangeExtension(xmlPath, null) + "_attributes.json";
                Assert.True(File.Exists(sidecarPath),
                    $"Expected JSON sidecar at {sidecarPath}");

                using var stream = File.OpenRead(sidecarPath);
                using var document = await JsonDocument.ParseAsync(stream);
                var root = document.RootElement;

                Assert.True(root.TryGetProperty("namespaceUri", out _));
                Assert.True(root.TryGetProperty("namespaceIndex", out _));
                Assert.True(root.TryGetProperty("exportedAt", out _));
                Assert.True(root.TryGetProperty("nodes", out var nodes));
                Assert.True(nodes.GetArrayLength() > 0);

                // At least one Variable node should have a "Value" attribute key.
                bool sawValueAttribute = false;
                foreach (var node in nodes.EnumerateArray())
                {
                    if (node.GetProperty("nodeClass").GetString() == "Variable" &&
                        node.GetProperty("attributes").TryGetProperty("Value", out var valueAttr) &&
                        valueAttr.TryGetProperty("status", out _))
                    {
                        sawValueAttribute = true;
                        break;
                    }
                }
                Assert.True(sawValueAttribute,
                    "Expected at least one Variable node with a 'Value' attribute in the sidecar.");
            }

            // Regression check: when --export-attributes is set, the NodeSet2
            // XML itself must also contain <Value> elements (NodeSetExportOptions.ExportValues=true).
            // Earlier versions wrote them only to the JSON sidecar.
            bool sawValueElementInXml = false;
            foreach (var xmlPath in exportedFiles.Values)
            {
                var xml = await File.ReadAllTextAsync(xmlPath);
                if (xml.Contains("<Value>") || xml.Contains("<Value "))
                {
                    sawValueElementInXml = true;
                    break;
                }
            }
            Assert.True(sawValueElementInXml,
                "Expected at least one exported NodeSet2 XML to contain a <Value> element when --export-attributes is set.");
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
    public async Task SubtreeExport_WithExportAttributes_ProducesJsonSidecar()
    {
        Assert.NotNull(_opcUaEndpoint);

        using var loggerFactory = LoggerFactory.Create(builder =>
        {
            builder.AddConsole();
            builder.SetMinimumLevel(LogLevel.Information);
        });

        var tempDir = Path.Combine(Path.GetTempPath(), "opcua-attrs-subtree-test-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);

        try
        {
            var options = new OpcUaClientOptions
            {
                Endpoint = _opcUaEndpoint,
                RetryCount = 3,
                RetryDelaySeconds = 5,
                ExportAttributes = true
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
                verbose: false,
                exportAttributes: true);

            var startNodeId = Opc.Ua.ExpandedNodeId.Parse(
                "ns=4;i=5", client.Session.NamespaceUris);

            var exportedFile = await exporter.ExportSubtreeAsync(startNodeId, tempDir);

            Assert.True(File.Exists(exportedFile));
            var sidecarPath = Path.ChangeExtension(exportedFile, null) + "_attributes.json";
            Assert.True(File.Exists(sidecarPath),
                $"Expected sidecar JSON at {sidecarPath}");

            using var stream = File.OpenRead(sidecarPath);
            using var document = await JsonDocument.ParseAsync(stream);
            var root = document.RootElement;

            Assert.Equal(4, root.GetProperty("namespaceIndex").GetInt32());
            Assert.True(root.GetProperty("nodes").GetArrayLength() > 0);

            // Regression check: <Value> must also appear in the NodeSet2 XML
            // itself when --export-attributes is set, not only in the JSON sidecar.
            var xml = await File.ReadAllTextAsync(exportedFile);
            Assert.True(xml.Contains("<Value>") || xml.Contains("<Value "),
                "Expected <Value> element in NodeSet2 XML subtree export with --export-attributes.");
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
