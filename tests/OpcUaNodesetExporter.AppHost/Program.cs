using Aspire.Hosting;

var builder = DistributedApplication.CreateBuilder(args);

// Add umati OPC UA sample server container
var umatiServer = builder
    .AddContainer("opcplc", "ghcr.io/umati/sample-server", "develop")
    .WithEndpoint(port: 50000, targetPort: 4840, scheme: "opc.tcp", name: "opcua")
    .WithOtlpExporter();

// Get the OPC UA endpoint for reference
var umatiServerEndpoint = umatiServer.GetEndpoint("opcua");

builder.Build().Run();
