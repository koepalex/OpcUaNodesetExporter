using Aspire.Hosting;
using Projects;

var builder = DistributedApplication.CreateBuilder(args);

// Define and clear the export folder on startup
var exportFolder = Path.Combine(builder.AppHostDirectory, "export");
if (Directory.Exists(exportFolder))
{
    Directory.Delete(exportFolder, recursive: true);
}
Directory.CreateDirectory(exportFolder);

// Add umati OPC UA sample server container
var umatiServer = builder
    .AddContainer("opcplc", "ghcr.io/umati/sample-server", "develop")
    .WithEndpoint(port: 50000, targetPort: 4840, scheme: "opc.tcp", name: "opcua");

// Get the OPC UA endpoint for reference
var umatiServerEndpoint = umatiServer.GetEndpoint("opcua");

// Add the OpcUaNodesetExporter project with the endpoint and output folder injected
builder.AddProject<OpcUaNodesetExporter>("opcua-nodeset-exporter")
    .WithEnvironment("OPCUA_ENDPOINT", umatiServerEndpoint)
    .WithArgs("--output", exportFolder);

builder.Build().Run();
