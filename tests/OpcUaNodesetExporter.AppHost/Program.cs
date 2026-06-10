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
    .AddContainer("umati", "ghcr.io/umati/sample-server", "develop")
    .WithEndpoint(port: 50002, targetPort: 4840, scheme: "opc.tcp", name: "opcua");

// Get the OPC UA endpoint for reference
var umatiServerEndpoint = umatiServer.GetEndpoint("opcua");

// Add OPC PLC server container
var opcplc = builder
    .AddContainer("opcplc", "mcr.microsoft.com/iotedge/opc-plc", "latest")
    .WithEndpoint(port: 50000, targetPort: 50000, scheme: "opc.tcp", name: "opcua")
    .WithArgs("--ph=localhost")
    .WithArgs("--cdn=localhost,opcplc") 
    .WithArgs("--autoaccept") 
    .WithArgs("--sn=25") 
    .WithArgs("--sr=10") 
    .WithArgs("--fn=2000") 
    .WithArgs("--veryfastrate=1000") 
    .WithArgs("--gn=5") 
    .WithArgs("--pn=50000")
    .WithArgs("--maxsessioncount=100") 
    .WithArgs("--maxsubscriptioncount=100") 
    .WithArgs("--maxqueuedrequestcount=2000") 
    .WithArgs("--ses") 
    .WithArgs("--alm") 
    .WithArgs("--at=FlatDirectory") 
    .WithArgs("--drurs");

// Get the OPC UA endpoint for reference
var opcPlcEndpoint = opcplc.GetEndpoint("opcua");

// Add the OpcUaNodesetExporter project with the endpoint and output folder injected
builder.AddProject<OpcUaNodesetExporter>("umati-opcua-nodeset-exporter")
    .WithEnvironment("OPCUA_ENDPOINT", umatiServerEndpoint)
    .WithArgs("--output", exportFolder);

builder.AddProject<OpcUaNodesetExporter>("opcplc-opcua-nodeset-exporter")
    .WithEnvironment("OPCUA_ENDPOINT", opcPlcEndpoint)
    .WithEnvironment("OPCUA_START_NODE", "nsu=http://microsoft.com/Opc/OpcPlc/Boiler;i=5017")
    .WithArgs("--output", exportFolder);

// Additional exporter instances that exercise --export-attributes (full + subtree mode).
// They write into dedicated subfolders so the JSON sidecars don't collide with the
// "plain" exports above.
var umatiAttrsFolder = Path.Combine(exportFolder, "umati-attrs");
Directory.CreateDirectory(umatiAttrsFolder);

var opcPlcAttrsFolder = Path.Combine(exportFolder, "opcplc-attrs");
Directory.CreateDirectory(opcPlcAttrsFolder);

builder.AddProject<OpcUaNodesetExporter>("umati-opcua-nodeset-exporter-with-attributes")
    .WithEnvironment("OPCUA_ENDPOINT", umatiServerEndpoint)
    .WithArgs("--output", umatiAttrsFolder)
    .WithArgs("--export-attributes");

builder.AddProject<OpcUaNodesetExporter>("opcplc-opcua-nodeset-exporter-with-attributes")
    .WithEnvironment("OPCUA_ENDPOINT", opcPlcEndpoint)
    .WithEnvironment("OPCUA_START_NODE", "nsu=http://microsoft.com/Opc/OpcPlc/Boiler;i=5017")
    .WithArgs("--output", opcPlcAttrsFolder)
    .WithArgs("--export-attributes");

builder.Build().Run();
