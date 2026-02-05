using System.CommandLine;
using OpcUaNodesetExporter.Commands;

// Create and invoke the export command
var command = new ExportCommand();
return await command.InvokeAsync(args);
