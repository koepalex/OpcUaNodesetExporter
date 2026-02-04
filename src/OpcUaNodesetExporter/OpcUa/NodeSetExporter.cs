using System.Diagnostics;
using Microsoft.Extensions.Logging;
using Opc.Ua;
using Opc.Ua.Client;
using Opc.Ua.Client.ComplexTypes;
using Opc.Ua.Export;
using ExportLocalizedText = Opc.Ua.Export.LocalizedText;

namespace OpcUaNodesetExporter.OpcUa;

/// <summary>
/// Exports OPC UA nodes to NodeSet2 XML files, grouped by namespace.
/// Based on the OPC Foundation reference implementation (ClientSamples.ExportNodesToNodeSet2PerNamespaceAsync).
/// </summary>
public class NodeSetExporter
{
    private const int MaxSearchDepth = 128;

    private readonly ILogger<NodeSetExporter> _logger;
    private readonly OpcUaClient _client;
    private readonly bool _verbose;

    /// <summary>
    /// Creates a new NodeSetExporter instance.
    /// </summary>
    /// <param name="logger">Logger instance.</param>
    /// <param name="client">Connected OPC UA client.</param>
    /// <param name="verbose">Enable verbose output.</param>
    public NodeSetExporter(ILogger<NodeSetExporter> logger, OpcUaClient client, bool verbose = false)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _client = client ?? throw new ArgumentNullException(nameof(client));
        _verbose = verbose;
    }

    /// <summary>
    /// Exports all custom namespaces to separate NodeSet2 XML files.
    /// </summary>
    /// <param name="outputDirectory">Directory to save the NodeSet2 files.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Dictionary mapping namespace URI to exported file path.</returns>
    public async Task<IReadOnlyDictionary<string, string>> ExportAllNamespacesAsync(
        string outputDirectory,
        CancellationToken cancellationToken = default)
    {
        _logger.LogInformation("Starting namespace export to {OutputDirectory}", outputDirectory);
        var stopwatch = Stopwatch.StartNew();

        // Ensure output directory exists
        Directory.CreateDirectory(outputDirectory);

        // Load type system first
        _logger.LogInformation("Loading type system...");
        await LoadTypeSystemAsync(cancellationToken).ConfigureAwait(false);

        // Fetch all nodes from the server
        _logger.LogInformation("Fetching all nodes from server...");
        var nodes = await FetchAllNodesAsync(cancellationToken).ConfigureAwait(false);

        _logger.LogInformation("Fetched {Count} nodes from server.", nodes.Count);

        // Export nodes per namespace
        var exportedFiles = await ExportNodesToNodeSet2PerNamespaceAsync(
            nodes,
            outputDirectory,
            cancellationToken).ConfigureAwait(false);

        stopwatch.Stop();
        _logger.LogInformation("Export completed in {Duration}ms. Exported {Count} namespaces.",
            stopwatch.ElapsedMilliseconds, exportedFiles.Count);

        return exportedFiles;
    }

    /// <summary>
    /// Loads the complex type system from the server.
    /// </summary>
    private async Task LoadTypeSystemAsync(CancellationToken cancellationToken)
    {
        await _client.ExecuteWithRetryAsync(async (session, ct) =>
        {
            var complexTypeSystem = new ComplexTypeSystem(session);
            await complexTypeSystem.LoadAsync(ct: ct).ConfigureAwait(false);

            _logger.LogInformation("Loaded {Count} custom types from server.",
                complexTypeSystem.GetDefinedTypes().Length);

            if (_verbose)
            {
                foreach (var type in complexTypeSystem.GetDefinedTypes())
                {
                    _logger.LogDebug("  Type: {Namespace}.{Name}", type.Namespace, type.Name);
                }
            }
        }, "LoadTypeSystem", cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Fetches all nodes from the server using the NodeCache.
    /// </summary>
    private async Task<IList<INode>> FetchAllNodesAsync(CancellationToken cancellationToken)
    {
        return await _client.ExecuteWithRetryAsync(async (session, ct) =>
        {
            var stopwatch = Stopwatch.StartNew();
            var nodeDictionary = new Dictionary<ExpandedNodeId, INode>();
            var references = new NodeIdCollection { ReferenceTypeIds.HierarchicalReferences };
            var nodesToBrowse = new ExpandedNodeIdCollection { ObjectIds.RootFolder };

            // Clear NodeCache to fetch fresh data
            session.NodeCache.Clear();
            await FetchReferenceIdTypesAsync(session, ct).ConfigureAwait(false);

            int searchDepth = 0;
            while (nodesToBrowse.Count > 0 && searchDepth < MaxSearchDepth)
            {
                ct.ThrowIfCancellationRequested();

                searchDepth++;
                _logger.LogInformation("Depth {Depth}: Browsing {Count} nodes ({Elapsed}ms)...",
                    searchDepth, nodesToBrowse.Count, stopwatch.ElapsedMilliseconds);

                var response = await session.NodeCache.FindReferencesAsync(
                    nodesToBrowse, references, false, true, ct).ConfigureAwait(false);

                var nextNodesToBrowse = new ExpandedNodeIdCollection();
                int duplicates = 0;
                int leafNodes = 0;

                foreach (var node in response)
                {
                    if (!nodeDictionary.ContainsKey(node.NodeId))
                    {
                        bool isLeafNode = false;

                        // Properties are leaf nodes
                        if (node is VariableNode variableNode)
                        {
                            var hasTypeDefinition = variableNode.ReferenceTable
                                .FirstOrDefault(r => r.ReferenceTypeId.Equals(ReferenceTypeIds.HasTypeDefinition));
                            if (hasTypeDefinition != null)
                            {
                                isLeafNode = hasTypeDefinition.TargetId == VariableTypeIds.PropertyType;
                            }
                        }

                        if (!isLeafNode)
                        {
                            nextNodesToBrowse.Add(node.NodeId);
                        }
                        else
                        {
                            leafNodes++;
                        }

                        // Only add nodes from custom namespaces (ns > 0)
                        if (node.NodeId.NamespaceIndex != 0)
                        {
                            nodeDictionary[node.NodeId] = node;
                        }
                    }
                    else
                    {
                        duplicates++;
                    }
                }

                if (duplicates > 0)
                {
                    _logger.LogDebug("Skipped {Count} duplicate nodes.", duplicates);
                }
                if (leafNodes > 0)
                {
                    _logger.LogDebug("Identified {Count} leaf nodes.", leafNodes);
                }

                nodesToBrowse = nextNodesToBrowse;
            }

            stopwatch.Stop();

            var result = nodeDictionary.Values.ToList();
            result.Sort((x, y) => x.NodeId.CompareTo(y.NodeId));

            _logger.LogInformation("FetchAllNodes found {Count} custom nodes in {Duration}ms.",
                result.Count, stopwatch.ElapsedMilliseconds);

            if (_verbose)
            {
                foreach (var node in result.Take(100))
                {
                    _logger.LogDebug("Node: {NodeId} ({NodeClass}) - {BrowseName}",
                        node.NodeId, node.NodeClass, node.BrowseName);
                }
                if (result.Count > 100)
                {
                    _logger.LogDebug("... and {Count} more nodes.", result.Count - 100);
                }
            }

            return (IList<INode>)result;
        }, "FetchAllNodes", cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Fetches all reference type IDs from the server.
    /// </summary>
    private static async Task FetchReferenceIdTypesAsync(ISession session, CancellationToken ct)
    {
        var bindingFlags = System.Reflection.BindingFlags.Instance |
                          System.Reflection.BindingFlags.Static |
                          System.Reflection.BindingFlags.Public;

        var namespaceUris = session.NamespaceUris;
        var referenceTypes = typeof(ReferenceTypeIds)
            .GetFields(bindingFlags)
            .Select(field => NodeId.ToExpandedNodeId((NodeId)field.GetValue(null)!, namespaceUris));

        await session.FetchTypeTreeAsync(referenceTypes.ToArray(), ct).ConfigureAwait(false);
    }

    /// <summary>
    /// Exports nodes to separate NodeSet2 XML files, one per namespace.
    /// Excludes OPC Foundation companion specifications.
    /// </summary>
    private async Task<IReadOnlyDictionary<string, string>> ExportNodesToNodeSet2PerNamespaceAsync(
        IList<INode> nodes,
        string outputDirectory,
        CancellationToken cancellationToken)
    {
        var session = _client.Session;

        _logger.LogInformation("Exporting {Count} nodes to separate NodeSet2 files per namespace...",
            nodes.Count);

        var stopwatch = Stopwatch.StartNew();

        // Group nodes by namespace, excluding OPC Foundation companion specs
        var nodesByNamespace = nodes
            .Where(node => node.NodeId.NamespaceIndex > 0) // Skip namespace 0 (OPC UA base)
            .GroupBy(node => node.NodeId.NamespaceIndex)
            .Where(group =>
            {
                string namespaceUri = session.NamespaceUris.GetString(group.Key);
                // Exclude OPC Foundation companion specifications
                return !string.IsNullOrEmpty(namespaceUri) &&
                    !namespaceUri.StartsWith("http://opcfoundation.org/UA/", StringComparison.OrdinalIgnoreCase);
            })
            .ToDictionary(
                group => group.Key,
                group => group.ToList());

        var exportedFiles = new Dictionary<string, string>();

        _logger.LogInformation("Found {Count} custom namespaces to export.", nodesByNamespace.Count);

        // Export each namespace to its own file
        foreach (var kvp in nodesByNamespace)
        {
            cancellationToken.ThrowIfCancellationRequested();

            string namespaceUri = session.NamespaceUris.GetString(kvp.Key);
            string fileName = CreateSafeFileName(namespaceUri, kvp.Key);
            string filePath = Path.Combine(outputDirectory, fileName);

            _logger.LogInformation("Exporting namespace {Index} ({Uri}): {Count} nodes -> {File}",
                kvp.Key, namespaceUri, kvp.Value.Count, fileName);

            await Task.Run(() =>
            {
                ExportNodesToNodeSet2File(session, kvp.Value, filePath);
            }, cancellationToken).ConfigureAwait(false);

            exportedFiles[namespaceUri] = filePath;
        }

        stopwatch.Stop();

        _logger.LogInformation("Exported {NamespaceCount} namespaces ({NodeCount} total nodes) in {Duration}ms.",
            exportedFiles.Count, nodes.Count, stopwatch.ElapsedMilliseconds);

        return exportedFiles;
    }

    /// <summary>
    /// Exports nodes to a single NodeSet2 XML file.
    /// </summary>
    private void ExportNodesToNodeSet2File(ISession session, IList<INode> nodes, string filePath)
    {
        using var outputStream = new FileStream(filePath, FileMode.Create, FileAccess.Write, FileShare.None);

        var nodeSet = new UANodeSet();

        // Set up namespace table
        nodeSet.NamespaceUris = session.NamespaceUris.ToArray()
            .Skip(1) // Skip the OPC UA namespace (index 0)
            .ToArray();

        // Set up server URIs
        nodeSet.ServerUris = session.ServerUris.ToArray();

        // Convert nodes to UANode objects
        var uaNodes = new List<UANode>();
        foreach (var node in nodes)
        {
            var uaNode = ConvertToUANode(session, node);
            if (uaNode != null)
            {
                uaNodes.Add(uaNode);
            }
        }

        nodeSet.Items = uaNodes.ToArray();
        nodeSet.LastModified = DateTime.UtcNow;
        nodeSet.LastModifiedSpecified = true;

        // Serialize to XML
        var serializer = new System.Xml.Serialization.XmlSerializer(typeof(UANodeSet));
        serializer.Serialize(outputStream, nodeSet);

        _logger.LogDebug("Exported {Count} nodes to {FilePath}", uaNodes.Count, filePath);
    }

    /// <summary>
    /// Converts an INode to a UANode for export.
    /// </summary>
    private static UANode? ConvertToUANode(ISession session, INode node)
    {
        UANode? uaNode = node.NodeClass switch
        {
            NodeClass.Object => ConvertObjectNode(session, (ObjectNode)node),
            NodeClass.Variable => ConvertVariableNode(session, (VariableNode)node),
            NodeClass.Method => ConvertMethodNode(session, (MethodNode)node),
            NodeClass.ObjectType => ConvertObjectTypeNode(session, (ObjectTypeNode)node),
            NodeClass.VariableType => ConvertVariableTypeNode(session, (VariableTypeNode)node),
            NodeClass.ReferenceType => ConvertReferenceTypeNode(session, (ReferenceTypeNode)node),
            NodeClass.DataType => ConvertDataTypeNode(session, (DataTypeNode)node),
            NodeClass.View => ConvertViewNode(session, (ViewNode)node),
            _ => null
        };

        return uaNode;
    }

    private static UAObject ConvertObjectNode(ISession session, ObjectNode node)
    {
        return new UAObject
        {
            NodeId = GetNodeIdString(session, node.NodeId),
            BrowseName = GetQualifiedNameString(session, node.BrowseName),
            DisplayName = new[] { new ExportLocalizedText { Value = node.DisplayName?.Text } },
            Description = node.Description != null ? new[] { new ExportLocalizedText { Value = node.Description.Text } } : null,
            EventNotifier = node.EventNotifier,
            References = GetReferences(session, node),
            ParentNodeId = GetNodeIdString(session, FindParentNodeId(node))
        };
    }

    private static UAVariable ConvertVariableNode(ISession session, VariableNode node)
    {
        return new UAVariable
        {
            NodeId = GetNodeIdString(session, node.NodeId),
            BrowseName = GetQualifiedNameString(session, node.BrowseName),
            DisplayName = new[] { new ExportLocalizedText { Value = node.DisplayName?.Text } },
            Description = node.Description != null ? new[] { new ExportLocalizedText { Value = node.Description.Text } } : null,
            DataType = GetNodeIdString(session, node.DataType),
            ValueRank = node.ValueRank,
            ArrayDimensions = node.ArrayDimensions != null ? string.Join(",", node.ArrayDimensions) : null,
            AccessLevel = node.AccessLevel,
            UserAccessLevel = node.UserAccessLevel,
            MinimumSamplingInterval = node.MinimumSamplingInterval,
            Historizing = node.Historizing,
            References = GetReferences(session, node),
            ParentNodeId = GetNodeIdString(session, FindParentNodeId(node))
        };
    }

    private static UAMethod ConvertMethodNode(ISession session, MethodNode node)
    {
        return new UAMethod
        {
            NodeId = GetNodeIdString(session, node.NodeId),
            BrowseName = GetQualifiedNameString(session, node.BrowseName),
            DisplayName = new[] { new ExportLocalizedText { Value = node.DisplayName?.Text } },
            Description = node.Description != null ? new[] { new ExportLocalizedText { Value = node.Description.Text } } : null,
            Executable = node.Executable,
            UserExecutable = node.UserExecutable,
            References = GetReferences(session, node),
            ParentNodeId = GetNodeIdString(session, FindParentNodeId(node))
        };
    }

    private static UAObjectType ConvertObjectTypeNode(ISession session, ObjectTypeNode node)
    {
        return new UAObjectType
        {
            NodeId = GetNodeIdString(session, node.NodeId),
            BrowseName = GetQualifiedNameString(session, node.BrowseName),
            DisplayName = new[] { new ExportLocalizedText { Value = node.DisplayName?.Text } },
            Description = node.Description != null ? new[] { new ExportLocalizedText { Value = node.Description.Text } } : null,
            IsAbstract = node.IsAbstract,
            References = GetReferences(session, node)
        };
    }

    private static UAVariableType ConvertVariableTypeNode(ISession session, VariableTypeNode node)
    {
        return new UAVariableType
        {
            NodeId = GetNodeIdString(session, node.NodeId),
            BrowseName = GetQualifiedNameString(session, node.BrowseName),
            DisplayName = new[] { new ExportLocalizedText { Value = node.DisplayName?.Text } },
            Description = node.Description != null ? new[] { new ExportLocalizedText { Value = node.Description.Text } } : null,
            IsAbstract = node.IsAbstract,
            DataType = GetNodeIdString(session, node.DataType),
            ValueRank = node.ValueRank,
            ArrayDimensions = node.ArrayDimensions != null ? string.Join(",", node.ArrayDimensions) : null,
            References = GetReferences(session, node)
        };
    }

    private static UAReferenceType ConvertReferenceTypeNode(ISession session, ReferenceTypeNode node)
    {
        return new UAReferenceType
        {
            NodeId = GetNodeIdString(session, node.NodeId),
            BrowseName = GetQualifiedNameString(session, node.BrowseName),
            DisplayName = new[] { new ExportLocalizedText { Value = node.DisplayName?.Text } },
            Description = node.Description != null ? new[] { new ExportLocalizedText { Value = node.Description.Text } } : null,
            IsAbstract = node.IsAbstract,
            Symmetric = node.Symmetric,
            InverseName = node.InverseName != null ? new[] { new ExportLocalizedText { Value = node.InverseName.Text } } : null,
            References = GetReferences(session, node)
        };
    }

    private static UADataType ConvertDataTypeNode(ISession session, DataTypeNode node)
    {
        return new UADataType
        {
            NodeId = GetNodeIdString(session, node.NodeId),
            BrowseName = GetQualifiedNameString(session, node.BrowseName),
            DisplayName = new[] { new ExportLocalizedText { Value = node.DisplayName?.Text } },
            Description = node.Description != null ? new[] { new ExportLocalizedText { Value = node.Description.Text } } : null,
            IsAbstract = node.IsAbstract,
            References = GetReferences(session, node)
        };
    }

    private static UAView ConvertViewNode(ISession session, ViewNode node)
    {
        return new UAView
        {
            NodeId = GetNodeIdString(session, node.NodeId),
            BrowseName = GetQualifiedNameString(session, node.BrowseName),
            DisplayName = new[] { new ExportLocalizedText { Value = node.DisplayName?.Text } },
            Description = node.Description != null ? new[] { new ExportLocalizedText { Value = node.Description.Text } } : null,
            ContainsNoLoops = node.ContainsNoLoops,
            EventNotifier = node.EventNotifier,
            References = GetReferences(session, node)
        };
    }

    private static string GetNodeIdString(ISession session, NodeId? nodeId)
    {
        if (nodeId == null || nodeId.IsNullNodeId)
            return string.Empty;

        return nodeId.ToString();
    }

    private static string GetNodeIdString(ISession session, ExpandedNodeId? nodeId)
    {
        if (nodeId == null || nodeId.IsNull)
            return string.Empty;

        var localNodeId = ExpandedNodeId.ToNodeId(nodeId, session.NamespaceUris);
        return localNodeId?.ToString() ?? nodeId.ToString();
    }

    private static string GetQualifiedNameString(ISession session, QualifiedName? qualifiedName)
    {
        if (qualifiedName == null || QualifiedName.IsNull(qualifiedName))
            return string.Empty;

        return qualifiedName.ToString();
    }

    private static Reference[]? GetReferences(ISession session, Node node)
    {
        if (node.ReferenceTable == null || node.ReferenceTable.Count == 0)
            return null;

        var references = new List<Reference>();
        foreach (var reference in node.ReferenceTable)
        {
            references.Add(new Reference
            {
                ReferenceType = GetNodeIdString(session, reference.ReferenceTypeId),
                IsForward = !reference.IsInverse,
                Value = GetNodeIdString(session, reference.TargetId)
            });
        }

        return references.Count > 0 ? references.ToArray() : null;
    }

    private static NodeId? FindParentNodeId(Node node)
    {
        if (node.ReferenceTable == null)
            return null;

        // Find inverse hierarchical reference (parent)
        var parentRef = node.ReferenceTable
            .FirstOrDefault(r => r.IsInverse &&
                (r.ReferenceTypeId == ReferenceTypeIds.HasComponent ||
                 r.ReferenceTypeId == ReferenceTypeIds.HasProperty ||
                 r.ReferenceTypeId == ReferenceTypeIds.Organizes ||
                 r.ReferenceTypeId == ReferenceTypeIds.HasSubtype));

        if (parentRef != null)
        {
            return ExpandedNodeId.ToNodeId(parentRef.TargetId, null);
        }

        return null;
    }

    /// <summary>
    /// Creates a safe filename from a namespace URI.
    /// </summary>
    private static string CreateSafeFileName(string namespaceUri, ushort namespaceIndex)
    {
        // Extract meaningful part from URI
        string fileName = namespaceUri
            .Replace("http://", string.Empty, StringComparison.OrdinalIgnoreCase)
            .Replace("https://", string.Empty, StringComparison.OrdinalIgnoreCase)
            .Replace("urn:", string.Empty, StringComparison.OrdinalIgnoreCase);

        // Replace invalid filename characters
        foreach (char c in Path.GetInvalidFileNameChars())
        {
            fileName = fileName.Replace(c, '_');
        }

        // Additional cleanup for common URI characters
        fileName = fileName
            .Replace('/', '_')
            .Replace('\\', '_')
            .Replace(':', '_')
            .TrimEnd('_');

        // Limit length and ensure uniqueness with namespace index
        if (fileName.Length > 200)
        {
            fileName = fileName[..200];
        }

        return $"{fileName}_ns{namespaceIndex}.xml";
    }
}
