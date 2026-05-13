using System.Diagnostics;
using Microsoft.Extensions.Logging;
using Opc.Ua;
using Opc.Ua.Client;
using Opc.Ua.Client.ComplexTypes;

namespace OpcUaNodesetExporter.OpcUa;

/// <summary>
/// Exports OPC UA nodes to NodeSet2 XML files, grouped by namespace.
/// Uses the OPC Foundation SDK's CoreClientUtils.ExportNodesToNodeSet2 for verified export functionality.
/// </summary>
public class NodeSetExporter
{
    private const int MaxSearchDepth = 128;

    private readonly ILogger<NodeSetExporter> _logger;
    private readonly ILoggerFactory _loggerFactory;
    private readonly OpcUaClient _client;
    private readonly bool _verbose;

    /// <summary>
    /// Creates a new NodeSetExporter instance.
    /// </summary>
    /// <param name="logger">Logger instance.</param>
    /// <param name="loggerFactory">Logger factory for creating SDK telemetry context.</param>
    /// <param name="client">Connected OPC UA client.</param>
    /// <param name="verbose">Enable verbose output.</param>
    public NodeSetExporter(ILogger<NodeSetExporter> logger, ILoggerFactory loggerFactory, OpcUaClient client, bool verbose = false)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _loggerFactory = loggerFactory ?? throw new ArgumentNullException(nameof(loggerFactory));
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
    /// Exports a subtree starting from a specific node to a single NodeSet2 XML file.
    /// Includes the start node, all its subnodes (via hierarchical references), and
    /// type definitions that are in the same namespace as the start node and used by the subtree.
    /// </summary>
    /// <param name="startNodeId">The ExpandedNodeId of the root node for the subtree export.</param>
    /// <param name="outputDirectory">Directory to save the NodeSet2 file.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The path to the exported NodeSet2 XML file.</returns>
    public async Task<string> ExportSubtreeAsync(
        ExpandedNodeId startNodeId,
        string outputDirectory,
        CancellationToken cancellationToken = default)
    {
        _logger.LogInformation("Starting subtree export from {StartNode} to {OutputDirectory}",
            startNodeId, outputDirectory);
        var stopwatch = Stopwatch.StartNew();

        Directory.CreateDirectory(outputDirectory);

        _logger.LogInformation("Loading type system...");
        await LoadTypeSystemAsync(cancellationToken).ConfigureAwait(false);

        _logger.LogInformation("Fetching subtree nodes from {StartNode}...", startNodeId);
        var subtreeNodes = await FetchSubtreeNodesAsync(startNodeId, cancellationToken).ConfigureAwait(false);
        _logger.LogInformation("Fetched {Count} subtree nodes.", subtreeNodes.Count);

        var startNamespaceIndex = startNodeId.NamespaceIndex;
        _logger.LogInformation("Collecting type definitions in namespace index {Namespace}...", startNamespaceIndex);
        var typeDefinitions = await CollectUsedTypeDefinitionsAsync(
            subtreeNodes, startNamespaceIndex, cancellationToken).ConfigureAwait(false);
        _logger.LogInformation("Collected {Count} type definitions.", typeDefinitions.Count);

        // Combine instance nodes and type definitions, avoiding duplicates
        var allNodes = new Dictionary<ExpandedNodeId, INode>();
        foreach (var node in subtreeNodes)
        {
            allNodes[node.NodeId] = node;
        }
        foreach (var node in typeDefinitions)
        {
            allNodes[node.NodeId] = node;
        }

        var combinedNodes = allNodes.Values.ToList();
        combinedNodes.Sort((x, y) => x.NodeId.CompareTo(y.NodeId));

        // Generate output file name from the start node
        var session = _client.Session;
        string namespaceUri = session.NamespaceUris.GetString(startNamespaceIndex);
        string fileName = CreateSafeFileName(namespaceUri, startNamespaceIndex);
        string filePath = Path.Combine(outputDirectory, fileName);

        _logger.LogInformation("Exporting {Count} nodes to {File}...", combinedNodes.Count, fileName);

        await Task.Run(() =>
        {
            ExportNodesToNodeSet2File(session, combinedNodes, filePath);
        }, cancellationToken).ConfigureAwait(false);

        stopwatch.Stop();
        _logger.LogInformation("Subtree export completed in {Duration}ms. Exported {Count} nodes to {File}.",
            stopwatch.ElapsedMilliseconds, combinedNodes.Count, filePath);

        return filePath;
    }

    /// <summary>
    /// Fetches all nodes in the subtree starting from the given node via hierarchical references.
    /// Includes the start node itself.
    /// </summary>
    private async Task<IList<INode>> FetchSubtreeNodesAsync(
        ExpandedNodeId startNodeId,
        CancellationToken cancellationToken)
    {
        return await _client.ExecuteWithRetryAsync(async (session, ct) =>
        {
            var stopwatch = Stopwatch.StartNew();
            var nodeDictionary = new Dictionary<ExpandedNodeId, INode>();
            var references = new NodeIdCollection { ReferenceTypeIds.HierarchicalReferences };
            var nodesToBrowse = new ExpandedNodeIdCollection { startNodeId };

            session.NodeCache.Clear();
            await FetchReferenceIdTypesAsync(session, ct).ConfigureAwait(false);

            // Add the start node itself
            var startNode = await session.NodeCache.FindAsync(startNodeId, ct).ConfigureAwait(false);
            if (startNode != null)
            {
                nodeDictionary[startNode.NodeId] = startNode;
            }

            int searchDepth = 0;
            while (nodesToBrowse.Count > 0 && searchDepth < MaxSearchDepth)
            {
                ct.ThrowIfCancellationRequested();

                searchDepth++;
                _logger.LogInformation("Subtree depth {Depth}: Browsing {Count} nodes ({Elapsed}ms)...",
                    searchDepth, nodesToBrowse.Count, stopwatch.ElapsedMilliseconds);

                var response = await session.NodeCache.FindReferencesAsync(
                    nodesToBrowse, references, false, true, ct).ConfigureAwait(false);

                var nextNodesToBrowse = new ExpandedNodeIdCollection();
                int duplicates = 0;

                foreach (var node in response)
                {
                    if (!nodeDictionary.ContainsKey(node.NodeId))
                    {
                        nodeDictionary[node.NodeId] = node;

                        bool isLeafNode = false;
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

                nodesToBrowse = nextNodesToBrowse;
            }

            stopwatch.Stop();

            var result = nodeDictionary.Values.ToList();
            result.Sort((x, y) => x.NodeId.CompareTo(y.NodeId));

            _logger.LogInformation("FetchSubtreeNodes found {Count} nodes in {Duration}ms.",
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
        }, "FetchSubtreeNodes", cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Collects type definitions used by the subtree nodes that are in the specified namespace.
    /// Also includes supertypes in the same namespace to ensure a valid type hierarchy.
    /// </summary>
    private async Task<IList<INode>> CollectUsedTypeDefinitionsAsync(
        IList<INode> subtreeNodes,
        ushort targetNamespaceIndex,
        CancellationToken cancellationToken)
    {
        return await _client.ExecuteWithRetryAsync(async (session, ct) =>
        {
            var typeDefNodes = new Dictionary<ExpandedNodeId, INode>();
            var processedTypeIds = new HashSet<ExpandedNodeId>();

            // Collect all type definition IDs referenced by subtree nodes
            var typeDefIdsToResolve = new HashSet<ExpandedNodeId>();
            foreach (var node in subtreeNodes)
            {
                var typeDefId = node.TypeDefinitionId;
                if (!NodeId.IsNull(typeDefId) && typeDefId.NamespaceIndex == targetNamespaceIndex)
                {
                    typeDefIdsToResolve.Add(typeDefId);
                }
            }

            _logger.LogDebug("Found {Count} unique type definition references in target namespace.",
                typeDefIdsToResolve.Count);

            // Resolve type definitions and walk the supertype chain
            while (typeDefIdsToResolve.Count > 0)
            {
                ct.ThrowIfCancellationRequested();

                var currentBatch = typeDefIdsToResolve.ToList();
                typeDefIdsToResolve.Clear();

                foreach (var typeDefId in currentBatch)
                {
                    if (processedTypeIds.Contains(typeDefId))
                    {
                        continue;
                    }
                    processedTypeIds.Add(typeDefId);

                    // Fetch the type definition node
                    var typeNode = await session.NodeCache.FindAsync(typeDefId, ct).ConfigureAwait(false);
                    if (typeNode == null)
                    {
                        _logger.LogWarning("Could not find type definition node {TypeDefId}", typeDefId);
                        continue;
                    }

                    typeDefNodes[typeNode.NodeId] = typeNode;

                    if (_verbose)
                    {
                        _logger.LogDebug("Included type definition: {NodeId} ({BrowseName})",
                            typeNode.NodeId, typeNode.BrowseName);
                    }

                    // Walk the supertype chain: find the parent type via HasSubtype inverse
                    var supertypes = await session.NodeCache.FindReferencesAsync(
                        typeDefId,
                        ReferenceTypeIds.HasSubtype,
                        true, // isInverse = true → finds the parent/supertype
                        false,
                        ct).ConfigureAwait(false);

                    foreach (var supertype in supertypes)
                    {
                        if (supertype.NodeId.NamespaceIndex == targetNamespaceIndex &&
                            !processedTypeIds.Contains(supertype.NodeId))
                        {
                            typeDefIdsToResolve.Add(supertype.NodeId);
                        }
                    }

                    // Also collect child nodes of the type definition (components, properties)
                    // that are in the same namespace, so the type definition is complete
                    var typeChildren = await session.NodeCache.FindReferencesAsync(
                        typeDefId,
                        ReferenceTypeIds.HierarchicalReferences,
                        false,
                        true,
                        ct).ConfigureAwait(false);

                    foreach (var child in typeChildren)
                    {
                        if (child.NodeId.NamespaceIndex == targetNamespaceIndex &&
                            !typeDefNodes.ContainsKey(child.NodeId))
                        {
                            typeDefNodes[child.NodeId] = child;
                        }
                    }
                }
            }

            var result = typeDefNodes.Values.ToList();
            _logger.LogInformation("Collected {Count} type definition nodes (including supertypes and children) in namespace {Namespace}.",
                result.Count, targetNamespaceIndex);

            return (IList<INode>)result;
        }, "CollectUsedTypeDefinitions", cancellationToken).ConfigureAwait(false);
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
    /// Exports nodes to a single NodeSet2 XML file using the OPC Foundation SDK.
    /// </summary>
    private void ExportNodesToNodeSet2File(ISession session, IList<INode> nodes, string filePath)
    {
        using var outputStream = new FileStream(filePath, FileMode.Create, FileAccess.Write, FileShare.None);

        // Create telemetry context from the logger factory
        var telemetryContext = new LoggerFactoryTelemetryContext(_loggerFactory);

        // Create system context with namespace information from the session
        var systemContext = new SystemContext(telemetryContext)
        {
            NamespaceUris = session.NamespaceUris,
            ServerUris = session.ServerUris
        };

        // Use the OPC Foundation SDK's verified export functionality
        CoreClientUtils.ExportNodesToNodeSet2(systemContext, nodes, outputStream);

        _logger.LogDebug("Exported {Count} nodes to {FilePath}", nodes.Count, filePath);
    }

    /// <summary>
    /// A telemetry context implementation that wraps an existing ILoggerFactory.
    /// </summary>
    private sealed class LoggerFactoryTelemetryContext : TelemetryContextBase
    {
        public LoggerFactoryTelemetryContext(ILoggerFactory loggerFactory)
            : base(loggerFactory)
        {
        }
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
