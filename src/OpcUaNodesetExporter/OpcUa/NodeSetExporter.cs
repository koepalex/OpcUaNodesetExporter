using System.Diagnostics;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Xml;
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
    private const uint DefaultMaxNodesPerRead = 1000;

    private readonly ILogger<NodeSetExporter> _logger;
    private readonly ILoggerFactory _loggerFactory;
    private readonly OpcUaClient _client;
    private readonly bool _verbose;
    private readonly bool _exportAttributes;

    /// <summary>
    /// Creates a new NodeSetExporter instance.
    /// </summary>
    /// <param name="logger">Logger instance.</param>
    /// <param name="loggerFactory">Logger factory for creating SDK telemetry context.</param>
    /// <param name="client">Connected OPC UA client.</param>
    /// <param name="verbose">Enable verbose output.</param>
    /// <param name="exportAttributes">
    /// When true, the exporter additionally reads the <c>Value</c> attribute
    /// for Variable / VariableType nodes (so it is included in the NodeSet2
    /// XML) and writes a JSON sidecar file per produced NodeSet2 file
    /// describing every attribute and its status.
    /// </param>
    public NodeSetExporter(
        ILogger<NodeSetExporter> logger,
        ILoggerFactory loggerFactory,
        OpcUaClient client,
        bool verbose = false,
        bool exportAttributes = false)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _loggerFactory = loggerFactory ?? throw new ArgumentNullException(nameof(loggerFactory));
        _client = client ?? throw new ArgumentNullException(nameof(client));
        _verbose = verbose;
        _exportAttributes = exportAttributes;
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

        // Read full attribute set per NodeClass so the serialized NodeSet2 XML
        // contains the actual server-side values for attributes such as
        // ValueRank, MinimumSamplingInterval, DataType, AccessLevel, etc.,
        // instead of the SDK's in-memory defaults (e.g. ValueRank = -2).
        await HydrateNodeAttributesAsync(nodes, cancellationToken).ConfigureAwait(false);

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

        // Read full attribute set per NodeClass before serializing so the
        // NodeSet2 XML reflects real server values instead of SDK defaults.
        await HydrateNodeAttributesAsync(combinedNodes, cancellationToken).ConfigureAwait(false);

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

        if (_exportAttributes)
        {
            await WriteAttributesJsonSidecarAsync(
                combinedNodes,
                startNamespaceIndex,
                namespaceUri,
                filePath,
                cancellationToken).ConfigureAwait(false);
        }

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

            if (_exportAttributes)
            {
                await WriteAttributesJsonSidecarAsync(
                    kvp.Value,
                    kvp.Key,
                    namespaceUri,
                    filePath,
                    cancellationToken).ConfigureAwait(false);
            }

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

        // When the user requested attribute export, also ask the SDK to emit
        // <Value> elements for variables. The default options omit them, which
        // is why our hydrated Variable.Value would otherwise be silently
        // discarded by CoreClientUtils.ExportNodesToNodeSet2.
        var exportOptions = _exportAttributes
            ? new NodeSetExportOptions { ExportValues = true }
            : NodeSetExportOptions.Default;

        // Use the OPC Foundation SDK's verified export functionality
        CoreClientUtils.ExportNodesToNodeSet2(systemContext, nodes, outputStream, exportOptions);

        _logger.LogDebug("Exported {Count} nodes to {FilePath} (ExportValues={ExportValues})",
            nodes.Count, filePath, exportOptions.ExportValues);
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

    /// <summary>
    /// Re-reads the standard attribute set per <see cref="NodeClass"/> for the
    /// given nodes so that attributes such as <c>ValueRank</c>,
    /// <c>MinimumSamplingInterval</c>, <c>DataType</c>, <c>AccessLevel</c>,
    /// etc. reflect actual server values instead of the SDK's in-memory
    /// defaults that are otherwise present after Browse-driven discovery.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The exporter discovers nodes via <c>NodeCache.FindReferencesAsync</c>,
    /// which is driven by the Browse service. Browse only returns a subset of
    /// node attributes; everything else keeps its SDK default
    /// (e.g. <c>ValueRank == ValueRanks.Any == -2</c>,
    /// <c>MinimumSamplingInterval == -1</c>). Because
    /// <c>CoreClientUtils.ExportNodesToNodeSet2</c> writes those in-memory
    /// values to XML when they differ from the NodeSet2 schema defaults, the
    /// emitted XML would otherwise show those nonsensical defaults for every
    /// variable. This method fixes that by issuing raw per-attribute
    /// <c>Read</c> calls and assigning the returned <see cref="DataValue"/>s
    /// onto the existing cached <see cref="Node"/> instances.
    /// </para>
    /// <para>
    /// Crucially, the method <strong>mutates the existing cached node</strong>
    /// rather than replacing it with a freshly-read <see cref="Node"/>: a
    /// replaced node would lose the references collected by the
    /// <see cref="NodeCache"/>, which would in turn cause
    /// <c>CoreClientUtils.ExportNodesToNodeSet2</c> to emit a NodeSet2 file
    /// without any <c>&lt;References&gt;</c> blocks.
    /// </para>
    /// <para>
    /// When an attribute read returns a <c>Bad</c> status, this method applies
    /// the NodeSet2 schema default (e.g., <c>ValueRank = -1</c>,
    /// <c>MinimumSamplingInterval = 0</c>, <c>AccessLevel = 0</c>,
    /// <c>Historizing = false</c>) instead of leaving the SDK default that
    /// would otherwise serialise incorrectly.
    /// </para>
    /// <para>
    /// When <see cref="_exportAttributes"/> is set, the <c>Value</c> attribute
    /// of Variable / VariableType nodes is additionally read and assigned, so
    /// it is included in the serialized NodeSet2 XML output.
    /// </para>
    /// </remarks>
    private async Task HydrateNodeAttributesAsync(
        IList<INode> nodes,
        CancellationToken cancellationToken)
    {
        if (nodes.Count == 0)
        {
            return;
        }

        await _client.ExecuteWithRetryAsync(async (session, ct) =>
        {
            var stopwatch = Stopwatch.StartNew();

            // Determine read chunk size from the server's reported operation limits.
            uint maxNodesPerRead = session.OperationLimits?.MaxNodesPerRead ?? 0;
            int chunkSize = maxNodesPerRead > 0 ? (int)maxNodesPerRead : (int)DefaultMaxNodesPerRead;

            // Build the flat (NodeId, AttributeId, target node) request list.
            // We assign attribute values onto the existing cached node instance
            // (which carries the Browse references) instead of replacing it,
            // so the serialized NodeSet2 XML keeps its <References> blocks.
            var requests = new List<(NodeId NodeId, uint AttributeId, INode Target)>(nodes.Count * 8);

            foreach (var node in nodes)
            {
                if (node.NodeClass == NodeClass.Unspecified)
                {
                    continue;
                }

                var nodeId = ExpandedNodeId.ToNodeId(node.NodeId, session.NamespaceUris);
                if (nodeId == null)
                {
                    continue;
                }

                foreach (var (attrId, _) in AttributesForNodeClass(node.NodeClass))
                {
                    // The Value attribute is only requested in --export-attributes mode:
                    // it can be expensive to read on large address spaces, and the
                    // default NodeSet2 export does not need it.
                    if (attrId == Attributes.Value && !_exportAttributes)
                    {
                        continue;
                    }

                    requests.Add((nodeId, attrId, node));
                }
            }

            if (requests.Count == 0)
            {
                return;
            }

            _logger.LogInformation(
                "Hydrating {Count} (node, attribute) pairs across {NodeCount} nodes (chunk size {Chunk})...",
                requests.Count, nodes.Count, chunkSize);

            int applied = 0;
            int unreadable = 0;

            for (int offset = 0; offset < requests.Count; offset += chunkSize)
            {
                ct.ThrowIfCancellationRequested();
                int take = Math.Min(chunkSize, requests.Count - offset);

                var nodesToRead = new ReadValueIdCollection(take);
                for (int i = 0; i < take; i++)
                {
                    nodesToRead.Add(new ReadValueId
                    {
                        NodeId = requests[offset + i].NodeId,
                        AttributeId = requests[offset + i].AttributeId,
                    });
                }

                ReadResponse? response = null;
                try
                {
                    response = await session.ReadAsync(
                        requestHeader: null,
                        maxAge: 0,
                        timestampsToReturn: TimestampsToReturn.Neither,
                        nodesToRead: nodesToRead,
                        ct: ct).ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex,
                        "Hydration Read chunk of {Count} (node, attribute) pairs failed; affected attributes will get NodeSet2 schema defaults.",
                        take);
                }

                for (int i = 0; i < take; i++)
                {
                    var req = requests[offset + i];
                    if (req.Target is not Node nodeImpl)
                    {
                        continue;
                    }

                    DataValue dv;
                    if (response != null && i < response.Results.Count && response.Results[i] != null)
                    {
                        dv = response.Results[i];
                    }
                    else
                    {
                        dv = new DataValue(StatusCodes.BadCommunicationError);
                    }

                    if (StatusCode.IsBad(dv.StatusCode))
                    {
                        unreadable++;
                    }
                    else if (req.AttributeId == Attributes.ValueRank
                        && dv.WrappedValue.Value is int vrCheck
                        && vrCheck == ValueRanks.Any)
                    {
                        // Helps the user distinguish "hydration didn't run" from
                        // "server actually returned ValueRank=Any (-2)".
                        _logger.LogDebug(
                            "Server returned ValueRank=Any (-2) for {NodeId}; this value will be serialised verbatim.",
                            req.NodeId);
                    }

                    ApplyAttributeToNode(nodeImpl, req.AttributeId, dv);
                    applied++;
                }
            }

            stopwatch.Stop();
            _logger.LogInformation(
                "Hydrated {Applied} attribute values ({Unreadable} fell back to NodeSet2 schema defaults) in {Duration}ms.",
                applied, unreadable, stopwatch.ElapsedMilliseconds);
        }, "HydrateNodeAttributes", cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Applies a single <see cref="DataValue"/> read result onto the
    /// corresponding attribute of the cached <see cref="Node"/>. On a
    /// <c>Bad</c> status, the NodeSet2 XML schema default is applied for the
    /// attributes that would otherwise serialise the SDK's misleading
    /// in-memory defaults (e.g. <c>ValueRank = -2</c>).
    /// </summary>
    /// <remarks>
    /// Exposed as <c>internal</c> for unit testing — production code calls it
    /// from <see cref="HydrateNodeAttributesAsync"/>.
    /// </remarks>
    internal static void ApplyAttributeToNode(Node node, uint attributeId, DataValue dv)
    {
        bool isGood = !StatusCode.IsBad(dv.StatusCode);
        object? raw = dv.WrappedValue.Value;

        // Common attributes (any node class).
        switch (attributeId)
        {
            case Attributes.Description:
                if (isGood && raw is LocalizedText desc)
                {
                    node.Description = desc;
                }
                return;
            case Attributes.WriteMask:
                if (isGood && raw is uint wm)
                {
                    node.WriteMask = wm;
                }
                return;
            case Attributes.UserWriteMask:
                if (isGood && raw is uint uwm)
                {
                    node.UserWriteMask = uwm;
                }
                return;
            case Attributes.NodeClass:
            case Attributes.BrowseName:
            case Attributes.DisplayName:
                // Already populated from Browse; we don't override the cached values.
                return;
        }

        switch (node)
        {
            case VariableNode vn:
                ApplyVariableAttribute(vn, attributeId, dv, isGood, raw);
                break;
            case VariableTypeNode vtn:
                ApplyVariableTypeAttribute(vtn, attributeId, dv, isGood, raw);
                break;
            case ObjectNode on:
                if (attributeId == Attributes.EventNotifier)
                {
                    on.EventNotifier = isGood && raw is byte enb ? enb : (byte)0;
                }
                break;
            case ObjectTypeNode otn:
                if (attributeId == Attributes.IsAbstract && isGood && raw is bool abs)
                {
                    otn.IsAbstract = abs;
                }
                break;
            case ReferenceTypeNode rtn:
                switch (attributeId)
                {
                    case Attributes.IsAbstract:
                        if (isGood && raw is bool absRt)
                        {
                            rtn.IsAbstract = absRt;
                        }
                        break;
                    case Attributes.Symmetric:
                        if (isGood && raw is bool sym)
                        {
                            rtn.Symmetric = sym;
                        }
                        break;
                    case Attributes.InverseName:
                        if (isGood && raw is LocalizedText inv)
                        {
                            rtn.InverseName = inv;
                        }
                        break;
                }
                break;
            case DataTypeNode dtn:
                switch (attributeId)
                {
                    case Attributes.IsAbstract:
                        if (isGood && raw is bool absDt)
                        {
                            dtn.IsAbstract = absDt;
                        }
                        break;
                    case Attributes.DataTypeDefinition:
                        if (isGood && raw is ExtensionObject def)
                        {
                            dtn.DataTypeDefinition = def;
                        }
                        break;
                }
                break;
            case MethodNode mn:
                switch (attributeId)
                {
                    case Attributes.Executable:
                        mn.Executable = isGood && raw is bool ex && ex;
                        break;
                    case Attributes.UserExecutable:
                        mn.UserExecutable = isGood && raw is bool uex && uex;
                        break;
                }
                break;
            case ViewNode vw:
                switch (attributeId)
                {
                    case Attributes.ContainsNoLoops:
                        vw.ContainsNoLoops = isGood && raw is bool nl && nl;
                        break;
                    case Attributes.EventNotifier:
                        vw.EventNotifier = isGood && raw is byte vnb ? vnb : (byte)0;
                        break;
                }
                break;
        }
    }

    private static void ApplyVariableAttribute(
        VariableNode vn, uint attributeId, DataValue dv, bool isGood, object? raw)
    {
        switch (attributeId)
        {
            case Attributes.Value:
                if (isGood)
                {
                    vn.Value = dv.WrappedValue;
                }
                break;
            case Attributes.DataType:
                if (isGood && raw is NodeId dt)
                {
                    vn.DataType = dt;
                }
                break;
            case Attributes.ValueRank:
                vn.ValueRank = isGood && raw is int vr ? vr : ValueRanks.Scalar;
                break;
            case Attributes.ArrayDimensions:
                vn.ArrayDimensions = isGood && raw is uint[] dims
                    ? new UInt32Collection(dims)
                    : new UInt32Collection();
                break;
            case Attributes.AccessLevel:
                vn.AccessLevel = isGood && raw is byte al ? al : (byte)0;
                break;
            case Attributes.UserAccessLevel:
                vn.UserAccessLevel = isGood && raw is byte ual ? ual : (byte)0;
                break;
            case Attributes.MinimumSamplingInterval:
                vn.MinimumSamplingInterval = isGood && raw is double ms ? ms : 0d;
                break;
            case Attributes.Historizing:
                vn.Historizing = isGood && raw is bool hi && hi;
                break;
            case Attributes.AccessLevelEx:
                if (isGood && raw is uint ax)
                {
                    vn.AccessLevelEx = ax;
                }
                break;
        }
    }

    private static void ApplyVariableTypeAttribute(
        VariableTypeNode vtn, uint attributeId, DataValue dv, bool isGood, object? raw)
    {
        switch (attributeId)
        {
            case Attributes.Value:
                if (isGood)
                {
                    vtn.Value = dv.WrappedValue;
                }
                break;
            case Attributes.DataType:
                if (isGood && raw is NodeId dt)
                {
                    vtn.DataType = dt;
                }
                break;
            case Attributes.ValueRank:
                vtn.ValueRank = isGood && raw is int vr ? vr : ValueRanks.Scalar;
                break;
            case Attributes.ArrayDimensions:
                vtn.ArrayDimensions = isGood && raw is uint[] dims
                    ? new UInt32Collection(dims)
                    : new UInt32Collection();
                break;
            case Attributes.IsAbstract:
                if (isGood && raw is bool abs)
                {
                    vtn.IsAbstract = abs;
                }
                break;
        }
    }

    /// <summary>
    /// Writes a JSON sidecar next to <paramref name="nodeSet2FilePath"/> that
    /// records every standard attribute (and its <see cref="StatusCode"/>) for
    /// each node in the export. Intended for diagnostic inspection — e.g.,
    /// detecting variables that have an unreadable or empty <c>Value</c>.
    /// </summary>
    /// <remarks>
    /// The sidecar issues a raw <c>Read</c> service call for the (node,
    /// attribute) pairs relevant to each node's <see cref="NodeClass"/> so the
    /// recorded status codes reflect what the server actually returned. The
    /// in-memory hydration done by
    /// <see cref="HydrateNodeAttributesAsync"/> does not preserve per-attribute
    /// status codes, so a dedicated read is required here.
    /// </remarks>
    private async Task WriteAttributesJsonSidecarAsync(
        IList<INode> nodes,
        ushort namespaceIndex,
        string namespaceUri,
        string nodeSet2FilePath,
        CancellationToken cancellationToken)
    {
        if (nodes.Count == 0)
        {
            return;
        }

        var sidecarPath = Path.ChangeExtension(nodeSet2FilePath, null) + "_attributes.json";
        _logger.LogInformation("Writing attribute diagnostic file: {Path}", sidecarPath);

        // Filter to the nodes that actually belong to this namespace.
        var relevantNodes = nodes
            .Where(n => n.NodeId.NamespaceIndex == namespaceIndex)
            .ToList();

        if (relevantNodes.Count == 0)
        {
            _logger.LogDebug("No nodes in namespace {Index} to write to sidecar.", namespaceIndex);
            return;
        }

        var dump = await _client.ExecuteWithRetryAsync(async (session, ct) =>
        {
            uint maxNodesPerRead = session.OperationLimits?.MaxNodesPerRead ?? 0;
            int chunkSize = maxNodesPerRead > 0 ? (int)maxNodesPerRead : (int)DefaultMaxNodesPerRead;

            // Build (node, attribute id) requests, tagged with which node /
            // attribute they map back to.
            var requestsByNode = new Dictionary<int, List<(uint AttributeId, string Name)>>();
            var flat = new List<(int NodeIndex, uint AttributeId, string Name, ReadValueId Rvid)>();

            for (int ni = 0; ni < relevantNodes.Count; ni++)
            {
                var node = relevantNodes[ni];
                var nodeId = ExpandedNodeId.ToNodeId(node.NodeId, session.NamespaceUris);
                if (nodeId == null)
                {
                    continue;
                }

                foreach (var (attrId, attrName) in AttributesForNodeClass(node.NodeClass))
                {
                    flat.Add((ni, attrId, attrName, new ReadValueId
                    {
                        NodeId = nodeId,
                        AttributeId = attrId,
                    }));

                    if (!requestsByNode.TryGetValue(ni, out var list))
                    {
                        list = new List<(uint, string)>();
                        requestsByNode[ni] = list;
                    }
                    list.Add((attrId, attrName));
                }
            }

            // Issue Read in chunks. Order is preserved so we can stitch back.
            var allValues = new DataValue[flat.Count];

            for (int offset = 0; offset < flat.Count; offset += chunkSize)
            {
                ct.ThrowIfCancellationRequested();
                int take = Math.Min(chunkSize, flat.Count - offset);

                var nodesToRead = new ReadValueIdCollection(
                    flat.Skip(offset).Take(take).Select(t => t.Rvid));

                ReadResponse? response = null;
                try
                {
                    response = await session.ReadAsync(
                        requestHeader: null,
                        maxAge: 0,
                        timestampsToReturn: TimestampsToReturn.Neither,
                        nodesToRead: nodesToRead,
                        ct: ct).ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex,
                        "Sidecar Read chunk of {Count} (node,attribute) pairs failed; those attributes will be recorded as 'BadCommunicationError'.",
                        take);
                }

                for (int i = 0; i < take; i++)
                {
                    if (response != null && i < response.Results.Count)
                    {
                        allValues[offset + i] = response.Results[i];
                    }
                    else
                    {
                        allValues[offset + i] = new DataValue(StatusCodes.BadCommunicationError);
                    }
                }
            }

            // Build the per-node attribute dictionaries.
            var nodeDumps = new List<NodeAttributeDump>(relevantNodes.Count);
            for (int ni = 0; ni < relevantNodes.Count; ni++)
            {
                var node = relevantNodes[ni];
                var attrs = new Dictionary<string, AttributeDump>(StringComparer.Ordinal);
                nodeDumps.Add(new NodeAttributeDump
                {
                    NodeId = node.NodeId.ToString() ?? string.Empty,
                    BrowseName = node.BrowseName?.ToString() ?? string.Empty,
                    DisplayName = node.DisplayName?.Text ?? string.Empty,
                    NodeClass = node.NodeClass.ToString(),
                    Attributes = attrs,
                });
            }

            for (int i = 0; i < flat.Count; i++)
            {
                var (nodeIndex, _, name, _) = flat[i];
                var dv = allValues[i] ?? new DataValue(StatusCodes.BadNoData);
                nodeDumps[nodeIndex].Attributes[name] = AttributeDump.FromDataValue(dv);
            }

            return new NamespaceAttributeDump
            {
                NamespaceUri = namespaceUri,
                NamespaceIndex = namespaceIndex,
                ExportedAt = DateTime.UtcNow,
                Nodes = nodeDumps,
            };
        }, "WriteAttributesJsonSidecar", cancellationToken).ConfigureAwait(false);

        var jsonOptions = new JsonSerializerOptions
        {
            WriteIndented = true,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        };

        await using var stream = new FileStream(
            sidecarPath, FileMode.Create, FileAccess.Write, FileShare.None);
        await JsonSerializer.SerializeAsync(stream, dump, jsonOptions, cancellationToken)
            .ConfigureAwait(false);

        _logger.LogInformation("Attribute diagnostic written for {Count} nodes -> {Path}",
            dump.Nodes.Count, sidecarPath);
    }

    /// <summary>
    /// Returns the OPC UA attribute ids (and human-readable names) that are
    /// relevant to a given <see cref="NodeClass"/>. Mirrors the set written
    /// by <c>CoreClientUtils.ExportNodesToNodeSet2</c>, plus <c>Value</c> for
    /// Variable / VariableType nodes.
    /// </summary>
    private static IEnumerable<(uint AttributeId, string Name)> AttributesForNodeClass(NodeClass nodeClass)
    {
        // Common attributes for every node class.
        yield return (Attributes.NodeClass, "NodeClass");
        yield return (Attributes.BrowseName, "BrowseName");
        yield return (Attributes.DisplayName, "DisplayName");
        yield return (Attributes.Description, "Description");
        yield return (Attributes.WriteMask, "WriteMask");
        yield return (Attributes.UserWriteMask, "UserWriteMask");

        switch (nodeClass)
        {
            case NodeClass.Variable:
                yield return (Attributes.Value, "Value");
                yield return (Attributes.DataType, "DataType");
                yield return (Attributes.ValueRank, "ValueRank");
                yield return (Attributes.ArrayDimensions, "ArrayDimensions");
                yield return (Attributes.AccessLevel, "AccessLevel");
                yield return (Attributes.UserAccessLevel, "UserAccessLevel");
                yield return (Attributes.MinimumSamplingInterval, "MinimumSamplingInterval");
                yield return (Attributes.Historizing, "Historizing");
                yield return (Attributes.AccessLevelEx, "AccessLevelEx");
                break;

            case NodeClass.VariableType:
                yield return (Attributes.Value, "Value");
                yield return (Attributes.DataType, "DataType");
                yield return (Attributes.ValueRank, "ValueRank");
                yield return (Attributes.ArrayDimensions, "ArrayDimensions");
                yield return (Attributes.IsAbstract, "IsAbstract");
                break;

            case NodeClass.Object:
                yield return (Attributes.EventNotifier, "EventNotifier");
                break;

            case NodeClass.ObjectType:
                yield return (Attributes.IsAbstract, "IsAbstract");
                break;

            case NodeClass.ReferenceType:
                yield return (Attributes.IsAbstract, "IsAbstract");
                yield return (Attributes.Symmetric, "Symmetric");
                yield return (Attributes.InverseName, "InverseName");
                break;

            case NodeClass.DataType:
                yield return (Attributes.IsAbstract, "IsAbstract");
                yield return (Attributes.DataTypeDefinition, "DataTypeDefinition");
                break;

            case NodeClass.Method:
                yield return (Attributes.Executable, "Executable");
                yield return (Attributes.UserExecutable, "UserExecutable");
                break;

            case NodeClass.View:
                yield return (Attributes.ContainsNoLoops, "ContainsNoLoops");
                yield return (Attributes.EventNotifier, "EventNotifier");
                break;
        }
    }

    // ----- JSON DTOs for the attribute sidecar -----

    private sealed class NamespaceAttributeDump
    {
        public string NamespaceUri { get; init; } = string.Empty;
        public ushort NamespaceIndex { get; init; }
        public DateTime ExportedAt { get; init; }
        public List<NodeAttributeDump> Nodes { get; init; } = new();
    }

    private sealed class NodeAttributeDump
    {
        public string NodeId { get; init; } = string.Empty;
        public string BrowseName { get; init; } = string.Empty;
        public string DisplayName { get; init; } = string.Empty;
        public string NodeClass { get; init; } = string.Empty;
        public Dictionary<string, AttributeDump> Attributes { get; init; } = new();
    }

    /// <summary>
    /// Serializable view of a single attribute Read result.
    /// <c>Value</c> contains the JSON-serializable representation of the
    /// attribute's value. Complex / non-JSON-friendly OPC UA types (NodeId,
    /// ByteString, LocalizedText, DateTime, ExtensionObject, …) are
    /// rendered as strings — consumers can look at the node's
    /// <c>DataType</c> attribute to know the original type.
    /// </summary>
    public sealed class AttributeDump
    {
        public string Status { get; init; } = "Good";
        public string? StatusCode { get; init; }
        public object? Value { get; init; }

        public static AttributeDump FromDataValue(DataValue dv)
        {
            var value = ConvertVariantToJsonFriendly(dv.WrappedValue);

            string symbolic = global::Opc.Ua.StatusCodes.GetBrowseName(dv.StatusCode.Code);
            if (string.IsNullOrEmpty(symbolic) || symbolic == dv.StatusCode.Code.ToString())
            {
                symbolic = $"0x{dv.StatusCode.Code:X8}";
            }

            return new AttributeDump
            {
                Status = symbolic,
                StatusCode = $"0x{dv.StatusCode.Code:X8}",
                Value = value,
            };
        }

        private static object? ConvertVariantToJsonFriendly(Variant variant)
        {
            if (variant.Value == null || variant == Variant.Null)
            {
                return null;
            }

            var v = variant.Value;
            switch (v)
            {
                case string:
                case bool:
                case sbyte or byte:
                case short or ushort:
                case int or uint:
                case long or ulong:
                case float or double:
                case decimal:
                    return v;
                case DateTime dt:
                    return dt.ToString("O", System.Globalization.CultureInfo.InvariantCulture);
                case Guid g:
                    return g.ToString();
                case Uuid uuid:
                    return uuid.ToString();
                case byte[] bytes:
                    return Convert.ToBase64String(bytes);
                case XmlElement xe:
                    return xe.OuterXml;
                case LocalizedText lt:
                    return lt.Text;
                case QualifiedName qn:
                    return qn.ToString();
                case NodeId nid:
                    return nid.ToString();
                case ExpandedNodeId enid:
                    return enid.ToString();
                case StatusCode sc:
                    return $"0x{sc.Code:X8}";
            }

            // Arrays of the above scalar types: convert element-wise.
            if (v is Array arr)
            {
                var items = new List<object?>(arr.Length);
                foreach (var item in arr)
                {
                    items.Add(ConvertVariantToJsonFriendly(new Variant(item)));
                }
                return items;
            }

            // Fallback: stringify ExtensionObject and any other complex value.
            return v.ToString();
        }
    }
}
