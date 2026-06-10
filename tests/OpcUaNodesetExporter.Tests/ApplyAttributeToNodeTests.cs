using Opc.Ua;
using OpcUaNodesetExporter.OpcUa;

namespace OpcUaNodesetExporter.Tests;

/// <summary>
/// Unit tests for <see cref="NodeSetExporter.ApplyAttributeToNode"/> — the
/// per-attribute mutator that <see cref="NodeSetExporter"/> uses to hydrate
/// cached <see cref="Node"/> instances after a raw Read call. These tests
/// are the regression net for the &quot;<c>ValueRank=-2</c> still in XML&quot;
/// problem: if hydration does not actually mutate the node, the SDK
/// exporter falls back to <see cref="ValueRanks.Any"/> (-2) when serialising.
/// </summary>
public class ApplyAttributeToNodeTests
{
    [Fact]
    public void Variable_ValueRank_Good_AppliesServerValue()
    {
        var node = new VariableNode { ValueRank = ValueRanks.Any };

        NodeSetExporter.ApplyAttributeToNode(
            node,
            Attributes.ValueRank,
            new DataValue(new Variant(ValueRanks.OneDimension)));

        Assert.Equal(ValueRanks.OneDimension, node.ValueRank);
    }

    [Fact]
    public void Variable_ValueRank_BadStatus_AppliesScalarSchemaDefault()
    {
        var node = new VariableNode { ValueRank = ValueRanks.Any };

        NodeSetExporter.ApplyAttributeToNode(
            node,
            Attributes.ValueRank,
            new DataValue(StatusCodes.BadAttributeIdInvalid));

        // -1 (Scalar) is the NodeSet2 XML schema default — the SDK exporter
        // omits the attribute entirely when it equals -1.
        Assert.Equal(ValueRanks.Scalar, node.ValueRank);
    }

    [Fact]
    public void Variable_MinimumSamplingInterval_BadStatus_AppliesZeroDefault()
    {
        var node = new VariableNode { MinimumSamplingInterval = -1 };

        NodeSetExporter.ApplyAttributeToNode(
            node,
            Attributes.MinimumSamplingInterval,
            new DataValue(StatusCodes.BadNotReadable));

        Assert.Equal(0d, node.MinimumSamplingInterval);
    }

    [Fact]
    public void Variable_MinimumSamplingInterval_Good_AppliesServerValue()
    {
        var node = new VariableNode { MinimumSamplingInterval = -1 };

        NodeSetExporter.ApplyAttributeToNode(
            node,
            Attributes.MinimumSamplingInterval,
            new DataValue(new Variant(250.0)));

        Assert.Equal(250.0, node.MinimumSamplingInterval);
    }

    [Fact]
    public void Variable_Value_Good_AppliesWrappedVariant()
    {
        var node = new VariableNode();

        NodeSetExporter.ApplyAttributeToNode(
            node,
            Attributes.Value,
            new DataValue(new Variant(42)));

        Assert.Equal(42, node.Value.Value);
    }

    [Fact]
    public void Variable_AccessLevel_BadStatus_AppliesZero()
    {
        var node = new VariableNode { AccessLevel = 99 };

        NodeSetExporter.ApplyAttributeToNode(
            node,
            Attributes.AccessLevel,
            new DataValue(StatusCodes.BadAttributeIdInvalid));

        Assert.Equal((byte)0, node.AccessLevel);
    }

    [Fact]
    public void Variable_Historizing_BadStatus_AppliesFalse()
    {
        var node = new VariableNode { Historizing = true };

        NodeSetExporter.ApplyAttributeToNode(
            node,
            Attributes.Historizing,
            new DataValue(StatusCodes.BadAttributeIdInvalid));

        Assert.False(node.Historizing);
    }

    [Fact]
    public void VariableType_ValueRank_BadStatus_AppliesScalarSchemaDefault()
    {
        var node = new VariableTypeNode { ValueRank = ValueRanks.Any };

        NodeSetExporter.ApplyAttributeToNode(
            node,
            Attributes.ValueRank,
            new DataValue(StatusCodes.BadAttributeIdInvalid));

        Assert.Equal(ValueRanks.Scalar, node.ValueRank);
    }

    [Fact]
    public void VariableType_Value_Good_AppliesWrappedVariant()
    {
        var node = new VariableTypeNode();

        NodeSetExporter.ApplyAttributeToNode(
            node,
            Attributes.Value,
            new DataValue(new Variant("hello")));

        Assert.Equal("hello", node.Value.Value);
    }

    [Fact]
    public void Description_Good_AppliesLocalizedText()
    {
        var node = new VariableNode();
        var description = new LocalizedText("en", "test description");

        NodeSetExporter.ApplyAttributeToNode(
            node,
            Attributes.Description,
            new DataValue(new Variant(description)));

        Assert.Equal("test description", node.Description.Text);
    }

    [Fact]
    public void Object_EventNotifier_BadStatus_AppliesZero()
    {
        var node = new ObjectNode { EventNotifier = 5 };

        NodeSetExporter.ApplyAttributeToNode(
            node,
            Attributes.EventNotifier,
            new DataValue(StatusCodes.BadAttributeIdInvalid));

        Assert.Equal((byte)0, node.EventNotifier);
    }
}
