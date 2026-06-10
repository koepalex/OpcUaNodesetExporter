using Opc.Ua;
using OpcUaNodesetExporter.OpcUa;

namespace OpcUaNodesetExporter.Tests;

public class AttributeDumpTests
{
    [Fact]
    public void FromDataValue_Good_PreservesScalarValueAndStatus()
    {
        var dv = new DataValue(new Variant(42), StatusCodes.Good, DateTime.UtcNow);

        var dump = NodeSetExporter.AttributeDump.FromDataValue(dv);

        Assert.Equal(42, dump.Value);
        Assert.Equal("0x00000000", dump.StatusCode);
        Assert.Equal("Good", dump.Status);
    }

    [Fact]
    public void FromDataValue_BadStatus_RecordsSymbolicName()
    {
        var dv = new DataValue(StatusCodes.BadAttributeIdInvalid);

        var dump = NodeSetExporter.AttributeDump.FromDataValue(dv);

        Assert.Null(dump.Value);
        Assert.Contains("Bad", dump.Status);
        Assert.StartsWith("0x", dump.StatusCode);
    }

    [Fact]
    public void FromDataValue_StringValue_IsCopiedThroughAsIs()
    {
        var dv = new DataValue(new Variant("hello"));

        var dump = NodeSetExporter.AttributeDump.FromDataValue(dv);

        Assert.Equal("hello", dump.Value);
    }

    [Fact]
    public void FromDataValue_LocalizedText_FallsBackToStringRepresentation()
    {
        var dv = new DataValue(new Variant(new LocalizedText("en", "Hello")));

        var dump = NodeSetExporter.AttributeDump.FromDataValue(dv);

        Assert.Equal("Hello", dump.Value);
    }

    [Fact]
    public void FromDataValue_NodeId_FallsBackToString()
    {
        var dv = new DataValue(new Variant(new NodeId(42, 3)));

        var dump = NodeSetExporter.AttributeDump.FromDataValue(dv);

        Assert.IsType<string>(dump.Value);
        Assert.Contains("ns=3", (string)dump.Value!);
    }

    [Fact]
    public void FromDataValue_ByteArray_IsBase64Encoded()
    {
        var bytes = new byte[] { 0x01, 0x02, 0x03 };
        var dv = new DataValue(new Variant(bytes));

        var dump = NodeSetExporter.AttributeDump.FromDataValue(dv);

        Assert.Equal(Convert.ToBase64String(bytes), dump.Value);
    }

    [Fact]
    public void FromDataValue_Array_ConvertsElementWise()
    {
        var dv = new DataValue(new Variant(new int[] { 1, 2, 3 }));

        var dump = NodeSetExporter.AttributeDump.FromDataValue(dv);

        var items = Assert.IsType<List<object?>>(dump.Value);
        Assert.Equal(new object?[] { 1, 2, 3 }, items);
    }

    [Fact]
    public void FromDataValue_NullVariant_RecordsNullValue()
    {
        var dv = new DataValue(Variant.Null);

        var dump = NodeSetExporter.AttributeDump.FromDataValue(dv);

        Assert.Null(dump.Value);
    }

    [Fact]
    public void FromDataValue_ExtensionObject_FallsBackToString()
    {
        // ExtensionObject without an explicit JSON representation should be
        // serialised as a string so the diagnostic file stays JSON-valid.
        var ext = new ExtensionObject(ObjectIds.Server, new byte[] { 0x10 });
        var dv = new DataValue(new Variant(ext));

        var dump = NodeSetExporter.AttributeDump.FromDataValue(dv);

        Assert.NotNull(dump.Value);
        Assert.IsType<string>(dump.Value);
    }
}
