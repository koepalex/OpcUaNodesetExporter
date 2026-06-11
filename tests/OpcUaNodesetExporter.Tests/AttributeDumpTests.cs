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

    [Theory]
    [InlineData(double.NaN, "NaN")]
    [InlineData(double.PositiveInfinity, "Infinity")]
    [InlineData(double.NegativeInfinity, "-Infinity")]
    public void FromDataValue_NonFiniteDouble_IsConvertedToToken(double value, string expectedToken)
    {
        var dv = new DataValue(new Variant(value));

        var dump = NodeSetExporter.AttributeDump.FromDataValue(dv);

        Assert.Equal(expectedToken, dump.Value);
    }

    [Theory]
    [InlineData(float.NaN, "NaN")]
    [InlineData(float.PositiveInfinity, "Infinity")]
    [InlineData(float.NegativeInfinity, "-Infinity")]
    public void FromDataValue_NonFiniteFloat_IsConvertedToToken(float value, string expectedToken)
    {
        var dv = new DataValue(new Variant(value));

        var dump = NodeSetExporter.AttributeDump.FromDataValue(dv);

        Assert.Equal(expectedToken, dump.Value);
    }

    [Fact]
    public void FromDataValue_FiniteDouble_RoundTripsAsDouble()
    {
        var dv = new DataValue(new Variant(3.14159));

        var dump = NodeSetExporter.AttributeDump.FromDataValue(dv);

        Assert.Equal(3.14159, Assert.IsType<double>(dump.Value));
    }

    [Fact]
    public void FromDataValue_DoubleArrayWithNaN_ConvertsTokenElementWise()
    {
        var arr = new[] { 1.0, double.NaN, double.PositiveInfinity, double.NegativeInfinity, 2.5 };
        var dv = new DataValue(new Variant(arr));

        var dump = NodeSetExporter.AttributeDump.FromDataValue(dv);

        var list = Assert.IsAssignableFrom<System.Collections.Generic.List<object?>>(dump.Value);
        Assert.Equal(5, list.Count);
        Assert.Equal(1.0, list[0]);
        Assert.Equal("NaN", list[1]);
        Assert.Equal("Infinity", list[2]);
        Assert.Equal("-Infinity", list[3]);
        Assert.Equal(2.5, list[4]);
    }

    [Fact]
    public async Task Serialize_DumpWithNonFiniteValues_DoesNotThrow()
    {
        // Direct regression test for the CI failure: serialise an
        // AttributeDump containing NaN / +-Infinity using the same options
        // the production sidecar writer uses and assert no exception.
        var dumpNan = NodeSetExporter.AttributeDump.FromDataValue(new DataValue(new Variant(double.NaN)));
        var dumpInf = NodeSetExporter.AttributeDump.FromDataValue(new DataValue(new Variant(double.PositiveInfinity)));
        var dumpNegInf = NodeSetExporter.AttributeDump.FromDataValue(new DataValue(new Variant(double.NegativeInfinity)));
        var dumpArr = NodeSetExporter.AttributeDump.FromDataValue(
            new DataValue(new Variant(new[] { 1.0, double.NaN, double.PositiveInfinity })));

        var payload = new
        {
            Items = new[] { dumpNan, dumpInf, dumpNegInf, dumpArr },
        };

        await using var stream = new MemoryStream();
        await System.Text.Json.JsonSerializer.SerializeAsync(
            stream, payload, NodeSetExporter.SidecarJsonOptions);

        var json = System.Text.Encoding.UTF8.GetString(stream.ToArray());
        Assert.Contains("\"NaN\"", json);
        Assert.Contains("\"Infinity\"", json);
        Assert.Contains("\"-Infinity\"", json);
    }
}
