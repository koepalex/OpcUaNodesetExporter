using OpcUaNodesetExporter.OpcUa;

namespace OpcUaNodesetExporter.Tests;

public class OpcUaClientBuilderTests
{
    [Fact]
    public void GetEffectiveSessionEndpointUrl_RewritesAuthority_WhenServerAdvertisesInternalEndpoint()
    {
        var requestedEndpoint = new Uri("opc.tcp://localhost:50001");
        const string discoveredEndpoint = "opc.tcp://opcplc:50000/UA/PLC";

        var effectiveEndpoint = OpcUaClientBuilder.GetEffectiveSessionEndpointUrl(requestedEndpoint, discoveredEndpoint);

        Assert.Equal("opc.tcp://localhost:50001/UA/PLC", effectiveEndpoint);
    }

    [Fact]
    public void GetEffectiveSessionEndpointUrl_PreservesDiscoveredPath_WhenAuthorityAlreadyMatches()
    {
        var requestedEndpoint = new Uri("opc.tcp://localhost:50000");
        const string discoveredEndpoint = "opc.tcp://localhost:50000/UA/Server";

        var effectiveEndpoint = OpcUaClientBuilder.GetEffectiveSessionEndpointUrl(requestedEndpoint, discoveredEndpoint);

        Assert.Equal(discoveredEndpoint, effectiveEndpoint);
    }

    [Fact]
    public void GetEffectiveSessionEndpointUrl_PrefersRequestedPath_WhenCallerSuppliesOne()
    {
        var requestedEndpoint = new Uri("opc.tcp://localhost:50001/custom/path");
        const string discoveredEndpoint = "opc.tcp://opcplc:50000/UA/PLC";

        var effectiveEndpoint = OpcUaClientBuilder.GetEffectiveSessionEndpointUrl(requestedEndpoint, discoveredEndpoint);

        Assert.Equal("opc.tcp://localhost:50001/custom/path", effectiveEndpoint);
    }
}
