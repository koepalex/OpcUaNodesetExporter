using OpcUaNodesetExporter.OpcUa;
using Opc.Ua;

namespace OpcUaNodesetExporter.Tests;

public class OpcUaClientOptionsTests
{
    [Fact]
    public void DefaultValues_AreSetCorrectly()
    {
        // Arrange & Act
        var options = new OpcUaClientOptions
        {
            Endpoint = "opc.tcp://localhost:4840"
        };

        // Assert
        Assert.Equal("opc.tcp://localhost:4840", options.Endpoint);
        Assert.Equal(MessageSecurityMode.None, options.SecurityMode);
        Assert.Equal(SecurityPolicies.None, options.SecurityPolicy);
        Assert.Equal(AuthenticationMode.Anonymous, options.AuthMode);
        Assert.Null(options.Username);
        Assert.Null(options.Password);
        Assert.Equal("./output", options.OutputDirectory);
        Assert.False(options.Verbose);
        Assert.Equal(3, options.RetryCount);
        Assert.Equal(5, options.RetryDelaySeconds);
        Assert.Equal(5, options.KeepAliveIntervalSeconds);
        Assert.Equal(120, options.SessionTimeoutSeconds);
        Assert.Equal(3, options.KeepAliveFailureThreshold);
        Assert.Equal("OpcUaNodesetExporter", options.ApplicationName);
    }

    [Fact]
    public void ApplicationUri_ContainsMachineName()
    {
        // Arrange
        var options = new OpcUaClientOptions
        {
            Endpoint = "opc.tcp://localhost:4840",
            ApplicationName = "TestApp"
        };

        // Act
        var uri = options.ApplicationUri;

        // Assert
        Assert.Contains(Environment.MachineName, uri);
        Assert.Contains("TestApp", uri);
        Assert.StartsWith("urn:", uri);
    }

    [Fact]
    public void SecurityMode_CanBeSet()
    {
        // Arrange & Act
        var options = new OpcUaClientOptions
        {
            Endpoint = "opc.tcp://localhost:4840",
            SecurityMode = MessageSecurityMode.SignAndEncrypt
        };

        // Assert
        Assert.Equal(MessageSecurityMode.SignAndEncrypt, options.SecurityMode);
    }

    [Fact]
    public void AuthMode_CanBeSetToUserName()
    {
        // Arrange & Act
        var options = new OpcUaClientOptions
        {
            Endpoint = "opc.tcp://localhost:4840",
            AuthMode = AuthenticationMode.UserName,
            Username = "admin",
            Password = "secret"
        };

        // Assert
        Assert.Equal(AuthenticationMode.UserName, options.AuthMode);
        Assert.Equal("admin", options.Username);
        Assert.Equal("secret", options.Password);
    }

    [Fact]
    public void KeepAliveSettings_CanBeConfigured()
    {
        // Arrange & Act
        var options = new OpcUaClientOptions
        {
            Endpoint = "opc.tcp://localhost:4840",
            KeepAliveIntervalSeconds = 10,
            SessionTimeoutSeconds = 300,
            KeepAliveFailureThreshold = 5
        };

        // Assert
        Assert.Equal(10, options.KeepAliveIntervalSeconds);
        Assert.Equal(300, options.SessionTimeoutSeconds);
        Assert.Equal(5, options.KeepAliveFailureThreshold);
    }

    [Theory]
    [InlineData(1, 60, 1)]
    [InlineData(30, 600, 10)]
    [InlineData(5, 120, 3)]
    public void KeepAliveSettings_AcceptVariousValues(int keepAliveInterval, int sessionTimeout, int failureThreshold)
    {
        // Arrange & Act
        var options = new OpcUaClientOptions
        {
            Endpoint = "opc.tcp://localhost:4840",
            KeepAliveIntervalSeconds = keepAliveInterval,
            SessionTimeoutSeconds = sessionTimeout,
            KeepAliveFailureThreshold = failureThreshold
        };

        // Assert
        Assert.Equal(keepAliveInterval, options.KeepAliveIntervalSeconds);
        Assert.Equal(sessionTimeout, options.SessionTimeoutSeconds);
        Assert.Equal(failureThreshold, options.KeepAliveFailureThreshold);
    }
}
