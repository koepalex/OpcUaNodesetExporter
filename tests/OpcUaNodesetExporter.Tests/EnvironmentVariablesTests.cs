using OpcUaNodesetExporter.Configuration;

namespace OpcUaNodesetExporter.Tests;

public class EnvironmentVariablesTests
{
    [Fact]
    public void GetValue_ReturnsNull_WhenVariableNotSet()
    {
        // Arrange
        var variableName = "TEST_NONEXISTENT_VAR_" + Guid.NewGuid().ToString("N");

        // Act
        var result = EnvironmentVariables.GetValue(variableName);

        // Assert
        Assert.Null(result);
    }

    [Fact]
    public void GetValue_ReturnsValue_WhenVariableSet()
    {
        // Arrange
        var variableName = "TEST_VAR_" + Guid.NewGuid().ToString("N");
        var expectedValue = "test_value";
        Environment.SetEnvironmentVariable(variableName, expectedValue);

        try
        {
            // Act
            var result = EnvironmentVariables.GetValue(variableName);

            // Assert
            Assert.Equal(expectedValue, result);
        }
        finally
        {
            Environment.SetEnvironmentVariable(variableName, null);
        }
    }

    [Fact]
    public void GetValue_ReturnsNull_WhenVariableIsEmpty()
    {
        // Arrange
        var variableName = "TEST_EMPTY_VAR_" + Guid.NewGuid().ToString("N");
        Environment.SetEnvironmentVariable(variableName, "   ");

        try
        {
            // Act
            var result = EnvironmentVariables.GetValue(variableName);

            // Assert
            Assert.Null(result);
        }
        finally
        {
            Environment.SetEnvironmentVariable(variableName, null);
        }
    }

    [Fact]
    public void GetValueOrDefault_ReturnsDefault_WhenVariableNotSet()
    {
        // Arrange
        var variableName = "TEST_NONEXISTENT_VAR_" + Guid.NewGuid().ToString("N");
        var defaultValue = "default_value";

        // Act
        var result = EnvironmentVariables.GetValueOrDefault(variableName, defaultValue);

        // Assert
        Assert.Equal(defaultValue, result);
    }

    [Fact]
    public void GetValueOrDefault_ReturnsValue_WhenVariableSet()
    {
        // Arrange
        var variableName = "TEST_VAR_" + Guid.NewGuid().ToString("N");
        var expectedValue = "actual_value";
        var defaultValue = "default_value";
        Environment.SetEnvironmentVariable(variableName, expectedValue);

        try
        {
            // Act
            var result = EnvironmentVariables.GetValueOrDefault(variableName, defaultValue);

            // Assert
            Assert.Equal(expectedValue, result);
        }
        finally
        {
            Environment.SetEnvironmentVariable(variableName, null);
        }
    }
}
