namespace OpcUaNodesetExporter.Configuration;

/// <summary>
/// Defines environment variable names that can be used to configure the tool.
/// </summary>
public static class EnvironmentVariables
{
    /// <summary>
    /// Environment variable for the OPC UA server endpoint URL.
    /// </summary>
    public const string Endpoint = "OPCUA_ENDPOINT";

    /// <summary>
    /// Environment variable for the username (UserName authentication).
    /// </summary>
    public const string Username = "OPCUA_USERNAME";

    /// <summary>
    /// Environment variable for the password (UserName authentication).
    /// </summary>
    public const string Password = "OPCUA_PASSWORD";

    /// <summary>
    /// Environment variable for the path to the client certificate.
    /// </summary>
    public const string CertificatePath = "OPCUA_CERTIFICATE_PATH";

    /// <summary>
    /// Environment variable for the client certificate password.
    /// </summary>
    public const string CertificatePassword = "OPCUA_CERTIFICATE_PASSWORD";

    /// <summary>
    /// Gets the value of an environment variable, returning null if not set or empty.
    /// </summary>
    /// <param name="variableName">The name of the environment variable.</param>
    /// <returns>The value of the environment variable, or null if not set.</returns>
    public static string? GetValue(string variableName)
    {
        var value = Environment.GetEnvironmentVariable(variableName);
        return string.IsNullOrWhiteSpace(value) ? null : value;
    }

    /// <summary>
    /// Gets the value of an environment variable with a fallback default value.
    /// </summary>
    /// <param name="variableName">The name of the environment variable.</param>
    /// <param name="defaultValue">The default value to return if the variable is not set.</param>
    /// <returns>The value of the environment variable, or the default value.</returns>
    public static string GetValueOrDefault(string variableName, string defaultValue)
    {
        return GetValue(variableName) ?? defaultValue;
    }
}
