namespace OpcUaNodesetExporter.Configuration;

/// <summary>
/// Utility class for reading sensitive data from stdin.
/// </summary>
public static class StdinReader
{
    /// <summary>
    /// Reads a single line from stdin (for passwords).
    /// </summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The trimmed line read from stdin, or null if empty.</returns>
    public static async Task<string?> ReadLineAsync(CancellationToken cancellationToken = default)
    {
        using var reader = new StreamReader(Console.OpenStandardInput());
        var line = await reader.ReadLineAsync(cancellationToken).ConfigureAwait(false);
        return string.IsNullOrWhiteSpace(line) ? null : line.Trim();
    }

    /// <summary>
    /// Reads all content from stdin (for base64-encoded certificates).
    /// </summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The trimmed content read from stdin, or null if empty.</returns>
    public static async Task<string?> ReadAllAsync(CancellationToken cancellationToken = default)
    {
        using var reader = new StreamReader(Console.OpenStandardInput());
        var content = await reader.ReadToEndAsync(cancellationToken).ConfigureAwait(false);
        return string.IsNullOrWhiteSpace(content) ? null : content.Trim();
    }

    /// <summary>
    /// Reads a base64-encoded certificate from stdin and converts it to bytes.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The decoded certificate bytes, or null if stdin is empty.</returns>
    /// <exception cref="FormatException">Thrown if the input is not valid base64.</exception>
    public static async Task<byte[]?> ReadBase64CertificateAsync(CancellationToken cancellationToken = default)
    {
        var base64Content = await ReadAllAsync(cancellationToken).ConfigureAwait(false);
        if (base64Content == null)
        {
            return null;
        }

        try
        {
            return Convert.FromBase64String(base64Content);
        }
        catch (FormatException ex)
        {
            throw new FormatException("Invalid base64 content provided via stdin. Ensure the certificate is base64-encoded.", ex);
        }
    }
}
