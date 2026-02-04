using Microsoft.Extensions.Logging;
using Opc.Ua;
using Opc.Ua.Client;

namespace OpcUaNodesetExporter.OpcUa;

/// <summary>
/// Wrapper for an OPC UA session that provides reconnection capabilities.
/// </summary>
public class OpcUaClient : IDisposable, IAsyncDisposable
{
    private readonly ILoggerFactory _loggerFactory;
    private readonly ILogger<OpcUaClient> _logger;
    private readonly ApplicationConfiguration _configuration;
    private readonly int _retryCount;
    private readonly TimeSpan _retryDelay;
    private ISession _session;
    private bool _disposed;

    internal OpcUaClient(
        ISession session,
        ApplicationConfiguration configuration,
        ILoggerFactory loggerFactory,
        int retryCount,
        TimeSpan retryDelay)
    {
        _session = session ?? throw new ArgumentNullException(nameof(session));
        _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
        _loggerFactory = loggerFactory ?? throw new ArgumentNullException(nameof(loggerFactory));
        _logger = loggerFactory.CreateLogger<OpcUaClient>();
        _retryCount = retryCount;
        _retryDelay = retryDelay;

        // Setup keep-alive handler for reconnection
        _session.KeepAlive += OnKeepAlive;
    }

    /// <summary>
    /// Gets the underlying OPC UA session.
    /// </summary>
    public ISession Session => _session;

    /// <summary>
    /// Gets whether the session is currently connected.
    /// </summary>
    public bool IsConnected => _session?.Connected ?? false;

    /// <summary>
    /// Event raised when the session is reconnected.
    /// </summary>
    public event EventHandler? Reconnected;

    /// <summary>
    /// Executes an operation with automatic reconnection on transient failures.
    /// </summary>
    /// <typeparam name="T">The return type of the operation.</typeparam>
    /// <param name="operation">The operation to execute.</param>
    /// <param name="operationName">Name of the operation for logging.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The result of the operation.</returns>
    public async Task<T> ExecuteWithRetryAsync<T>(
        Func<ISession, CancellationToken, Task<T>> operation,
        string operationName,
        CancellationToken cancellationToken = default)
    {
        Exception? lastException = null;

        for (int attempt = 0; attempt <= _retryCount; attempt++)
        {
            try
            {
                if (!_session.Connected)
                {
                    _logger.LogWarning("Session disconnected before {Operation}, attempting reconnect...", operationName);
                    await ReconnectAsync(cancellationToken).ConfigureAwait(false);
                }

                return await operation(_session, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex) when (IsTransientError(ex))
            {
                lastException = ex;
                _logger.LogWarning(ex, "{Operation} failed with transient error on attempt {Attempt}/{Total}",
                    operationName, attempt + 1, _retryCount + 1);

                if (attempt < _retryCount)
                {
                    var delay = TimeSpan.FromSeconds(_retryDelay.TotalSeconds * Math.Pow(2, attempt));
                    _logger.LogInformation("Waiting {Delay}s before retry...", delay.TotalSeconds);
                    await Task.Delay(delay, cancellationToken).ConfigureAwait(false);

                    // Try to reconnect before next attempt
                    await TryReconnectAsync(cancellationToken).ConfigureAwait(false);
                }
            }
        }

        throw new OpcUaConnectionException(
            $"Operation '{operationName}' failed after {_retryCount + 1} attempts.",
            lastException);
    }

    /// <summary>
    /// Executes an operation with automatic reconnection on transient failures.
    /// </summary>
    /// <param name="operation">The operation to execute.</param>
    /// <param name="operationName">Name of the operation for logging.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public async Task ExecuteWithRetryAsync(
        Func<ISession, CancellationToken, Task> operation,
        string operationName,
        CancellationToken cancellationToken = default)
    {
        await ExecuteWithRetryAsync(async (session, ct) =>
        {
            await operation(session, ct).ConfigureAwait(false);
            return true;
        }, operationName, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Attempts to reconnect the session.
    /// </summary>
    private async Task ReconnectAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("Reconnecting to OPC UA server...");

        try
        {
            if (_session.Connected)
            {
                _logger.LogDebug("Session still connected, no reconnect needed.");
                return;
            }

            // Try to reconnect the existing session
            await _session.ReconnectAsync(cancellationToken).ConfigureAwait(false);

            _logger.LogInformation("Reconnected successfully. Session ID: {SessionId}", _session.SessionId);
            Reconnected?.Invoke(this, EventArgs.Empty);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to reconnect session");
            throw;
        }
    }

    /// <summary>
    /// Attempts to reconnect, suppressing errors.
    /// </summary>
    private async Task TryReconnectAsync(CancellationToken cancellationToken)
    {
        try
        {
            await ReconnectAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Reconnection attempt failed, will retry on next operation");
        }
    }

    private void OnKeepAlive(ISession session, KeepAliveEventArgs e)
    {
        if (e.Status != null && ServiceResult.IsNotGood(e.Status))
        {
            _logger.LogWarning("Keep-alive error: {Status}", e.Status);

            if (!session.Connected)
            {
                _logger.LogWarning("Session disconnected, will attempt reconnect on next operation.");
            }
        }
    }

    private static bool IsTransientError(Exception ex)
    {
        if (ex is ServiceResultException sre)
        {
            var code = sre.StatusCode;
            return code == StatusCodes.BadServerNotConnected ||
                   code == StatusCodes.BadConnectionClosed ||
                   code == StatusCodes.BadCommunicationError ||
                   code == StatusCodes.BadTimeout ||
                   code == StatusCodes.BadRequestTimeout ||
                   code == StatusCodes.BadSecureChannelClosed ||
                   code == StatusCodes.BadTcpServerTooBusy ||
                   code == StatusCodes.BadSessionIdInvalid ||
                   code == StatusCodes.BadSessionClosed;
        }

        return ex is TimeoutException ||
               ex is System.Net.Sockets.SocketException ||
               ex is System.IO.IOException;
    }

    /// <summary>
    /// Closes the session and releases resources.
    /// </summary>
    public async Task CloseAsync(CancellationToken cancellationToken = default)
    {
        if (_session?.Connected == true)
        {
            _logger.LogInformation("Closing OPC UA session...");
            await _session.CloseAsync(cancellationToken).ConfigureAwait(false);
            _logger.LogInformation("Session closed.");
        }
    }

    /// <summary>
    /// Asynchronously disposes the client and closes the session.
    /// </summary>
    public async ValueTask DisposeAsync()
    {
        if (_disposed) return;
        _disposed = true;

        _session.KeepAlive -= OnKeepAlive;

        if (_session?.Connected == true)
        {
            try
            {
                await _session.CloseAsync().ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error closing session during async dispose");
            }
        }

        _session?.Dispose();

        GC.SuppressFinalize(this);
    }

    /// <summary>
    /// Disposes the client and closes the session.
    /// </summary>
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        _session.KeepAlive -= OnKeepAlive;

        if (_session?.Connected == true)
        {
            try
            {
#pragma warning disable CS0618 // Use CloseAsync instead
                _session.Close();
#pragma warning restore CS0618
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error closing session during dispose");
            }
        }

        _session?.Dispose();

        GC.SuppressFinalize(this);
    }
}
