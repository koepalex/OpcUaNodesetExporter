using System.Globalization;
using System.Text;
using Microsoft.Extensions.Logging;

namespace OpcUaNodesetExporter.Logging;

/// <summary>
/// Minimal file <see cref="ILoggerProvider"/>. Writes every log entry from
/// every category as a single, timestamped, plain-text line. Intended for
/// diagnostic capture of verbose runs (e.g. <c>--log-file diag.log</c>) without
/// pulling in a third-party logging package.
/// </summary>
/// <remarks>
/// <para>Thread-safe: a single <see cref="object"/> gate serialises writes to
/// the underlying <see cref="StreamWriter"/>.</para>
/// <para>The provider honours its own <see cref="LogLevel"/> filter so the file
/// can capture <c>Debug</c>/<c>Trace</c> even when the console provider is
/// configured at <c>Information</c>, and vice versa.</para>
/// </remarks>
public sealed class FileLoggerProvider : ILoggerProvider
{
    private readonly StreamWriter _writer;
    private readonly object _gate = new();
    private readonly LogLevel _minLevel;
    private bool _disposed;

    /// <summary>
    /// Creates a new <see cref="FileLoggerProvider"/> that appends to (or
    /// creates) the given <paramref name="path"/>. Parent directories are
    /// created on demand.
    /// </summary>
    /// <param name="path">Target log file path (relative or absolute).</param>
    /// <param name="minLevel">Minimum level a log entry must meet to be written.</param>
    /// <param name="append">When <c>true</c>, append to an existing file; otherwise overwrite.</param>
    public FileLoggerProvider(string path, LogLevel minLevel = LogLevel.Trace, bool append = true)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            throw new ArgumentException("Log file path must not be empty.", nameof(path));
        }

        var fullPath = Path.GetFullPath(path);
        var directory = Path.GetDirectoryName(fullPath);
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        var stream = new FileStream(
            fullPath,
            append ? FileMode.Append : FileMode.Create,
            FileAccess.Write,
            FileShare.Read);

        _writer = new StreamWriter(stream, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false))
        {
            AutoFlush = true,
        };
        _minLevel = minLevel;
        FilePath = fullPath;
    }

    /// <summary>Gets the absolute path the provider is writing to.</summary>
    public string FilePath { get; }

    /// <inheritdoc />
    public ILogger CreateLogger(string categoryName) =>
        new FileLogger(categoryName, _writer, _gate, _minLevel);

    /// <inheritdoc />
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        lock (_gate)
        {
            _writer.Flush();
            _writer.Dispose();
        }
    }

    private sealed class FileLogger : ILogger
    {
        private readonly string _category;
        private readonly StreamWriter _writer;
        private readonly object _gate;
        private readonly LogLevel _minLevel;

        public FileLogger(string category, StreamWriter writer, object gate, LogLevel minLevel)
        {
            _category = category;
            _writer = writer;
            _gate = gate;
            _minLevel = minLevel;
        }

        public IDisposable BeginScope<TState>(TState state) where TState : notnull => NullScope.Instance;

        public bool IsEnabled(LogLevel logLevel) =>
            logLevel != LogLevel.None && logLevel >= _minLevel;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            if (!IsEnabled(logLevel))
            {
                return;
            }

            var message = formatter(state, exception);
            if (string.IsNullOrEmpty(message) && exception is null)
            {
                return;
            }

            var line = string.Create(CultureInfo.InvariantCulture,
                $"{DateTime.UtcNow:O} [{LevelToken(logLevel)}] {_category}: {message}");

            lock (_gate)
            {
                _writer.WriteLine(line);
                if (exception is not null)
                {
                    _writer.WriteLine(exception);
                }
            }
        }

        private static string LevelToken(LogLevel level) => level switch
        {
            LogLevel.Trace => "TRC",
            LogLevel.Debug => "DBG",
            LogLevel.Information => "INF",
            LogLevel.Warning => "WRN",
            LogLevel.Error => "ERR",
            LogLevel.Critical => "CRT",
            _ => "LOG",
        };

        private sealed class NullScope : IDisposable
        {
            public static readonly NullScope Instance = new();
            public void Dispose() { }
        }
    }
}
