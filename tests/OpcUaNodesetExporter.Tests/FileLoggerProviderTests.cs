using Microsoft.Extensions.Logging;
using OpcUaNodesetExporter.Logging;

namespace OpcUaNodesetExporter.Tests;

public class FileLoggerProviderTests
{
    [Fact]
    public void Logs_AreWrittenToFile_WithLevelAndCategoryTokens()
    {
        var path = Path.Combine(Path.GetTempPath(),
            "opcua-flp-" + Guid.NewGuid().ToString("N") + ".log");
        try
        {
            using (var provider = new FileLoggerProvider(path, LogLevel.Debug, append: false))
            {
                var logger = provider.CreateLogger("UnitTest");
                logger.LogDebug("debug-line");
                logger.LogInformation("info-line {Num}", 42);
                logger.LogWarning("warn-line");
            }

            Assert.True(File.Exists(path));
            var contents = File.ReadAllText(path);
            Assert.Contains("[DBG] UnitTest: debug-line", contents);
            Assert.Contains("[INF] UnitTest: info-line 42", contents);
            Assert.Contains("[WRN] UnitTest: warn-line", contents);
        }
        finally
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
    }

    [Fact]
    public void EntriesBelowMinLevel_AreFiltered()
    {
        var path = Path.Combine(Path.GetTempPath(),
            "opcua-flp-" + Guid.NewGuid().ToString("N") + ".log");
        try
        {
            using (var provider = new FileLoggerProvider(path, LogLevel.Warning, append: false))
            {
                var logger = provider.CreateLogger("UnitTest");
                logger.LogInformation("should-not-appear");
                logger.LogDebug("also-not-here");
                logger.LogWarning("kept");
                logger.LogError("also-kept");
            }

            var contents = File.ReadAllText(path);
            Assert.DoesNotContain("should-not-appear", contents);
            Assert.DoesNotContain("also-not-here", contents);
            Assert.Contains("kept", contents);
            Assert.Contains("also-kept", contents);
        }
        finally
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
    }

    [Fact]
    public void ParentDirectory_IsCreatedOnDemand()
    {
        var dir = Path.Combine(Path.GetTempPath(),
            "opcua-flp-" + Guid.NewGuid().ToString("N"), "nested", "subdir");
        var path = Path.Combine(dir, "log.txt");
        try
        {
            using (var provider = new FileLoggerProvider(path, LogLevel.Trace, append: false))
            {
                provider.CreateLogger("Cat").LogInformation("hi");
            }

            Assert.True(File.Exists(path));
            Assert.Contains("hi", File.ReadAllText(path));
        }
        finally
        {
            if (Directory.Exists(dir))
            {
                Directory.Delete(dir, recursive: true);
            }
        }
    }

    [Fact]
    public void Append_PreservesExistingContents()
    {
        var path = Path.Combine(Path.GetTempPath(),
            "opcua-flp-" + Guid.NewGuid().ToString("N") + ".log");
        try
        {
            File.WriteAllText(path, "previous-content\n");

            using (var provider = new FileLoggerProvider(path, LogLevel.Trace, append: true))
            {
                provider.CreateLogger("Cat").LogInformation("new-entry");
            }

            var contents = File.ReadAllText(path);
            Assert.Contains("previous-content", contents);
            Assert.Contains("new-entry", contents);
        }
        finally
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
    }

    [Fact]
    public void Exceptions_AreSerialised_AfterMessage()
    {
        var path = Path.Combine(Path.GetTempPath(),
            "opcua-flp-" + Guid.NewGuid().ToString("N") + ".log");
        try
        {
            using (var provider = new FileLoggerProvider(path, LogLevel.Trace, append: false))
            {
                var logger = provider.CreateLogger("Cat");
                logger.LogError(new InvalidOperationException("boom"), "operation failed");
            }

            var contents = File.ReadAllText(path);
            Assert.Contains("operation failed", contents);
            Assert.Contains("InvalidOperationException", contents);
            Assert.Contains("boom", contents);
        }
        finally
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
    }

    [Fact]
    public void EmptyPath_Throws()
    {
        Assert.Throws<ArgumentException>(() =>
            new FileLoggerProvider("", LogLevel.Trace));
    }
}
