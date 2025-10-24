using System;
using System.Diagnostics;
using System.Threading;

namespace MonitorApp.Utilities;

internal static class WindowsEventLogger
{
    private const string SourceName = "MonitorApp";
    private const string LogName = "Application";

    private static int _initialized;

    public static void EnsureSource()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        if (Interlocked.Exchange(ref _initialized, 1) == 1)
        {
            return;
        }

        try
        {
            if (!EventLog.SourceExists(SourceName))
            {
                var data = new EventSourceCreationData(SourceName, LogName);
                EventLog.CreateEventSource(data);
            }
        }
        catch (Exception ex)
        {
            Trace.WriteLine($"Failed to ensure EventLog source: {ex}");
        }
    }

    public static void LogInformation(string message) => Write(EventLogEntryType.Information, message);

    public static void LogWarning(string message) => Write(EventLogEntryType.Warning, message);

    public static void LogError(string message) => Write(EventLogEntryType.Error, message);

    public static void LogError(string message, Exception exception)
    {
        var details = $"{message}{Environment.NewLine}{exception}";
        Write(EventLogEntryType.Error, details);
    }

    private static void Write(EventLogEntryType type, string message)
    {
        if (string.IsNullOrWhiteSpace(message))
        {
            return;
        }

        if (!OperatingSystem.IsWindows())
        {
            Trace.WriteLine($"[{type}] {message}");
            return;
        }

        EnsureSource();

        try
        {
            EventLog.WriteEntry(SourceName, message, type);
        }
        catch (Exception ex)
        {
            Trace.WriteLine($"[{type}] {message}");
            Trace.WriteLine($"EventLog write failed: {ex}");
        }
    }
}
