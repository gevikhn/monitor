using System;
using Microsoft.Win32;

namespace MonitorApp.Utilities;

internal static class WindowsStartupManager
{
    private const string RunRegistryPath = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private const string ValueName = "MonitorApp";

    public static bool IsSupported => OperatingSystem.IsWindows();

    public static bool IsEnabled()
    {
        if (!IsSupported)
        {
            return false;
        }

        using var key = OpenRunRegistryKey(writable: false);
        if (key is null)
        {
            return false;
        }

        var configuredValue = key.GetValue(ValueName) as string;
        if (string.IsNullOrWhiteSpace(configuredValue))
        {
            return false;
        }

        return string.Equals(Normalize(configuredValue), Normalize(GetExecutableCommand()), StringComparison.OrdinalIgnoreCase);
    }

    public static void Enable()
    {
        if (!IsSupported)
        {
            throw new PlatformNotSupportedException("开机自启动仅支持在 Windows 平台上启用。");
        }

        using var key = CreateRunRegistryKey()
                       ?? throw new InvalidOperationException("无法访问注册表 Run 节点。");

        key.SetValue(ValueName, GetExecutableCommand());
    }

    public static void Disable()
    {
        if (!IsSupported)
        {
            return;
        }

        using var key = OpenRunRegistryKey(writable: true);
        key?.DeleteValue(ValueName, throwOnMissingValue: false);
    }

    private static string GetExecutableCommand()
    {
        var processPath = Environment.ProcessPath;
        if (string.IsNullOrWhiteSpace(processPath))
        {
            throw new InvalidOperationException("无法识别当前进程路径。");
        }

        return QuoteIfNeeded(processPath);
    }

    private static string QuoteIfNeeded(string path)
        => path.Contains(' ', StringComparison.Ordinal) ? $"\"{path}\"" : path;

    private static string Normalize(string command)
    {
        var trimmed = command.Trim();
        if (trimmed.Length >= 2 && trimmed[0] == '"' && trimmed[^1] == '"')
        {
            trimmed = trimmed[1..^1];
        }

        return trimmed;
    }

    private static RegistryKey? OpenRunRegistryKey(bool writable)
    {
        var view = Environment.Is64BitOperatingSystem ? RegistryView.Registry64 : RegistryView.Registry32;
        using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view);
        return baseKey.OpenSubKey(RunRegistryPath, writable);
    }

    private static RegistryKey? CreateRunRegistryKey()
    {
        var view = Environment.Is64BitOperatingSystem ? RegistryView.Registry64 : RegistryView.Registry32;
        using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view);
        return baseKey.CreateSubKey(RunRegistryPath, writable: true);
    }
}
