using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Xml.Linq;

namespace MonitorApp.Utilities;

internal static class WindowsStartupManager
{
    private const string TaskName = "MonitorApp_AutoStart";

    public static bool IsSupported => OperatingSystem.IsWindows();

    public static bool IsEnabled()
    {
        if (!IsSupported)
        {
            return false;
        }

        var (exitCode, standardOutput, _) = RunSchtasks("/Query", "/TN", TaskName, "/XML");
        if (exitCode != 0 || string.IsNullOrWhiteSpace(standardOutput))
        {
            return false;
        }

        try
        {
            var document = XDocument.Parse(standardOutput);
            var ns = document.Root?.Name.Namespace;
            if (ns is null)
            {
                return false;
            }

            var commandElement = document
                .Descendants(ns + "Exec")
                .Select(exec => exec.Element(ns + "Command"))
                .FirstOrDefault(element => element is not null);

            if (commandElement is null)
            {
                return false;
            }

            return string.Equals(
                NormalizePath(commandElement.Value),
                NormalizePath(GetExecutablePath()),
                StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    public static void Enable()
    {
        if (!IsSupported)
        {
            throw new PlatformNotSupportedException("开机自启动仅支持在 Windows 平台上启用。");
        }

        var (exitCode, _, errorOutput) = RunSchtasks(
            "/Create",
            "/F",
            "/SC", "ONLOGON",
            "/RL", "HIGHEST",
            "/TN", TaskName,
            "/TR", QuoteIfNeeded(GetExecutablePath()));

        if (exitCode != 0)
        {
            throw new InvalidOperationException($"无法创建开机自启动任务：{errorOutput.Trim()}".Trim());
        }
    }

    public static void Disable()
    {
        if (!IsSupported)
        {
            return;
        }

        RunSchtasks("/Delete", "/TN", TaskName, "/F");
    }

    private static string GetExecutablePath()
    {
        var processPath = Environment.ProcessPath;
        if (string.IsNullOrWhiteSpace(processPath))
        {
            throw new InvalidOperationException("无法识别当前进程路径。");
        }

        return processPath;
    }

    private static string QuoteIfNeeded(string path)
        => path.Contains(' ', StringComparison.Ordinal) ? $"\"{path}\"" : path;

    private static string NormalizePath(string path)
        => Path.GetFullPath(path.Trim().Trim('"'));

    private static (int ExitCode, string StandardOutput, string StandardError) RunSchtasks(params string[] arguments)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = "schtasks",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        foreach (var argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        using var process = Process.Start(startInfo)
            ?? throw new InvalidOperationException("无法调用 schtasks.exe。");

        var standardOutput = process.StandardOutput.ReadToEnd();
        var standardError = process.StandardError.ReadToEnd();
        process.WaitForExit();

        return (process.ExitCode, standardOutput, standardError);
    }
}
