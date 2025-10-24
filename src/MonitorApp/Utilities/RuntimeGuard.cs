using System;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Net.Http;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace MonitorApp.Utilities;

internal static class RuntimeGuard
{
    private static readonly Version RequiredRuntimeVersion = new(9, 0, 0);
    private static int _initialized;

    public static async Task EnsureDotnetRuntimeAsync(CancellationToken cancellationToken = default)
    {
        if (Interlocked.Exchange(ref _initialized, 1) == 1)
        {
            return;
        }

        if (IsRuntimeSatisfied())
        {
            return;
        }

        WindowsEventLogger.LogInformation("未检测到所需的 .NET 9 运行时组件，正在尝试自动安装...");

        try
        {
            await InstallRuntimeAsync(RequiredRuntimeVersion, cancellationToken);

            if (!IsRuntimeSatisfied())
            {
                WindowsEventLogger.LogWarning("自动安装完成，但当前进程仍无法加载 .NET 9 运行时组件。请尝试重新启动应用程序。");
            }
        }
        catch (Exception ex)
        {
            WindowsEventLogger.LogError("自动安装 .NET 运行时失败", ex);
            WindowsEventLogger.LogError("请手动安装 .NET 9 运行时后重新启动应用。下载地址: https://dotnet.microsoft.com/zh-cn/download/dotnet/9.0");
        }
    }

    private static bool IsRuntimeSatisfied()
    {
        try
        {
            var assembly = Assembly.Load("System.Threading.AccessControl");
            var version = assembly.GetName().Version;
            return version is not null && version >= RequiredRuntimeVersion;
        }
        catch (Exception)
        {
            return false;
        }
    }

    private static async Task InstallRuntimeAsync(Version version, CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindows() && !OperatingSystem.IsLinux() && !OperatingSystem.IsMacOS())
        {
            throw new PlatformNotSupportedException("自动安装仅支持 Windows、Linux 或 macOS。");
        }

        var installDir = ResolveInstallDirectory();
        Directory.CreateDirectory(installDir);
        AppendInstallDirToPath(installDir);

        var tempDirectory = Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), $"dotnet-install-{Guid.NewGuid():N}"));

        try
        {
            if (OperatingSystem.IsWindows())
            {
                var scriptPath = Path.Combine(tempDirectory.FullName, "dotnet-install.ps1");
                await DownloadFileAsync("https://dot.net/v1/dotnet-install.ps1", scriptPath, cancellationToken);

                var shell = FindWindowsShell();
                var psi = new ProcessStartInfo(shell)
                {
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true,
                };

                psi.ArgumentList.Add("-NoLogo");
                psi.ArgumentList.Add("-NonInteractive");
                psi.ArgumentList.Add("-ExecutionPolicy");
                psi.ArgumentList.Add("Bypass");
                psi.ArgumentList.Add("-File");
                psi.ArgumentList.Add(scriptPath);
                psi.ArgumentList.Add("-Runtime");
                psi.ArgumentList.Add("dotnet");
                psi.ArgumentList.Add("-Version");
                psi.ArgumentList.Add(version.ToString());
                psi.ArgumentList.Add("-InstallDir");
                psi.ArgumentList.Add(installDir);

                await RunProcessAsync(psi, cancellationToken);
            }
            else
            {
                var scriptPath = Path.Combine(tempDirectory.FullName, "dotnet-install.sh");
                await DownloadFileAsync("https://dot.net/v1/dotnet-install.sh", scriptPath, cancellationToken);
                MakeExecutable(scriptPath);

                var psi = new ProcessStartInfo("bash")
                {
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true,
                };

                psi.ArgumentList.Add(scriptPath);
                psi.ArgumentList.Add("--runtime");
                psi.ArgumentList.Add("dotnet");
                psi.ArgumentList.Add("--version");
                psi.ArgumentList.Add(version.ToString());
                psi.ArgumentList.Add("--install-dir");
                psi.ArgumentList.Add(installDir);

                await RunProcessAsync(psi, cancellationToken);
            }

            WindowsEventLogger.LogInformation($".NET 9 runtime 已安装到: {installDir}");
        }
        finally
        {
            try
            {
                tempDirectory.Delete(recursive: true);
            }
            catch
            {
                // ignore
            }
        }
    }

    private static string ResolveInstallDirectory()
    {
        if (OperatingSystem.IsWindows())
        {
            var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            return Path.Combine(localAppData, "Microsoft", "dotnet");
        }

        var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        return Path.Combine(home, ".dotnet");
    }

    private static void AppendInstallDirToPath(string installDir)
    {
        var pathVar = Environment.GetEnvironmentVariable("PATH") ?? string.Empty;
        if (!pathVar.Contains(installDir, StringComparison.OrdinalIgnoreCase))
        {
            var newPath = installDir + Path.PathSeparator + pathVar;
            Environment.SetEnvironmentVariable("PATH", newPath);
        }
    }

    private static async Task DownloadFileAsync(string url, string destinationPath, CancellationToken cancellationToken)
    {
        using var http = new HttpClient();
        await using var stream = await http.GetStreamAsync(url, cancellationToken);
        await using var fileStream = File.Create(destinationPath);
        await stream.CopyToAsync(fileStream, cancellationToken);
    }

    private static void MakeExecutable(string filePath)
    {
        if (!OperatingSystem.IsWindows())
        {
            using var process = Process.Start(new ProcessStartInfo("chmod")
            {
                ArgumentList = { "+x", filePath },
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            });
            process?.WaitForExit();
        }
    }

    private static string FindWindowsShell()
    {
        var pwsh = ResolveCommandFullPath("pwsh.exe");
        if (!string.IsNullOrEmpty(pwsh))
        {
            return pwsh;
        }

        var powershell = ResolveCommandFullPath("powershell.exe");
        if (!string.IsNullOrEmpty(powershell))
        {
            return powershell;
        }

        throw new InvalidOperationException("未找到 PowerShell，可执行自动安装需要 PowerShell 支持。");
    }

    private static string? ResolveCommandFullPath(string command)
    {
        try
        {
            var path = Environment.GetEnvironmentVariable("PATH") ?? string.Empty;
            foreach (var segment in path.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
            {
                var candidate = Path.Combine(segment, command);
                if (File.Exists(candidate))
                {
                    return candidate;
                }
            }
        }
        catch
        {
            // ignore
        }

        return null;
    }

    private static async Task RunProcessAsync(ProcessStartInfo psi, CancellationToken cancellationToken)
    {
        using var process = new Process { StartInfo = psi };
        var outputBuilder = new StringBuilder();
        var errorBuilder = new StringBuilder();

        process.OutputDataReceived += (_, e) =>
        {
            if (e.Data is not null)
            {
                lock (outputBuilder)
                {
                    outputBuilder.AppendLine(e.Data);
                }
            }
        };

        process.ErrorDataReceived += (_, e) =>
        {
            if (e.Data is not null)
            {
                lock (errorBuilder)
                {
                    errorBuilder.AppendLine(e.Data);
                }
            }
        };

        if (!process.Start())
        {
            throw new InvalidOperationException("无法启动 dotnet 安装进程。");
        }

        process.BeginOutputReadLine();
        process.BeginErrorReadLine();

        await process.WaitForExitAsync(cancellationToken);

        var output = outputBuilder.ToString().Trim();
        if (!string.IsNullOrEmpty(output))
        {
            WindowsEventLogger.LogInformation(TruncateForEventLog($"dotnet-install 输出:{Environment.NewLine}{output}"));
        }

        if (process.ExitCode != 0)
        {
            throw new InvalidOperationException($"dotnet-install 退出代码: {process.ExitCode}{Environment.NewLine}{errorBuilder}");
        }
    }

    private static string TruncateForEventLog(string message)
    {
        const int maxLength = 8000;
        return message.Length <= maxLength ? message : message[..maxLength];
    }
}
