using System;
using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using LibreHardwareMonitor.PawnIo;
using Microsoft.Extensions.Logging;

namespace MonitorApp.Utilities;

internal static class PawnIoInstaller
{
    private static readonly Uri InstallerUri = new("https://github.com/namazso/PawnIO.Setup/releases/latest/download/PawnIO_setup.exe");
    private static readonly string[] LocalInstallerCandidates =
    {
        Path.Combine(AppContext.BaseDirectory, "PawnIO_setup.exe"),
        Path.Combine(AppContext.BaseDirectory, "lib", "PawnIO_setup.exe")
    };

    public static async Task EnsureInstalledAsync(ILogger logger, CancellationToken cancellationToken = default)
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        if (PawnIo.IsInstalled)
        {
            logger.LogDebug("PawnIO 已安装，检测到版本 {Version}", PawnIo.Version);
            return;
        }

        logger.LogInformation("未检测到 PawnIO，准备自动安装。");

        string? installerPath = FindLocalInstaller(logger);
        var downloaded = false;

        if (string.IsNullOrEmpty(installerPath))
        {
            installerPath = await DownloadInstallerAsync(logger, cancellationToken);
            downloaded = true;
        }

        try
        {
            await RunInstallerAsync(installerPath, logger, cancellationToken);
        }
        finally
        {
            if (downloaded)
            {
                TryDeleteInstaller(installerPath, logger);
            }
        }

        if (!PawnIo.IsInstalled)
        {
            throw new InvalidOperationException("PawnIO 安装程序已执行，但仍未检测到安装成功。");
        }

        logger.LogInformation("PawnIO 安装完成，当前版本 {Version}", PawnIo.Version);
    }

    private static string? FindLocalInstaller(ILogger logger)
    {
        foreach (var candidate in LocalInstallerCandidates)
        {
            try
            {
                if (File.Exists(candidate))
                {
                    logger.LogDebug("使用本地 PawnIO 安装程序：{Path}", candidate);
                    return candidate;
                }
            }
            catch (Exception ex)
            {
                logger.LogDebug(ex, "检查本地 PawnIO 安装程序 {Path} 时出错。", candidate);
            }
        }

        return null;
    }

    private static async Task<string> DownloadInstallerAsync(ILogger logger, CancellationToken cancellationToken)
    {
        var tempFile = Path.Combine(Path.GetTempPath(), $"PawnIO_setup_{Guid.NewGuid():N}.exe");

        logger.LogInformation("正在下载 PawnIO 安装程序：{Uri}", InstallerUri);

        using var httpClient = new HttpClient();
        httpClient.DefaultRequestHeaders.UserAgent.ParseAdd("MonitorApp/1.0");
        using var response = await httpClient.GetAsync(InstallerUri, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        response.EnsureSuccessStatusCode();

        await using (var fileStream = File.Create(tempFile))
        {
            await response.Content.CopyToAsync(fileStream, cancellationToken);
        }

        logger.LogInformation("PawnIO 安装程序已下载至 {Path}", tempFile);

        return tempFile;
    }

    private static async Task RunInstallerAsync(string installerPath, ILogger logger, CancellationToken cancellationToken)
    {
        logger.LogInformation("正在安装 PawnIO（{Installer}）...", installerPath);

        var startInfo = new ProcessStartInfo
        {
            FileName = installerPath,
            Arguments = "-install -silent",
            UseShellExecute = true,
            Verb = "runas",
            WindowStyle = ProcessWindowStyle.Hidden,
            WorkingDirectory = Path.GetDirectoryName(installerPath) ?? AppContext.BaseDirectory
        };

        try
        {
            using var process = Process.Start(startInfo);
            if (process is null)
            {
                throw new InvalidOperationException("无法启动 PawnIO 安装程序进程。");
            }

            await process.WaitForExitAsync(cancellationToken);

            if (process.ExitCode != 0)
            {
                throw new InvalidOperationException($"PawnIO 安装程序返回错误代码 {process.ExitCode}。");
            }
        }
        catch (System.ComponentModel.Win32Exception ex) when (ex.NativeErrorCode == 1223)
        {
            throw new InvalidOperationException("PawnIO 安装被用户取消。", ex);
        }
    }

    private static void TryDeleteInstaller(string path, ILogger logger)
    {
        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
        catch (Exception ex)
        {
            logger.LogDebug(ex, "清理 PawnIO 安装程序 {Path} 时出错。", path);
        }
    }
}
