using System;
using System.Diagnostics;
using System.Drawing;
using System.Threading;
using System.Windows.Forms;
using Microsoft.Extensions.Hosting;

namespace MonitorApp.Utilities;

internal static class TrayHost
{
    private static Thread? _uiThread;

    public static void Initialize(IHostApplicationLifetime lifetime, string serviceUrl)
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        if (_uiThread is not null)
        {
            return;
        }

        _uiThread = new Thread(() =>
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);

            using var context = new TrayApplicationContext(lifetime, serviceUrl);
            Application.Run(context);
        })
        {
            IsBackground = true,
            Name = "TrayHostThread"
        };

        _uiThread.SetApartmentState(ApartmentState.STA);
        _uiThread.Start();
    }
}

internal sealed class TrayApplicationContext : ApplicationContext
{
    private readonly IHostApplicationLifetime _lifetime;
    private readonly string _serviceUrl;
    private readonly NotifyIcon _notifyIcon;
    private readonly ContextMenuStrip _contextMenu;
    private ToolStripMenuItem _startupMenuItem = null!;
    private readonly SynchronizationContext _syncContext;

    public TrayApplicationContext(IHostApplicationLifetime lifetime, string serviceUrl)
    {
        _lifetime = lifetime;
        _serviceUrl = serviceUrl;
        _syncContext = SynchronizationContext.Current ?? new WindowsFormsSynchronizationContext();

        _contextMenu = BuildMenu();

        _notifyIcon = new NotifyIcon
        {
            Icon = SystemIcons.Application,
            Visible = true,
            Text = "系统监控",
            ContextMenuStrip = _contextMenu
        };

        _notifyIcon.DoubleClick += (_, _) => ShowWindow();

        lifetime.ApplicationStopping.Register(() =>
        {
            _syncContext.Post(_ => ExitFromHost(), null);
        });
    }

    private ContextMenuStrip BuildMenu()
    {
        var menu = new ContextMenuStrip();

        var showItem = new ToolStripMenuItem("显示窗口", null, (_, _) => ShowWindow());
        _startupMenuItem = new ToolStripMenuItem(string.Empty, null, (_, _) => ToggleStartup());
        var exitItem = new ToolStripMenuItem("退出程序", null, (_, _) => ExitApplication());

        UpdateStartupMenuItem();

        menu.Items.Add(showItem);
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add(_startupMenuItem);
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add(exitItem);

        return menu;
    }

    private void ShowWindow()
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = _serviceUrl,
                UseShellExecute = true
            };

            Process.Start(psi);
        }
        catch (Exception ex)
        {
            _notifyIcon.ShowBalloonTip(
                3000,
                "无法打开窗口",
                ex.Message,
                ToolTipIcon.Error);
        }
    }

    private void ToggleStartup()
    {
        try
        {
            if (WindowsStartupManager.IsEnabled())
            {
                WindowsStartupManager.Disable();
                ShowBalloonTip("已关闭开机自启动");
            }
            else
            {
                WindowsStartupManager.Enable();
                ShowBalloonTip("已开启开机自启动");
            }
        }
        catch (Exception ex)
        {
            ShowBalloonTip($"操作失败：{ex.Message}", ToolTipIcon.Error);
        }
        finally
        {
            UpdateStartupMenuItem();
        }
    }

    private void ExitApplication()
    {
        _notifyIcon.Visible = false;
        _lifetime.StopApplication();
        ExitThread();
    }

    private void ExitFromHost()
    {
        _notifyIcon.Visible = false;
        ExitThread();
    }

    private void UpdateStartupMenuItem()
    {
        if (!WindowsStartupManager.IsSupported)
        {
            _startupMenuItem.Enabled = false;
            _startupMenuItem.Text = "当前平台不支持开机启动";
            return;
        }

        var enabled = WindowsStartupManager.IsEnabled();
        _startupMenuItem.Text = enabled ? "关闭开机启动" : "开启开机启动";
        _startupMenuItem.Checked = enabled;
    }

    private void ShowBalloonTip(string message, ToolTipIcon icon = ToolTipIcon.Info)
    {
        _notifyIcon.ShowBalloonTip(2000, "系统监控", message, icon);
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _notifyIcon.Dispose();
            _contextMenu.Dispose();
        }

        base.Dispose(disposing);
    }
}
