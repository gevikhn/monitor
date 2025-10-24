using System.Linq;
using MonitorApp.Services;
using MonitorApp.Utilities;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

await RuntimeGuard.EnsureDotnetRuntimeAsync();

var builder = WebApplication.CreateBuilder(args);

if (OperatingSystem.IsWindows())
{
    WindowsEventLogger.EnsureSource();
    builder.Logging.AddEventLog(settings =>
    {
        settings.LogName = "Application";
        settings.SourceName = "MonitorApp";
    });
}

var baseUrl = builder.Configuration.GetValue<string>("App:BaseUrl") ?? "http://127.0.0.1:5231";
builder.WebHost.UseUrls(baseUrl);

builder.Services.AddSingleton<HardwareMonitorService>();

var app = builder.Build();

app.UseDefaultFiles();
app.UseStaticFiles();

app.MapGet("/api/metrics", (HardwareMonitorService monitor) =>
{
    var snapshot = monitor.GetSnapshot();
    return Results.Json(snapshot);
});

var lifetime = app.Services.GetRequiredService<IHostApplicationLifetime>();

var started = false;

try
{
    await app.StartAsync();
    started = true;

    var logger = app.Services.GetRequiredService<ILogger<Program>>();

    var resolvedUrl = app.Urls.FirstOrDefault() ?? baseUrl;
    TrayHost.Initialize(lifetime, resolvedUrl);

    logger.LogInformation("MonitorApp 已启动，监听地址 {Url}", resolvedUrl);

    await app.WaitForShutdownAsync();
}
finally
{
    if (started)
    {
        var logger = app.Services.GetService<ILogger<Program>>();
        logger?.LogInformation("MonitorApp 正在停止");

        await app.StopAsync();
    }

    await app.DisposeAsync();
}
