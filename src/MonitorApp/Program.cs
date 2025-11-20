using MonitorApp.Services;
using MonitorApp.Utilities;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using System.Linq;
using System.Reflection;
using System.IO;

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

var baseUrl = builder.Configuration.GetValue<string>("App:BaseUrl") ?? "http://0.0.0.0:5231";
builder.WebHost.UseUrls(baseUrl);

builder.Services.AddSingleton<HardwareMonitorService>();

var app = builder.Build();

if (OperatingSystem.IsWindows())
{
    var loggerFactory = app.Services.GetRequiredService<ILoggerFactory>();
    var pawnIoLogger = loggerFactory.CreateLogger(nameof(PawnIoInstaller));
    await PawnIoInstaller.EnsureInstalledAsync(pawnIoLogger);

    var startupLogger = loggerFactory.CreateLogger<Program>();
    ProcessEfficiencyManager.EnableForCurrentProcess(startupLogger);
}

var assembly = Assembly.GetExecutingAssembly();
const string indexResource = "wwwroot/index.html";
const string manifestResource = "wwwroot/manifest.json";
const string iconResource = "wwwroot/favicon.png";

var indexHtml = await LoadEmbeddedStringAsync(indexResource);
var manifestJson = await LoadEmbeddedStringAsync(manifestResource);
var iconPng = await LoadEmbeddedBytesAsync(iconResource);

app.MapGet("/", () => Results.Content(indexHtml, "text/html; charset=utf-8"));
app.MapGet("/index.html", () => Results.Content(indexHtml, "text/html; charset=utf-8"));
app.MapGet("/manifest.json", () => Results.Content(manifestJson, "application/manifest+json; charset=utf-8"));
app.MapGet("/favicon.png", () => Results.File(iconPng, "image/png"));

app.MapGet("/css/{name}", (string name) => ServeEmbeddedResource($"wwwroot/css/{name}"));
app.MapGet("/fonts/{name}", (string name) => ServeEmbeddedResource($"wwwroot/fonts/{name}"));

IResult ServeEmbeddedResource(string resourceName)
{
    var stream = assembly.GetManifestResourceStream(resourceName);
    if (stream is null) return Results.NotFound();
    return Results.Stream(stream, GetContentType(resourceName));
}

string GetContentType(string path) => Path.GetExtension(path).ToLowerInvariant() switch
{
    ".html" => "text/html; charset=utf-8",
    ".css" => "text/css; charset=utf-8",
    ".js" => "application/javascript; charset=utf-8",
    ".json" => "application/json; charset=utf-8",
    ".png" => "image/png",
    ".woff2" => "font/woff2",
    ".woff" => "font/woff",
    ".ttf" => "font/ttf",
    _ => "application/octet-stream"
};

app.MapGet("/api/metrics", (HardwareMonitorService monitor) =>
{
    var snapshot = monitor.GetSnapshot();
    return Results.Json(snapshot);
});

async Task<string> LoadEmbeddedStringAsync(string resourceName)
{
    await using var stream = assembly.GetManifestResourceStream(resourceName);
    if (stream is null)
    {
        throw new FileNotFoundException($"Embedded resource was not found: {resourceName}");
    }

    using var reader = new StreamReader(stream);
    return await reader.ReadToEndAsync();
}

async Task<byte[]> LoadEmbeddedBytesAsync(string resourceName)
{
    await using var stream = assembly.GetManifestResourceStream(resourceName);
    if (stream is null)
    {
        throw new FileNotFoundException($"Embedded resource was not found: {resourceName}");
    }

    using var buffer = new MemoryStream();
    await stream.CopyToAsync(buffer);
    return buffer.ToArray();
}

var lifetime = app.Services.GetRequiredService<IHostApplicationLifetime>();

var started = false;

try
{
    await app.StartAsync();
    started = true;

    var logger = app.Services.GetRequiredService<ILogger<Program>>();

    var resolvedUrl = app.Urls.FirstOrDefault() ?? baseUrl;
    //如果ip是0.0.0.0，则替换为127.0.0.1
    if (resolvedUrl.Contains("0.0.0.0"))
    {
        resolvedUrl = resolvedUrl.Replace("0.0.0.0", "127.0.0.1");
    }
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

