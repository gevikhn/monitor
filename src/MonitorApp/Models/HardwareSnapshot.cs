using System;
using System.Collections.Generic;

namespace MonitorApp.Models;

public sealed record HardwareSnapshot
{
    public required DateTimeOffset Timestamp { get; init; }
    public required string MachineName { get; init; }
    public required string OSVersion { get; init; }
    public string? Motherboard { get; init; }
    public IReadOnlyList<GpuMetrics> Gpus { get; init; } = Array.Empty<GpuMetrics>();
    public required CpuMetrics Cpu { get; init; }
    public required MemoryMetrics Memory { get; init; }
    public required IReadOnlyList<NetworkAdapterMetrics> NetworkAdapters { get; init; }
    public required IReadOnlyList<TemperatureReading> Temperatures { get; init; }
    public IReadOnlyList<TemperatureHighlight> TemperatureHighlights { get; init; } = Array.Empty<TemperatureHighlight>();
    public required NetworkSummary Network { get; init; }
    public required DiskSummary Disk { get; init; }
    public ForegroundAppMetrics? ForegroundApp { get; init; }
}

public sealed record CpuMetrics
{
    public required string Name { get; init; }
    public double? TotalLoadPercentage { get; init; }
    public double? PackageTemperatureC { get; init; }
    public double? ClockMhz { get; init; }
    public IReadOnlyList<TemperatureReading> CoreTemperatures { get; init; } = Array.Empty<TemperatureReading>();
}

public sealed record MemoryMetrics
{
    public double? TotalGb { get; init; }
    public double? UsedGb { get; init; }
    public double? AvailableGb { get; init; }
    public double? UsagePercentage { get; init; }
    public double? SpeedMhz { get; init; }
    public double? VirtualTotalGb { get; init; }
}

public sealed record NetworkAdapterMetrics
{
    public required string Name { get; init; }
    public required string Identifier { get; init; }
    public double? UploadMBps { get; init; }
    public double? DownloadMBps { get; init; }
}

public sealed record TemperatureReading
{
    public required string Hardware { get; init; }
    public required string HardwareType { get; init; }
    public required string Sensor { get; init; }
    public double? ValueC { get; init; }
}

public sealed record GpuMetrics
{
    public required string Name { get; init; }
    public double? LoadPercentage { get; init; }
    public double? TemperatureC { get; init; }
    public double? HotspotTemperatureC { get; init; }
    public double? MemoryUsedGb { get; init; }
    public double? MemoryTotalGb { get; init; }
    public double? MemoryUsagePercentage { get; init; }
    public double? CoreClockMhz { get; init; }
    public double? PowerWatts { get; init; }
}

public sealed record TemperatureHighlight
{
    public required string Label { get; init; }
    public double? ValueC { get; init; }
}

public sealed record NetworkSummary
{
    public double? UploadMBps { get; init; }
    public double? DownloadMBps { get; init; }
}

public sealed record DiskSummary
{
    public double? ReadMbps { get; init; }
    public double? WriteMbps { get; init; }
}

public sealed record ForegroundAppMetrics
{
    public string? WindowTitle { get; init; }
    public string? ProcessName { get; init; }
    public double? CpuUsagePercentage { get; init; }
    public double? MemoryUsageMb { get; init; }
}
