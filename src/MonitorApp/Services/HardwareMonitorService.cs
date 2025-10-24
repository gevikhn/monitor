using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Management;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using LibreHardwareMonitor.Hardware;
using MonitorApp.Models;
using MonitorApp.Utilities;
using Microsoft.Extensions.Logging;

namespace MonitorApp.Services;

public sealed class HardwareMonitorService : IDisposable
{
    private Computer _computer;
    private readonly UpdateVisitor _visitor = new();
    private bool _disposed;
    private bool _memoryFallback;
    private readonly Dictionary<int, ProcessCpuSample> _processCpuSamples = new();
    private readonly ILogger<HardwareMonitorService> _logger;
    private readonly object _networkAdapterCacheLock = new();
    private HashSet<string> _physicalAdapterKeyCache = new(StringComparer.Ordinal);
    private DateTimeOffset _physicalAdapterKeysCachedAt = DateTimeOffset.MinValue;
    private readonly object _sensorCacheLock = new();
    private readonly Dictionary<SensorCacheKey, ISensor?> _sensorCache = new();
    private IHardware? _cpuHardware;
    private IHardware? _memoryHardware;
    private List<IHardware> _allHardware = new();
    private List<IHardware> _gpuHardware = new();
    private List<IHardware> _networkHardware = new();
    private List<IHardware> _storageHardware = new();
    private string? _cachedCpuName;
    private string? _cachedMotherboardName;

    public HardwareMonitorService(ILogger<HardwareMonitorService> logger)
    {
        _logger = logger;
        _computer = CreateComputer(includeMemory: true);

        try
        {
            _computer.Open();
        }
        catch (FileNotFoundException ex) when (IsRamSpdToolkitMissing(ex))
        {
            _logger.LogWarning(ex, "未检测到 RAMSPDToolkit-NDD 组件，将禁用内存硬件传感器并使用系统内存信息替代。");
            TryCloseComputer(_computer);
            _computer = CreateComputer(includeMemory: false);
            _memoryFallback = true;
            _computer.Open();
        }

        CacheHardwareInventory();
    }

    public HardwareSnapshot GetSnapshot()
    {
        ThrowIfDisposed();

        _computer.Accept(_visitor);

        var timestamp = DateTimeOffset.Now;
        var cpuHardware = _cpuHardware;
        var cpuName = _cachedCpuName ?? cpuHardware?.Name ?? "Unknown CPU";

        var cpuLoad = FindSensorValue(cpuHardware, SensorType.Load, "CPU Total", "Total CPU", "CPU Usage");

        var cpuPackageTemp = FindSensorValue(cpuHardware, SensorType.Temperature, "Package", "CPU Package", "Tctl", "Tdie");
        var cpuClock = FindSensorValue(cpuHardware, SensorType.Clock, "Core", "CPU", "Average");

        var coreTemperatures = EnumerateSensors(cpuHardware, SensorType.Temperature)
            .Select(sensor => ToTemperatureReading(sensor.Hardware, sensor.Sensor))
            .OrderBy(t => t.Sensor, StringComparer.OrdinalIgnoreCase)
            .ToList();

        var memoryMetrics = CollectMemoryMetrics();
        var physicalAdapterKeys = GetPhysicalNetworkAdapterKeys();
        var gpuMetrics = CollectGpuMetrics();
        var (networkAdapters, networkSummary) = CollectNetworkMetrics(physicalAdapterKeys);
        var diskSummary = CollectDiskSummary();

        var temperatureReadings = _allHardware
            .SelectMany(h => EnumerateSensors(h, SensorType.Temperature)
                .Select(sensor => ToTemperatureReading(sensor.Hardware, sensor.Sensor)))
            .OrderBy(t => t.Hardware, StringComparer.OrdinalIgnoreCase)
            .ThenBy(t => t.Sensor, StringComparer.OrdinalIgnoreCase)
            .ToList();

        var temperatureHighlights = BuildTemperatureHighlights(cpuPackageTemp, coreTemperatures, temperatureReadings);
        var foregroundApp = OperatingSystem.IsWindows() ? CollectForegroundAppMetrics() : null;

        var motherboardName = _cachedMotherboardName;

        return new HardwareSnapshot
        {
            Timestamp = timestamp,
            MachineName = Environment.MachineName,
            OSVersion = Environment.OSVersion.ToString(),
            Motherboard = motherboardName,
            Gpus = gpuMetrics,
            Cpu = new CpuMetrics
            {
                Name = cpuName,
                TotalLoadPercentage = cpuLoad,
                PackageTemperatureC = cpuPackageTemp,
                ClockMhz = cpuClock,
                CoreTemperatures = coreTemperatures
            },
            Memory = memoryMetrics,
            NetworkAdapters = networkAdapters,
            Temperatures = temperatureReadings,
            TemperatureHighlights = temperatureHighlights,
            Network = networkSummary,
            Disk = diskSummary,
            ForegroundApp = foregroundApp
        };
    }

    private Computer CreateComputer(bool includeMemory) =>
        new()
        {
            IsCpuEnabled = true,
            IsGpuEnabled = true,
            IsMemoryEnabled = includeMemory,
            IsMotherboardEnabled = true,
            IsNetworkEnabled = true,
            IsStorageEnabled = true,
            IsControllerEnabled = true
        };

    private void CacheHardwareInventory()
    {
        var hardware = _computer.Hardware ?? Array.Empty<IHardware>();
        var hardwareList = new List<IHardware>(hardware);

        lock (_sensorCacheLock)
        {
            _sensorCache.Clear();
        }

        _allHardware = hardwareList;
        _cpuHardware = hardwareList.FirstOrDefault(h => h.HardwareType == HardwareType.Cpu);
        _cachedCpuName = _cpuHardware?.Name;
        _memoryHardware = hardwareList.FirstOrDefault(h => h.HardwareType == HardwareType.Memory);
        _cachedMotherboardName = hardwareList.FirstOrDefault(h => h.HardwareType == HardwareType.Motherboard)?.Name;

        _gpuHardware = hardwareList.Where(IsPhysicalGpuHardware).ToList();
        _networkHardware = hardwareList.Where(h => h.HardwareType == HardwareType.Network).ToList();
        _storageHardware = hardwareList.Where(h => h.HardwareType == HardwareType.Storage).ToList();
    }

    private void TryCloseComputer(Computer computer)
    {
        try
        {
            computer.Close();
        }
        catch
        {
            // ignore
        }
    }

    private static double? ToMegabytesPerSecond(double? value) =>
        value.HasValue ? value.Value / 1_048_576d : null;

    private static TemperatureReading ToTemperatureReading(IHardware hardware, ISensor sensor) =>
        new()
        {
            Hardware = hardware.Name,
            HardwareType = hardware.HardwareType.ToString(),
            Sensor = sensor.Name,
            ValueC = sensor.Value
        };

    private static IReadOnlyList<TemperatureHighlight> BuildTemperatureHighlights(double? cpuPackageTemp, IReadOnlyList<TemperatureReading> coreTemperatures, IReadOnlyList<TemperatureReading> allReadings)
    {
        var highlights = new List<TemperatureHighlight>();

        if (cpuPackageTemp is { } package)
        {
            highlights.Add(new TemperatureHighlight
            {
                Label = "CPU 封装",
                ValueC = package
            });
        }

        var coreHot = coreTemperatures
            .Where(t => t.ValueC.HasValue)
            .OrderByDescending(t => t.ValueC)
            .FirstOrDefault();

        if (coreHot is not null)
        {
            highlights.Add(new TemperatureHighlight
            {
                Label = "CPU 核心",
                ValueC = coreHot.ValueC
            });
        }

        var motherboardTemp = allReadings
            .Where(t => IsMatch(t.HardwareType, "Motherboard") || ContainsKeyword(t.Hardware, "motherboard") || ContainsKeyword(t.Sensor, "system"))
            .Where(t => t.ValueC.HasValue)
            .OrderByDescending(t => t.ValueC)
            .FirstOrDefault();

        if (motherboardTemp is not null)
        {
            highlights.Add(new TemperatureHighlight
            {
                Label = "主板",
                ValueC = motherboardTemp.ValueC
            });
        }

        var storageHot = allReadings
            .Where(t => IsStorageHardware(t.HardwareType) || ContainsKeyword(t.Hardware, "ssd") || ContainsKeyword(t.Hardware, "nvme") || ContainsKeyword(t.Sensor, "drive"))
            .Where(t => t.ValueC.HasValue)
            .OrderByDescending(t => t.ValueC)
            .FirstOrDefault();

        if (storageHot is not null)
        {
            highlights.Add(new TemperatureHighlight
            {
                Label = storageHot.Hardware,
                ValueC = storageHot.ValueC
            });
        }

        return highlights;
    }

    [SupportedOSPlatform("windows")]
    private ForegroundAppMetrics? CollectForegroundAppMetrics()
    {
        if (!OperatingSystem.IsWindows())
        {
            return null;
        }

        return ProcessEfficiencyManager.RunWithThreadPriority(() =>
        {
            try
            {
                var handle = GetForegroundWindow();
                if (handle == IntPtr.Zero)
                {
                    return null;
                }

                if (GetWindowThreadProcessId(handle, out var pid) == 0 || pid == 0)
                {
                    return null;
                }

                var windowTitle = GetWindowTitle(handle);
                if (string.IsNullOrWhiteSpace(windowTitle))
                {
                    windowTitle = null;
                }

                Process? process = null;
                try
                {
                    process = Process.GetProcessById((int)pid);
                }
                catch
                {
                    // ignore; fall back to window-title-only information
                }

                try
                {
                    string? processName = null;
                    double? cpuUsage = null;
                    double? memoryUsageMb = null;

                    if (process is not null)
                    {
                        process.Refresh();

                        if (string.IsNullOrWhiteSpace(windowTitle))
                        {
                            var mainWindowTitle = process.MainWindowTitle;
                            if (!string.IsNullOrWhiteSpace(mainWindowTitle))
                            {
                                windowTitle = mainWindowTitle;
                            }
                        }

                        processName = SafeProcessName(process);
                        cpuUsage = CalculateProcessCpu(process, DateTime.UtcNow);

                        try
                        {
                            var workingSet = process.WorkingSet64;
                            if (workingSet > 0)
                            {
                                memoryUsageMb = workingSet / 1024d / 1024d;
                            }
                        }
                        catch
                        {
                            // ignore
                        }
                    }

                    var fallbackLabel = $"PID {pid}";
                    return new ForegroundAppMetrics
                    {
                        WindowTitle = windowTitle ?? processName ?? fallbackLabel,
                        ProcessName = processName ?? fallbackLabel,
                        CpuUsagePercentage = cpuUsage,
                        MemoryUsageMb = memoryUsageMb
                    };
                }
                finally
                {
                    process?.Dispose();
                }
            }
            catch
            {
                return null;
            }
        });
    }

    private double? CalculateProcessCpu(Process process, DateTime now)
    {
        PurgeStaleSamples(now);

        TimeSpan totalProcessorTime;
        try
        {
            totalProcessorTime = process.TotalProcessorTime;
        }
        catch
        {
            return null;
        }

        if (_processCpuSamples.TryGetValue(process.Id, out var sample))
        {
            var elapsed = now - sample.Timestamp;
            if (elapsed <= TimeSpan.Zero)
            {
                _processCpuSamples[process.Id] = new ProcessCpuSample(totalProcessorTime, now);
                return null;
            }

            var deltaCpu = totalProcessorTime - sample.TotalProcessorTime;
            if (deltaCpu <= TimeSpan.Zero)
            {
                _processCpuSamples[process.Id] = new ProcessCpuSample(totalProcessorTime, now);
                return 0d;
            }

            var cpuPercent = deltaCpu.TotalMilliseconds / (elapsed.TotalMilliseconds * Environment.ProcessorCount) * 100d;
            _processCpuSamples[process.Id] = new ProcessCpuSample(totalProcessorTime, now);

            if (double.IsFinite(cpuPercent))
            {
                return Math.Clamp(cpuPercent, 0d, 100d);
            }

            return null;
        }

        _processCpuSamples[process.Id] = new ProcessCpuSample(totalProcessorTime, now);
        return null;
    }

    private void PurgeStaleSamples(DateTime now)
    {
        if (_processCpuSamples.Count == 0)
        {
            return;
        }

        var threshold = now - TimeSpan.FromMinutes(2);
        var toRemove = new List<int>();
        foreach (var (pid, sample) in _processCpuSamples)
        {
            if (sample.Timestamp < threshold)
            {
                toRemove.Add(pid);
            }
        }

        foreach (var pid in toRemove)
        {
            _processCpuSamples.Remove(pid);
        }
    }

    private static bool IsRamSpdToolkitMissing(FileNotFoundException ex) =>
        ex.FileName?.Contains("RAMSPDToolkit", StringComparison.OrdinalIgnoreCase) == true;

    private static readonly TimeSpan PhysicalAdapterCacheDuration = TimeSpan.FromMinutes(1);

    private static readonly HashSet<NetworkInterfaceType> PhysicalInterfaceTypes = new()
    {
        NetworkInterfaceType.Ethernet,
        NetworkInterfaceType.GigabitEthernet,
        NetworkInterfaceType.FastEthernetFx,
        NetworkInterfaceType.FastEthernetT,
        NetworkInterfaceType.Ethernet3Megabit,
        NetworkInterfaceType.Wireless80211
    };

    private static readonly string[] VirtualAdapterKeywords =
    {
        "virtual",
        "vpn",
        "loopback",
        "vmware",
        "hyper-v",
        "filter",
        "miniport",
        "ndis",
        "npcap",
        "qos",
        "driver",
        "bluetooth",
        "tunnel",
        "teredo",
        "isatap",
        "tap",
        "vEthernet",
        "bridge",
        "km-test"
    };

    private IReadOnlySet<string> GetPhysicalNetworkAdapterKeys()
    {
        var now = DateTimeOffset.UtcNow;

        lock (_networkAdapterCacheLock)
        {
            var cacheIsFresh = now - _physicalAdapterKeysCachedAt < PhysicalAdapterCacheDuration;
            if (cacheIsFresh && _physicalAdapterKeyCache.Count > 0)
            {
                return _physicalAdapterKeyCache;
            }

            static void AddNormalizedKey(HashSet<string> target, string? value)
            {
                var key = NormalizeAdapterKey(value);
                if (!string.IsNullOrEmpty(key))
                {
                    target.Add(key);
                }
            }

            HashSet<string>? rebuilt = null;

            try
            {
                rebuilt = new HashSet<string>(StringComparer.Ordinal);

                foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (!IsPhysicalInterface(nic))
                    {
                        continue;
                    }

                    AddNormalizedKey(rebuilt, nic.Name);
                    AddNormalizedKey(rebuilt, nic.Description);
                    AddNormalizedKey(rebuilt, nic.Id);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "读取网卡信息失败");

                if (_physicalAdapterKeyCache.Count > 0)
                {
                    _physicalAdapterKeysCachedAt = now;
                    return _physicalAdapterKeyCache;
                }
            }

            _physicalAdapterKeysCachedAt = now;

            if (rebuilt is not null)
            {
                _physicalAdapterKeyCache = rebuilt;
            }
            else if (_physicalAdapterKeyCache.Count == 0)
            {
                _physicalAdapterKeyCache = new HashSet<string>(StringComparer.Ordinal);
            }

            return _physicalAdapterKeyCache;
        }
    }

    private static bool IsPhysicalNetworkHardware(IHardware hardware, IReadOnlySet<string> physicalKeys)
    {
        if (physicalKeys.Count == 0)
        {
            // 无法确定物理网卡，保持兼容返回全部
            return true;
        }

        var hardwareNameKey = NormalizeAdapterKey(hardware.Name);
        var identifierKey = NormalizeAdapterKey(hardware.Identifier.ToString());

        return MatchesAnyKey(physicalKeys, hardwareNameKey) || MatchesAnyKey(physicalKeys, identifierKey);
    }

    private static bool MatchesAnyKey(IReadOnlySet<string> keys, string candidate) =>
        !string.IsNullOrEmpty(candidate) && keys.Contains(candidate);

    private static string NormalizeAdapterKey(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        var builder = new StringBuilder(value.Length);
        foreach (var ch in value)
        {
            if (char.IsLetterOrDigit(ch))
            {
                builder.Append(char.ToLowerInvariant(ch));
            }
        }

        return builder.ToString();
    }

    private static bool IsPhysicalInterface(NetworkInterface networkInterface)
    {
        if (networkInterface.OperationalStatus != OperationalStatus.Up)
        {
            return false;
        }

        if (!PhysicalInterfaceTypes.Contains(networkInterface.NetworkInterfaceType))
        {
            return false;
        }

        var name = networkInterface.Name ?? string.Empty;
        var description = networkInterface.Description ?? string.Empty;

        if (ContainsVirtualKeyword(name) || ContainsVirtualKeyword(description))
        {
            return false;
        }

        return true;
    }

    private static bool ContainsVirtualKeyword(string value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return false;
        }

        foreach (var keyword in VirtualAdapterKeywords)
        {
            if (value.IndexOf(keyword, StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return true;
            }
        }

        return false;
    }

    private static readonly string[] VirtualGpuKeywords =
    {
        "microsoft basic render",
        "basic display adapter",
        "microsoft remote display",
        "hyper-v",
        "virtual",
        "vmware",
        "virtualbox",
        "citrix",
        "parallels",
        "software adapter",
        "wsl",
        "render-only",
        "mshyperv"
    };

    private (List<NetworkAdapterMetrics> Adapters, NetworkSummary Summary) CollectNetworkMetrics(IReadOnlySet<string> physicalAdapterKeys)
    {
        double totalUpload = 0;
        double totalDownload = 0;

        var adapters = _networkHardware
            .Where(h => IsPhysicalNetworkHardware(h, physicalAdapterKeys))
            .Select(h =>
            {
                var upload = ToMegabytesPerSecond(FindSensorValue(h, SensorType.Throughput, "Upload", "Sent"));
                var download = ToMegabytesPerSecond(FindSensorValue(h, SensorType.Throughput, "Download", "Received"));

                if (upload is > 0)
                {
                    totalUpload += upload.Value;
                }

                if (download is > 0)
                {
                    totalDownload += download.Value;
                }

                return new NetworkAdapterMetrics
                {
                    Name = h.Name,
                    UploadMBps = upload,
                    DownloadMBps = download
                };
            })
            .OrderBy(n => n.Name, StringComparer.OrdinalIgnoreCase)
            .ToList();

        var summary = new NetworkSummary
        {
            UploadMBps = totalUpload,
            DownloadMBps = totalDownload
        };

        return (adapters, summary);
    }

    private DiskSummary CollectDiskSummary()
    {
        double totalRead = 0;
        double totalWrite = 0;

        foreach (var hardware in _storageHardware)
        {
            var read = ToMegabytesPerSecond(FindSensorValue(hardware, SensorType.Throughput, "Read", "读取", "读", "Input"));
            var write = ToMegabytesPerSecond(FindSensorValue(hardware, SensorType.Throughput, "Write", "写", "Output"));

            if (read is > 0)
            {
                totalRead += read.Value;
            }

            if (write is > 0)
            {
                totalWrite += write.Value;
            }
        }

        return new DiskSummary
        {
            ReadMbps = totalRead,
            WriteMbps = totalWrite
        };
    }

    private List<GpuMetrics> CollectGpuMetrics()
    {
        var metrics = _gpuHardware
            .Select(CreateGpuMetrics)
            .Where(g => g is not null)
            .Select(g => g!)
            .GroupBy(g => NormalizeAdapterKey(g.Name), StringComparer.Ordinal)
            .Select(group => group.First())
            .OrderBy(g => g.Name, StringComparer.OrdinalIgnoreCase)
            .ToList();

        return metrics;
    }

    private static bool IsPhysicalGpuHardware(IHardware hardware)
    {
        if (hardware.HardwareType is not (HardwareType.GpuAmd or HardwareType.GpuNvidia or HardwareType.GpuIntel))
        {
            return false;
        }

        var name = hardware.Name ?? string.Empty;
        var identifier = hardware.Identifier.ToString();

        if (ContainsVirtualGpuKeyword(name) || ContainsVirtualGpuKeyword(identifier))
        {
            return false;
        }

        return true;
    }

    private static bool ContainsVirtualGpuKeyword(string value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return false;
        }

        foreach (var keyword in VirtualGpuKeywords)
        {
            if (value.IndexOf(keyword, StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return true;
            }
        }

        return false;
    }

    private GpuMetrics? CreateGpuMetrics(IHardware hardware)
    {
        var load = FindSensorValue(hardware, SensorType.Load, "GPU Core", "Core", "Total", "GPU");
        var temperature = FindSensorValue(hardware, SensorType.Temperature, "Hot Spot", "Junction", "Core", "GPU");
        var hotspot = FindSensorValue(hardware, SensorType.Temperature, "Hot Spot", "Junction");
        var clock = FindSensorValue(hardware, SensorType.Clock, "Core", "Graphics");
        var power = FindSensorValue(hardware, SensorType.Power, "GPU", "Graphics");
        var memoryLoad = FindSensorValue(hardware, SensorType.Load, "Memory", "VRAM");
        var memoryUsed = FindSensorValue(hardware, SensorType.Data, "Memory Used", "GPU Memory Used", "VRAM Used");
        var memoryFree = FindSensorValue(hardware, SensorType.Data, "Memory Free", "GPU Memory Free", "VRAM Free");
        var memoryTotal = FindSensorValue(hardware, SensorType.Data, "Memory Total", "Total Memory", "VRAM Total");

        if (memoryTotal is null && memoryUsed is not null && memoryFree is not null)
        {
            memoryTotal = memoryUsed + memoryFree;
        }

        double? memoryUsagePercentage = memoryLoad;
        if (memoryUsagePercentage is null && memoryUsed is not null && memoryTotal is > 0)
        {
            memoryUsagePercentage = memoryUsed / memoryTotal * 100d;
        }

        return new GpuMetrics
        {
            Name = hardware.Name,
            LoadPercentage = load,
            TemperatureC = temperature,
            HotspotTemperatureC = hotspot,
            MemoryUsedGb = ConvertMegabytesToGigabytes(memoryUsed),
            MemoryTotalGb = ConvertMegabytesToGigabytes(memoryTotal),
            MemoryUsagePercentage = memoryUsagePercentage,
            CoreClockMhz = clock,
            PowerWatts = power
        };
    }

    private static double? ConvertMegabytesToGigabytes(double? value) =>
        value.HasValue ? value.Value / 1024d : null;

    private MemoryMetrics CollectMemoryMetrics()
    {
        var memoryHardware = _memoryHardware;

        if (_memoryFallback || memoryHardware is null)
        {
            if (!OperatingSystem.IsWindows())
            {
                return new MemoryMetrics();
            }

            return GetMemoryMetricsFromSystem();
        }

        var usedMemory = FindSensorValue(memoryHardware, SensorType.Data, "Used", "Memory Used");
        var availableMemory = FindSensorValue(memoryHardware, SensorType.Data, "Available", "Free");

        double? totalMemory = null;
        if (usedMemory.HasValue && availableMemory.HasValue)
        {
            totalMemory = usedMemory + availableMemory;
        }

        var memoryUsage = FindSensorValue(memoryHardware, SensorType.Load, "Memory", "Used");

        return new MemoryMetrics
        {
            TotalGb = totalMemory is > 0 ? totalMemory / 1024d : totalMemory,
            UsedGb = usedMemory is > 0 ? usedMemory / 1024d : usedMemory,
            AvailableGb = availableMemory is > 0 ? availableMemory / 1024d : availableMemory,
            UsagePercentage = memoryUsage
        };
    }

    [SupportedOSPlatform("windows")]
    private MemoryMetrics GetMemoryMetricsFromSystem()
    {
        if (TryGetMemoryMetricsFromNative(out var metrics))
        {
            return metrics;
        }

        return GetMemoryMetricsFromWmi();
    }

    [SupportedOSPlatform("windows")]
    private bool TryGetMemoryMetricsFromNative(out MemoryMetrics metrics)
    {
        metrics = new MemoryMetrics();

        try
        {
            var status = new MemoryStatusEx { Length = (uint)Marshal.SizeOf<MemoryStatusEx>() };
            if (!GlobalMemoryStatusEx(ref status))
            {
                return false;
            }

            var totalGb = ConvertBytesToGigabytes(status.TotalPhys);
            var freeGb = ConvertBytesToGigabytes(status.AvailPhys);
            var usedGb = totalGb - freeGb;
            var usagePercentage = totalGb > 0 ? (usedGb / totalGb) * 100d : (double?)null;

            metrics = new MemoryMetrics
            {
                TotalGb = totalGb,
                UsedGb = usedGb,
                AvailableGb = freeGb,
                UsagePercentage = usagePercentage
            };

            return true;
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "读取系统内存信息的本机 API 调用失败");
            metrics = new MemoryMetrics();
            return false;
        }
    }

    [SupportedOSPlatform("windows")]
    private MemoryMetrics GetMemoryMetricsFromWmi()
    {
        try
        {
            using var searcher = new ManagementObjectSearcher("SELECT TotalVisibleMemorySize, FreePhysicalMemory FROM Win32_OperatingSystem");
            foreach (var os in searcher.Get())
            {
                var totalKb = Convert.ToUInt64(os["TotalVisibleMemorySize"], CultureInfo.InvariantCulture);
                var freeKb = Convert.ToUInt64(os["FreePhysicalMemory"], CultureInfo.InvariantCulture);

                var totalGb = ConvertKilobytesToGigabytes(totalKb);
                var freeGb = ConvertKilobytesToGigabytes(freeKb);
                var usedGb = totalGb - freeGb;
                var usagePercentage = totalGb > 0 ? (usedGb / totalGb) * 100d : (double?)null;

                return new MemoryMetrics
                {
                    TotalGb = totalGb,
                    UsedGb = usedGb,
                    AvailableGb = freeGb,
                    UsagePercentage = usagePercentage
                };
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "读取系统内存信息失败");
        }

        return new MemoryMetrics
        {
            TotalGb = null,
            UsedGb = null,
            AvailableGb = null,
            UsagePercentage = null
        };
    }

    private static double ConvertBytesToGigabytes(ulong valueInBytes) =>
        valueInBytes / 1024d / 1024d / 1024d;

    private static double ConvertKilobytesToGigabytes(ulong valueInKb) =>
        valueInKb / 1024d / 1024d;

    private double? FindSensorValue(IHardware? hardware, SensorType sensorType, params string[] keywords)
    {
        if (hardware is null)
        {
            return null;
        }

        var hardwareId = hardware.Identifier.ToString();
        List<ISensor>? sensors = null;

        if (keywords is { Length: > 0 })
        {
            foreach (var keyword in keywords)
            {
                if (TryGetCachedSensor(hardwareId, sensorType, keyword, out var cachedSensor))
                {
                    var cachedValue = ReadSensorValue(cachedSensor);
                    if (cachedValue.HasValue)
                    {
                        return cachedValue;
                    }
                }

                sensors ??= EnumerateSensors(hardware, sensorType)
                    .Select(tuple => tuple.Sensor)
                    .ToList();

                ISensor? firstMatch = null;
                foreach (var sensor in sensors)
                {
                    if (!SensorMatches(sensor, keyword))
                    {
                        continue;
                    }

                    firstMatch ??= sensor;

                    var value = ReadSensorValue(sensor);
                    if (value.HasValue)
                    {
                        CacheSensor(hardwareId, sensorType, keyword, sensor);
                        return value;
                    }
                }

                if (firstMatch is not null)
                {
                    CacheSensor(hardwareId, sensorType, keyword, firstMatch);
                }
            }
        }

        if (TryGetCachedSensor(hardwareId, sensorType, string.Empty, out var defaultSensor))
        {
            var cachedValue = ReadSensorValue(defaultSensor);
            if (cachedValue.HasValue)
            {
                return cachedValue;
            }
        }

        sensors ??= EnumerateSensors(hardware, sensorType)
            .Select(tuple => tuple.Sensor)
            .ToList();

        foreach (var sensor in sensors)
        {
            var value = ReadSensorValue(sensor);
            if (value.HasValue)
            {
                CacheSensor(hardwareId, sensorType, string.Empty, sensor);
                return value;
            }
        }

        return null;
    }

    private bool TryGetCachedSensor(string hardwareId, SensorType sensorType, string keyword, out ISensor? sensor)
    {
        var key = new SensorCacheKey(hardwareId, sensorType, NormalizeSensorKeyword(keyword));
        lock (_sensorCacheLock)
        {
            return _sensorCache.TryGetValue(key, out sensor);
        }
    }

    private void CacheSensor(string hardwareId, SensorType sensorType, string keyword, ISensor? sensor)
    {
        var key = new SensorCacheKey(hardwareId, sensorType, NormalizeSensorKeyword(keyword));
        lock (_sensorCacheLock)
        {
            _sensorCache[key] = sensor;
        }
    }

    private static string NormalizeSensorKeyword(string? keyword) =>
        string.IsNullOrWhiteSpace(keyword) ? string.Empty : keyword.Trim().ToLowerInvariant();

    private static double? ReadSensorValue(ISensor? sensor) => sensor?.Value;

    private static bool SensorMatches(ISensor sensor, string keyword)
    {
        if (string.IsNullOrWhiteSpace(keyword))
        {
            return false;
        }

        return sensor.Name.Contains(keyword, StringComparison.OrdinalIgnoreCase) ||
               sensor.Identifier.ToString().Contains(keyword, StringComparison.OrdinalIgnoreCase);
    }

    private static bool ContainsKeyword(string value, string keyword) =>
        !string.IsNullOrEmpty(value) && value.IndexOf(keyword, StringComparison.OrdinalIgnoreCase) >= 0;

    private static bool IsMatch(string value, string expected) =>
        string.Equals(value, expected, StringComparison.OrdinalIgnoreCase);

    private static bool IsStorageHardware(string hardwareType) =>
        IsMatch(hardwareType, HardwareType.Storage.ToString()) ||
        IsMatch(hardwareType, HardwareType.EmbeddedController.ToString());

    private static string? SafeProcessName(Process process)
    {
        try
        {
            return process.ProcessName;
        }
        catch
        {
            return null;
        }
    }

    private static string GetWindowTitle(IntPtr handle)
    {
        var length = GetWindowTextLength(handle);
        var capacity = length > 0 ? length + 1 : 256;
        var builder = new StringBuilder(capacity);
        _ = GetWindowText(handle, builder, builder.Capacity);
        return builder.ToString();
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    private static extern bool GlobalMemoryStatusEx(ref MemoryStatusEx lpBuffer);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    private struct MemoryStatusEx
    {
        public uint Length;
        public uint MemoryLoad;
        public ulong TotalPhys;
        public ulong AvailPhys;
        public ulong TotalPageFile;
        public ulong AvailPageFile;
        public ulong TotalVirtual;
        public ulong AvailVirtual;
        public ulong AvailExtendedVirtual;
    }

    [DllImport("user32.dll")]
    private static extern IntPtr GetForegroundWindow();

    [DllImport("user32.dll")]
    private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);

    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern int GetWindowText(IntPtr hWnd, StringBuilder lpString, int nMaxCount);

    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern int GetWindowTextLength(IntPtr hWnd);

    private sealed record ProcessCpuSample(TimeSpan TotalProcessorTime, DateTime Timestamp);
    private readonly record struct SensorCacheKey(string HardwareId, SensorType SensorType, string Keyword);

    private static IEnumerable<(IHardware Hardware, ISensor Sensor)> EnumerateSensors(IHardware? hardware, SensorType sensorType)
    {
        if (hardware is null)
        {
            yield break;
        }

        foreach (var sensor in hardware.Sensors.Where(s => s.SensorType == sensorType))
        {
            yield return (hardware, sensor);
        }

        foreach (var subHardware in hardware.SubHardware)
        {
            foreach (var sensor in EnumerateSensors(subHardware, sensorType))
            {
                yield return sensor;
            }
        }
    }

    private void ThrowIfDisposed()
    {
        if (_disposed)
        {
            throw new ObjectDisposedException(nameof(HardwareMonitorService));
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _computer.Close();
        _disposed = true;
        GC.SuppressFinalize(this);
    }

    private sealed class UpdateVisitor : IVisitor
    {
        public void VisitComputer(IComputer computer) => computer.Traverse(this);

        public void VisitHardware(IHardware hardware)
        {
            hardware.Update();
            foreach (var subHardware in hardware.SubHardware)
            {
                subHardware.Accept(this);
            }
        }

        public void VisitSensor(ISensor sensor)
        {
        }

        public void VisitParameter(IParameter parameter)
        {
        }
    }
}
