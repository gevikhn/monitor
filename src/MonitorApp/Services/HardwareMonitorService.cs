using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Management;
using System.Net.NetworkInformation;
using System.Net;
using System.Net.Sockets;
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
    private readonly object _memoryInfoCacheLock = new();
    private double? _cachedMemorySpeedMhz;
    private DateTimeOffset _memorySpeedCachedAt = DateTimeOffset.MinValue;
    private double? _cachedVirtualTotalGb;
    private DateTimeOffset _virtualMemoryCachedAt = DateTimeOffset.MinValue;
    private static readonly TimeSpan MemoryInfoCacheDuration = TimeSpan.FromMinutes(5);
    // GPU info cache (e.g., total VRAM via WMI). Total VRAM is stable, so no expiry needed.
    private readonly object _gpuInfoCacheLock = new();
    private readonly Dictionary<string, double?> _gpuTotalMemoryMbCache = new(StringComparer.Ordinal);
    // Foreground usage tracking
    private readonly object _foregroundLock = new();
    private string? _currentForegroundKey;
    private DateTimeOffset _sessionStartAt = DateTimeOffset.MinValue;
    private readonly Dictionary<string, double> _foregroundSeconds = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, string?> _foregroundTitles = new(StringComparer.OrdinalIgnoreCase);
    private static readonly TimeSpan MinForegroundSession = TimeSpan.FromMinutes(1);
    private static readonly HashSet<string> ExcludedForegroundProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        // 基础系统进程
        "explorer", "searchhost", "shellhost", "shellexperiencehost", "widgets",
        // 常见补充
        "applicationframehost", "systemsettings", "textinputhost", "startmenuexperiencehost",
        // 旧版搜索组件
        "searchapp", "searchui",
        "sihost", "taskmgr", "smartscreen"
    };
    private static string NormalizeProcName(string? name)
    {
        if (string.IsNullOrWhiteSpace(name)) return string.Empty;
        var n = name.Trim();
        if (n.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) n = n[..^4];
        return n;
    }
    private static bool IsExcludedProcessName(string? name) => ExcludedForegroundProcesses.Contains(NormalizeProcName(name));

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
    UpdateForegroundUsage(foregroundApp, timestamp);

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
            ForegroundApp = foregroundApp,
            TopForegroundApps = GetTopForegroundApps(timestamp)
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

        // Prefer true motherboard/embedded-controller temperatures; avoid misclassifying SSD "system" sensors
        var motherboardCandidates = allReadings
            .Where(t => t.ValueC.HasValue)
            .Where(t =>
                IsMatch(t.HardwareType, "Motherboard") ||
                IsMatch(t.HardwareType, "EmbeddedController"))
            .ToList();

        if (motherboardCandidates.Count == 0)
        {
            // Fallback by hardware/sensor keywords, include SuperIO; exclude anything that looks like storage
            static bool IsStorageLike(TemperatureReading t) =>
                IsStorageHardware(t.HardwareType) ||
                ContainsKeyword(t.Hardware, "ssd") ||
                ContainsKeyword(t.Hardware, "nvme") ||
                ContainsKeyword(t.Hardware, "hdd") ||
                ContainsKeyword(t.Hardware, "drive") ||
                ContainsKeyword(t.Hardware, "disk");

            motherboardCandidates = allReadings
                .Where(t => t.ValueC.HasValue)
                .Where(t =>
                    IsMatch(t.HardwareType, "SuperIO") ||
                    ContainsKeyword(t.Hardware, "motherboard") ||
                    ContainsKeyword(t.Hardware, "mainboard") ||
                    ContainsKeyword(t.Hardware, "board") ||
                    ContainsKeyword(t.Hardware, "chipset") ||
                    ContainsKeyword(t.Hardware, "pch") ||
                    ContainsKeyword(t.Hardware, "vrm") ||
                    ContainsKeyword(t.Hardware, "mos") ||
                    ContainsKeyword(t.Hardware, "mosfet") ||
                    // Chinese keywords
                    ContainsKeyword(t.Hardware, "主板") ||
                    ContainsKeyword(t.Hardware, "系统板") ||
                    ContainsKeyword(t.Hardware, "芯片组") ||
                    ContainsKeyword(t.Hardware, "南桥") ||
                    ContainsKeyword(t.Hardware, "北桥") ||
                    // Some boards only expose meaningful labels in sensor names
                    ContainsKeyword(t.Sensor, "motherboard") ||
                    ContainsKeyword(t.Sensor, "mainboard") ||
                    ContainsKeyword(t.Sensor, "chipset") ||
                    ContainsKeyword(t.Sensor, "pch") ||
                    ContainsKeyword(t.Sensor, "vrm") ||
                    ContainsKeyword(t.Sensor, "mos") ||
                    ContainsKeyword(t.Sensor, "mosfet") ||
                    ContainsKeyword(t.Sensor, "系统") ||
                    ContainsKeyword(t.Sensor, "主板") ||
                    ContainsKeyword(t.Sensor, "芯片组"))
                .Where(t => !IsStorageLike(t))
                .ToList();
        }

        var motherboardTemp = motherboardCandidates
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

    private void UpdateForegroundUsage(ForegroundAppMetrics? current, DateTimeOffset now)
    {
        lock (_foregroundLock)
        {
            var currKey = current != null
                ? (!string.IsNullOrWhiteSpace(current.ProcessName) ? current.ProcessName! : (current.WindowTitle ?? "Unknown"))
                : null;

            // First assignment
            if (_currentForegroundKey is null)
            {
                _currentForegroundKey = currKey;
                _sessionStartAt = now;
            }
            else if (!string.Equals(_currentForegroundKey, currKey, StringComparison.Ordinal))
            {
                // Session switched: finalize previous session if meets threshold and not excluded
                var duration = now - _sessionStartAt;
                if (_currentForegroundKey != null && duration >= MinForegroundSession && !IsExcludedProcessName(_currentForegroundKey))
                {
                    var seconds = duration.TotalSeconds;
                    if (_foregroundSeconds.TryGetValue(_currentForegroundKey, out var s))
                        _foregroundSeconds[_currentForegroundKey] = s + seconds;
                    else
                        _foregroundSeconds[_currentForegroundKey] = seconds;
                }

                // Start new session
                _currentForegroundKey = currKey;
                _sessionStartAt = now;
            }

            // Update display title for current known process
            if (current != null && !string.IsNullOrWhiteSpace(currKey))
            {
                if (!_foregroundTitles.ContainsKey(currKey))
                {
                    _foregroundTitles[currKey] = current.WindowTitle;
                }
                else if (!string.IsNullOrWhiteSpace(current.WindowTitle))
                {
                    _foregroundTitles[currKey] = current.WindowTitle;
                }
            }
        }
    }

    private IReadOnlyList<TopForegroundApp> GetTopForegroundApps(DateTimeOffset now)
    {
        lock (_foregroundLock)
        {
            // Include ongoing session only if meets threshold and not excluded
            if (_currentForegroundKey != null)
            {
                var duration = now - _sessionStartAt;
                if (duration >= MinForegroundSession && !IsExcludedProcessName(_currentForegroundKey))
                {
                    var seconds = duration.TotalSeconds;
                    if (_foregroundSeconds.TryGetValue(_currentForegroundKey, out var s))
                        _foregroundSeconds[_currentForegroundKey] = Math.Max(s, s); // no-op, keep existing
                    else
                        _foregroundSeconds[_currentForegroundKey] = 0; // ensure key exists for display accumulation below
                }
            }

            var list = _foregroundSeconds
                .Where(kv => kv.Value >= MinForegroundSession.TotalSeconds && !IsExcludedProcessName(kv.Key))
                .OrderByDescending(kv => kv.Value)
                .Take(3)
                .Select(kv => new TopForegroundApp
                {
                    Name = kv.Key,
                    DisplayTitle = _foregroundTitles.TryGetValue(kv.Key, out var title) ? title : null,
                    TotalSeconds = kv.Value
                })
                .ToList();

            // Add ongoing session duration to display if it's in Top or when list has <3
            if (_currentForegroundKey != null)
            {
                var duration = now - _sessionStartAt;
                if (duration >= MinForegroundSession && !IsExcludedProcessName(_currentForegroundKey))
                {
                    var seconds = duration.TotalSeconds;
                    var existing = list.FirstOrDefault(x => string.Equals(x.Name, _currentForegroundKey, StringComparison.OrdinalIgnoreCase));
                    if (existing is null)
                    {
                        list.Add(new TopForegroundApp
                        {
                            Name = _currentForegroundKey,
                            DisplayTitle = _foregroundTitles.TryGetValue(_currentForegroundKey, out var t) ? t : null,
                            TotalSeconds = (_foregroundSeconds.TryGetValue(_currentForegroundKey, out var s) ? s : 0) + seconds
                        });
                    }
                    else
                    {
                        var idx = list.FindIndex(x => string.Equals(x.Name, _currentForegroundKey, StringComparison.OrdinalIgnoreCase));
                        if (idx >= 0)
                        {
                            list[idx] = existing with { TotalSeconds = existing.TotalSeconds + seconds };
                        }
                    }

                    list = list
                        .Where(x => x.TotalSeconds >= MinForegroundSession.TotalSeconds)
                        .OrderByDescending(x => x.TotalSeconds)
                        .Take(3)
                        .ToList();
                }
            }

            return list;
        }
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

        NetworkInterface[] nicSnapshot;
        try
        {
            nicSnapshot = NetworkInterface.GetAllNetworkInterfaces();
        }
        catch
        {
            nicSnapshot = Array.Empty<NetworkInterface>();
        }

        var adapters = _networkHardware
            .Where(h => IsPhysicalNetworkHardware(h, physicalAdapterKeys))
            .Select(h =>
            {
                var identifier = h.Identifier.ToString();
                if (string.IsNullOrWhiteSpace(identifier))
                {
                    identifier = NormalizeAdapterKey(h.Name);
                }

                if (string.IsNullOrWhiteSpace(identifier))
                {
                    identifier = "network-adapter";
                }

                var displayName = string.IsNullOrWhiteSpace(h.Name) ? identifier : h.Name;

                var upload = ToMegabytesPerSecond(FindSensorValue(h, SensorType.Throughput, "Upload", "Sent"));
                var download = ToMegabytesPerSecond(FindSensorValue(h, SensorType.Throughput, "Download", "Received"));

                var ipAddresses = GetIpAddressesForHardware(h, nicSnapshot);
                var nic = FindMatchingInterfaceForHardware(h, nicSnapshot);
                double? linkSpeedMbps = null;
                string? connectionType = null;
                if (nic is not null)
                {
                    try
                    {
                        if (nic.Speed > 0)
                        {
                            linkSpeedMbps = nic.Speed / 1_000_000d; // bits per second -> Mbps
                        }
                        connectionType = nic.NetworkInterfaceType == NetworkInterfaceType.Wireless80211 ? "wireless" : "wired";
                    }
                    catch
                    {
                        // ignore
                    }
                }

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
                    Name = displayName,
                    Identifier = identifier,
                    UploadMBps = upload,
                    DownloadMBps = download,
                    IpAddresses = ipAddresses,
                    LinkSpeedMbps = linkSpeedMbps,
                    ConnectionType = connectionType
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

    private static IReadOnlyList<string> GetIpAddressesForHardware(IHardware hardware, IEnumerable<NetworkInterface> nics)
    {
        var match = FindMatchingInterfaceForHardware(hardware, nics);
        if (match is null)
        {
            return Array.Empty<string>();
        }

        try
        {
            var props = match.GetIPProperties();
            var unicast = props.UnicastAddresses;
            var ips = new List<string>();
            foreach (var addr in unicast)
            {
                var ip = addr.Address;
                if (ip is null)
                {
                    continue;
                }
                // Only keep IPv4 addresses
                if (ip.AddressFamily != AddressFamily.InterNetwork)
                {
                    continue;
                }
                if (IPAddress.IsLoopback(ip))
                {
                    continue;
                }
                ips.Add(ip.ToString());
            }

            // IPv4 only; order is stable now
            ips = ips.ToList();

            return ips;
        }
        catch
        {
            return Array.Empty<string>();
        }
    }

    private static NetworkInterface? FindMatchingInterfaceForHardware(IHardware hardware, IEnumerable<NetworkInterface> nics)
    {
        var hwNameKey = NormalizeAdapterKey(hardware.Name);
        var hwIdKey = NormalizeAdapterKey(hardware.Identifier.ToString());

        static string Norm(string? v)
        {
            if (string.IsNullOrWhiteSpace(v)) return string.Empty;
            var sb = new StringBuilder(v.Length);
            foreach (var ch in v)
            {
                if (char.IsLetterOrDigit(ch)) sb.Append(char.ToLowerInvariant(ch));
            }
            return sb.ToString();
        }

        NetworkInterface? candidate = null;
        foreach (var nic in nics)
        {
            if (nic is null) continue;
            if (nic.OperationalStatus != OperationalStatus.Up) continue;

            var name = Norm(nic.Name);
            var id = Norm(nic.Id);
            var desc = Norm(nic.Description);

            var nameMatch = !string.IsNullOrEmpty(hwNameKey) && (name.Contains(hwNameKey, StringComparison.Ordinal) || desc.Contains(hwNameKey, StringComparison.Ordinal));
            var idMatch = !string.IsNullOrEmpty(hwIdKey) && (id.Contains(hwIdKey, StringComparison.Ordinal) || desc.Contains(hwIdKey, StringComparison.Ordinal));

            if (nameMatch || idMatch)
            {
                candidate = nic;
                break;
            }
        }

        return candidate;
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
        // Prefer dedicated VRAM metrics when available to avoid counting shared memory
        var dedicatedUsed = FindSensorValue(hardware, SensorType.Data,
            "Dedicated Memory Used", "GPU Dedicated Memory Used", "D3D Dedicated Memory Used",
            "Local Memory Used", "VRAM Used (Dedicated)");
        var dedicatedFree = FindSensorValue(hardware, SensorType.Data,
            "Dedicated Memory Free", "GPU Dedicated Memory Free", "D3D Dedicated Memory Free",
            "Local Memory Free", "VRAM Free (Dedicated)");
        var memoryUsed = dedicatedUsed ?? FindSensorValue(hardware, SensorType.Data, "Memory Used", "GPU Memory Used", "VRAM Used");
        var memoryFree = dedicatedFree ?? FindSensorValue(hardware, SensorType.Data, "Memory Free", "GPU Memory Free", "VRAM Free");
        var memoryTotal = FindSensorValue(hardware, SensorType.Data, "Dedicated Memory Total", "GPU Dedicated Memory Total", "Local Memory Total", "Memory Total", "GPU Memory Total", "VRAM Total");

        // NVIDIA: Prefer NVML for accurate dedicated VRAM used/total
        try
        {
            var nameKey = NormalizeAdapterKey(hardware.Name);
            if (!string.IsNullOrEmpty(nameKey) && nameKey.Contains("nvidia", StringComparison.Ordinal))
            {
                var nvmlInfo = TryGetNvidiaMemoryInfoMbViaNvml(nameKey);
                if (nvmlInfo.TotalMb is > 0)
                {
                    memoryTotal = nvmlInfo.TotalMb;
                }
                if (nvmlInfo.UsedMb is >= 0)
                {
                    memoryUsed = nvmlInfo.UsedMb;
                }
                if (nvmlInfo.FreeMb is >= 0)
                {
                    memoryFree = nvmlInfo.FreeMb;
                }
            }
        }
        catch
        {
            // ignore NVML errors, fall back to sensors/WMI below
        }

    var dedicatedMemoryTotal = CalculateDedicatedGpuMemoryTotal(memoryUsed, memoryFree);
        if (dedicatedMemoryTotal is not null)
        {
            memoryTotal = dedicatedMemoryTotal;
        }
        else if (memoryTotal is null && memoryUsed is not null && memoryFree is not null)
        {
            memoryTotal = memoryUsed + memoryFree;
        }

        // WMI fallback for total VRAM (MB) when sensors are missing
        if (memoryTotal is null || memoryTotal <= 0)
        {
            var totalMbFromWmi = GetCachedGpuTotalMemoryMb(hardware);
            if (totalMbFromWmi is > 0)
            {
                memoryTotal = totalMbFromWmi;
            }
        }

        // Prefer computing percentage from used/total when available, otherwise fall back to sensor load
        double? memoryUsagePercentage = null;
        if (memoryUsed is not null && memoryTotal is > 0)
        {
            memoryUsagePercentage = memoryUsed / memoryTotal * 100d;
        }
        else
        {
            memoryUsagePercentage = memoryLoad;
        }

        // If we have percentage and total, but missing used, estimate used = total * pct
        if (memoryUsed is null && memoryUsagePercentage is not null && memoryTotal is > 0)
        {
            memoryUsed = memoryTotal * (memoryUsagePercentage.Value / 100d);
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

    // Prefer dedicated memory (used + free) to avoid counting shared GPU memory.
    private static double? CalculateDedicatedGpuMemoryTotal(double? memoryUsed, double? memoryFree)
    {
        if (memoryUsed is null || memoryFree is null)
        {
            return null;
        }

        var sum = memoryUsed.Value + memoryFree.Value;
        return sum > 0 ? sum : null;
    }

    [SupportedOSPlatform("windows")]
    private double? GetCachedGpuTotalMemoryMb(IHardware hardware)
    {
        // Key by normalized name; if empty fall back to identifier
        var nameKey = NormalizeAdapterKey(hardware.Name);
        var idKey = NormalizeAdapterKey(hardware.Identifier.ToString());
        var cacheKey = !string.IsNullOrEmpty(nameKey) ? nameKey : idKey;
        if (string.IsNullOrEmpty(cacheKey))
        {
            cacheKey = "gpu";
        }

        lock (_gpuInfoCacheLock)
        {
            if (_gpuTotalMemoryMbCache.TryGetValue(cacheKey, out var cached))
            {
                return cached;
            }

            double? resolved = null;
            try
            {
                if (!OperatingSystem.IsWindows())
                {
                    _gpuTotalMemoryMbCache[cacheKey] = null;
                    return null;
                }
                // Prefer NVIDIA NVML if available for accurate VRAM on NVIDIA GPUs
                if (!string.IsNullOrEmpty(nameKey) && nameKey.Contains("nvidia", StringComparison.Ordinal))
                {
                    resolved = TryGetNvidiaTotalMemoryMbViaNvml(nameKey);
                }

                // Fallback: WMI Win32_VideoController (can be inaccurate on some drivers)
                if (resolved is null || resolved <= 0)
                {
                    using var searcher = new ManagementObjectSearcher("SELECT Name, AdapterRAM, PNPDeviceID FROM Win32_VideoController");
                    using var results = searcher.Get();

                    static string Norm(string? v)
                    {
                        if (string.IsNullOrWhiteSpace(v)) return string.Empty;
                        var sb = new StringBuilder(v.Length);
                        foreach (var ch in v)
                        {
                            if (char.IsLetterOrDigit(ch)) sb.Append(char.ToLowerInvariant(ch));
                        }
                        return sb.ToString();
                    }

                    var normName = nameKey;
                    var normId = idKey;

                    ulong bestAdapterRam = 0;
                    ulong fallbackMaxRam = 0;

                    foreach (ManagementObject mo in results)
                    {
                        try
                        {
                            var wmiName = Norm(mo["Name"] as string);
                            var wmiPnp = Norm(mo["PNPDeviceID"] as string);
                            var ramObj = mo["AdapterRAM"]; // bytes

                            if (ramObj is null) continue;

                            ulong ramBytes = 0;
                            try
                            {
                                ramBytes = Convert.ToUInt64(ramObj);
                            }
                            catch
                            {
                                continue;
                            }

                            // Track max as fallback (prefer discrete with largest VRAM)
                            if (ramBytes > fallbackMaxRam)
                            {
                                fallbackMaxRam = ramBytes;
                            }

                            // Strong match by name or PNP ID
                            var nameMatch = !string.IsNullOrEmpty(normName) && wmiName.Contains(normName, StringComparison.Ordinal);
                            var idMatch = !string.IsNullOrEmpty(normId) && wmiPnp.Contains(normId, StringComparison.Ordinal);
                            if (nameMatch || idMatch)
                            {
                                if (ramBytes > bestAdapterRam)
                                {
                                    bestAdapterRam = ramBytes;
                                }
                            }
                        }
                        catch
                        {
                            // ignore this entry
                        }
                    }

                    var selected = bestAdapterRam > 0 ? bestAdapterRam : fallbackMaxRam;
                    if (selected > 0)
                    {
                        // Convert bytes -> MB
                        resolved = selected / 1024d / 1024d;
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Failed to query GPU total memory via WMI");
            }

            _gpuTotalMemoryMbCache[cacheKey] = resolved;
            return resolved;
        }
    }

    [SupportedOSPlatform("windows")]
    private double? TryGetNvidiaTotalMemoryMbViaNvml(string normGpuName)
    {
        try
        {
            if (nvmlInit_v2() != 0) return null;
            try
            {
                if (nvmlDeviceGetCount_v2(out var count) != 0 || count <= 0)
                {
                    return null;
                }

                double? bestMb = null;
                Span<byte> nameBuf = stackalloc byte[96];
                for (uint i = 0; i < (uint)count; i++)
                {
                    if (nvmlDeviceGetHandleByIndex_v2(i, out var handle) != 0)
                    {
                        continue;
                    }

                    if (nvmlDeviceGetName(handle, ref nameBuf[0], (uint)nameBuf.Length) != 0)
                    {
                        // still try memory even without name
                    }

                    var deviceName = Encoding.ASCII.GetString(nameBuf).TrimEnd('\0', ' ', '\t', '\r', '\n');
                    var normName = NormalizeAdapterKey(deviceName);

                    nvmlMemory_t mem;
                    if (nvmlDeviceGetMemoryInfo(handle, out mem) != 0)
                    {
                        continue;
                    }

                    var totalMb = mem.total / 1024d / 1024d;
                    // Prefer name match; otherwise keep the largest NVIDIA VRAM as fallback
                    if (!string.IsNullOrEmpty(normGpuName) && normName.Contains(normGpuName, StringComparison.Ordinal))
                    {
                        return totalMb;
                    }

                    if (bestMb is null || totalMb > bestMb)
                    {
                        bestMb = totalMb;
                    }
                }

                return bestMb;
            }
            finally
            {
                _ = nvmlShutdown();
            }
        }
        catch (DllNotFoundException)
        {
            return null;
        }
        catch
        {
            return null;
        }
    }

    [SupportedOSPlatform("windows")]
    private (double? TotalMb, double? UsedMb, double? FreeMb) TryGetNvidiaMemoryInfoMbViaNvml(string normGpuName)
    {
        try
        {
            if (nvmlInit_v2() != 0) return (null, null, null);
            try
            {
                if (nvmlDeviceGetCount_v2(out var count) != 0 || count <= 0)
                {
                    return (null, null, null);
                }

                (double? TotalMb, double? UsedMb, double? FreeMb) best = (null, null, null);
                Span<byte> nameBuf = stackalloc byte[96];
                for (uint i = 0; i < (uint)count; i++)
                {
                    if (nvmlDeviceGetHandleByIndex_v2(i, out var handle) != 0)
                    {
                        continue;
                    }

                    _ = nvmlDeviceGetName(handle, ref nameBuf[0], (uint)nameBuf.Length);
                    var deviceName = Encoding.ASCII.GetString(nameBuf).TrimEnd('\0', ' ', '\t', '\r', '\n');
                    var normName = NormalizeAdapterKey(deviceName);

                    if (nvmlDeviceGetMemoryInfo(handle, out var mem) != 0)
                    {
                        continue;
                    }

                    var totalMb = mem.total / 1024d / 1024d;
                    var usedMb = mem.used / 1024d / 1024d;
                    var freeMb = mem.free / 1024d / 1024d;

                    // Prefer exact/contains match; else keep the largest VRAM as fallback
                    if (!string.IsNullOrEmpty(normGpuName) && normName.Contains(normGpuName, StringComparison.Ordinal))
                    {
                        return (totalMb, usedMb, freeMb);
                    }

                    if (best.TotalMb is null || totalMb > best.TotalMb)
                    {
                        best = (totalMb, usedMb, freeMb);
                    }
                }

                return best;
            }
            finally
            {
                _ = nvmlShutdown();
            }
        }
        catch (DllNotFoundException)
        {
            return (null, null, null);
        }
        catch
        {
            return (null, null, null);
        }
    }

    // NVML interop (NVIDIA-only). Functions return 0 (NVML_SUCCESS) on success.
    [DllImport("nvml.dll", ExactSpelling = true)]
    private static extern int nvmlInit_v2();

    [DllImport("nvml.dll", ExactSpelling = true)]
    private static extern int nvmlShutdown();

    [DllImport("nvml.dll", ExactSpelling = true)]
    private static extern int nvmlDeviceGetCount_v2(out int deviceCount);

    [DllImport("nvml.dll", ExactSpelling = true)]
    private static extern int nvmlDeviceGetHandleByIndex_v2(uint index, out IntPtr device);

    [DllImport("nvml.dll", ExactSpelling = true)]
    private static extern int nvmlDeviceGetName(IntPtr device, ref byte name, uint length);

    [StructLayout(LayoutKind.Sequential)]
    private struct nvmlMemory_t
    {
        public ulong total;
        public ulong free;
        public ulong used;
    }

    [DllImport("nvml.dll", ExactSpelling = true)]
    private static extern int nvmlDeviceGetMemoryInfo(IntPtr device, out nvmlMemory_t memory);

    private MemoryMetrics CollectMemoryMetrics()
    {
        MemoryMetrics metrics;
        var memoryHardware = _memoryHardware;

        if (_memoryFallback || memoryHardware is null)
        {
            if (!OperatingSystem.IsWindows())
            {
                metrics = new MemoryMetrics();
            }
            else
            {
                metrics = GetMemoryMetricsFromSystem();
            }
        }
        else
        {
            var usedMemory = FindSensorValue(memoryHardware, SensorType.Data, "Used", "Memory Used");
            var availableMemory = FindSensorValue(memoryHardware, SensorType.Data, "Available", "Free");

            double? totalMemory = null;
            if (usedMemory.HasValue && availableMemory.HasValue)
            {
                totalMemory = usedMemory + availableMemory;
            }

            var memoryUsage = FindSensorValue(memoryHardware, SensorType.Load, "Memory", "Used");
            var memoryClock = FindSensorValue(memoryHardware, SensorType.Clock, "Memory", "DRAM", "RAM");

            metrics = new MemoryMetrics
            {
                TotalGb = totalMemory is > 0 ? totalMemory / 1024d : totalMemory,
                UsedGb = usedMemory is > 0 ? usedMemory / 1024d : usedMemory,
                AvailableGb = availableMemory is > 0 ? availableMemory / 1024d : availableMemory,
                UsagePercentage = memoryUsage,
                SpeedMhz = memoryClock,
                VirtualTotalGb = null
            };
        }

        if (OperatingSystem.IsWindows())
        {
            var enrichedSpeed = metrics.SpeedMhz ?? GetCachedMemorySpeedMhz();
            var enrichedVirtual = metrics.VirtualTotalGb ?? GetCachedVirtualTotalGb();
            if (enrichedSpeed != metrics.SpeedMhz || enrichedVirtual != metrics.VirtualTotalGb)
            {
                metrics = metrics with
                {
                    SpeedMhz = enrichedSpeed,
                    VirtualTotalGb = enrichedVirtual
                };
            }
        }

        return metrics;
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
    private double? GetCachedMemorySpeedMhz()
    {
        lock (_memoryInfoCacheLock)
        {
            var now = DateTimeOffset.UtcNow;
            if (_memorySpeedCachedAt != DateTimeOffset.MinValue &&
                now - _memorySpeedCachedAt < MemoryInfoCacheDuration)
            {
                return _cachedMemorySpeedMhz;
            }

            var speed = GetMemorySpeedFromWmi();
            _cachedMemorySpeedMhz = speed;
            _memorySpeedCachedAt = now;
            return speed;
        }
    }

    [SupportedOSPlatform("windows")]
    private double? GetCachedVirtualTotalGb()
    {
        lock (_memoryInfoCacheLock)
        {
            var now = DateTimeOffset.UtcNow;
            if (_virtualMemoryCachedAt != DateTimeOffset.MinValue &&
                now - _virtualMemoryCachedAt < MemoryInfoCacheDuration)
            {
                return _cachedVirtualTotalGb;
            }

            var total = GetVirtualMemoryTotalFromWmi();
            _cachedVirtualTotalGb = total;
            _virtualMemoryCachedAt = now;
            return total;
        }
    }

    [SupportedOSPlatform("windows")]
    private double? GetMemorySpeedFromWmi()
    {
        try
        {
            using var searcher = new ManagementObjectSearcher("SELECT ConfiguredClockSpeed, Speed FROM Win32_PhysicalMemory");
            using var modules = searcher.Get();
            double? best = null;

            foreach (ManagementObject module in modules)
            {
                try
                {
                    var candidate = ToClockSpeedMhz(module["ConfiguredClockSpeed"]) ?? ToClockSpeedMhz(module["Speed"]);
                    if (candidate is > 0)
                    {
                        best = best is null ? candidate : Math.Max(best.Value, candidate.Value);
                    }
                }
                finally
                {
                    module.Dispose();
                }
            }

            return best;
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "使用 WMI 获取内存速度失败");
            return null;
        }
    }

    [SupportedOSPlatform("windows")]
    private double? GetVirtualMemoryTotalFromWmi()
    {
        try
        {
            using var searcher = new ManagementObjectSearcher("SELECT TotalVirtualMemorySize FROM Win32_OperatingSystem");
            using var results = searcher.Get();
            foreach (ManagementObject os in results)
            {
                try
                {
                    var total = ToVirtualTotalGb(os["TotalVirtualMemorySize"]);
                    if (total.HasValue)
                    {
                        return total;
                    }
                }
                finally
                {
                    os.Dispose();
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "使用 WMI 获取虚拟内存总量失败");
        }

        return null;
    }

    private static double? ToClockSpeedMhz(object? value)
    {
        if (value is null)
        {
            return null;
        }

        try
        {
            var clock = Convert.ToDouble(value, CultureInfo.InvariantCulture);
            return clock > 0 ? clock : null;
        }
        catch
        {
            try
            {
                var clock = Convert.ToUInt32(value, CultureInfo.InvariantCulture);
                return clock > 0 ? clock : (double?)null;
            }
            catch
            {
                return null;
            }
        }
    }

    private static double? ToVirtualTotalGb(object? value)
    {
        if (value is null)
        {
            return null;
        }

        try
        {
            var kilobytes = Convert.ToUInt64(value, CultureInfo.InvariantCulture);
            return ConvertKilobytesToGigabytes(kilobytes);
        }
        catch
        {
            return null;
        }
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
            var virtualTotalGb = ConvertBytesToGigabytes(status.TotalVirtual);

            metrics = new MemoryMetrics
            {
                TotalGb = totalGb,
                UsedGb = usedGb,
                AvailableGb = freeGb,
                UsagePercentage = usagePercentage,
                SpeedMhz = null,
                VirtualTotalGb = virtualTotalGb > 0 ? virtualTotalGb : (double?)null
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
            using var searcher = new ManagementObjectSearcher("SELECT TotalVisibleMemorySize, FreePhysicalMemory, TotalVirtualMemorySize FROM Win32_OperatingSystem");
            using var results = searcher.Get();
            foreach (ManagementObject os in results)
            {
                try
                {
                    var totalKb = Convert.ToUInt64(os["TotalVisibleMemorySize"], CultureInfo.InvariantCulture);
                    var freeKb = Convert.ToUInt64(os["FreePhysicalMemory"], CultureInfo.InvariantCulture);

                    var totalGb = ConvertKilobytesToGigabytes(totalKb);
                    var freeGb = ConvertKilobytesToGigabytes(freeKb);
                    var usedGb = totalGb - freeGb;
                    var usagePercentage = totalGb > 0 ? (usedGb / totalGb) * 100d : (double?)null;

                    double? virtualTotalGb = null;
                    if (os["TotalVirtualMemorySize"] is not null)
                    {
                        var virtualKb = Convert.ToUInt64(os["TotalVirtualMemorySize"], CultureInfo.InvariantCulture);
                        virtualTotalGb = ConvertKilobytesToGigabytes(virtualKb);
                    }

                    return new MemoryMetrics
                    {
                        TotalGb = totalGb,
                        UsedGb = usedGb,
                        AvailableGb = freeGb,
                        UsagePercentage = usagePercentage,
                        SpeedMhz = null,
                        VirtualTotalGb = virtualTotalGb
                    };
                }
                finally
                {
                    os.Dispose();
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "获取系统内存信息失败");
        }

        return new MemoryMetrics
        {
            TotalGb = null,
            UsedGb = null,
            AvailableGb = null,
            UsagePercentage = null,
            SpeedMhz = null,
            VirtualTotalGb = null
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
