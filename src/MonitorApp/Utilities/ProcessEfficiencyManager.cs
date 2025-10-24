using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;
using Microsoft.Extensions.Logging;

namespace MonitorApp.Utilities;

internal static class ProcessEfficiencyManager
{
    private const uint PROCESS_POWER_THROTTLING_CURRENT_VERSION = 1;
    private const uint PROCESS_POWER_THROTTLING_EXECUTION_SPEED = 0x1;
    private const uint IDLE_PRIORITY_CLASS = 0x00000040;
    private const int THREAD_PRIORITY_IDLE = -15;
    internal const int ThreadPriorityNormal = 0;
    private const int THREAD_PRIORITY_ERROR_RETURN = 0x7fffffff;
    private const byte ThreadEcoApplied = 0x1;
    private const byte ThreadIdlePriorityApplied = 0x2;

    private static int _initialized;
    private static System.Threading.Timer? _threadRefreshTimer;
    private static readonly ConcurrentDictionary<int, byte> ThreadStates = new();
    private static readonly TimeSpan ThreadRefreshInterval = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan ThreadRefreshDuration = TimeSpan.FromMinutes(2);
    private static readonly int MaxRefreshTicks = (int)Math.Ceiling(ThreadRefreshDuration.TotalMilliseconds / ThreadRefreshInterval.TotalMilliseconds);
    private static int _refreshTicks;

    public static void EnableForCurrentProcess(ILogger? logger = null)
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        if (!OperatingSystem.IsWindowsVersionAtLeast(10, 0, 22000))
        {
            logger?.LogDebug("当前 Windows 版本不支持效能模式 API。");
            return;
        }

        if (Interlocked.Exchange(ref _initialized, 1) == 1)
        {
            logger?.LogDebug("效能模式已初始化，跳过重复调用。");
            return;
        }

        ThreadStates.Clear();

        try
        {
            using var process = Process.GetCurrentProcess();
            var safeHandle = process.SafeHandle;
            var addRef = false;

            try
            {
                safeHandle.DangerousAddRef(ref addRef);
                var rawHandle = safeHandle.DangerousGetHandle();

                var state = new ProcessPowerThrottlingState
                {
                    Version = PROCESS_POWER_THROTTLING_CURRENT_VERSION,
                    ControlMask = PROCESS_POWER_THROTTLING_EXECUTION_SPEED,
                    StateMask = PROCESS_POWER_THROTTLING_EXECUTION_SPEED
                };

                var processEcoApplied = false;
                if (!SetProcessInformation(rawHandle, ProcessInformationClass.ProcessPowerThrottling, ref state, (uint)Marshal.SizeOf<ProcessPowerThrottlingState>()))
                {
                    var error = Marshal.GetLastWin32Error();
                    var message = $"启用效能模式失败，Win32 错误码 {error} (0x{error:X}).";
                    logger?.LogWarning(message);
                    WindowsEventLogger.LogWarning(message);
                }
                else
                {
                    processEcoApplied = true;
                    var message = $"已为进程 {process.ProcessName} (PID {process.Id}) 启用 Windows 效能模式。";
                    logger?.LogInformation(message);
                    WindowsEventLogger.LogInformation(message);
                }

                if (!SetPriorityClass(rawHandle, IDLE_PRIORITY_CLASS))
                {
                    var error = Marshal.GetLastWin32Error();
                    logger?.LogWarning("进程优先级设置为 IDLE 失败，Win32 错误 {Error}", error);
                }
                else
                {
                    var message = $"已为进程 {process.ProcessName} (PID {process.Id}) 设置 IDLE_PRIORITY_CLASS。";
                    logger?.LogInformation(message);
                    if (!processEcoApplied)
                    {
                        WindowsEventLogger.LogInformation(message);
                    }
                }

                ApplyEcoToThreads(logger);
                ScheduleThreadRefresh(logger);
            }
            finally
            {
                if (addRef)
                {
                    safeHandle.DangerousRelease();
                }
            }
        }
        catch (Exception ex)
        {
            logger?.LogWarning(ex, "启用效能模式时发生异常");
            WindowsEventLogger.LogWarning($"启用效能模式时发生异常：{ex}");
        }
    }

    private static void ScheduleThreadRefresh(ILogger? logger)
    {
        _threadRefreshTimer?.Dispose();
        _refreshTicks = 0;
        _threadRefreshTimer = new System.Threading.Timer(_ =>
        {
            try
            {
                ApplyEcoToThreads(logger);

                if (Interlocked.Increment(ref _refreshTicks) >= MaxRefreshTicks)
                {
                    _threadRefreshTimer?.Dispose();
                    _threadRefreshTimer = null;
                }
            }
            catch
            {
                // ignore timer callback failures
            }
        }, null, ThreadRefreshInterval, ThreadRefreshInterval);
    }

    private static void ApplyEcoToThreads(ILogger? logger)
    {
        try
        {
            using var process = Process.GetCurrentProcess();
            var seenThreads = new HashSet<int>();
            foreach (ProcessThread thread in process.Threads)
            {
                try
                {
                    var threadId = thread.Id;
                    seenThreads.Add(threadId);

                    using var handle = OpenThreadHandle(threadId);
                    if (handle is null || handle.IsInvalid)
                    {
                        continue;
                    }

                    ThreadStates.TryGetValue(threadId, out var flags);

                    var state = new ThreadPowerThrottlingState
                    {
                        Version = PROCESS_POWER_THROTTLING_CURRENT_VERSION,
                        ControlMask = PROCESS_POWER_THROTTLING_EXECUTION_SPEED,
                        StateMask = PROCESS_POWER_THROTTLING_EXECUTION_SPEED
                    };

                    var ecoApplied = (flags & ThreadEcoApplied) != 0;
                    if (!ecoApplied)
                    {
                        if (SetThreadInformation(handle.DangerousGetHandle(), ThreadInformationClass.ThreadPowerThrottling, ref state, (uint)Marshal.SizeOf<ThreadPowerThrottlingState>()))
                        {
                            flags |= ThreadEcoApplied;
                            logger?.LogDebug("线程 {ThreadId} 已启用效能模式。", threadId);
                        }
                        else
                        {
                            var error = Marshal.GetLastWin32Error();
                            logger?.LogDebug("线程 {ThreadId} 启用效能模式失败，Win32 错误 {Error}", threadId, error);
                        }
                    }

                    var idlePriorityApplied = (flags & ThreadIdlePriorityApplied) != 0;
                    if (!idlePriorityApplied)
                    {
                        if (SetThreadPriority(handle.DangerousGetHandle(), THREAD_PRIORITY_IDLE))
                        {
                            flags |= ThreadIdlePriorityApplied;
                            logger?.LogDebug("线程 {ThreadId} 已设置为 IDLE 优先级。", threadId);
                        }
                        else
                        {
                            var error = Marshal.GetLastWin32Error();
                            logger?.LogDebug("线程 {ThreadId} 设置 IDLE 优先级失败，Win32 错误 {Error}", threadId, error);
                        }
                    }

                    ThreadStates[threadId] = flags;
                }
                catch
                {
                // ignore thread failures
                }
            }

            foreach (var key in ThreadStates.Keys)
            {
                if (!seenThreads.Contains(key))
                {
                    ThreadStates.TryRemove(key, out _);
                }
            }
        }
        catch
        {
            // ignore process enumeration failures
        }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetProcessInformation(
        IntPtr hProcess,
        ProcessInformationClass processInformationClass,
        ref ProcessPowerThrottlingState processInformation,
        uint processInformationSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetThreadInformation(
        IntPtr hThread,
        ThreadInformationClass threadInformationClass,
        ref ThreadPowerThrottlingState threadInformation,
        uint threadInformationSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetPriorityClass(IntPtr hProcess, uint dwPriorityClass);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetThreadPriority(IntPtr hThread, int nPriority);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern int GetThreadPriority(IntPtr hThread);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentThread();

    internal static T RunWithThreadPriority<T>(Func<T> callback, int priority = ThreadPriorityNormal)
    {
        if (!OperatingSystem.IsWindows())
        {
            return callback();
        }

        IntPtr threadHandle = IntPtr.Zero;
        int originalPriority = ThreadPriorityNormal;
        var priorityChanged = false;

        try
        {
            threadHandle = GetCurrentThread();
            if (threadHandle == IntPtr.Zero)
            {
                return callback();
            }

            originalPriority = GetThreadPriority(threadHandle);
            if (originalPriority == THREAD_PRIORITY_ERROR_RETURN)
            {
                originalPriority = ThreadPriorityNormal;
            }

            if (originalPriority != priority && SetThreadPriority(threadHandle, priority))
            {
                priorityChanged = true;
            }
        }
        catch
        {
            // ignore and execute callback with current priority
        }

        try
        {
            return callback();
        }
        finally
        {
            if (priorityChanged)
            {
                try
                {
                    _ = SetThreadPriority(threadHandle, originalPriority);
                }
                catch
                {
                    // ignore restore failures
                }
            }
        }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenThread(ThreadAccess desiredAccess, bool inheritHandle, uint threadId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    private enum ProcessInformationClass
    {
        ProcessMemoryPriority = 0,
        ProcessMemoryExhaustionInfo = 1,
        ProcessAppMemoryInfo = 2,
        ProcessInPrivateInfo = 3,
        ProcessPowerThrottling = 4
    }

    private enum ThreadInformationClass
    {
        ThreadMemoryPriority = 0,
        ThreadAbsoluteCpuPriority = 1,
        ThreadDynamicCodePolicy = 2,
        ThreadPowerThrottling = 4
    }

    [Flags]
    private enum ThreadAccess : uint
    {
        SetInformation = 0x0020,
        QueryInformation = 0x0040
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessPowerThrottlingState
    {
        public uint Version;
        public uint ControlMask;
        public uint StateMask;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ThreadPowerThrottlingState
    {
        public uint Version;
        public uint ControlMask;
        public uint StateMask;
    }

    private sealed class SafeThreadHandle : SafeHandle
    {
        public SafeThreadHandle() : base(IntPtr.Zero, true)
        {
        }

        public SafeThreadHandle(IntPtr preexistingHandle) : base(IntPtr.Zero, true)
        {
            SetHandle(preexistingHandle);
        }

        public override bool IsInvalid => handle == IntPtr.Zero || handle == new IntPtr(-1);

        protected override bool ReleaseHandle() => CloseHandle(handle);
    }

    private static SafeThreadHandle? OpenThreadHandle(int threadId)
    {
        var rawHandle = OpenThread(ThreadAccess.SetInformation | ThreadAccess.QueryInformation, false, (uint)threadId);
        if (rawHandle == IntPtr.Zero)
        {
            return null;
        }

        return new SafeThreadHandle(rawHandle);
    }
}
