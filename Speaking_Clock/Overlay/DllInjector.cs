using System.ComponentModel;
using System.Diagnostics;
using Speaking_Clock;
using Vanara.PInvoke;

namespace Speaking_clock.Overlay;

/// <summary>
///     Provides functionality to inject a DLL into a remote process using the LoadLibrary method.
///     It automatically handles both 32-bit and 64-bit processes.
/// </summary>
public static class DllInjector
{
    private static readonly string dll32Path = "SpeakingClockOverlayx86.dll";
    private static readonly string dll64Path = "SpeakingClockOverlayx64.dll";
    internal static Process? CurrentProcess;

    internal static void InjectToForeground(Process fullscreenProcess)
    {
        // Get process ID from window handle
        if (fullscreenProcess.Id == 0)
        {
            Debug.WriteLine("No process found for foreground window.");
            return;
        }

        // Determine if target process is 32-bit
        var is32Bit = IsProcess32Bit(fullscreenProcess);

        // Pick correct DLL and injector
        var dllPath = is32Bit ? dll32Path : dll64Path;
        var injectorExe = is32Bit ? "Injector_x86.exe" : "Injector_x64.exe";

        var startInfo = new ProcessStartInfo
        {
            FileName = Path.Combine(Beallitasok.BasePath, "DllInjector", injectorExe),
            Arguments =
                $"inject \"{fullscreenProcess.ProcessName}.exe\" \"{Path.Combine(Beallitasok.BasePath, "DllInjector", dllPath)}\" 1000",
            WorkingDirectory = Path.Combine(Beallitasok.BasePath, "DllInjector"),
            CreateNoWindow = true,
            UseShellExecute = true, // Required for Verb
            Verb = "runas", // Run as administrator
            WindowStyle = ProcessWindowStyle.Hidden
        };

        Process.Start(startInfo);

        Debug.WriteLine($"Injected {dllPath} into {fullscreenProcess.ProcessName}.exe ({(is32Bit ? "x86" : "x64")}).");

        CurrentProcess = fullscreenProcess;

        CurrentProcess.WaitForExit();
        Beallitasok.DeactivateLegacyOverlay();
        Debug.WriteLine($"{CurrentProcess.ProcessName} exited, resetting DLL injection state.");
        CurrentProcess = null;
        Beallitasok.OverlayMode = "";
        if (Beallitasok.PlayingRadio)
            if (Beallitasok.radioPlayerWidget == null || Beallitasok.radioPlayerWidget.IsDisposed)
                OnlineRadioPlayer.Stop();
    }


    private static bool IsProcess32Bit(Process process)
    {
        if (!Environment.Is64BitOperatingSystem)
            return true;

        if (!Kernel32.IsWow64Process(process.Handle, out var isWow64))
            throw new Win32Exception();

        return isWow64;
    }

    internal static bool IsForceSimpleOverlay(string procName)
    {
        var UserBlockedProcesses = Beallitasok.ÁtfedésSection["UseSimpleOverlay"].StringValue.Split(";");
        string[] blockedProcesses =
        {
            "chrome", "msedge", "firefox", "opera", "brave", "iexplore",
            Path.GetFileNameWithoutExtension(Beallitasok.DefaultBrowerPath)
        };

        return blockedProcesses.Contains(Path.GetFileNameWithoutExtension(procName),
                   StringComparer.OrdinalIgnoreCase) ||
               UserBlockedProcesses.Contains(Path.GetFileName(procName), StringComparer.OrdinalIgnoreCase);
    }

    internal static bool IsForcedExternal(string procName)
    {
        var ForcedProcesses = Beallitasok.ÁtfedésSection["DontHookRendering"].StringValue
            .Split(";", StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        string[] ForcedProcessesBuiltIn =
        {
            "hd-player", "vlc", "potplayer", "mpc-hc", "wmplayer", "PowerDVD"
        };

        return ForcedProcessesBuiltIn.Any(builtIn =>
                   Path.GetFileNameWithoutExtension(procName)
                       .StartsWith(builtIn, StringComparison.OrdinalIgnoreCase))
               || ForcedProcesses.Contains(Path.GetFileName(procName), StringComparer.OrdinalIgnoreCase);
    }
}