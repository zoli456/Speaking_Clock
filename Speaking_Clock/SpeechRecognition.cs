using System.Diagnostics;
using System.Runtime.InteropServices;
using ManagedBass;
using Vanara.PInvoke;
using Vosk;

namespace Speaking_Clock;

internal class SpeechRecognition
{
    private static readonly User32.SetWindowPosFlags TopmostFlags = User32.SetWindowPosFlags.SWP_NOMOVE |
                                                          User32.SetWindowPosFlags.SWP_NOSIZE |
                                                          User32.SetWindowPosFlags.SWP_SHOWWINDOW;

    internal static bool IsRunning;
    private static int _recordingDevice;
    private static VoskRecognizer _recognizer;
    private static Model _voskModel;
    internal static string[] Temp;

    // Callback for recording
    private static bool RecordingCallback(int handle, IntPtr buffer, int length, IntPtr user)
    {
        if (!IsRunning || length <= 0 || _recognizer == null) return true;

        try
        {
            var data = new byte[length];
            Marshal.Copy(buffer, data, 0, length);

            if (_recognizer.AcceptWaveform(data, length))
            {
                Temp = _recognizer.FinalResult().Split("\"");
                if (Temp.Length > 3 && Temp[3].Length > 0)
                    ProcessResult(Temp[3]);
            }
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"Recording callback error: {ex.Message}");
        }

        return true;
    }

    internal static void ActivateRecognition(string modelPath)
    {
        if (IsRunning) return;

        try
        {
            // Validate model path
            if (!Directory.Exists(modelPath))
            {
                Beallitasok.HangfelismerésSection["Bekapcsolva"].BoolValue = false;
                Debug.WriteLine($"Model path not found: {modelPath}");
                return;
            }

            if (!IsRecordingDeviceInitialized())
                if (!Bass.RecordInit())
                    Debug.WriteLine("RecordInit failed: " + Bass.LastError);
            // return;
            // Load or reload model and recognizer
            _voskModel?.Dispose();
            _voskModel = new Model(modelPath);

            _recognizer?.Dispose();
            _recognizer = new VoskRecognizer(_voskModel, 16000.0f);

            // Start or restart recording
            if (_recordingDevice == 0)
            {
                _recordingDevice = Bass.RecordStart(16000, 1, BassFlags.Default, 100, RecordingCallback, IntPtr.Zero);
                if (_recordingDevice == 0)
                {
                    Debug.WriteLine("RecordStart failed: " + Bass.LastError);
                    return;
                }
            }
            else
            {
                Bass.ChannelPlay(_recordingDevice);
            }

            IsRunning = true;
            Debug.WriteLine("Recording started successfully");
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"ActivateRecognition error: {ex.Message}");
            DeactivateRecognition();
        }
    }

    private static bool IsRecordingDeviceInitialized()
    {
        try
        {
            return Bass.RecordGetDeviceInfo(Bass.CurrentDevice, out var deviceInfo) &&
                   deviceInfo.IsInitialized;
        }
        catch
        {
            return false;
        }
    }

    internal static void DeactivateRecognition()
    {
        try
        {
            if (_recordingDevice != 0)
            {
                Bass.ChannelPause(_recordingDevice);
                //Bass.RecordFree();
                _voskModel?.Dispose();
                _recognizer?.Dispose();
            }
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"DeactivateRecognition error: {ex.Message}");
        }
        finally
        {
            IsRunning = false;
        }
    }

    // Add this for complete cleanup when closing application
    internal static void FullCleanup()
    {
        try
        {
            if (_recordingDevice != 0)
            {
                Bass.ChannelStop(_recordingDevice);
                _recordingDevice = 0;
                Bass.RecordFree();
            }

            _recognizer?.Dispose();
            _recognizer = null;

            _voskModel?.Dispose();
            _voskModel = null;
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"FullCleanup error: {ex.Message}");
        }
        finally
        {
            IsRunning = false;
        }
    }

    /// <summary>
    ///     Process the recognized result.
    /// </summary>
    /// <param name="result">The recognized word.</param>
    private static void ProcessResult(string result)
    {
        Debug.WriteLine(result);
        // Process the recognized result
        switch (result)
        {
            case "time":
            {
                Debug.WriteLine("Jelenlegi idő felolvasás");
                Beallitasok.Most_mod();
                return;
            }
            case "today":
            {
                Debug.WriteLine("Mostani időjárás felolvasás");
                Beallitasok.AnnounceWeather();
                return;
            }
            case "tomorrow":
            {
                Debug.WriteLine("Holnapi időjárás felolvasás");
                Beallitasok.AnnounceForecast();
                return;
            }
            case "green":
            {
                Debug.WriteLine("Mai névnap felolvasás");
                Beallitasok.AnnounceNameDay();
                return;
            }
            case "browser":
            {
                if (!Beallitasok.FullScreenApplicationRunning)
                    Task.Run(() =>
                    {
                        Debug.WriteLine("Böngésző megnyitás");
                        var browserProcess = Process.Start(Utils.GetDefaultBrowser());
                        browserProcess.WaitForInputIdle();
                        var hWnd = new HWND(browserProcess.MainWindowHandle);
                        User32.SetForegroundWindow(hWnd);
                        User32.SetWindowPos(hWnd, HWND.HWND_TOPMOST, 0, 0, 0, 0, TopmostFlags);
                    });
                return;
            }
            case "calculator":
            {
                if (!Beallitasok.FullScreenApplicationRunning)
                    Task.Run(() =>
                    {
                        Debug.WriteLine("Számológép megnyitás");
                        var calculatorProcess = Process.Start("calc.exe");
                        calculatorProcess.WaitForInputIdle();
                        var hWnd = new HWND(calculatorProcess.MainWindowHandle);
                        User32.SetForegroundWindow(hWnd);
                        User32.SetWindowPos(hWnd, HWND.HWND_TOP, 0, 0, 0, 0, TopmostFlags);
                    });

                return;
            }
        }

        if (result == Beallitasok.HangfelismerésSection["Kiváltó_Szó"].StringValue)
            Beallitasok.SimulateRealKeyPress(
                Utils.CharToHexKeyCode(Beallitasok.HangfelismerésSection["Eredmény_billentyű"].StringValue));
    }

    /// <summary>
    ///     Enable voice recognition by unpausing the recording
    /// </summary>
    internal static void EnableVoiceRecognition()
    {
        if (!Beallitasok.HangfelismerésSection["Bekapcsolva"].BoolValue ||
            _recordingDevice == 0 ||
            IsRunning)
            return;

        try
        {
            Bass.ChannelPlay(_recordingDevice); // Unpauses the channel
            IsRunning = true;
            Debug.WriteLine("Voice recognition unpaused");
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"Error unpausing voice recognition: {ex.Message}");
        }
    }

    /// <summary>
    ///     Disable voice recognition by pausing the recording
    /// </summary>
    internal static void DisableVoiceRecognition()
    {
        if (_recordingDevice == 0 || !IsRunning) return;

        try
        {
            Bass.ChannelPause(_recordingDevice);
            IsRunning = false;
            Debug.WriteLine("Voice recognition paused");
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"Error pausing voice recognition: {ex.Message}");
        }
    }
}