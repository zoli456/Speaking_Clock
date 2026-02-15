using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net.Http.Headers;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Microsoft.Win32;
using SharpCompress.Archives;
using SharpCompress.Archives.Zip;
using SharpCompress.Common;
using SharpCompress.Readers;
using Speaking_clock.Properties;
using Telerik.WinControls.UI;
using Vanara.PInvoke;
using static Vanara.PInvoke.Ole32;
using static Vanara.PInvoke.CoreAudio;

namespace Speaking_Clock;

internal class Utils
{
    /// <summary>
    ///     Converts a character or key name to a hex keycode.
    /// </summary>
    /// <param name="key">Input character or key name.</param>
    /// <returns>Hex keycode, or <c>0x00</c> if not recognized.</returns>
    internal static User32.VK CharToHexKeyCode(string key)
    {
        if (string.IsNullOrWhiteSpace(key))
            return 0x00;

        var charToKeyCodeMap = new Dictionary<string, byte>(StringComparer.OrdinalIgnoreCase)
        {
            // Function keys
            { "f1", 0x70 }, { "f2", 0x71 }, { "f3", 0x72 }, { "f4", 0x73 },
            { "f5", 0x74 }, { "f6", 0x75 }, { "f7", 0x76 }, { "f8", 0x77 },
            { "f9", 0x78 }, { "f10", 0x79 }, { "f11", 0x7A }, { "f12", 0x7B },

            // Control/navigation
            { "esc", 0x1B }, { "enter", 0x0D }, { "space", 0x20 }, { "tab", 0x09 },
            { "shift", 0x10 }, { "ctrl", 0x11 }, { "alt", 0x12 }, { "backspace", 0x08 },
            { "capslock", 0x14 }, { "leftarrow", 0x25 }, { "uparrow", 0x26 },
            { "rightarrow", 0x27 }, { "downarrow", 0x28 }, { "insert", 0x2D },
            { "delete", 0x2E }, { "home", 0x24 }, { "end", 0x23 }, { "pageup", 0x21 },
            { "pagedown", 0x22 }, { "numlock", 0x90 }, { "scrolllock", 0x91 },
            { "printscreen", 0x2C }, { "pause", 0x13 },
            { "lshift", 0xA0 }, { "rshift", 0xA1 }, { "lcontrol", 0xA2 }, { "rcontrol", 0xA3 },
            { "lalt", 0xA4 }, { "ralt", 0xA5 },

            // Numbers
            { "0", 0x30 }, { "1", 0x31 }, { "2", 0x32 }, { "3", 0x33 }, { "4", 0x34 },
            { "5", 0x35 }, { "6", 0x36 }, { "7", 0x37 }, { "8", 0x38 }, { "9", 0x39 },

            // Letters
            { "a", 0x41 }, { "b", 0x42 }, { "c", 0x43 }, { "d", 0x44 }, { "e", 0x45 },
            { "f", 0x46 }, { "g", 0x47 }, { "h", 0x48 }, { "i", 0x49 }, { "j", 0x4A },
            { "k", 0x4B }, { "l", 0x4C }, { "m", 0x4D }, { "n", 0x4E }, { "o", 0x4F },
            { "p", 0x50 }, { "q", 0x51 }, { "r", 0x52 }, { "s", 0x53 }, { "t", 0x54 },
            { "u", 0x55 }, { "v", 0x56 }, { "w", 0x57 }, { "x", 0x58 }, { "y", 0x59 },
            { "z", 0x5A },

            // OEM keys (punctuation/symbols)
            { ";", 0xBA }, { "semicolon", 0xBA },
            { "=", 0xBB }, { "equals", 0xBB },
            { ",", 0xBC }, { "comma", 0xBC },
            { "-", 0xBD }, { "minus", 0xBD },
            { ".", 0xBE }, { "period", 0xBE },
            { "/", 0xBF }, { "slash", 0xBF },
            { "`", 0xC0 }, { "backtick", 0xC0 },
            { "[", 0xDB }, { "lbracket", 0xDB },
            { "\\", 0xDC }, { "backslash", 0xDC },
            { "]", 0xDD }, { "rbracket", 0xDD },
            { "'", 0xDE }, { "quote", 0xDE },
            { "oem8", 0xDF }
        };

        return (User32.VK)(charToKeyCodeMap.TryGetValue(key.Trim(), out var code) ? code : (byte)0x00);
    }

    /// <summary>
    ///     Converts a hex keycode to a character or key name.
    /// </summary>
    /// <param name="hexKeyCode">Keycode in hexadecimal format.</param>
    /// <returns>Key name, or <c>"unknown key"</c> if not recognized.</returns>
    internal static string HexKeyCodeToChar(byte hexKeyCode)
    {
        var keyCodeMap = new Dictionary<byte, string>
        {
            // Function keys
            { 0x70, "f1" }, { 0x71, "f2" }, { 0x72, "f3" }, { 0x73, "f4" },
            { 0x74, "f5" }, { 0x75, "f6" }, { 0x76, "f7" }, { 0x77, "f8" },
            { 0x78, "f9" }, { 0x79, "f10" }, { 0x7A, "f11" }, { 0x7B, "f12" },

            // Control/navigation
            { 0x1B, "esc" }, { 0x0D, "enter" }, { 0x20, "space" }, { 0x09, "tab" },
            { 0x10, "shift" }, { 0x11, "ctrl" }, { 0x12, "alt" }, { 0x08, "backspace" },
            { 0x14, "capslock" }, { 0x25, "leftarrow" }, { 0x26, "uparrow" },
            { 0x27, "rightarrow" }, { 0x28, "downarrow" }, { 0x2D, "insert" },
            { 0x2E, "delete" }, { 0x24, "home" }, { 0x23, "end" }, { 0x21, "pageup" },
            { 0x22, "pagedown" }, { 0x90, "numlock" }, { 0x91, "scrolllock" },
            { 0x2C, "printscreen" }, { 0x13, "pause" },
            { 0xA0, "lshift" }, { 0xA1, "rshift" }, { 0xA2, "lcontrol" }, { 0xA3, "rcontrol" },
            { 0xA4, "lalt" }, { 0xA5, "ralt" },

            // Numbers
            { 0x30, "0" }, { 0x31, "1" }, { 0x32, "2" }, { 0x33, "3" }, { 0x34, "4" },
            { 0x35, "5" }, { 0x36, "6" }, { 0x37, "7" }, { 0x38, "8" }, { 0x39, "9" },

            // Letters
            { 0x41, "a" }, { 0x42, "b" }, { 0x43, "c" }, { 0x44, "d" }, { 0x45, "e" },
            { 0x46, "f" }, { 0x47, "g" }, { 0x48, "h" }, { 0x49, "i" }, { 0x4A, "j" },
            { 0x4B, "k" }, { 0x4C, "l" }, { 0x4D, "m" }, { 0x4E, "n" }, { 0x4F, "o" },
            { 0x50, "p" }, { 0x51, "q" }, { 0x52, "r" }, { 0x53, "s" }, { 0x54, "t" },
            { 0x55, "u" }, { 0x56, "v" }, { 0x57, "w" }, { 0x58, "x" }, { 0x59, "y" },
            { 0x5A, "z" },

            // OEM keys (punctuation/symbols)
            { 0xBA, ";" }, { 0xBB, "=" }, { 0xBC, "," }, { 0xBD, "-" }, { 0xBE, "." },
            { 0xBF, "/" }, { 0xC0, "`" }, { 0xDB, "[" }, { 0xDC, "\\" },
            { 0xDD, "]" }, { 0xDE, "'" }, { 0xDF, "oem8" }
        };

        return keyCodeMap.TryGetValue(hexKeyCode, out var keyName) ? keyName : "unknown key";
    }


    /// <summary>
    ///     Checks if any process with the specified name is currently playing audio.
    /// </summary>
    /// <param name="processName">
    ///     The name of the process to check (e.g., "chrome", "firefox", "vlc"). Do not include the .exe
    ///     extension.
    /// </param>
    /// <returns>True if at least one instance of the process is actively playing audio, false otherwise.</returns>
    /// <exception cref="ArgumentException">Thrown if the process name is null or empty.</exception>
    /// <exception cref="InvalidOperationException">
    ///     Thrown if no process with the given name is found or if a Core Audio API
    ///     call fails.
    /// </exception>
    public static bool IsProcessPlayingAudio(string processName)
    {
        if (string.IsNullOrWhiteSpace(processName))
            throw new ArgumentException("Process name cannot be null or empty.", nameof(processName));

        // 1. Get the Process IDs for the given process name
        var processes = Process.GetProcessesByName(processName);
        if (processes.Length == 0)
        {
            Debug.WriteLine($"No process found with the name: {processName}");
            return false;
        }

        var targetProcessIds = new HashSet<uint>(processes.Select(p => (uint)p.Id));
        foreach (var process in processes) process.Dispose();

        // Ensure COM is initialized for this thread using the nested helper class
        using var comInit = new CoInitializeScope(COINIT.COINIT_APARTMENTTHREADED);

        IMMDeviceEnumerator? deviceEnumerator = null;
        IMMDevice? defaultDevice = null;
        IAudioSessionManager2? sessionManager = null;
        IAudioSessionEnumerator? sessionEnumerator = null;

        try
        {
            // 2. Get device enumerator
            deviceEnumerator = new IMMDeviceEnumerator();
            // 3. Get default audio endpoint
            defaultDevice = deviceEnumerator.GetDefaultAudioEndpoint(EDataFlow.eRender, ERole.eMultimedia);
            // 4. Get session manager
            sessionManager = defaultDevice.Activate<IAudioSessionManager2>();
            // 5. Get session enumerator
            sessionEnumerator = sessionManager.GetSessionEnumerator();

            var sessionCount = sessionEnumerator.GetCount();

            // 6. Iterate through audio sessions
            for (var i = 0; i < sessionCount; i++)
            {
                IAudioSessionControl? sessionControl = null;
                IAudioSessionControl2? sessionControl2 = null;
                try
                {
                    sessionControl = sessionEnumerator.GetSession(i);
                    sessionControl2 = sessionControl as IAudioSessionControl2;

                    if (sessionControl2 != null && sessionControl != null)
                    {
                        // 7. Get Process ID
                        var processId = sessionControl2.GetProcessId();
                        // 8. Check if it's a target process
                        if (targetProcessIds.Contains(processId))
                        {
                            // 9. Check state
                            var state = sessionControl.GetState();
                            if (state == AudioSessionState.AudioSessionStateActive)
                            {
                                Debug.WriteLine($"Process {processName} (PID: {processId}) is playing audio.");
                                return true; // Found one playing
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"Error processing session {i}: {ex.Message}");
                    sessionControl2 = null; // Avoid releasing potentially invalid refs
                    sessionControl = null;
                }
                finally
                {
                    // Release COM objects for the current session
                    if (sessionControl2 != null) Marshal.ReleaseComObject(sessionControl2);
                    if (sessionControl != null) Marshal.ReleaseComObject(sessionControl);
                }
            }

            Debug.WriteLine($"Process {processName} was found, but is not currently playing audio.");
            return false; // None found playing
        }
        catch (COMException ex)
        {
            Debug.WriteLine($"A COM error occurred: {ex.Message} (HResult: {ex.HResult:X})");
            throw new InvalidOperationException("Failed to query audio sessions via Core Audio.", ex);
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"An unexpected error occurred: {ex.Message}");
            throw new InvalidOperationException("An error occurred while checking process audio state.", ex);
        }
        finally
        {
            // Release main COM objects
            if (sessionEnumerator != null) Marshal.ReleaseComObject(sessionEnumerator);
            if (sessionManager != null) Marshal.ReleaseComObject(sessionManager);
            if (defaultDevice != null) Marshal.ReleaseComObject(defaultDevice);
            if (deviceEnumerator != null) Marshal.ReleaseComObject(deviceEnumerator);
            // CoUninitialize handled by CoInitializeScope's Dispose
        }
    }

    /// <summary>
    ///     Gets the default browser executable path from the registry.
    /// </summary>
    /// <returns></returns>
    internal static string GetDefaultBrowser()
    {
        var browser = string.Empty;
        try
        {
            // Path to the registry key for default HTTP handler
            var regKey =
                @"HKEY_CURRENT_USER\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoice";
            var progId = (string)Registry.GetValue(regKey, "ProgId", null);

            if (progId != null)
            {
                // Open the corresponding registry entry to fetch the executable
                var browserKeyPath = $@"HKEY_CLASSES_ROOT\{progId}\shell\open\command";
                var browserCommand = (string)Registry.GetValue(browserKeyPath, "", null);

                if (!string.IsNullOrEmpty(browserCommand))
                {
                    // Clean up the command string
                    var firstQuote = browserCommand.IndexOf('"');
                    var secondQuote = browserCommand.IndexOf('"', firstQuote + 1);
                    if (firstQuote >= 0 && secondQuote > firstQuote)
                        browser = browserCommand.Substring(firstQuote + 1, secondQuote - firstQuote - 1);
                }
            }
        }
        catch (Exception ex)
        {
            Debug.WriteLine("Error retrieving default browser: " + ex.Message);
        }

        return browser;
    }

    /// <summary>
    ///     Gets the path to the user's Pictures directory and creates a Speaking_clock subdirectory.
    /// </summary>
    /// <returns></returns>
    internal static string GetOrCreateSpeakingClockPath()
    {
        // Get the path to the user's Pictures directory
        var picturesPath = Environment.GetFolderPath(Environment.SpecialFolder.MyPictures);

        // Define the path for the Speaking_clock directory
        var speakingClockPath = Path.Combine(picturesPath, "Speaking_clock");

        // Check if the Speaking_clock directory exists; if not, create it
        if (!Directory.Exists(speakingClockPath)) Directory.CreateDirectory(speakingClockPath);

        // Generate a timestamped filename
        var timestamp = DateTime.Now.ToString("yyyy-MM-dd_HH-mm-ss");
        var fileName = $"{timestamp}.png";

        // Combine the directory and filename
        return Path.Combine(speakingClockPath, fileName);
    }

    /// <summary>
    ///     Adds a watermark text to an image and returns the watermarked image.
    /// </summary>
    /// <param name="image"></param>
    /// <param name="watermarkText"></param>
    /// <returns></returns>
    internal static Image AddWatermark(Image image, string watermarkText)
    {
        // Create a new bitmap with the same dimensions as the original image
        var watermarkedImage = new Bitmap(image.Width, image.Height);

        // Draw the original image onto the new bitmap
        using (var graphics = Graphics.FromImage(watermarkedImage))
        {
            graphics.DrawImage(image, 0, 0, image.Width, image.Height);

            // Set up font and brush for the watermark
            using var watermarkFont = new Font("Arial", 24, FontStyle.Bold, GraphicsUnit.Pixel);
            using var watermarkBrush = new SolidBrush(Color.FromArgb(255, 255, 255, 255)); // Semi-transparent white

            // Position watermark at the bottom-right corner
            var textSize = graphics.MeasureString(watermarkText, watermarkFont);
            var x = image.Width - textSize.Width - 10;
            var y = image.Height - textSize.Height - 10;

            // Draw watermark text on the image
            graphics.DrawString(watermarkText, watermarkFont, watermarkBrush, x, y);
        }

        return watermarkedImage;
    }

    public static float GetSystemDpi()
    {
        // Create a graphics object from the primary screen
        using (var graphics = Graphics.FromHwnd(IntPtr.Zero))
        {
            // Get the DPI X (horizontal DPI)
            return graphics.DpiX;
        }
    }

    internal static IntPtr GetFullscreenGameHandle()
    {
        // Get the handle of the active window
        var hWnd = User32.GetForegroundWindow();
        if (hWnd == IntPtr.Zero) return IntPtr.Zero;

        // Check if the window is minimized
        if (User32.IsIconic(hWnd))
            return IntPtr.Zero;

        // Get window style and extended style
        var style = User32.GetWindowLong(hWnd, User32.WindowLongFlags.GWL_STYLE);
        var exStyle = User32.GetWindowLong(hWnd, User32.WindowLongFlags.GWL_EXSTYLE);

        // Get window dimensions
        if (!User32.GetWindowRect(hWnd, out var windowRect))
            return IntPtr.Zero;

        // Determine the monitor the window is on
        var screen = Screen.AllScreens.FirstOrDefault(s => s.Bounds.IntersectsWith(new Rectangle(
            windowRect.left, windowRect.top,
            windowRect.right - windowRect.left,
            windowRect.bottom - windowRect.top)));

        if (screen == null) return IntPtr.Zero;

        // Check if the window covers the entire monitor area
        var isFullScreen = windowRect.left <= screen.Bounds.Left && windowRect.top <= screen.Bounds.Top &&
                           windowRect.right >= screen.Bounds.Right && windowRect.bottom >= screen.Bounds.Bottom;

        // Check if the window is borderless or uses overlapping style
        var isBorderless =
            (style & unchecked((int)User32.WindowStyles.WS_POPUP)) == unchecked((int)User32.WindowStyles.WS_POPUP) ||
            (style & unchecked((int)User32.WindowStyles.WS_OVERLAPPEDWINDOW)) !=
            unchecked((int)User32.WindowStyles.WS_OVERLAPPEDWINDOW);
        var isTopmost = (exStyle & (uint)User32.WindowStylesEx.WS_EX_TOPMOST) != 0;

        // Return the handle if the window is in fullscreen mode, otherwise return IntPtr.Zero
        return (IntPtr)(isFullScreen && (isBorderless || isTopmost) ? hWnd : IntPtr.Zero);
    }

    public static List<string> RendezesElsoBetuAlapjan(List<string> lista)
    {
        return lista.OrderBy(s => s[0]).ToList();
    }

    /// <summary>
    ///     Downloads and installs the latest release of a GitHub repository using the GitHub API.
    /// </summary>
    /// <param name="owner"></param>
    /// <param name="repo"></param>
    /// <param name="index"></param>
    /// <param name="argument"></param>
    /// <returns></returns>
    internal static async Task DownloadAndInstallLatestRelease(string owner, string repo, int index, string argument)
    {
        using var client = new HttpClient();

        var apiUrl = $"https://api.github.com/repos/{owner}/{repo}/releases/latest";
        client.DefaultRequestHeaders.UserAgent.TryParseAdd(
            Beallitasok.UserAgent);

        var response = await client.GetAsync(apiUrl);
        response.EnsureSuccessStatusCode();

        var jsonResponse = await response.Content.ReadAsStringAsync();

        using var doc = JsonDocument.Parse(jsonResponse);
        var assetUrl = doc.RootElement
            .GetProperty("assets")[index]
            .GetProperty("browser_download_url")
            .GetString();
        var assetName = Path.GetFileName(assetUrl);

        Debug.WriteLine($"Downloading {assetName} using optimized downloader...");

        var filePath = Path.Combine(Path.GetTempPath(), assetName);
        await DownloadFileMultiThreaded(assetUrl, filePath, client, 10 * 1024 * 1024, 3);

        Debug.WriteLine($"Downloaded to {filePath}");

        Debug.WriteLine("Starting installation...");
        RunSilentInstaller(filePath, argument);

        if (File.Exists(filePath))
        {
            File.Delete(filePath);
            Debug.WriteLine("Temporary file deleted.");
        }
    }

    /// <summary>
    ///     Downloads and installs the DirectX 9 runtime using a multi-threaded download method.
    /// </summary>
    /// <returns></returns>
    internal static async Task DownloadAndInstallDirectX9()
    {
        var directXUrl =
            "https://download.microsoft.com/download/8/4/A/84A35BF1-DAFE-4AE8-82AF-AD2AE20B6B14/directx_Jun2010_redist.exe";
        var fileName = "directx_Jun2010_redist.exe";

        Debug.WriteLine($"Downloading {fileName}...");
        var filePath = Path.Combine(Path.GetTempPath(), fileName);

        using var client = new HttpClient();
        await DownloadFileMultiThreaded(directXUrl, filePath, client, 10 * 1024 * 1024, 3);

        Debug.WriteLine($"Downloaded DirectX runtime to {filePath}");

        // Temporary extraction directory for DirectX installer files
        var extractionPath = Path.Combine(Path.GetTempPath(), "DirectXTemp");

        // Run the DirectX redistributable installer with proper arguments
        Debug.WriteLine("Starting installation...");
        RunSilentInstaller(filePath, $"/Q /T:\"{extractionPath}\"");

        // Run the extracted DirectX setup silently
        var setupPath = Path.Combine(extractionPath, "DXSETUP.exe");
        if (File.Exists(setupPath))
        {
            RunSilentInstaller(setupPath, "/silent");

            // Cleanup extracted files
            Directory.Delete(extractionPath, true);
            Debug.WriteLine("DirectX installation files cleaned up.");
        }
        else
        {
            Debug.WriteLine("DXSETUP.exe not found. Installation failed.");
        }

        // Cleanup downloaded installer
        if (File.Exists(filePath))
        {
            File.Delete(filePath);
            Debug.WriteLine("Temporary file deleted.");
        }
    }

    /// <summary>
    ///     Downloads a file from the specified URL using multiple threads and saves it to the destination path.
    /// </summary>
    /// <param name="url">URL of the file to download.</param>
    /// <param name="destinationPath">Destination path to save the downloaded file.</param>
    /// <param name="client">HttpClient instance to use for downloading the file.</param>
    /// <param name="chunkSize">Chunk size in bytes to download in each request.</param>
    /// <param name="maxRetries">Maximum number of retries for each chunk.</param>
    /// <returns></returns>
    /// <exception cref="InvalidOperationException"></exception>
    internal static async Task DownloadFileMultiThreaded(string url, string destinationPath, HttpClient client,
        int chunkSize, int maxRetries)
    {
        var response = await client.SendAsync(new HttpRequestMessage(HttpMethod.Head, url));
        response.EnsureSuccessStatusCode();

        if (!response.Content.Headers.ContentLength.HasValue)
            throw new InvalidOperationException("File size unknown, cannot perform multi-threaded download.");

        var totalFileSize = response.Content.Headers.ContentLength.Value;
        var ranges = new ConcurrentBag<(long start, long end)>();
        for (long i = 0; i < totalFileSize; i += chunkSize)
        {
            var end = Math.Min(i + chunkSize - 1, totalFileSize - 1);
            ranges.Add((i, end));
        }

        // Open the destination file in write mode
        using var fileStream = new FileStream(destinationPath, FileMode.Create, FileAccess.Write, FileShare.None);

        // Pre-allocate the file size to improve performance
        fileStream.SetLength(totalFileSize);

        var tasks = new ConcurrentBag<Task>();

        foreach (var range in ranges)
            tasks.Add(Task.Run(async () =>
            {
                var retries = 0;
                while (retries < maxRetries)
                    try
                    {
                        var request = new HttpRequestMessage(HttpMethod.Get, url);
                        request.Headers.Range = new RangeHeaderValue(range.start, range.end);
                        var partResponse = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead);
                        partResponse.EnsureSuccessStatusCode();

                        using var partStream = await partResponse.Content.ReadAsStreamAsync();
                        // Lock to write the chunk directly to the file
                        lock (fileStream)
                        {
                            fileStream.Seek(range.start, SeekOrigin.Begin);
                            partStream.CopyTo(fileStream);
                        }

                        break;
                    }
                    catch
                    {
                        retries++;
                        if (retries == maxRetries)
                            throw;
                    }

                Debug.WriteLine($"Downloaded and saved chunk {range.start}-{range.end}.");
            }));

        await Task.WhenAll(tasks);
    }

    /// <summary>
    ///     Runs a silent installer with the specified file path and arguments.
    /// </summary>
    /// <param name="filePath"></param>
    /// <param name="arguments"></param>
    internal static void RunSilentInstaller(string filePath, string arguments)
    {
        var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = filePath,
                Arguments = arguments,
                UseShellExecute = true,
                CreateNoWindow = true
            }
        };

        process.Start();
        process.WaitForExit();

        if (process.ExitCode == 0)
            MessageBox.Show("Telepítés sikerült.", "Információ", MessageBoxButtons.OK, MessageBoxIcon.Information);
        else
            MessageBox.Show($"Telepítés nem sikerült ezzel a kóddal: {process.ExitCode}.", "Hiba", MessageBoxButtons.OK,
                MessageBoxIcon.Error);
    }

    /// <summary>
    ///     Enables a Windows feature using the DISM command-line tool.
    /// </summary>
    /// <param name="featureName"></param>
    internal static void EnableWindowsFeature(string featureName)
    {
        try
        {
            // Create a process to run the DISM command
            var process = new Process();
            process.StartInfo.FileName = "dism.exe";
            process.StartInfo.Arguments = $"/online /enable-feature /featurename:{featureName} /all";
            process.StartInfo.UseShellExecute = false;
            process.StartInfo.RedirectStandardOutput = true;
            process.StartInfo.RedirectStandardError = true;
            process.StartInfo.CreateNoWindow = true;

            // Start the process
            process.Start();

            // Read the output
            var output = process.StandardOutput.ReadToEnd();
            var error = process.StandardError.ReadToEnd();

            // Wait for the process to complete
            process.WaitForExit();

            // Check the exit code
            if (process.ExitCode == 0)
                MessageBox.Show($"Sikerült bekacsolni a {featureName} szolgáltatást.", "Információ",
                    MessageBoxButtons.OK, MessageBoxIcon.Information);
            else
                MessageBox.Show($"Nem sikerült bekapcsolni a {featureName} szolgáltatást. Hiba: {error}", "Hiba",
                    MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"An error occurred: {ex.Message}");
        }
    }

    /// <summary>
    ///     Adds a folder to Windows Defender exclusions.
    /// </summary>
    internal static void AddFolderToDefenderExclusions()
    {
        // Open folder selection dialog
        using (var folderDialog = new FolderBrowserDialog())
        {
            folderDialog.UseDescriptionForTitle = true;
            folderDialog.Description = "Mely mappát adjam a kivételek közé?";
            if (folderDialog.ShowDialog() == DialogResult.OK)
            {
                var folderPath = folderDialog.SelectedPath;

                // Add the folder to Windows Defender exclusions using PowerShell
                var command = $"Add-MpPreference -ExclusionPath \\\"{folderPath}\\\"";

                ExecutePowerShellCommand(command);

                MessageBox.Show($"\"{folderPath}\" hozzá lett adva a kivételek közé.", "Információ",
                    MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            else
            {
                Debug.WriteLine("No folder was selected.");
            }
        }
    }

    internal static bool IsAdministrator()
    {
        using (var identity = WindowsIdentity.GetCurrent())
        {
            var principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }
    }

    /// <summary>
    ///     Executes a PowerShell command with the specified arguments.
    /// </summary>
    /// <param name="command"></param>
    private static void ExecutePowerShellCommand(string command)
    {
        var processInfo = new ProcessStartInfo
        {
            FileName = "powershell",
            Arguments = $"-inputformat none -outputformat none -NonInteractive -Command {command}",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        using (var process = Process.Start(processInfo))
        {
            if (process == null)
                MessageBox.Show("Nem sikerült elindítani a PowerShellt!", "Hiba", MessageBoxButtons.OK,
                    MessageBoxIcon.Error);

            process.WaitForExit();

            var output = process.StandardOutput.ReadToEnd();
            var error = process.StandardError.ReadToEnd();

            if (process.ExitCode != 0 && process.ExitCode != 1)
                MessageBox.Show("Hiba történt!", "Hiba", MessageBoxButtons.OK, MessageBoxIcon.Error);

            Debug.WriteLine(output);
        }
    }

    /// <summary>
    ///     Extracts a password-protected ZIP archive to a specified folder.
    /// </summary>
    /// <param name="zipFilePath"></param>
    /// <param name="password"></param>
    internal static void ExtractPasswordProtectedZip(string zipFilePath, string password)
    {
        // Show folder selector dialog
        using (var folderDialog = new FolderBrowserDialog())
        {
            folderDialog.UseDescriptionForTitle = true;
            folderDialog.Description = "Válassz egy mappát ahová kerüljön";

            if (folderDialog.ShowDialog() == DialogResult.OK)
            {
                var destinationPath = folderDialog.SelectedPath;

                try
                {
                    using (var archive = ZipArchive.OpenArchive(zipFilePath, new ReaderOptions { Password = password }))
                    {
                        foreach (var entry in archive.Entries)
                            if (!entry.IsDirectory)
                            {
                                var destinationFilePath = Path.Combine(destinationPath, entry.Key);

                                // Ensure the directory exists
                                Directory.CreateDirectory(Path.GetDirectoryName(destinationFilePath)!);

                                entry.WriteToFile(destinationFilePath);
                                Debug.WriteLine($"Extracted: {entry.Key}");
                            }
                    }

                    MessageBox.Show("Fájlok beillesztése sikerült!", "Információ", MessageBoxButtons.OK,
                        MessageBoxIcon.Information);
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Egy hiba történt: {ex.Message}", "Hiba", MessageBoxButtons.OK,
                        MessageBoxIcon.Error);
                }
            }
            else
            {
                MessageBox.Show("Nem válaszottál ki mappát.", "Hiba", MessageBoxButtons.OK,
                    MessageBoxIcon.Warning);
            }
        }
    }

    /// <summary>
    ///     Encrypts a file using AES encryption and writes the encrypted content to a new file.
    /// </summary>
    /// <param name="inputFilePath"></param>
    /// <param name="outputFilePath"></param>
    /// <param name="key">Key for the encryption.</param>
    /// <exception cref="ArgumentException"></exception>
    /// <exception cref="ArgumentNullException"></exception>
    /// <exception cref="InvalidOperationException"></exception>
    internal static void EncryptFile(string inputFilePath, string outputFilePath, string key)
    {
        if (string.IsNullOrEmpty(inputFilePath) || !File.Exists(inputFilePath))
            throw new ArgumentException("Input file path is invalid.");
        if (string.IsNullOrEmpty(outputFilePath))
            throw new ArgumentException("Output file path cannot be null or empty.");
        if (string.IsNullOrEmpty(key))
            throw new ArgumentNullException(nameof(key), "Key cannot be null or empty.");

        try
        {
            byte[] keyBytes;
            using (var sha256 = SHA256.Create())
            {
                keyBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(key));
            }

            using (var aes = Aes.Create())
            {
                aes.Key = keyBytes;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                aes.GenerateIV();
                var iv = aes.IV;

                using (var inputFileStream = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read))
                using (var outputFileStream = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write))
                {

                    outputFileStream.Write(iv, 0, iv.Length);


                    using (var encryptor = aes.CreateEncryptor())
                    using (var cryptoStream = new CryptoStream(outputFileStream, encryptor, CryptoStreamMode.Write))
                    {
                        inputFileStream.CopyTo(cryptoStream);
                    }
                }
            }
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException("Encryption failed.", ex);
        }
    }

    /// <summary>
    ///     Decrypts a file using AES encryption and returns the decrypted content as a byte array.
    /// </summary>
    /// <param name="inputFilePath">The path to the encrypted file.</param>
    /// <param name="key">Key used for decryption.</param>
    /// <returns></returns>
    /// <exception cref="ArgumentException"></exception>
    /// <exception cref="ArgumentNullException"></exception>
    /// <exception cref="InvalidOperationException"></exception>
    internal static byte[] DecryptFileToMemory(string inputFilePath, string key)
    {
        if (string.IsNullOrEmpty(inputFilePath) || !File.Exists(inputFilePath))
            throw new ArgumentException("Input file path is invalid.");
        if (string.IsNullOrEmpty(key))
            throw new ArgumentNullException(nameof(key), "Key cannot be null or empty.");

        try
        {

            byte[] keyBytes;
            using (var sha256 = SHA256.Create())
            {
                keyBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(key));
            }

            using (var inputFileStream = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read))
            {

                var iv = new byte[16];
                inputFileStream.Read(iv, 0, iv.Length);

                using (var aes = Aes.Create())
                {
                    aes.Key = keyBytes;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CBC;
                    aes.Padding = PaddingMode.PKCS7;


                    using (var decryptor = aes.CreateDecryptor())
                    using (var cryptoStream = new CryptoStream(inputFileStream, decryptor, CryptoStreamMode.Read))
                    using (var memoryStream = new MemoryStream())
                    {
                        cryptoStream.CopyTo(memoryStream);
                        return memoryStream.ToArray();
                    }
                }
            }
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException("Decryption failed.", ex);
        }
    }

    /// <summary>
    ///     Shows a desktop alert with the specified caption and content text for a given duration.
    /// </summary>
    /// <param name="captionText">Text for the caption.</param>
    /// <param name="contentText">Text for the content.</param>
    /// <param name="time">Time in milliseconds to show the alert.</param>
    internal static void ShowAlert(string captionText, string contentText, int time)
    {
        var alert = new RadDesktopAlert
        {
            CaptionText = captionText,
            ContentText = contentText,
            AutoCloseDelay = time,
            FadeAnimationType = FadeAnimationType.FadeIn,
            ContentImage = Resources.clock,
            AutoSize = true
        };
        alert.Closed += (sender, args) => alert.Dispose();
        alert.Show();
    }

    /// <summary>
    ///     Loads a password-protected ZIP archive into memory and returns a dictionary of file names and memory streams.
    /// </summary>
    /// <param name="zipFilePath">Path to the ZIP archive file.</param>
    /// <param name="password">Password used to decrypt the archive.</param>
    /// <returns></returns>
    internal static Dictionary<string, MemoryStream> LoadPasswordProtectedZipIntoMemory(string zipFilePath,
        string password)
    {
        var filesInMemory = new Dictionary<string, MemoryStream>();
        using var archive = ZipArchive.OpenArchive(zipFilePath, new ReaderOptions
        {
            Password = password,
            ArchiveEncoding = new ArchiveEncoding
            {
                Default = Encoding.Latin1
            }
        });

        foreach (var entry in archive.Entries)
        {

            if (entry.IsDirectory || !entry.IsEncrypted) continue;
            var memoryStream = new MemoryStream();

            entry.WriteTo(memoryStream);
            memoryStream.Seek(0, SeekOrigin.Begin);


            filesInMemory.Add(entry.Key, memoryStream);
        }

        return filesInMemory;
    }
}

internal class CoInitializeScope : IDisposable
{
    private readonly HRESULT hr;
    private bool disposedValue;

    public CoInitializeScope(COINIT dwCoInit)
    {
        hr = CoInitializeEx(IntPtr.Zero, dwCoInit);
        disposedValue = false;
        if (hr.Failed) throw new COMException("CoInitializeEx failed", (int)hr);
    }

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    protected virtual void Dispose(bool disposing)
    {
        if (!disposedValue)
        {
            if (hr.Succeeded)
                CoUninitialize();
            disposedValue = true;
        }
    }

    ~CoInitializeScope()
    {
        Dispose(false);
    }
}