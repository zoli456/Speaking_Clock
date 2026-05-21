using Speaking_clock;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Xml;
using Vanara.PInvoke;
using HtmlDocument = HtmlAgilityPack.HtmlDocument;

namespace Speaking_Clock;

public class DataServices
{
    private static readonly string ApiUrl = "https://ipinfo.io/json";
    private static readonly string CurrentApiUrl = "https://api.weatherapi.com/v1/current.json";
    private static readonly string ForcastApiUrl = "https://api.weatherapi.com/v1/forecast.json";
    private static readonly HttpClient HttpClient = new();
    private static readonly string TtsApiBaseUrl = "https://api.flowery.pw";
    private static readonly string UserAgent =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36";

    /// <summary>
    ///     Get the weather data from the WeatherAPI.com API.
    /// </summary>
    /// <param name="location">The city or location to get the weather data for.</param>
    /// <param name="current">Get the current weather or a forecast.</param>
    /// <returns></returns>
    public static async Task<string> GetWeatherAsync(string location, bool current, string ApiKey)
    {
        try
        {
            var url = $"{(current ? CurrentApiUrl : ForcastApiUrl)}?key={ApiKey}&q={location}&lang=hu" +
                      (current ? "" : "&days=2");

            var response = await HttpClient.GetAsync(url);
            response.EnsureSuccessStatusCode();
            return await response.Content.ReadAsStringAsync();
        }
        catch (HttpRequestException e)
        {
            return $"Request error: {e.Message}";
        }
    }

    /// <summary>
    ///     Get the weather data from the Weather.com API.
    /// </summary>
    /// <param name="cordinates">Cordinates of the location.</param>
    /// <returns></returns>
    public static async Task<string> GetWeatherdotComAsync(string cordinates, string Apikey)
    {
        try
        {
            var url =
                $"https://api.weather.com/v3/aggcommon/v3-wx-observations-current;v3-wx-forecast-daily-7day?format=json&geocode={cordinates}&units=m&language=hu-hu&apiKey={Apikey}";

            var response = await HttpClient.GetAsync(url);
            response.EnsureSuccessStatusCode();
            return await response.Content.ReadAsStringAsync();
        }
        catch (HttpRequestException e)
        {
            return $"Request error: {e.Message}";
        }
    }

    /// <summary>
    ///     Convert text to speech using the Flowery API.
    /// </summary>
    /// <param name="text">The input text to convert to speech.</param>
    /// <returns></returns>
    public static async Task<byte[]> ConvertTextToSpeech(string text)
    {
        try
        {
            var audioData = await GetTtsFromApiV2(text);
            if (audioData != null && audioData.Length > 0)
                return audioData;
            Debug.WriteLine("No audio data received from the TTS API.");
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"Error occurred: {ex.Message}");
        }

        return null;
    }

    /// <summary>
    ///     Get the text-to-speech audio data from the Flowery API.
    /// </summary>
    /// <param name="text">The input text to convert to speech.</param>
    /// <returns></returns>
    private static async Task<byte[]?> GetTtsFromApiV2(string text)
    {
        var url = $"{TtsApiBaseUrl}/v2/tts";
        var voiceId = "ed2e0393-ecd2-5acd-aeca-27d923b7141f";

        string ssml;
        var settings = new XmlWriterSettings
        {
            Encoding = Encoding.UTF8,
            OmitXmlDeclaration = true,
            Indent = false
        };

        using (var stringWriter = new StringWriter())
        using (var xmlWriter = XmlWriter.Create(stringWriter, settings))
        {
            xmlWriter.WriteStartElement("speak", "http://www.w3.org/2001/10/synthesis");

            xmlWriter.WriteStartElement("voice");
            xmlWriter.WriteAttributeString("name", voiceId);

            xmlWriter.WriteStartElement("prosody");
            xmlWriter.WriteAttributeString("rate", "slow");
            xmlWriter.WriteAttributeString("volume", "+2dB");

            xmlWriter.WriteString(text);

            xmlWriter.WriteEndElement();
            xmlWriter.WriteEndElement();
            xmlWriter.WriteEndElement();

            xmlWriter.Flush();
            ssml = stringWriter.ToString();
        }

        using var request = new HttpRequestMessage(HttpMethod.Post, url);

        // Audio format negotiation
        request.Headers.TryAddWithoutValidation("Accept", "audio/mpeg");
        request.Headers.TryAddWithoutValidation("User-Agent", UserAgent);

        // SSML payload
        request.Content = new StringContent(
            ssml,
            Encoding.UTF8,
            "application/ssml+xml"
        );

        var response = await HttpClient.SendAsync(request);

        if (!response.IsSuccessStatusCode)
            return null;

        return await response.Content.ReadAsByteArrayAsync();
    }

    /// <summary>
    ///     Get the namedays from the Nevnap API.
    /// </summary>
    /// <returns></returns>
    public static async Task<string> GetNamedaysAsync()
    {
        try
        {
            var response = await HttpClient.GetAsync("https://nevnap.xsak.hu/json.php");
            response.EnsureSuccessStatusCode();
            return await response.Content.ReadAsStringAsync();
        }
        catch (HttpRequestException e)
        {
            return $"Request error: {e.Message}";
        }
    }

    /// <summary>
    ///     Get the location data from the IP address.
    /// </summary>
    /// <returns></returns>
    public static async Task<string> GetLocationByIpAsync()
    {
        try
        {
            var response = await HttpClient.GetAsync(ApiUrl);
            response.EnsureSuccessStatusCode();
            return await response.Content.ReadAsStringAsync();
        }
        catch (HttpRequestException e)
        {
            return $"Request error: {e.Message}";
        }
    }

    /// <summary>
    ///     Get the wallpaper image from the Bing API.
    /// </summary>
    /// <returns></returns>
    private static async Task<string> GetBingImageUrlAsync()
    {
        var url = "https://www.bing.com/HPImageArchive.aspx?format=js&idx=0&n=1&mkt=en-US";
        try
        {
            var response = await HttpClient.GetAsync(url);
            response.EnsureSuccessStatusCode();
            var json = await response.Content.ReadAsStringAsync();

            // Deserialize JSON to get only required property
            var data = JsonSerializer.Deserialize<JsonElement>(json);
            var imageUrl = "https://www.bing.com" + data.GetProperty("images")[0].GetProperty("url").GetString();
            return imageUrl;
        }
        catch (Exception ex)
        {
            Debug.WriteLine("Error fetching Bing image: " + ex.Message);
            return null;
        }
    }

    /// <summary>
    ///     Download the Bing wallpaper image.
    /// </summary>
    /// <param name="imageUrl">The URL of the image to download.</param>
    /// <returns></returns>
    private static async Task<string> DownloadImageAsync(string imageUrl)
    {
        var localPath = Path.Combine(Path.GetTempPath(), "bing_wallpaper.jpg");
        try
        {
            var response = await HttpClient.GetAsync(imageUrl);
            response.EnsureSuccessStatusCode();
            var imageData = await response.Content.ReadAsByteArrayAsync();
            await File.WriteAllBytesAsync(localPath, imageData);
            return localPath;
        }
        catch (Exception ex)
        {
            Debug.WriteLine("Error downloading image: " + ex.Message);
            return null;
        }
    }

    /// <summary>
    ///     Set the wallpaper image.
    /// </summary>
    /// <param name="localFilePath">Local file path of the image to set as wallpaper.</param>
    private static void SetWallpaper(string localFilePath)
    {
        try
        {
            var pathPointer = Marshal.StringToHGlobalUni(localFilePath);

            User32.SystemParametersInfo(
                User32.SPI.SPI_SETDESKWALLPAPER,
                0,
                pathPointer,
                User32.SPIF.SPIF_UPDATEINIFILE | User32.SPIF.SPIF_SENDCHANGE);

            Marshal.FreeHGlobal(pathPointer);
        }
        catch (Exception ex)
        {
            Debug.WriteLine("Error setting wallpaper: " + ex.Message);
        }
    }

    /// <summary>
    ///     Set the daily Bing wallpaper.
    /// </summary>
    /// <returns></returns>
    internal static async Task SetDailyWallpaperAsync()
    {
        var imageUrl = await GetBingImageUrlAsync();
        if (!string.IsNullOrEmpty(imageUrl))
        {
            var localFilePath = await DownloadImageAsync(imageUrl);
            if (!string.IsNullOrEmpty(localFilePath))
            {
                SetWallpaper(localFilePath);
                Debug.WriteLine("Bing wallpaper set successfully.");
            }
        }
        else
        {
            Debug.WriteLine("Failed to retrieve Bing image URL.");
        }
    }

    /// <summary>
    ///     Downloads a file from a GitHub repository's raw URL and loads it into memory.
    /// </summary>
    /// <param name="fileUrl">The raw URL of the file on GitHub.</param>
    /// <returns>A byte array containing the file's content.</returns>
    internal static async Task DownloadFileAsync(string fileUrl, string outputFilePath)
    {
        if (string.IsNullOrEmpty(fileUrl))
            throw new ArgumentNullException(nameof(fileUrl), "File URL cannot be null or empty.");
        if (string.IsNullOrEmpty(outputFilePath))
            throw new ArgumentNullException(nameof(outputFilePath), "Output file path cannot be null or empty.");

        try
        {
            Debug.WriteLine($"Downloading file from {fileUrl}...");
            // Send a GET request to the file URL
            var response = await HttpClient.GetAsync(fileUrl);

            // Ensure the request was successful
            response.EnsureSuccessStatusCode();

            // Read the file content as a byte array
            var fileBytes = await response.Content.ReadAsByteArrayAsync();

            // Save the file to the specified path
            await File.WriteAllBytesAsync(outputFilePath, fileBytes);
            Debug.WriteLine($"File downloaded successfully and saved to {outputFilePath}");
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"Failed to download file from {fileUrl}");
        }
    }

    /// <summary>
    ///     Download the lastest link to the lastest Winrar.
    /// </summary>
    /// <param name="language">Language of the Winrar.</param>
    /// <returns></returns>
    internal static async Task<string> GetLatestWinRar64BitLinkAsync(string language)
    {
        const string winrarUrl = "https://www.rarlab.com/download.htm";

        try
        {
            var html = await HttpClient.GetStringAsync(winrarUrl);

            HtmlDocument doc = new();
            doc.LoadHtml(html);

            // Find all links on the page
            var linkNodes = doc.DocumentNode.SelectNodes("//a[@href]");
            if (linkNodes == null)
                return "No links found on the WinRAR download page.";

            foreach (var linkNode in linkNodes)
            {
                var href = linkNode.GetAttributeValue("href", string.Empty);

                // Look for links containing "winrar-x64" and the specified language
                if (href.Contains("winrar-x64") && href.Contains($"{language}.exe"))
                {
                    // Ensure the link is absolute
                    if (!Uri.IsWellFormedUriString(href, UriKind.Absolute))
                        href = new Uri(new Uri(winrarUrl), href).ToString();
                    return href;
                }
            }

            return $"64-bit WinRAR link not found for language '{language}'.";
        }
        catch (Exception ex)
        {
            return $"Error retrieving WinRAR link: {ex.Message}";
        }
    }

    /// <summary>
    ///     Download and install the latest Winrar.
    /// </summary>
    /// <returns></returns>
    internal static async Task DownloadAndInstallWinrar()
    {
        var winrarUrl =
            await GetLatestWinRar64BitLinkAsync("hu");
        const string fileName = "WinrarX64.exe";

        Debug.WriteLine($"Downloading {fileName}...");
        var filePath = Path.Combine(Path.GetTempPath(), fileName);

        await Utils.DownloadFileMultiThreaded(winrarUrl, filePath, HttpClient, 5 * 1024 * 1024, 3);

        Debug.WriteLine($"Downloaded Winrar runtime to {filePath}");

        // Run the DirectX redistributable installer with proper arguments
        Debug.WriteLine("Starting installation...");
        Utils.RunSilentInstaller(filePath, "/S");

        // Cleanup downloaded installer
        if (File.Exists(filePath))
        {
            File.Delete(filePath);
            Debug.WriteLine("Temporary file deleted.");
        }
    }

    /// <summary>
    ///     Get the latest 7-Zip 64-bit download link.
    /// </summary>
    /// <returns></returns>
    internal static async Task<string> GetLatest7Zip64BitLinkAsync()
    {
        const string sevenZipUrl = "https://www.7-zip.org/";

        try
        {
            var html = await HttpClient.GetStringAsync(sevenZipUrl);

            HtmlDocument doc = new();
            doc.LoadHtml(html);

            // Look for all download links on the page
            var linkNodes = doc.DocumentNode.SelectNodes("//a[@href]");
            if (linkNodes == null)
                return "No links found on the 7-Zip download page.";

            foreach (var linkNode in linkNodes)
            {
                var href = linkNode.GetAttributeValue("href", string.Empty);

                // Look for 64-bit Windows installer links (usually end with ".exe" and contain "x64")
                if (href.Contains("7z") && href.Contains("x64") && href.EndsWith(".exe"))
                {
                    // Ensure the link is absolute
                    if (!Uri.IsWellFormedUriString(href, UriKind.Absolute))
                        href = new Uri(new Uri(sevenZipUrl), href).ToString();
                    return href;
                }
            }

            return "64-bit 7-Zip link not found.";
        }
        catch (Exception ex)
        {
            return $"Error retrieving 7-Zip link: {ex.Message}";
        }
    }

    /// <summary>
    ///     Download and install the latest 7-Zip.
    /// </summary>
    /// <returns></returns>
    internal static async Task DownloadAndInstall7Zip()
    {
        var winrarUrl =
            await GetLatest7Zip64BitLinkAsync();
        const string fileName = "7zipX64.exe";

        Debug.WriteLine($"Downloading {fileName}...");
        var filePath = Path.Combine(Path.GetTempPath(), fileName);

        await Utils.DownloadFileMultiThreaded(winrarUrl, filePath, HttpClient, 5 * 1024 * 1024, 3);

        Debug.WriteLine($"Downloaded 7-Zip runtime to {filePath}");

        // Run the DirectX redistributable installer with proper arguments
        Debug.WriteLine("Starting installation...");
        Utils.RunSilentInstaller(filePath, "/S");

        // Cleanup downloaded installer
        if (File.Exists(filePath))
        {
            File.Delete(filePath);
            Debug.WriteLine("Temporary file deleted.");
        }
    }

    /// <summary>
    ///     Get the latest Nvidia driver download link for the specified GPU.
    /// </summary>
    /// <returns></returns>
    internal static async Task DownloadAndInstallNvidia()
    {
        var driver = new Driver
        {
            Channel = DriverChannel.GameReady,
            Edition = DriverEdition.DCH
        };
        var driverUrl =
            await NvidiaDriverFinder.GetLatestNvidiaDriverForGpuAsync(ComputerInfo.VgaNev().Replace("NVIDIA ", ""),
                driver, ComputerInfo.WindowsNevEsVerzio().Contains("Windows 10"));
        const string fileName = "NvidiaDriver.exe";

        Debug.WriteLine($"Downloading {fileName}...");
        var filePath = Path.Combine(Path.GetTempPath(), fileName);

        await Utils.DownloadFileMultiThreaded(driverUrl, filePath, HttpClient, 100 * 1024 * 1024, 3);

        Debug.WriteLine($"Downloaded Nvidia Driver to {filePath}");

        // Run the DirectX redistributable installer with proper arguments
        Debug.WriteLine("Starting installation...");
        Utils.RunSilentInstaller(filePath, "/S");

        // Cleanup downloaded installer
        if (File.Exists(filePath))
        {
            File.Delete(filePath);
            Debug.WriteLine("Temporary file deleted.");
        }
    }
}