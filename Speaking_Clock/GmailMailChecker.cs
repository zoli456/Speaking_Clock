using System.Diagnostics;
using System.Management;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Google.Apis.Auth.OAuth2;
using Google.Apis.Auth.OAuth2.Responses;
using Google.Apis.Gmail.v1;
using Google.Apis.Services;
using Google.Apis.Util.Store;
using Speaking_clock;

namespace Speaking_Clock;

public class GmailMailChecker
{
    private static readonly string ApplicationName = "Beszelo Ora";
    private static readonly string EncryptedTokenFilePath = "UserData";
    private static readonly string[] Scopes = { GmailService.Scope.GmailReadonly };
    private static GmailService _gmailService;
    private static UserCredential _credential;

    private static readonly byte[] EncryptionKey = Secrets.GmailEncryptionKey;
    private static readonly byte[] InitializationVector = Secrets.GmailInitializationVector;

    public static async Task<UserCredential> RequestAuthorizationAsync()
    {
        if (_credential != null)
            return _credential;

        try
        {
            using var stream = Assembly.GetExecutingAssembly()
                .GetManifestResourceStream("Speaking_Clock.credentials.json");
            if (stream == null) throw new FileNotFoundException("Resource not found");

            _credential = await GoogleWebAuthorizationBroker.AuthorizeAsync(
                GoogleClientSecrets.Load(stream).Secrets,
                Scopes, "user",
                CancellationToken.None,
                new EncryptedFileDataStore(EncryptedTokenFilePath));

            Debug.WriteLine("Authorization successful!");
        }
        catch (Exception ex)
        {
            Debug.WriteLine("Failed to authorize: " + ex.Message);
            throw;
        }

        return _credential;
    }

    public static async Task InitializeGmailServiceAsync()
    {
        _credential = await RequestAuthorizationAsync();
        _gmailService = new GmailService(new BaseClientService.Initializer
        {
            HttpClientInitializer = _credential,
            ApplicationName = ApplicationName
        });
        Debug.WriteLine("Gmail API service created successfully!");
    }

    internal static async Task CheckForUnreadEmailsAsync(DateTime startDateTime)
    {
        try
        {
            if (_credential.Token.IsStale)
            {
                Debug.WriteLine("Token expired, refreshing...");
                await _credential.RefreshTokenAsync(CancellationToken.None);
            }

            var unixTimestamp = ((DateTimeOffset)startDateTime).ToUnixTimeSeconds();
            var request = _gmailService.Users.Messages.List("me");
            request.LabelIds = "UNREAD";
            request.Q = $"after:{unixTimestamp}";

            var response = await request.ExecuteAsync();

            if (response.Messages?.Any() == true)
            {
                Debug.WriteLine("You have new unread emails.");
                foreach (var msg in response.Messages)
                {
                    var email = await _gmailService.Users.Messages.Get("me", msg.Id).ExecuteAsync();
                    var subject = email.Payload.Headers.FirstOrDefault(h => h.Name == "Subject")?.Value ?? "No Subject";
                    Utils.ShowAlert(subject, email.Snippet, 30);
                    Debug.WriteLine($"New Email: {subject} - {email.Snippet}");
                }
            }
            else
            {
                Debug.WriteLine("No new emails received after " + startDateTime);
            }
        }
        catch (Exception ex)
        {
            Debug.WriteLine("An error occurred: " + ex.Message);
            throw;
        }
    }


    internal static void DisposeData()
    {
        _gmailService?.Dispose();
        _credential = null;
    }

    private class EncryptedFileDataStore : IDataStore
    {
        private readonly string _path;

        public EncryptedFileDataStore(string path)
        {
            _path = path;
        }

        public async Task StoreAsync<T>(string key, T value)
        {
            if (value is TokenResponse tokenResponse)
            {
                var deviceId = GetDeviceIdentifier();
                var dataToStore = new StoredData { TokenData = tokenResponse, DeviceId = deviceId };
                var json = JsonSerializer.Serialize(dataToStore);
                var encryptedData = EncryptStringToBytes_Aes(json, EncryptionKey, InitializationVector);

                await File.WriteAllBytesAsync(_path, encryptedData);
            }
            else
            {
                throw new InvalidOperationException("Unsupported data type for storage.");
            }
        }

        public async Task DeleteAsync<T>(string key)
        {
            if (File.Exists(_path)) File.Delete(_path);
        }

        public async Task<T> GetAsync<T>(string key)
        {
            if (!File.Exists(_path)) return default;

            try
            {
                var encryptedData = await File.ReadAllBytesAsync(_path);
                var decryptedJson = DecryptStringFromBytes_Aes(encryptedData, EncryptionKey, InitializationVector);
                var storedData = JsonSerializer.Deserialize<StoredData>(decryptedJson);
                var currentDeviceId = GetDeviceIdentifier();

                if (storedData.DeviceId != currentDeviceId)
                    throw new UnauthorizedAccessException("Token file was copied from a different device.");

                if (typeof(T) == typeof(TokenResponse)) return (T)(object)storedData.TokenData;

                return default;
            }
            catch (CryptographicException e)
            {
                Debug.WriteLine($"Decryption failed: {e.Message}. Deleting corrupted UserData file.");
                await ClearAsync();
                return default;
            }
            catch (Exception ex)
            {
                Debug.WriteLine("An unexpected error occurred: " + ex.Message);
                throw;
            }
        }

        public async Task ClearAsync()
        {
            if (File.Exists(_path)) File.Delete(_path);
        }

        private static byte[] EncryptStringToBytes_Aes(string plainText, byte[] key, byte[] iv)
        {
            using var aesAlg = Aes.Create();
            aesAlg.Key = key;
            aesAlg.IV = iv;
            var encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

            using var msEncrypt = new MemoryStream();
            using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
            using (var swEncrypt = new StreamWriter(csEncrypt))
            {
                swEncrypt.Write(plainText);
            }

            return msEncrypt.ToArray();
        }

        private static string DecryptStringFromBytes_Aes(byte[] cipherText, byte[] key, byte[] iv)
        {
            using var aesAlg = Aes.Create();
            aesAlg.Key = key;
            aesAlg.IV = iv;
            var decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

            using var msDecrypt = new MemoryStream(cipherText);
            using var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read);
            using var srDecrypt = new StreamReader(csDecrypt);
            return srDecrypt.ReadToEnd();
        }

        private static string GetDeviceIdentifier()
        {
            try
            {
                using var searcher =
                    new ManagementObjectSearcher(
                        "SELECT MACAddress FROM Win32_NetworkAdapter WHERE MACAddress IS NOT NULL");
                foreach (ManagementObject obj in searcher.Get()) return obj["MACAddress"]?.ToString();
            }
            catch
            {
                return Environment.MachineName;
            }

            return null;
        }

        private class StoredData
        {
            public TokenResponse TokenData { get; set; }
            public string DeviceId { get; set; }
        }
    }
}