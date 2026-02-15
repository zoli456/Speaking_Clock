using System.ComponentModel;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Text.Json;
using ManagedBass;
using Microsoft.Win32;
using Microsoft.Win32.TaskScheduler;
using SharpConfig;
using Speaking_clock;
using Speaking_clock.Overlay;
using Speaking_clock.Widgets;
using Speaking_Clock.Widgets;
using Telerik.WinControls.UI;
using Vanara.PInvoke;
using Configuration = SharpConfig.Configuration;
using MethodInvoker = System.Windows.Forms.MethodInvoker;
using PlaybackState = ManagedBass.PlaybackState;
using Task = System.Threading.Tasks.Task;
using Timer = System.Windows.Forms.Timer;

namespace Speaking_Clock;

public partial class Beallitasok : Form
{
    // Constants for key event flags
    private const User32.KEYEVENTF KeyeventfKeydown = 0; // Simulate key down event

    internal static readonly string BasePath = Path.GetDirectoryName(Application.ExecutablePath);
    internal static string SetttingsFileName = "settings.ini";
    internal static DateTime NextNotificationDate;
    internal static bool NotificationEnabled;
    internal static Configuration ConfigParser = Configuration.LoadFromFile($"{BasePath}\\{SetttingsFileName}");
    internal static Section BeszédSection = ConfigParser["Beszéd"];
    internal static Section IndításSection = ConfigParser["Indítás"];
    internal static Section SzinkronizálásSection = ConfigParser["Szinkronizálás"];
    internal static Section FigyelmeztetésSection = ConfigParser["Figyelmeztetés"];
    internal static Section HangfelismerésSection = ConfigParser["Hangfelismerés"];
    internal static Section HáttérképSection = ConfigParser["Háttérkép"];
    internal static Section RádióSection = ConfigParser["Rádió"];
    internal static Section ÁtfedésSection = ConfigParser["Átfedés"];

    internal static Section GyorsmenüSection = ConfigParser["Gyorsmenü"];

    //internal static Section GmailSection = ConfigParser["Gmail"];
    internal static Section ScreenCaptureSection = ConfigParser["Képlopás"];
    internal static Section RSS_Reader_Section = ConfigParser["RSS_Olvasó"];
    internal static Section WidgetSection = ConfigParser["Widgetek"];
    internal static bool NotificationRepeate;
    internal static bool PlayingRadio;
    internal static RadioControl _radioControl;
    internal static VirtualKeyboard Virtualkeyboard;
    internal static CustomWarningForm CustomWarningForm;
    internal static string Cordinates = "";
    internal static string Location = "";
    internal static string NameDays = "";
    internal static int LastNamedayIndex = -1;
    private static DateTime _nextWeatherCheck;
    private static byte[] _weatherSound;
    private static byte[] _namedaySound;
    private static byte[] _forecastSound;

    internal static QuickMenu QuickMenu;

    internal static FullScreenMenu FullscreenMenu;
    internal static bool FullScreenmenuOpened;

    internal static OverlayForm Overlay;
    internal static TimeOverlayForm TimeOverlay;
    internal static Minesweeper minesweeperForm;
    internal static Flagguesser flagguesserForm;
    internal static QuizWidget quizForm;
    internal static LogoGuesser logoGuesserForm;
    internal static MemoryStream AlarmSound;
    internal static MemoryStream NotificationSound;
    internal static bool Lejátszás;

    internal static MemoryStream TimefileStream;
    internal static Dictionary<string, MemoryStream> ZipContent;
    internal static float BaseDpi = Utils.GetSystemDpi();
    internal static JsonDocument weatherData;
    internal static DateTime KovetkezoBeszed;
    internal static string VoskModel = "vosk-model-small-en-us-0.15";
    internal static List<string> RadioNames = new();
    internal static List<string> RandioUrLs = new();
    internal static string ZipPassword = Secrets.ZipPassword;
    internal static string RadioDataKey = Secrets.RadioDataKey;

    internal static string UserAgent =
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36";

    internal static NotifyIcon TrayIcon = new();

    internal static bool isVisibleCore;

    internal static string DefaultBrowerPath;
    internal static DateTime JelenlegiIdo;
    internal static int[] warningTimes = { 5, 10, 15, 20, 30, 45, 60 };
    internal static RssReader[] rssReader = new RssReader[4];
    internal static DotMatrixClock dotMatrix;
    internal static AnalogClock analogClock;
    internal static CalendarWidget calendarWidget;
    internal static NamedayWidget NamedayWidgetWidget;
    internal static RadioPlayerWidget radioPlayerWidget;
    internal static WeatherWidget weatherWidget;
    internal static bool FullScreenApplicationRunning;
    private static Process FullScreenApplicationProcess;
    internal static string OverlayMode = "";
    private WidgetSetup _widgetForm;
    internal bool DefaultBrowserPlayingAudio;
    internal Timer? DelayedLoadTimer;
    internal bool Kimondva;
    private Mutex mutex;
    internal Nevjegy? Nevjegy;
    private bool PendingWidgetUpdate;
    internal SystemInformation? SystemInformation;

    public Beallitasok()
    {
        InitializeComponent();
        Environment.CurrentDirectory = AppDomain.CurrentDomain.BaseDirectory;
        // Define a unique name for the Mutex
        mutex = new Mutex(true, "2DE96183-A1E5-408C-BBCC-CF513F65AF0C", out var isNewInstance);
        if (!isNewInstance)
        {
            MessageBox.Show("Ez az alkalmazás már fut.", "Hiba", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            Close(); // Exit the application
        }

        if (!Bass.Init())
        {
            Debug.WriteLine("BASS Init error: " + Bass.LastError);
            if (!Bass.Init(-1, 44100, DeviceInitFlags.Default, IntPtr.Zero))
                Debug.WriteLine("BASS Second init attempt failed: " + Bass.LastError);
        }

        /*Bass.PluginLoad("bassmix.dll");
        Bass.PluginLoad("bassflac.dll");
        Bass.PluginLoad("bass_aac.dll");*/
        // Configure network settings for streaming
        Bass.Configure(ManagedBass.Configuration.NetBufferLength, 1000); // 1 second buffer
        Bass.Configure(ManagedBass.Configuration.NetPreBuffer, 0); // No pre-buffering

        if (!File.Exists(SetttingsFileName)) Close();

        TrayIcon.Icon = Icon;
        JelenlegiIdo = DateTime.Now;

        var asm = Assembly.GetExecutingAssembly();
        var resourceNames = asm.GetManifestResourceNames();
        Debug.WriteLine("Embedded resources:");
        foreach (var name in resourceNames) Debug.WriteLine(" • " + name);

        /*#if RELEASE
                TopMost = true;
        #endif*/
        AnnounceTimeCheckBox.Checked = BeszédSection["Bekapcsolva"].BoolValue;
        voiceRecognitionCheckbox.Checked = BeszédSection["Bekapcsolva"].BoolValue;
        startup_checkbox.Checked = IndításSection["Automatikus"].BoolValue;
        hanypercenkent.Text = BeszédSection["Gyakoriság"].IntValue.ToString();
        Volume_trackBar.Value = BeszédSection["Hangerő"].IntValue;
        label3.Text = $"{Volume_trackBar.Value}%";
        twentyfour_checkbox.Checked = BeszédSection["24óra"].BoolValue;
        Synctime_checkBox.Checked = SzinkronizálásSection["Automatikus"].BoolValue;
        synctime_timer.Enabled = SzinkronizálásSection["Automatikus"].BoolValue;
        timerszerver_textBox.Text = SzinkronizálásSection["Szerver"].StringValue;
        ArrangeTimer.Checked = BeszédSection["Igazítás"].BoolValue;
        voiceRecognitionCheckbox.Checked = HangfelismerésSection["Bekapcsolva"].BoolValue;
        NoiseFilteringcheckBox.Checked = HangfelismerésSection["Zajszűrés"].BoolValue;
        DailyWallpaperBox.Checked = HáttérképSection["Bekapcsolva"].BoolValue;
        ScreenCapturecheckBox.Checked = ScreenCaptureSection["Bekapcsolva"].BoolValue;
        OverlaycheckBox.Checked = ÁtfedésSection["Bekapcsolva"].BoolValue;
        OverlaytextBox.Text = OverlayMessenger.ConvertToMultiLine(ÁtfedésSection["Gombok"].StringValue);
        DonthookapiTextbox.Text = ÁtfedésSection["DontHookRendering"].StringValue.Trim();
        DontHookTextBox.Text = ÁtfedésSection["UseSimpleOverlay"].StringValue.Trim();
        WatermarktextBox.Text = ScreenCaptureSection["Vízjel"].StringValue.Trim();

        try
        {
            DefaultBrowerPath = Utils.GetDefaultBrowser();
            DefaultBrowserPlayingAudio = false;
        }
        catch (Exception e)
        {
            DefaultBrowerPath = "";
        }

        if (HangfelismerésSection["Eredmény_billentyű"].StringValue != "" &&
            HangfelismerésSection["Kiváltó_Szó"].StringValue != "")
        {
            TriggerWordtextBox.Text = HangfelismerésSection["Kiváltó_Szó"].StringValue;
            TriggerActiontextBox.Text = HangfelismerésSection["Eredmény_billentyű"].StringValue;
        }

        if (Environment.GetCommandLineArgs().Length > 0)
            if (Environment.GetCommandLineArgs().Any(x => x == "auto"))
            {
                DelayedLoadTimer = new Timer();
                DelayedLoadTimer.Interval = 5000;
                DelayedLoadTimer.Tick += DelayedLoadTimer_Tick;
                DelayedLoadTimer.Start();
                return;
                // }
            }

        PostLauchSetup();
        isVisibleCore = true;
        Visible = true;
/*#if DEBUG
        Utils.EncryptFile($"{BasePath}\\Fájlok\\RadioStations.dat", $"{BasePath}\\Fájlok\\RadioStations_enc.dat",
            RadioDataKey);
#endif*/
        Activate();
        Focus();
    }

    private void button1_Click(object sender, EventArgs e)
    {
        Most_mod();
    }

    protected override void SetVisibleCore(bool value)
    {
        base.SetVisibleCore(isVisibleCore);
    }

    /// <summary>
    ///     Play the current time
    /// </summary>
    /// <returns></returns>
    internal static async Task Most_mod()
    {
        var fileToPlay = "";
        while (Lejátszás) await Task.Delay(100);
        //if (OnlineRadioPlayer._playbackState == OnlineRadioPlayer.PlaybackState.Playing) return;
        SafeInvoke(SayItNowbutton, () => { SayItNowbutton.Enabled = false; });
        SpeechRecognition.DisableVoiceRecognition();
        if (DateTime.Now.Minute == 0)
        {
            fileToPlay = string.Concat("teljes_óra/",
                twentyfour_checkbox.Checked ? JelenlegiIdo.Hour : tizekkettoorasra_alakitas(JelenlegiIdo.Hour),
                " óra van.mp3");
            if (!ZipContent.TryGetValue(fileToPlay, out TimefileStream))
            {
                SpeechRecognition.EnableVoiceRecognition();
                return;
            }

            await PlaySound(TimefileStream);
        }
        else
        {
            SafeInvoke(SayItNowbutton, () => { SayItNowbutton.Enabled = false; });
            fileToPlay = string.Concat("óra/",
                twentyfour_checkbox.Checked ? JelenlegiIdo.Hour : tizekkettoorasra_alakitas(JelenlegiIdo.Hour),
                " óra.mp3");
            if (!ZipContent.TryGetValue(fileToPlay, out TimefileStream))
            {
                SpeechRecognition.EnableVoiceRecognition();
                return;
            }

            await PlaySound(TimefileStream);
            fileToPlay = $"perc/{JelenlegiIdo.Minute} perc van.mp3";
            if (!ZipContent.TryGetValue(fileToPlay, out TimefileStream))
            {
                SpeechRecognition.EnableVoiceRecognition();
                return;
            }

            await PlaySound(TimefileStream);
        }

        SpeechRecognition.EnableVoiceRecognition();
        SafeInvoke(SayItNowbutton, () => { SayItNowbutton.Enabled = true; });
    }

    public static bool SafeInvoke(Control control, MethodInvoker method)
    {
        if (control != null && !control.IsDisposed && control.IsHandleCreated && control.FindForm().IsHandleCreated)
        {
            if (control.InvokeRequired)
                control.Invoke(method);
            else
                method();

            return true;
        }

        return false;
    }

    private static int tizekkettoorasra_alakitas(int hour)
    {
        if (hour > 12) return hour - 12;

        return hour;
    }


    internal static async Task<bool> PlaySound(MemoryStream streamtoPlayStream)
    {
        Lejátszás = true;
        try
        {
            streamtoPlayStream.Position = 0;

            byte[] audioData;
            using (var ms = new MemoryStream())
            {
                await streamtoPlayStream.CopyToAsync(ms);
                audioData = ms.ToArray();
            }

            var stream = Bass.CreateStream(audioData, 0, audioData.Length, BassFlags.Default);
            if (stream == 0)
            {
                Console.WriteLine($"BASS Error creating stream: {Bass.LastError}");
                return false;
            }

            var volume = (float)((decimal)BeszédSection["Hangerő"].IntValue / 100);
            Bass.ChannelSetAttribute(stream, ChannelAttribute.Volume, volume);

            if (!Bass.ChannelPlay(stream))
            {
                Console.WriteLine($"BASS Play failed: {Bass.LastError}");
                Bass.StreamFree(stream);
                return false;
            }

            while (Bass.ChannelIsActive(stream) == PlaybackState.Playing) await Task.Delay(50);
            Bass.StreamFree(stream);

            return true;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Playback error: {ex.Message}");
            return false;
        }
        finally
        {
            Lejátszás = false;
        }
    }


    private void button2_Click(object sender, EventArgs e)
    {
        try
        {
            if (Volume_trackBar.Value > 100 || Volume_trackBar.Value < 0) throw new Exception("Hibás adat!");

            if (int.Parse(hanypercenkent.Text.Trim()) == 0) throw new Exception("Hibás adat!");
        }
        catch (Exception ex)
        {
            MessageBox.Show("Hibás adatokat adtál meg!", "Hiba", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }


        BeszédSection["Bekapcsolva"].BoolValue = AnnounceTimeCheckBox.Checked;
        IndításSection["Automatikus"].BoolValue = startup_checkbox.Checked;
        BeszédSection["Gyakoriság"].IntValue = int.Parse(hanypercenkent.Text.Trim());
        BeszédSection["Hangerő"].IntValue = Volume_trackBar.Value;
        BeszédSection["24óra"].BoolValue = twentyfour_checkbox.Checked;
        BeszédSection["Hang"].StringValue = hangok_comboBox.SelectedItem.ToString();
        BeszédSection["Igazítás"].BoolValue = ArrangeTimer.Checked;
        SzinkronizálásSection["Automatikus"].BoolValue = Synctime_checkBox.Checked;
        SzinkronizálásSection["Szerver"].StringValue = SzinkronizálásSection["Szerver"].StringValue.Trim();
        synctime_timer.Enabled = Synctime_checkBox.Checked;
        HangfelismerésSection["Bekapcsolva"].BoolValue = voiceRecognitionCheckbox.Checked;
        HangfelismerésSection["Zajszűrés"].BoolValue = NoiseFilteringcheckBox.Checked;
        HáttérképSection["Bekapcsolva"].BoolValue = DailyWallpaperBox.Checked;
        ScreenCaptureSection["Bekapcsolva"].BoolValue = ScreenCapturecheckBox.Checked;
        GyorsmenüSection["Bekapcsolva"].BoolValue = QuickMenucheckBox.Checked;
        CreateTask();
        ÁtfedésSection["Bekapcsolva"].BoolValue = OverlaycheckBox.Checked;
        ÁtfedésSection["Gombok"].StringValue = OverlayMessenger.ConvertToSingleLine(OverlaytextBox.Text);
        ScreenCaptureSection["Vízjel"].StringValue = WatermarktextBox.Text.Trim();

        DonthookapiTextbox.Text = DonthookapiTextbox.Text.Trim();
        if (!DonthookapiTextbox.Text.Contains(";") && DonthookapiTextbox.Text.Length > 0)
        {
            DonthookapiTextbox.Focus();
            MessageBox.Show("Hibás adatokat adtál meg!", "Hiba", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        ÁtfedésSection["DontHookRendering"].StringValue = DonthookapiTextbox.Text;
        DonthookapiTextbox.Text = DonthookapiTextbox.Text.Trim();
        DontHookTextBox.Text = DontHookTextBox.Text.Trim();
        if (!DontHookTextBox.Text.Contains(";") && DontHookTextBox.Text.Length > 0)
        {
            DontHookTextBox.Focus();
            MessageBox.Show("Hibás adatokat adtál meg!", "Hiba", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        ÁtfedésSection["UseSimpleOverlay"].StringValue = DontHookTextBox.Text;

        ÁtfedésSection["DontHookRendering"].StringValue = DonthookapiTextbox.Text;
        DontHookTextBox.Text = DontHookTextBox.Text.Trim();
        ÁtfedésSection["UseSimpleOverlay"].StringValue = DontHookTextBox.Text.Trim();

        if (BeszédSection["Bekapcsolva"].BoolValue)
            KovetkezoBeszed = DateTime.Now.AddMinutes(BeszédSection["Gyakoriság"].IntValue);

        if (TriggerActiontextBox.Text != "" && TriggerWordtextBox.Text != "")
        {
            if (Utils.CharToHexKeyCode(TriggerActiontextBox.Text.Trim().ToLower()) == 0x00)
            {
                TriggerActiontextBox.Text = "";
                TriggerWordtextBox.Text = "";
                HangfelismerésSection["Eredmény_billentyű"].StringValue = "";
                HangfelismerésSection["Kiváltó_Szó"].StringValue = "";
                MessageBox.Show("Nem engedélyezett billentyűt írtál be.", "Hiba", MessageBoxButtons.OK,
                    MessageBoxIcon.Stop);
            }
            else
            {
                HangfelismerésSection["Eredmény_billentyű"].StringValue = TriggerActiontextBox.Text.Trim().ToLower();
                HangfelismerésSection["Kiváltó_Szó"].StringValue = TriggerWordtextBox.Text.Trim().ToLower();
            }
        }

        ConfigParser.SaveToFile($"{BasePath}\\{SetttingsFileName}");
        ZipContent =
            Utils.LoadPasswordProtectedZipIntoMemory($"{BasePath}\\Hangok\\{BeszédSection["Hang"].StringValue}",
                ZipPassword);

        if (QuickMenucheckBox.Checked)
            //BlockMiddleClick.ActivateHook();
            MouseButtonPress.ActivateMouseHook();
        else
            //BlockMiddleClick.DeactivateHook();
            MouseButtonPress.DeactivateMouseHook();

        if (HangfelismerésSection["Bekapcsolva"].BoolValue)
            SpeechRecognition.ActivateRecognition(VoskModel);
        else
            SpeechRecognition.DeactivateRecognition();

        MessageBox.Show("A beállítások sikeresen mentésre kerültek!", "Információ", MessageBoxButtons.OK,
            MessageBoxIcon.Information);
    }

    /// <summary>
    ///     Create or delete the task that starts the application on startup
    /// </summary>
    private void CreateTask()
    {
        if (startup_checkbox.Checked)
            using (var td = TaskService.Instance.NewTask())
            {
                td.RegistrationInfo.Description = "Elindítja a Beszélő órát.";
                var lt = new LogonTrigger();
                lt.Delay = TimeSpan.FromSeconds(10);
                td.Triggers.Add(lt);
                td.Principal.RunLevel = TaskRunLevel.Highest;
                td.Actions.Add(Application.ExecutablePath, "auto");
                TaskService.Instance.RootFolder.RegisterTaskDefinition(
                    Assembly.GetExecutingAssembly().GetName().Name, td);
                lt.Dispose();
            }
        else
            using (var ts = new TaskService())
            {
                if (ts.GetTask(Assembly.GetExecutingAssembly().GetName().Name) != null)
                    ts.RootFolder.DeleteTask(Assembly.GetExecutingAssembly().GetName().Name);
            }
    }

    /// <summary>
    ///     Set the application to start on startup
    /// </summary>
    private void SetStartup()
    {
        var rk = Registry.CurrentUser.OpenSubKey
            ("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", true);
        IndításSection["Automatikus"].BoolValue = startup_checkbox.Checked;
        if (startup_checkbox.Checked)
            rk.SetValue(Assembly.GetExecutingAssembly().GetName().Name, Application.ExecutablePath);
        else
            rk.DeleteValue(Assembly.GetExecutingAssembly().GetName().Name, false);

        rk.Dispose();
    }

    private void ResetNotification()
    {
        ResetCustomButtons();
        // Get the last item in the collection
        var lastItem = _warnings.DropDownItems[_warnings.DropDownItems.Count - 1];

        // Check if it is a ToolStripMenuItem
        if (lastItem is ToolStripMenuItem menuItem)
        {
            menuItem.Checked = false;
            menuItem.Text = "Egyedi...";
        }
    }

    private void szamlalo_Tick(object sender, EventArgs e)
    {
        JelenlegiIdo = DateTime.Now;
        FullScreenApplicationProcess = FullScreenChecker.GetForegroundFullscreenProcess();
        FullScreenApplicationRunning = FullScreenApplicationProcess != null;
        if (ÁtfedésSection["Bekapcsolva"].BoolValue) UpdateOverlay();

        if (HangfelismerésSection["Bekapcsolva"].BoolValue && DefaultBrowerPath != "")
            if (DefaultBrowserPlayingAudio !=
                Utils.IsProcessPlayingAudio(
                    Path.GetFileNameWithoutExtension(DefaultBrowerPath)))
            {
                DefaultBrowserPlayingAudio = !DefaultBrowserPlayingAudio;

                if (DefaultBrowserPlayingAudio)
                    SpeechRecognition.DisableVoiceRecognition();
                else
                    SpeechRecognition.EnableVoiceRecognition();
            }

        if (NotificationEnabled)
            if (NextNotificationDate <= JelenlegiIdo)
            {
                if (!FullScreenApplicationRunning)
                    Utils.ShowAlert("Figyelmeztetés!", "Egy előre beállított figyelmeztető lejárt.",
                        30);
                if (!PlayingRadio)
                    PlaySound(AlarmSound);
                if (!NotificationRepeate)
                {
                    NotificationEnabled = false;
                    ResetNotification();
                }
                else
                {
                    NextNotificationDate = JelenlegiIdo.AddMinutes(MinutesUntil(FigyelmeztetésSection["Óra"].IntValue,
                        FigyelmeztetésSection["Perc"].IntValue));
                }
            }

        var shouldAnnounce = BeszédSection["Igazítás"].BoolValue
            ? JelenlegiIdo.Minute % BeszédSection["Gyakoriság"].IntValue == 0
            : JelenlegiIdo.Hour == KovetkezoBeszed.Hour && JelenlegiIdo.Minute == KovetkezoBeszed.Minute;

        if (shouldAnnounce && BeszédSection["Bekapcsolva"].BoolValue)
        {
            if (!Kimondva)
            {
                KovetkezoBeszed = JelenlegiIdo.AddMinutes(BeszédSection["Gyakoriság"].IntValue);
                Kimondva = true;
                Most_mod();
            }
        }
        else
        {
            Kimondva = false;
        }

        if (HáttérképSection["Bekapcsolva"].BoolValue &&
            JelenlegiIdo.Day != HáttérképSection["Utolsó_frissítés"].DateTimeValue.Day /*&& JelenlegiIdo.Hour > 9*/)
            try
            {
                DataServices.SetDailyWallpaperAsync();
                HáttérképSection["Utolsó_frissítés"].DateTimeValue = JelenlegiIdo;
                ConfigParser.SaveToFile($"{BasePath}\\{SetttingsFileName}");
            }
            catch (Exception exception)
            {
                Debug.WriteLine(exception);
                HáttérképSection["Bekapcsolva"].BoolValue = false;
            }

        if (PendingWidgetUpdate /*&& !FullScreenApplicationRunning*/) WidgetUpdate();
    }

    private void Form1_FormClosing(object sender, FormClosingEventArgs e)
    {
        if (e.CloseReason == CloseReason.UserClosing)
        {
            isVisibleCore = false;
            Hide();
            e.Cancel = true;
        }
    }

    private void button3_Click(object sender, EventArgs e)
    {
        SpeechRecognition.FullCleanup();
        Application.Exit();
    }

    private static void hangok_kereses()
    {
        hangok_comboBox?.Items?.Clear();
        var hangokMappaLista = Directory.GetFiles($"{BasePath}\\Hangok");
        foreach (var s in hangokMappaLista)
            if (!s.Contains("mp3"))
                hangok_comboBox.Items.Add(Path.GetFileName(s));
    }

    private void pictureBox1_Click(object sender, EventArgs e)
    {
        hangok_kereses();
    }

    /// <summary>
    ///     Get the current time from an NTP server
    /// </summary>
    /// <param name="ntpServer">The address of the NTP server.</param>
    /// <returns></returns>
    public static DateTime GetNetworkTime(string ntpServer)
    {
        const int daysTo1900 = 1900 * 365 + 95; // 95 = offset for leap-years etc.
        const long ticksPerSecond = 10000000L;
        const long ticksPerDay = 24 * 60 * 60 * ticksPerSecond;
        const long ticksTo1900 = daysTo1900 * ticksPerDay;

        var ntpData = new byte[48];
        ntpData[0] = 0x1B; // LeapIndicator = 0 (no warning), VersionNum = 3 (IPv4 only), Mode = 3 (Client Mode)

        var addresses = Dns.GetHostEntry(ntpServer).AddressList;
        var ipEndPoint = new IPEndPoint(addresses[0], 123);
        var pingDuration = Stopwatch.GetTimestamp(); // temp access (JIT-Compiler need some time at first call)
        using (var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp))
        {
            socket.Connect(ipEndPoint);
            socket.ReceiveTimeout = 5000;
            socket.Send(ntpData);
            pingDuration = Stopwatch.GetTimestamp(); // after Send-Method to reduce WinSocket API-Call time

            socket.Receive(ntpData);
            pingDuration = Stopwatch.GetTimestamp() - pingDuration;
        }

        var pingTicks = pingDuration * ticksPerSecond / Stopwatch.Frequency;

        // optional: display response-time
        // Debug.WriteLine("{0:N2} ms", new TimeSpan(pingTicks).TotalMilliseconds);

        var intPart = ((long)ntpData[40] << 24) | ((long)ntpData[41] << 16) | ((long)ntpData[42] << 8) | ntpData[43];
        var fractPart = ((long)ntpData[44] << 24) | ((long)ntpData[45] << 16) | ((long)ntpData[46] << 8) | ntpData[47];
        var netTicks = intPart * ticksPerSecond + ((fractPart * ticksPerSecond) >> 32);

        var networkDateTime = new DateTime(ticksTo1900 + netTicks + pingTicks / 2);

        return networkDateTime.ToLocalTime(); // without ToLocalTime() = faster
    }

    private void button4_Click(object sender, EventArgs e)
    {
        button4.Enabled = false;
        try
        {
            ChangeDateTime(GetNetworkTime(SzinkronizálásSection["Szerver"].StringValue));
        }
        catch (Exception ex)
        {
            Debug.WriteLine(ex.Message);
            MessageBox.Show("Nem sikerült a szinkronizálás!", "Hiba", MessageBoxButtons.OK, MessageBoxIcon.Error);
            button4.Enabled = true;
            return;
        }

        MessageBox.Show("Sikerült az időszikronizálás!", "Siker", MessageBoxButtons.OK, MessageBoxIcon.Information);
        button4.Enabled = true;
    }

    /// <summary>
    ///     Change the system time
    /// </summary>
    /// <param name="newDate"></param>
    /// <exception cref="Win32Exception"></exception>
    private static void ChangeDateTime(DateTime newDate)
    {
        var dateTime = newDate.ToUniversalTime();

        var st = new SYSTEMTIME
        {
            wYear = (ushort)dateTime.Year,
            wMonth = (ushort)dateTime.Month,
            wDay = (ushort)dateTime.Day,
            wHour = (ushort)dateTime.Hour,
            wMinute = (ushort)dateTime.Minute,
            wSecond = (ushort)dateTime.Second
        };

        // Use SetSystemTime from Kernel32 to set the system time
        if (!Kernel32.SetSystemTime(st)) throw new Win32Exception();
    }

    private void synctime_timer_Tick(object sender, EventArgs e)
    {
        Debug.WriteLine("Automatikus időszinkronizálás!");
        DoTimeSync();
    }

    private void button5_Click(object sender, EventArgs e)
    {
        if (Nevjegy == null || Nevjegy.IsDisposed)
        {
            Nevjegy = new Nevjegy();
            Nevjegy.Show();
        }
        else
        {
            Nevjegy?.Focus();
        }
    }

    private void Volume_trackBar_Scroll(object sender, EventArgs e)
    {
        label3.Text = $"{Volume_trackBar.Value}%";
    }


    internal static void SetWarningTime(int perc)
    {
        NextNotificationDate = DateTime.Now.AddMinutes(perc);
        NotificationEnabled = true;
    }

    internal static void DisableCustomNotification()
    {
        var lastItem = _warnings.DropDownItems[_warnings.DropDownItems.Count - 1];
        if (lastItem is ToolStripMenuItem menuItem)
        {
            menuItem.Checked = false;
            menuItem.Text = "Egyedi...";
        }

        var lastItem2 =
            QuickMenu.radApplicationMenu2.Items[QuickMenu.radApplicationMenu2.Items.Count - 1] as RadMenuItem;
        lastItem2.Text = "Egyedi...";
        lastItem2.IsChecked = false;
        NotificationEnabled = false;
        NextNotificationDate = DateTime.MinValue;
        if (NotificationEnabled)
        {
            FigyelmeztetésSection["Óra"].IntValue = -1;
            FigyelmeztetésSection["Perc"].IntValue = -1;
            NotificationRepeate = false;
            ConfigParser.SaveToFile($"{BasePath}\\{SetttingsFileName}");
        }
    }


    private void ExitButton_Click(object sender, EventArgs e)
    {
        SpeechRecognition.FullCleanup();
        Application.Exit();
    }

    /// <summary>
    ///     Simulate a key press
    /// </summary>
    /// <param name="keyCode"></param>
    internal static void SimulateRealKeyPress(User32.VK keyCode)
    {
        User32.keybd_event(keyCode, 0, KeyeventfKeydown,
            IntPtr.Zero);

        Thread.Sleep(50);
        User32.keybd_event(keyCode, 0, User32.KEYEVENTF.KEYEVENTF_KEYUP,
            IntPtr.Zero);
    }

    internal static async Task<bool> UpdateWeatherData()
    {
        if (_nextWeatherCheck < DateTime.Now)
            try
            {
                var weatherJson = await DataServices.GetWeatherdotComAsync(Cordinates, Secrets.WeatherdotcomApiKey);
                weatherData = JsonDocument.Parse(weatherJson);
                return true;
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error fetching weather data: {ex.Message}");
                return false;
            }

        return false;
    }

    internal static async Task UpdateLocationData()
    {
        if (string.IsNullOrEmpty(Location))
            try
            {
                var locationJson = await DataServices.GetLocationByIpAsync();
                using var locationData = JsonDocument.Parse(locationJson);
                var root = locationData.RootElement;

                Cordinates = root.GetProperty("loc").GetString();
                Location = root.GetProperty("city").GetString();

                if (string.IsNullOrEmpty(Location))
                    throw new Exception("Failed to retrieve location from IP.");
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error retrieving location by IP: {ex.Message}");
            }
    }

    /// <summary>
    ///     Announce the current weather
    /// </summary>
    /// <returns></returns>
    internal static async Task AnnounceWeather()
    {
        await UpdateLocationData();

        if (_weatherSound != null && _nextWeatherCheck >= DateTime.Now)
        {
            //DataServices.PlayStream(_weatherSound, 1.3f);
            PlaySound(new MemoryStream(_weatherSound));
            return;
        }

        await UpdateWeatherData();

        try
        {
            var current = weatherData.RootElement.GetProperty("v3-wx-observations-current");
            var temperature = current.GetProperty("temperature").GetInt32();
            var condition = current.GetProperty("wxPhraseLong").GetString();

            var temperatureText = temperature >= 0
                ? $"Jelenleg {temperature} fok van és az időjárás {condition}."
                : $"Jelenleg mínusz {temperature} fok van és az időjárás {condition}.";

            _weatherSound = await DataServices.ConvertTextToSpeech(temperatureText);
            _nextWeatherCheck = DateTimeOffset.FromUnixTimeSeconds(current.GetProperty("expirationTimeUtc").GetInt64())
                .LocalDateTime;
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"Error processing weather data: {ex.Message}");
            return;
        }

        //DataServices.PlayStream(_weatherSound, 1.3f);
        PlaySound(new MemoryStream(_weatherSound));
    }

    /// <summary>
    ///     Announce the forecast for the next day
    /// </summary>
    /// <returns></returns>
    internal static async Task AnnounceForecast()
    {
        await UpdateLocationData();

        if (_forecastSound != null && _nextWeatherCheck >= DateTime.Now)
        {
            //DataServices.PlayStream(_forecastSound, 1.3f);
            PlaySound(new MemoryStream(_forecastSound));
            return;
        }

        await UpdateWeatherData();

        try
        {
            var current = weatherData.RootElement.GetProperty("v3-wx-observations-current");
            var forecast = weatherData.RootElement.GetProperty("v3-wx-forecast-daily-3day").GetProperty("daypart")[0];

            var dataindex = 0;
            for (var i = 0; i < forecast.GetProperty("daypartName").GetArrayLength(); i++)
                if (forecast.GetProperty("daypartName")[i].GetString() == "Holnap")
                {
                    dataindex = i;
                    break;
                }

            var minTemp = forecast.GetProperty("temperature")[dataindex + 1].GetInt32() >= 0
                ? forecast.GetProperty("temperature")[dataindex + 1].GetInt32().ToString()
                : $"mínusz {forecast.GetProperty("temperature")[dataindex + 1].GetInt32()}";

            var maxTemp = forecast.GetProperty("temperature")[dataindex].GetInt32() >= 0
                ? forecast.GetProperty("temperature")[dataindex].GetInt32().ToString()
                : $"mínusz {forecast.GetProperty("temperature")[dataindex].GetInt32()}";

            var temperatureText =
                $"Holnap a hőmérséklet {minTemp} és {maxTemp} fok között lesz. Holnapi időjárás: {forecast.GetProperty("wxPhraseLong")[dataindex].GetString()}. Csapadék valószínűsége {forecast.GetProperty("precipChance")[dataindex].GetInt32()} százalék.";

            _forecastSound = await DataServices.ConvertTextToSpeech(temperatureText);
            _nextWeatherCheck = DateTimeOffset.FromUnixTimeSeconds(current.GetProperty("expirationTimeUtc").GetInt64())
                .LocalDateTime;
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"Error processing weather data: {ex.Message}");
            return;
        }

        // DataServices.PlayStream(_forecastSound, 1.3f);
        PlaySound(new MemoryStream(_forecastSound));
    }

    /// <summary>
    ///     Announce the name days of the day
    /// </summary>
    /// <returns></returns>
    internal static async Task AnnounceNameDay()
    {
        //  if (OnlineRadioPlayer._playbackState == OnlineRadioPlayer.PlaybackState.Playing) return;
        try
        {
            if (string.IsNullOrEmpty(NameDays) || _namedaySound == null || LastNamedayIndex != DateTime.Now.Day)
            {
                var root = JsonDocument.Parse(await DataServices.GetNamedaysAsync()).RootElement;

                if (!root.TryGetProperty("nev1", out var nev1))
                {
                    Debug.WriteLine("Error: 'nev1' key is missing in the response.");
                    return;
                }

                NameDays = string.Join(", ", nev1.EnumerateArray().Select(n => n.GetString()));
                LastNamedayIndex = DateTime.Now.Day;

                try
                {
                    _namedaySound =
                        await DataServices.ConvertTextToSpeech(
                            $"Mai napon a névnapját ünnepli: {NameDays.Replace(", ", " és ")}");
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"Error during text-to-speech conversion: {ex.Message}");
                    return;
                }


                try
                {
                    //DataServices.PlayStream(_namedaySound, 1.3f);
                    PlaySound(new MemoryStream(_namedaySound));
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"Error during audio playback: {ex.Message}");
                }
            }
            else
            {
                Debug.WriteLine("Old");


                try
                {
                    //DataServices.PlayStream(_namedaySound, 1.3f);
                    PlaySound(new MemoryStream(_namedaySound));
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"Error during audio playback: {ex.Message}");
                }
            }
        }
        catch (HttpRequestException httpEx)
        {
            Debug.WriteLine($"Network error: {httpEx.Message}");
        }
        catch (JsonException jsonEx)
        {
            Debug.WriteLine($"JSON parsing error: {jsonEx.Message}");
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"An unexpected error occurred: {ex.Message}");
        }
    }


    private void beállításokToolStripMenuItem_Click(object sender, EventArgs e)
    {
        isVisibleCore = true;
        Visible = !Visible;
    }

    private void holnapiIdőjárásToolStripMenuItem_Click(object sender, EventArgs e)
    {
        AnnounceForecast();
    }

    private void maiIdőjárásToolStripMenuItem_Click(object sender, EventArgs e)
    {
        AnnounceWeather();
    }

    private void maiNévnapToolStripMenuItem_Click(object sender, EventArgs e)
    {
        AnnounceNameDay();
    }

    /// <summary>
    ///     Start playing a radio station
    /// </summary>
    /// <param name="url"></param>
    /// <param name="randioName"></param>
    /// <returns></returns>
    internal static async Task StartRadio(string url, string randioName)
    {
        if (WidgetSection["Rádió_Bekapcsolva"].BoolValue && radioPlayerWidget._isPlaying) return;
        while (Lejátszás) await Task.Delay(100);
        PlayingRadio = true;
        SafeInvoke(SayItNowbutton, () => { SayItNowbutton.Enabled = false; });
        if (_radioControl == null || _radioControl.IsDisposed)
            _radioControl = new RadioControl();
        _radioControl.Radiolabel.Text = randioName;
        if (RádióSection["Hangerő"].IntValue == -1)
        {
            Debug.WriteLine("Új érték");
            RádióSection["Hangerő"].IntValue = BeszédSection["Hangerő"].IntValue;
            ConfigParser.SaveToFile($"{BasePath}\\{SetttingsFileName}");
        }

        RadioControl.RadiotrackBar.Value = RádióSection["Hangerő"].IntValue;
        OnlineRadioPlayer.PlayStreamAsync(url);
        _radioControl.Show();
    }

    private void DelayedLoadTimer_Tick(object sender, EventArgs e)
    {
        DelayedLoadTimer.Enabled = false;
        PostLauchSetup();
        DelayedLoadTimer.Dispose();
    }

    private async void button6_Click(object sender, EventArgs e)
    {
        /* if (File.Exists("UserData") && GmailSection["Bekapcsolva"].BoolValue)
         {
             File.Delete("UserData");
             MailTimer.Enabled = false;
             Gmailbutton.Text = "Gmail \u274c";
             GmailSection["Bekapcsolva"].BoolValue = false;
             GmailSection["Utolsó_ellenőrzés"].StringValue = "";
             ConfigParser.SaveToFile($"{Path}\\{SetttingsFileName}");
             GmailMailChecker.DisposeData();
             MessageBox.Show("Gmail értesítések sikeresen kikapcsolva!", "Információ", MessageBoxButtons.OK,
                 MessageBoxIcon.Information);
         }
         else
         {
             await GmailMailChecker.InitializeGmailServiceAsync();
             MailTimer.Enabled = true;
             Gmailbutton.Text = "Gmail \u2714\ufe0f";
             GmailSection["Bekapcsolva"].BoolValue = true;
             GmailSection["Utolsó_ellenőrzés"].DateTimeValue = DateTime.Now;
             ConfigParser.SaveToFile($"{Path}\\{SetttingsFileName}");
             MessageBox.Show("Sikerült bekapcsolni a Gmail értesítéseket!", "Információ", MessageBoxButtons.OK,
                 MessageBoxIcon.Information);
         }*/
    }

    private void MailTimer_Tick(object sender, EventArgs e)
    {
        /* if (!FullScreenChecker.IsAppInFullScreen())
             GmailMailChecker.CheckForUnreadEmailsAsync(GmailSection["Utolsó_ellenőrzés"].DateTimeValue);*/
    }

    /// <summary>
    ///     Reset the buttons for the custom warnings
    /// </summary>
    internal static void ResetCustomButtons()
    {
        foreach (ToolStripItem item in _warnings.DropDownItems)
            if (item is ToolStripMenuItem menuItem)
                menuItem.Checked = false; // Uncheck the item

        foreach (RadMenuItem item in QuickMenu.radApplicationMenu2.Items)
            if (item is RadMenuItem menuItem)
                menuItem.IsChecked = false; // Uncheck the item
    }

    /// <summary>
    ///     Initalize the application after a small delay
    /// </summary>
    private static async Task PostLauchSetup()
    {
        Task.Run(async () =>
        {
            /*if (RádióSection["Utolsó_frissítés"].DateTimeValue < DateTime.Now)
            {
                Debug.WriteLine("Updating radio stations...");
                try
                {
                    await DataServices.DownloadFileAsync(
                        "https://raw.githubusercontent.com/zoli456/Speaking_clock/main/stations/RadioStations_enc.dat",
                        $"{BasePath}\\Fájlok\\RadioStations.dat");
                    RádióSection["Utolsó_frissítés"].DateTimeValue = DateTime.Now.AddDays(2);
                    ConfigParser.SaveToFile($"{BasePath}\\{SetttingsFileName}");
                    Debug.WriteLine("Updating radios was successful.");
                }
                catch (Exception ex)
                {
                }
            }*/


            if (File.Exists($"{BasePath}\\Fájlok\\RadioStations.dat"))
            {
                var file2 = File.ReadAllLines($"{BasePath}\\Fájlok\\RadioStations.dat");
                for (var i = 0; i < file2.Length; i++)
                {
                    var temp = file2[i].Split("\t");
                    RadioNames.Add(temp[0]);
                    RandioUrLs.Add(temp[1]);
                }

                for (var i = 0; i < RadioNames.Count; i++)
                {
                    var index = i;
                    var subMenuItem = new ToolStripMenuItem { Text = RadioNames[index] };
                    subMenuItem.Click += (sender, e) => { StartRadio(RandioUrLs[index], RadioNames[index]); };
                    rádióToolStripMenuItem.DropDownItems.Add(subMenuItem);
                }
            }
        });

        for (var i = 0; i < warningTimes.Length; i++)
        {
            var index = i;
            var subMenuItem = new ToolStripMenuItem { Text = $"{warningTimes[index]} perc múlva" };
            subMenuItem.Click += (sender, e) =>
            {
                var clickedItem = sender as ToolStripMenuItem;

                if (!subMenuItem.Checked)
                {
                    DisableCustomNotification();
                    SetWarningTime(warningTimes[index]);
                    Debug.WriteLine($"Set a notification in {warningTimes[index]} minutes.");
                    if (clickedItem != null && clickedItem.Owner != null)
                        foreach (ToolStripItem item in clickedItem.Owner.Items)
                            if (item is ToolStripMenuItem menuItem)
                                menuItem.Checked = menuItem == clickedItem;
                }
                else
                {
                    (_warnings.DropDownItems[index] as ToolStripMenuItem).Checked =
                        false;
                    DisableCustomNotification();
                }
            };
            _warnings.DropDownItems.Add(subMenuItem);
        }


        var CustomsubMenuItem = new ToolStripMenuItem { Text = "Egyedi..." };
        CustomsubMenuItem.Click += (sender, e) =>
        {
            if (CustomsubMenuItem.Checked)
            {
                DisableCustomNotification();
            }
            else
            {
                CustomWarningForm = new CustomWarningForm();
                CustomWarningForm.Show();
            }
        };
        _warnings.DropDownItems.Add(CustomsubMenuItem);
        if (FigyelmeztetésSection["Óra"].IntValue != -1 && FigyelmeztetésSection["Perc"].IntValue != -1)
        {
            NotificationEnabled = true;
            var lastItem = _warnings.DropDownItems[_warnings.DropDownItems.Count - 1];

            // Check if it is a ToolStripMenuItem
            if (lastItem is ToolStripMenuItem menuItem)
            {
                menuItem.Checked = true;
                menuItem.Text =
                    $"Figyelmeztetés {FigyelmeztetésSection["Óra"].IntValue}:{FigyelmeztetésSection["Perc"].IntValue} kor";
            }
        }

        AlarmSound = new MemoryStream(File.ReadAllBytes($"{BasePath}\\Hangok\\alarm.mp3"));
        NotificationSound = new MemoryStream(File.ReadAllBytes($"{BasePath}\\Hangok\\notification.mp3"));
        hangok_kereses();
        hangok_comboBox.SelectedIndex = hangok_comboBox.FindStringExact(BeszédSection["Hang"].StringValue);
        ZipContent =
            Utils.LoadPasswordProtectedZipIntoMemory($"{BasePath}\\Hangok\\{BeszédSection["Hang"].StringValue}",
                ZipPassword);

        /* if (GmailSection["Bekapcsolva"].BoolValue)
         {
             GmailMailChecker.InitializeGmailServiceAsync();
             MailTimer.Enabled = true;
             Gmailbutton.Text = "Gmail \u2714\ufe0f";
         }
         else
         {
             Gmailbutton.Text = "Gmail \u274c";
         }*/

        if (HangfelismerésSection["Bekapcsolva"].BoolValue) SpeechRecognition.ActivateRecognition(VoskModel);
        Gmailbutton.Enabled = true;
        Applybutton.Enabled = true;


        QuickMenu = new QuickMenu();
        QuickMenu.Dispose();

        TrayIcon.Text = "Beszélő óra";
        TrayIcon.ContextMenuStrip = TimerMenu;


        DoTimeSync();

        if (RSS_Reader_Section["Olvasó_1_Bekapcsolva"].BoolValue) EnableRSSReader(1);
        if (RSS_Reader_Section["Olvasó_2_Bekapcsolva"].BoolValue) EnableRSSReader(2);
        if (RSS_Reader_Section["Olvasó_3_Bekapcsolva"].BoolValue) EnableRSSReader(3);
        if (RSS_Reader_Section["Olvasó_4_Bekapcsolva"].BoolValue) EnableRSSReader(4);

        if (WidgetSection["Analóg_Bekapcsolva"].BoolValue)
        {
            Debug.WriteLine("Analóg óra bekapcsolva!");
            analogClock = new AnalogClock(WidgetSection["Analóg_X"].IntValue, WidgetSection["Analóg_Y"].IntValue,
                WidgetSection["Analóg_méret"].FloatValue);
        }

        if (WidgetSection["Pontozott_Bekapcsolva"].BoolValue)
        {
            Debug.WriteLine("Pontozott óra bekapcsolva!");
            dotMatrix = new DotMatrixClock(WidgetSection["Pontozott_másodperc"].BoolValue,
                WidgetSection["Pontozott_X"].IntValue,
                WidgetSection["Pontozott_Y"].IntValue, WidgetSection["Pontozott_pont_méret"].IntValue,
                WidgetSection["Pontozott_pont_távolság"].IntValue, WidgetSection["Pontozott_szám_távolság"].IntValue);
        }

        if (WidgetSection["Naptár_Bekapcsolva"].BoolValue)
        {
            Debug.WriteLine("Naptár bekapcsolva!");
            calendarWidget = new CalendarWidget(WidgetSection["Naptár_X"].IntValue, WidgetSection["Naptár_Y"].IntValue);
        }

        if (WidgetSection["Névnap_Bekapcsolva"].BoolValue)
        {
            Debug.WriteLine("Névnap bekapcsolva!");
            NamedayWidgetWidget =
                new NamedayWidget(WidgetSection["Névnap_X"].IntValue, WidgetSection["Névnap_Y"].IntValue);
        }

        if (WidgetSection["Rádió_Bekapcsolva"].BoolValue)
        {
            Debug.WriteLine("Rádió bekapcsolva!");
            radioPlayerWidget =
                new RadioPlayerWidget(WidgetSection["Rádió_X"].IntValue, WidgetSection["Rádió_Y"].IntValue);
        }

        if (WidgetSection["Időjárás_Bekapcsolva"].BoolValue)
        {
            Debug.WriteLine("Időjárás bekapcsolva!");
            await UpdateLocationData();
            await UpdateWeatherData();
            weatherWidget =
                new WeatherWidget(WidgetSection["Időjárás_X"].IntValue, WidgetSection["Időjárás_Y"].IntValue,
                    WidgetSection["Időjárás_Napok"].IntValue);
        }

        if (WidgetSection["Aknakereső_Bekapcsolva"].BoolValue)
        {
            Debug.WriteLine("Aknakereső bekapcsolva!");
            minesweeperForm =
                new Minesweeper(WidgetSection["Aknakereső_X"].IntValue, WidgetSection["Aknakereső_Y"].IntValue);
        }

        if (WidgetSection["Zászló_Bekapcsolva"].BoolValue)
        {
            Debug.WriteLine("Zászló bekapcsolva!");
            flagguesserForm =
                new Flagguesser(WidgetSection["Zászló_X"].IntValue, WidgetSection["Zászló_Y"].IntValue);
        }

        if (WidgetSection["Quiz_Bekapcsolva"].BoolValue)
        {
            Debug.WriteLine("Quiz bekapcsolva!");
            quizForm =
                new QuizWidget(WidgetSection["Quiz_X"].IntValue, WidgetSection["Quiz_Y"].IntValue);
        }

        if (WidgetSection["Logo_Bekapcsolva"].BoolValue)
        {
            Debug.WriteLine("Logo bekapcsolva!");
            logoGuesserForm =
                new LogoGuesser(WidgetSection["Logo_X"].IntValue, WidgetSection["Logo_Y"].IntValue);
        }

        if (BeszédSection["Bekapcsolva"].BoolValue)
            KovetkezoBeszed = DateTime.Now.AddMinutes(BeszédSection["Gyakoriság"].IntValue);
        TrayIcon.Visible = true;
        szamlalo.Enabled = true;

        KeyboardFunction.ActivateKeyboardHook();
        if (GyorsmenüSection["Bekapcsolva"].BoolValue)
        {
            QuickMenucheckBox.Checked = true;
            MouseButtonPress.ActivateMouseHook();
        }

        Task.Run(() => { OverlayMessenger.RunServerLoop(); });
    }

    internal static void EnableRSSReader(int index)
    {
        var rssReaderSetting = new RssReaderSettings();
        Debug.WriteLine($"RSS Olvasó {index} bekapcsolva!");
        rssReaderSetting.InitialX = RSS_Reader_Section[$"Olvasó_{index}_Pos_X"].IntValue;
        rssReaderSetting.InitialY = RSS_Reader_Section[$"Olvasó_{index}_Pos_Y"].IntValue;
        switch (index)
        {
            case 1:
            {
                rssReaderSetting.HeaderColor = "blue";
                break;
            }
            case 2:
            {
                rssReaderSetting.HeaderColor = "red";
                break;
            }
            case 3:
            {
                rssReaderSetting.HeaderColor = "green";
                break;
            }
            case 4:
            {
                rssReaderSetting.HeaderColor = "orange";
                break;
            }
        }

        rssReader[index - 1] = new RssReader(index, RSS_Reader_Section[$"Olvasó_{index}_URL"].StringValue,
            RSS_Reader_Section[$"Olvasó_{index}_Név"].StringValue, rssReaderSetting);
    }

    private void hardwareToolStripMenuItem_Click(object sender, EventArgs e)
    {
        if (SystemInformation == null || SystemInformation.IsDisposed)
        {
            SystemInformation = new SystemInformation();
        }
        else
        {
            SystemInformation.Dispose();
            SystemInformation = new SystemInformation();
        }

        SystemInformation.InfotextBox.Text += ComputerInfo.WindowsNevEsVerzio() + Environment.NewLine;
        SystemInformation.InfotextBox.Text +=
            $"Windows aktivációs állapot:  {ComputerInfo.WindowsAktivaciosAllapot()}" + Environment.NewLine;
        SystemInformation.InfotextBox.Text += $"TPM bekapcsolva: {ComputerInfo.IsTpmEnabled()}" + Environment.NewLine;
        SystemInformation.InfotextBox.Text +=
            $"Biztonságos rendszerindítás bekapcsolva: {ComputerInfo.IsSecureBootEnabled()}" + Environment.NewLine;
        SystemInformation.InfotextBox.Text += $"Víruskereső(k):  {string.Join(", ", ComputerInfo.VirusScannerNev())}" +
                                              Environment.NewLine;
        SystemInformation.InfotextBox.Text += $"Alaplap:  {ComputerInfo.AlaplapNev()}" + Environment.NewLine;
        SystemInformation.InfotextBox.Text += $"Processzor:  {ComputerInfo.ProcesszorNev()}" + Environment.NewLine;
        SystemInformation.InfotextBox.Text += $"RAM:  {ComputerInfo.RamMeret()}" + Environment.NewLine;
        SystemInformation.InfotextBox.Text += $"Videókártya:  {ComputerInfo.VgaNev()}" + Environment.NewLine;
        SystemInformation.InfotextBox.Text += $"Videókártya driver verzió:  {ComputerInfo.VgaDriverVerzio()}";
        SystemInformation.Show();
    }

    private void futóFolyamatokToolStripMenuItem_Click(object sender, EventArgs e)
    {
        if (SystemInformation == null || SystemInformation.IsDisposed)
        {
            SystemInformation = new SystemInformation();
        }
        else
        {
            SystemInformation.Dispose();
            SystemInformation = new SystemInformation();
        }

        var lista = Utils.RendezesElsoBetuAlapjan(ComputerInfo.FutoFolyamatokListazasa());
        foreach (var elem in lista) SystemInformation.InfotextBox.Text += elem + Environment.NewLine;
        SystemInformation.Show();
    }

    private void telepítettProgramokToolStripMenuItem_Click(object sender, EventArgs e)
    {
        if (SystemInformation == null || SystemInformation.IsDisposed)
        {
            SystemInformation = new SystemInformation();
        }
        else
        {
            SystemInformation.Dispose();
            SystemInformation = new SystemInformation();
        }

        var lista = Utils.RendezesElsoBetuAlapjan(ComputerInfo.TelepitettProgramokListazasa());
        foreach (var elem in lista) SystemInformation.InfotextBox.Text += elem + Environment.NewLine;
        SystemInformation.Show();
    }

    private void cKönytárakTelepítéseToolStripMenuItem_Click(object sender, EventArgs e)
    {
        Utils.DownloadAndInstallLatestRelease("abbodi1406", "vcredist", 1, "/y");
    }

    private void directX9TelepítéseToolStripMenuItem_Click(object sender, EventArgs e)
    {
        Utils.DownloadAndInstallDirectX9();
    }

    private void directPlayTelepítésToolStripMenuItem_Click(object sender, EventArgs e)
    {
        Utils.EnableWindowsFeature("DirectPlay");
    }

    private void net35TelepítésToolStripMenuItem_Click(object sender, EventArgs e)
    {
        Utils.EnableWindowsFeature("NetFx3");
    }

    private void hozzáadásADefenderKivételekhezToolStripMenuItem_Click(object sender, EventArgs e)
    {
        Utils.AddFolderToDefenderExclusions();
    }

    private void játékJavítás1TelepítésToolStripMenuItem_Click(object sender, EventArgs e)
    {
        Utils.ExtractPasswordProtectedZip($"{BasePath}\\Fájlok\\GameFix1", "Amjgw9LRXWsXyu5Sw7YE");
    }

    private void játékJavítás2TelepítésToolStripMenuItem_Click(object sender, EventArgs e)
    {
        Utils.ExtractPasswordProtectedZip($"{BasePath}\\Fájlok\\GameFix2", "Amjgw9LRXWsXyu5Sw7YE");
    }

    private void winrarTelepítéseToolStripMenuItem_Click(object sender, EventArgs e)
    {
        DataServices.DownloadAndInstallWinrar();
    }

    private void zipTelepítéseToolStripMenuItem_Click(object sender, EventArgs e)
    {
        DataServices.DownloadAndInstall7Zip();
    }

    private async void nVIDIAVezérlőLetöltésToolStripMenuItem_Click(object sender, EventArgs e)
    {
        /*MessageBox.Show("Hamarosan megfog kezdődni a driver letöltése és utána el fog indulni.", "Információ",
            MessageBoxButtons.OK, MessageBoxIcon.Information);*/
        try
        {
            //DataServices.DownloadAndInstallNvidia();
            var driver = new Driver
            {
                Channel = DriverChannel.GameReady,
                Edition = DriverEdition.DCH
            };
            Process.Start(new ProcessStartInfo
            {
                FileName = await NvidiaDriverFinder.GetLatestNvidiaDriverForGpuAsync(
                    ComputerInfo.VgaNev().Replace("NVIDIA ", ""),
                    driver, ComputerInfo.WindowsNevEsVerzio().Contains("Windows 10")),
                UseShellExecute = true
            });
        }
        catch (Exception a)
        {
            Debug.WriteLine(a);
            MessageBox.Show("Nem sikerül letölteni a drivert.", "Hiba", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    private void button1_Click_1(object sender, EventArgs e)
    {
        if (_widgetForm == null || _widgetForm.IsDisposed)
        {
            _widgetForm = new WidgetSetup();
            _widgetForm.Show();
        }
        else
        {
            _widgetForm?.Focus();
        }
    }

    private void RssUpdateTimer_Tick(object sender, EventArgs e)
    {
        PendingWidgetUpdate = true;
        RssUpdateTimer.Enabled = false;
    }

    private async void WidgetUpdate()
    {
        PendingWidgetUpdate = false;
        RssUpdateTimer.Enabled = true;
        if (RSS_Reader_Section["Olvasó_1_Bekapcsolva"].BoolValue) await rssReader[0].OnUpdateTimerElapsedAsync();
        if (RSS_Reader_Section["Olvasó_2_Bekapcsolva"].BoolValue) await rssReader[1].OnUpdateTimerElapsedAsync();
        if (RSS_Reader_Section["Olvasó_3_Bekapcsolva"].BoolValue) await rssReader[2].OnUpdateTimerElapsedAsync();
        if (RSS_Reader_Section["Olvasó_4_Bekapcsolva"].BoolValue) await rssReader[3].OnUpdateTimerElapsedAsync();
        if (WidgetSection["Időjárás_Bekapcsolva"].BoolValue)
        {
            if (await UpdateWeatherData())
                weatherWidget.FetchWeatherDataAndForecast();
            else
                Debug.WriteLine("Időjárás widget frissítése nem szükséges.");
        }
    }

    internal static void ActivateLegacyOverlay()
    {
        if (!FullScreenApplicationRunning) return;
        if (Overlay == null || Overlay.IsDisposed) Overlay = new OverlayForm();

        if (TimeOverlay == null) TimeOverlay = new TimeOverlayForm();

        Debug.WriteLine("Legacy overlay created.");
    }

    internal static void DeactivateLegacyOverlay()
    {
        if (Overlay != null)
        {
            if (Overlay.InvokeRequired)
            {
                Overlay.Invoke(() =>
                {
                    Overlay?.Close();
                    Overlay?.Dispose();
                    Overlay = null;
                });
            }
            else
            {
                Overlay?.Close();
                Overlay?.Dispose();
                Overlay = null;
            }
        }

        if (TimeOverlay != null)
        {
            TimeOverlay.HideOverlay();
            TimeOverlay?.Dispose();
            TimeOverlay = null;
        }
    }


    private static void UpdateOverlay()
    {
        if (!FullScreenApplicationRunning) return;
        if (DllInjector.IsForceSimpleOverlay($"{FullScreenApplicationProcess.ProcessName}.exe"))
        {
            ActivateLegacyOverlay();
        }
        else
        {
            DeactivateLegacyOverlay();
            if (DllInjector.CurrentProcess == null)
                Task.Run(() => { DllInjector.InjectToForeground(FullScreenApplicationProcess); });

            if (NotificationEnabled)
            {
                if ((NextNotificationDate - DateTime.Now).Minutes < 10)
                    OverlayMessenger.SetButtonTextAsync((NextNotificationDate - DateTime.Now).Minutes
                        .ToString());
                else
                    OverlayMessenger.SetButtonTextAsync("X");
            }
            else
            {
                OverlayMessenger.SetButtonTextAsync("X");
            }
        }
    }

    internal static int MinutesUntil(int targetHour, int targetMinute)
    {
        var now = DateTime.Now;
        var targetTime = new DateTime(
            now.Year, now.Month, now.Day, targetHour, targetMinute, 0
        );

        // If target time already passed today, move it to tomorrow
        if (targetTime <= now)
            targetTime = targetTime.AddDays(1);

        var difference = targetTime - now;
        return (int)Math.Round(difference.TotalMinutes);
    }

    private static void DoTimeSync()
    {
        if (!SzinkronizálásSection["Automatikus"].BoolValue) return;
        Debug.WriteLine("Automatikus időszinkronizálás!");
        try
        {
            button4.Enabled = false;
            ChangeDateTime(GetNetworkTime(SzinkronizálásSection["Szerver"].StringValue));
            button4.Enabled = true;
        }
        catch (Exception ex)
        {
            button4.Enabled = true;
        }
    }
}