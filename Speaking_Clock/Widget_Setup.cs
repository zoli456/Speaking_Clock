using System.Diagnostics;
using Speaking_Clock;
using Speaking_clock.Widgets;
using Speaking_Clock.Widgets;
using Beallitasok = Speaking_Clock.Beallitasok;

namespace Speaking_clock;

public partial class WidgetSetup : Form
{
    private bool initalized;

    public WidgetSetup()
    {
        InitializeComponent();
    }

    private void RSS_button1_Click(object sender, EventArgs e)
    {
        if (RSS_URL_textBox1.Text.Length < 3 || RSS_textBox1.Text.Length < 3)
        {
            MessageBox.Show("Hiányosan töltötted ki az adatokat!", "Hiba", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        Uri uriResult;
        var result = Uri.TryCreate(RSS_URL_textBox1.Text, UriKind.Absolute, out uriResult)
                     && (uriResult.Scheme == Uri.UriSchemeHttp || uriResult.Scheme == Uri.UriSchemeHttps);
        if (!result)
        {
            MessageBox.Show("Érvénytelen URL!", "Hiba", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        Beallitasok.RSS_Reader_Section["Olvasó_1_URL"].StringValue = RSS_URL_textBox1.Text;

        Beallitasok.RSS_Reader_Section["Olvasó_1_Név"].StringValue = RSS_textBox1.Text;

        Beallitasok.RSS_Reader_Section["Olvasó_1_Bekapcsolva"].BoolValue =
            !Beallitasok.RSS_Reader_Section["Olvasó_1_Bekapcsolva"].BoolValue;

        Beallitasok.ConfigParser.SaveToFile($"{Beallitasok.BasePath}\\{Beallitasok.SetttingsFileName}");

        if (Beallitasok.RSS_Reader_Section["Olvasó_1_Bekapcsolva"].BoolValue)
        {
            RSS_button1.Text = "Bekapcsolva";
            RSS_textBox1.Enabled = false;
            RSS_URL_textBox1.Enabled = false;
            Debug.WriteLine("RSS olvasó 1 bekapcsolva!");
            Beallitasok.EnableRSSReader(1);
        }
        else
        {
            RSS_button1.Text = "Kikapcsolva";
            RSS_textBox1.Enabled = true;
            RSS_URL_textBox1.Enabled = true;
            Beallitasok.rssReader[0]?.Dispose();
        }

        Focus();
    }

    private void RSS_button2_Click(object sender, EventArgs e)
    {
        if (RSS_URL_textBox2.Text.Length < 3 || RSS_textBox2.Text.Length < 3)
        {
            MessageBox.Show("Hiányosan töltötted ki az adatokat!", "Hiba", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        Uri uriResult;
        var result = Uri.TryCreate(RSS_URL_textBox2.Text, UriKind.Absolute, out uriResult)
                     && (uriResult.Scheme == Uri.UriSchemeHttp || uriResult.Scheme == Uri.UriSchemeHttps);
        if (!result)
        {
            MessageBox.Show("Érvénytelen URL!", "Hiba", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        Beallitasok.RSS_Reader_Section["Olvasó_2_URL"].StringValue = RSS_URL_textBox2.Text;

        Beallitasok.RSS_Reader_Section["Olvasó_2_Név"].StringValue = RSS_textBox2.Text;

        Beallitasok.RSS_Reader_Section["Olvasó_2_Bekapcsolva"].BoolValue =
            !Beallitasok.RSS_Reader_Section["Olvasó_2_Bekapcsolva"].BoolValue;

        Beallitasok.ConfigParser.SaveToFile($"{Beallitasok.BasePath}\\{Beallitasok.SetttingsFileName}");

        if (Beallitasok.RSS_Reader_Section["Olvasó_2_Bekapcsolva"].BoolValue)
        {
            RSS_button2.Text = "Bekapcsolva";
            RSS_textBox2.Enabled = false;
            RSS_URL_textBox2.Enabled = false;
            Debug.WriteLine("RSS olvasó 2 bekapcsolva!");
            Beallitasok.EnableRSSReader(2);
        }
        else
        {
            RSS_button2.Text = "Kikapcsolva";
            RSS_textBox2.Enabled = true;
            RSS_URL_textBox2.Enabled = true;
            Beallitasok.rssReader[1]?.Dispose();
        }

        Focus();
    }

    private void RSS_button3_Click(object sender, EventArgs e)
    {
        if (RSS_URL_textBox3.Text.Length < 3 || RSS_textBox3.Text.Length < 3)
        {
            MessageBox.Show("Hiányosan töltötted ki az adatokat!", "Hiba", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        Uri uriResult;
        var result = Uri.TryCreate(RSS_URL_textBox3.Text, UriKind.Absolute, out uriResult)
                     && (uriResult.Scheme == Uri.UriSchemeHttp || uriResult.Scheme == Uri.UriSchemeHttps);
        if (!result)
        {
            MessageBox.Show("Érvénytelen URL!", "Hiba", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        Beallitasok.RSS_Reader_Section["Olvasó_3_URL"].StringValue = RSS_URL_textBox3.Text;

        Beallitasok.RSS_Reader_Section["Olvasó_3_Név"].StringValue = RSS_textBox3.Text;

        Beallitasok.RSS_Reader_Section["Olvasó_3_Bekapcsolva"].BoolValue =
            !Beallitasok.RSS_Reader_Section["Olvasó_3_Bekapcsolva"].BoolValue;

        Beallitasok.ConfigParser.SaveToFile($"{Beallitasok.BasePath}\\{Beallitasok.SetttingsFileName}");

        if (Beallitasok.RSS_Reader_Section["Olvasó_3_Bekapcsolva"].BoolValue)
        {
            RSS_button3.Text = "Bekapcsolva";
            RSS_textBox3.Enabled = false;
            RSS_URL_textBox3.Enabled = false;
            Debug.WriteLine("RSS olvasó 3 bekapcsolva!");
            Beallitasok.EnableRSSReader(3);
        }
        else
        {
            RSS_button3.Text = "Kikapcsolva";
            RSS_textBox3.Enabled = true;
            RSS_URL_textBox3.Enabled = true;
            Beallitasok.rssReader[2]?.Dispose();
        }

        Focus();
    }

    private void RSS_button4_Click(object sender, EventArgs e)
    {
        if (RSS_URL_textBox4.Text.Length < 3 || RSS_textBox4.Text.Length < 3)
        {
            MessageBox.Show("Hiányosan töltötted ki az adatokat!", "Hiba", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        Uri uriResult;
        var result = Uri.TryCreate(RSS_URL_textBox4.Text, UriKind.Absolute, out uriResult)
                     && (uriResult.Scheme == Uri.UriSchemeHttp || uriResult.Scheme == Uri.UriSchemeHttps);
        if (!result)
        {
            MessageBox.Show("Érvénytelen URL!", "Hiba", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        Beallitasok.RSS_Reader_Section["Olvasó_4_URL"].StringValue = RSS_URL_textBox4.Text;

        Beallitasok.RSS_Reader_Section["Olvasó_4_Név"].StringValue = RSS_textBox4.Text;

        Beallitasok.RSS_Reader_Section["Olvasó_4_Bekapcsolva"].BoolValue =
            !Beallitasok.RSS_Reader_Section["Olvasó_4_Bekapcsolva"].BoolValue;

        Beallitasok.ConfigParser.SaveToFile($"{Beallitasok.BasePath}\\{Beallitasok.SetttingsFileName}");

        if (Beallitasok.RSS_Reader_Section["Olvasó_4_Bekapcsolva"].BoolValue)
        {
            RSS_button4.Text = "Bekapcsolva";
            RSS_textBox4.Enabled = false;
            RSS_URL_textBox4.Enabled = false;
            Beallitasok.EnableRSSReader(4);
        }
        else
        {
            RSS_button4.Text = "Kikapcsolva";
            RSS_textBox4.Enabled = true;
            RSS_URL_textBox4.Enabled = true;
            Beallitasok.rssReader[3]?.Dispose();
        }

        Focus();
    }

    private void RSS_Setup_Load(object sender, EventArgs e)
    {
        /*#if RELEASE
                TopMost = true;
        #endif*/
        if (Beallitasok.RSS_Reader_Section["Olvasó_1_Bekapcsolva"].BoolValue)
        {
            RSS_button1.Text = "Bekapcsolva";
            RSS_textBox1.Enabled = false;
            RSS_URL_textBox1.Enabled = false;
        }
        else
        {
            RSS_button1.Text = "Kikapcsolva";
            RSS_textBox1.Enabled = true;
            RSS_URL_textBox1.Enabled = true;
        }

        if (Beallitasok.RSS_Reader_Section["Olvasó_2_Bekapcsolva"].BoolValue)
        {
            RSS_textBox2.Enabled = false;
            RSS_URL_textBox2.Enabled = false;
            RSS_button2.Text = "Bekapcsolva";
        }
        else
        {
            RSS_textBox2.Enabled = true;
            RSS_URL_textBox2.Enabled = true;
            RSS_button2.Text = "Kikapcsolva";
        }

        if (Beallitasok.RSS_Reader_Section["Olvasó_3_Bekapcsolva"].BoolValue)
        {
            RSS_textBox3.Enabled = false;
            RSS_URL_textBox3.Enabled = false;
            RSS_button3.Text = "Bekapcsolva";
        }
        else
        {
            RSS_textBox3.Enabled = true;
            RSS_URL_textBox3.Enabled = true;
            RSS_button3.Text = "Kikapcsolva";
        }

        if (Beallitasok.RSS_Reader_Section["Olvasó_4_Bekapcsolva"].BoolValue)
        {
            RSS_textBox4.Enabled = false;
            RSS_URL_textBox4.Enabled = false;
            RSS_button4.Text = "Bekapcsolva";
        }
        else
        {
            RSS_textBox4.Enabled = true;
            RSS_URL_textBox4.Enabled = true;
            RSS_button4.Text = "Kikapcsolva";
        }

        Drag_checkbox.Checked = Beallitasok.RSS_Reader_Section["Húzás"].BoolValue;

        RSS_textBox1.Text = Beallitasok.RSS_Reader_Section["Olvasó_1_Név"].StringValue;
        RSS_URL_textBox1.Text = Beallitasok.RSS_Reader_Section["Olvasó_1_URL"].StringValue;
        RSS_textBox2.Text = Beallitasok.RSS_Reader_Section["Olvasó_2_Név"].StringValue;
        RSS_URL_textBox2.Text = Beallitasok.RSS_Reader_Section["Olvasó_2_URL"].StringValue;
        RSS_textBox3.Text = Beallitasok.RSS_Reader_Section["Olvasó_3_Név"].StringValue;
        RSS_URL_textBox3.Text = Beallitasok.RSS_Reader_Section["Olvasó_3_URL"].StringValue;
        RSS_textBox4.Text = Beallitasok.RSS_Reader_Section["Olvasó_4_Név"].StringValue;
        RSS_URL_textBox4.Text = Beallitasok.RSS_Reader_Section["Olvasó_4_URL"].StringValue;

        AnalogClockcheckBox.Checked = Beallitasok.WidgetSection["Analóg_Bekapcsolva"].BoolValue;
        DottedClockcheckBox.Checked = Beallitasok.WidgetSection["Pontozott_Bekapcsolva"].BoolValue;
        Calendar_checkBox.Checked = Beallitasok.WidgetSection["Naptár_Bekapcsolva"].BoolValue;
        NamedaycheckBox.Checked = Beallitasok.WidgetSection["Névnap_Bekapcsolva"].BoolValue;
        ShowSecondcheckBox.Checked = Beallitasok.WidgetSection["Pontozott_másodperc"].BoolValue;

        RadiocheckBox.Checked = Beallitasok.WidgetSection["Rádió_bekapcsolva"].BoolValue;

        if (Beallitasok.WidgetSection["Analóg_Bekapcsolva"].BoolValue)
        {
            SmallcheckBox1.Enabled = false;
            BigcheckBox1.Enabled = false;
        }

        if (Beallitasok.WidgetSection["Pontozott_Bekapcsolva"].BoolValue)
        {
            SmallcheckBox2.Enabled = false;
            BigcheckBox2.Enabled = false;
            ShowSecondcheckBox.Enabled = false;
        }

        if (Beallitasok.WidgetSection["Analóg_méret"].FloatValue >= 1f)
            BigcheckBox1.Checked = true;
        else
            SmallcheckBox1.Checked = true;
        if (Beallitasok.WidgetSection["Pontozott_pont_méret"].IntValue >= 10)
            BigcheckBox2.Checked = true;
        else
            SmallcheckBox2.Checked = true;

        WeathercheckBox.Checked = Beallitasok.WidgetSection["Időjárás_Bekapcsolva"].BoolValue;

        DaystextBox.Text = Beallitasok.WidgetSection["Időjárás_Napok"].StringValue;

        MinesweepercheckBox.Checked = Beallitasok.WidgetSection["Aknakereső_Bekapcsolva"].BoolValue;

        FlagcheckBox.Checked = Beallitasok.WidgetSection["Zászló_Bekapcsolva"].BoolValue;

        QuizcheckBox.Checked = Beallitasok.WidgetSection["Quiz_Bekapcsolva"].BoolValue;

        LogocheckBox.Checked = Beallitasok.WidgetSection["Logo_Bekapcsolva"].BoolValue;

        initalized = true;
    }

    private void RSS_Setup_FormClosed(object sender, FormClosedEventArgs e)
    {
        Dispose();
    }

    private void Drag_checkbox_CheckedChanged(object sender, EventArgs e)
    {
        if (!initalized) return;
        Debug.WriteLine($"Húzás: {Drag_checkbox.Checked}");
        Beallitasok.RSS_Reader_Section["Húzás"].BoolValue = Drag_checkbox.Checked;
        Beallitasok.ConfigParser.SaveToFile($"{Beallitasok.BasePath}\\{Beallitasok.SetttingsFileName}");
    }

    private void checkBox1_CheckedChanged(object sender, EventArgs e)
    {
        if (!initalized) return;
        Debug.WriteLine($"Analóg óra: {AnalogClockcheckBox.Checked}");
        Beallitasok.WidgetSection["Analóg_Bekapcsolva"].BoolValue = AnalogClockcheckBox.Checked;
        Beallitasok.ConfigParser.SaveToFile($"{Beallitasok.BasePath}\\{Beallitasok.SetttingsFileName}");

        if (Beallitasok.WidgetSection["Analóg_Bekapcsolva"].BoolValue &&
            (Beallitasok.analogClock == null || Beallitasok.analogClock.IsDisposed))
            Beallitasok.analogClock = new AnalogClock(Beallitasok.WidgetSection["Analóg_X"].IntValue,
                Beallitasok.WidgetSection["Analóg_Y"].IntValue, Beallitasok.WidgetSection["Analóg_méret"].FloatValue);
        else
            Beallitasok.analogClock?.Dispose();

        initalized = false;
        SmallcheckBox1.Enabled = !AnalogClockcheckBox.Checked;
        BigcheckBox1.Enabled = !AnalogClockcheckBox.Checked;
        Focus();
        initalized = true;
    }

    private void DottedClockcheckBox_CheckedChanged(object sender, EventArgs e)
    {
        if (!initalized) return;
        Debug.WriteLine($"Pontozott óra: {DottedClockcheckBox.Checked}");
        Beallitasok.WidgetSection["Pontozott_Bekapcsolva"].BoolValue = DottedClockcheckBox.Checked;
        Beallitasok.ConfigParser.SaveToFile($"{Beallitasok.BasePath}\\{Beallitasok.SetttingsFileName}");
        if (Beallitasok.WidgetSection["Pontozott_Bekapcsolva"].BoolValue &&
            (Beallitasok.dotMatrix == null || Beallitasok.dotMatrix.IsDisposed))
            Beallitasok.dotMatrix = new DotMatrixClock(Beallitasok.WidgetSection["Pontozott_másodperc"].BoolValue,
                Beallitasok.WidgetSection["Pontozott_X"].IntValue,
                Beallitasok.WidgetSection["Pontozott_Y"].IntValue,
                Beallitasok.WidgetSection["Pontozott_pont_méret"].IntValue,
                Beallitasok.WidgetSection["Pontozott_pont_távolság"].IntValue,
                Beallitasok.WidgetSection["Pontozott_szám_távolság"].IntValue);
        else
            Beallitasok.dotMatrix?.Dispose();
        initalized = false;
        SmallcheckBox2.Enabled = !DottedClockcheckBox.Checked;
        BigcheckBox2.Enabled = !DottedClockcheckBox.Checked;
        ShowSecondcheckBox.Enabled = !DottedClockcheckBox.Checked;
        Focus();
        initalized = true;
    }

    private void checkBox1_CheckedChanged_1(object sender, EventArgs e)
    {
        if (!initalized) return;
        Debug.WriteLine($"Naptár: {Calendar_checkBox.Checked}");
        Beallitasok.WidgetSection["Naptár_Bekapcsolva"].BoolValue = Calendar_checkBox.Checked;
        Beallitasok.ConfigParser.SaveToFile($"{Beallitasok.BasePath}\\{Beallitasok.SetttingsFileName}");
        if (Beallitasok.WidgetSection["Naptár_Bekapcsolva"].BoolValue &&
            (Beallitasok.calendarWidget == null || Beallitasok.calendarWidget.IsDisposed))
            Beallitasok.calendarWidget = new CalendarWidget(Beallitasok.WidgetSection["Naptár_X"].IntValue,
                Beallitasok.WidgetSection["Naptár_Y"].IntValue);
        else
            Beallitasok.calendarWidget?.Dispose();
        Focus();
    }

    private void checkBox2_CheckedChanged(object sender, EventArgs e)
    {
        if (!initalized) return;
        Debug.WriteLine($"Névnap: {NamedaycheckBox.Checked}");
        Beallitasok.WidgetSection["Névnap_Bekapcsolva"].BoolValue = NamedaycheckBox.Checked;
        Beallitasok.ConfigParser.SaveToFile($"{Beallitasok.BasePath}\\{Beallitasok.SetttingsFileName}");
        if (Beallitasok.WidgetSection["Névnap_Bekapcsolva"].BoolValue && (Beallitasok.NamedayWidgetWidget == null ||
                                                                          Beallitasok.NamedayWidgetWidget.IsDisposed))
            Beallitasok.NamedayWidgetWidget = new NamedayWidget(Beallitasok.WidgetSection["Névnap_X"].IntValue,
                Beallitasok.WidgetSection["Névnap_Y"].IntValue);
        else
            Beallitasok.NamedayWidgetWidget?.Dispose();
        Focus();
    }

    private void SmallcheckBox2_CheckedChanged(object sender, EventArgs e)
    {
        if (!initalized) return;
        initalized = false;
        BigcheckBox2.Checked = !BigcheckBox2.Checked;
        SmallcheckBox2.Checked = true;
        Beallitasok.WidgetSection["Pontozott_pont_méret"].IntValue = 7;
        Beallitasok.WidgetSection["Pontozott_pont_távolság"].IntValue = 10;
        Beallitasok.WidgetSection["Pontozott_szám_távolság"].IntValue = 50;
        Beallitasok.ConfigParser.SaveToFile($"{Beallitasok.BasePath}\\{Beallitasok.SetttingsFileName}");
        initalized = true;
    }

    private void BigcheckBox2_CheckedChanged(object sender, EventArgs e)
    {
        if (!initalized) return;
        initalized = false;
        SmallcheckBox2.Checked = !SmallcheckBox2.Checked;
        BigcheckBox2.Checked = true;
        Beallitasok.WidgetSection["Pontozott_pont_méret"].IntValue = 10;
        Beallitasok.WidgetSection["Pontozott_pont_távolság"].IntValue = 15;
        Beallitasok.WidgetSection["Pontozott_szám_távolság"].IntValue = 80;
        Beallitasok.ConfigParser.SaveToFile($"{Beallitasok.BasePath}\\{Beallitasok.SetttingsFileName}");
        initalized = true;
    }

    private void SmallcheckBox1_CheckedChanged(object sender, EventArgs e)
    {
        if (!initalized) return;
        initalized = false;
        BigcheckBox1.Checked = !BigcheckBox1.Checked;
        SmallcheckBox1.Checked = true;
        Beallitasok.WidgetSection["Analóg_méret"].FloatValue = 0.7f;
        Beallitasok.ConfigParser.SaveToFile($"{Beallitasok.BasePath}\\{Beallitasok.SetttingsFileName}");
        initalized = true;
    }

    private void BigcheckBox1_CheckedChanged(object sender, EventArgs e)
    {
        if (!initalized) return;
        initalized = false;
        SmallcheckBox1.Checked = !SmallcheckBox1.Checked;
        BigcheckBox1.Checked = true;
        Beallitasok.WidgetSection["Analóg_méret"].FloatValue = 1f;
        Beallitasok.ConfigParser.SaveToFile($"{Beallitasok.BasePath}\\{Beallitasok.SetttingsFileName}");
        initalized = true;
    }

    private void ShowSecondcheckBox_CheckedChanged(object sender, EventArgs e)
    {
        if (!initalized) return;
        Beallitasok.WidgetSection["Pontozott_másodperc"].BoolValue = ShowSecondcheckBox.Checked;
        Beallitasok.ConfigParser.SaveToFile($"{Beallitasok.BasePath}\\{Beallitasok.SetttingsFileName}");
    }

    private void RadiocheckBox_CheckedChanged(object sender, EventArgs e)
    {
        if (!initalized) return;
        Debug.WriteLine($"Rádió: {RadiocheckBox.Checked}");
        Beallitasok.WidgetSection["Rádió_Bekapcsolva"].BoolValue = RadiocheckBox.Checked;
        Beallitasok.ConfigParser.SaveToFile($"{Beallitasok.BasePath}\\{Beallitasok.SetttingsFileName}");
        if (Beallitasok.WidgetSection["Rádió_Bekapcsolva"].BoolValue)
        {
            Beallitasok.radioPlayerWidget = new RadioPlayerWidget(Beallitasok.WidgetSection["Rádió_X"].IntValue,
                Beallitasok.WidgetSection["Rádió_Y"].IntValue);
        }
        else
        {
            if (Beallitasok.radioPlayerWidget != null && !Beallitasok.radioPlayerWidget.IsDisposed &&
                Beallitasok.radioPlayerWidget._isPlaying)
            {
                OnlineRadioPlayer.Stop();
                Beallitasok.SafeInvoke(Beallitasok.SayItNowbutton,
                    () => { Beallitasok.SayItNowbutton.Enabled = true; });
            }

            Beallitasok.radioPlayerWidget?.Dispose();
        }

        Focus();
    }

    private async void WeathercheckBox_CheckedChanged(object sender, EventArgs e)
    {
        if (!initalized) return;
        try
        {
            Debug.WriteLine($"Időjárás: {WeathercheckBox.Checked}");
            Beallitasok.WidgetSection["Időjárás_Bekapcsolva"].BoolValue = WeathercheckBox.Checked;
            var napok = int.Parse(DaystextBox.Text);
            if (napok > 7 || napok < 0)
            {
                Beallitasok.WidgetSection["Időjárás_Napok"].IntValue = napok > 7 ? 7 : 0;
                DaystextBox.Text = (napok > 7 ? 7 : 0).ToString();
            }
            else
            {
                Beallitasok.WidgetSection["Időjárás_Napok"].IntValue = napok;
            }

            Beallitasok.ConfigParser.SaveToFile($"{Beallitasok.BasePath}\\{Beallitasok.SetttingsFileName}");
            if (Beallitasok.WidgetSection["Időjárás_Bekapcsolva"].BoolValue)
            {
                await Beallitasok.UpdateLocationData();
                await Beallitasok.UpdateWeatherData();
                Beallitasok.weatherWidget = new WeatherWidget(Beallitasok.WidgetSection["Időjárás_X"].IntValue,
                    Beallitasok.WidgetSection["Időjárás_Y"].IntValue,
                    Beallitasok.WidgetSection["Időjárás_Napok"].IntValue);
            }
            else
            {
                Beallitasok.weatherWidget?.Dispose();
            }

            Focus();
        }
        catch (Exception err)
        {
            Beallitasok.WidgetSection["Időjárás_Napok"].IntValue = 0;
            DaystextBox.Text = "0";
        }
    }

    private void MinesweepercheckBox_CheckedChanged(object sender, EventArgs e)
    {
        if (!initalized) return;
        Debug.WriteLine($"Aknakereső: {MinesweepercheckBox.Checked}");
        Beallitasok.WidgetSection["Aknakereső_Bekapcsolva"].BoolValue = MinesweepercheckBox.Checked;
        Beallitasok.ConfigParser.SaveToFile($"{Beallitasok.BasePath}\\{Beallitasok.SetttingsFileName}");
        if (Beallitasok.WidgetSection["Aknakereső_Bekapcsolva"].BoolValue &&
            (Beallitasok.minesweeperForm == null || Beallitasok.minesweeperForm.IsDisposed))
            Beallitasok.minesweeperForm = new Minesweeper(Beallitasok.WidgetSection["Aknakereső_X"].IntValue,
                Beallitasok.WidgetSection["Aknakereső_Y"].IntValue);
        else
            Beallitasok.minesweeperForm?.Dispose();
        initalized = false;
        Focus();
        initalized = true;
    }

    private void FlagcheckBox_CheckedChanged(object sender, EventArgs e)
    {
        if (!initalized) return;
        Debug.WriteLine($"Zászló: {FlagcheckBox.Checked}");
        Beallitasok.WidgetSection["Zászló_Bekapcsolva"].BoolValue = FlagcheckBox.Checked;
        Beallitasok.ConfigParser.SaveToFile($"{Beallitasok.BasePath}\\{Beallitasok.SetttingsFileName}");
        if (Beallitasok.WidgetSection["Zászló_Bekapcsolva"].BoolValue &&
            (Beallitasok.flagguesserForm == null || Beallitasok.flagguesserForm.IsDisposed))
            Beallitasok.flagguesserForm = new Flagguesser(Beallitasok.WidgetSection["Zászló_X"].IntValue,
                Beallitasok.WidgetSection["Zászló_Y"].IntValue);
        else
            Beallitasok.flagguesserForm?.Dispose();
        initalized = false;
        Focus();
        initalized = true;
    }

    private void QuizcheckBox_CheckedChanged(object sender, EventArgs e)
    {
        if (!initalized) return;
        Debug.WriteLine($"Quiz: {QuizcheckBox.Checked}");
        Beallitasok.WidgetSection["Quiz_Bekapcsolva"].BoolValue = QuizcheckBox.Checked;
        Beallitasok.ConfigParser.SaveToFile($"{Beallitasok.BasePath}\\{Beallitasok.SetttingsFileName}");
        if (Beallitasok.WidgetSection["Quiz_Bekapcsolva"].BoolValue &&
            (Beallitasok.quizForm == null || Beallitasok.quizForm.IsDisposed))
            Beallitasok.quizForm = new QuizWidget(Beallitasok.WidgetSection["Quiz_X"].IntValue,
                Beallitasok.WidgetSection["Quiz_Y"].IntValue);
        else
            Beallitasok.quizForm?.Dispose();
        initalized = false;
        Focus();
        initalized = true;
    }

    private void LogocheckBox_CheckedChanged(object sender, EventArgs e)
    {
        if (!initalized) return;
        Debug.WriteLine($"Logo: {LogocheckBox.Checked}");
        Beallitasok.WidgetSection["Logo_Bekapcsolva"].BoolValue = LogocheckBox.Checked;
        Beallitasok.ConfigParser.SaveToFile($"{Beallitasok.BasePath}\\{Beallitasok.SetttingsFileName}");
        if (Beallitasok.WidgetSection["Logo_Bekapcsolva"].BoolValue &&
            (Beallitasok.logoGuesserForm == null || Beallitasok.logoGuesserForm.IsDisposed))
            Beallitasok.logoGuesserForm = new LogoGuesser(Beallitasok.WidgetSection["Logo_X"].IntValue,
                Beallitasok.WidgetSection["Logo_Y"].IntValue);
        else
            Beallitasok.logoGuesserForm?.Dispose();
        initalized = false;
        Focus();
        initalized = true;
    }

    private void NotescheckBox_CheckedChanged(object sender, EventArgs e)
    {
        if (!initalized) return;
        Debug.WriteLine($"Notes: {LogocheckBox.Checked}");
        Beallitasok.WidgetSection["Notes_Bekapcsolva"].BoolValue = NotescheckBox.Checked;
        Beallitasok.ConfigParser.SaveToFile($"{Beallitasok.BasePath}\\{Beallitasok.SetttingsFileName}");
        if (Beallitasok.WidgetSection["Notes_Bekapcsolva"].BoolValue &&
            (Beallitasok.noteswidget == null || Beallitasok.noteswidget.IsDisposed))
            Beallitasok.noteswidget = new NotesWidget(Beallitasok.WidgetSection["Notes_X"].IntValue,
                Beallitasok.WidgetSection["Notes_Y"].IntValue);
        else
            Beallitasok.noteswidget?.Dispose();
        initalized = false;
        Focus();
        initalized = true;
    }
}