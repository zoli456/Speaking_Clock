using System.Reflection;
using System.Text.Json;
using System.Text.Json.Serialization;
using Speaking_Clock;
using Vanara.PInvoke;
using Vortice;
using Vortice.Direct2D1;
using Vortice.DirectWrite;
using Vortice.Mathematics;
using Vortice.WIC;
using BitmapInterpolationMode = Vortice.Direct2D1.BitmapInterpolationMode;
using Color = System.Drawing.Color;
using FontStyle = Vortice.DirectWrite.FontStyle;
using PixelFormat = Vortice.WIC.PixelFormat;
using Timer = System.Windows.Forms.Timer;

namespace Speaking_clock.Widgets;

// Helper Data Classes
public class CountryName
{
    [JsonPropertyName("common")] public string Common { get; set; }
    [JsonPropertyName("official")] public string Official { get; set; }
}

public class TranslationDetail
{
    [JsonPropertyName("official")] public string Official { get; set; }
    [JsonPropertyName("common")] public string Common { get; set; }
}

public class Translations
{
    [JsonPropertyName("hun")] public TranslationDetail Hun { get; set; }
}

public class Flags
{
    [JsonPropertyName("filename")] public string Filename { get; set; }
}

public class CountryData
{
    [JsonPropertyName("name")] public CountryName Name { get; set; }
    [JsonPropertyName("translations")] public Translations Translations { get; set; }
    [JsonPropertyName("flags")] public Flags Flags { get; set; }
}

public class Flagguesser : CompositionWidgetBase
{
    private static readonly int NumOptions = 4;
    private static readonly float MinimizeButtonSize = 30f;
    private static readonly float MinimizeButtonPadding = 5f;
    private readonly List<CountryData> _currentOptions = new();
    private readonly Timer _nextRoundTimer;

    private readonly RectangleF[] _optionRects;
    private readonly Random _random = new((int)DateTimeOffset.UtcNow.ToUnixTimeSeconds());
    private readonly IWICImagingFactory _wicFactory;

    private List<CountryData> _allCountries;
    private ID2D1SolidColorBrush _borderBrush;
    private ID2D1SolidColorBrush _buttonBrush;

    private int _correctAnswersCount;
    private ID2D1SolidColorBrush _correctBrush;
    private CountryData _correctCountry;
    private ID2D1Bitmap _currentFlagBitmap;

    private GameState _gameState;
    private int _incorrectAnswersCount;
    private ID2D1SolidColorBrush _incorrectBrush;
    private bool _isMinimized = true;
    private ID2D1SolidColorBrush _minimizeButtonBrush;
    private RectangleF _minimizeButtonRect;
    private Point _mouseDownLocation;

    private int _selectedIndex = -1;
    private bool _showResultFeedback;

    private ID2D1SolidColorBrush _startButtonBrush;
    private RectangleF _startButtonRect;
    private ID2D1SolidColorBrush _textBrush;
    private IDWriteTextFormat _textFormatOptions;
    private IDWriteTextFormat _textFormatScore;

    public Flagguesser(int startX, int startY)
        : base(startX, startY, 200, 60)
    {
        Text = "Flag Guesser Widget";
        BackColor = Color.Gray;

        _currentOptions = new List<CountryData>();
        _optionRects = new RectangleF[NumOptions];
        _gameState = GameState.Minimized;
        _wicFactory = GraphicsFactories.WicFactory;

        MouseDown -= OnBaseMouseDown;
        MouseMove -= OnBaseMouseMove;
        MouseUp -= OnBaseMouseUp;
        MouseDown += Widget_MouseDown;
        MouseMove += Widget_MouseMove;
        MouseUp += Widget_MouseUp;

        CreateDeviceIndependentResources();

        _nextRoundTimer = new Timer { Interval = 4000 };
        _nextRoundTimer.Tick += (s, e) =>
        {
            _nextRoundTimer.Stop();
            StartNewRound();
        };

        LoadCountriesDataAsync();
    }

    private void CreateDeviceIndependentResources()
    {
        _textFormatOptions?.Dispose();
        _textFormatOptions =
            _dwriteFactory.CreateTextFormat("Segoe UI", FontWeight.SemiBold, FontStyle.Normal, FontStretch.Normal, 16);
        _textFormatOptions.TextAlignment = TextAlignment.Center;
        _textFormatOptions.ParagraphAlignment = ParagraphAlignment.Center;
        _textFormatOptions.WordWrapping = WordWrapping.Wrap;

        _textFormatScore?.Dispose();
        _textFormatScore =
            _dwriteFactory.CreateTextFormat("Segoe UI", FontWeight.Normal, FontStyle.Normal, FontStretch.Normal, 14);
        _textFormatScore.TextAlignment = TextAlignment.Center;
        _textFormatScore.ParagraphAlignment = ParagraphAlignment.Center;
    }

    private void CheckAndCreateBrushes(ID2D1DeviceContext context)
    {
        if (_textBrush != null && _textBrush.Factory.NativePointer == context.Factory.NativePointer) return;

        DisposeBrushes();

        _textBrush = context.CreateSolidColorBrush(new Color4(Color.White.ToArgb()));
        _buttonBrush = context.CreateSolidColorBrush(new Color4(Color.FromArgb(255, 60, 60, 65).ToArgb()));
        _correctBrush = context.CreateSolidColorBrush(new Color4(Color.FromArgb(255, 34, 139, 34).ToArgb()));
        _incorrectBrush = context.CreateSolidColorBrush(new Color4(Color.FromArgb(255, 178, 34, 34).ToArgb()));
        _borderBrush = context.CreateSolidColorBrush(new Color4(Color.FromArgb(255, 90, 90, 95).ToArgb()));
        _startButtonBrush = context.CreateSolidColorBrush(new Color4(Color.FromArgb(255, 70, 70, 75).ToArgb()));
        _minimizeButtonBrush = context.CreateSolidColorBrush(new Color4(Color.FromArgb(255, 80, 80, 85).ToArgb()));
    }

    private async void LoadCountriesDataAsync()
    {
        try
        {
            using var rs = Assembly.GetExecutingAssembly().GetManifestResourceStream("Speaking_clock.countries.json")
                           ?? throw new FileNotFoundException("Resource not found!");

            string jsonText;
            using (var rdr = new StreamReader(rs))
            {
                jsonText = await rdr.ReadToEndAsync();
            }

            var allLoadedCountries = JsonSerializer.Deserialize<List<CountryData>>(jsonText,
                new JsonSerializerOptions { PropertyNameCaseInsensitive = true });

            _allCountries = allLoadedCountries?
                .Where(c => c.Flags?.Filename != null && !string.IsNullOrWhiteSpace(c.Flags.Filename) &&
                            c.Translations?.Hun?.Common != null &&
                            !string.IsNullOrWhiteSpace(c.Translations.Hun.Common) &&
                            c.Name?.Common != null)
                .ToList();

            if (_allCountries == null || _allCountries.Count < NumOptions)
            {
                _gameState = GameState.Error;
                Invalidate();
                return;
            }

            StartNewRound();
        }
        catch (Exception)
        {
            _gameState = GameState.Error;
            Invalidate();
        }
    }

    private void StartNewRound()
    {
        if (_allCountries == null || _allCountries.Count < NumOptions)
        {
            _gameState = GameState.Error;
            Invalidate();
            return;
        }

        _showResultFeedback = false;
        _selectedIndex = -1;
        _currentFlagBitmap?.Dispose();
        _currentFlagBitmap = null;
        _currentOptions.Clear();

        _correctCountry = _allCountries[_random.Next(_allCountries.Count)];
        _currentOptions.Add(_correctCountry);

        while (_currentOptions.Count < NumOptions)
        {
            var randomCountry = _allCountries[_random.Next(_allCountries.Count)];
            if (!_currentOptions.Any(c => c.Name.Common == randomCountry.Name.Common))
                _currentOptions.Add(randomCountry);
        }

        // Shuffle
        for (var i = _currentOptions.Count - 1; i > 0; i--)
        {
            var j = _random.Next(i + 1);
            (_currentOptions[i], _currentOptions[j]) = (_currentOptions[j], _currentOptions[i]);
        }

        // Load flag
        if (_correctCountry.Flags != null && !string.IsNullOrWhiteSpace(_correctCountry.Flags.Filename))
            if (_d2dContext != null)
                LoadFlagBitmapInternal(_d2dContext);

        _gameState = GameState.ShowingQuestion;
        Invalidate();
    }

    private void LoadFlagBitmapInternal(ID2D1DeviceContext context)
    {
        if (_correctCountry?.Flags?.Filename == null) return;

        _currentFlagBitmap?.Dispose();
        _currentFlagBitmap = null;

        var baseDirectory = AppDomain.CurrentDomain.BaseDirectory;
        var flagPath = Path.Combine(baseDirectory, "Assets", "flags", _correctCountry.Flags.Filename);

        if (File.Exists(flagPath))
            try
            {
                using var stream = new FileStream(flagPath, FileMode.Open, FileAccess.Read);
                _currentFlagBitmap = LoadBitmapFromStream(context, stream, _wicFactory);
            }
            catch (Exception)
            {
                /* log */
            }
    }

    public static ID2D1Bitmap LoadBitmapFromStream(ID2D1RenderTarget renderTarget, Stream stream,
        IWICImagingFactory wicFactory)
    {
        using var wicBitmapDecoder = wicFactory.CreateDecoderFromStream(stream);
        using var wicFrameDecode = wicBitmapDecoder.GetFrame(0);
        using var wicConverter = wicFactory.CreateFormatConverter();
        wicConverter.Initialize(wicFrameDecode, PixelFormat.Format32bppPBGRA, BitmapDitherType.None, null, 0.0,
            BitmapPaletteType.MedianCut);
        return renderTarget.CreateBitmapFromWicBitmap(wicConverter);
    }

    protected override void DrawContent(ID2D1DeviceContext context)
    {
        CheckAndCreateBrushes(context);
        if (_currentFlagBitmap == null && _gameState == GameState.ShowingQuestion) LoadFlagBitmapInternal(context);

        //context.Clear(new Color4(Color.Gray.ToArgb()));

        if (_isMinimized)
            DrawMinimizedScreen(context);
        else
            switch (_gameState)
            {
                case GameState.Initializing:
                    DrawCenteredText(context, "Initializing...", ClientRectangle, _textFormatOptions);
                    break;
                case GameState.Error:
                    DrawCenteredText(context, "An error occurred. Please restart.", ClientRectangle,
                        _textFormatOptions);
                    break;
                case GameState.ShowingQuestion:
                case GameState.ShowingResult:
                    DrawGameScreen(context);
                    break;
            }
    }

    private void DrawCenteredText(ID2D1DeviceContext rt, string text, RectangleF bounds, IDWriteTextFormat format)
    {
        if (format != null && _textBrush != null)
            rt.DrawText(text, format, (Rect)bounds, _textBrush);
    }

    private void DrawGameScreen(ID2D1DeviceContext rt)
    {
        _minimizeButtonRect = new RectangleF(
            Width - MinimizeButtonSize - MinimizeButtonPadding,
            MinimizeButtonPadding,
            MinimizeButtonSize,
            MinimizeButtonSize);

        rt.FillRectangle(_minimizeButtonRect, _minimizeButtonBrush);
        rt.DrawRectangle(_minimizeButtonRect, _borderBrush, 1.5f);

        var minusLine = new RectangleF(
            _minimizeButtonRect.Left + 8,
            _minimizeButtonRect.Top + _minimizeButtonRect.Height / 2 - 1,
            _minimizeButtonRect.Width - 16,
            3);
        rt.FillRectangle(minusLine, _textBrush);

        var scoreDisplayHeight = 30f;
        var topMargin = MinimizeButtonSize + MinimizeButtonPadding * 2;
        var spacing = 10f;
        var flagMaxHeight = Height * 0.35f;
        var flagMaxWidth = Width * 0.9f;
        var buttonAreaPadding = Width * 0.05f;

        var scoreText = $"Helyes: {_correctAnswersCount}   Hibás: {_incorrectAnswersCount}";
        var scoreRect = new RectangleF(buttonAreaPadding, topMargin, Width - buttonAreaPadding * 2, scoreDisplayHeight);
        DrawCenteredText(rt, scoreText, scoreRect, _textFormatScore);

        var flagTopY = topMargin + scoreDisplayHeight + spacing;
        var flagRect = new RectangleF();
        if (_currentFlagBitmap != null)
        {
            var aspectRatio = (float)_currentFlagBitmap.PixelSize.Width / _currentFlagBitmap.PixelSize.Height;
            var displayWidth = flagMaxWidth;
            var displayHeight = displayWidth / aspectRatio;

            if (displayHeight > flagMaxHeight)
            {
                displayHeight = flagMaxHeight;
                displayWidth = displayHeight * aspectRatio;
            }

            flagRect = new RectangleF((Width - displayWidth) / 2, flagTopY, displayWidth, displayHeight);
            rt.DrawBitmap(_currentFlagBitmap, flagRect, 1.0f, BitmapInterpolationMode.Linear,
                new RawRectF(0, 0, _currentFlagBitmap.PixelSize.Width, _currentFlagBitmap.PixelSize.Height));
        }
        else
        {
            flagRect = new RectangleF((Width - flagMaxWidth) / 2, flagTopY, flagMaxWidth, flagMaxHeight);
            DrawCenteredText(rt, "Loading flag...", flagRect, _textFormatOptions);
        }

        var buttonsTopY = flagRect.Bottom + spacing * 1.5f;
        var availableHeightForButtons = Height - buttonsTopY - spacing;
        var buttonHeight = (availableHeightForButtons - (NumOptions - 1) * spacing) / NumOptions;
        if (buttonHeight < 35) buttonHeight = 35;
        if (buttonHeight > 60) buttonHeight = 60;

        var currentY = buttonsTopY;
        for (var i = 0; i < NumOptions; i++)
        {
            _optionRects[i] = new RectangleF(buttonAreaPadding, currentY, Width - buttonAreaPadding * 2, buttonHeight);
            var currentOptionBrush = _buttonBrush;

            if (_showResultFeedback)
            {
                if (_currentOptions[i].Name.Common == _correctCountry.Name.Common)
                    currentOptionBrush = _correctBrush;
                else if (i == _selectedIndex) currentOptionBrush = _incorrectBrush;
            }

            if (currentOptionBrush != null) rt.FillRectangle(_optionRects[i], currentOptionBrush);
            if (_borderBrush != null) rt.DrawRectangle(_optionRects[i], _borderBrush, 1.5f);

            var optionText = _currentOptions.Count > i && _currentOptions[i]?.Translations?.Hun?.Common != null
                ? _currentOptions[i].Translations.Hun.Common
                : "N/A";
            DrawCenteredText(rt, optionText, _optionRects[i], _textFormatOptions);
            currentY += buttonHeight + spacing;
        }
    }

    protected override bool CanDrag()
    {
        return false;
    }

    protected override void SavePosition(int x, int y)
    {
        Beallitasok.WidgetSection["Zászló_X"].IntValue = x;
        Beallitasok.WidgetSection["Zászló_Y"].IntValue = y;
        Beallitasok.ConfigParser.SaveToFile(Path.Combine(Beallitasok.BasePath, Beallitasok.SetttingsFileName));
    }

    private void Widget_MouseDown(object sender, MouseEventArgs e)
    {
        if (_isMinimized)
        {
            // When minimized, only allow dragging with right mouse button
            if (e.Button == MouseButtons.Right && Beallitasok.RSS_Reader_Section["Húzás"].BoolValue)
            {
                _isDragging = true;
                _mouseDownLocation = e.Location;
            }
        }
        else
        {
            // When not minimized, check if clicking on minimize button
            if (_minimizeButtonRect.Contains(e.Location)) return;

            // When not minimized, only allow dragging if clicking on flag area
            if (e.Button == MouseButtons.Left && Beallitasok.RSS_Reader_Section["Húzás"].BoolValue)
            {
                var flagRect = GetCurrentFlagRect();
                if (flagRect.Contains(e.Location))
                {
                    _isDragging = true;
                    _mouseDownLocation = e.Location;
                }
            }
        }
    }

    private void Widget_MouseMove(object sender, MouseEventArgs e)
    {
        if (_isDragging)
        {
            Left += e.X - _mouseDownLocation.X;
            Top += e.Y - _mouseDownLocation.Y;
        }
    }

    private void Widget_MouseUp(object sender, MouseEventArgs e)
    {
        if (_isDragging)
        {
            _isDragging = false;
            Beallitasok.WidgetSection["Zászló_X"].IntValue = Left;
            Beallitasok.WidgetSection["Zászló_Y"].IntValue = Top;
            Beallitasok.ConfigParser.SaveToFile(Path.Combine(Beallitasok.BasePath, Beallitasok.SetttingsFileName));
            return; // Skip other checks if we were dragging
        }

        if (_isMinimized)
        {
            if (_startButtonRect.Contains(e.X, e.Y)) ExpandToFullView();
        }
        else
        {
            // Check if clicked on minimize button
            if (_minimizeButtonRect.Contains(e.X, e.Y))
            {
                MinimizeToButton();
                return;
            }

            if (_gameState == GameState.ShowingQuestion)
                for (var i = 0; i < NumOptions; i++)
                    if (_optionRects[i].Contains(e.X, e.Y))
                    {
                        _selectedIndex = i;
                        _showResultFeedback = true;
                        _gameState = GameState.ShowingResult;

                        if (_currentOptions[i].Name.Common == _correctCountry.Name.Common)
                            _correctAnswersCount++;
                        else
                            _incorrectAnswersCount++;

                        _nextRoundTimer.Start();
                        Invalidate();
                        break;
                    }
        }
    }

    private RectangleF GetCurrentFlagRect()
    {
        var topMargin = MinimizeButtonSize + MinimizeButtonPadding * 2;
        var scoreDisplayHeight = 30f;
        var spacing = 10f;
        var flagTopY = topMargin + scoreDisplayHeight + spacing;
        var flagMaxWidth = Width * 0.9f;
        var flagMaxHeight = Height * 0.35f;

        if (_currentFlagBitmap != null)
        {
            var aspectRatio = (float)_currentFlagBitmap.PixelSize.Width / _currentFlagBitmap.PixelSize.Height;
            var displayWidth = flagMaxWidth;
            var displayHeight = displayWidth / aspectRatio;

            if (displayHeight > flagMaxHeight)
            {
                displayHeight = flagMaxHeight;
                displayWidth = displayHeight * aspectRatio;
            }

            return new RectangleF((Width - displayWidth) / 2, flagTopY, displayWidth, displayHeight);
        }

        return new RectangleF((Width - flagMaxWidth) / 2, flagTopY, flagMaxWidth, flagMaxHeight);
    }

    private void DisposeBrushes()
    {
        _textBrush?.Dispose();
        _buttonBrush?.Dispose();
        _correctBrush?.Dispose();
        _incorrectBrush?.Dispose();
        _borderBrush?.Dispose();
        _startButtonBrush?.Dispose();
        _minimizeButtonBrush?.Dispose();

        _textBrush = null;
        _buttonBrush = null;
        _correctBrush = null;
        _incorrectBrush = null;
        _borderBrush = null;
        _startButtonBrush = null;
        _minimizeButtonBrush = null;
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _nextRoundTimer?.Dispose();
            _currentFlagBitmap?.Dispose();
            DisposeBrushes();
            _textFormatOptions?.Dispose();
            _textFormatScore?.Dispose();
        }

        base.Dispose(disposing);
    }

    private void DrawMinimizedScreen(ID2D1DeviceContext rt)
    {
        _startButtonRect = new RectangleF(20, 10, Width - 40, Height - 20);
        rt.FillRectangle(_startButtonRect, _startButtonBrush);
        rt.DrawRectangle(_startButtonRect, _borderBrush, 1.5f);
        DrawCenteredText(rt, "Zászlók", _startButtonRect, _textFormatOptions);
    }

    private void ExpandToFullView()
    {
        _isMinimized = false;
        Width = 380;
        Height = 600;
        StartNewRound();
    }

    private void MinimizeToButton()
    {
        _isMinimized = true;
        Width = 200;
        Height = 60;
        Invalidate();
    }

    protected override void WndProc(ref Message m)
    {
        if (m.Msg == (int)User32.WindowMessage.WM_DISPLAYCHANGE)
            RepositionOverlay();
        base.WndProc(ref m);
    }

    private void RepositionOverlay()
    {
        Left = Beallitasok.WidgetSection["Zászló_X"].IntValue;
        Top = Beallitasok.WidgetSection["Zászló_Y"].IntValue;
    }

    private enum GameState
    {
        Minimized,
        Initializing,
        ShowingQuestion,
        ShowingResult,
        Error
    }
}