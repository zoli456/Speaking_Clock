using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using SharpCompress.Archives;
using Speaking_clock.Widgets;
using Vanara.PInvoke;
using Vortice;
using Vortice.Direct2D1;
using Vortice.DirectWrite;
using Vortice.Mathematics;
using Vortice.WIC;
using BitmapInterpolationMode = Vortice.Direct2D1.BitmapInterpolationMode;
using Color = System.Drawing.Color;
using FontStyle = Vortice.DirectWrite.FontStyle;
using Timer = System.Windows.Forms.Timer;

namespace Speaking_Clock.Widgets;

public class LogoData
{
    [JsonPropertyName("filename")] public string Filename { get; set; }
    [JsonPropertyName("full_filename")] public string FullFilename { get; set; }
    [JsonPropertyName("logo_name")] public string LogoName { get; set; }
}

public class LogoGuesser : CompositionWidgetBase
{
    private const float MinimizeButtonSize = 30f;
    private const float MinimizeButtonPadding = 5f;
    private readonly Timer _nextRoundTimer;
    private readonly Random _random = new((int)DateTimeOffset.UtcNow.ToUnixTimeSeconds());
    private readonly IWICImagingFactory _wicFactory;

    private List<LogoData> _allLogos;
    private HashSet<char> _alreadyGuessedChars;
    private ID2D1SolidColorBrush _borderBrush;
    private ID2D1SolidColorBrush _buttonBrush;

    private int _correctlyGuessedLogosCount;
    private LogoData _currentLogo;
    private ID2D1Bitmap _currentLogoBitmap;
    private string _currentLogoNameNormalized = "";

    private GameState _gameState;
    private StringBuilder _guessedCharsDisplay;
    private ID2D1SolidColorBrush _inputBackgroundBrush;

    private RectangleF _inputDisplayRect;

    private bool _isMinimized = true;
    private ID2D1SolidColorBrush _minimizeButtonBrush;
    private RectangleF _minimizeButtonRect;
    private Point _mouseDownLocation;

    private bool _showFullLogo;
    private ID2D1SolidColorBrush _skipButtonBrush;
    private RectangleF _skipButtonRect;
    private int _skippedLogosCount;

    private ID2D1SolidColorBrush _startButtonBrush;
    private RectangleF _startButtonRect;
    private ID2D1SolidColorBrush _textBrush;

    private IDWriteTextFormat _textFormatButton;
    private IDWriteTextFormat _textFormatInput;
    private IDWriteTextFormat _textFormatScore;

    public LogoGuesser(int startX, int startY)
        : base(startX, startY, 160, 40)
    {
        Text = "Logo Guesser Widget";
        BackColor = Color.FromArgb(45, 45, 48);
        KeyPreview = true;

        MouseDown -= OnBaseMouseDown;
        MouseMove -= OnBaseMouseMove;
        MouseUp -= OnBaseMouseUp;
        MouseDown += Widget_MouseDown;
        MouseMove += Widget_MouseMove;
        MouseUp += Widget_MouseUp;

        _gameState = GameState.Minimized;
        _wicFactory = GraphicsFactories.WicFactory;

        CreateDeviceIndependentResources();

        _nextRoundTimer = new Timer { Interval = 3000 };
        _nextRoundTimer.Tick += (s, e) =>
        {
            _nextRoundTimer.Stop();
            StartNewRound();
        };

        KeyPress += Widget_KeyPress;
        LoadLogosDataAsync();
    }

    private void CreateDeviceIndependentResources()
    {
        _textFormatInput?.Dispose();
        _textFormatInput =
            _dwriteFactory.CreateTextFormat("Segoe UI", FontWeight.Bold, FontStyle.Normal, FontStretch.Normal, 24);
        _textFormatInput.TextAlignment = TextAlignment.Center;
        _textFormatInput.ParagraphAlignment = ParagraphAlignment.Center;
        _textFormatInput.WordWrapping = WordWrapping.NoWrap;

        _textFormatScore?.Dispose();
        _textFormatScore =
            _dwriteFactory.CreateTextFormat("Segoe UI", FontWeight.Normal, FontStyle.Normal, FontStretch.Normal, 14);
        _textFormatScore.TextAlignment = TextAlignment.Leading;
        _textFormatScore.ParagraphAlignment = ParagraphAlignment.Center;

        _textFormatButton?.Dispose();
        _textFormatButton =
            _dwriteFactory.CreateTextFormat("Segoe UI", FontWeight.SemiBold, FontStyle.Normal, FontStretch.Normal, 16);
        _textFormatButton.TextAlignment = TextAlignment.Center;
        _textFormatButton.ParagraphAlignment = ParagraphAlignment.Center;
    }

    private void CheckAndCreateBrushes(ID2D1DeviceContext context)
    {
        if (_textBrush != null && _textBrush.Factory.NativePointer == context.Factory.NativePointer) return;

        DisposeBrushes();

        _textBrush = context.CreateSolidColorBrush(new Color4(Color.White.ToArgb()));
        _buttonBrush = context.CreateSolidColorBrush(new Color4(Color.FromArgb(255, 70, 70, 75).ToArgb()));
        _inputBackgroundBrush = context.CreateSolidColorBrush(new Color4(Color.FromArgb(255, 50, 50, 55).ToArgb()));
        _borderBrush = context.CreateSolidColorBrush(new Color4(Color.FromArgb(255, 90, 90, 95).ToArgb()));
        _startButtonBrush = context.CreateSolidColorBrush(new Color4(Color.FromArgb(255, 0, 122, 204).ToArgb()));
        _minimizeButtonBrush = context.CreateSolidColorBrush(new Color4(Color.FromArgb(255, 80, 80, 85).ToArgb()));
        _skipButtonBrush = context.CreateSolidColorBrush(new Color4(Color.FromArgb(255, 200, 80, 80).ToArgb()));
    }

    private async void LoadLogosDataAsync()
    {
        try
        {
            var resourceName = "Speaking_clock.logos_final.json";
            using var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(resourceName);
            if (stream == null)
            {
                var baseDirectory = AppDomain.CurrentDomain.BaseDirectory;
                var filePath = Path.Combine(baseDirectory, "logos_corrected.json");
                if (File.Exists(filePath))
                {
                    using var fileStream = new FileStream(filePath, FileMode.Open, FileAccess.Read);
                    _allLogos = await JsonSerializer.DeserializeAsync<List<LogoData>>(fileStream,
                        new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                }
                else
                {
                    // Error state handled in draw loop
                    _gameState = GameState.Error;
                    Invalidate();
                    return;
                }
            }
            else
            {
                _allLogos = await JsonSerializer.DeserializeAsync<List<LogoData>>(stream,
                    new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
            }

            _allLogos = _allLogos?
                .Where(logo => !string.IsNullOrWhiteSpace(logo.Filename) &&
                               !string.IsNullOrWhiteSpace(logo.FullFilename) &&
                               !string.IsNullOrWhiteSpace(logo.LogoName))
                .ToList();

            if (_allLogos == null || _allLogos.Count == 0)
            {
                _gameState = GameState.Error;
                Invalidate();
                return;
            }

            _gameState = GameState.Minimized;
            Invalidate();
        }
        catch (Exception)
        {
            _gameState = GameState.Error;
            Invalidate();
        }
    }

    private void StartNewRound()
    {
        if (_allLogos == null || _allLogos.Count == 0)
        {
            _gameState = GameState.Error;
            Invalidate();
            return;
        }

        _showFullLogo = false;
        _currentLogoBitmap?.Dispose();
        _currentLogoBitmap = null;

        _currentLogo = _allLogos[_random.Next(_allLogos.Count)];
        _currentLogoNameNormalized = NormalizeString(_currentLogo.LogoName);

        _guessedCharsDisplay = new StringBuilder();
        for (var i = 0; i < _currentLogoNameNormalized.Length; i++)
            if (_currentLogoNameNormalized[i] == ' ')
                _guessedCharsDisplay.Append(' ');
            else
                _guessedCharsDisplay.Append('_');
        _alreadyGuessedChars = new HashSet<char>();

        LoadLogoImage(_currentLogo.Filename);
        _gameState = GameState.ShowingQuestion;
        Invalidate();
    }

    private string NormalizeString(string input)
    {
        if (string.IsNullOrWhiteSpace(input)) return "";
        var upper = input.ToUpperInvariant();
        return Regex.Replace(upper, @"\s+", " ").Trim();
    }

    private void LoadLogoImage(string fileName, bool isFullImage = false)
    {
        // Bitmaps must be recreated during Draw or cached. 
        // Note: In Direct2D with Composition, resources are bound to the device.
        // We will reload the bitmap stream here, but defer creation or create it immediately if context is available.
        // Since we don't have context easily here without storing it (which is risky), we will flag it to be loaded in DrawContent
        // or rely on the fact that we can't easily create it without the context.

        // HOWEVER, for this widget refactor, we can assume the bitmap needs to be created using the current device context.
        // The cleanest way without major architecture change is to load bytes to memory, then create texture in Draw.
        // BUT, we can access _d2dContext from base if we are on the same thread.

        if (_d2dContext != null) LoadLogoBitmapInternal(_d2dContext, fileName, isFullImage);
        Invalidate();
    }

    private void LoadLogoBitmapInternal(ID2D1DeviceContext context, string fileName, bool isFullImage)
    {
        _currentLogoBitmap?.Dispose();
        _currentLogoBitmap = null;

        if (string.IsNullOrWhiteSpace(fileName)) return;

        try
        {
            var baseDirectory = AppDomain.CurrentDomain.BaseDirectory;
            var archivePath = Path.Combine(baseDirectory, "Assets", "logos", "logo.dat");

            if (!File.Exists(archivePath)) return;

            using var archive = ArchiveFactory.OpenArchive(archivePath);
            var entry = archive.Entries.FirstOrDefault(e =>
                !e.IsDirectory && string.Equals(Path.GetFileName(e.Key), fileName, StringComparison.OrdinalIgnoreCase));

            if (entry == null) return;

            using var memoryStream = new MemoryStream();
            entry.WriteTo(memoryStream);
            memoryStream.Position = 0;

            // Load directly using the context
            _currentLogoBitmap = LoadBitmapFromStream(context, memoryStream, _wicFactory);
            if (isFullImage) _showFullLogo = true;
        }
        catch (Exception)
        {
            /* Log error */
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

        // If bitmap is null but we have a logo, try to reload it (context restoration handling)
        if (_currentLogoBitmap == null && _currentLogo != null && _gameState != GameState.Error)
        {
            var file = _showFullLogo ? _currentLogo.FullFilename : _currentLogo.Filename;
            LoadLogoBitmapInternal(context, file, _showFullLogo);
        }

        // Clear to widget background color
        context.Clear(new Color4(BackColor.R / 255.0f, BackColor.G / 255.0f, BackColor.B / 255.0f));

        if (_isMinimized)
            DrawMinimizedScreen(context);
        else
            switch (_gameState)
            {
                case GameState.Initializing:
                    DrawCenteredText(context, "Initializing Logos...", ClientRectangle, _textFormatButton);
                    break;
                case GameState.Error:
                    DrawCenteredText(context, "An error occurred. Please restart.", ClientRectangle, _textFormatButton);
                    break;
                case GameState.ShowingQuestion:
                case GameState.ShowingResult:
                    DrawGameScreen(context);
                    break;
            }
    }

    private void DrawCenteredText(ID2D1DeviceContext rt, string text, RectangleF bounds, IDWriteTextFormat format,
        ID2D1Brush brush = null)
    {
        if (format != null && (brush ?? _textBrush) != null)
            rt.DrawText(text, format, (Rect)bounds, brush ?? _textBrush);
    }

    private void DrawGameScreen(ID2D1DeviceContext rt)
    {
        _minimizeButtonRect = new RectangleF(
            Width - MinimizeButtonSize - MinimizeButtonPadding,
            MinimizeButtonPadding,
            MinimizeButtonSize,
            MinimizeButtonSize);
        rt.FillRectangle(_minimizeButtonRect, _minimizeButtonBrush);
        rt.DrawRectangle(_minimizeButtonRect, _borderBrush, 1.0f);
        var minusLine = new RectangleF(_minimizeButtonRect.Left + 7,
            _minimizeButtonRect.Top + _minimizeButtonRect.Height / 2 - 1, _minimizeButtonRect.Width - 14, 2);
        rt.FillRectangle(minusLine, _textBrush);

        var topMargin = MinimizeButtonSize + MinimizeButtonPadding * 2;
        var contentPadding = 15f;
        var scoreHeight = 25f;
        var logoAreaHeight = Height * 0.40f;
        var inputAreaHeight = 60f;
        var buttonHeight = 40f;
        var spacing = 10f;

        var scoreText = $"Kitalálva: {_correctlyGuessedLogosCount}  Kihagyva: {_skippedLogosCount}";
        var scoreRect = new RectangleF(contentPadding, topMargin, Width - contentPadding * 2, scoreHeight);
        DrawCenteredText(rt, scoreText, scoreRect, _textFormatScore);

        var logoTopY = scoreRect.Bottom + spacing;
        RectangleF logoRect;
        if (_currentLogoBitmap != null)
        {
            var aspectRatio = (float)_currentLogoBitmap.PixelSize.Width / _currentLogoBitmap.PixelSize.Height;
            var displayWidth = Width - contentPadding * 2;
            var displayHeight = displayWidth / aspectRatio;

            if (displayHeight > logoAreaHeight)
            {
                displayHeight = logoAreaHeight;
                displayWidth = displayHeight * aspectRatio;
            }

            if (displayWidth > Width - contentPadding * 2)
            {
                displayWidth = Width - contentPadding * 2;
                displayHeight = displayWidth / aspectRatio;
            }

            logoRect = new RectangleF((Width - displayWidth) / 2, logoTopY, displayWidth, displayHeight);
            rt.DrawBitmap(_currentLogoBitmap, logoRect, 1.0f, BitmapInterpolationMode.Linear,
                new RawRectF(0, 0, _currentLogoBitmap.Size.Width, _currentLogoBitmap.Size.Height));
        }
        else
        {
            logoRect = new RectangleF(contentPadding, logoTopY, Width - contentPadding * 2, logoAreaHeight);
            DrawCenteredText(rt, _currentLogo != null ? "Logo missing..." : "Loading...", logoRect, _textFormatButton);
        }

        var inputDisplayTopY = logoRect.Bottom + spacing;
        _inputDisplayRect =
            new RectangleF(contentPadding, inputDisplayTopY, Width - contentPadding * 2, inputAreaHeight);
        rt.FillRectangle(_inputDisplayRect, _inputBackgroundBrush);
        rt.DrawRectangle(_inputDisplayRect, _borderBrush, 1.0f);

        var currentGuessedString = _guessedCharsDisplay?.ToString() ?? "";

        // Dynamic font resizing logic
        if (!string.IsNullOrEmpty(currentGuessedString) && _inputDisplayRect.Width > 0)
            using (var textLayout = _dwriteFactory.CreateTextLayout(currentGuessedString, _textFormatInput,
                       _inputDisplayRect.Width, _inputDisplayRect.Height))
            {
                if (textLayout.Metrics.LayoutWidth > _inputDisplayRect.Width)
                {
                    var newFontSize = _textFormatInput.FontSize *
                                      (_inputDisplayRect.Width / textLayout.Metrics.LayoutWidth) * 0.9f;
                    if (newFontSize < 1) newFontSize = 1;

                    var oldFormat = _textFormatInput;
                    _textFormatInput = _dwriteFactory.CreateTextFormat(oldFormat.FontFamilyName, oldFormat.FontWeight,
                        oldFormat.FontStyle, oldFormat.FontStretch, Math.Max(10, newFontSize));
                    _textFormatInput.TextAlignment = TextAlignment.Center;
                    _textFormatInput.ParagraphAlignment = ParagraphAlignment.Center;
                    _textFormatInput.WordWrapping = WordWrapping.NoWrap;
                    oldFormat.Dispose();
                }
            }

        var stringToDrawOnScreen = " ";
        if (!string.IsNullOrEmpty(currentGuessedString))
            stringToDrawOnScreen = string.Join(" ", currentGuessedString.ToCharArray());
        DrawCenteredText(rt, stringToDrawOnScreen, _inputDisplayRect, _textFormatInput);

        var skipButtonTopY = _inputDisplayRect.Bottom + spacing * 2;
        _skipButtonRect = new RectangleF(Width / 2f - 60f, skipButtonTopY, 120f, buttonHeight);
        rt.FillRectangle(_skipButtonRect, _skipButtonBrush);
        rt.DrawRectangle(_skipButtonRect, _borderBrush, 1.0f);
        DrawCenteredText(rt, "KIHAGY", _skipButtonRect, _textFormatButton);
    }

    // Disable generic dragging to implement Right-Click only dragging
    protected override bool CanDrag()
    {
        return false;
    }

    protected override void SavePosition(int x, int y)
    {
        Beallitasok.WidgetSection["Logo_X"].IntValue = x;
        Beallitasok.WidgetSection["Logo_Y"].IntValue = y;
        Beallitasok.ConfigParser.SaveToFile(Path.Combine(Beallitasok.BasePath, Beallitasok.SetttingsFileName));
    }

    private void Widget_MouseDown(object sender, MouseEventArgs e)
    {
        if (Beallitasok.RSS_Reader_Section["Húzás"].BoolValue)
        {
            if (e.Button == MouseButtons.Right && _isMinimized)
            {
                var dragRect = new RectangleF(0, 0, Width, MinimizeButtonSize);
                if (dragRect.Contains(e.Location))
                {
                    _isDragging = true;
                    _mouseDownLocation = e.Location;
                }

                return;
            }

            if (!_isMinimized && e.Button == MouseButtons.Left && !_minimizeButtonRect.Contains(e.Location) &&
                !_skipButtonRect.Contains(e.Location))
            {
                _isDragging = true;
                _mouseDownLocation = e.Location;
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
        if (e.Button == MouseButtons.Left && _isMinimized)
            if (_startButtonRect.Contains(e.Location))
            {
                ExpandToFullView();
                return;
            }

        if (!_isMinimized && _minimizeButtonRect.Contains(e.Location))
        {
            MinimizeToButton();
            return;
        }

        if (_gameState == GameState.ShowingQuestion && _skipButtonRect.Contains(e.Location))
        {
            HandleSkip();
            return;
        }

        if (_isDragging)
        {
            _isDragging = false;
            Beallitasok.WidgetSection["Logo_X"].IntValue = Left;
            Beallitasok.WidgetSection["Logo_Y"].IntValue = Top;
            Beallitasok.ConfigParser.SaveToFile(Path.Combine(Beallitasok.BasePath, Beallitasok.SetttingsFileName));
        }
    }

    private void Widget_KeyPress(object sender, KeyPressEventArgs e)
    {
        if (_isMinimized || _gameState != GameState.ShowingQuestion || _showFullLogo || _currentLogo == null)
            return;

        var keyPressed = char.ToUpperInvariant(e.KeyChar);
        if (!char.IsLetterOrDigit(keyPressed) && !(keyPressed == ' ' && _currentLogoNameNormalized.Contains(' ')))
            return;

        if (_alreadyGuessedChars.Contains(keyPressed)) return;

        _alreadyGuessedChars.Add(keyPressed);
        var found = false;
        for (var i = 0; i < _currentLogoNameNormalized.Length; i++)
            if (_currentLogoNameNormalized[i] == keyPressed)
            {
                _guessedCharsDisplay[i] = _currentLogo.LogoName[i];
                found = true;
            }

        if (found)
        {
            var allRevealed = true;
            var currentDisplay = _guessedCharsDisplay.ToString();
            for (var i = 0; i < currentDisplay.Length; i++)
                if (_currentLogoNameNormalized[i] != ' ' && currentDisplay[i] == '_')
                {
                    allRevealed = false;
                    break;
                }

            if (allRevealed)
            {
                _correctlyGuessedLogosCount++;
                _gameState = GameState.ShowingResult;
                LoadLogoImage(_currentLogo.FullFilename, true);
                _nextRoundTimer.Start();
            }
        }

        Invalidate();
    }

    private void HandleSkip()
    {
        if (_currentLogo == null) return;

        _skippedLogosCount++;
        _gameState = GameState.ShowingResult;

        if (_guessedCharsDisplay != null && _currentLogo.LogoName != null && _currentLogoNameNormalized != null)
            for (var i = 0; i < _currentLogoNameNormalized.Length; i++)
                if (_currentLogoNameNormalized[i] != ' ')
                {
                    if (i < _currentLogo.LogoName.Length)
                        _guessedCharsDisplay[i] = _currentLogo.LogoName[i];
                    else
                        _guessedCharsDisplay[i] = _currentLogoNameNormalized[i];
                }

        LoadLogoImage(_currentLogo.FullFilename, true);
        _nextRoundTimer.Start();
        Invalidate();
    }

    private void DisposeBrushes()
    {
        _textBrush?.Dispose();
        _buttonBrush?.Dispose();
        _inputBackgroundBrush?.Dispose();
        _borderBrush?.Dispose();
        _startButtonBrush?.Dispose();
        _minimizeButtonBrush?.Dispose();
        _skipButtonBrush?.Dispose();

        _textBrush = null;
        _buttonBrush = null;
        _inputBackgroundBrush = null;
        _borderBrush = null;
        _startButtonBrush = null;
        _minimizeButtonBrush = null;
        _skipButtonBrush = null;
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _nextRoundTimer?.Dispose();
            _currentLogoBitmap?.Dispose();
            DisposeBrushes();
            _textFormatInput?.Dispose();
            _textFormatScore?.Dispose();
            _textFormatButton?.Dispose();
        }

        base.Dispose(disposing);
    }

    private void DrawMinimizedScreen(ID2D1DeviceContext rt)
    {
        _startButtonRect = new RectangleF(0, 0, Width, Height);
        rt.FillRectangle(_startButtonRect, _startButtonBrush);
        rt.DrawRectangle(_startButtonRect, _borderBrush, 1.5f);
        DrawCenteredText(rt, "Logók", _startButtonRect, _textFormatButton);
    }

    private void ExpandToFullView()
    {
        _isMinimized = false;
        Width = 400;
        Height = 550;
        _gameState = GameState.Initializing;
        Invalidate();
        StartNewRound();
    }

    private void MinimizeToButton()
    {
        _isMinimized = true;
        _gameState = GameState.Minimized;
        Width = 160;
        Height = 40;
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
        Left = Beallitasok.WidgetSection["Logo_X"].IntValue;
        Top = Beallitasok.WidgetSection["Logo_Y"].IntValue;
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