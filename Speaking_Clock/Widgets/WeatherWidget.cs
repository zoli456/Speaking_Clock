using System.Diagnostics;
using System.Drawing.Text;
using System.Globalization;
using System.Numerics;
using System.Text.Json;
using Speaking_Clock;
using Speaking_clock.Overlay;
using Vanara.PInvoke;
using Vortice.Direct2D1;
using Vortice.DirectWrite;
using Vortice.Mathematics;
using Vortice.WIC;

using BitmapInterpolationMode = Vortice.Direct2D1.BitmapInterpolationMode;
using Color = System.Drawing.Color;
using FontStyle = Vortice.DirectWrite.FontStyle;
using Size = System.Drawing.Size;

namespace Speaking_clock.Widgets;

public class DisplayWeatherData
{
    public string DayName { get; set; } = "Friday";
    public string Date { get; set; } = "May 11";
    public string Location { get; set; } = "Budapest, Hungary";
    public string UpdateTime { get; set; } = $"Updated at {DateTime.Now:HH:mm} CEST";
    public string Temperature { get; set; } = "8°C";
    public string Condition { get; set; } = "Fair";
    public string WeatherIconName { get; set; } = "fair_day.png";
    public string FeelsLike { get; set; } = "7°";
    public string Humidity { get; set; } = "52%";
    public string Visibility { get; set; } = "10 km";
    public string Wind { get; set; } = "11 km/h E";
    public string Pressure { get; set; } = "1021 mb Rising";
    public string DewPoint { get; set; } = "1°";
    public string UvIndex { get; set; } = "0 (Low)";
    public string Sunrise { get; set; } = "5:08";
    public string Sunset { get; set; } = "20:05";
    public string MoonPhase { get; set; } = "Waxing Gibbous";
    public string MoonIllumination { get; set; } = "93.1% Megvilágítva";
    public string MoonIconName { get; set; } = "moon_waxing_gibbous.png";
    public string FullDateDisplay { get; set; } = DateTime.Now.ToString("dddd, MMMM dd");
}

public class ForecastDayData
{
    public string DayName { get; set; } = "Saturday";
    public string Date { get; set; } = "May 12";
    public string TemperatureHigh { get; set; } = "20°";
    public string TemperatureLow { get; set; } = "8°";
    public string Humidity { get; set; } = "N/A";
    public string Condition { get; set; } = "Mostly Sunny";
    public string WeatherIconName { get; set; } = "mostly_sunny.png";
    public string PrecipitationChance { get; set; } = "1%";
}

public class WeatherWidget : CompositionWidgetBase
{
    private static readonly string IconBasePath = "Assets/WeatherIcons/";
    private static readonly string MoonBasePath = "Assets/MoonIcons/";
    private static readonly string PlaceholderWeatherIconFilename = "placeholder_weather.png";
    private static readonly string PlaceholderMoonIconFilename = "placeholder_moon.png";

    private static readonly float GlobalPadding = 10f;
    private static readonly float SeparatorThickness = 1f;
    private static readonly float CornerRadius = 15.0f;

    private readonly SizeI _detailsMoonIconSize = new(80, 80);
    private readonly SizeI _forecastDayIconSize = new(125, 75);

    private readonly List<ForecastDayData> _forecastDays;
    private readonly Dictionary<string, ID2D1Bitmap?> _loadedForecastIcons = new();
    private readonly SizeI _mainWeatherIconSize = new(170, 120);

    private readonly int forecastdaystoDraw;

    // Font Handling
    private string _actualCenturyGothicNameInCollection = "Century Gothic";
    private ID2D1SolidColorBrush? _backgroundBrush; // New: for drawing the background
    private IDWriteFontCollection1? _centuryGothicFontCollection;

    // Text Formats
    private IDWriteTextFormat? _conditionTextFormat;

    // Resources
    private ID2D1Bitmap? _currentMainWeatherIconBitmap;
    private ID2D1Bitmap? _currentMoonDetailsIconBitmap;
    private IDWriteTextFormat? _defaultTextFormat;

    private DisplayWeatherData _displayedWeather;
    private IDWriteTextFormat? _forecastDateTextFormat;
    private IDWriteTextFormat? _forecastDayNameTextFormat;
    private IDWriteTextFormat? _forecastTempTextFormat;
    private IDWriteTextFormat? _largeTemperatureTextFormat;
    private List<string> _loadedCustomFontFamilyNames = new();
    private ID2D1SolidColorBrush? _precipitationTextBrush;
    private ID2D1SolidColorBrush? _separatorBrush;
    private IDWriteTextFormat? _smallTextFormat;

    // Brushes
    private ID2D1SolidColorBrush? _textBrush;
    private PrivateFontCollection? customFonts;

    public WeatherWidget(int startX, int startY, int days)
        : base(startX, startY, 270, 500) // Initialize with default size, will resize later
    {
        forecastdaystoDraw = days;
        Text = "Weather Widget";

        _displayedWeather = new DisplayWeatherData();
        _forecastDays = new List<ForecastDayData>();
    }

    protected override void OnHandleCreated(EventArgs e)
    {
        // Base creates Device, Context, and SwapChain
        base.OnHandleCreated(e);

        LoadCustomFonts();
        CreateDeviceDependentResources();
        FetchWeatherDataAndForecast();
    }

    // --- Input & Config Implementation ---

    protected override bool CanDrag()
    {
        return Beallitasok.RSS_Reader_Section["Húzás"].BoolValue;
    }

    protected override void SavePosition(int x, int y)
    {
        Beallitasok.WidgetSection["Időjárás_X"].IntValue = x;
        Beallitasok.WidgetSection["Időjárás_Y"].IntValue = y;
        Beallitasok.ConfigParser.SaveToFile($"{Beallitasok.BasePath}\\{Beallitasok.SetttingsFileName}");
    }

    protected override void WndProc(ref Message m)
    {
        if (m.Msg == (int)User32.WindowMessage.WM_DISPLAYCHANGE)
            RepositionOverlay();

        base.WndProc(ref m);
    }

    private void RepositionOverlay()
    {
        Left = Beallitasok.WidgetSection["Időjárás_X"].IntValue;
        Top = Beallitasok.WidgetSection["Időjárás_Y"].IntValue;
    }

    // --- Resource Management ---

    private void LoadCustomFonts()
    {
        if (_dwriteFactory == null) return;

        var centuryGothicFiles = new[]
        {
            $"{Beallitasok.BasePath}\\Assets\\Fonts\\gothic.ttf",
            $"{Beallitasok.BasePath}\\Assets\\Fonts\\gothicb.ttf",
            $"{Beallitasok.BasePath}\\Assets\\Fonts\\gothici.ttf",
            $"{Beallitasok.BasePath}\\Assets\\Fonts\\gothicbi.ttf"
        };

        var existingFontFiles = centuryGothicFiles.Where(File.Exists).ToArray();
        if (!existingFontFiles.Any())
        {
            Debug.WriteLine("No custom fonts found.");
            return;
        }

        try
        {
            // Assuming DirectWriteFontLoader is a helper you have available as per original code
            _centuryGothicFontCollection = DirectWriteFontLoader.LoadFontCollection(
                _dwriteFactory,
                existingFontFiles,
                out _loadedCustomFontFamilyNames
            );

            if (_centuryGothicFontCollection != null)
            {
                var targetName = "Century Gothic";
                _actualCenturyGothicNameInCollection =
                    _loadedCustomFontFamilyNames.FirstOrDefault(name =>
                        name.Equals(targetName, StringComparison.OrdinalIgnoreCase)) ??
                    _loadedCustomFontFamilyNames.FirstOrDefault() ??
                    targetName;
            }
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"Font loading error: {ex.Message}");
        }
    }

    private void CreateDeviceDependentResources()
    {
        if (_d2dContext == null) return;

        // Dispose existing brushes
        _textBrush?.Dispose();
        _separatorBrush?.Dispose();
        _precipitationTextBrush?.Dispose();
        _backgroundBrush?.Dispose();

        // Create Brushes
        _textBrush = _d2dContext.CreateSolidColorBrush(new Color4(Color.White.ToArgb()));

        _separatorBrush = _d2dContext.CreateSolidColorBrush(new Color4(
            Color.LightGray.R / 255f, Color.LightGray.G / 255f, Color.LightGray.B / 255f, 0.4f));

        _precipitationTextBrush = _d2dContext.CreateSolidColorBrush(new Color4(
            Color.SkyBlue.R / 255f, Color.SkyBlue.G / 255f, Color.SkyBlue.B / 255f));

        // Background: 0.1, 0.1, 0.1, 0.85 alpha
        _backgroundBrush = _d2dContext.CreateSolidColorBrush(new Color4(0.1f, 0.1f, 0.1f, 0.85f));

        // Create Text Formats
        CreateTextFormats();
    }

    private void CreateTextFormats()
    {
        // Dispose old formats
        _largeTemperatureTextFormat?.Dispose();
        _conditionTextFormat?.Dispose();
        _defaultTextFormat?.Dispose();
        _smallTextFormat?.Dispose();
        _forecastDayNameTextFormat?.Dispose();
        _forecastDateTextFormat?.Dispose();
        _forecastTempTextFormat?.Dispose();

        IDWriteFontCollection? fontCollection = _centuryGothicFontCollection;
        var fontName = _actualCenturyGothicNameInCollection;

        _largeTemperatureTextFormat = _dwriteFactory.CreateTextFormat(fontName, fontCollection, FontWeight.Bold,
            FontStyle.Normal, FontStretch.Normal, 60f, CultureInfo.CurrentCulture.Name);
        _conditionTextFormat = _dwriteFactory.CreateTextFormat(fontName, fontCollection, FontWeight.Normal,
            FontStyle.Normal, FontStretch.Normal, 15f, CultureInfo.CurrentCulture.Name);
        _defaultTextFormat = _dwriteFactory.CreateTextFormat(fontName, fontCollection, FontWeight.Normal,
            FontStyle.Normal, FontStretch.Normal, 15f, CultureInfo.CurrentCulture.Name);
        _smallTextFormat = _dwriteFactory.CreateTextFormat(fontName, fontCollection, FontWeight.Normal,
            FontStyle.Normal, FontStretch.Normal, 15f, CultureInfo.CurrentCulture.Name);
        _forecastDayNameTextFormat = _dwriteFactory.CreateTextFormat(fontName, fontCollection, FontWeight.Bold,
            FontStyle.Normal, FontStretch.Normal, 15f, CultureInfo.CurrentCulture.Name);
        _forecastDateTextFormat = _dwriteFactory.CreateTextFormat(fontName, fontCollection, FontWeight.Normal,
            FontStyle.Normal, FontStretch.Normal, 13f, CultureInfo.CurrentCulture.Name);
        _forecastTempTextFormat = _dwriteFactory.CreateTextFormat(fontName, fontCollection, FontWeight.Normal,
            FontStyle.Normal, FontStretch.Normal, 13f, CultureInfo.CurrentCulture.Name);

        // Helper to set alignment
        void SetAlign(IDWriteTextFormat? tf)
        {
            if (tf != null) tf.TextAlignment = TextAlignment.Leading;
        }

        SetAlign(_largeTemperatureTextFormat);
        SetAlign(_conditionTextFormat);
        SetAlign(_defaultTextFormat);
        SetAlign(_smallTextFormat);
        SetAlign(_forecastDayNameTextFormat);
        SetAlign(_forecastDateTextFormat);
        SetAlign(_forecastTempTextFormat);
    }

    private void LoadAssets()
    {
        if (_d2dContext == null) return;

        _currentMainWeatherIconBitmap?.Dispose();
        _currentMainWeatherIconBitmap =
            LoadBitmapFromPath(Path.Combine(IconBasePath, _displayedWeather.WeatherIconName),
                PlaceholderWeatherIconFilename);

        _currentMoonDetailsIconBitmap?.Dispose();
        _currentMoonDetailsIconBitmap = LoadBitmapFromPath(Path.Combine(MoonBasePath, _displayedWeather.MoonIconName),
            PlaceholderMoonIconFilename);

        foreach (var day in _forecastDays)
            if (!_loadedForecastIcons.ContainsKey(day.WeatherIconName) ||
                _loadedForecastIcons[day.WeatherIconName] == null)
                _loadedForecastIcons[day.WeatherIconName] =
                    LoadBitmapFromPath(Path.Combine(IconBasePath, day.WeatherIconName), PlaceholderWeatherIconFilename);
    }

    private ID2D1Bitmap? LoadBitmapFromPath(string primaryIconFilenameWithSubpath, string fallbackIconFilename)
    {
        if (_d2dContext == null) return null;

        var baseDir = AppDomain.CurrentDomain.BaseDirectory;
        var primaryFullPath = Path.Combine(baseDir, primaryIconFilenameWithSubpath);
        string? pathToLoad = null;

        if (File.Exists(primaryFullPath))
        {
            pathToLoad = primaryFullPath;
        }
        else
        {
            string[] fallbackSearchPaths =
            {
                Path.Combine(baseDir, IconBasePath, fallbackIconFilename),
                Path.Combine(baseDir, "Assets", fallbackIconFilename),
                Path.Combine(baseDir, fallbackIconFilename)
            };

            foreach (var fallbackPath in fallbackSearchPaths)
                if (File.Exists(fallbackPath))
                {
                    pathToLoad = fallbackPath;
                    break;
                }
        }

        if (string.IsNullOrEmpty(pathToLoad)) return null;

        try
        {
            using var decoder = GraphicsFactories.WicFactory.CreateDecoderFromFileName(pathToLoad);
            using var frame = decoder.GetFrame(0);
            using var converter = GraphicsFactories.WicFactory.CreateFormatConverter();
            converter.Initialize(frame, PixelFormat.Format32bppPBGRA, BitmapDitherType.None, null, 0,
                BitmapPaletteType.MedianCut);

            // Use the DeviceContext to create the bitmap
            return _d2dContext.CreateBitmapFromWicBitmap(converter);
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"Error loading bitmap {pathToLoad}: {ex.Message}");
            return null;
        }
    }

    // --- Drawing Logic ---

    /// <summary>
    ///     Main entry point called by CompositionWidgetBase
    /// </summary>
    protected override void DrawContent(ID2D1DeviceContext context)
    {
        // Re-initialize brushes if lost (e.g. device lost/reset)
        if (_textBrush == null) CreateDeviceDependentResources();
        if (_textBrush == null || _backgroundBrush == null) return; // Safety check

        var bgRect = new Rect(0, 0, ClientSize.Width, ClientSize.Height);
        var roundedBg = new RoundedRectangle((RectangleF)bgRect, CornerRadius, CornerRadius);
        context.FillRoundedRectangle(roundedBg, _backgroundBrush);

        // Draw Content
        float currentY = 0;
        DrawMainWeatherArea(context, new Rect(0, currentY, ClientSize.Width, ClientSize.Height), ref currentY);
        DrawForecastArea(context, new Rect(0, currentY, ClientSize.Width, ClientSize.Height - currentY), ref currentY);
    }

    private void DrawMainWeatherArea(ID2D1DeviceContext context, Rect areaRect, ref float currentGlobalY)
    {
        if (_displayedWeather == null || _textBrush == null) return;

        var localCurrentY = areaRect.Top + 5;
        var contentWidth = areaRect.Width - 2 * GlobalPadding;
        var textBlockForTempCondWidth = contentWidth;

        if (_largeTemperatureTextFormat != null)
            DrawTextBlock(context, ref localCurrentY, GlobalPadding, textBlockForTempCondWidth,
                _displayedWeather.Temperature, _largeTemperatureTextFormat, _textBrush, 0);

        if (_conditionTextFormat != null)
            DrawTextBlock(context, ref localCurrentY, GlobalPadding, textBlockForTempCondWidth,
                _displayedWeather.Condition, _conditionTextFormat, _textBrush);

        var iconMainWeatherX = areaRect.Right - GlobalPadding - _mainWeatherIconSize.Width;
        var iconMainWeatherY = localCurrentY - _mainWeatherIconSize.Height + 20;

        var iconRect = new Rect(iconMainWeatherX, iconMainWeatherY, _mainWeatherIconSize.Width,
            _mainWeatherIconSize.Height);

        if (_currentMainWeatherIconBitmap != null)
        {
            var sourceRect = new Rect(0, 0, _currentMainWeatherIconBitmap.PixelSize.Width,
                _currentMainWeatherIconBitmap.PixelSize.Height);
            context.DrawBitmap(_currentMainWeatherIconBitmap, iconRect, 1.0f, BitmapInterpolationMode.Linear,
                sourceRect);
        }
        else
        {
            DrawIconPlaceholder(context, iconRect, "W", Color.DarkGray);
        }

        localCurrentY += _mainWeatherIconSize.Height - 120;

        if (_defaultTextFormat != null)
        {
            DrawTextBlock(context, ref localCurrentY, GlobalPadding, contentWidth,
                $"Érződik: {_displayedWeather.FeelsLike}", _defaultTextFormat, _textBrush);
            DrawTextBlock(context, ref localCurrentY, GlobalPadding, contentWidth,
                $"Páratartalom: {_displayedWeather.Humidity}", _defaultTextFormat, _textBrush);
            DrawTextBlock(context, ref localCurrentY, GlobalPadding, contentWidth,
                $"Látótávolság: {_displayedWeather.Visibility}", _defaultTextFormat, _textBrush);
            DrawTextBlock(context, ref localCurrentY, GlobalPadding, contentWidth, $"Szél: {_displayedWeather.Wind}",
                _defaultTextFormat, _textBrush);
            DrawTextBlock(context, ref localCurrentY, GlobalPadding, contentWidth,
                $"UV Index: {_displayedWeather.UvIndex}", _defaultTextFormat, _textBrush);

            // Moon Details
            var actualMoonTextStartY = localCurrentY;
            float moonPhaseTextHeight = 0, moonIllumTextHeight = 0;
            var spacingAfterMoonPhase = 2f;

            if (_defaultTextFormat != null && !string.IsNullOrEmpty(_displayedWeather.MoonPhase))
            {
                using var layout1 = _dwriteFactory.CreateTextLayout($"Hold: {_displayedWeather.MoonPhase}",
                    _defaultTextFormat, contentWidth, float.MaxValue);
                moonPhaseTextHeight = layout1.Metrics.Height;
            }

            if (_smallTextFormat != null && !string.IsNullOrEmpty(_displayedWeather.MoonIllumination))
            {
                using var layout2 = _dwriteFactory.CreateTextLayout(_displayedWeather.MoonIllumination,
                    _smallTextFormat, contentWidth, float.MaxValue);
                moonIllumTextHeight = layout2.Metrics.Height;
            }

            var totalTextBlockHeight = moonPhaseTextHeight + spacingAfterMoonPhase + moonIllumTextHeight;
            var moonIconDetailsX = areaRect.Right - GlobalPadding - _detailsMoonIconSize.Width;
            var iconDrawY = actualMoonTextStartY + (totalTextBlockHeight - _detailsMoonIconSize.Height) / 2;
            if (iconDrawY < actualMoonTextStartY) iconDrawY = actualMoonTextStartY;

            var iconMoonRect = new Rect(moonIconDetailsX, iconDrawY, _detailsMoonIconSize.Width,
                _detailsMoonIconSize.Height);

            if (_currentMoonDetailsIconBitmap != null)
            {
                var moonSourceRect = new Rect(0, 0, _currentMoonDetailsIconBitmap.PixelSize.Width,
                    _currentMoonDetailsIconBitmap.PixelSize.Height);
                context.DrawBitmap(_currentMoonDetailsIconBitmap, iconMoonRect, 1.0f, BitmapInterpolationMode.Linear,
                    moonSourceRect);
            }
            else
            {
                DrawIconPlaceholder(context, iconMoonRect, "M", Color.LightSlateGray);
            }

            var tempTextY = actualMoonTextStartY;
            DrawTextBlock(context, ref tempTextY, GlobalPadding, contentWidth, $"Hold: {_displayedWeather.MoonPhase}",
                _defaultTextFormat, _textBrush, spacingAfterMoonPhase);
            DrawTextBlock(context, ref tempTextY, GlobalPadding, contentWidth, _displayedWeather.MoonIllumination,
                _smallTextFormat, _textBrush);

            localCurrentY = Math.Max(tempTextY, iconDrawY + _detailsMoonIconSize.Height);
            localCurrentY -= 40;
        }

        if (_defaultTextFormat != null)
        {
            DrawTextBlock(context, ref localCurrentY, GlobalPadding, contentWidth,
                $"Napkelte: {_displayedWeather.Sunrise}", _defaultTextFormat, _textBrush);
            DrawTextBlock(context, ref localCurrentY, GlobalPadding, contentWidth,
                $"Napnyugta: {_displayedWeather.Sunset}", _defaultTextFormat, _textBrush);
            localCurrentY += 5;
        }

        currentGlobalY = localCurrentY;
    }

    private void DrawForecastArea(ID2D1DeviceContext context, Rect areaRect, ref float currentGlobalY)
    {
        if (_forecastDays == null || _textBrush == null || _precipitationTextBrush == null ||
            _separatorBrush == null) return;

        var localCurrentY = currentGlobalY;

        // Draw separator if needed
        if (localCurrentY > GlobalPadding + SeparatorThickness)
        {
            DrawHorizontalSeparator(context, localCurrentY, GlobalPadding, areaRect.Width - 2 * GlobalPadding);
            localCurrentY += SeparatorThickness + 5;
        }
        else if (localCurrentY == 0)
        {
            localCurrentY += GlobalPadding;
        }

        var contentWidth = areaRect.Width - 2 * GlobalPadding;

        for (var i = 0; i < _forecastDays.Count; i++)
        {
            var day = _forecastDays[i];
            if (i > forecastdaystoDraw) break;

            var itemStartY = localCurrentY;
            var textStartX = GlobalPadding;
            var availableTextWidth = contentWidth;

            // --- Draw Text ---
            if (_forecastDayNameTextFormat != null)
                DrawTextBlock(context, ref localCurrentY, textStartX, availableTextWidth, day.DayName,
                    _forecastDayNameTextFormat, _textBrush, 1);
            if (_forecastDateTextFormat != null)
                DrawTextBlock(context, ref localCurrentY, textStartX, availableTextWidth, day.Date,
                    _forecastDateTextFormat, _textBrush, 1);

            if (_forecastTempTextFormat != null)
            {
                var temperaturesText =
                    i != 0 ? $"{day.TemperatureHigh} / {day.TemperatureLow}" : $"{day.TemperatureHigh}";
                var precipitationText = $"💧{day.PrecipitationChance}";
                var horizontalPaddingBetweenTexts = 15f;
                var spacingAfterCombinedLine = 1f;
                var lineStartY = localCurrentY;

                var maxLayoutHeight = Math.Max(_forecastTempTextFormat.FontSize, ClientSize.Height - lineStartY);
                if (maxLayoutHeight <= 0) maxLayoutHeight = _forecastTempTextFormat.FontSize;

                using var tempTextLayoutLocal = _dwriteFactory.CreateTextLayout(temperaturesText,
                    _forecastTempTextFormat, availableTextWidth, maxLayoutHeight);
                context.DrawTextLayout(new Vector2(textStartX, lineStartY), tempTextLayoutLocal, _textBrush);

                var precipitationX = textStartX + tempTextLayoutLocal.Metrics.WidthIncludingTrailingWhitespace +
                                     horizontalPaddingBetweenTexts;
                var remainingWidthForPrecipitation = areaRect.Width - GlobalPadding - precipitationX;
                if (remainingWidthForPrecipitation < _forecastTempTextFormat.FontSize)
                    remainingWidthForPrecipitation = _forecastTempTextFormat.FontSize;

                using var precipTextLayoutLocal = _dwriteFactory.CreateTextLayout(precipitationText,
                    _forecastTempTextFormat, remainingWidthForPrecipitation, maxLayoutHeight);
                context.DrawTextLayout(new Vector2(precipitationX, lineStartY), precipTextLayoutLocal,
                    _precipitationTextBrush);

                var tempHeight = tempTextLayoutLocal.Metrics.Height;
                var precipHeight = precipTextLayoutLocal.Metrics.Height;
                localCurrentY = lineStartY + Math.Max(tempHeight, precipHeight) + spacingAfterCombinedLine;
            }

            // --- Prepare for Icon and Condition ---
            float conditionTextHeight = 0;
            var conditionSpacingAfter = 3f;
            IDWriteTextLayout? conditionLayout = null;

            if (_smallTextFormat != null && !string.IsNullOrEmpty(day.Condition))
            {
                var widthForCondition = contentWidth - GlobalPadding;
                conditionLayout = _dwriteFactory.CreateTextLayout(day.Condition, _smallTextFormat, widthForCondition,
                    float.MaxValue);
                conditionTextHeight = conditionLayout.Metrics.Height;
            }

            var potentialYAfterCondition = localCurrentY + conditionTextHeight + conditionSpacingAfter;
            var textBlockActualHeight = potentialYAfterCondition - itemStartY - conditionSpacingAfter;

            _loadedForecastIcons.TryGetValue(day.WeatherIconName, out var dayIcon);
            var iconX = areaRect.Right - GlobalPadding - _forecastDayIconSize.Width;
            var iconY = itemStartY + (textBlockActualHeight - _forecastDayIconSize.Height) / 2;
            if (iconY < itemStartY) iconY = itemStartY;

            var iconRect = new Rect(iconX, iconY, _forecastDayIconSize.Width, _forecastDayIconSize.Height);

            if (dayIcon != null)
            {
                var sourceRect = new Rect(0, 0, dayIcon.PixelSize.Width, dayIcon.PixelSize.Height);
                context.DrawBitmap(dayIcon, iconRect, 1.0f, BitmapInterpolationMode.Linear, sourceRect);
            }
            else
            {
                DrawIconPlaceholder(context, iconRect, "i", Color.DimGray);
            }

            if (conditionLayout != null)
            {
                context.DrawTextLayout(new Vector2(textStartX, localCurrentY), conditionLayout, _textBrush);
                localCurrentY += conditionLayout.Metrics.Height + conditionSpacingAfter;
                conditionLayout.Dispose();
            }
            else
            {
                localCurrentY += conditionSpacingAfter;
            }

            var bottomOfIcon = iconY + _forecastDayIconSize.Height;
            localCurrentY = Math.Max(localCurrentY, bottomOfIcon) + 5;

            if (i < forecastdaystoDraw)
            {
                DrawHorizontalSeparator(context, localCurrentY, GlobalPadding, contentWidth);
                localCurrentY += SeparatorThickness + 5;
            }
            else
            {
                localCurrentY += 5;
            }
        }

        currentGlobalY = localCurrentY;
    }

    private void DrawHorizontalSeparator(ID2D1DeviceContext context, float yPosition, float startX, float width)
    {
        if (_separatorBrush == null) return;
        context.DrawLine(new Vector2(startX, yPosition), new Vector2(startX + width, yPosition), _separatorBrush,
            SeparatorThickness);
    }

    private void DrawTextBlock(ID2D1DeviceContext context, ref float currentY, float x, float maxWidth, string text,
        IDWriteTextFormat format, ID2D1Brush brush, float spacingAfter = 5f)
    {
        if (string.IsNullOrEmpty(text) || brush == null || format == null) return;
        var availableHeight = ClientSize.Height - currentY;
        if (availableHeight <= format.FontSize) return; // Don't draw if no space

        using var textLayout =
            _dwriteFactory.CreateTextLayout(text, format, maxWidth, Math.Max(format.FontSize, availableHeight));
        context.DrawTextLayout(new Vector2(x, currentY), textLayout, brush);
        currentY += textLayout.Metrics.Height + spacingAfter;
    }

    private void DrawIconPlaceholder(ID2D1DeviceContext context, Rect rect, string text, Color color)
    {
        if (_defaultTextFormat == null || _textBrush == null) return;

        using var phBrush =
            context.CreateSolidColorBrush(new Color4(color.R / 255f, color.G / 255f, color.B / 255f, 0.7f));
        var roundedRect = new RoundedRectangle((RectangleF)rect, CornerRadius / 3, CornerRadius / 3);
        context.FillRoundedRectangle(roundedRect, phBrush);

        using var layout = _dwriteFactory.CreateTextLayout(text, _defaultTextFormat, rect.Width, rect.Height);
        layout.TextAlignment = TextAlignment.Center;
        layout.ParagraphAlignment = ParagraphAlignment.Center;
        context.DrawTextLayout(new Vector2(rect.Left, rect.Top), layout, _textBrush);
    }

    // --- Data Fetching & Logic ---

    internal async Task FetchWeatherDataAndForecast()
    {
        Debug.WriteLine("Fetching weather and forecast data...");

        if (Beallitasok.weatherData == null)
        {
            _displayedWeather = new DisplayWeatherData();
            _forecastDays.Clear();
            LoadAssets();
            if (IsHandleCreated && !IsDisposed) Invalidate();
            return;
        }

        var root = Beallitasok.weatherData.RootElement;
        var options = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };

        V3WxObservationsCurrent? currentObs = null;
        V3WxForecastDaily7Day? forecastData = null;

        try
        {
            if (root.TryGetProperty("v3-wx-observations-current", out var currentObsElement))
                currentObs = currentObsElement.Deserialize<V3WxObservationsCurrent>(options);

            if (root.TryGetProperty("v3-wx-forecast-daily-7day", out var forecastDataElement))
                forecastData = forecastDataElement.Deserialize<V3WxForecastDaily7Day>(options);

            if (currentObs == null || forecastData == null) throw new Exception("Data incomplete");
        }
        catch (Exception)
        {
            _displayedWeather = new DisplayWeatherData();
            _forecastDays.Clear();
            LoadAssets();
            if (IsHandleCreated && !IsDisposed) Invalidate();
            return;
        }

        var moonData = await MoonService.LoadMoonDataAsync();

        var currentValidTime = DateTime.TryParse(currentObs.ValidTimeLocal, out var parsedValidTime)
            ? parsedValidTime
            : DateTime.Now;
        var sunriseTime = DateTime.TryParse(currentObs.SunriseTimeLocal, out var parsedSunrise)
            ? parsedSunrise
            : currentValidTime.Date.AddHours(6);
        var sunsetTime = DateTime.TryParse(currentObs.SunsetTimeLocal, out var parsedSunset)
            ? parsedSunset
            : currentValidTime.Date.AddHours(20);

        _displayedWeather = new DisplayWeatherData
        {
            Location = Beallitasok.Location,
            UpdateTime = $"Frissítve {currentValidTime:HH:mm} CEST",
            Temperature = $"{currentObs.Temperature}°C",
            Condition = currentObs.WxPhraseLong ?? currentObs.CloudCoverPhrase ?? "N/A",
            WeatherIconName = currentObs.IconCode.HasValue ? $"{currentObs.IconCode}.png" : "unknown.png",
            FeelsLike = $"{currentObs.TemperatureFeelsLike}°",
            Humidity = $"{currentObs.RelativeHumidity}%",
            Visibility = $"{currentObs.Visibility?.ToString("F2", CultureInfo.InvariantCulture) ?? "N/A"} km",
            Wind = $"{currentObs.WindSpeed} km/h {currentObs.WindDirectionCardinal}",
            Pressure = $"{currentObs.PressureAltimeter} mb", 
            DewPoint = $"{currentObs.TemperatureDewPoint}°",
            UvIndex = $"{currentObs.UvIndex} ({currentObs.UvDescription})",
            Sunrise = sunriseTime.ToString("H:mm"),
            Sunset = sunsetTime.ToString("H:mm"),
            MoonPhase = MoonString(moonData.Phase.Replace("_", " ")),
            MoonIllumination = $"{moonData.PercentIlluminated}% megvilágítva",
            MoonIconName = $"{moonData.Phase}.png",
            Date = currentValidTime.ToString("MMMM dd", CultureInfo.CreateSpecificCulture("hu-HU")),
            FullDateDisplay = currentValidTime.ToString("dddd, MMMM dd", CultureInfo.CreateSpecificCulture("hu-HU"))
        };

        await OverlayMessenger.SendWeatherAsync($"{_displayedWeather.Condition} {_displayedWeather.Temperature}");

        _forecastDays.Clear();
        var dayParts = forecastData.Daypart?.FirstOrDefault();
        var todayforecastIndex = !dayParts?.IconCode[0].HasValue ?? false ? 1 : 0;

        // Add today/tonight
        if (dayParts != null)
            _forecastDays.Add(new ForecastDayData
            {
                DayName = dayParts.DaypartName[todayforecastIndex] ?? "Tonight",
                Date = currentValidTime.ToString("MMM dd", CultureInfo.CreateSpecificCulture("hu-HU")),
                TemperatureLow = currentObs.DayOrNight == "N" ? "" :
                    dayParts.Temperature[0].HasValue ? $"{dayParts.Temperature[0]}°" : "N/A",
                TemperatureHigh = dayParts.Temperature[todayforecastIndex].HasValue
                    ? $"{dayParts.Temperature[todayforecastIndex]}°"
                    : "N/A",
                PrecipitationChance = dayParts.PrecipChance[todayforecastIndex].HasValue
                    ? $"{dayParts.PrecipChance[1]}%"
                    : "N/A",
                Condition = (dayParts.WxPhraseLong?.Count > 1 ? dayParts.WxPhraseLong[todayforecastIndex] : null) ??
                            "N/A",
                WeatherIconName = dayParts.IconCode[todayforecastIndex].HasValue
                    ? $"{dayParts.IconCode[todayforecastIndex]}.png"
                    : "unknown.png"
            });

        var numberOfForecastDays = forecastData.DayOfWeek?.Count ?? 0;
        if (forecastData.DayOfWeek != null && dayParts != null)
            for (var i = 1; i < numberOfForecastDays && _forecastDays.Count < 8; i++)
            {
                var dayPartIndexForDay = i * 2;
                if (dayPartIndexForDay >= (dayParts.DaypartName?.Count ?? 0)) break;

                var forecastDate = i < (forecastData.ValidTimeLocal?.Count ?? 0) &&
                                   DateTime.TryParse(forecastData.ValidTimeLocal?[i], out var parsedForecastDate)
                    ? parsedForecastDate
                    : currentValidTime.Date.AddDays(i);

                _forecastDays.Add(new ForecastDayData
                {
                    DayName = forecastData.DayOfWeek[i] ?? "N/A",
                    Date = forecastDate.ToString("MMM dd", CultureInfo.CreateSpecificCulture("hu-HU")),
                    TemperatureHigh = forecastData.CalendarDayTemperatureMax?.Count > i
                        ? $"{forecastData.CalendarDayTemperatureMax[i]}°"
                        : "N/A",
                    TemperatureLow = forecastData.CalendarDayTemperatureMin?.Count > i
                        ? $"{forecastData.CalendarDayTemperatureMin[i]}°"
                        : "N/A",
                    PrecipitationChance = dayParts.PrecipChance?.Count > dayPartIndexForDay
                        ? $"{dayParts.PrecipChance[dayPartIndexForDay]}%"
                        : "N/A",
                    Condition = (dayParts.WxPhraseLong?.Count > dayPartIndexForDay
                        ? dayParts.WxPhraseLong[dayPartIndexForDay]
                        : "N/A") ?? "N/A",
                    WeatherIconName = dayParts.IconCode?.Count > dayPartIndexForDay &&
                                      dayParts.IconCode[dayPartIndexForDay].HasValue
                        ? $"{dayParts.IconCode[dayPartIndexForDay]}.png"
                        : "unknown.png"
                });
            }

        LoadAssets();
        ApplyNewHeight((int)RecalculateHeight());
        if (IsHandleCreated && !IsDisposed) Invalidate();
    }

    private float RecalculateHeight()
    {
        if (_dwriteFactory == null) return ClientSize.Height;

        var totalHeight = 0f;
        var contentWidth = Width - 2 * GlobalPadding;

        // ---------- MAIN WEATHER ----------
        // Temperature
        if (_largeTemperatureTextFormat != null)
        {
            using var tl = _dwriteFactory.CreateTextLayout(
                _displayedWeather.Temperature, _largeTemperatureTextFormat, contentWidth, float.MaxValue);
            totalHeight += tl.Metrics.Height + 5;
        }

        // Condition
        if (_conditionTextFormat != null)
        {
            using var tl = _dwriteFactory.CreateTextLayout(
                _displayedWeather.Condition, _conditionTextFormat, contentWidth, float.MaxValue);
            totalHeight += tl.Metrics.Height + 5;
        }

        // Main weather icon block forces additional height
        totalHeight += _mainWeatherIconSize.Height - 120;

        // Details (feels, humidity, visibility, wind, UV)
        string[] details =
        {
            $"Érződik: {_displayedWeather.FeelsLike}",
            $"Páratartalom: {_displayedWeather.Humidity}",
            $"Látótávolság: {_displayedWeather.Visibility}",
            $"Szél: {_displayedWeather.Wind}",
            $"UV Index: {_displayedWeather.UvIndex}"
        };

        foreach (var d in details)
            if (_defaultTextFormat != null)
            {
                using var tl = _dwriteFactory.CreateTextLayout(d, _defaultTextFormat, contentWidth, float.MaxValue);
                totalHeight += tl.Metrics.Height + 5;
            }

        // ---------- MOON SECTION ----------
        float moonTextHeight = 0;
        if (_defaultTextFormat != null)
        {
            using var tl = _dwriteFactory.CreateTextLayout(
                $"Hold: {_displayedWeather.MoonPhase}", _defaultTextFormat, contentWidth, float.MaxValue);
            moonTextHeight += tl.Metrics.Height;
        }

        if (_smallTextFormat != null)
        {
            using var tl = _dwriteFactory.CreateTextLayout(
                _displayedWeather.MoonIllumination, _smallTextFormat, contentWidth, float.MaxValue);
            moonTextHeight += tl.Metrics.Height;
        }

        var moonBlockHeight = Math.Max(moonTextHeight, _detailsMoonIconSize.Height);
        totalHeight += moonBlockHeight - 40;

        // Sunrise / Sunset
        if (_defaultTextFormat != null)
        {
            using var tl1 = _dwriteFactory.CreateTextLayout(
                $"Napkelte: {_displayedWeather.Sunrise}", _defaultTextFormat, contentWidth, float.MaxValue);
            using var tl2 = _dwriteFactory.CreateTextLayout(
                $"Napnyugta: {_displayedWeather.Sunset}", _defaultTextFormat, contentWidth, float.MaxValue);
            totalHeight += tl1.Metrics.Height + 5;
            totalHeight += tl2.Metrics.Height + 5;
        }

        // ---------- FORECAST ----------
        totalHeight += 10; // top separator spacing

        for (var i = 0; i < _forecastDays.Count && i <= forecastdaystoDraw; i++)
        {
            var day = _forecastDays[i];

            float blockHeight = 0;

            // Day name
            if (_forecastDayNameTextFormat != null)
            {
                using var tl = _dwriteFactory.CreateTextLayout(day.DayName, _forecastDayNameTextFormat, contentWidth,
                    float.MaxValue);
                blockHeight += tl.Metrics.Height + 1;
            }

            // Date
            if (_forecastDateTextFormat != null)
            {
                using var tl =
                    _dwriteFactory.CreateTextLayout(day.Date, _forecastDateTextFormat, contentWidth, float.MaxValue);
                blockHeight += tl.Metrics.Height + 1;
            }

            // Temps + precipitation (same line)
            if (_forecastTempTextFormat != null)
            {
                using var tl = _dwriteFactory.CreateTextLayout($"{day.TemperatureHigh} / {day.TemperatureLow}",
                    _forecastTempTextFormat, contentWidth, float.MaxValue);
                blockHeight += tl.Metrics.Height + 1;
            }

            // Condition (small)
            if (_smallTextFormat != null)
            {
                using var tl =
                    _dwriteFactory.CreateTextLayout(day.Condition, _smallTextFormat, contentWidth, float.MaxValue);
                blockHeight += tl.Metrics.Height + 3;
            }

            blockHeight = Math.Max(blockHeight, _forecastDayIconSize.Height);

            totalHeight += blockHeight + 10; // bottom spacing
        }

        totalHeight += 10; // bottom padding

        return totalHeight;
    }


    private void ApplyNewHeight(int newHeight)
    {
        if (ClientSize.Height == newHeight) return;

        ClientSize = new Size(ClientSize.Width, newHeight);
    }

    private string MoonString(string name)
    {
        return name switch
        {
            "Full Moon" => "Telihold",
            "Waning Gibbous" => "Fogyó hold",
            "Last Quarter" => "Utolsó negyed",
            "Waning Crescent" => "Fogyó félhold",
            "New Moon" => "Újhold",
            "Waxing Crescent" => "Növő félhold",
            "First Quarter" => "Első negyed",
            "Waxing Gibbous" => "Növő félhold",
            _ => "Hold"
        };
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _currentMainWeatherIconBitmap?.Dispose();
            _currentMoonDetailsIconBitmap?.Dispose();
            foreach (var iconEntry in _loadedForecastIcons) iconEntry.Value?.Dispose();

            _textBrush?.Dispose();
            _separatorBrush?.Dispose();
            _precipitationTextBrush?.Dispose();
            _backgroundBrush?.Dispose();

            _largeTemperatureTextFormat?.Dispose();
            _conditionTextFormat?.Dispose();
            _defaultTextFormat?.Dispose();
            _smallTextFormat?.Dispose();
            _forecastDayNameTextFormat?.Dispose();
            _forecastDateTextFormat?.Dispose();
            _forecastTempTextFormat?.Dispose();
        }

        base.Dispose(disposing);
    }
}