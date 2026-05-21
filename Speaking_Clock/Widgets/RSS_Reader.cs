using System.Diagnostics;
using System.Globalization;
using System.Numerics;
using System.Xml;
using Speaking_Clock;
using Speaking_clock.Overlay;
using Vortice.Direct2D1;
using Vortice.DirectWrite;
using Vortice.Mathematics;
using static Vanara.PInvoke.User32;
using RectangleF = System.Drawing.RectangleF;
using Size = System.Drawing.Size;
using Timer = System.Timers.Timer;

namespace Speaking_clock.Widgets;

public class RssReaderSettings
{
    public int FontSize { get; set; } = 18;
    public int TitleFontSize { get; set; } = 20;
    public int ItemSpacing { get; set; } = 3;
    public int HeaderVerticalPadding { get; set; } = 5;
    public int MaxDisplayItems { get; set; } = 10;
    public int WindowWidth { get; set; } = 400;
    public double WindowOpacity { get; set; } = 0.9; // Applied via Alpha in Brush now
    public string HeaderColor { get; set; } = "blue";
    public string TextColor { get; set; } = "white";
    public string ContentBackgroundColor { get; set; } = "#D0202020";
    public string HoverItemBackgroundColor { get; set; } = "#404040";
    public string FontName { get; set; } = "Arial";
    public int UpdateIntervalMs { get; set; } = 600000;
    public int CornerRadius { get; set; } = 15; // kept for compatibility but unused in rectangular mode
    public int ScrollbarWidth { get; set; } = 8;
    public string ScrollbarColor { get; set; } = "gray";
    public int InitialX { get; set; } = 100;
    public int InitialY { get; set; } = 100;
}

public record RssFeedItem(string Title, string Link, string FullDescription);

internal class RssReader : CompositionWidgetBase
{
    private static readonly int ToolTipInitialDelay = 200;
    private static readonly int ToolTipAutoPopDelay = 7000;
    private static readonly int ToolTipReshowDelay = 200;
    private static readonly HttpClient httpClient = new();

    // --- Configuration ---
    private readonly string _feedUrl;
    private readonly int _formInstanceIndex;
    private readonly RssReaderSettings _settings;

    // --- Other ---
    private readonly ToolTip _toolTip = new();
    private readonly Timer _updateTimer;
    private readonly string _widgetTitle;

    // --- Brushes & Formats (Device Dependent) ---
    private ID2D1SolidColorBrush? _contentBackgroundBrush;
    private ID2D1SolidColorBrush? _defaultTextBrush;
    private ID2D1SolidColorBrush? _headerBrush;
    private float _headerHeight;
    private ID2D1SolidColorBrush? _hoverBackgroundBrush;

    // --- Logic State ---
    private int _hoveredIndex = -1;
    private float _itemHeight;

    private List<RssFeedItem> _items = new();
    private IDWriteTextFormat? _listItemTextFormat;
    private ID2D1SolidColorBrush? _scrollbarBrush;
    private int _scrollOffset;
    private IDWriteTextFormat? _titleTextFormat;
    private int _visibleWindowHeight;

    // Constructor
    public RssReader(int formInstanceIndex, string feedUrl, string title, RssReaderSettings settings)
        : base(
            settings?.InitialX ?? 100,
            settings?.InitialY ?? 100,
            settings?.WindowWidth ?? 400,
            CalculateInitialHeight(settings ?? new RssReaderSettings()))
    {
        _formInstanceIndex = formInstanceIndex;
        _feedUrl = feedUrl;
        _widgetTitle = title;
        _settings = settings ?? new RssReaderSettings();

        InitializeUiProperties();
        InitializeToolTip();

        // Calculate internal dimensions based on settings
        CalculateDimensions();

        // Initial RSS Load
        _ = LoadRssFeedAsync();

        _updateTimer = new Timer(_settings.UpdateIntervalMs);
        _updateTimer.Elapsed += async (s, e) => await OnUpdateTimerElapsedAsync();
        _updateTimer.Start();
    }

    // Static helper to determine height before calling Base Constructor
    private static int CalculateInitialHeight(RssReaderSettings s)
    {
        float hHeight = s.TitleFontSize + s.HeaderVerticalPadding * 2;
        float iHeight = s.FontSize + s.ItemSpacing * 2;
        return (int)(hHeight + s.MaxDisplayItems * iHeight);
    }

    private void InitializeUiProperties()
    {
        Text = _widgetTitle;
        // Note: Transparency and Styles are largely handled by CompositionWidgetBase
        Opacity = 1.0; // DComp handles alpha via brushes, Form opacity should stay 1
    }

    private void CalculateDimensions()
    {
        _itemHeight = _settings.FontSize + _settings.ItemSpacing * 2;
        _headerHeight = _settings.TitleFontSize + _settings.HeaderVerticalPadding * 2;
        _visibleWindowHeight = (int)(_headerHeight + _settings.MaxDisplayItems * _itemHeight);

        // Update Form Size if calculation differs from current
        if (ClientSize.Height != _visibleWindowHeight || ClientSize.Width != _settings.WindowWidth)
            ClientSize = new Size(_settings.WindowWidth, _visibleWindowHeight);
        // We do NOT set Region here. We draw rectangular corners in DrawContent.
    }

    private void InitializeToolTip()
    {
        _toolTip.AutoPopDelay = ToolTipAutoPopDelay;
        _toolTip.InitialDelay = ToolTipInitialDelay;
        _toolTip.ReshowDelay = ToolTipReshowDelay;
        _toolTip.ShowAlways = true;
        // Tooltips on layered/transparent windows can be tricky, 
        // typically requires standard window parenting.
    }

    // --- Base Class Overrides: Rendering ---

    protected override void DrawContent(ID2D1DeviceContext context)
    {
        // 1. Ensure Resources exist for this specific Context
        CreateDeviceDependentResources(context);

        if (_items == null) return;

        // --- ROUNDED CORNER CLIPPING SETUP ---

        // Define the full bounds
        var fullRect = new RectangleF(0, 0, ClientSize.Width, ClientSize.Height);

        // Define the rounding parameters
        var roundedFull = new RoundedRectangle(fullRect, _settings.CornerRadius, _settings.CornerRadius);

        // Create a Geometry for clipping. 
        // We create it from the Factory associated with the current context to ensure compatibility.
        using var roundedGeometry = context.Factory.CreateRoundedRectangleGeometry(roundedFull);

        // Prepare the layer parameters. 
        // 'GeometricMask' is the key: it forces all subsequent drawing to fit inside the rounded shape.
        var layerParams = new LayerParameters1
        {
            ContentBounds = fullRect,
            GeometricMask = roundedGeometry,
            MaskTransform = Matrix3x2.Identity,
            MaskAntialiasMode = AntialiasMode.PerPrimitive, // Smooths the edges
            Opacity = 1.0f
        };

        // Push the layer. Everything drawn between PushLayer and PopLayer is clipped.
        context.PushLayer(layerParams, null);

        // -------------------------------------
        //      START DRAWING CONTENT
        // -------------------------------------

        // Draw Header Background
        var headerRect = new Rect(0, 0, ClientSize.Width, _headerHeight);
        if (_headerBrush != null) context.FillRectangle(headerRect, _headerBrush);

        // Draw Content Area Background
        var contentRect = new Rect(0, _headerHeight, ClientSize.Width, ClientSize.Height);
        if (_contentBackgroundBrush != null) context.FillRectangle(contentRect, _contentBackgroundBrush);

        // Draw Title Text
        if (_titleTextFormat != null && _defaultTextBrush != null)
            context.DrawText(_widgetTitle, _titleTextFormat, headerRect, _defaultTextBrush);

        // Draw Items and Scrollbar
        DrawRssItems(context);
        DrawCustomScrollbar(context);

        // Restore the drawing state
        context.PopLayer();
    }

    private void CreateDeviceDependentResources(ID2D1DeviceContext context)
    {
        if (_defaultTextBrush == null || _defaultTextBrush.Factory.NativePointer != context.Factory.NativePointer)
        {
            DisposeDeviceDependentResources();

            _defaultTextBrush = context.CreateSolidColorBrush(ParseColor(_settings.TextColor, Colors.White));
            _headerBrush = context.CreateSolidColorBrush(ParseColor(_settings.HeaderColor, Colors.CornflowerBlue));

            // Parse background color and apply Opacity setting
            var bgCol = ParseColor(_settings.ContentBackgroundColor, new Color4(0.2f, 0.2f, 0.2f, 0.8f));
            _contentBackgroundBrush = context.CreateSolidColorBrush(bgCol);

            _hoverBackgroundBrush =
                context.CreateSolidColorBrush(ParseColor(_settings.HoverItemBackgroundColor, Colors.DarkGray));
            _scrollbarBrush = context.CreateSolidColorBrush(ParseColor(_settings.ScrollbarColor, Colors.DimGray));
            if (_titleTextFormat == null)
            {
                _titleTextFormat = _dwriteFactory.CreateTextFormat(_settings.FontName, _settings.TitleFontSize);
                _titleTextFormat.TextAlignment = TextAlignment.Center;
                _titleTextFormat.ParagraphAlignment = ParagraphAlignment.Center;
            }

            if (_listItemTextFormat == null)
            {
                _listItemTextFormat = _dwriteFactory.CreateTextFormat(_settings.FontName, _settings.FontSize);
                _listItemTextFormat.TextAlignment = TextAlignment.Leading;
                _listItemTextFormat.ParagraphAlignment = ParagraphAlignment.Center;
                _listItemTextFormat.WordWrapping = WordWrapping.NoWrap;

                var trimmingSign = _dwriteFactory.CreateEllipsisTrimmingSign(_listItemTextFormat);
                _listItemTextFormat.SetTrimming(
                    new Trimming { Granularity = TrimmingGranularity.Character, Delimiter = 0, DelimiterCount = 0 },
                    trimmingSign);
            }
        }
    }

    private void DisposeDeviceDependentResources()
    {
        _defaultTextBrush?.Dispose();
        _defaultTextBrush = null;
        _headerBrush?.Dispose();
        _headerBrush = null;
        _contentBackgroundBrush?.Dispose();
        _contentBackgroundBrush = null;
        _hoverBackgroundBrush?.Dispose();
        _hoverBackgroundBrush = null;
        _scrollbarBrush?.Dispose();
        _scrollbarBrush = null;
    }

    private void DrawRssItems(ID2D1DeviceContext context)
    {
        var currentY = _headerHeight;
        var scrollbarAreaWidth = _items.Count > _settings.MaxDisplayItems ? _settings.ScrollbarWidth + 5 : 0;

        for (var i = 0; i < _settings.MaxDisplayItems; i++)
        {
            var itemActualIndex = _scrollOffset + i;
            if (itemActualIndex >= _items.Count) break;

            var item = _items[itemActualIndex];
            var itemRect = new Rect(0, currentY, ClientSize.Width - scrollbarAreaWidth, _itemHeight);
            var textRect = new Rect(10, currentY, ClientSize.Width - scrollbarAreaWidth - 20, _itemHeight);

            if (i == _hoveredIndex && _hoverBackgroundBrush != null)
                context.FillRectangle(itemRect, _hoverBackgroundBrush);

            var displayText = $"• {item.Title}";

            if (_listItemTextFormat != null && _defaultTextBrush != null)
                context.DrawText(
                    displayText,
                    _listItemTextFormat,
                    textRect,
                    _defaultTextBrush,
                    DrawTextOptions.Clip
                );
            currentY += _itemHeight;
        }
    }

    private void DrawCustomScrollbar(ID2D1DeviceContext context)
    {
        if (_items.Count <= _settings.MaxDisplayItems || _scrollbarBrush == null)
            return;

        var trackHeight = ClientSize.Height - _headerHeight - 10;
        float trackX = ClientSize.Width - _settings.ScrollbarWidth - 5;
        var trackY = _headerHeight + 5;

        var contentRatio = (float)_settings.MaxDisplayItems / _items.Count;
        var thumbHeight = Math.Max(20, trackHeight * contentRatio);

        var scrollableRatio = _items.Count - _settings.MaxDisplayItems == 0
            ? 0
            : (float)_scrollOffset / (_items.Count - _settings.MaxDisplayItems);

        var thumbY = trackY + (trackHeight - thumbHeight) * scrollableRatio;

        var thumbRect = new RectangleF(trackX, thumbY, _settings.ScrollbarWidth, thumbHeight);

        // --- Rounded Scrollbar ---
        var radius = _settings.ScrollbarWidth / 2f;
        var roundedThumb = new RoundedRectangle(thumbRect, radius, radius);

        using var thumbGeometry = context.Factory.CreateRoundedRectangleGeometry(roundedThumb);
        context.FillGeometry(thumbGeometry, _scrollbarBrush);
    }


    // --- Base Class Overrides: Input & Logic ---
    protected override void SavePosition(int x, int y)
    {
        Debug.WriteLine($"Saving position for Reader {_formInstanceIndex}: X={x}, Y={y}");
        Beallitasok.RSS_Reader_Section[$"Olvasó_{_formInstanceIndex}_Pos_X"].IntValue = x;
        Beallitasok.RSS_Reader_Section[$"Olvasó_{_formInstanceIndex}_Pos_Y"].IntValue = y;
        Beallitasok.ConfigParser.SaveToFile($"{Beallitasok.BasePath}\\{Beallitasok.SetttingsFileName}");
    }

    protected override bool CanDrag()
    {
        // Check global setting
        if (!Beallitasok.RSS_Reader_Section["Húzás"].BoolValue) return false;

        // Check if mouse is in the Header area.
        var clientPoint = PointToClient(Cursor.Position);
        return clientPoint.Y <= _headerHeight;
    }

    protected override void OnChildMouseMove(MouseEventArgs e)
    {
        UpdateHoveredItem(e.Location);
    }

protected override void OnChildMouseUp(MouseEventArgs e)
{
    if (e.Button == MouseButtons.Left && _hoveredIndex != -1)
    {
        var actualItemIndex = _scrollOffset + _hoveredIndex;

        if (actualItemIndex >= 0 && actualItemIndex < _items.Count)
        {
            try
            {
                var link = _items[actualItemIndex].Link;

                if (!string.IsNullOrWhiteSpace(link) &&
                    Uri.IsWellFormedUriString(link, UriKind.Absolute))
                {
                    Process.Start(new ProcessStartInfo
                    {
                        FileName = "explorer.exe",
                        Arguments = $"\"{link}\"",
                        UseShellExecute = true,
                        Verb = "open"
                    });
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine(ex.Message);
            }
        }
    }
}

protected override void OnMouseWheel(MouseEventArgs e)
    {
        base.OnMouseWheel(e); // Always good practice

        if (!_items.Any() || _items.Count <= _settings.MaxDisplayItems) return;

        var scrollDirection = e.Delta > 0 ? -1 : 1;
        var newScrollOffset = _scrollOffset + scrollDirection;

        _scrollOffset = Math.Max(0, Math.Min(newScrollOffset, _items.Count - _settings.MaxDisplayItems));

        UpdateHoveredItem(PointToClient(MousePosition));
        Invalidate();
    }

    protected override void OnMouseLeave(EventArgs e)
    {
        base.OnMouseLeave(e);
        if (_hoveredIndex != -1)
        {
            _hoveredIndex = -1;
            _toolTip.SetToolTip(this, string.Empty);
            Invalidate();
        }
    }

    private void UpdateHoveredItem(Point mouseLocation)
    {
        var newHoveredIndex = -1;
        var tooltipText = string.Empty;

        if (mouseLocation.Y > _headerHeight && mouseLocation.Y < _visibleWindowHeight)
        {
            var relativeY = mouseLocation.Y - _headerHeight;
            var potentialVisibleIndex = (int)(relativeY / _itemHeight);

            if (potentialVisibleIndex >= 0 && potentialVisibleIndex < _settings.MaxDisplayItems)
            {
                var actualItemIndex = _scrollOffset + potentialVisibleIndex;
                if (actualItemIndex < _items.Count)
                {
                    newHoveredIndex = potentialVisibleIndex;
                    tooltipText = _items[actualItemIndex].Title;
                }
            }
        }

        if (_hoveredIndex != newHoveredIndex)
        {
            _hoveredIndex = newHoveredIndex;
            if (_toolTip.GetToolTip(this) != tooltipText) _toolTip.SetToolTip(this, tooltipText);
            Invalidate();
        }
    }

    // --- Async Logic & Helpers ---

    internal async Task OnUpdateTimerElapsedAsync()
    {
        await LoadRssFeedAsync();
    }

    private async Task LoadRssFeedAsync()
    {
        if (string.IsNullOrEmpty(_feedUrl))
        {
            UpdateItemsWithError("RSS URL not configured");
            return;
        }

        try
        {
            var rssContent = await httpClient.GetStringAsync(_feedUrl);
            var doc = new XmlDocument();
            doc.LoadXml(rssContent);

            var newFeedItems = new List<RssFeedItem>();
            var itemNodes = doc.SelectNodes("//item");

            if (itemNodes != null)
                foreach (XmlNode node in itemNodes)
                {
                    var title = node["title"]?.InnerText ?? "No Title";
                    var link = node["link"]?.InnerText ?? "#";
                    var description = node["description"]?.InnerText ?? node["summary"]?.InnerText ?? title;
                    newFeedItems.Add(new RssFeedItem(title, link, description));
                    await OverlayMessenger.SendHeadlineAsync(title, link);
                }

            if (!newFeedItems.SequenceEqual(_items))
            {
                _items = newFeedItems;
                _scrollOffset = 0;
                _hoveredIndex = -1;
                if (IsHandleCreated) Invalidate();
            }
        }
        catch (Exception ex)
        {
            UpdateItemsWithError($"Error: {ex.Message}");
        }
    }

    private void UpdateItemsWithError(string errorMessage)
    {
        _items.Clear();
        _items.Add(new RssFeedItem("Error", "#", errorMessage));
        _scrollOffset = 0;
        _hoveredIndex = -1;
        if (IsHandleCreated) Invalidate();
    }

    private Color4 ParseColor(string colorString, Color4 defaultColor)
    {
        if (string.IsNullOrWhiteSpace(colorString)) return defaultColor;
        try
        {
            if (colorString.StartsWith("#"))
            {
                var hex = colorString.Substring(1);
                uint argb;
                if (hex.Length == 6)
                {
                    argb = uint.Parse(hex, NumberStyles.HexNumber) | 0xFF000000;
                }
                else if (hex.Length == 8)
                {
                    argb = uint.Parse(hex, NumberStyles.HexNumber);
                    // ARGB -> ABGR
                    argb = (argb & 0xFF00FF00) | ((argb & 0x00FF0000) >> 16) | ((argb & 0x000000FF) << 16);
                }
                else
                {
                    return defaultColor;
                }

                return new Color4(argb);
            }

            var sdColor = ColorTranslator.FromHtml(colorString);
            return new Color4(sdColor.R / 255f, sdColor.G / 255f, sdColor.B / 255f, sdColor.A / 255f);
        }
        catch
        {
            return defaultColor;
        }
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _updateTimer?.Stop();
            _updateTimer?.Dispose();
            _toolTip?.Dispose();
            DisposeDeviceDependentResources();
            _titleTextFormat?.Dispose();
            _listItemTextFormat?.Dispose();
        }

        base.Dispose(disposing);
    }

    protected override void WndProc(ref Message m)
    {
        if (m.Msg == (int)WindowMessage.WM_DISPLAYCHANGE)
        {
            Left = Beallitasok.RSS_Reader_Section[$"Olvasó_{_formInstanceIndex}_Pos_X"].IntValue;
            Top = Beallitasok.RSS_Reader_Section[$"Olvasó_{_formInstanceIndex}_Pos_Y"].IntValue;
        }

        base.WndProc(ref m);
    }
}