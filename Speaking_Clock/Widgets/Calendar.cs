using System.Globalization;
using System.Numerics;
using Speaking_Clock;
using Vortice.Direct2D1;
using Vortice.DirectWrite;
using Vortice.Mathematics;
using D2DColor = Vortice.Mathematics.Color4;
using FontStyle = Vortice.DirectWrite.FontStyle;
using TextAntialiasMode = Vortice.Direct2D1.TextAntialiasMode;
using Timer = System.Windows.Forms.Timer;

namespace Speaking_clock.Widgets;

public class CalendarWidget : CompositionWidgetBase
{
    // Text Formats
    private readonly IDWriteTextFormat _buttonSymbolTextFormat;
    private readonly Timer _dailyUpdateTimer;
    private readonly IDWriteTextFormat _dayTextFormat;
    private readonly IDWriteTextFormat _monthYearTextFormat;

    private ID2D1SolidColorBrush? _acrylicBackgroundBrush;

    // Resources
    private ID2D1SolidColorBrush? _buttonBrush;
    private ID2D1SolidColorBrush? _buttonHoverBrush;
    private ID2D1SolidColorBrush? _buttonSymbolBrush;
    private ID2D1SolidColorBrush? _currentDayBrush;

    private ID2D1SolidColorBrush? _defaultTextBrush;

    // Logic / State
    private DateTime _displayDate;
    private ID2D1SolidColorBrush? _highlightDayBrush;
    private HashSet<DateTime> _highlightedDays = new();

    // Interactive UI Elements
    private bool _isMouseOverNextButton;
    private bool _isMouseOverPrevButton;
    private RectangleF _nextButtonRect;
    private RectangleF _prevButtonRect;

    // Shadow brush
    private ID2D1SolidColorBrush? _shadowBrush;
    private ID2D1SolidColorBrush? _sundayBrush;
    private int _yearOfLastHolidayCalculation;
    public DayOfWeek FirstDayOfWeek = DayOfWeek.Monday;


    public CalendarWidget(int startX = 100, int startY = 100)
        : base(startX, startY, CalendarLook.DefaultWidth, CalendarLook.DefaultHeight)
    {
        _displayDate = DateTime.Now;
        _yearOfLastHolidayCalculation = _displayDate.Year;

        // Initialize Text Formats using the Base Class factory
        _monthYearTextFormat = _dwriteFactory.CreateTextFormat("Arial", FontWeight.Bold,
            FontStyle.Normal,
            FontStretch.Normal, CalendarLook.HeaderFontSize);

        _dayTextFormat = _dwriteFactory.CreateTextFormat("Arial", FontWeight.Bold, FontStyle.Normal,
            FontStretch.Normal, CalendarLook.DayFontSize);

        _buttonSymbolTextFormat = _dwriteFactory.CreateTextFormat("Arial", FontWeight.Bold,
            FontStyle.Normal,
            FontStretch.Normal, CalendarLook.ButtonSymbolFontSize);
        _buttonSymbolTextFormat.TextAlignment = TextAlignment.Center;
        _buttonSymbolTextFormat.ParagraphAlignment = ParagraphAlignment.Center;

        // Logic Setup
        UpdateButtonRects();
        SetHighlightedDays(GetHolidaysForYear(_displayDate.Year));

        // Timer
        _dailyUpdateTimer = new Timer();
        _dailyUpdateTimer.Tick += (s, e) =>
        {
            Invalidate();
            UpdateDailyTimerInterval();
        };
        UpdateDailyTimerInterval();
        _dailyUpdateTimer.Start();
    }

    // --- Base Class Overrides ---

    protected override void DrawContent(ID2D1DeviceContext context)
    {
        if (_defaultTextBrush == null) CreateDeviceResources(context);

        context.TextAntialiasMode = TextAntialiasMode.Cleartype;
        context.AntialiasMode = AntialiasMode.PerPrimitive;

        DrawNavigationButtons(context);
        DrawMonthYearHeader(context);

        // NEW: Draw the background before the text
        DrawDaysBackground(context);

        DrawDayNamesHeader(context);
        DrawDaysOfMonth(context);
    }

    protected override void SavePosition(int x, int y)
    {
        Beallitasok.WidgetSection["Naptár_X"].IntValue = x;
        Beallitasok.WidgetSection["Naptár_Y"].IntValue = y;
        Beallitasok.ConfigParser.SaveToFile($"{Beallitasok.BasePath}\\{Beallitasok.SetttingsFileName}");
    }

    protected override bool CanDrag()
    {
        // Prevent dragging if we are hovering over buttons, otherwise check settings
        if (_isMouseOverNextButton || _isMouseOverPrevButton) return false;

        return Beallitasok.RSS_Reader_Section["Húzás"].BoolValue;
    }

    private void DrawDaysBackground(ID2D1DeviceContext context)
    {
        // 1. Calculate the exact number of rows required for this specific month
        var firstDayCurrentMonth = new DateTime(_displayDate.Year, _displayDate.Month, 1);
        var daysInMonth = DateTime.DaysInMonth(_displayDate.Year, _displayDate.Month);

        // Calculate offset (empty cells before the 1st of the month)
        var startColumnOffset = ((int)firstDayCurrentMonth.DayOfWeek - (int)FirstDayOfWeek + 7) % 7;

        // Total cells needed = offset + actual days
        var totalCellsUsed = startColumnOffset + daysInMonth;

        var rowCount = (totalCellsUsed + 6) / 7;

        var padding = 5.0f;
        var startX = CalendarLook.DayColumnStartX - padding;
        var startY = CalendarLook.DayNamesRowTop - padding;

        // Width is fixed (7 columns)
        var width = CalendarLook.DayCellWidth * 7 + padding * 2;

        // Height Calculation:
        float contentHeight = CalendarLook.DayCellHeight
                              + 5 // The gap defined in NumbersGridYStart calculation
                              + rowCount * CalendarLook.DayCellHeight;

        var height = contentHeight + padding * 2;

        var bgRect = new RectangleF(startX, startY, width, height);
        var roundedRect = new RoundedRectangle(bgRect, 8f, 8f);

        context.FillRoundedRectangle(roundedRect, _acrylicBackgroundBrush);
    }

    protected override void OnResize(EventArgs e)
    {
        base.OnResize(e);
        UpdateButtonRects();
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _dailyUpdateTimer?.Dispose();

            _defaultTextBrush?.Dispose();
            _currentDayBrush?.Dispose();
            _sundayBrush?.Dispose();
            _highlightDayBrush?.Dispose();
            _buttonBrush?.Dispose();
            _buttonHoverBrush?.Dispose();
            _buttonSymbolBrush?.Dispose();
            _shadowBrush?.Dispose();
            _acrylicBackgroundBrush?.Dispose();

            _monthYearTextFormat?.Dispose();
            _dayTextFormat?.Dispose();
            _buttonSymbolTextFormat?.Dispose();
        }

        base.Dispose(disposing);
    }


    // --- Resource Creation ---

    private void CreateDeviceResources(ID2D1DeviceContext context)
    {
        _defaultTextBrush?.Dispose();
        _currentDayBrush?.Dispose();
        _sundayBrush?.Dispose();
        _highlightDayBrush?.Dispose();
        _buttonBrush?.Dispose();
        _buttonHoverBrush?.Dispose();
        _buttonSymbolBrush?.Dispose();
        _shadowBrush?.Dispose();
        _acrylicBackgroundBrush?.Dispose();

        _defaultTextBrush = context.CreateSolidColorBrush(new D2DColor(1, 1, 1));
        _currentDayBrush = context.CreateSolidColorBrush(new D2DColor(1, 0.6f, 0));
        _sundayBrush = context.CreateSolidColorBrush(new D2DColor(1f, 0f, 0f));
        _highlightDayBrush = context.CreateSolidColorBrush(new D2DColor(1f, 0f, 0f));

        _buttonBrush = context.CreateSolidColorBrush(new D2DColor(0.3f, 0.3f, 0.3f));
        _buttonHoverBrush = context.CreateSolidColorBrush(new D2DColor(0.5f, 0.5f, 0.5f));
        _buttonSymbolBrush = context.CreateSolidColorBrush(new D2DColor(1f, 1f, 1f));

        // Soft shadow brush
        _shadowBrush = context.CreateSolidColorBrush(new D2DColor(0f, 0f, 0f, 0.6f));

        // Acrylic background
        _acrylicBackgroundBrush = context.CreateSolidColorBrush(new D2DColor(0f, 0f, 0f, 0.4f));
    }

    private void DrawNavigationButtons(ID2D1DeviceContext context)
    {
        // Previous Button
        var prevEllipse = new Ellipse(
            new Vector2(_prevButtonRect.Left + CalendarLook.ButtonRadius,
                _prevButtonRect.Top + CalendarLook.ButtonRadius),
            CalendarLook.ButtonRadius,
            CalendarLook.ButtonRadius
        );
        context.FillEllipse(prevEllipse, _isMouseOverPrevButton ? _buttonHoverBrush : _buttonBrush);
        context.DrawText(CalendarLook.PrevButtonSymbol, _buttonSymbolTextFormat, (Rect)_prevButtonRect,
            _buttonSymbolBrush);

        // Next Button
        var nextEllipse = new Ellipse(
            new Vector2(_nextButtonRect.Left + CalendarLook.ButtonRadius,
                _nextButtonRect.Top + CalendarLook.ButtonRadius),
            CalendarLook.ButtonRadius,
            CalendarLook.ButtonRadius
        );
        context.FillEllipse(nextEllipse, _isMouseOverNextButton ? _buttonHoverBrush : _buttonBrush);
        context.DrawText(CalendarLook.NextButtonSymbol, _buttonSymbolTextFormat, (Rect)_nextButtonRect,
            _buttonSymbolBrush);
    }

    private void DrawMonthYearHeader(ID2D1DeviceContext context)
    {
        var culture = CultureInfo.CurrentUICulture;
        var headerText = _displayDate.ToString("yyyy MMMM", culture);

        using var textLayout = _dwriteFactory.CreateTextLayout(headerText, _monthYearTextFormat,
            Width, CalendarLook.MonthYearHeaderTextHeight);

        textLayout.TextAlignment = TextAlignment.Center;
        var textMetrics = textLayout.Metrics;
        var textRect = new Rect(
            0,
            CalendarLook.MonthYearHeaderTextTop,
            Width,
            CalendarLook.MonthYearHeaderTextTop + textMetrics.Height
        );

        DrawTextWithSoftShadow(context, textLayout, new Vector2(textRect.X, textRect.Y), _defaultTextBrush);
    }

    private void DrawDayNamesHeader(ID2D1DeviceContext context)
    {
        var culture = CultureInfo.CurrentUICulture;
        var dayNames = culture.DateTimeFormat.AbbreviatedDayNames;
        var startDayIndex = (int)FirstDayOfWeek;

        for (var i = 0; i < 7; i++)
        {
            var currentDayNameIndex = (startDayIndex + i) % 7;
            var dayNameToDraw = dayNames[currentDayNameIndex].ToUpper();
            var dayOfWeekEnum = (DayOfWeek)currentDayNameIndex;

            float x = i * CalendarLook.DayCellWidth + CalendarLook.DayColumnStartX;
            var textRect = new Rect(x, CalendarLook.DayNamesRowTop, x + CalendarLook.DayCellWidth,
                CalendarLook.DayNamesRowTop + CalendarLook.DayCellHeight);

            var brush = dayOfWeekEnum == DayOfWeek.Sunday ? _sundayBrush : _defaultTextBrush;
            using var textLayout = _dwriteFactory.CreateTextLayout(dayNameToDraw, _dayTextFormat,
                CalendarLook.DayCellWidth, CalendarLook.DayCellHeight);

            textLayout.TextAlignment = TextAlignment.Center;
            textLayout.ParagraphAlignment = ParagraphAlignment.Center;

            DrawTextWithSoftShadow(context, textLayout, new Vector2(textRect.Left, textRect.Top), brush);
        }
    }

    private void DrawDaysOfMonth(ID2D1DeviceContext context)
    {
        var firstDayCurrentMonth = new DateTime(_displayDate.Year, _displayDate.Month, 1);
        var daysInMonth = DateTime.DaysInMonth(_displayDate.Year, _displayDate.Month);
        var startColumnOffset = ((int)firstDayCurrentMonth.DayOfWeek - (int)FirstDayOfWeek + 7) % 7;

        for (var dayOfMonth = 1; dayOfMonth <= daysInMonth; dayOfMonth++)
        {
            var dateToDraw = new DateTime(_displayDate.Year, _displayDate.Month, dayOfMonth);
            var dayIndexInGrid = startColumnOffset + (dayOfMonth - 1);
            var row = dayIndexInGrid / 7;
            var col = dayIndexInGrid % 7;

            float x = col * CalendarLook.DayCellWidth + CalendarLook.DayColumnStartX;
            float y = row * CalendarLook.DayCellHeight + CalendarLook.NumbersGridYStart;
            var textRect = new Rect(x, y, x + CalendarLook.DayCellWidth, y + CalendarLook.DayCellHeight);

            ID2D1SolidColorBrush selectedBrush;
            if (dateToDraw.Date == DateTime.Today) selectedBrush = _currentDayBrush!;
            else if (_highlightedDays.Contains(dateToDraw.Date)) selectedBrush = _highlightDayBrush!;
            else if (dateToDraw.DayOfWeek == DayOfWeek.Sunday) selectedBrush = _sundayBrush!;
            else selectedBrush = _defaultTextBrush!;

            using var textLayout = _dwriteFactory.CreateTextLayout(dayOfMonth.ToString(),
                _dayTextFormat,
                CalendarLook.DayCellWidth, CalendarLook.DayCellHeight);

            textLayout.TextAlignment = TextAlignment.Center;
            textLayout.ParagraphAlignment = ParagraphAlignment.Center;

            DrawTextWithSoftShadow(context, textLayout, new Vector2(textRect.Left, textRect.Top), selectedBrush);
        }
    }

    // Helper to draw text with a soft, blurred-looking shadow by painting several slightly-offset shadow draws
    private void DrawTextWithSoftShadow(ID2D1DeviceContext context, IDWriteTextLayout layout, Vector2 pos,
        ID2D1SolidColorBrush? textBrush)
    {
        // Fallback: if resources not ready, do a single draw
        if (_shadowBrush == null || textBrush == null)
        {
            context.DrawTextLayout(pos, layout, textBrush ?? _defaultTextBrush!);
            return;
        }

        // Multiple offset draws to simulate a soft blur
        // The offsets and alpha combine to create a soft appearance.
        context.DrawTextLayout(pos + new Vector2(1, 1), layout, _shadowBrush);
        context.DrawTextLayout(pos + new Vector2(2, 1), layout, _shadowBrush);
        context.DrawTextLayout(pos + new Vector2(1, 2), layout, _shadowBrush);
        // a very subtle extra layer for softness
        context.DrawTextLayout(pos + new Vector2(0.5f, 1.5f), layout, _shadowBrush);

        // Draw the actual text on top
        context.DrawTextLayout(pos, layout, textBrush);
    }

    // --- Interaction Logic ---

    protected override void OnChildMouseDown(MouseEventArgs e)
    {
        var mousePoint = new PointF(e.X, e.Y);

        if (_prevButtonRect.Contains(mousePoint))
        {
            NavigateMonth(-1);
            return;
        }

        if (_nextButtonRect.Contains(mousePoint)) NavigateMonth(1);
    }

    protected override void OnChildMouseMove(MouseEventArgs e)
    {
        var mousePoint = new PointF(e.X, e.Y);
        var needsRedraw = false;

        var oldHoverPrev = _isMouseOverPrevButton;
        _isMouseOverPrevButton = _prevButtonRect.Contains(mousePoint);
        if (oldHoverPrev != _isMouseOverPrevButton) needsRedraw = true;

        var oldHoverNext = _isMouseOverNextButton;
        _isMouseOverNextButton = _nextButtonRect.Contains(mousePoint);
        if (oldHoverNext != _isMouseOverNextButton) needsRedraw = true;

        if (needsRedraw) Invalidate();
    }

    protected override void OnChildMouseUp(MouseEventArgs e)
    {
        
    }

    protected override void OnMouseLeave(EventArgs e)
    {
        // Hook into the base form event
        base.OnMouseLeave(e);
        var needsRedraw = false;
        if (_isMouseOverPrevButton)
        {
            _isMouseOverPrevButton = false;
            needsRedraw = true;
        }

        if (_isMouseOverNextButton)
        {
            _isMouseOverNextButton = false;
            needsRedraw = true;
        }

        if (needsRedraw) Invalidate();
    }

    protected override void OnMouseWheel(MouseEventArgs e)
    {
        base.OnMouseWheel(e);
        if (e.Delta > 0) NavigateMonth(-1);
        else if (e.Delta < 0) NavigateMonth(1);
    }

    private void NavigateMonth(int monthOffset)
    {
        _displayDate = _displayDate.AddMonths(monthOffset);
        if (_displayDate.Year != _yearOfLastHolidayCalculation)
        {
            SetHighlightedDays(GetHolidaysForYear(_displayDate.Year));
            _yearOfLastHolidayCalculation = _displayDate.Year;
        }

        Invalidate();
    }

    private void UpdateDailyTimerInterval()
    {
        var now = DateTime.Now;
        var nextMidnight = now.Date.AddDays(1);
        var timeUntilMidnight = nextMidnight - now;
        _dailyUpdateTimer.Interval = Math.Max(1000, (int)timeUntilMidnight.TotalMilliseconds);
    }

    public void SetHighlightedDays(IEnumerable<DateTime> days)
    {
        _highlightedDays = new HashSet<DateTime>(days.Select(d => d.Date));
        Invalidate();
    }

    private List<DateTime> GetHolidaysForYear(int year)
    {
        var holidays = new List<DateTime>
        {
            new(year, 1, 1), new(year, 3, 15), new(year, 5, 1),
            new(year, 8, 20), new(year, 10, 23), new(year, 11, 1),
            new(year, 12, 25), new(year, 12, 26)
        };
        var easterSunday = CalculateEasterSunday(year);
        holidays.Add(easterSunday.AddDays(-2)); // Good Friday
        holidays.Add(easterSunday.AddDays(1)); // Easter Monday
        holidays.Add(easterSunday.AddDays(50)); // Pentecost Monday
        return holidays;
    }

    public static DateTime CalculateEasterSunday(int year)
    {
        var day = 0;
        var month = 0;
        var g = year % 19;
        var c = year / 100;
        var h = (c - c / 4 - (8 * c + 13) / 25 + 19 * g + 15) % 30;
        var i = h - h / 28 * (1 - h / 28 * (29 / (h + 1)) * ((21 - g) / 11));
        day = i - (year + year / 4 + i + 2 - c + c / 4) % 7 + 28;
        month = 3;
        if (day > 31)
        {
            month++;
            day -= 31;
        }

        return new DateTime(year, month, day);
    }

    private void UpdateButtonRects()
    {
        float prevButtonCenterX = CalendarLook.ButtonHorizontalMargin + CalendarLook.ButtonRadius;
        float buttonCenterY = CalendarLook.ButtonTopY + CalendarLook.ButtonRadius;

        _prevButtonRect = new RectangleF(
            prevButtonCenterX - CalendarLook.ButtonRadius,
            buttonCenterY - CalendarLook.ButtonRadius,
            CalendarLook.ButtonRadius * 2,
            CalendarLook.ButtonRadius * 2
        );

        float nextButtonCenterX = ClientSize.Width - CalendarLook.ButtonHorizontalMargin - CalendarLook.ButtonRadius;
        _nextButtonRect = new RectangleF(
            nextButtonCenterX - CalendarLook.ButtonRadius,
            buttonCenterY - CalendarLook.ButtonRadius,
            CalendarLook.ButtonRadius * 2,
            CalendarLook.ButtonRadius * 2
        );
    }

    // --- Constants ---

    private static class CalendarLook
    {
        public static readonly int DefaultWidth = 380;
        public static readonly int DefaultHeight = 280;
        public static readonly float WidgetOpacity = 1;

        public static readonly int ButtonRadius = 12;
        public static readonly int ButtonTopY = 10;
        public static readonly int ButtonHorizontalMargin = 10;
        public static readonly string PrevButtonSymbol = "<";
        public static readonly string NextButtonSymbol = ">";
        public static readonly int ButtonSymbolFontSize = 16;

        public static readonly int MonthYearHeaderTextTop = 10;
        public static readonly int MonthYearHeaderTextHeight = 30;

        public static readonly int DayNamesRowTop = MonthYearHeaderTextTop + MonthYearHeaderTextHeight + 5;
        public static readonly int DayColumnStartX = 15;
        public static readonly int DayCellWidth = (DefaultWidth - DayColumnStartX * 2 + 10) / 7;
        public static readonly int DayCellHeight = 28;

        public static readonly int NumbersGridYStart = DayNamesRowTop + DayCellHeight + 5;
        public static readonly int HeaderFontSize = 24;
        public static readonly int DayFontSize = 20;
    }
}