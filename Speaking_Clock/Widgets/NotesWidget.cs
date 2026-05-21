using Speaking_Clock;
using System.Diagnostics;
using System.Numerics;
using Vortice.Direct2D1;
using Vortice.DirectWrite;
using Vortice.Mathematics;
using Vortice.WIC;
using FontStyle = Vortice.DirectWrite.FontStyle;

namespace Speaking_clock.Widgets;

public class NotesWidget : CompositionWidgetBase
{
    // ------------------------

    private ID2D1Bitmap? _openNotepadBitmap;
    private ID2D1Bitmap? _closedNotepadBitmap;

    private ID2D1SolidColorBrush? _textBrush;
    private ID2D1SolidColorBrush? _highlightBrush;
    private IDWriteTextFormat? _textFormat;

    private bool _isOpen = true;
    private bool _selectAll = false;
    private string _notesText = "";
    private int _cursorPosition = 0;

    private readonly float _textOffsetX = 20f;
    private readonly float _textOffsetY = 51f;
    private readonly float _lineSpacing = 23.5f;
    private readonly float _baseline = 22.0f;
    private readonly float _fontSize = 15f;

    public NotesWidget(int startX, int startY)
        : base(startX, startY, 350, 450)
    {
        Text = "Notes Widget";
        MouseDoubleClick += OnWidgetDoubleClick;
        LoadNotes();
    }

    private void LoadNotes()
    {
        if (Beallitasok.WidgetSection["Notes_text"].StringValue.Length > 0)
        {
            // Unescape newlines
            _notesText = Beallitasok.WidgetSection["Notes_text"].StringValue.ToString().Replace("\\n", "\n").Replace("\\r", "\r");
        }
        else
        {
            _notesText = "• Buy milk\n• Finish Direct2D implementation\n• Call the dentist\n• Walk the dog";
        }

        // Default the cursor to the end of the text on load
        _cursorPosition = _notesText.Length;
    }

    private void SaveNotes()
    {
        // Escape newlines so it safely writes to a single INI key
        string escapedText = _notesText.Replace("\r", "\\r").Replace("\n", "\\n");
        Beallitasok.WidgetSection["Notes_text"].StringValue = escapedText;
        Beallitasok.ConfigParser.SaveToFile($"{Beallitasok.BasePath}\\{Beallitasok.SetttingsFileName}");
    }

    // Checks if the proposed text will fit inside the widget's drawable area
    private bool WillTextFit(string proposedText)
    {
        if (_dwriteFactory == null || _textFormat == null) return true;

        var maxTextWidth = ClientSize.Width - _textOffsetX - 20;
        var maxTextHeight = ClientSize.Height - _textOffsetY - 60;

        using var textLayout = _dwriteFactory.CreateTextLayout(
            proposedText,
            _textFormat,
            maxTextWidth,
            maxTextHeight);

        // If the calculated height of the text exceeds our maximum height, it won't fit
        return textLayout.Metrics.Height <= maxTextHeight;
    }

    protected override void OnHandleCreated(EventArgs e)
    {
        base.OnHandleCreated(e);
        CreateDeviceDependentResources();
    }

    private void CreateDeviceDependentResources()
    {
        if (_d2dContext == null) return;

        _textBrush?.Dispose();
        _highlightBrush?.Dispose();
        _textFormat?.Dispose();
        _openNotepadBitmap?.Dispose();
        _closedNotepadBitmap?.Dispose();

        _openNotepadBitmap = LoadBitmapFromPath("notepad_open.png");
        _closedNotepadBitmap = LoadBitmapFromPath("notepad_closed.png");

        _textBrush = _d2dContext.CreateSolidColorBrush(new Color4(0.15f, 0.15f, 0.15f, 1.0f));
        _highlightBrush = _d2dContext.CreateSolidColorBrush(new Color4(0.0f, 0.47f, 0.83f, 0.3f));

        if (_dwriteFactory != null)
        {
            _textFormat = _dwriteFactory.CreateTextFormat(
                "Segoe Print",
                FontWeight.Normal,
                FontStyle.Normal,
                FontStretch.Normal,
                _fontSize);

            _textFormat.TextAlignment = TextAlignment.Leading;
            _textFormat.ParagraphAlignment = ParagraphAlignment.Near;
            _textFormat.WordWrapping = WordWrapping.Wrap; // Ensure word wrap is enforced
            _textFormat.SetLineSpacing(LineSpacingMethod.Uniform, _lineSpacing, _baseline);
        }
    }

    private ID2D1Bitmap? LoadBitmapFromPath(string filename)
    {
        if (_d2dContext == null) return null;

        var baseDir = AppDomain.CurrentDomain.BaseDirectory;
        var fullPath = Path.Combine(baseDir, "Assets", "Notes", filename);

        if (!File.Exists(fullPath))
        {
            Debug.WriteLine($"Notes Widget Warning: Could not find image at {fullPath}");
            return null;
        }

        try
        {
            using var decoder = GraphicsFactories.WicFactory.CreateDecoderFromFileName(fullPath);
            using var frame = decoder.GetFrame(0);
            using var converter = GraphicsFactories.WicFactory.CreateFormatConverter();
            converter.Initialize(
                frame,
                PixelFormat.Format32bppPBGRA,
                BitmapDitherType.None,
                null,
                0,
                BitmapPaletteType.MedianCut);

            return _d2dContext.CreateBitmapFromWicBitmap(converter);
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"Error loading bitmap {fullPath}: {ex.Message}");
            return null;
        }
    }

    protected override void DrawContent(ID2D1DeviceContext context)
    {
        var destRect = new Rect(0, 0, ClientSize.Width, ClientSize.Height);
        var activeBitmap = _isOpen ? _openNotepadBitmap : _closedNotepadBitmap;

        if (activeBitmap != null)
        {
            var sourceRect = new Rect(0, 0, activeBitmap.PixelSize.Width, activeBitmap.PixelSize.Height);
            context.DrawBitmap(activeBitmap, destRect, 1.0f, Vortice.Direct2D1.BitmapInterpolationMode.Linear, sourceRect);
        }

        if (_isOpen)
        {
            var maxTextWidth = ClientSize.Width - _textOffsetX - 20;
            var maxTextHeight = ClientSize.Height - _textOffsetY - 60;

            if (_selectAll && _highlightBrush != null && !string.IsNullOrEmpty(_notesText))
            {
                var highlightRect = new Rect(_textOffsetX, _textOffsetY, maxTextWidth + _textOffsetX - 20, maxTextHeight + _textOffsetY - 20);
                context.FillRectangle(highlightRect, _highlightBrush);
            }

            if (_textBrush != null && _textFormat != null && _dwriteFactory != null)
            {
                string displayText = _notesText;

                // Insert cursor at the specific position
                if (Focused && !_selectAll)
                {
                    // Clamp to prevent out-of-bounds exceptions
                    if (_cursorPosition > _notesText.Length) _cursorPosition = _notesText.Length;
                    if (_cursorPosition < 0) _cursorPosition = 0;

                    displayText = _notesText.Insert(_cursorPosition, "|");
                }

                using var textLayout = _dwriteFactory.CreateTextLayout(
                    displayText,
                    _textFormat,
                    maxTextWidth,
                    maxTextHeight);

                context.DrawTextLayout(new Vector2(_textOffsetX, _textOffsetY), textLayout, _textBrush);
            }
        }
    }

    // --- Input Handling ---

    protected override void OnMouseClick(MouseEventArgs e)
    {
        Focus();

        if (_selectAll)
        {
            _selectAll = false;
            Invalidate();
        }

        // Hit-test to move cursor to the clicked location
        if (_isOpen && _dwriteFactory != null && _textFormat != null)
        {
            var maxTextWidth = ClientSize.Width - _textOffsetX - 20;
            var maxTextHeight = ClientSize.Height - _textOffsetY - 60;

            // Use the layout WITHOUT the cursor for accurate hit testing
            using var textLayout = _dwriteFactory.CreateTextLayout(
                _notesText,
                _textFormat,
                maxTextWidth,
                maxTextHeight);

            float hitX = e.X - _textOffsetX;
            float hitY = e.Y - _textOffsetY;

            // DirectWrite provides mapping from X/Y space to the character index
            textLayout.HitTestPoint(hitX, hitY, out var isTrailingHit, out var isInside, out var metrics);

            _cursorPosition = (int)metrics.TextPosition;

            // If user clicked the right half of the character, move cursor after it
            if (isTrailingHit)
            {
                _cursorPosition++;
            }

            // Clamp for safety
            if (_cursorPosition > _notesText.Length) _cursorPosition = _notesText.Length;
            if (_cursorPosition < 0) _cursorPosition = 0;

            Invalidate();
        }

        base.OnMouseClick(e);
    }

    private void OnWidgetDoubleClick(object? sender, MouseEventArgs e)
    {
        if (e.Button == MouseButtons.Left)
        {
            _isOpen = !_isOpen;
            Invalidate();
        }
    }

    protected override void OnKeyDown(KeyEventArgs e)
    {
        if (!_isOpen) return;

        bool isCtrl = e.Modifiers == Keys.Control;

        // Select All
        if (isCtrl && e.KeyCode == Keys.A)
        {
            _selectAll = true;
            Invalidate();
            e.SuppressKeyPress = true;
            return;
        }

        // Copy
        if (isCtrl && e.KeyCode == Keys.C)
        {
            if (!string.IsNullOrEmpty(_notesText)) Clipboard.SetText(_notesText);
            e.SuppressKeyPress = true;
            return;
        }

        // Paste
        if (isCtrl && e.KeyCode == Keys.V)
        {
            if (Clipboard.ContainsText())
            {
                string clipboardText = Clipboard.GetText();
                string proposedText = _selectAll ? clipboardText : _notesText.Insert(_cursorPosition, clipboardText);

                // Only paste if it doesn't overflow
                if (WillTextFit(proposedText))
                {
                    _notesText = proposedText;
                    if (_selectAll)
                    {
                        _cursorPosition = clipboardText.Length;
                    }
                    else
                    {
                        _cursorPosition += clipboardText.Length;
                    }

                    _selectAll = false;
                    SaveNotes();
                    Invalidate();
                }
            }
            e.SuppressKeyPress = true;
            return;
        }

        // Delete Key
        if (e.KeyCode == Keys.Delete)
        {
            if (_selectAll)
            {
                _notesText = "";
                _selectAll = false;
                _cursorPosition = 0;
                SaveNotes();
                Invalidate();
            }
            else if (_cursorPosition < _notesText.Length)
            {
                _notesText = _notesText.Remove(_cursorPosition, 1);
                SaveNotes();
                Invalidate();
            }
        }
        // Backspace Key
        else if (e.KeyCode == Keys.Back)
        {
            if (_selectAll)
            {
                _notesText = "";
                _selectAll = false;
                _cursorPosition = 0;
                SaveNotes();
                Invalidate();
            }
            else if (_cursorPosition > 0 && _notesText.Length > 0)
            {
                _notesText = _notesText.Remove(_cursorPosition - 1, 1);
                _cursorPosition--;
                SaveNotes();
                Invalidate();
            }
        }
        // Enter Key
        else if (e.KeyCode == Keys.Enter)
        {
            string proposedText = _selectAll ? "\n" : _notesText.Insert(_cursorPosition, "\n");
            if (WillTextFit(proposedText))
            {
                _notesText = proposedText;

                if (_selectAll) _cursorPosition = 1;
                else _cursorPosition++;

                _selectAll = false;
                SaveNotes();
                Invalidate();
            }
        }
        // Left Arrow
        else if (e.KeyCode == Keys.Left)
        {
            if (_cursorPosition > 0)
            {
                _cursorPosition--;
                _selectAll = false;
                Invalidate();
                e.SuppressKeyPress = true;
            }
        }
        // Right Arrow
        else if (e.KeyCode == Keys.Right)
        {
            if (_cursorPosition < _notesText.Length)
            {
                _cursorPosition++;
                _selectAll = false;
                Invalidate();
                e.SuppressKeyPress = true;
            }
        }

        base.OnKeyDown(e);
    }

    protected override void OnKeyPress(KeyPressEventArgs e)
    {
        if (!_isOpen) return;

        // Ignore control characters generated by shortcuts
        if (e.KeyChar == (char)1 || e.KeyChar == (char)3 || e.KeyChar == (char)22 || e.KeyChar == (char)8) return;

        if (!char.IsControl(e.KeyChar))
        {
            string proposedText = _selectAll ? e.KeyChar.ToString() : _notesText.Insert(_cursorPosition, e.KeyChar.ToString());

            // Only add character if it doesn't overflow
            if (WillTextFit(proposedText))
            {
                _notesText = proposedText;

                if (_selectAll) _cursorPosition = 1;
                else _cursorPosition++;

                _selectAll = false;
                SaveNotes();
                Invalidate();
            }
        }
        base.OnKeyPress(e);
    }

    protected override bool CanDrag()
    {
        var localPos = PointToClient(Cursor.Position);
        return localPos.Y <= 65;
    }

    protected override void SavePosition(int x, int y)
    {
        Debug.WriteLine($"Notes widget position saved to X:{x}, Y:{y}");
        Beallitasok.WidgetSection["Notes_X"].IntValue = x;
        Beallitasok.WidgetSection["Notes_Y"].IntValue = y;
        Beallitasok.ConfigParser.SaveToFile($"{Beallitasok.BasePath}\\{Beallitasok.SetttingsFileName}");
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            SaveNotes();

            _openNotepadBitmap?.Dispose();
            _closedNotepadBitmap?.Dispose();
            _textBrush?.Dispose();
            _highlightBrush?.Dispose();
            _textFormat?.Dispose();
        }

        base.Dispose(disposing);
    }
}