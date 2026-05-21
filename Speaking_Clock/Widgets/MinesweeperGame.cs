using System.Numerics;
using Speaking_Clock;
using Vanara.PInvoke;
using Vortice.Direct2D1;
using Vortice.DirectWrite;
using Vortice.Mathematics;
using Color = System.Drawing.Color;
using FontStyle = Vortice.DirectWrite.FontStyle;
using Size = System.Drawing.Size;
using Point = System.Drawing.Point;
using RectangleF = System.Drawing.RectangleF;

namespace Speaking_clock.Widgets;

public enum GameState
{
    NotStarted,
    Playing,
    Won,
    Lost
}

public class CellInfo
{
    public CellInfo()
    {
        IsMine = false;
        IsRevealed = false;
        IsFlagged = false;
        AdjacentMines = 0;
    }

    public bool IsMine { get; set; }
    public bool IsRevealed { get; set; }
    public bool IsFlagged { get; set; }
    public int AdjacentMines { get; set; }
    public bool IsEmptyAndRevealed => IsRevealed && !IsMine && AdjacentMines == 0;
}

public class MinesweeperGame
{
    private bool _firstClick;

    public MinesweeperGame(int rows, int cols, int minesCount)
    {
        Rows = rows;
        Cols = cols;
        MinesCount = Math.Max(0, Math.Min(minesCount, rows * cols - 1));
        ResetGame();
    }

    public int Rows { get; private set; }
    public int Cols { get; private set; }
    public int MinesCount { get; private set; }
    public CellInfo[,] Board { get; private set; }
    public GameState CurrentGameState { get; private set; }
    public int RevealedCellsCount { get; private set; }
    public int FlagsPlacedCount { get; private set; }

    private void ResetGame()
    {
        Board = new CellInfo[Rows, Cols];
        for (var r = 0; r < Rows; r++)
        for (var c = 0; c < Cols; c++)
            Board[r, c] = new CellInfo();

        CurrentGameState = GameState.NotStarted;
        RevealedCellsCount = 0;
        FlagsPlacedCount = 0;
        _firstClick = true;
    }

    public void InitializeBoardAndPlaceMines(int initialSafeRow, int initialSafeCol)
    {
        var rand = new Random((int)DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        var minesPlaced = 0;
        while (minesPlaced < MinesCount)
        {
            var r = rand.Next(Rows);
            var c = rand.Next(Cols);

            if (r == initialSafeRow && c == initialSafeCol) continue;

            if (!Board[r, c].IsMine)
            {
                Board[r, c].IsMine = true;
                minesPlaced++;
            }
        }

        CalculateAllAdjacentMines();
        CurrentGameState = GameState.Playing;
        _firstClick = false;
    }

    private void CalculateAllAdjacentMines()
    {
        for (var r = 0; r < Rows; r++)
        for (var c = 0; c < Cols; c++)
            if (!Board[r, c].IsMine)
                Board[r, c].AdjacentMines = CountAdjacentMines(r, c);
    }

    private int CountAdjacentMines(int row, int col)
    {
        var count = 0;
        for (var rOffset = -1; rOffset <= 1; rOffset++)
        for (var cOffset = -1; cOffset <= 1; cOffset++)
        {
            if (rOffset == 0 && cOffset == 0) continue;
            var nr = row + rOffset;
            var nc = col + cOffset;
            if (nr >= 0 && nr < Rows && nc >= 0 && nc < Cols && Board[nr, nc].IsMine) count++;
        }

        return count;
    }

    public void RevealCell(int row, int col)
    {
        if (row < 0 || row >= Rows || col < 0 || col >= Cols) return;

        if (_firstClick) InitializeBoardAndPlaceMines(row, col);

        var cell = Board[row, col];
        if (CurrentGameState != GameState.Playing || cell.IsRevealed || cell.IsFlagged) return;

        cell.IsRevealed = true;
        RevealedCellsCount++;

        if (cell.IsMine)
        {
            CurrentGameState = GameState.Lost;
            RevealAllMinesOnLoss();
            return;
        }

        if (cell.AdjacentMines == 0)
            for (var rOffset = -1; rOffset <= 1; rOffset++)
            for (var cOffset = -1; cOffset <= 1; cOffset++)
                RevealCell(row + rOffset, col + cOffset);

        CheckWinCondition();
    }

    private void RevealAllMinesOnLoss()
    {
        for (var r = 0; r < Rows; r++)
        for (var c = 0; c < Cols; c++)
            if (Board[r, c].IsMine)
                Board[r, c].IsRevealed = true;
    }

    public void ToggleFlag(int row, int col)
    {
        if (_firstClick || CurrentGameState != GameState.Playing || row < 0 || row >= Rows || col < 0 || col >= Cols ||
            Board[row, col].IsRevealed) return;

        Board[row, col].IsFlagged = !Board[row, col].IsFlagged;
        if (Board[row, col].IsFlagged) FlagsPlacedCount++;
        else FlagsPlacedCount--;
    }

    private void CheckWinCondition()
    {
        if (CurrentGameState != GameState.Playing) return;

        if (RevealedCellsCount == Rows * Cols - MinesCount)
        {
            CurrentGameState = GameState.Won;
            for (var r = 0; r < Rows; r++)
            for (var c = 0; c < Cols; c++)
                if (Board[r, c].IsMine && !Board[r, c].IsFlagged)
                {
                    Board[r, c].IsFlagged = true;
                    FlagsPlacedCount++;
                }
        }
    }

    public void Restart(int newRows, int newCols, int newMines)
    {
        Rows = newRows;
        Cols = newCols;
        MinesCount = Math.Max(0, Math.Min(newMines, newRows * newCols - 1));
        ResetGame();
    }
}

public class Minesweeper : CompositionWidgetBase
{
    private static readonly float MinimizeButtonSize = 30f;
    private static readonly float MinimizeButtonPadding = 5f;
    private readonly float _cellSize = 30.0f;
    private readonly int _cols;
    private readonly MinesweeperGame _game;
    private readonly int _mines;
    private readonly float _newGameButtonHeight = 30.0f;
    private readonly float _newGameButtonPadding = 5.0f;
    private readonly string _newGameButtonText = "Új játék";
    private readonly float _newGameButtonWidth = 100.0f;
    private readonly int _rows;
    private readonly float _statusBarHeight = 40.0f;

    private IDWriteTextFormat _emojiTextFormat;

    private float _gridOffsetY;
    private ID2D1SolidColorBrush _hiddenCellBrush;

    private bool _isMinimized = true;
    private ID2D1SolidColorBrush _lineBrush;
    private ID2D1SolidColorBrush _minimizeButtonBrush;
    private RectangleF _minimizeButtonRect;

    private Point _mouseDownLocation;

    private ID2D1SolidColorBrush _newGameButtonBrush;

    // Game UI elements
    private RectangleF _newGameButtonRect;
    private ID2D1SolidColorBrush _newGameButtonTextBrush;
    private IDWriteTextFormat _newGameButtonTextFormat;

    private ID2D1SolidColorBrush _revealedCellBrush;
    private ID2D1SolidColorBrush _startButtonBrush;
    private RectangleF _startButtonRect;
    private ID2D1SolidColorBrush _statusBarBrush;
    private string _statusMessage = string.Empty;
    private IDWriteTextFormat _statusTextFormat;
    private ID2D1SolidColorBrush _textBrush;
    private IDWriteTextFormat _textFormat;

    // Pass 160, 40 as initial size (minimized state)
    public Minesweeper(int startX, int startY, int rows = 10, int cols = 10, int mines = 15)
        : base(startX, startY, 160, 40)
    {
        _rows = rows;
        _cols = cols;
        _mines = mines;
        _game = new MinesweeperGame(_rows, _cols, _mines);

        MouseDown -= OnBaseMouseDown;
        MouseMove -= OnBaseMouseMove;
        MouseUp -= OnBaseMouseUp;
        MouseDown += Minesweeper_MouseDown;
        MouseMove += Minesweeper_MouseMove;
        MouseUp += Minesweeper_MouseUp;


        Text = "Aknakereső 💣";
        BackColor = Color.FromArgb(220, 220, 220); 

        CreateDeviceIndependentResources();
        _isMinimized = true;
        UpdateFormSize();
        UpdateStatusMessage();
    }

    private void CreateDeviceIndependentResources()
    {
        _textFormat?.Dispose();
        _textFormat = _dwriteFactory.CreateTextFormat("Arial", FontWeight.Bold, FontStyle.Normal, FontStretch.Normal,
            _cellSize * 0.5f);
        _textFormat.TextAlignment = TextAlignment.Center;
        _textFormat.ParagraphAlignment = ParagraphAlignment.Center;

        _emojiTextFormat?.Dispose();
        _emojiTextFormat = _dwriteFactory.CreateTextFormat("Segoe UI Emoji", FontWeight.Normal, FontStyle.Normal,
            FontStretch.Normal, _cellSize * 0.6f);
        _emojiTextFormat.TextAlignment = TextAlignment.Center;
        _emojiTextFormat.ParagraphAlignment = ParagraphAlignment.Center;

        _statusTextFormat?.Dispose();
        _statusTextFormat =
            _dwriteFactory.CreateTextFormat("Arial", FontWeight.Normal, FontStyle.Normal, FontStretch.Normal, 16.0f);
        _statusTextFormat.TextAlignment = TextAlignment.Leading;
        _statusTextFormat.ParagraphAlignment = ParagraphAlignment.Center;

        _newGameButtonTextFormat?.Dispose();
        _newGameButtonTextFormat =
            _dwriteFactory.CreateTextFormat("Arial", FontWeight.SemiBold, FontStyle.Normal, FontStretch.Normal, 14.0f);
        _newGameButtonTextFormat.TextAlignment = TextAlignment.Center;
        _newGameButtonTextFormat.ParagraphAlignment = ParagraphAlignment.Center;
    }

    private void UpdateFormSize()
    {
        if (_isMinimized)
        {
            ClientSize = new Size(160, 40);
            _startButtonRect = new RectangleF(0, 0, ClientSize.Width, ClientSize.Height);
        }
        else
        {
            // Calculate grid size
            var gridWidth = (int)(_cols * _cellSize);
            var gridHeight = (int)(_rows * _cellSize);

            // Add extra space for minimize button at top
            var buttonAreaHeight = MinimizeButtonSize + 2 * MinimizeButtonPadding;
            var totalHeight = gridHeight + _statusBarHeight + buttonAreaHeight;

            ClientSize = new Size(gridWidth, (int)totalHeight);

            // Position minimize button in top-right, above the grid
            _minimizeButtonRect = new RectangleF(
                gridWidth - MinimizeButtonSize - MinimizeButtonPadding,
                MinimizeButtonPadding,
                MinimizeButtonSize,
                MinimizeButtonSize);

            // Adjust grid and status bar positions
            _gridOffsetY = buttonAreaHeight;
            _newGameButtonRect = new RectangleF(
                gridWidth - _newGameButtonWidth - _newGameButtonPadding,
                _gridOffsetY + gridHeight + (_statusBarHeight - _newGameButtonHeight) / 2,
                _newGameButtonWidth,
                _newGameButtonHeight);
        }
    }
    protected override bool CanDrag()
    {
        return false;
    }

    protected override void SavePosition(int x, int y)
    {
        Beallitasok.WidgetSection["Aknakereső_X"].IntValue = x;
        Beallitasok.WidgetSection["Aknakereső_Y"].IntValue = y;
        Beallitasok.ConfigParser.SaveToFile(Path.Combine(Beallitasok.BasePath, Beallitasok.SetttingsFileName));
    }

    private void Minesweeper_MouseDown(object sender, MouseEventArgs e)
    {
        if (_isMinimized)
        {
            // When minimized, only allow dragging with right mouse button
            if (e.Button == MouseButtons.Right && Beallitasok.RSS_Reader_Section["Húzás"].BoolValue)
            {
                _isDragging = true;
                _mouseDownLocation = e.Location;
            }
            else if (e.Button == MouseButtons.Left && _startButtonRect.Contains(e.Location))
            {
                ExpandToFullView();
            }
        }
        else
        {
            // Check for minimize button click
            if (_minimizeButtonRect.Contains(e.Location))
            {
                MinimizeToButton();
                return;
            }

            // Check for New Game button click
            if (_newGameButtonRect.Contains(e.Location))
                if (e.Button == MouseButtons.Left)
                {
                    _game.Restart(_rows, _cols, _mines);
                    UpdateStatusMessage();
                    Invalidate();
                    return;
                }

            // Calculate cell coordinates with grid offset
            var c = (int)(e.X / _cellSize);
            var r = (int)((e.Y - _gridOffsetY) / _cellSize); // Subtract grid offset from Y position

            // Only process clicks within the grid bounds
            if (r >= 0 && r < _rows && c >= 0 && c < _cols)
                if (_game.CurrentGameState == GameState.Playing || _game.CurrentGameState == GameState.NotStarted)
                {
                    if (e.Button == MouseButtons.Left)
                        _game.RevealCell(r, c);
                    else if (e.Button == MouseButtons.Right)
                        _game.ToggleFlag(r, c);
                    UpdateStatusMessage();
                    Invalidate();
                    return;
                }

            // When not minimized, allow dragging with left button
            if (e.Button == MouseButtons.Left && Beallitasok.RSS_Reader_Section["Húzás"].BoolValue)
            {
                _isDragging = true;
                _mouseDownLocation = e.Location;
            }
        }
    }

    private void Minesweeper_MouseMove(object sender, MouseEventArgs e)
    {
        if (_isDragging)
        {
            Left += e.X - _mouseDownLocation.X;
            Top += e.Y - _mouseDownLocation.Y;
        }
    }

    private void Minesweeper_MouseUp(object sender, MouseEventArgs e)
    {
        if (_isDragging)
        {
            _isDragging = false;
            Beallitasok.WidgetSection["Aknakereső_X"].IntValue = Left;
            Beallitasok.WidgetSection["Aknakereső_Y"].IntValue = Top;
            Beallitasok.ConfigParser.SaveToFile(Path.Combine(Beallitasok.BasePath, Beallitasok.SetttingsFileName));
        }
    }

    private void UpdateStatusMessage()
    {
        switch (_game.CurrentGameState)
        {
            case GameState.NotStarted:
                _statusMessage = $"Aknák: {_game.MinesCount}. Kattints a kezdéshez!";
                break;
            case GameState.Playing:
                var minesRemaining = _game.MinesCount - _game.FlagsPlacedCount;
                _statusMessage = $"Aknák: {minesRemaining} | Zászlók: {_game.FlagsPlacedCount}";
                break;
            case GameState.Won:
                _statusMessage = "🎉 Gratulálok! Megnyerted! 🎉";
                break;
            case GameState.Lost:
                _statusMessage = "💣 Vége a játéknak! Ráléptél egy aknára! 💣";
                break;
        }
    }

    private void CheckAndCreateBrushes(ID2D1DeviceContext context)
    {
        if (_lineBrush != null && _lineBrush.Factory.NativePointer == context.Factory.NativePointer) return;

        DisposeBrushes();
        _lineBrush = context.CreateSolidColorBrush(new Color4(Color.DimGray.ToArgb()));
        _textBrush = context.CreateSolidColorBrush(new Color4(Color.Black.ToArgb()));
        _hiddenCellBrush = context.CreateSolidColorBrush(new Color4(Color.LightGray.ToArgb()));
        _revealedCellBrush = context.CreateSolidColorBrush(new Color4(Color.WhiteSmoke.ToArgb()));
        _statusBarBrush = context.CreateSolidColorBrush(new Color4(Color.Silver.ToArgb()));
        _newGameButtonBrush = context.CreateSolidColorBrush(new Color4(Color.DarkGray.ToArgb()));
        _newGameButtonTextBrush = context.CreateSolidColorBrush(new Color4(Color.White.ToArgb()));
        _startButtonBrush = context.CreateSolidColorBrush(new Color4(Color.DarkGray.ToArgb()));
        _minimizeButtonBrush = context.CreateSolidColorBrush(new Color4(Color.FromArgb(255, 80, 80, 85).ToArgb()));
    }

    protected override void DrawContent(ID2D1DeviceContext context)
    {
        CheckAndCreateBrushes(context);

        // Clear with specific background color for this game
        context.Clear(new Color4(BackColor.R / 255.0f, BackColor.G / 255.0f, BackColor.B / 255.0f));

        if (_isMinimized)
            DrawMinimizedScreen(context);
        else
            DrawGameScreen(context);
    }

    private void DrawMinimizedScreen(ID2D1DeviceContext rt)
    {
        rt.FillRectangle(_startButtonRect, _startButtonBrush);
        rt.DrawRectangle(_startButtonRect, _lineBrush, 1.5f);
        DrawCenteredText(rt, "Aknakereső", _startButtonRect, _textFormat);
    }

    private void DrawGameScreen(ID2D1DeviceContext rt)
    {
        // Draw game board (offset by _gridOffsetY)
        for (var r = 0; r < _rows; r++)
        for (var c = 0; c < _cols; c++)
        {
            var cell = _game.Board[r, c];
            var cellRect = new Rect(
                c * _cellSize,
                _gridOffsetY + r * _cellSize,
                _cellSize,
                _cellSize);

            var cellFillBrush = cell.IsRevealed ? _revealedCellBrush : _hiddenCellBrush;
            rt.FillRectangle(cellRect, cellFillBrush);

            var cellText = "";
            var formatToUse = _textFormat;

            if (cell.IsRevealed)
            {
                if (cell.IsMine)
                {
                    cellText = "💣";
                    formatToUse = _emojiTextFormat;
                }
                else if (cell.AdjacentMines > 0)
                {
                    cellText = cell.AdjacentMines.ToString();
                }
            }
            else if (cell.IsFlagged)
            {
                cellText = "🚩";
                formatToUse = _emojiTextFormat;
            }

            if (!string.IsNullOrEmpty(cellText))
                rt.DrawText(cellText, formatToUse, cellRect, _textBrush);

            rt.DrawRectangle(cellRect, _lineBrush, 0.8f);
        }

        // Draw status bar background
        var statusBgRect = new Rect(
            0,
            _gridOffsetY + _rows * _cellSize,
            ClientSize.Width,
            _statusBarHeight);
        rt.FillRectangle(statusBgRect, _statusBarBrush);

        // Draw status bar top border
        rt.DrawLine(
            new Vector2(0, _gridOffsetY + _rows * _cellSize),
            new Vector2(ClientSize.Width, _gridOffsetY + _rows * _cellSize),
            _lineBrush, 1.0f);

        // Draw status message
        var statusTextRect = new Rect(
            _newGameButtonPadding,
            _gridOffsetY + _rows * _cellSize,
            ClientSize.Width - _newGameButtonWidth - 2 * _newGameButtonPadding,
            _statusBarHeight);
        rt.DrawText(_statusMessage, _statusTextFormat, statusTextRect, _textBrush);

        // Draw New Game button
        var d2dButtonRect = new Rect(
            _newGameButtonRect.X,
            _gridOffsetY + _rows * _cellSize + (_statusBarHeight - _newGameButtonHeight) / 2,
            _newGameButtonRect.Width,
            _newGameButtonRect.Height);
        rt.FillRectangle(d2dButtonRect, _newGameButtonBrush);
        rt.DrawRectangle(d2dButtonRect, _lineBrush, 1.0f);
        rt.DrawText(_newGameButtonText, _newGameButtonTextFormat, d2dButtonRect, _newGameButtonTextBrush);

        // Draw minimize button in its own area above the grid
        var buttonColor = new Color4(0.3f, 0.3f, 0.3f);
        using (var buttonBrush = rt.CreateSolidColorBrush(buttonColor))
        {
            rt.FillRectangle(_minimizeButtonRect, buttonBrush);
            rt.DrawRectangle(_minimizeButtonRect, _lineBrush, 1.5f);

            // Draw minus sign
            var minusLine = new RectangleF(
                _minimizeButtonRect.Left + 8,
                _minimizeButtonRect.Top + _minimizeButtonRect.Height / 2 - 1,
                _minimizeButtonRect.Width - 16,
                3);
            rt.FillRectangle(minusLine, _textBrush);
        }
    }

    private void DrawCenteredText(ID2D1DeviceContext rt, string text, RectangleF bounds, IDWriteTextFormat format)
    {
        if (format != null && _textBrush != null)
            rt.DrawText(text, format, (Rect)bounds, _textBrush);
    }

    private void ExpandToFullView()
    {
        _isMinimized = false;
        UpdateFormSize();
        Invalidate();
    }

    private void MinimizeToButton()
    {
        _isMinimized = true;
        UpdateFormSize();
        Invalidate();
    }

    private void DisposeBrushes()
    {
        _lineBrush?.Dispose();
        _textBrush?.Dispose();
        _hiddenCellBrush?.Dispose();
        _revealedCellBrush?.Dispose();
        _statusBarBrush?.Dispose();
        _newGameButtonBrush?.Dispose();
        _newGameButtonTextBrush?.Dispose();
        _startButtonBrush?.Dispose();
        _minimizeButtonBrush?.Dispose();

        _lineBrush = null;
        _textBrush = null;
        _hiddenCellBrush = null;
        _revealedCellBrush = null;
        _statusBarBrush = null;
        _newGameButtonBrush = null;
        _newGameButtonTextBrush = null;
        _startButtonBrush = null;
        _minimizeButtonBrush = null;
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            DisposeBrushes();
            _textFormat?.Dispose();
            _emojiTextFormat?.Dispose();
            _statusTextFormat?.Dispose();
            _newGameButtonTextFormat?.Dispose();
        }

        base.Dispose(disposing);
    }

    protected override void WndProc(ref Message m)
    {
        if (m.Msg == (int)User32.WindowMessage.WM_DISPLAYCHANGE)
            RepositionOverlay();

        base.WndProc(ref m);
    }

    private void RepositionOverlay()
    {
        Left = Beallitasok.WidgetSection["Aknakereső_X"].IntValue;
        Top = Beallitasok.WidgetSection["Aknakereső_Y"].IntValue;
    }
}