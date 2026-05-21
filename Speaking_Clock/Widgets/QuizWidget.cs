using System.Reflection;
using System.Text.Json;
using System.Text.Json.Serialization;
using Speaking_Clock;
using Vortice.Direct2D1;
using Vortice.DirectWrite;
using Vortice.Mathematics;
using Color = System.Drawing.Color;
using FontStyle = Vortice.DirectWrite.FontStyle;
using Timer = System.Windows.Forms.Timer;

namespace Speaking_clock.Widgets;

public class QuizItem
{
    [JsonPropertyName("Kerdes")] public string Kerdes { get; set; }
    [JsonPropertyName("A")] public string A { get; set; }
    [JsonPropertyName("B")] public string B { get; set; }
    [JsonPropertyName("C")] public string C { get; set; }
    [JsonPropertyName("D")] public string D { get; set; }
    [JsonPropertyName("Valasz")] public string Valasz { get; set; }
}

public class QuizWidget : CompositionWidgetBase
{
    private static readonly int NumOptions = 4;
    private static readonly float MinimizeButtonSize = 30f;
    private static readonly float MinimizeButtonPadding = 5f;
    private readonly List<string> _currentOptionTexts = new();
    private readonly Timer _nextRoundTimer;

    private readonly RectangleF[] _optionRects;
    private readonly Random _random = new((int)DateTimeOffset.UtcNow.ToUnixTimeSeconds());

    private List<QuizItem> _allQuestions;

    // Brushes (Lazy loaded)
    private ID2D1SolidColorBrush _borderBrush;
    private ID2D1SolidColorBrush _buttonBrush;
    private int _correctAnswersCount;
    private ID2D1SolidColorBrush _correctBrush;
    private QuizItem _currentQuestion;
    private GameState _gameState;
    private int _incorrectAnswersCount;
    private ID2D1SolidColorBrush _incorrectBrush;
    private bool _isMinimized = true;
    private ID2D1SolidColorBrush _minimizeButtonBrush;
    private RectangleF _minimizeButtonRect;

    private Point _mouseDownLocation;
    private ID2D1SolidColorBrush _questionBackgroundBrush;
    private int _selectedIndex = -1;
    private bool _showResultFeedback;
    private ID2D1SolidColorBrush _startButtonBrush;
    private RectangleF _startButtonRect;
    private ID2D1SolidColorBrush _textBrush;

    // Text Formats
    private IDWriteTextFormat _textFormatOptions;
    private IDWriteTextFormat _textFormatQuestion;
    private IDWriteTextFormat _textFormatScore;

    public QuizWidget(int startX, int startY) : base(startX, startY, 200, 60)
    {
        Opacity = 1;
        Text = "Quiz Widget";

        _optionRects = new RectangleF[NumOptions];
        _gameState = GameState.Minimized;

        MouseDown -= OnBaseMouseDown;
        MouseMove -= OnBaseMouseMove;
        MouseUp -= OnBaseMouseUp;
        MouseDown += Widget_MouseDown;
        MouseMove += Widget_MouseMove;
        MouseUp += Widget_MouseUp;

        _nextRoundTimer = new Timer { Interval = 4000 };
        _nextRoundTimer.Tick += (s, e) =>
        {
            _nextRoundTimer.Stop();
            StartNewRound();
        };

        CreateDeviceIndependentResources();
        LoadQuizDataAsync();
    }

    private void CreateDeviceIndependentResources()
    {
        _textFormatQuestion =
            _dwriteFactory.CreateTextFormat("Segoe UI", FontWeight.Bold, FontStyle.Normal, FontStretch.Normal, 18);
        _textFormatQuestion.TextAlignment = TextAlignment.Leading;
        _textFormatQuestion.ParagraphAlignment = ParagraphAlignment.Near;
        _textFormatQuestion.WordWrapping = WordWrapping.Wrap;

        _textFormatOptions =
            _dwriteFactory.CreateTextFormat("Segoe UI", FontWeight.SemiBold, FontStyle.Normal, FontStretch.Normal, 16);
        _textFormatOptions.TextAlignment = TextAlignment.Center;
        _textFormatOptions.ParagraphAlignment = ParagraphAlignment.Center;
        _textFormatOptions.WordWrapping = WordWrapping.Wrap;

        _textFormatScore =
            _dwriteFactory.CreateTextFormat("Segoe UI", FontWeight.Normal, FontStyle.Normal, FontStretch.Normal, 14);
        _textFormatScore.TextAlignment = TextAlignment.Center;
        _textFormatScore.ParagraphAlignment = ParagraphAlignment.Center;
    }

    private void EnsureDeviceDependentResources(ID2D1DeviceContext context)
    {
        if (_textBrush == null || _textBrush.Factory.NativePointer != context.Factory.NativePointer)
        {
            _textBrush?.Dispose();
            _buttonBrush?.Dispose();
            _correctBrush?.Dispose();
            _incorrectBrush?.Dispose();
            _borderBrush?.Dispose();
            _startButtonBrush?.Dispose();
            _minimizeButtonBrush?.Dispose();
            _questionBackgroundBrush?.Dispose();

            _textBrush = context.CreateSolidColorBrush(new Color4(Color.White.ToArgb()));
            _buttonBrush = context.CreateSolidColorBrush(new Color4(Color.FromArgb(255, 60, 60, 65).ToArgb()));
            _correctBrush = context.CreateSolidColorBrush(new Color4(Color.FromArgb(255, 34, 139, 34).ToArgb()));
            _incorrectBrush = context.CreateSolidColorBrush(new Color4(Color.FromArgb(255, 178, 34, 34).ToArgb()));
            _borderBrush = context.CreateSolidColorBrush(new Color4(Color.FromArgb(255, 90, 90, 95).ToArgb()));
            _startButtonBrush = context.CreateSolidColorBrush(new Color4(Color.FromArgb(255, 70, 70, 75).ToArgb()));
            _minimizeButtonBrush = context.CreateSolidColorBrush(new Color4(Color.FromArgb(255, 80, 80, 85).ToArgb()));
            _questionBackgroundBrush =
                context.CreateSolidColorBrush(new Color4(Color.FromArgb(255, 45, 45, 50).ToArgb()));
        }
    }

    protected override void DrawContent(ID2D1DeviceContext context)
    {
        EnsureDeviceDependentResources(context);

        if (_isMinimized)
            DrawMinimizedScreen(context);
        else
            switch (_gameState)
            {
                case GameState.Initializing:
                    DrawCenteredText(context, "Initializing Quiz...", ClientRectangle, _textFormatOptions);
                    break;
                case GameState.Error:
                    DrawCenteredText(context, "An error occurred. Please check data.", ClientRectangle,
                        _textFormatOptions);
                    break;
                case GameState.ShowingQuestion:
                case GameState.ShowingResult:
                    DrawGameScreen(context);
                    break;
            }
    }

    private void DrawGameScreen(ID2D1RenderTarget rt)
    {
        // Minimize Button
        _minimizeButtonRect = new RectangleF(Width - MinimizeButtonSize - MinimizeButtonPadding, MinimizeButtonPadding,
            MinimizeButtonSize, MinimizeButtonSize);
        rt.FillRectangle(_minimizeButtonRect, _minimizeButtonBrush);
        rt.DrawRectangle(_minimizeButtonRect, _borderBrush, 1.5f);

        var minusLine = new RectangleF(_minimizeButtonRect.Left + 8,
            _minimizeButtonRect.Top + _minimizeButtonRect.Height / 2 - 1, _minimizeButtonRect.Width - 16, 3);
        rt.FillRectangle(minusLine, _textBrush);

        // Score
        var scoreDisplayHeight = 30f;
        var topMargin = MinimizeButtonSize + MinimizeButtonPadding * 2;
        var spacing = 10f;
        var questionAreaPadding = Width * 0.05f;

        var scoreText = $"Helyes: {_correctAnswersCount}    Hibás: {_incorrectAnswersCount}";
        var scoreRect = new RectangleF(questionAreaPadding, topMargin, Width - questionAreaPadding * 2,
            scoreDisplayHeight);
        DrawTextInRect(rt, scoreText, scoreRect, _textFormatScore, _textBrush);

        // Question
        var questionTopY = topMargin + scoreDisplayHeight + spacing;
        var questionHeight = Height * 0.25f;
        var questionBackgroundRect = new RectangleF(questionAreaPadding, questionTopY, Width - questionAreaPadding * 2,
            questionHeight);

        rt.FillRectangle(questionBackgroundRect, _questionBackgroundBrush);
        rt.DrawRectangle(questionBackgroundRect, _borderBrush, 1.5f);

        var textPadding = 5f;
        var questionTextLayoutRect = new RectangleF(questionBackgroundRect.Left + textPadding,
            questionBackgroundRect.Top + textPadding, questionBackgroundRect.Width - textPadding * 2,
            questionBackgroundRect.Height - textPadding * 2);

        DrawTextInRect(rt, _currentQuestion != null ? _currentQuestion.Kerdes : "Loading question...",
            questionTextLayoutRect, _textFormatQuestion, _textBrush);

        // Options
        var buttonsTopY = questionBackgroundRect.Bottom + spacing * 1.5f;
        var availableHeightForButtons = Height - buttonsTopY - spacing - MinimizeButtonPadding;
        var buttonHeight = (availableHeightForButtons - (NumOptions - 1) * spacing) / NumOptions;
        buttonHeight = Math.Max(35f, Math.Min(buttonHeight, 60f));

        var currentY = buttonsTopY;
        for (var i = 0; i < NumOptions; i++)
        {
            _optionRects[i] =
                new RectangleF(questionAreaPadding, currentY, Width - questionAreaPadding * 2, buttonHeight);
            var currentOptionBrush = _buttonBrush;

            if (_showResultFeedback && _currentQuestion != null)
            {
                var correctVal = _currentQuestion.Valasz.ToUpper();
                var optionLetter = ((char)('A' + i)).ToString();

                if (optionLetter == correctVal) currentOptionBrush = _correctBrush;
                else if (i == _selectedIndex) currentOptionBrush = _incorrectBrush;
            }

            rt.FillRectangle(_optionRects[i], currentOptionBrush);
            rt.DrawRectangle(_optionRects[i], _borderBrush, 1.5f);

            var optionText = _currentOptionTexts.Count > i ? _currentOptionTexts[i] : "N/A";
            optionText = $"{(char)('A' + i)}) {optionText}";
            DrawTextInRect(rt, optionText, _optionRects[i], _textFormatOptions, _textBrush);
            currentY += buttonHeight + spacing;
        }
    }

    private void DrawMinimizedScreen(ID2D1RenderTarget rt)
    {
        _startButtonRect = new RectangleF(10, 10, Width - 20, Height - 20);
        rt.FillRectangle(_startButtonRect, _startButtonBrush);
        rt.DrawRectangle(_startButtonRect, _borderBrush, 1.5f);
        DrawCenteredText(rt, "Quiz", _startButtonRect, _textFormatOptions);
    }

    private void DrawTextInRect(ID2D1RenderTarget rt, string text, RectangleF layoutRect, IDWriteTextFormat format,
        ID2D1Brush brush)
    {
        if (format != null && brush != null && !string.IsNullOrEmpty(text))
            rt.DrawText(text, format, (Rect)layoutRect, brush);
    }

    private void DrawCenteredText(ID2D1RenderTarget rt, string text, RectangleF bounds, IDWriteTextFormat format)
    {
        if (format != null && _textBrush != null && !string.IsNullOrEmpty(text))
            rt.DrawText(text, format, (Rect)bounds, _textBrush);
    }

    protected override bool CanDrag()
    {
        if (!(Beallitasok.RSS_Reader_Section?["Húzás"]?.BoolValue ?? true)) return false;

        // Determine where the mouse is relative to the control to decide if we can drag
        var cursorClientPos = PointToClient(Cursor.Position);

        if (_isMinimized)
            return MouseButtons == MouseButtons.Right;

        // We can't drag if we are clicking buttons
        if (_minimizeButtonRect.Contains(cursorClientPos)) return false;

        // Check options
        if (_gameState == GameState.ShowingQuestion)
            for (var i = 0; i < NumOptions; i++)
                if (_optionRects[i].Contains(cursorClientPos))
                    return false;

        // Check if inside draggable areas
        var draggableAreaTop = MinimizeButtonSize + MinimizeButtonPadding * 2;
        var draggableHeight = Height * 0.25f + 30f + 10f;
        var questionAreaRect = GetQuestionAreaRect();
        var generalDragArea = new RectangleF(0, 0, Width, draggableAreaTop + draggableHeight);

        if (questionAreaRect.Contains(cursorClientPos) || generalDragArea.Contains(cursorClientPos)) return true;

        return false;
    }

    protected override void OnChildMouseUp(MouseEventArgs e)
    {
        if (_isMinimized)
        {
            if (e.Button == MouseButtons.Left && _startButtonRect.Contains(e.X, e.Y)) ExpandToFullView();
        }
        else
        {
            if (e.Button == MouseButtons.Left && _minimizeButtonRect.Contains(e.X, e.Y))
            {
                MinimizeToButton();
                return;
            }

            if (_gameState == GameState.ShowingQuestion && e.Button == MouseButtons.Left)
                for (var i = 0; i < NumOptions; i++)
                    if (_optionRects[i].Contains(e.X, e.Y))
                    {
                        _selectedIndex = i;
                        _showResultFeedback = true;
                        _gameState = GameState.ShowingResult;

                        var selectedAnswerLetter = ((char)('A' + i)).ToString();
                        if (_currentQuestion != null && selectedAnswerLetter == _currentQuestion.Valasz.ToUpper())
                            _correctAnswersCount++;
                        else
                            _incorrectAnswersCount++;

                        _nextRoundTimer.Start();
                        Invalidate();
                        break;
                    }
        }
    }

    protected override void SavePosition(int x, int y)
    {
        Beallitasok.WidgetSection["Quiz_X"].IntValue = x;
        Beallitasok.WidgetSection["Quiz_Y"].IntValue = y;
        Beallitasok.ConfigParser?.SaveToFile(Path.Combine(Beallitasok.BasePath, Beallitasok.SetttingsFileName));
    }

    private RectangleF GetQuestionAreaRect()
    {
        var topMargin = MinimizeButtonSize + MinimizeButtonPadding * 2;
        var scoreDisplayHeight = 30f;
        var spacing = 10f;
        var questionAreaPadding = Width * 0.05f;
        var questionTopY = topMargin + scoreDisplayHeight + spacing;
        var questionHeight = Height * 0.25f;
        return new RectangleF(questionAreaPadding, questionTopY, Width - questionAreaPadding * 2, questionHeight);
    }

    private async void LoadQuizDataAsync()
    {
        try
        {
            var resourceName = "Speaking_clock.QuestionData.json";
            using var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(resourceName)
                               ?? throw new FileNotFoundException($"Could not load embedded resource: {resourceName}");

            string jsonText;
            using (var rdr = new StreamReader(stream))
            {
                jsonText = await rdr.ReadToEndAsync();
            }

            _allQuestions = JsonSerializer.Deserialize<List<QuizItem>>(jsonText,
                new JsonSerializerOptions { PropertyNameCaseInsensitive = true });

            _allQuestions = _allQuestions?.Where(q =>
                !string.IsNullOrWhiteSpace(q.Kerdes) && !string.IsNullOrWhiteSpace(q.A) &&
                !string.IsNullOrWhiteSpace(q.B) && !string.IsNullOrWhiteSpace(q.C) &&
                !string.IsNullOrWhiteSpace(q.D) && !string.IsNullOrWhiteSpace(q.Valasz) &&
                new[] { "A", "B", "C", "D" }.Contains(q.Valasz.ToUpper())).ToList();

            if (_allQuestions == null || _allQuestions.Count == 0)
            {
                _gameState = GameState.Error;
                Invalidate();
                return;
            }

            if (!_isMinimized) StartNewRound();
            else Invalidate();
        }
        catch (Exception)
        {
            _gameState = GameState.Error;
            Invalidate();
        }
    }

    private void StartNewRound()
    {
        if (_allQuestions == null || _allQuestions.Count == 0) return;
        _showResultFeedback = false;
        _selectedIndex = -1;
        _currentOptionTexts.Clear();
        _currentQuestion = _allQuestions[_random.Next(_allQuestions.Count)];
        _currentOptionTexts.Add(_currentQuestion.A);
        _currentOptionTexts.Add(_currentQuestion.B);
        _currentOptionTexts.Add(_currentQuestion.C);
        _currentOptionTexts.Add(_currentQuestion.D);
        _gameState = GameState.ShowingQuestion;
        Invalidate();
    }

    private void ExpandToFullView()
    {
        _isMinimized = false;
        Width = 420;
        Height = 550;
        if (_allQuestions == null) LoadQuizDataAsync();
        else StartNewRound();
    }

    private void MinimizeToButton()
    {
        _isMinimized = true;
        _gameState = GameState.Minimized;
        Width = 200;
        Height = 60;
        Invalidate();
    }

    private void Widget_MouseDown(object sender, MouseEventArgs e)
    {
        if (e.Button == MouseButtons.Left && !_isMinimized && _minimizeButtonRect.Contains(e.Location))
            // Click on minimize button, don't start drag.
            return;

        var canDrag = Beallitasok.RSS_Reader_Section?["Húzás"]?.BoolValue ?? true;
        if (!canDrag) return;

        if (_isMinimized && e.Button == MouseButtons.Right) // Drag minimized with Right Mouse
        {
            _isDragging = true;
            _mouseDownLocation = e.Location;
        }
        else if (!_isMinimized && e.Button == MouseButtons.Left) // Drag expanded with Left Mouse on specific areas
        {
            // Allow dragging by clicking the question area or score area
            var draggableAreaTop = MinimizeButtonSize + MinimizeButtonPadding * 2;
            var draggableHeight = Height * 0.25f + 30f + 10f; // Approx height of score + question + spacing
            var questionAreaRect =
                GetQuestionAreaRect();

            if (questionAreaRect.Contains(e.Location) ||
                new RectangleF(0, 0, Width, draggableAreaTop + draggableHeight)
                    .Contains(e.Location)) // Broader drag area
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
        if (_isDragging)
        {
            _isDragging = false;
            if (Beallitasok.WidgetSection != null)
            {
                Beallitasok.WidgetSection["Quiz_X"].IntValue = Left;
                Beallitasok.WidgetSection["Quiz_Y"].IntValue = Top;
                Beallitasok.ConfigParser?.SaveToFile(Path.Combine(Beallitasok.BasePath, Beallitasok.SetttingsFileName));
            }

            return;
        }

        if (_isMinimized)
        {
            if (e.Button == MouseButtons.Left && _startButtonRect.Contains(e.X, e.Y)) ExpandToFullView();
        }
        else // Not minimized
        {
            if (e.Button == MouseButtons.Left && _minimizeButtonRect.Contains(e.X, e.Y))
            {
                MinimizeToButton();
                return;
            }

            if (_gameState == GameState.ShowingQuestion && e.Button == MouseButtons.Left)
                for (var i = 0; i < NumOptions; i++)
                    if (_optionRects[i].Contains(e.X, e.Y))
                    {
                        _selectedIndex = i;
                        _showResultFeedback = true;
                        _gameState = GameState.ShowingResult;

                        var selectedAnswerLetter = ((char)('A' + i)).ToString();
                        if (_currentQuestion != null && selectedAnswerLetter == _currentQuestion.Valasz.ToUpper())
                            _correctAnswersCount++;
                        else
                            _incorrectAnswersCount++;

                        _nextRoundTimer.Start();
                        Invalidate();
                        break;
                    }
        }
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _nextRoundTimer?.Dispose();
            _textBrush?.Dispose();
            _buttonBrush?.Dispose();
            _correctBrush?.Dispose();
            _incorrectBrush?.Dispose();
            _borderBrush?.Dispose();
            _minimizeButtonBrush?.Dispose();
            _startButtonBrush?.Dispose();
            _questionBackgroundBrush?.Dispose();
            _textFormatQuestion?.Dispose();
            _textFormatOptions?.Dispose();
            _textFormatScore?.Dispose();
        }

        base.Dispose(disposing);
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