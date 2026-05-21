using System.ComponentModel;
using static Vanara.PInvoke.User32;
using Timer = System.Windows.Forms.Timer;


namespace Speaking_Clock;

public class OverlayForm : Form
{
    private Button _topLeftButton;
    private Timer _updatetimer;
    private IContainer components;

    public OverlayForm()
    {
        InitializeComponent();
        InitializeOverlay();
        SetWindowPos(Handle,
            (IntPtr)SpecialWindowHandles.HWND_TOPMOST,
            0, 0, 0, 0,
            SetWindowPosFlags.SWP_NOMOVE |
            SetWindowPosFlags.SWP_NOSIZE |
            SetWindowPosFlags.SWP_NOACTIVATE /*|
            SetWindowPosFlags.SWP_NOZORDER*/);
    }

    protected override CreateParams CreateParams
    {
        get
        {
            var pm = base.CreateParams;
            pm.ExStyle |=
                (int)(WindowStylesEx.WS_EX_TOPMOST |
                      WindowStylesEx.WS_EX_NOACTIVATE);
            return pm;
        }
    }

    /* protected override void WndProc(ref Message m)
     {
         static readonly int waInactive = 0;
         if (m.Msg == (int)User32.WindowMessage.WM_MOUSEACTIVATE)
         {
             m.Result = (IntPtr)User32.WindowMessage.WM_NCACTIVATE;
             return;
         }

         if (m.Msg == (int)User32.WindowMessage.WM_ACTIVATE)
         {
             if (((int)m.WParam & 0xFFFF) != waInactive)
             {
                 if (m.LParam != IntPtr.Zero)
                     User32.SetActiveWindow(m.LParam);
                 else
                     User32.SetActiveWindow(IntPtr.Zero);
             }
         }

         base.WndProc(ref m);
     }*/

    private void InitializeOverlay()
    {
        // Set up the form properties
        FormBorderStyle = FormBorderStyle.None; // No border
        TopMost = true; // Keep it on top
        StartPosition = FormStartPosition.Manual; // Manual positioning
        Location = new Point(0, 0); // Top-left corner
        BackColor = Color.Lime; // Key color for transparency
        TransparencyKey = Color.Lime; // Make form background transparent
        Size = new Size(30, 30); // Adjust size as needed
        ShowInTaskbar = false;

        // Create a button
        _topLeftButton = new Button();
        _topLeftButton.Text = "X";
        _topLeftButton.Size = new Size(30, 30);
        _topLeftButton.Location = new Point(0, 0); // Position within the form
        _topLeftButton.Click += TopLeftButton_Click;
        _topLeftButton.BackColor = Color.Red;
        _topLeftButton.Font = new Font("Microsoft Sans Serif", 9F, FontStyle.Bold);


        // Add the button to the form
        Controls.Add(_topLeftButton);

        var style = GetWindowLong(Handle, WindowLongFlags.GWL_EXSTYLE);
        SetWindowLong(Handle, WindowLongFlags.GWL_EXSTYLE,
            style | 0x80000 | 0x8000000); // WS_EX_LAYERED | WS_EX_NOACTIVATE

        // Define the attribute and the value to set
        /*var attribute = DwmApi.DWMWINDOWATTRIBUTE.DWMWA_EXCLUDED_FROM_PEEK;
        var value = 1; // 1 to enable exclusion, 0 to disable

        // Apply the attribute to the window
        DwmApi.DwmSetWindowAttribute(Handle, attribute, Marshal.UnsafeAddrOfPinnedArrayElement(new[] { value }, 0),
            sizeof(int));*/
    }

    private void InitializeComponent()
    {
        components = new Container();
        _updatetimer = new Timer(components);
        SuspendLayout();
        // 
        // Updatetimer
        // 
        _updatetimer.Enabled = true;
        _updatetimer.Interval = 1000;
        _updatetimer.Tick += Updatetimer_Tick;
        // 
        // OverlayForm
        // 
        ClientSize = new Size(284, 261);
        Name = "OverlayForm";
        ResumeLayout(false);
    }

    private void TopLeftButton_Click(object sender, EventArgs e)
    {
        if (Beallitasok.FullScreenmenuOpened)
        {
            Beallitasok.FullscreenMenu?.Close();
            return;
        }

        if (Beallitasok.FullscreenMenu == null || Beallitasok.FullscreenMenu.IsDisposed)
            Beallitasok.FullscreenMenu = new FullScreenMenu();
        Beallitasok.FullscreenMenu.Show();
    }

    private void Updatetimer_Tick(object sender, EventArgs e)
    {
        if (Beallitasok.FullScreenApplicationRunning)
        {
            //BlockMiddleClick.DeactivateHook();
            if (Beallitasok.GyorsmenüSection["Bekapcsolva"].BoolValue)
                MouseButtonPress.DeactivateMouseHook();
            if (Beallitasok.ÁtfedésSection["Bekapcsolva"].BoolValue)
            {
                if (IsCursorNearTopLeft())
                    Beallitasok.Overlay.Show(); //User32.ShowWindow(this.Handle, ShowWindowCommand.SW_SHOW);
                else if (Beallitasok.NotificationEnabled)
                    Beallitasok.Overlay.Show();
                else
                    Beallitasok.Overlay?.Hide();
                Beallitasok.QuickMenu?.Close();
            }
        }
        else
        {
            //BlockMiddleClick.ActivateHook();
            if (Beallitasok.GyorsmenüSection["Bekapcsolva"].BoolValue)
                MouseButtonPress.ActivateMouseHook();
            if (Beallitasok.ÁtfedésSection["Bekapcsolva"].BoolValue) Beallitasok.FullscreenMenu?.Close();
        }

        if (Beallitasok.NotificationEnabled)
        {
            if ((Beallitasok.NextNotificationDate - DateTime.Now).Minutes < 10)
                _topLeftButton.Text = (Beallitasok.NextNotificationDate - DateTime.Now).Minutes.ToString();
            else
                _topLeftButton.Text = "X";
        }
        else
        {
            _topLeftButton.Text = "X";
        }
    }

    public static bool IsCursorNearTopLeft(int threshold = 40)
    {
        // Get the handle of the currently focused window
        var foregroundWindow = GetForegroundWindow();

        // Convert HWND to IntPtr if needed
        var foregroundWindowPtr = (IntPtr)foregroundWindow;

        // Check if the current window is the desktop or if it's invalid
        if (foregroundWindowPtr == IntPtr.Zero)
            return false;

        // Get the cursor position in screen coordinates
        if (GetCursorPos(out var screenCursorPosition))
            // Convert screen coordinates to client coordinates for the window
            if (ScreenToClient(foregroundWindowPtr, ref screenCursorPosition))
            {
                // Get the DPI scaling factor if necessary
                var dpiScale = GetDpiScaling(foregroundWindowPtr);

                // Scale threshold by DPI factor
                var scaledThreshold = (int)(threshold * dpiScale);

                // Check if the cursor is within the threshold distance from the top-left corner (0, 0)
                return screenCursorPosition.x <= scaledThreshold && screenCursorPosition.y <= scaledThreshold;
            }

        return false;
    }

    // Helper function to get DPI scaling factor
    private static float GetDpiScaling(IntPtr windowHandle)
    {
        // Obtain the DPI for the window and cast to int if needed
        var dpi = (int)GetDpiForWindow(windowHandle);

        return dpi / Beallitasok.BaseDpi;
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            if (_updatetimer != null)
            {
                _updatetimer.Stop();
                _updatetimer.Tick -= Updatetimer_Tick;
                _updatetimer.Dispose();
                _updatetimer = null;
            }

            if (_topLeftButton != null)
            {
                _topLeftButton.Click -= TopLeftButton_Click;
                _topLeftButton.Dispose();
                _topLeftButton = null;
            }

            if (components != null)
            {
                components.Dispose();
                components = null;
            }
        }

        base.Dispose(disposing);
    }
}