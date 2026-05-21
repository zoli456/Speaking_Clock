using System.Diagnostics;
using Telerik.WinControls.UI;
using Vanara.PInvoke;
using static Vanara.PInvoke.User32;

namespace Speaking_Clock;

internal partial class QuickMenu : RadForm
{
    private static readonly HWND HwndTopmost = new(new IntPtr(-1));

    private readonly SetWindowPosFlags TopmostFlags = /*User32.SetWindowPosFlags.SWP_NOMOVE |
                                                             User32.SetWindowPosFlags.SWP_NOSIZE |*/
        SetWindowPosFlags.SWP_SHOWWINDOW;

    private bool mouseIsOutsideForm;

    public QuickMenu()
    {
        InitializeComponent();
        // Set the extended window style to WS_EX_NOACTIVATE for click-through without focus change
        var exStyle = GetWindowLong(Handle, WindowLongFlags.GWL_EXSTYLE);
        exStyle |= (int)WindowStylesEx.WS_EX_NOACTIVATE; // Prevent focus on click
        SetWindowLong(Handle, WindowLongFlags.GWL_EXSTYLE, (IntPtr)exStyle);

        // Keep the form always on top
        SetWindowPos(Handle, HwndTopmost, 0, 0, 0, 0,
            SetWindowPosFlags.SWP_NOMOVE | SetWindowPosFlags.SWP_NOSIZE);

        for (var i = 0; i < Beallitasok.RadioNames.Count; i++)
        {
            var index = i;
            var radApplicationMenuItem = new RadMenuItem { Text = Beallitasok.RadioNames[index] };
            radApplicationMenuItem.Click += (sender, e) =>
            {
                Beallitasok.StartRadio(Beallitasok.RandioUrLs[index], Beallitasok.RadioNames[index]);
                Close();
            };
            radApplicationMenu1.Items.Add(radApplicationMenuItem);
        }

        for (var i = 0; i < Beallitasok.warningTimes.Length; i++)
        {
            var index = i;
            var subMenuItem = new RadMenuItem { Text = $"{Beallitasok.warningTimes[index]} perc múlva" };
            subMenuItem.Click += (sender, e) =>
            {
                var clickedItem = sender as RadMenuItem;
                if (!subMenuItem.IsChecked)
                {
                    Beallitasok.DisableCustomNotification();
                    Beallitasok.SetWarningTime(Beallitasok.warningTimes[index]);
                    Debug.WriteLine($"Set a notification in {Beallitasok.warningTimes[index]} minutes.");
                    // Cast the sender to ToolStripMenuItem
                    if (clickedItem != null && clickedItem.Owner != null)
                        // Iterate through all the items in the same menu
                        for (var i = 0; i < radApplicationMenu2.Items.Count; i++)
                            if (radApplicationMenu2.Items[i] is RadMenuItem menuItem)
                            {
                                // Check all items except the clicked one
                                menuItem.IsChecked = menuItem == clickedItem;
                                (Beallitasok._warnings.DropDownItems[i] as ToolStripMenuItem).Checked =
                                    menuItem == clickedItem;
                            }
                }
                else
                {
                    (Beallitasok._warnings.DropDownItems[index] as ToolStripMenuItem).Checked =
                        false;
                    subMenuItem.IsChecked = false;
                    Beallitasok.DisableCustomNotification();
                }

                Close();
            };
            radApplicationMenu2.Items.Add(subMenuItem);
        }

        var CustomsubMenuItem = new RadMenuItem { Text = "Egyedi..." };
        CustomsubMenuItem.Click += (sender, e) =>
        {
            if (CustomsubMenuItem.IsChecked)
            {
                Beallitasok.DisableCustomNotification();
            }
            else
            {
                Beallitasok.CustomWarningForm = new CustomWarningForm();
                Beallitasok.CustomWarningForm.Show();
            }

            Close();
        };
        radApplicationMenu2.Items.Add(CustomsubMenuItem);
    }

    protected override bool ShowWithoutActivation => true;

    /* protected override void OnHandleCreated(EventArgs e)
     {
         base.OnHandleCreated(e);

         // Get current window extended style as an integer, then cast to WindowStylesEx
         var exStyle = (User32.WindowStylesEx)User32.GetWindowLong(Handle, User32.WindowLongFlags.GWL_EXSTYLE);

         // Modify the style to add no-activate, topmost, and tool window attributes
         exStyle |= User32.WindowStylesEx.WS_EX_NOACTIVATE;
         exStyle |= User32.WindowStylesEx.WS_EX_TOPMOST;
         exStyle |= User32.WindowStylesEx.WS_EX_TOOLWINDOW;

         // Set the new extended window style
         User32.SetWindowLong(Handle, User32.WindowLongFlags.GWL_EXSTYLE, (int)exStyle);
     }*/

    protected override CreateParams CreateParams
    {
        get
        {
            var pm = base.CreateParams;
            pm.ExStyle |=
                (int)(WindowStylesEx.WS_EX_TOPMOST |
                      WindowStylesEx.WS_EX_NOACTIVATE | WindowStylesEx.WS_EX_TOOLWINDOW);
            return pm;
        }
    }

    private void radButton2_Click(object? sender, EventArgs e)
    {
        Beallitasok.AnnounceWeather();
        Close();
    }

    private void QuickMenu_Shown(object? sender, EventArgs e)
    {
        for (var i = 0; i < Beallitasok._warnings.DropDownItems.Count; i++)
            if (Beallitasok._warnings.DropDownItems[i] is ToolStripMenuItem menuItem)
                if (menuItem.Checked)
                {
                    var radMenuItem = radApplicationMenu2.Items[i] as RadMenuItem;
                    radMenuItem.IsChecked = true;
                    if (i == Beallitasok._warnings.DropDownItems.Count - 1)
                        radMenuItem.Text = Beallitasok._warnings
                            .DropDownItems[Beallitasok._warnings.DropDownItems.Count - 1].Text;
                }
    }

    private void radButton1_Click(object? sender, EventArgs e)
    {
        if (Beallitasok.Virtualkeyboard == null || Beallitasok.Virtualkeyboard.IsDisposed)
            Beallitasok.Virtualkeyboard = new VirtualKeyboard();
        Beallitasok.Virtualkeyboard.radCheckBox1.Checked = Beallitasok.GyorsmenüSection["Billentyűzet_Grey"].BoolValue;
        if (Beallitasok.GyorsmenüSection["Billentyűzet_Grey"].BoolValue)
            Beallitasok.Virtualkeyboard.ThemeName = "Fluent";
        Beallitasok.Virtualkeyboard.StartPosition = FormStartPosition.Manual;
        Beallitasok.Virtualkeyboard.Top = Beallitasok.GyorsmenüSection["Billentyűzet_PosX"].IntValue;
        Beallitasok.Virtualkeyboard.Left = Beallitasok.GyorsmenüSection["Billentyűzet_PosY"].IntValue;
        Beallitasok.Virtualkeyboard.Show();
        Close();
    }

    private void radButton3_Click(object? sender, EventArgs e)
    {
        var calculatorProcess = Process.GetProcessesByName("Számológép").FirstOrDefault();

        if (calculatorProcess == null)
            Process.Start("calc.exe");
        else
            return;
        Close();
    }

    private void radButton6_Click(object? sender, EventArgs e)
    {
        Debug.WriteLine("Böngésző megnyitás");
        var browserProcess = Process.Start(Utils.GetDefaultBrowser());
        browserProcess.WaitForInputIdle();
        var hWnd = new HWND(browserProcess.MainWindowHandle);
        SetForegroundWindow(hWnd);
        SetWindowPos(hWnd, HwndTopmost, 0, 0, 0, 0, TopmostFlags);
        Close();
    }

    private void radButton4_Click(object? sender, EventArgs e)
    {
        Beallitasok.AnnounceNameDay();
        Close();
    }

    private void radButton5_Click(object? sender, EventArgs e)
    {
        Beallitasok.AnnounceForecast();
        Close();
    }

    // Optionally handle system key interference
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

         // Prevent ALT+TAB, WINKEY, etc., from affecting the fullscreen app
         /* if (m.Msg == (int)User32.WindowMessage.WM_SYSKEYDOWN || m.Msg == (int)User32.WindowMessage.WM_KEYDOWN) return;
          base.WndProc(ref m);*/
    //}

    private void QuickMenu_MouseLeave(object sender, EventArgs e)
    {
        var mousePosition = PointToClient(Cursor.Position);
        if (mousePosition.X < 0 || mousePosition.Y < 0 ||
            mousePosition.X > ClientSize.Width || mousePosition.Y > ClientSize.Height)
        {
            mouseIsOutsideForm = true;
            Close();
        }
    }

    private void QuickMenu_MouseEnter(object sender, EventArgs e)
    {
        mouseIsOutsideForm = false;
    }
}