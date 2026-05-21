using Telerik.WinControls.UI;
using static Vanara.PInvoke.User32;

namespace Speaking_Clock;

public partial class FullScreenMenu : RadForm
{
    public FullScreenMenu()
    {
        InitializeComponent();
        // Define the attribute and the value to set
        // var attribute = DwmApi.DWMWINDOWATTRIBUTE.DWMWA_EXCLUDED_FROM_PEEK;
        //var value = 1; // 1 to enable exclusion, 0 to disable

        SetWindowPos(Handle,
            (IntPtr)SpecialWindowHandles.HWND_TOPMOST,
            0, 0, 0, 0,
            SetWindowPosFlags.SWP_NOMOVE |
            SetWindowPosFlags.SWP_NOSIZE |
            SetWindowPosFlags.SWP_NOACTIVATE /*|
            SetWindowPosFlags.SWP_NOZORDER*/);

        // Apply the attribute to the window
        /*  DwmApi.DwmSetWindowAttribute(Handle, attribute, Marshal.UnsafeAddrOfPinnedArrayElement(new[] { value }, 0),
              sizeof(int));*/
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
     { static readonly int waInactive = 0;
         if (m.Msg == (int)WindowMessage.WM_MOUSEACTIVATE)
         {
             m.Result = (IntPtr)WindowMessage.WM_NCACTIVATE;
             return;
         }

         if (m.Msg == (int)WindowMessage.WM_ACTIVATE)
         {
             if (((int)m.WParam & 0xFFFF) != waInactive)
             {
                 if (m.LParam != IntPtr.Zero)
                     SetActiveWindow(m.LParam);
                 else
                     SetActiveWindow(IntPtr.Zero);
             }
         }
         base.WndProc(ref m);
     }*/

    private void radButton1_Click(object sender, EventArgs e)
    {
        if (radListControl1.SelectedIndex != -1)
        {
            if (radListControl1.SelectedIndex == Beallitasok.warningTimes.Length)
            {
                Beallitasok.DisableCustomNotification();
            }
            else
            {
                Beallitasok.DisableCustomNotification();
                for (var i = 0; i < Beallitasok.warningTimes.Length; i++)
                    (Beallitasok._warnings.DropDownItems[i] as ToolStripMenuItem).Checked =
                        radListControl1.SelectedIndex == i;

                Beallitasok.SetWarningTime(Beallitasok.warningTimes[radListControl1.SelectedIndex]);
            }
        }

        Beallitasok.Overlay?.Show();
        Close();
    }

    private void FullScreenMenu_Shown(object sender, EventArgs e)
    {
        radLabel2.Text = $"Jelenlegi idő: {DateTime.Now:H:mm}";
        Beallitasok.FullScreenmenuOpened = true;
        for (var i = 0; i < Beallitasok.warningTimes.Length; i++)
            radListControl1.Items.Add($"{Beallitasok.warningTimes[i]} perc múlva");
        radListControl1.Items.Add("Kikapcsolás");
    }

    private void FullScreenMenu_FormClosed(object sender, FormClosedEventArgs e)
    {
        Beallitasok.FullScreenmenuOpened = false;
    }

    private void FullScreenMenu_FormClosing(object sender, FormClosingEventArgs e)
    {
        Beallitasok.FullScreenmenuOpened = false;
    }

    private void timeUpdater_Tick(object sender, EventArgs e)
    {
        radLabel2.Text = $"Jelenlegi idő: {DateTime.Now:H:mm}";
    }

    private void AutoClosetimer_Tick(object sender, EventArgs e)
    {
        Close();
    }
}