using System.Runtime.InteropServices;
using static Vanara.PInvoke.User32;

namespace Speaking_Clock;

public class NewComboBox : ComboBox
{
    private static readonly int GwlStyle = -16;
    private static readonly int EsLeft = 0x0000;
    private static readonly int EsCenter = 0x0001;
    private static readonly int EsRight = 0x0002;

    public NewComboBox()
    {
        DrawMode = DrawMode.OwnerDrawFixed;
    }

    protected override void OnHandleCreated(EventArgs e)
    {
        base.OnHandleCreated(e);
        SetupEdit();
    }

    private void SetupEdit()
    {
        // Use the Vanara struct for COMBOBOXINFO
        var info = new COMBOBOXINFO();
        info.cbSize = Marshal.SizeOf(info);

        // Get ComboBox info using Vanara's ComboBoxMessage.CB_GETCOMBOBOXINFO
        var result = SendMessage(Handle, ComboBoxMessage.CB_GETCOMBOBOXINFO, IntPtr.Zero, ref info);

        // Check if the result is non-zero (successful)
        if (result != IntPtr.Zero)
        {
            // Retrieve and modify the window style
            var style = GetWindowLong(info.hwndEdit, (WindowLongFlags)GwlStyle);
            style |= 1;
            SetWindowLong(info.hwndEdit, (WindowLongFlags)GwlStyle, style);
        }
    }

    protected override void OnDrawItem(DrawItemEventArgs e)
    {
        base.OnDrawItem(e);
        e.DrawBackground();
        var txt = "";
        if (e.Index >= 0)
            txt = GetItemText(Items[e.Index]);
        TextRenderer.DrawText(e.Graphics, txt, Font, e.Bounds,
            ForeColor, TextFormatFlags.Left | TextFormatFlags.HorizontalCenter);
    }

    private void InitializeComponent()
    {
        SuspendLayout();
        ResumeLayout(false);
    }

    // Use Vanara's RECT structure directly
    public struct Rect
    {
        public int Left;
        public int Top;
        public int Right;
        public int Bottom;

        public int Width => Right - Left;

        public int Height => Bottom - Top;
    }
}