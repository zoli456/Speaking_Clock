using System.Diagnostics;
using System.Drawing.Imaging;
using Speaking_clock.Overlay;
using Vanara.PInvoke;

namespace Speaking_Clock;

public class ScreenCapture
{
    [Flags]
    public enum PrintWindowFlags : uint
    {
        PwClientonly = 0x00000001, // Only client area
        PwRenderfullcontent = 0x00000002 // Entire window content
    }

    /// <summary>
    ///     Captures the screen or active window and saves it to a file.
    /// </summary>
    /// <param name="captureActiveWindow"></param>
    public static void CaptureScreen(bool captureActiveWindow)
    {
        if (Beallitasok.OverlayMode != "EXTERNAL" && Beallitasok.OverlayMode != "")
        {
            OverlayMessenger.SendRequestScreenshootAsync();
            return;
        }

        int width, height;
        Point topLeft;
        User32.SafeReleaseHDC hdcSrc;
        Gdi32.SafeHDC hdcMemory;
        Gdi32.SafeHBITMAP hBitmap;

        if (captureActiveWindow)
        {
            // Get active window handle and dimensions
            var activeWindow = User32.GetForegroundWindow();
            User32.GetWindowRect(activeWindow, out var windowRect);

            // Set dimensions for active window capture
            width = windowRect.right - windowRect.left;
            height = windowRect.bottom - windowRect.top;
            topLeft = new Point(windowRect.left, windowRect.top);

            // Capture the active window
            hdcSrc = User32.GetDC(IntPtr.Zero);
            hdcMemory = Gdi32.CreateCompatibleDC(hdcSrc);
            hBitmap = Gdi32.CreateCompatibleBitmap(hdcSrc, width, height);

            var hOldBitmap = Gdi32.SelectObject(hdcMemory, hBitmap);
            User32.PrintWindow(activeWindow, hdcMemory, (User32.PW)PrintWindowFlags.PwRenderfullcontent);
            Gdi32.SelectObject(hdcMemory, hOldBitmap);
        }
        else
        {
            // Capture the entire screen
            width = Screen.PrimaryScreen.Bounds.Width;
            height = Screen.PrimaryScreen.Bounds.Height;
            topLeft = new Point(0, 0);

            // Get device context and perform screen capture
            hdcSrc = User32.GetDC(IntPtr.Zero);
            hdcMemory = Gdi32.CreateCompatibleDC(hdcSrc);
            hBitmap = Gdi32.CreateCompatibleBitmap(hdcSrc, width, height);

            var hOldBitmap = Gdi32.SelectObject(hdcMemory, hBitmap);
            Gdi32.BitBlt(hdcMemory, 0, 0, width, height, hdcSrc, topLeft.X, topLeft.Y,
                Gdi32.RasterOperationMode.SRCCOPY);
            Gdi32.SelectObject(hdcMemory, hOldBitmap);
        }

        // Save the captured image
        SaveBitmap(hBitmap, Utils.GetOrCreateSpeakingClockPath());

        // Release resources
        Gdi32.DeleteDC(hdcMemory);
        User32.ReleaseDC(IntPtr.Zero, hdcSrc);
    }

    /// <summary>
    ///     Saves the captured bitmap to a file.
    /// </summary>
    /// <param name="hBitmap"></param>
    /// <param name="filePath"></param>
    internal static void SaveBitmap(Gdi32.SafeHBITMAP hBitmap, string filePath)
    {
        Debug.WriteLine($"Writing bitmap to {filePath}");
        using var bitmap = Image.FromHbitmap(hBitmap.DangerousGetHandle());
        var watermark = Beallitasok.ScreenCaptureSection["Vízjel"].StringValue.Trim();

        if (!string.IsNullOrEmpty(watermark))
        {
            using var watermarkedImage = Utils.AddWatermark(bitmap, watermark);
            watermarkedImage.Save(filePath, ImageFormat.Png);
        }
        else
        {
            bitmap.Save(filePath, ImageFormat.Png);
        }
    }

    internal static void SaveBitmap(byte[] imageBytes, string filePath)
    {
        Debug.WriteLine($"Writing bytes to {filePath}");
        using var ms = new MemoryStream(imageBytes);
        using var bitmap = new Bitmap(ms);

        var watermark = Beallitasok.ScreenCaptureSection["Vízjel"].StringValue.Trim();

        if (!string.IsNullOrEmpty(watermark))
        {
            using var watermarkedImage = Utils.AddWatermark(bitmap, watermark);
            watermarkedImage.Save(filePath, ImageFormat.Png);
        }
        else
        {
            bitmap.Save(filePath, ImageFormat.Png);
        }
    }
}