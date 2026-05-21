using System.Diagnostics;
using Vanara.PInvoke;
using Vortice.DCommon;
using Vortice.Direct2D1;
using Vortice.Direct3D;
using Vortice.Direct3D11;
using Vortice.DirectComposition;
using Vortice.DirectWrite;
using Vortice.DXGI;
using Vortice.Mathematics;
using Vortice.WinForms;
using AlphaMode = Vortice.DCommon.AlphaMode;
using FeatureLevel = Vortice.Direct3D.FeatureLevel;
using Size = System.Drawing.Size;

namespace Speaking_clock.Widgets;

public abstract class CompositionWidgetBase : RenderForm
{
    // Composition Objects
    protected IDCompositionDevice _compositionDevice;
    protected IDCompositionTarget _compositionTarget;
    protected ID2D1DeviceContext _d2dContext;
    protected ID2D1Device _d2dDevice;
    protected ID2D1Factory1 _d2dFactory;

    protected ID3D11DeviceContext _d3dContext;

    // Core DirectX Objects
    protected ID3D11Device1 _d3dDevice;
    private bool _directXInitialized;
    private Point _dragStartPoint;

    // Global Resources
    protected IDWriteFactory _dwriteFactory;

    // Logic
    internal bool _isDragging;
    protected IDCompositionVisual _rootVisual;
    protected float _scale = 1.0f;
    protected IDXGISwapChain1 _swapChain;

    public CompositionWidgetBase(int startX, int startY, int width, int height)
    {
        // Basic Form Setup
        FormBorderStyle = FormBorderStyle.None;
        StartPosition = FormStartPosition.Manual;
        Location = new Point(startX, startY);
        ClientSize = new Size(width, height);
        ShowInTaskbar = false;

        // Initialize Factories
        _d2dFactory = GraphicsFactories.D2DFactory
                      ?? throw new InvalidOperationException("D2D Factory is not ID2D1Factory1 compatible");
        _dwriteFactory = GraphicsFactories.DWriteFactory;

        // Drag Events
        MouseDown += OnBaseMouseDown;
        MouseMove += OnBaseMouseMove;
        MouseUp += OnBaseMouseUp;
        Show();
    }

    protected override CreateParams CreateParams
    {
        get
        {
            var cp = base.CreateParams;
            // WS_EX_TOOLWINDOW: Hides from Alt-Tab
            // WS_EX_NOREDIRECTIONBITMAP (0x00200000): Tells Windows not to allocate a GDI bitmap.
            // WS_EX_LAYERED to prevent conflict with DirectComposition alpha handling.
            cp.ExStyle |= (int)User32.WindowStylesEx.WS_EX_TOOLWINDOW |
                          (int)User32.WindowStylesEx.WS_EX_NOREDIRECTIONBITMAP;
            return cp;
        }
    }

    protected override void OnHandleCreated(EventArgs e)
    {
        base.OnHandleCreated(e);
        if (!_directXInitialized)
        {
            InitializeDirectX();
            _directXInitialized = true;
        }
    }

    private void InitializeDirectX()
    {
        // Create D3D11 Device
        ID3D11Device tempDevice;
        D3D11.D3D11CreateDevice(
            null,
            DriverType.Hardware,
            DeviceCreationFlags.BgraSupport,
            new[] { FeatureLevel.Level_10_0, FeatureLevel.Level_11_0 },
            out tempDevice
        ).CheckError();

        _d3dDevice = tempDevice.QueryInterface<ID3D11Device1>();
        _d3dContext = _d3dDevice.ImmediateContext;
        tempDevice.Dispose();

        // Create DXGI Objects
        using var dxgiDevice = _d3dDevice.QueryInterface<IDXGIDevice>();

        // Create D2D Device
        _d2dDevice = _d2dFactory.CreateDevice(dxgiDevice);
        _d2dContext = _d2dDevice.CreateDeviceContext(DeviceContextOptions.None);

        // Create Swap Chain
        using var dxgiAdapter = dxgiDevice.GetAdapter();
        using var dxgiFactory = dxgiAdapter.GetParent<IDXGIFactory2>();

        var swapChainDesc = new SwapChainDescription1
        {
            Width = (uint)ClientSize.Width,
            Height = (uint)ClientSize.Height,
            Format = Format.B8G8R8A8_UNorm,
            Stereo = false,
            SampleDescription = new SampleDescription(1, 0),
            BufferUsage = Usage.RenderTargetOutput | Usage.Backbuffer,
            BufferCount = 2,
            Scaling = Scaling.Stretch,
            SwapEffect = SwapEffect.FlipSequential,
            AlphaMode = Vortice.DXGI.AlphaMode.Premultiplied
        };

        _swapChain = dxgiFactory.CreateSwapChainForComposition(_d3dDevice, swapChainDesc);

        //  Link SwapChain to D2D Context
        CreateBitmapTarget();

        // Init DirectComposition
        DComp.DCompositionCreateDevice(dxgiDevice, out _compositionDevice);

        _compositionDevice.CreateTargetForHwnd(Handle, true, out _compositionTarget);

        _rootVisual = _compositionDevice.CreateVisual();
        _rootVisual.SetContent(_swapChain);
        _compositionTarget.SetRoot(_rootVisual);
        _compositionDevice.Commit();
    }

    private void CreateBitmapTarget()
    {
        // Get BackBuffer
        using var backBuffer = _swapChain.GetBuffer<IDXGISurface>(0);

        // Create Bitmap properties
        var bitmapProps = new BitmapProperties1(
            new PixelFormat(Format.B8G8R8A8_UNorm, AlphaMode.Premultiplied),
            96, 96,
            BitmapOptions.Target | BitmapOptions.CannotDraw
        );

        // Create Bitmap pointing to the swap chain buffer
        using var targetBitmap = _d2dContext.CreateBitmapFromDxgiSurface(backBuffer, bitmapProps);
        _d2dContext.Target = targetBitmap;
    }

    protected override void OnResize(EventArgs e)
    {
        base.OnResize(e);

        if (_swapChain != null && ClientSize.Width > 0 && ClientSize.Height > 0)
        {
            // Release reference to backbuffer before resizing
            _d2dContext.Target = null;

            // Resize
            _swapChain.ResizeBuffers(0, (uint)ClientSize.Width, (uint)ClientSize.Height, Format.Unknown,
                SwapChainFlags.None);

            // Re-link
            CreateBitmapTarget();

            // Re-commit composition (sometimes needed if scaling changes)
            _compositionDevice.Commit();

            Invalidate();
        }
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        // Don't call base.OnPaint(e) to avoid GDI interference
        if (_d2dContext == null) return;

        try
        {
            _d2dContext.BeginDraw();
            _d2dContext.Clear(new Color4(0, 0, 0, 0)); // Fully transparent background

            DrawContent(_d2dContext); // Child implementation

            _d2dContext.EndDraw();

            // Present the SwapChain
            _swapChain.Present(1, PresentFlags.None);
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"DirectX Paint Error: {ex.Message}");
            // Re-init could go here if device lost
        }
    }

    protected abstract void DrawContent(ID2D1DeviceContext context);

    protected abstract void SavePosition(int x, int y);

    protected virtual bool CanDrag()
    {
        return true;
    }

    // --- Input Handling ---

    internal void OnBaseMouseDown(object sender, MouseEventArgs e)
    {
        if (e.Button == MouseButtons.Left && CanDrag())
        {
            _isDragging = true;
            _dragStartPoint = e.Location;
        }

        OnChildMouseDown(e); // Passthrough
    }

    internal void OnBaseMouseMove(object sender, MouseEventArgs e)
    {
        if (_isDragging)
        {
            Left += e.X - _dragStartPoint.X;
            Top += e.Y - _dragStartPoint.Y;
        }

        OnChildMouseMove(e); // Passthrough
    }

    internal void OnBaseMouseUp(object sender, MouseEventArgs e)
    {
        if (e.Button == MouseButtons.Left && _isDragging)
        {
            _isDragging = false;
            SavePosition(Left, Top);
        }

        OnChildMouseUp(e); // Passthrough
    }

    protected virtual void OnChildMouseDown(MouseEventArgs e)
    {
    }

    protected virtual void OnChildMouseMove(MouseEventArgs e)
    {
    }

    protected virtual void OnChildMouseUp(MouseEventArgs e)
    {
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            // Dispose Composition
            _rootVisual?.Dispose();
            _compositionTarget?.Dispose();
            _compositionDevice?.Dispose();

            // Dispose D2D/D3D/DXGI
            if (_d2dContext != null) _d2dContext.Target = null;
            _d2dContext?.Dispose();
            _d2dDevice?.Dispose();
            _swapChain?.Dispose();
            _d3dContext?.Dispose();
            _d3dDevice?.Dispose();
        }

        base.Dispose(disposing);
    }
}