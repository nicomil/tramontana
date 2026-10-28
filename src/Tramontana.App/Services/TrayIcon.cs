using System.Runtime.InteropServices;

namespace Tramontana.App.Services;

/// <summary>
/// Notification area icon with a native menu, attached to the main window
/// through a window subclass. The tooltip shows live CPU, memory and disk.
/// </summary>
public sealed unsafe partial class TrayIcon : IDisposable
{
    private const int WM_APP_TRAY = 0x8000 + 17;
    private const int WM_LBUTTONUP = 0x0202, WM_RBUTTONUP = 0x0205, WM_CONTEXTMENU = 0x007B, WM_COMMAND = 0x0111;
    private const uint NIM_ADD = 0, NIM_MODIFY = 1, NIM_DELETE = 2, NIM_SETVERSION = 4;
    private const uint NIF_MESSAGE = 1, NIF_ICON = 2, NIF_TIP = 4, NIF_SHOWTIP = 0x80;
    private const int NOTIFYICON_VERSION_4 = 4;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct NOTIFYICONDATAW
    {
        public uint cbSize;
        public IntPtr hWnd;
        public uint uID;
        public uint uFlags;
        public uint uCallbackMessage;
        public IntPtr hIcon;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)] public string szTip;
        public uint dwState, dwStateMask;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)] public string szInfo;
        public uint uVersion;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)] public string szInfoTitle;
        public uint dwInfoFlags;
        public Guid guidItem;
        public IntPtr hBalloonIcon;
    }

    [DllImport("shell32.dll", CharSet = CharSet.Unicode)] private static extern bool Shell_NotifyIconW(uint message, ref NOTIFYICONDATAW data);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern IntPtr LoadImageW(IntPtr instance, string name, uint type, int cx, int cy, uint load);
    [DllImport("user32.dll")] private static extern bool DestroyIcon(IntPtr icon);
    [DllImport("user32.dll")] private static extern IntPtr CreatePopupMenu();
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern bool AppendMenuW(IntPtr menu, uint flags, nuint id, string? text);
    [DllImport("user32.dll")] private static extern int TrackPopupMenuEx(IntPtr menu, uint flags, int x, int y, IntPtr hwnd, IntPtr tpm);
    [DllImport("user32.dll")] private static extern bool DestroyMenu(IntPtr menu);
    [DllImport("user32.dll")] private static extern bool GetCursorPos(out POINT point);
    [DllImport("user32.dll")] private static extern bool SetForegroundWindow(IntPtr hwnd);
    [DllImport("comctl32.dll")] private static extern bool SetWindowSubclass(IntPtr hwnd, delegate* unmanaged<IntPtr, uint, nint, nint, nuint, nuint, nint> proc, nuint id, nuint data);
    [DllImport("comctl32.dll")] private static extern bool RemoveWindowSubclass(IntPtr hwnd, delegate* unmanaged<IntPtr, uint, nint, nint, nuint, nuint, nint> proc, nuint id);
    [DllImport("comctl32.dll")] private static extern nint DefSubclassProc(IntPtr hwnd, uint message, nint wParam, nint lParam);

    [StructLayout(LayoutKind.Sequential)] private struct POINT { public int X, Y; }

    private static TrayIcon? _instance;
    private readonly IntPtr _hwnd;
    private readonly IntPtr _icon;
    private readonly List<(string Text, Action Action)> _menu;
    private readonly Action _onClick;
    private bool _added;

    public TrayIcon(IntPtr hwnd, string iconPath, Action onClick, List<(string Text, Action Action)> menu)
    {
        _hwnd = hwnd;
        _onClick = onClick;
        _menu = menu;
        _icon = LoadImageW(IntPtr.Zero, iconPath, 1 /* IMAGE_ICON */, 16, 16, 0x10 /* LR_LOADFROMFILE */);
        _instance = this;
        SetWindowSubclass(hwnd, &WindowProc, 1, 0);
        var data = Data(NIF_MESSAGE | NIF_ICON | NIF_TIP | NIF_SHOWTIP, "Tramontana");
        _added = Shell_NotifyIconW(NIM_ADD, ref data);
        data.uVersion = NOTIFYICON_VERSION_4;
        Shell_NotifyIconW(NIM_SETVERSION, ref data);
    }

    private NOTIFYICONDATAW Data(uint flags, string tip) => new()
    {
        cbSize = (uint)Marshal.SizeOf<NOTIFYICONDATAW>(),
        hWnd = _hwnd,
        uID = 1,
        uFlags = flags,
        uCallbackMessage = WM_APP_TRAY,
        hIcon = _icon,
        szTip = tip.Length > 127 ? tip[..127] : tip,
        szInfo = "",
        szInfoTitle = "",
    };

    public void SetTooltip(string text)
    {
        if (!_added) return;
        var data = Data(NIF_TIP | NIF_SHOWTIP, text);
        Shell_NotifyIconW(NIM_MODIFY, ref data);
    }

    [UnmanagedCallersOnly]
    private static nint WindowProc(IntPtr hwnd, uint message, nint wParam, nint lParam, nuint id, nuint data)
    {
        var self = _instance;
        if (self is not null && message == WM_APP_TRAY)
        {
            int ev = (int)(lParam & 0xFFFF);
            if (ev == WM_LBUTTONUP) self._onClick();
            else if (ev is WM_RBUTTONUP or WM_CONTEXTMENU) self.ShowMenu();
            return 0;
        }
        return DefSubclassProc(hwnd, message, wParam, lParam);
    }

    private void ShowMenu()
    {
        IntPtr menu = CreatePopupMenu();
        for (int i = 0; i < _menu.Count; i++)
        {
            if (_menu[i].Text == "-") AppendMenuW(menu, 0x800 /* MF_SEPARATOR */, 0, null);
            else AppendMenuW(menu, 0, (nuint)(i + 1), _menu[i].Text);
        }
        GetCursorPos(out var point);
        SetForegroundWindow(_hwnd);
        int chosen = TrackPopupMenuEx(menu, 0x0100 /* TPM_RETURNCMD */ | 0x0020 /* TPM_RIGHTBUTTON */, point.X, point.Y, _hwnd, IntPtr.Zero);
        DestroyMenu(menu);
        if (chosen > 0 && chosen <= _menu.Count) _menu[chosen - 1].Action();
    }

    public void Dispose()
    {
        if (_added)
        {
            var data = Data(0, "");
            Shell_NotifyIconW(NIM_DELETE, ref data);
            _added = false;
        }
        RemoveWindowSubclass(_hwnd, &WindowProc, 1);
        if (_icon != IntPtr.Zero) DestroyIcon(_icon);
        _instance = null;
    }
}
