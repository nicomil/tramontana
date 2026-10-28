using System.Net;
using System.Runtime.InteropServices;

namespace Tramontana.Modules.Protection.Processes;

/// <summary>One TCP or UDP endpoint of a process.</summary>
public sealed record Connection(int Pid, string Protocol, IPAddress Local, int LocalPort, IPAddress? Remote, int RemotePort, string State)
{
    public bool IsListening => State == "LISTEN" || (Protocol == "UDP" && Remote is null);
    public bool ListensOnAllInterfaces => IsListening && (Local.Equals(IPAddress.Any) || Local.Equals(IPAddress.IPv6Any));
    public bool IsEstablished => State == "ESTABLISHED";
}

public interface IConnectionSource
{
    IReadOnlyList<Connection> List();
}

public sealed class FakeConnections(params Connection[] connections) : IConnectionSource
{
    public IReadOnlyList<Connection> List() => connections;
}

/// <summary>The TCP and UDP tables with owning PIDs (no privileges needed).</summary>
public sealed partial class SystemConnections : IConnectionSource
{
    private static readonly string[] TcpStates = ["", "CLOSED", "LISTEN", "SYN_SENT", "SYN_RCVD", "ESTABLISHED", "FIN_WAIT1", "FIN_WAIT2", "CLOSE_WAIT", "CLOSING", "LAST_ACK", "TIME_WAIT", "DELETE_TCB"];

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_TCPROW_OWNER_PID { public uint State, LocalAddr, LocalPort, RemoteAddr, RemotePort, OwningPid; }

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_UDPROW_OWNER_PID { public uint LocalAddr, LocalPort, OwningPid; }

    [LibraryImport("iphlpapi.dll")]
    private static partial uint GetExtendedTcpTable(IntPtr table, ref int size, [MarshalAs(UnmanagedType.Bool)] bool order, int family, int tableClass, uint reserved);

    [LibraryImport("iphlpapi.dll")]
    private static partial uint GetExtendedUdpTable(IntPtr table, ref int size, [MarshalAs(UnmanagedType.Bool)] bool order, int family, int tableClass, uint reserved);

    public IReadOnlyList<Connection> List()
    {
        var list = new List<Connection>();
        const int AfInet = 2, TcpTableOwnerPidAll = 5, UdpTableOwnerPid = 1;
        int size = 0;
        GetExtendedTcpTable(IntPtr.Zero, ref size, false, AfInet, TcpTableOwnerPidAll, 0);
        IntPtr buffer = Marshal.AllocHGlobal(size);
        try
        {
            if (GetExtendedTcpTable(buffer, ref size, false, AfInet, TcpTableOwnerPidAll, 0) == 0)
            {
                int count = Marshal.ReadInt32(buffer);
                IntPtr row = buffer + 4;
                int rowSize = Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();
                for (int i = 0; i < count; i++, row += rowSize)
                {
                    var r = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(row);
                    string state = r.State < TcpStates.Length ? TcpStates[r.State] : r.State.ToString();
                    var remote = state == "LISTEN" ? null : new IPAddress(r.RemoteAddr);
                    list.Add(new Connection((int)r.OwningPid, "TCP", new IPAddress(r.LocalAddr), Port(r.LocalPort), remote, remote is null ? 0 : Port(r.RemotePort), state));
                }
            }
        }
        finally { Marshal.FreeHGlobal(buffer); }

        size = 0;
        GetExtendedUdpTable(IntPtr.Zero, ref size, false, AfInet, UdpTableOwnerPid, 0);
        buffer = Marshal.AllocHGlobal(size);
        try
        {
            if (GetExtendedUdpTable(buffer, ref size, false, AfInet, UdpTableOwnerPid, 0) == 0)
            {
                int count = Marshal.ReadInt32(buffer);
                IntPtr row = buffer + 4;
                int rowSize = Marshal.SizeOf<MIB_UDPROW_OWNER_PID>();
                for (int i = 0; i < count; i++, row += rowSize)
                {
                    var r = Marshal.PtrToStructure<MIB_UDPROW_OWNER_PID>(row);
                    list.Add(new Connection((int)r.OwningPid, "UDP", new IPAddress(r.LocalAddr), Port(r.LocalPort), null, 0, ""));
                }
            }
        }
        finally { Marshal.FreeHGlobal(buffer); }
        return list;
    }

    private static int Port(uint networkOrder) => (int)(((networkOrder & 0xFF) << 8) | ((networkOrder >> 8) & 0xFF));
}
