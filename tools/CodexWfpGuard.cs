// Codex-SG 守护层方案 B：WFP 应用级过滤器（自有 provider + 最高权重 sublayer，不碰系统防火墙规则）。
// 每个被守护的 exe 4 条 BLOCK：远端≠127.0.0.1 / 端口≠7899 / 协议≠TCP（IPv4），IPv6 全阻。
// 编译：csc /nologo /platform:x64 /out:tools\CodexWfpGuard.exe tools\CodexWfpGuard.cs
// 用法：sync <exe...>（管理员，整体替换）| list（管理员）| remove-all（管理员）| probe（无需管理员）
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;

internal static class CodexWfpGuard
{
    const ushort Port = 7899;
    static readonly Guid Provider = new Guid("5d0e6a3c-2f7b-4c1e-9a54-7899c0de5501");
    static readonly Guid Sublayer = new Guid("5d0e6a3c-2f7b-4c1e-9a54-7899c0de5502");
    static readonly Guid LayerV4 = new Guid("c38d57d1-05a7-4c33-904f-7fbceee60e82"); // ALE_AUTH_CONNECT_V4
    static readonly Guid LayerV6 = new Guid("4a72393b-319f-44bc-84c3-ba54dcb3b6b4"); // ALE_AUTH_CONNECT_V6
    static readonly Guid CondApp = new Guid("d78e1e87-8644-4ea5-9437-d809ecefc971");
    static readonly Guid CondAddr = new Guid("b235ae9a-1d64-49b8-a44c-5ff3d9095045");
    static readonly Guid CondPort = new Guid("c35a604d-d22b-4e1a-91b4-68f674ee674b");
    static readonly Guid CondProto = new Guid("3971ef2b-623e-4f9a-8cb1-6e79b806b9a7");
    const uint FWP_UINT8 = 1, FWP_UINT16 = 2, FWP_UINT32 = 3, FWP_BYTE_BLOB_TYPE = 12;
    const uint MATCH_EQUAL = 0, MATCH_NOT_EQUAL = 10, ACTION_BLOCK = 0x1001;
    const uint FLAG_PERSISTENT = 1, FILTER_FLAG_CLEAR_ACTION_RIGHT = 8;
    const uint E_ALREADY_EXISTS = 0x80320009, E_PROVIDER_NOT_FOUND = 0x80320005, E_SUBLAYER_NOT_FOUND = 0x80320007;

    [StructLayout(LayoutKind.Explicit, Size = 16)] struct FwpValue { [FieldOffset(0)] public uint type; [FieldOffset(8)] public IntPtr value; }
    [StructLayout(LayoutKind.Sequential)] struct Display { public IntPtr name, description; }
    [StructLayout(LayoutKind.Sequential)] struct Blob { public uint size; public IntPtr data; }
    [StructLayout(LayoutKind.Sequential)] struct Cond { public Guid fieldKey; public uint matchType; public FwpValue value; }
    [StructLayout(LayoutKind.Sequential)] struct FwpAction { public uint type; public Guid filterType; }
    [StructLayout(LayoutKind.Sequential)] struct Ctx { public ulong a, b; }
    [StructLayout(LayoutKind.Sequential)] struct Filter
    {
        public Guid filterKey; public Display displayData; public uint flags; public IntPtr providerKey; public Blob providerData;
        public Guid layerKey; public Guid subLayerKey; public FwpValue weight; public uint numFilterConditions; public IntPtr filterCondition;
        public FwpAction action; public Ctx context; public IntPtr reserved; public ulong filterId; public FwpValue effectiveWeight;
    }
    [StructLayout(LayoutKind.Sequential)] struct ProviderS { public Guid providerKey; public Display displayData; public uint flags; public Blob providerData; public IntPtr serviceName; }
    [StructLayout(LayoutKind.Sequential)] struct SublayerS { public Guid subLayerKey; public Display displayData; public uint flags; public IntPtr providerKey; public Blob providerData; public ushort weight; }

    [DllImport("fwpuclnt.dll")] static extern uint FwpmEngineOpen0(IntPtr server, uint authn, IntPtr ident, IntPtr session, out IntPtr h);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmEngineClose0(IntPtr h);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmTransactionBegin0(IntPtr h, uint flags);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmTransactionCommit0(IntPtr h);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmTransactionAbort0(IntPtr h);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmProviderAdd0(IntPtr h, ref ProviderS p, IntPtr sd);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmSubLayerAdd0(IntPtr h, ref SublayerS s, IntPtr sd);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmFilterAdd0(IntPtr h, ref Filter f, IntPtr sd, out ulong id);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmFilterDeleteByKey0(IntPtr h, ref Guid key);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmSubLayerDeleteByKey0(IntPtr h, ref Guid key);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmProviderDeleteByKey0(IntPtr h, ref Guid key);
    [DllImport("fwpuclnt.dll", CharSet = CharSet.Unicode)] static extern uint FwpmGetAppIdFromFileName0(string file, out IntPtr blob);
    [DllImport("fwpuclnt.dll")] static extern void FwpmFreeMemory0(ref IntPtr p);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmFilterCreateEnumHandle0(IntPtr h, IntPtr tmpl, out IntPtr e);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmFilterEnum0(IntPtr h, IntPtr e, uint n, out IntPtr rows, out uint got);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmFilterDestroyEnumHandle0(IntPtr h, IntPtr e);

    static void Check(uint r, string where) { if (r != 0) throw new Exception(where + " failed: 0x" + r.ToString("X8")); }

    static IntPtr OpenEngine() { IntPtr h; Check(FwpmEngineOpen0(IntPtr.Zero, 10, IntPtr.Zero, IntPtr.Zero, out h), "FwpmEngineOpen"); return h; }

    static List<KeyValuePair<Guid, string>> Ours(IntPtr h)
    {
        var list = new List<KeyValuePair<Guid, string>>();
        IntPtr e; Check(FwpmFilterCreateEnumHandle0(h, IntPtr.Zero, out e), "FilterEnumHandle");
        try
        {
            while (true)
            {
                IntPtr rows; uint got;
                Check(FwpmFilterEnum0(h, e, 256, out rows, out got), "FilterEnum");
                for (int i = 0; i < got; i++)
                {
                    IntPtr row = Marshal.ReadIntPtr(rows, i * IntPtr.Size);
                    IntPtr pk = Marshal.ReadIntPtr(row, 40);
                    if (pk != IntPtr.Zero && (Guid)Marshal.PtrToStructure(pk, typeof(Guid)) == Provider)
                        list.Add(new KeyValuePair<Guid, string>((Guid)Marshal.PtrToStructure(row, typeof(Guid)),
                            Marshal.PtrToStringUni(Marshal.ReadIntPtr(row, 24)) ?? ""));
                }
                if (rows != IntPtr.Zero) FwpmFreeMemory0(ref rows);
                if (got < 256) break;
            }
        }
        finally { FwpmFilterDestroyEnumHandle0(h, e); }
        return list;
    }

    static void Setup(IntPtr h, List<IntPtr> mem)
    {
        var p = new ProviderS { providerKey = Provider, flags = FLAG_PERSISTENT };
        p.displayData.name = Str("Codex 7899 Local Guard", mem);
        uint r = FwpmProviderAdd0(h, ref p, IntPtr.Zero); if (r != E_ALREADY_EXISTS) Check(r, "ProviderAdd");
        var s = new SublayerS { subLayerKey = Sublayer, flags = FLAG_PERSISTENT, providerKey = GuidPtr(Provider, mem), weight = 0xFFFF };
        s.displayData.name = Str("Codex 7899 application-scoped restrictions", mem);
        r = FwpmSubLayerAdd0(h, ref s, IntPtr.Zero); if (r != E_ALREADY_EXISTS) Check(r, "SubLayerAdd");
    }

    static IntPtr Str(string s, List<IntPtr> mem) { IntPtr p = Marshal.StringToHGlobalUni(s); mem.Add(p); return p; }
    static IntPtr GuidPtr(Guid g, List<IntPtr> mem) { IntPtr p = Marshal.AllocHGlobal(16); Marshal.StructureToPtr(g, p, false); mem.Add(p); return p; }
    static Cond C(Guid field, uint match, uint type, IntPtr value) { return new Cond { fieldKey = field, matchType = match, value = new FwpValue { type = type, value = value } }; }

    static void AddPath(IntPtr h, string path, List<IntPtr> mem)
    {
        if (!File.Exists(path)) throw new FileNotFoundException("Executable missing: " + path);
        IntPtr app; Check(FwpmGetAppIdFromFileName0(path, out app), "AppId " + path);
        try
        {
            for (int kind = 0; kind < 4; kind++)
            {
                var conds = new List<Cond> { C(CondApp, MATCH_EQUAL, FWP_BYTE_BLOB_TYPE, app) };
                if (kind == 0) conds.Add(C(CondAddr, MATCH_NOT_EQUAL, FWP_UINT32, new IntPtr(0x7f000001)));
                if (kind == 1) conds.Add(C(CondPort, MATCH_NOT_EQUAL, FWP_UINT16, new IntPtr(Port)));
                if (kind == 2) conds.Add(C(CondProto, MATCH_NOT_EQUAL, FWP_UINT8, new IntPtr(6)));
                int size = Marshal.SizeOf(typeof(Cond));
                IntPtr arr = Marshal.AllocHGlobal(size * conds.Count); mem.Add(arr);
                for (int i = 0; i < conds.Count; i++) Marshal.StructureToPtr(conds[i], arr + i * size, false);
                var f = new Filter
                {
                    filterKey = Guid.NewGuid(), flags = FLAG_PERSISTENT | FILTER_FLAG_CLEAR_ACTION_RIGHT,
                    providerKey = GuidPtr(Provider, mem), layerKey = kind == 3 ? LayerV6 : LayerV4, subLayerKey = Sublayer,
                    numFilterConditions = (uint)conds.Count, filterCondition = arr, action = new FwpAction { type = ACTION_BLOCK }
                };
                f.displayData.name = Str("Codex7899: " + kind + " " + path, mem);
                f.displayData.description = Str(path, mem);
                ulong id; Check(FwpmFilterAdd0(h, ref f, IntPtr.Zero, out id), "FilterAdd " + kind);
            }
        }
        finally { FwpmFreeMemory0(ref app); }
    }

    static void InTx(Action<IntPtr, List<IntPtr>> body)
    {
        IntPtr h = OpenEngine(); var mem = new List<IntPtr>(); bool done = false;
        try
        {
            Check(FwpmTransactionBegin0(h, 0), "TransactionBegin");
            body(h, mem);
            Check(FwpmTransactionCommit0(h), "TransactionCommit"); done = true;
        }
        finally
        {
            if (!done) FwpmTransactionAbort0(h);
            foreach (IntPtr p in mem) Marshal.FreeHGlobal(p);
            FwpmEngineClose0(h);
        }
    }

    // 以本 exe 身份做功能探测：本 exe 也在守护名单里，所以结果反映过滤器是否真的生效。
    static int Try(string ip, int port, bool udp)
    {
        IPAddress a = IPAddress.Parse(ip);
        using (var s = new Socket(a.AddressFamily, udp ? SocketType.Dgram : SocketType.Stream, udp ? ProtocolType.Udp : ProtocolType.Tcp))
        {
            try
            {
                if (udp)
                {
                    // 被阻断的 UDP 会被静默丢弃，send 照样成功；所以发真实 DNS 查询，收到回包才算“通”。
                    byte[] q = { 0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, (byte)'e', (byte)'x', (byte)'a', (byte)'m', (byte)'p', (byte)'l', (byte)'e', 3, (byte)'c', (byte)'o', (byte)'m', 0, 0, 1, 0, 1 };
                    s.ReceiveTimeout = 3000; s.Connect(a, port); s.Send(q);
                    s.Receive(new byte[512]); return 0;
                }
                IAsyncResult ar = s.BeginConnect(a, port, null, null);
                if (!ar.AsyncWaitHandle.WaitOne(4000)) return 10060;
                s.EndConnect(ar); return 0;
            }
            catch (SocketException ex) { return ex.ErrorCode; }
        }
    }

    static int Probe()
    {
        bool ok = true;
        Func<string, int, bool, Func<int, bool>, string, bool> t = (ip, port, udp, pass, want) =>
        {
            int r = Try(ip, port, udp); bool good = pass(r);
            Console.WriteLine("{0} {1}:{2} -> {3} ({4}) {5}", udp ? "UDP" : "TCP", ip, port, r, want, good ? "OK" : "FAIL");
            return good;
        };
        ok &= t("1.1.1.1", 443, false, r => r == 10013, "expect blocked");
        ok &= t("127.0.0.1", 7897, false, r => r == 10013, "expect blocked");
        ok &= t("1.1.1.1", 53, true, r => r != 0, "expect no reply");
        ok &= t("2606:4700:4700::1111", 443, false, r => r != 0, "expect not connected");
        ok &= t("127.0.0.1", Port, false, r => r != 10013, "expect allowed");
        Console.WriteLine(ok ? "PROBE PASS" : "PROBE FAIL");
        return ok ? 0 : 2;
    }

    static int Main(string[] args)
    {
        try
        {
            if (Marshal.SizeOf(typeof(Filter)) != 200 || Marshal.SizeOf(typeof(Cond)) != 40) throw new Exception("Struct layout mismatch (build with /platform:x64).");
            string mode = args.Length > 0 ? args[0] : "";
            if (mode == "probe") return Probe();
            if (mode == "list")
            {
                IntPtr h = OpenEngine();
                try { foreach (var kv in Ours(h)) Console.WriteLine(kv.Key + "\t" + kv.Value); }
                finally { FwpmEngineClose0(h); }
                return 0;
            }
            if (mode == "sync" && args.Length > 1)
            {
                InTx((h, mem) =>
                {
                    Setup(h, mem);
                    foreach (var kv in Ours(h)) { Guid k = kv.Key; Check(FwpmFilterDeleteByKey0(h, ref k), "FilterDelete"); }
                    for (int i = 1; i < args.Length; i++) AddPath(h, Path.GetFullPath(args[i]), mem);
                });
                IntPtr h2 = OpenEngine();
                try
                {
                    int n = Ours(h2).Count;
                    if (n != 4 * (args.Length - 1)) throw new Exception("Expected " + 4 * (args.Length - 1) + " filters, found " + n);
                    Console.WriteLine("Committed " + n + " filters for " + (args.Length - 1) + " executable(s).");
                }
                finally { FwpmEngineClose0(h2); }
                return 0;
            }
            if (mode == "remove-all")
            {
                InTx((h, mem) =>
                {
                    foreach (var kv in Ours(h)) { Guid k = kv.Key; Check(FwpmFilterDeleteByKey0(h, ref k), "FilterDelete"); }
                    Guid s = Sublayer, p = Provider;
                    uint r = FwpmSubLayerDeleteByKey0(h, ref s); if (r != E_SUBLAYER_NOT_FOUND) Check(r, "SubLayerDelete");
                    r = FwpmProviderDeleteByKey0(h, ref p); if (r != E_PROVIDER_NOT_FOUND) Check(r, "ProviderDelete");
                });
                Console.WriteLine("Removed all Codex 7899 filters.");
                return 0;
            }
            throw new Exception("Usage: sync <exe...> | list | remove-all | probe");
        }
        catch (Exception ex) { Console.Error.WriteLine("[ERROR] " + ex.Message); return 1; }
    }
}
