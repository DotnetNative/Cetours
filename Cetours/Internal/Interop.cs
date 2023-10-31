using System.Runtime.InteropServices;

#region Enum
public enum MemState : int
{
    Commit = 0x1000,
    Free = 0x10000,
    Reserve = 0x2000
}

[Flags]
public enum MemProtect : int
{
    ZeroAccess = 0,
    NoAccess = 1,
    ReadOnly = 2,
    ReadWrite = 4,
    WriteCopy = 8,
    Execute = 16,
    ExecuteRead = 32,
    ExecuteReadWrite = 64,
    ExecuteWriteCopy = 128,
    Guard = 256,
    ReadWriteGuard = 260,
    NoCache = 512
}

public enum MemType : int
{
    Image = 0x1000000,
    Mapped = 0x40000,
    Private = 0x20000
}
#endregion
internal unsafe class Interop
{
    const string kernel = "kernel32";

    [DllImport(kernel, CharSet = CharSet.Unicode)]
    public static extern
        nint GetModuleHandle([MarshalAs(UnmanagedType.LPWStr)] string moduleName);

    [DllImport(kernel)]
    public unsafe static extern
        nint VirtualQuery(void* lpAddress, MBI* lpBuffer, int dwLength);

    [DllImport(kernel)]
    public static extern
        bool VirtualProtectEx(nint hProcess, void* dwAddress, long nSize, int flNewProtect, int* lpflOldProtect);

    [DllImport(kernel)]
    public static extern
        nint GetCurrentProcess();

    [DllImport(kernel)]
    public static extern
        int GetCurrentThreadId();

    [DllImport(kernel)]
    public static extern
        nint GetCurrentThread();

    [DllImport(kernel)]
    public static extern
        int GetLastError();

    [DllImport(kernel)]
    public static extern
        int SuspendThread(nint hThread);

    [DllImport(kernel)]
    public static extern
        int ResumeThread(nint hThread);

    [DllImport(kernel)]
    public static extern
        int VirtualQueryEx(nint hProcess, void* lpAddress, MBI* lpBuffer, int dwLength);

    [DllImport(kernel)]
    public static extern
        bool VirtualFree(nint lpAddress, long dwSize, int dwFreeType);

    [DllImport(kernel, ExactSpelling = true, EntryPoint = "RtlMoveMemory")]
    public static extern
        void CopyMemory(void* pdst, void* psrc, int cb);

    [DllImport(kernel)]
    public static extern
        bool VirtualProtect(void* lpAddress, long dwSize, MemProtect flNewProtect, MemProtect* lpflOldProtect);

    [DllImport(kernel, SetLastError = true)]
    public static extern
        void* VirtualAlloc(void* lpAddress, long dwSize, MemState flAllocationType, MemProtect flProtect);

    [StructLayout(LayoutKind.Sequential)]
    public unsafe struct MBI
    {
        public unsafe byte* BaseAddress;
        public unsafe byte* AllocationBase;
        public uint AllocationProtect;
        public nint RegionSize;
        public MemState State;
        public MemProtect Protect;
        public MemType Type;

        public override string ToString() => $"BaseAddr: {(nint)BaseAddress}, AllocAddr: {(nint)AllocationBase}, AllocProtect: {AllocationProtect}, Size: {RegionSize}, State: {State}, Protect: {Protect}, Type: {Type}";
    }
}