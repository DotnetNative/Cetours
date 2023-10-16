using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using static System.Runtime.InteropServices.JavaScript.JSType;

public static unsafe class Interop
{
    const string user = "user32";
    const string kernel = "kernel32";

    [DllImport(kernel, CharSet = CharSet.Unicode)] public static extern
        nint GetModuleHandle([MarshalAs(UnmanagedType.LPWStr)] string moduleName);

    [DllImport(kernel)] public unsafe static extern 
        nint VirtualQuery(byte* lpAddress, MEMORY_BASIC_INFORMATION* lpBuffer, int dwLength);

    [DllImport(kernel)] public static extern 
        bool VirtualProtectEx(nint hProcess, void* dwAddress, long nSize, int flNewProtect, int* lpflOldProtect);

    [DllImport(kernel)] public static extern
        nint GetCurrentProcess();

    [DllImport(kernel)] public static extern 
        int VirtualQueryEx(nint hProcess, void* lpAddress, MEMORY_BASIC_INFORMATION* lpBuffer, int dwLength);

    [DllImport(kernel)] public static extern
        bool VirtualFree(nint lpAddress, long dwSize, int dwFreeType);

    [DllImport(kernel, ExactSpelling = true, EntryPoint = "RtlMoveMemory")] public static extern 
        void CopyMemory(void* pdst, void* psrc, int cb);

    [DllImport(kernel)] public static extern
        bool VirtualProtect(void* lpAddress, long dwSize, int flNewProtect, int* lpflOldProtect);
}