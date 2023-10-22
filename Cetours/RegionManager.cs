using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Intrinsics.X86;
using System.Text;
using System.Threading.Tasks;
using static Interop;

namespace Cetours;
internal static unsafe class RegionManager
{
    public static byte* AllocRegion(void* addr, int size)
    {
        var direction = 1;

        addr = (byte*)addr - ((nint)addr % 0x1000);

        var ptr = (byte*)addr;

        MBI mbi;
        while (true)
        {
            if (VirtualQuery(ptr, &mbi, sizeof(MBI)) == 0)
                return null;

            if (mbi.State == MemState.Free && mbi.RegionSize >= size)
            {
                var result = (byte*)VirtualAlloc(mbi.BaseAddress, size, MemState.Commit | MemState.Reserve, MemProtect.ExecuteReadWrite);
                if (result == null)
                {
                    var error = GetLastError();

                    if (error == 0x1E7 /* Attempt to access invalid address */)
                    {
                        if (direction == -1)
                        {
                            ptr += mbi.RegionSize * direction;
                            continue;
                        }

                        direction = direction * -1;
                        ptr = (byte*)addr;

                        continue;
                    }
                }
                return result;
            }

            ptr += mbi.RegionSize * direction;
        }
    }

    public static int GetRegionSize(void* addr) => (int)GetRegion(addr).RegionSize;

    public static MBI GetRegion(void* addr)
    {
        MBI mbi;
        VirtualQuery(addr, &mbi, sizeof(MBI));
        return mbi;
    }

    public static MemProtect SetRegionProtection(void* addr, int size, MemProtect newProtect)
    {
        MemProtect oldProtect;
        VirtualProtect(addr, size, newProtect, &oldProtect);

        return oldProtect;
    }

    public static MemProtect SetRegionProtection(void* addr, MemProtect newProtect)
    {
        MemProtect oldProtect;
        int size = GetRegionSize(addr);
        VirtualProtect(addr, size, newProtect, &oldProtect);

        return oldProtect;
    }
}
