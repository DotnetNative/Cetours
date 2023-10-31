using static Interop;

namespace Cetours.Internal;
internal static unsafe class RegionManager
{
    const long MinMemBarrier = 0,
               MaxMemBarrier = 0x7FFFFFFFFFFF;
    const int X32Range = int.MaxValue;

    static byte* ToRegionPtr(void* ptr) => (byte*)ptr - (nint)ptr % 0x1000;

    public static byte* TryAllocRegionInX32Range(void* addr, int size)
    {
        var ptr = AllocRegionInX32Range(addr, size);
        return ptr == null ? AllocRegion(addr, size) : ptr;
    }

    public static byte* AllocRegionInX32Range(void* addr, int size)
    {
        addr = ToRegionPtr(addr);

        var lPtr = (byte*)Math.Max(MinMemBarrier, (nint)addr - X32Range + size - 1);
        var hPtr = (byte*)Math.Min(MaxMemBarrier, (nint)addr + X32Range - size);

        MBI* mbi = stackalloc MBI[1];
        for (var ptr = lPtr; ptr < hPtr; ptr += mbi->RegionSize)
        {
            if (VirtualQuery(ptr, mbi, sizeof(MBI)) == 0)
                return null;

            if (mbi->State == MemState.Free && mbi->RegionSize >= size)
            {
                var result = (byte*)VirtualAlloc(mbi->BaseAddress, size, MemState.Commit | MemState.Reserve, MemProtect.ExecuteReadWrite);
                if (result == null)
                    continue;

                return ptr;
            }
        }

        return null;
    }

    public static byte* AllocRegion(void* addr, int size)
    {
        var direction = 1;

        addr = ToRegionPtr(addr);

        var ptr = (byte*)addr;

        MBI* mbi = stackalloc MBI[1];
        while (true)
        {
            if (VirtualQuery(ptr, mbi, sizeof(MBI)) == 0)
                return null;

            if (mbi->State == MemState.Free && mbi->RegionSize >= size)
            {
                var result = (byte*)VirtualAlloc(mbi->BaseAddress, size, MemState.Commit | MemState.Reserve, MemProtect.ExecuteReadWrite);
                if (result == null)
                {
                    var error = GetLastError();

                    if (error == 0x1E7 /* Attempt to access invalid address */)
                    {
                        if (direction == -1)
                        {
                            AddAddr();
                            continue;
                        }

                        direction = direction * -1;
                        ptr = (byte*)addr;

                        continue;
                    }
                }

                return ptr;
            }

            AddAddr();
        }

        void AddAddr()
        {
            ptr += mbi->RegionSize * direction;
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
