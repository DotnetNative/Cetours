global using static Cetours.Assembler.ASM;
global using static Memory.MemEx;
using Cetours.Assembler;
using Cetours.Hooking;
using Cetours.Internal;

namespace Cetours;
public static unsafe class Cetour
{
    public static Hook Create(void* orig, void* ripped, HookInnerData? data = null)
    {
        if (data == null)
            data = new();

        RegionManager.SetRegionProtection(ripped, MemProtect.ExecuteReadWrite);
        RegionManager.SetRegionProtection(orig, MemProtect.ExecuteReadWrite);

        var fasm = new ASM(orig);

        if (fasm.IsJmpREXWQwordPtr()) // Is IAT REXW Jmp
        {
            var innerFuncAddr = (void*)fasm.GetJmpREXWQwordPtrAddr();

            return new RedirectHook(orig, ripped, innerFuncAddr, data);
        }
        else if (fasm.IsJmpQwordPtr()) // Is IAT Jmp
        {
            var innerFuncAddr = (void*)fasm.GetJmpQwordPtrAddr();

            return new RedirectHook(orig, ripped, innerFuncAddr, data);
        }
        else // Use AllocationTrampolineHook
        {
            var reg = RegionManager.TryAllocRegionInX32Range(orig, 0x1000);

            return new AllocationTrampolineHook(orig, ripped, reg, data);
        }
    }
}