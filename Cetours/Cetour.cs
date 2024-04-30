global using static Cetours.Assembler.ASM;
global using static Memory.MemEx;
using Cetours.Assembler;
using Cetours.Hooking;

namespace Cetours;
public static unsafe class Cetour
{
    public static Hook Create(void* orig, void* ripped, HookInnerData? data = null)
    {
        if (data is null)
            data = new();

        Mem.SetRegionProtection(ripped, MemProtect.ExecuteReadWrite);
        Mem.SetRegionProtection(orig, MemProtect.ExecuteReadWrite);

        var fasm = new ASM(orig);

        if (fasm.IsJmpREXWQwordPtr()) // Is IAT REXW Jmp
        {
            var innerFuncAddr = fasm.GetJmpREXWQwordPtrAddr();

            return new RedirectHook(orig, ripped, innerFuncAddr, data);
        }
        else if (fasm.IsJmpQwordPtr()) // Is IAT Jmp
        {
            var innerFuncAddr = fasm.GetJmpQwordPtrAddr();

            return new RedirectHook(orig, ripped, innerFuncAddr, data);
        }
        else // Use AllocationTrampolineHook
        {
            var reg = Mem.TryAllocRegionInX32Range(orig, 0x1000);

            return new AllocationTrampolineHook(orig, ripped, reg, data);
        }
    }
}