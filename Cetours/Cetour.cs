global using static Memory.MemEx;
global using static Cetours.ASM;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Cetours;
public static unsafe class Cetour
{
    public static Hook Create(void* orig, void* ripped)
    {
        RegionManager.SetRegionProtection(ripped, MemProtect.ExecuteReadWrite);
        RegionManager.SetRegionProtection(orig, MemProtect.ExecuteReadWrite);

        var fasm = new ASM(orig);

        if (fasm.IsJmpQwordPtr()) // Is IAT Jmp
        {
            var iatOpcode = fasm.GetJmpQwordPtrOpcode();
            var innerFuncAddr = fasm.GetJmpQwordPtrAddr();

            return new IATWithFreeBytes()
            {
                OriginOpcode = iatOpcode,
                Origin = orig,
                Ripped = ripped,
                New = (void*)innerFuncAddr
            };
        }
        else
        {
            var sasm = new ASM(orig);

            int len = sasm.GetRoundedInstructionsLength(JMP_ABSOLUTE_X64_SIZE);

            var reg = RegionManager.AllocRegion(orig, 0x1000);

            var asm = new ASM(reg);
            asm.Copy(orig, len);
            asm.JmpAbsoluteX64(orig);

            return new AllocationTrampolineHook()
            {
                Length = len,
                Origin = orig,
                Ripped = ripped,
                New = reg,
            };
        }
    }
}