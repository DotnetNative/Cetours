using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static Memory.MemEx;
using static Cetours.ASM;

namespace Cetours;
public static unsafe class Cetour
{
    public static void* Create(void** orig, void* ripped, out int len)
    {
        RegionManager.SetRegionProtection(ripped, MemProtect.ExecuteReadWrite);
        RegionManager.SetRegionProtection(*orig, MemProtect.ExecuteReadWrite);

        {
            var fasm = new ASM(*orig);

            {
                if (fasm.IsIATImportJmp())
                    *orig = (void*)fasm.GetATImportAddr();
            }

            RegionManager.SetRegionProtection(*orig, MemProtect.ExecuteReadWrite);

            var sasm = new ASM(*orig);

            len = sasm.GetRoundedInstructionsLength(JMP_ABSOLUTE_X64_SIZE);
        }

        var reg = RegionManager.AllocRegion(*orig, 0x1000);

        {
            var asm = new ASM(reg);
            asm.Copy(*orig, len);
            asm.JmpAbsoluteX64(*orig);
        }

        return reg;
    }

    public static void Attach(void* orig, void* ripped, int len)
    {
        var asm = new ASM(orig);
        asm.JmpAbsoluteX64(ripped);
        asm.Nop(len - JMP_ABSOLUTE_X64_SIZE);
    }

    public static void Detach(void* orig, void* allocated, int len)
    {
        var asm = new ASM(orig);
        asm.Copy(allocated, len);
    }
}