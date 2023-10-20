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
    public static void* Create(void* orig, void* ripped, out int len)
    {
        RegionManager.SetRegionProtection(orig, MemProtect.ExecuteReadWrite);
        RegionManager.SetRegionProtection(ripped, MemProtect.ExecuteReadWrite);

        var reg = RegionManager.AllocRegion(orig, 0x1000);

        {
            var asm = new ASM(orig);
            len = asm.GetRoundedInstructionsLength(JMP_X32_REL_SIZE);
        }

        {
            var asm = new ASM(reg);
            asm._Copy(orig, len);
            asm.Jmp_X32Rel((byte*)orig + len);
        }

        return reg;
    }

    public static void Attach(void* orig, void* ripped, int len)
    {
        var asm = new ASM(orig);
        asm.Jmp_X32Rel(ripped);
        asm.Nop(len - JMP_X32_REL_SIZE);
    }

    public static void Detach(void* orig, void* allocated, int len)
    {
        var asm = new ASM(orig);
        asm._Copy(allocated, len);
    }
}