using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace Cetours;

public unsafe abstract class Hook
{
    public void* Origin;
    public void* Ripped;
    public void* New;

    public abstract void Attach();

    public abstract void Detach();
}

public unsafe class AllocationTrampolineHook : Hook
{
    public int Length;

    public override void Attach()
    {
        var asm = new ASM(Origin);
        asm.JmpAbsoluteX64(Ripped);
        asm.Nop(Length - JMP_ABSOLUTE_X64_SIZE);
    }

    public override void Detach()
    {
        var asm = new ASM(Origin);
        asm.Copy(New, Length);
    }
}

public unsafe class IATWithFreeBytes : Hook
{
    public int OriginOpcode;

    public override void Attach()
    {
        var asm = new ASM(Origin);
        asm.JmpAbsoluteX64(Ripped);
    }

    public override void Detach()
    {
        var asm = new ASM(Origin);
        asm._JmpQwordPtr(OriginOpcode);
        asm.Nop(JMP_ABSOLUTE_X64_SIZE - _JMP_QWORD_PTR_SIZE);
    }
}