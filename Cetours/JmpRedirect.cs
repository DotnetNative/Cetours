using Cetours.Assembler;
using Cetours.Hooking;

namespace Cetours;
public abstract unsafe class JmpRedirect
{
    public JmpRedirect(void* from, void* to)
    {
        From = (byte*)from;
        To = (byte*)to;
    }

    public readonly byte* From;
    public readonly byte* To;
    public int Length { get; init; }

    public abstract void Enable();
    public abstract void Disable();

    public static JmpRedirect Create(Hook hook, void* fromV, void* toV)
    {
        var from = (byte*)fromV;
        var to = (byte*)toV;

        var distance = (nint)from - (nint)to;
        var isX32Range = distance < int.MaxValue && distance > int.MinValue;

        return isX32Range ? new RelativeJmpRedirect(from, to) : new X64RegisterAbsoluteJmpRedirect(hook.JmpRegister, from, to);
    }
}


public unsafe abstract class StaticJmpRedirect : JmpRedirect
{
    public StaticJmpRedirect(void* from, void* to, int length) : base(from, to)
    {
        Length = length;

        originalBytes = new byte[length];
        rippedBytes = new byte[length];

        Copy(originalBytes, from);
    }

    protected readonly byte[] originalBytes;
    protected readonly byte[] rippedBytes;

    public override void Enable() => Copy(From, rippedBytes);
    public override void Disable() => Copy(From, rippedBytes);
}

public unsafe class X64RegisterAbsoluteJmpRedirect : StaticJmpRedirect
{
    public X64RegisterAbsoluteJmpRedirect(Register register, void* from, void* to) : base(from, to, new ASM(from).GetRoundedInstructionsLength(GetSizeOfJmpAbsoluteX64(register)))
    {
        fixed (byte* ptr = rippedBytes)
        {
            var asm = new ASM(ptr);
            asm.JmpAbsoluteX64(register, to);
        }
    }
}

public unsafe class RelativeJmpRedirect : StaticJmpRedirect
{
    public RelativeJmpRedirect(void* from, void* to) : base(from, to, new ASM(from).GetRoundedInstructionsLength(JMP_X32_REL_SIZE))
    {
        fixed (byte* ptr = rippedBytes)
        {
            var asm = new ASM(ptr);
            asm.JmpRelativeX32(from, to);
        }
    }
}