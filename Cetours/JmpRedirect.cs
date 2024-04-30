namespace Cetours;
public abstract unsafe class JmpRedirect
{
    public JmpRedirect(pointer from, pointer to)
    {
        From = from;
        To = to;
    }

    public readonly pointer From;
    public readonly pointer To;
    public int Length { get; init; }

    public abstract void Enable();
    public abstract void Disable();

    public static JmpRedirect Create(Hook hook, pointer from, pointer to)
    {
        var isX32Range = (from - to) < uint.MaxValue;

        return isX32Range ? new RelativeJmpRedirect(from, to) : new X64RegisterAbsoluteJmpRedirect(hook.Data.JmpRegister, from, to);
    }
}

public unsafe abstract class StaticJmpRedirect : JmpRedirect
{
    public StaticJmpRedirect(pointer from, pointer to, int length) : base(from, to)
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
    public X64RegisterAbsoluteJmpRedirect(X64Register register, pointer from, pointer to) : base(from, to, new ASM(from).GetRoundedInstructionsLength(GetSizeOfJmpAbsoluteX64(register)))
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
    public RelativeJmpRedirect(pointer from, pointer to) : base(from, to, new ASM(from).GetRoundedInstructionsLength(JMP_X32_REL_SIZE))
    {
        fixed (byte* ptr = rippedBytes)
        {
            var asm = new ASM(ptr);
            asm.JmpRelativeX32(from, to);
        }
    }
}