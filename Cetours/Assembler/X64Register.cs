namespace Cetours.Assembler;
public abstract record X64Register(byte MovOC, byte JmpOC, bool IsExtended = false);
public abstract record RX64Register(byte MovOC, byte JmpOC) : X64Register(MovOC, JmpOC, true);

public static class X64Registers
{
    public static readonly RAXRegister RAX = new();
    public static readonly RBXRegister RBX = new();
    public static readonly RCXRegister RCX = new();
    public static readonly RDXRegister RDX = new();
    public static readonly RSIRegister RSI = new();
    public static readonly RDIRegister RDI = new();
    public static readonly RBPRegister RBP = new();
    public static readonly RSPRegister RSP = new();
    public static readonly R8Register R8 = new();
    public static readonly R9Register R9 = new();
    public static readonly R10Register R10 = new();
    public static readonly R11Register R11 = new();
    public static readonly R12Register R12 = new();
    public static readonly R13Register R13 = new();
    public static readonly R14Register R14 = new();
    public static readonly R15Register R15 = new();

    public record RAXRegister() : X64Register(0xb8, 0xe0);
    public record RBXRegister() : X64Register(0xbb, 0xe3);
    public record RCXRegister() : X64Register(0xb9, 0xe1);
    public record RDXRegister() : X64Register(0xba, 0xe2);
    public record RSIRegister() : X64Register(0xbe, 0xe6);
    public record RDIRegister() : X64Register(0xbf, 0xe7);
    public record RBPRegister() : X64Register(0xbd, 0xe5);
    public record RSPRegister() : X64Register(0xbc, 0xe4);
    public record R8Register() : RX64Register(0xb8, 0xe0);
    public record R9Register() : RX64Register(0xb9, 0xe1);
    public record R10Register() : RX64Register(0xba, 0xe2);
    public record R11Register() : RX64Register(0xbb, 0xe3);
    public record R12Register() : RX64Register(0xbc, 0xe4);
    public record R13Register() : RX64Register(0xbd, 0xe5);
    public record R14Register() : RX64Register(0xbe, 0xe6);
    public record R15Register() : RX64Register(0xbf, 0xe7);
}