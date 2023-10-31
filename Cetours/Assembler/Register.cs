﻿namespace Cetours.Assembler;

public abstract record Register(byte MovOC, byte JmpOC, bool IsExtended = false);

public class X64Registers
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

    public record RAXRegister() : Register(0xb8, 0xe0);
    public record RBXRegister() : Register(0xbb, 0xe3);
    public record RCXRegister() : Register(0xb9, 0xe1);
    public record RDXRegister() : Register(0xba, 0xe2);
    public record RSIRegister() : Register(0xbe, 0xe6);
    public record RDIRegister() : Register(0xbf, 0xe7);
    public record RBPRegister() : Register(0xbd, 0xe5);
    public record RSPRegister() : Register(0xbc, 0xe4);
    public record R8Register() : Register(0xb8, 0xe0, true);
    public record R9Register() : Register(0xb9, 0xe1, true);
    public record R10Register() : Register(0xba, 0xe2, true);
    public record R11Register() : Register(0xbb, 0xe3, true);
    public record R12Register() : Register(0xbc, 0xe4, true);
    public record R13Register() : Register(0xbd, 0xe5, true);
    public record R14Register() : Register(0xbe, 0xe6, true);
    public record R15Register() : Register(0xbf, 0xe7, true);
}