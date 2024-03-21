using Memory;
using static Cetours.Assembler.ASMTables;

namespace Cetours.Assembler;
internal unsafe partial class ASM
{
    public const byte
        RET = 0xc3,
        NOP = 0x90,
        JMP_X32_REL_SIZE = 5;

    public ASM(void* ptr)
    {
        p = (byte*)ptr;
        *p = *p;
    }

    byte* p;

    public byte* CurrentAddr() => p;

    public void Nop(int count)
    {
        for (int i = 0; i < count; i++)
            _Nop();
    }

    public void JmpRelativeX32(void* from, void* to) => _JmpRel(from, to);

    public void JmpRelativeX32(void* to) => _JmpRel(to);

    public static int GetSizeOfJmpAbsoluteX64(Register register) => register.IsExtended ? 13 : 12;
    public void JmpAbsoluteX64(void* to)
    {
        _Mov(X64Registers.R12, (long)to);
        _JmpAbs(X64Registers.R12);
    }

    public void JmpAbsoluteX64(Register register, void* to)
    {
        _Mov(register, (long)to);
        _JmpAbs(register);
    }

    #region Methods
    public void Copy(void* from, int count)
    {
        MemEx.Copy(p, from, count);
        p += count;
    }

    public bool IsNext(params byte[] bytes) => Compare(p, bytes);

    public void Back(int count) => p -= count;
    public void BackTo(void* ptr) => p = (byte*)ptr;

    public int GetNextInstructionLength() => GetInstructionLength(p);
    public int GetRoundedInstructionsLength(int len)
    {
        int i = 0;

        while (i < len)
            i += GetInstructionLength(p + i);

        return i;
    }

    #region JmpREXWQwordPtr
    static byte[] JmpREXWQwordPtrPattern = { 0x48, 0xff, 0x25 };

    public bool IsJmpREXWQwordPtr() => Compare(p, JmpREXWQwordPtrPattern);

    public nint GetJmpREXWQwordPtrAddr() => *(nint*)GetJmpREXWQwordPtrPointerAddr();

    public nint GetJmpREXWQwordPtrPointerAddr()
    {
        int offset = GetJmpREXWQwordPtrOpcode();
        var curAddr = (nint)p;
        var instructionSize = 3 + sizeof(int);
        var addr = curAddr + offset + instructionSize;

        return addr;
    }

    public int GetJmpREXWQwordPtrOpcode()
    {
        byte* ptr = p + 3;
        int opcode = *(int*)ptr;
        return opcode;
    }
    #endregion

    #region JmpQwordPtr
    static byte[] JmpQwordPtrPattern = { 0xff, 0x25 };

    public bool IsJmpQwordPtr() => Compare(p, JmpQwordPtrPattern);

    public nint GetJmpQwordPtrAddr() => *(nint*)GetJmpQwordPtrPointerAddr();

    public nint GetJmpQwordPtrPointerAddr()
    {
        int offset = GetJmpQwordPtrOpcode();
        var curAddr = (nint)p;
        var instructionSize = 2 + sizeof(int);
        var addr = curAddr + offset + instructionSize;

        return addr;
    }

    public int GetJmpQwordPtrOpcode()
    {
        byte* ptr = p + 2;
        int opcode = *(int*)ptr;
        return opcode;
    }
    #endregion

    #endregion

    #region Internal
    byte GetInstructionLength(byte[] table, byte* instruction)
    {
        byte i = table[*instruction++];
        return i < 0x10 ? i : GetInstructionLength(INSTRUCTION_TABLES[i - 0x10], instruction);
    }

    byte GetInstructionLength(byte* instruction) => GetInstructionLength(INSTRUCTION_TABLE, instruction);

    void Write(long val)
    {
        *(long*)p = val;
        p += sizeof(long);
    }

    void Write(int val)
    {
        *(int*)p = val;
        p += sizeof(int);
    }
    #endregion

    #region Instructions
    public void _Mov(Register register, long ptr)
    {
        *p++ = (byte)(register.IsExtended ? 0x49 : 0x48);
        *p++ = register.MovOC;
        Write(ptr);
    }

    public void _JmpAbs(Register register)
    {
        if (register.IsExtended)
            *p++ = 0x41;
        *p++ = 0xff;
        *p++ = register.JmpOC;
    }

    public void _JmpRel(void* to)
    {
        *p++ = 0xe9;
        Write((int)((byte*)to - (p + JMP_X32_REL_SIZE)));
    }

    public void _JmpRel(void* from, void* to)
    {
        *p++ = 0xe9;
        Write((int)((byte*)to - ((byte*)from + JMP_X32_REL_SIZE)));
    }

    public void _Ret() => *p++ = RET;
    public void _Nop() => *p++ = NOP;

    public const int _JMP_REXW_QWORD_PTR_SIZE = 7;
    public void _JmpREXWQwordPtr(int operand)
    {
        *p++ = 0x48;
        *p++ = 0xff;
        *p++ = 0x25;
        Write(operand);
    }

    public const int _JMP_QWORD_PTR_SIZE = 6;
    public void _JmpQwordPtr(int operand)
    {
        *p++ = 0xff;
        *p++ = 0x25;
        Write(operand);
    }
    #endregion
}