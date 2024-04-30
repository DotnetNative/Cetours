namespace Cetours.Assembler;
internal unsafe partial class ASM
{
    public const byte
        RET = 0xc3,
        NOP = 0x90,
        JMP_X32_REL_SIZE = 5;

    public ASM(pointer ptr)
    {
        pointer = ptr;
        *(byte*)pointer = pointer[0];
    }

    pointer pointer;

    public byte* CurrentAddr() => pointer;

    public void Nop(int count)
    {
        for (int i = 0; i < count; i++)
            _Nop();
    }

    public void JmpRelativeX32(pointer from, pointer to) => _JmpRel(from, to);

    public void JmpRelativeX32(pointer to) => _JmpRel(to);

    public static int GetSizeOfJmpAbsoluteX64(X64Register register) => register.IsExtended ? 13 : 12;
    public void JmpAbsoluteX64(pointer to)
    {
        _Mov(X64Registers.R12, to);
        _JmpAbs(X64Registers.R12);
    }

    public void JmpAbsoluteX64(X64Register register, pointer to)
    {
        _Mov(register, to);
        _JmpAbs(register);
    }

    #region Methods
    public void Copy(pointer from, int count)
    {
        MemEx.Copy(pointer, from, count);
        pointer += count;
    }

    public bool IsNext(params byte[] bytes) => Compare(pointer, bytes);

    public void Back(int count) => pointer -= count;
    public void BackTo(void* ptr) => pointer = (byte*)ptr;

    public int GetNextInstructionLength() => GetInstructionLength(pointer);
    public int GetRoundedInstructionsLength(int len)
    {
        int i = 0;

        while (i < len)
            i += GetInstructionLength(pointer + i);

        return i;
    }

    #region JmpREXWQwordPtr
    static byte[] JmpREXWQwordPtrPattern = [0x48, 0xff, 0x25];

    public bool IsJmpREXWQwordPtr() => Compare(pointer, JmpREXWQwordPtrPattern);

    public pointer GetJmpREXWQwordPtrAddr() => *(pointer*)GetJmpREXWQwordPtrPointerAddr();

    public nint GetJmpREXWQwordPtrPointerAddr()
    {
        int offset = GetJmpREXWQwordPtrOpcode();
        var curAddr = (nint)pointer;
        var instructionSize = 3 + sizeof(int);
        var addr = curAddr + offset + instructionSize;

        return addr;
    }

    public int GetJmpREXWQwordPtrOpcode()
    {
        var ptr = pointer + 3;
        int opcode = *(int*)ptr;
        return opcode;
    }
    #endregion

    #region JmpQwordPtr
    static byte[] JmpQwordPtrPattern = { 0xff, 0x25 };

    public bool IsJmpQwordPtr() => Compare(pointer, JmpQwordPtrPattern);

    public nint GetJmpQwordPtrAddr() => *(nint*)GetJmpQwordPtrPointerAddr();

    public nint GetJmpQwordPtrPointerAddr()
    {
        int offset = GetJmpQwordPtrOpcode();
        var curAddr = (nint)pointer;
        var instructionSize = 2 + sizeof(int);
        var addr = curAddr + offset + instructionSize;

        return addr;
    }

    public int GetJmpQwordPtrOpcode()
    {
        int opcode = *(int*)(pointer + 2);
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
        *(long*)pointer = val;
        pointer += sizeof(long);
    }

    void Write(int val)
    {
        *(int*)pointer = val;
        pointer += sizeof(int);
    }
    #endregion

    #region Instructions
    public void _Mov(X64Register register, long ptr)
    {
        *(byte*)pointer = (byte)(register.IsExtended ? 0x49 : 0x48);
        pointer++;
        *(byte*)pointer = register.MovOC;
        pointer++;
        Write(ptr);
    }

    public void _JmpAbs(X64Register register)
    {
        if (register.IsExtended)
        {
            *(byte*)pointer = 0x41;
            pointer++;
        }
        *(byte*)pointer = 0xff;
        pointer++;
        *(byte*)pointer++ = register.JmpOC;
        pointer++;
    }

    public void _JmpRel(void* to)
    {
        *(byte*)pointer = 0xe9;
        pointer++;
        Write((int)((byte*)to - ((byte*)pointer + JMP_X32_REL_SIZE)));
    }

    public void _JmpRel(void* from, void* to)
    {
        *(byte*)pointer = 0xe9;
        pointer++;
        Write((int)((byte*)to - ((byte*)from + JMP_X32_REL_SIZE)));
    }

    public void _Ret()
    {
        *(byte*)pointer = RET;
        pointer++;
    }
    public void _Nop()
    {
        *(byte*)pointer = NOP;
        pointer++;
    }

    public const int _JMP_REXW_QWORD_PTR_SIZE = 7;
    public void _JmpREXWQwordPtr(int operand)
    {
        MemEx.Copy(pointer, [0x48, 0xff, 0x25]);
        pointer += 3;
        Write(operand);
    }

    public const int _JMP_QWORD_PTR_SIZE = 6;
    public void _JmpQwordPtr(int operand)
    {
        MemEx.Copy(pointer, [0xff, 0x25]);
        pointer += 2;
        Write(operand);
    }
    #endregion
}