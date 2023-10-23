using Memory;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static Cetours.ASMTables;

namespace Cetours;
internal unsafe class ASM
{
    public const byte 
        RET = 0xc3,
        NOP = 0x90,
        JMP_NEAR_REL = 0xe9;

    static byte[] JmpQwordPtrPattern = { 0x48, 0xff, 0x25 };

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

    public const int JMP_ABSOLUTE_X64_SIZE = 13;
    public void JmpAbsoluteX64(void* ptr)
    {
        _MovR9((long)ptr);
        _JmpR9();
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

    public bool IsJmpQwordPtr() => Compare(p, JmpQwordPtrPattern);

    public nint GetJmpQwordPtrAddr() => *(nint*)GetJmpQwordPtrPointerAddr();

    public nint GetJmpQwordPtrPointerAddr()
    {
        int offset = GetJmpQwordPtrOpcode();
        var curAddr = (nint)p;
        var instructionSize = 3 + sizeof(int);
        var addr = curAddr + offset + instructionSize;

        return addr;
    }

    public int GetJmpQwordPtrOpcode()
    {
        byte* ptr = p + 3;
        int opcode = *(int*)ptr;
        return opcode;
    }

    public int GetNextInstructionLength() => GetInstructionLength(p);

    public int GetRoundedInstructionsLength(int len)
    {
        int i = 0;

        while (i < len)
            i += GetInstructionLength(p + i);

        return i;
    }
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
    public void _MovR9(long ptr)
    {
        *p++ = 0x49;
        *p++ = 0xb9;
        Write(ptr);
    }
    public void _JmpR9()
    {
        *p++ = 0x41;
        *p++ = 0xff;
        *p++ = 0xe1;
    }
    public void _Ret() => *p++ = RET;
    public void _Nop() => *p++ = NOP;

    public const int _JMP_QWORD_PTR_SIZE = 7;
    public void _JmpQwordPtr(int operand)
    {
        *p++ = 0x48;
        *p++ = 0xff;
        *p++ = 0x25;
        Write(operand);
    }
    #endregion
}