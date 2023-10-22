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
    public const int JMP_X32_REL_SIZE = 5;

    public const byte 
        RET = 0xc3,
        NOP = 0x90,
        JMP_NEAR_REL = 0xe9,
        REX = 0x48;

    static byte[] IATImportPattern = { 0x48, 0xff, 0x25 };

    public ASM(void* ptr)
    {
        p = (byte*)ptr;
        *p = *p;
    }

    byte* p;
    
    public void Copy(void* from, int count)
    {
        MemEx.Copy(p, from, count);
        p += count;
    }

    public bool IsNext(params byte[] bytes) => MemEx.Compare(p, bytes);

    public void Back(int count) => p -= count;
    public void BackTo(void* ptr) => p = (byte*)ptr;

    public bool IsIATImportJmp() => MemEx.Compare(p, IATImportPattern);

    public nint GetATImportAddr()
    {
        byte* ptr = p + 3;
        int offset = *(int*)ptr;
        var curAddr = (nint)p;
        var instructionSize = 3 + sizeof(int);
        var addr = curAddr + offset + instructionSize;

        return addr;
    }

    public int GetNextInstructionLength() => GetInstructionLength(p);

    public int GetRoundedInstructionsLength(int len)
    {
        int i = 0;

        while (i < len)
            i += GetInstructionLength(p + i);

        return i;
    }

    byte GetInstructionLength(byte[] table, byte* instruction)
    {
        byte i = table[*instruction++];
        return i < 0x10 ? i : GetInstructionLength(INSTRUCTION_TABLES[i - 0x10], instruction);
    }

    byte GetInstructionLength(byte* instruction) => GetInstructionLength(INSTRUCTION_TABLE, instruction);

    #region Instructions
    public void Jmp_X32Rel(void* to)
    {
        byte* jumpSrc = p + JMP_X32_REL_SIZE;
        *p++ = JMP_NEAR_REL;
        long opcodeL = (nint)to - (nint)jumpSrc;
        int opcodeI = (int)opcodeL;
        *(int*)p = opcodeI;
        p += sizeof(int);
    }

    public void Ret() => *p++ = RET;

    public void Nop() => *p++ = NOP;

    public void Nop(int count)
    {
        for (int i = 0; i < count; i++)
            Nop();
    }
    #endregion
}