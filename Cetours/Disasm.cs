using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.JavaScript;
using System.Text;
using System.Threading.Tasks;

namespace Cetours;

public unsafe struct COPYENTRY
{
    public COPYENTRY(uint nFixedSize = 4, uint nFixedSize16 = 4, uint nModOffset = 4, uint nRelOffset = 4, uint nFlagBits = 4, void* pfCopy = null)
    {
        this.nFixedSize = nFixedSize;
        this.nFixedSize16 = nFixedSize16;
        this.nModOffset = nModOffset;
        this.nRelOffset = nRelOffset;
        this.nFlagBits = nFlagBits;
        this.pfCopy = pfCopy;
    }

    public uint nFixedSize = 4;
    public uint nFixedSize16 = 4;
    public uint nModOffset = 4;
    public uint nRelOffset = 4;
    public uint nFlagBits = 4;
    public void* pfCopy;
};

public static unsafe class Disasm
{
    public static void* DetourCopyInstruction(void* pDst, void** ppDstPool, void* pSrc, void**ppTarget, int* plExtra)
    {
        CDetourDis oDetourDisasm = new((byte**)ppTarget, plExtra);
        return oDetourDisasm.CopyInstruction((byte*)pDst, (byte*)pSrc);
    }

    public static void* CopyBytesPtr = (delegate* unmanaged<CDetourDis*, COPYENTRY*, byte*, byte*, byte*>)&CopyBytes;
    public static void* CopyBytesJumpPtr = (delegate* unmanaged<CDetourDis*, COPYENTRY*, byte*, byte*, byte*>)&CopyBytesJump;
    public static void* CopyBytesPrefixPtr = (delegate* unmanaged<CDetourDis*, COPYENTRY*, byte*, byte*, byte*>)&CopyBytesPrefix;
    public static void* CopyBytesSegmentPtr = (delegate* unmanaged<CDetourDis*, COPYENTRY*, byte*, byte*, byte*>)&CopyBytesSegment;
    public static void* CopyBytesRaxPtr = (delegate* unmanaged<CDetourDis*, COPYENTRY*, byte*, byte*, byte*>)&CopyBytesRax;
    public static void* CopyF2Ptr = (delegate* unmanaged<CDetourDis*, COPYENTRY*, byte*, byte*, byte*>)&CopyF2;
    public static void* CopyF3Ptr = (delegate* unmanaged<CDetourDis*, COPYENTRY*, byte*, byte*, byte*>)&CopyF3;
    public static void* Copy0FPtr = (delegate* unmanaged<CDetourDis*, COPYENTRY*, byte*, byte*, byte*>)&Copy0F;
    public static void* Copy0F78Ptr = (delegate* unmanaged<CDetourDis*, COPYENTRY*, byte*, byte*, byte*>)&Copy0F78;
    public static void* Copy0F00Ptr = (delegate* unmanaged<CDetourDis*, COPYENTRY*, byte*, byte*, byte*>)&Copy0F00;
    public static void* Copy0FB8Ptr = (delegate* unmanaged<CDetourDis*, COPYENTRY*, byte*, byte*, byte*>)&Copy0FB8;
    public static void* Copy66Ptr = (delegate* unmanaged<CDetourDis*, COPYENTRY*, byte*, byte*, byte*>)&Copy66;
    public static void* Copy67Ptr = (delegate* unmanaged<CDetourDis*, COPYENTRY*, byte*, byte*, byte*>)&Copy67;
    public static void* CopyF6Ptr = (delegate* unmanaged<CDetourDis*, COPYENTRY*, byte*, byte*, byte*>)&CopyF6;
    public static void* CopyF7Ptr = (delegate* unmanaged<CDetourDis*, COPYENTRY*, byte*, byte*, byte*>)&CopyF7;
    public static void* CopyFFPtr = (delegate* unmanaged<CDetourDis*, COPYENTRY*, byte*, byte*, byte*>)&CopyFF;
    public static void* CopyVex2Ptr = (delegate* unmanaged<CDetourDis*, COPYENTRY*, byte*, byte*, byte*>)&CopyVex2;
    public static void* CopyVex3Ptr = (delegate* unmanaged<CDetourDis*, COPYENTRY*, byte*, byte*, byte*>)&CopyVex3;
    public static void* CopyEvexPtr = (delegate* unmanaged<CDetourDis*, COPYENTRY*, byte*, byte*, byte*>)&CopyEvex;
    public static void* CopyXopPtr = (delegate* unmanaged<CDetourDis*, COPYENTRY*, byte*, byte*, byte*>)&CopyXop;
    public static void* InvalidPtr = (delegate* unmanaged<CDetourDis*, COPYENTRY*, byte*, byte*, byte*>)&Invalid;
    public static COPYENTRY ENTRY_DataIgnored = new(0, 0, 0, 0, 0);
    public static COPYENTRY ENTRY_CopyBytes1 = new(1, 1, 0, 0, 0, CopyBytesPtr);
    public static COPYENTRY ENTRY_CopyBytes1Address = new(9, 5, 0, 0, ADDRESS, CopyBytesPtr);
    public static COPYENTRY ENTRY_CopyBytes1Dynamic = new(1, 1, 0, 0, DYNAMIC, CopyBytesPtr);
    public static COPYENTRY ENTRY_CopyBytes2 = new(2, 2, 0, 0, 0, CopyBytesPtr);
    public static COPYENTRY ENTRY_CopyBytes2Jump = ENTRY_DataIgnored with { pfCopy = CopyBytesJumpPtr };
    public static COPYENTRY ENTRY_CopyBytes2CantJump = new(2, 2, 0, 1, NOENLARGE, CopyBytesPtr);
    public static COPYENTRY ENTRY_CopyBytes2Dynamic = new(2, 2, 0, 0, DYNAMIC, CopyBytesPtr);
    public static COPYENTRY ENTRY_CopyBytes3 = new(3, 3, 0, 0, 0, CopyBytesPtr);
    public static COPYENTRY ENTRY_CopyBytes3Dynamic = new(3, 3, 0, 0, DYNAMIC, CopyBytesPtr);
    public static COPYENTRY ENTRY_CopyBytes3Or5 = new(5, 3, 0, 0, 0, CopyBytesPtr);
    public static COPYENTRY ENTRY_CopyBytes3Or5Dynamic = new(5, 3, 0, 0, DYNAMIC, CopyBytesPtr);
    public static COPYENTRY ENTRY_CopyBytes3Or5Rax = new(5, 3, 0, 0, RAX, CopyBytesPtr);
    public static COPYENTRY ENTRY_CopyBytes3Or5Target = new(5, 5, 0, 1, 0, CopyBytesPtr);
    public static COPYENTRY ENTRY_CopyBytes4 = new(4, 4, 0, 0, 0, CopyBytesPtr);
    public static COPYENTRY ENTRY_CopyBytes5 = new(5, 5, 0, 0, 0, CopyBytesPtr);
    public static COPYENTRY ENTRY_CopyBytes5Or7Dynamic = new(7, 5, 0, 0, DYNAMIC, CopyBytesPtr);
    public static COPYENTRY ENTRY_CopyBytes7 = new(7, 7, 0, 0, 0, CopyBytesPtr);
    public static COPYENTRY ENTRY_CopyBytes2Mod = new(2, 2, 1, 0, 0, CopyBytesPtr);
    public static COPYENTRY ENTRY_CopyBytes2ModDynamic = new(2, 2, 1, 0, DYNAMIC, CopyBytesPtr);
    public static COPYENTRY ENTRY_CopyBytes2Mod1 = new(3, 3, 1, 0, 0, CopyBytesPtr);
    public static COPYENTRY ENTRY_CopyBytes2ModOperand = new(6, 4, 1, 0, 0, CopyBytesPtr);
    public static COPYENTRY ENTRY_CopyBytes3Mod = new(3, 3, 2, 0, 0, CopyBytesPtr); 
    public static COPYENTRY ENTRY_CopyBytes3Mod1 = new(4, 4, 2, 0, 0, CopyBytesPtr);
    public static COPYENTRY ENTRY_CopyBytesPrefix = ENTRY_DataIgnored with { pfCopy = CopyBytesPrefixPtr };
    public static COPYENTRY ENTRY_CopyBytesSegment = ENTRY_DataIgnored with { pfCopy = CopyBytesSegmentPtr };
    public static COPYENTRY ENTRY_CopyBytesRax = ENTRY_DataIgnored with { pfCopy = CopyBytesRaxPtr };
    public static COPYENTRY ENTRY_CopyF2 = ENTRY_DataIgnored with { pfCopy = CopyF2Ptr };
    public static COPYENTRY ENTRY_CopyF3 = ENTRY_DataIgnored with { pfCopy = CopyF3Ptr };
    public static COPYENTRY ENTRY_Copy0F = ENTRY_DataIgnored with { pfCopy = Copy0FPtr };
    public static COPYENTRY ENTRY_Copy0F78 = ENTRY_DataIgnored with { pfCopy = Copy0F78Ptr };
    public static COPYENTRY ENTRY_Copy0F00 = ENTRY_DataIgnored with { pfCopy = Copy0F00Ptr };
    public static COPYENTRY ENTRY_Copy0FB8 = ENTRY_DataIgnored with { pfCopy = Copy0FB8Ptr };
    public static COPYENTRY ENTRY_Copy66 = ENTRY_DataIgnored with { pfCopy = Copy66Ptr };
    public static COPYENTRY ENTRY_Copy67 = ENTRY_DataIgnored with { pfCopy = Copy67Ptr };
    public static COPYENTRY ENTRY_CopyF6 = ENTRY_DataIgnored with { pfCopy = CopyF6Ptr };
    public static COPYENTRY ENTRY_CopyF7 = ENTRY_DataIgnored with { pfCopy = CopyF7Ptr };
    public static COPYENTRY ENTRY_CopyFF = ENTRY_DataIgnored with { pfCopy = CopyFFPtr };
    public static COPYENTRY ENTRY_CopyVex2 = ENTRY_DataIgnored with { pfCopy = CopyVex2Ptr };
    public static COPYENTRY ENTRY_CopyVex3 = ENTRY_DataIgnored with { pfCopy = CopyVex3Ptr };
    public static COPYENTRY ENTRY_CopyEvex = ENTRY_DataIgnored with { pfCopy = CopyEvexPtr };
    public static COPYENTRY ENTRY_CopyXop = ENTRY_DataIgnored with { pfCopy = CopyXopPtr }; 
    public static COPYENTRY ENTRY_CopyBytesXop = new(5, 5, 4, 0, 0, CopyBytesPtr); 
    public static COPYENTRY ENTRY_CopyBytesXop1 = new(6, 6, 4, 0, 0, CopyBytesPtr); 
    public static COPYENTRY ENTRY_CopyBytesXop4 = new(9, 9, 4, 0, 0, CopyBytesPtr);
    public static COPYENTRY ENTRY_Invalid = ENTRY_DataIgnored with { pfCopy = InvalidPtr };

    public static byte* s_pbModuleBeg;
    public static byte* s_pbModuleEnd;
    public static bool s_fLimitReferencesToModule;

    [UnmanagedCallersOnly]
    public static byte* CopyBytes(CDetourDis* t, COPYENTRY* pEntry, byte* pbDst, byte* pbSrc)
    {
        uint nBytesFixed;

        var t2 = t;

        uint nModOffset = pEntry->nModOffset;
        uint nFlagBits = pEntry->nFlagBits;
        uint nFixedSize = pEntry->nFixedSize;
        uint nFixedSize16 = pEntry->nFixedSize16;

        if ((nFlagBits & ADDRESS) != 0)
        {
            nBytesFixed = t->m_bAddressOverride ? nFixedSize16 : nFixedSize;
        }
        else if (t->m_bRaxOverride)
        {
            nBytesFixed = (uint)(nFixedSize + (((nFlagBits & RAX) != 0) ? 4 : 0));
        }
        else
        {
            nBytesFixed = t->m_bOperandOverride ? nFixedSize16 : nFixedSize;
        }

        uint nBytes = nBytesFixed;
        uint nRelOffset = pEntry->nRelOffset;
        uint cbTarget = nBytes - nRelOffset;
        if (nModOffset > 0)
        {
            byte bModRm = pbSrc[nModOffset];
            byte bFlags = s_rbModRm[bModRm];

            nBytes += (uint)(bFlags & NOTSIB);

            if ((bFlags & SIB) != 0)
            {
                byte bSib = pbSrc[nModOffset + 1];

                if ((bSib & 0x07) == 0x05)
                {
                    if ((bModRm & 0xc0) == 0x00)
                    {
                        nBytes += 4;
                    }
                    else if ((bModRm & 0xc0) == 0x40)
                    {
                        nBytes += 1;
                    }
                    else if ((bModRm & 0xc0) == 0x80)
                    {
                        nBytes += 4;
                    }
                }
                cbTarget = nBytes - nRelOffset;
            }
            else if ((bFlags & RIP) != 0)
            {
                nRelOffset = nModOffset + 1;
                cbTarget = 4;
            }
        }
        CopyMemory(pbDst, pbSrc, (int)nBytes);

        if (nRelOffset != 0)
        {
            *t->m_ppbTarget = t->AdjustTarget(pbDst, pbSrc, nBytes, nRelOffset, cbTarget);
            if (pEntry->nRelOffset == 0)
            {
                *t->m_ppbTarget = null;
            }
        }
        if ((nFlagBits & NOENLARGE) != 0)
        {
            *t->m_plExtra = -*t->m_plExtra;
        }
        if ((nFlagBits & DYNAMIC) != 0)
        {
            *t->m_ppbTarget = (byte*)DETOUR_INSTRUCTION_TARGET_DYNAMIC;
        }
        return pbSrc + nBytes;
    }

    [UnmanagedCallersOnly]
    public static byte* CopyBytesPrefix(CDetourDis* t, COPYENTRY* pEntry, byte* pbDst, byte* pbSrc)
    {
        var t2 = *t;

        pbDst[0] = pbSrc[0];
        int index = pbSrc[1];

        COPYENTRY pEntryNF = s_rceCopyTable[index];
        return ((delegate* unmanaged<CDetourDis*, COPYENTRY*, byte*, byte*, byte*>)pEntryNF.pfCopy)(t, pEntry = &pEntryNF, pbDst + 1, pbSrc + 1);
    }

    [UnmanagedCallersOnly]
    public static  byte* CopyBytesSegment(CDetourDis* t, COPYENTRY* pEntry, byte* pbDst, byte* pbSrc)
    {
        var v2 = &t;

        t->m_nSegmentOverride = pbSrc[0];
        return ((delegate* unmanaged<CDetourDis*, COPYENTRY*, byte*, byte*, byte*>)&CopyBytesPrefix)(t, null, pbDst, pbSrc);
    }

    [UnmanagedCallersOnly]
    public static byte* CopyBytesRax(CDetourDis* t, COPYENTRY* pEntry, byte* pbDst, byte* pbSrc)
    {
        if ((pbSrc[0] & 0x8) != 0)
        {
            t->m_bRaxOverride = true;
        }
        return ((delegate* unmanaged<CDetourDis*, COPYENTRY*, byte*, byte*, byte*>)&CopyBytesPrefix)(t, null, pbDst, pbSrc);
    }

    [UnmanagedCallersOnly]
    public static byte* CopyBytesJump(CDetourDis* t, COPYENTRY* pEntry, byte* pbDst, byte* pbSrc)
    {
        //(void)pEntry;

        void* pvSrcAddr = &pbSrc[1];
        void* pvDstAddr = null;
        long* nOldOffset = (long*)*(byte**)&pvSrcAddr;
        long* nNewOffset = null;

        *t->m_ppbTarget = pbSrc + 2 + (nint)nOldOffset;

        if (pbSrc[0] == 0xeb)
        {
            pbDst[0] = 0xe9;
            pvDstAddr = &pbDst[1];
            nNewOffset = nOldOffset - ((pbDst - pbSrc) + 3);
            **(int**)&pvDstAddr = (int)nNewOffset;

            *t->m_plExtra = 3;
            return pbSrc + 2;
        }

        pbDst[0] = 0x0f;
        pbDst[1] = (byte)(0x80 | (pbSrc[0] & 0xf));
        pvDstAddr = &pbDst[2];
        nNewOffset = nOldOffset - ((pbDst - pbSrc) + 4);
        **(int**)&pvDstAddr = (int)nNewOffset;

        *t->m_plExtra = 4;
        return pbSrc + 2;
    }

    [UnmanagedCallersOnly]
    public static byte* Invalid(CDetourDis* t, COPYENTRY* pEntry, byte* pbDst, byte* pbSrc)
    {
        //(void)pbDst;
        //(void)pEntry;
        return pbSrc + 1;
    }

    [UnmanagedCallersOnly]
    public static byte* Copy0F(CDetourDis* t, COPYENTRY* pEntry, byte* pbDst, byte* pbSrc)
    {
        pbDst[0] = pbSrc[0];
        COPYENTRY pEntryNF = s_rceCopyTable0F[pbSrc[1]];
        return ((delegate* unmanaged<CDetourDis*, COPYENTRY*, byte*, byte*, byte*>)pEntry->pfCopy)(t, pEntry = &pEntryNF, pbDst + 1, pbSrc + 1);
    }

    [UnmanagedCallersOnly]
    public static byte* Copy0F78(CDetourDis* t, COPYENTRY* pEntryUnused, byte* pbDst, byte* pbSrc)
    {
        COPYENTRY vmread = ENTRY_CopyBytes2Mod;
        COPYENTRY extrq_insertq = ENTRY_CopyBytes4;

        COPYENTRY* pEntry = ((t->m_bF2 || t->m_bOperandOverride) ? &extrq_insertq : &vmread);

        return ((delegate* unmanaged<CDetourDis*, COPYENTRY*, byte*, byte*, byte*>)pEntry->pfCopy)(t, pEntry, pbDst, pbSrc);
    }

    [UnmanagedCallersOnly]
    public static byte* Copy0F00(CDetourDis* t, COPYENTRY* pEntryUnused, byte* pbDst, byte* pbSrc)
    {
        COPYENTRY other = ENTRY_CopyBytes2Mod;
        COPYENTRY jmpe = ENTRY_CopyBytes2ModDynamic;

        COPYENTRY* pEntry = (((6 << 3) == ((7 << 3) & pbSrc[1])) ? &jmpe : &other);
        return ((delegate* unmanaged<CDetourDis*, COPYENTRY*, byte*, byte*, byte*>)pEntry->pfCopy)(t, pEntry, pbDst, pbSrc);
    }

    [UnmanagedCallersOnly]
    public static byte* Copy0FB8(CDetourDis* t, COPYENTRY* pEntryUnused, byte* pbDst, byte* pbSrc)
    {
        COPYENTRY popcnt = ENTRY_CopyBytes2Mod;
        COPYENTRY jmpe = ENTRY_CopyBytes3Or5Dynamic;
        COPYENTRY* pEntry = t->m_bF3 ? &popcnt : &jmpe;
        return ((delegate* unmanaged<CDetourDis*, COPYENTRY*, byte*, byte*, byte*>)pEntry->pfCopy)(t, pEntry, pbDst, pbSrc);
    }

    [UnmanagedCallersOnly]
    public static byte* Copy66(CDetourDis* t, COPYENTRY* pEntry, byte* pbDst, byte* pbSrc)
    {
        t->m_bOperandOverride = true;
        return ((delegate* unmanaged<CDetourDis*, COPYENTRY*, byte*, byte*, byte*>)&CopyBytesPrefix)(t, pEntry, pbDst, pbSrc);
    }

    [UnmanagedCallersOnly]
    public static byte* Copy67(CDetourDis* t, COPYENTRY* pEntry, byte* pbDst, byte* pbSrc)
    {
        t->m_bAddressOverride = true;
        return ((delegate* unmanaged<CDetourDis*, COPYENTRY*, byte*, byte*, byte*>)&CopyBytesPrefix)(t, pEntry, pbDst, pbSrc);
    }

    [UnmanagedCallersOnly]
    public static byte* CopyF2(CDetourDis* t, COPYENTRY* pEntry, byte* pbDst, byte* pbSrc)
    {
        t->m_bF2 = true;
        return ((delegate* unmanaged<CDetourDis*, COPYENTRY*, byte*, byte*, byte*>)&CopyBytesPrefix)(t, pEntry, pbDst, pbSrc);
    }

    [UnmanagedCallersOnly]
    public static byte* CopyF3(CDetourDis* t, COPYENTRY* pEntry, byte* pbDst, byte* pbSrc)
    {
        t->m_bF3 = true;
        return ((delegate* unmanaged<CDetourDis*, COPYENTRY*, byte*, byte*, byte*>)&CopyBytesPrefix)(t, pEntry, pbDst, pbSrc);
    }

    [UnmanagedCallersOnly]
    public static byte* CopyF6(CDetourDis* t, COPYENTRY* pEntry, byte* pbDst, byte* pbSrc)
    {
        //(void)pEntry;

        if (0x00 == (0x38 & pbSrc[1]))
        {
            COPYENTRY ce = ENTRY_CopyBytes2Mod1;
            return ((delegate* unmanaged<CDetourDis*, COPYENTRY*, byte*, byte*, byte*>)ce.pfCopy)(t, &ce, pbDst, pbSrc);
        }

        {
            COPYENTRY ce = ENTRY_CopyBytes2Mod;
            return ((delegate* unmanaged<CDetourDis*, COPYENTRY*, byte*, byte*, byte*>)ce.pfCopy)(t, &ce, pbDst, pbSrc);
        }
    }

    [UnmanagedCallersOnly]
    public static byte* CopyF7(CDetourDis* t, COPYENTRY* pEntry, byte* pbDst, byte* pbSrc)
    {
        //(void)pEntry;

        if (0x00 == (0x38 & pbSrc[1]))
        {
            COPYENTRY ce = ENTRY_CopyBytes2ModOperand;
            return ((delegate* unmanaged<CDetourDis*, COPYENTRY*, byte*, byte*, byte*>)ce.pfCopy)(t, &ce, pbDst, pbSrc);
        }

        {
            COPYENTRY ce = ENTRY_CopyBytes2Mod;
            return ((delegate* unmanaged<CDetourDis*, COPYENTRY*, byte*, byte*, byte*>)ce.pfCopy)(t, &ce, pbDst, pbSrc);
        }
    }

    [UnmanagedCallersOnly]
    public static byte* CopyFF(CDetourDis* t, COPYENTRY* pEntry, byte* pbDst, byte* pbSrc)
    {
        //(void)pEntry;

        COPYENTRY ce = ENTRY_CopyBytes2Mod;
        byte* pbOut = ((delegate* unmanaged<CDetourDis*, COPYENTRY*, byte*, byte*, byte*>)ce.pfCopy)(t, &ce, pbDst, pbSrc);

        byte b1 = pbSrc[1];

        if (0x15 == b1 || 0x25 == b1)
        {
            if (t->m_nSegmentOverride != 0x64 && t->m_nSegmentOverride != 0x65)
            {
                int offset = *(int*)&pbSrc[2];
                byte** ppbTarget = (byte**)(pbSrc + 6 + offset);
                if (s_fLimitReferencesToModule &&
                    (ppbTarget < (void*)s_pbModuleBeg || ppbTarget >= (void*)s_pbModuleEnd))
                {

                    *t->m_ppbTarget = (byte*)DETOUR_INSTRUCTION_TARGET_DYNAMIC;
                }
                else
                {
                    *t->m_ppbTarget = *ppbTarget;
                }
            }
            else
            {
                *t->m_ppbTarget = (byte*)DETOUR_INSTRUCTION_TARGET_DYNAMIC;
            }
        }
        else if (0x10 == (0x30 & b1) ||
                 0x20 == (0x30 & b1))
        {
            *t->m_ppbTarget = (byte*)DETOUR_INSTRUCTION_TARGET_DYNAMIC;
        }
        return pbOut;
    }

    [UnmanagedCallersOnly]
    public static byte* CopyVexEvexCommon(CDetourDis* t, byte m, byte* pbDst, byte* pbSrc, byte p, byte fp16)
    {
        COPYENTRY ceF38 = ENTRY_CopyBytes2Mod;
        COPYENTRY ceF3A = ENTRY_CopyBytes2Mod1;
        COPYENTRY ceInvalid = ENTRY_Invalid;

        switch (p & 3)
        {
            case 0: break;
            case 1: t->m_bOperandOverride = true; break;
            case 2: t->m_bF3 = true; break;
            case 3: t->m_bF2 = true; break;
        }

        COPYENTRY* pEntry;

        switch (m | fp16)
        {
            default: return ((delegate* unmanaged<CDetourDis*, COPYENTRY*, byte*, byte*, byte*>)&Invalid)(t, &ceInvalid, pbDst, pbSrc);
            case 1:
                {
                    COPYENTRY pEntryFN = s_rceCopyTable0F[pbSrc[0]];
                    pEntry = &pEntryFN;
                    return ((delegate* unmanaged<CDetourDis*, COPYENTRY*, byte*, byte*, byte*>)pEntry->pfCopy)(t, pEntry, pbDst, pbSrc);
                }
            case 5:
            case 6:
            case 2: return ((delegate* unmanaged<CDetourDis*, COPYENTRY*, byte*, byte*, byte*>)&CopyBytes)(t, &ceF38, pbDst, pbSrc);
            case 3: return ((delegate* unmanaged<CDetourDis*, COPYENTRY*, byte*, byte*, byte*>)&CopyBytes)(t, &ceF3A, pbDst, pbSrc);
        }
    }

    [UnmanagedCallersOnly]
    public static byte* CopyVexCommon(CDetourDis* t, byte m, byte* pbDst, byte* pbSrc)
    {
        t->m_bVex = true;
        byte p = (byte)(pbSrc[-1] & 3);
        return ((delegate* unmanaged<CDetourDis*, byte, byte*, byte*, byte, byte, byte*>)&CopyVexEvexCommon)(t, m, pbDst, pbSrc, p, 0);
    }

    [UnmanagedCallersOnly]
    public static byte* CopyVex3(CDetourDis* t, COPYENTRY* pEntry, byte* pbDst, byte* pbSrc)
    {
        pbDst[0] = pbSrc[0];
        pbDst[1] = pbSrc[1];
        pbDst[2] = pbSrc[2];
        t->m_bRaxOverride |= !!((pbSrc[2] & 0x80) != 0);
        return ((delegate* unmanaged<CDetourDis*, byte, byte*, byte*, byte*>)&CopyVexCommon)(t, (byte)(pbSrc[1] & 0x1F), pbDst + 3, pbSrc + 3);
    }

    [UnmanagedCallersOnly]
    public static byte* CopyVex2(CDetourDis* t, COPYENTRY* pEntry, byte* pbDst, byte* pbSrc)
    {
        pbDst[0] = pbSrc[0];
        pbDst[1] = pbSrc[1];
        return ((delegate* unmanaged<CDetourDis*, byte, byte*, byte*, byte*>)&CopyVexCommon)(t, 1, pbDst + 2, pbSrc + 2);
    }

    [UnmanagedCallersOnly]
    public static byte* CopyEvex(CDetourDis* t, COPYENTRY* pEntry, byte* pbDst, byte* pbSrc)
    {
        byte p0 = pbSrc[1];

        COPYENTRY ceInvalid = ENTRY_Invalid;

        if ((p0 & 8u) != 0)
            return ((delegate* unmanaged<CDetourDis*, COPYENTRY*, byte*, byte*, byte*>)&Invalid)(t, &ceInvalid, pbDst, pbSrc);

        byte p1 = pbSrc[2];

        if ((p1 & 0x04) != 0x04)
            return ((delegate* unmanaged<CDetourDis*, COPYENTRY*, byte*, byte*, byte*>)&Invalid)(t, &ceInvalid, pbDst, pbSrc);

        *(uint*)pbDst = *(uint*)pbSrc;

        t->m_bEvex = true;

        return ((delegate* unmanaged<CDetourDis*, byte, byte*, byte*, byte, byte, byte*>)&CopyVexEvexCommon)(t, (byte)(p0 & 3), pbDst + 4, pbSrc + 4, (byte)(p1 & 3), (byte)(p0 & 4));
    }

    [UnmanagedCallersOnly]
    public static byte* CopyXop(CDetourDis* t, COPYENTRY* pEntry, byte* pbDst, byte* pbSrc)
    {
        COPYENTRY cePop = ENTRY_CopyBytes2Mod;
        COPYENTRY ceXop = ENTRY_CopyBytesXop;
        COPYENTRY ceXop1 = ENTRY_CopyBytesXop1;
        COPYENTRY ceXop4 = ENTRY_CopyBytesXop4;

        byte m = (byte)(pbSrc[1] & 0x1F);
        switch (m)
        {
            default:
                return ((delegate* unmanaged<CDetourDis*, COPYENTRY*, byte*, byte*, byte*>)&CopyBytes)(t, &cePop, pbDst, pbSrc);

            case 8:
                return ((delegate* unmanaged<CDetourDis*, COPYENTRY*, byte*, byte*, byte*>)&CopyBytes)(t, &ceXop1, pbDst, pbSrc);

            case 9:
                return ((delegate* unmanaged<CDetourDis*, COPYENTRY*, byte*, byte*, byte*>)&CopyBytes)(t, &ceXop, pbDst, pbSrc);

            case 10:
                return ((delegate* unmanaged<CDetourDis*, COPYENTRY*, byte*, byte*, byte*>)&CopyBytes)(t, &ceXop4, pbDst, pbSrc);
        }
    }

    public static byte[] s_rbModRm = new byte[256] {
        0,0,0,0, SIB|1,RIP|4,0,0, 0,0,0,0, SIB|1,RIP|4,0,0,
        0,0,0,0, SIB|1,RIP|4,0,0, 0,0,0,0, SIB|1,RIP|4,0,0,
        0,0,0,0, SIB|1,RIP|4,0,0, 0,0,0,0, SIB|1,RIP|4,0,0,
        0,0,0,0, SIB|1,RIP|4,0,0, 0,0,0,0, SIB|1,RIP|4,0,0,
        1,1,1,1, 2,1,1,1, 1,1,1,1, 2,1,1,1,                
        1,1,1,1, 2,1,1,1, 1,1,1,1, 2,1,1,1,                
        1,1,1,1, 2,1,1,1, 1,1,1,1, 2,1,1,1,                
        1,1,1,1, 2,1,1,1, 1,1,1,1, 2,1,1,1,                
        4,4,4,4, 5,4,4,4, 4,4,4,4, 5,4,4,4,                
        4,4,4,4, 5,4,4,4, 4,4,4,4, 5,4,4,4,                
        4,4,4,4, 5,4,4,4, 4,4,4,4, 5,4,4,4,                
        4,4,4,4, 5,4,4,4, 4,4,4,4, 5,4,4,4,                
        0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,                
        0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,                
        0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,                
        0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0                 
    };
    public static COPYENTRY[] s_rceCopyTable =
    {
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2,                         
        ENTRY_CopyBytes3Or5,
        ENTRY_Invalid,                            
        ENTRY_Invalid,
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2,                         
        ENTRY_CopyBytes3Or5, 
        ENTRY_Invalid,
        ENTRY_Copy0F,                             
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2,                         
        ENTRY_CopyBytes3Or5,
        ENTRY_Invalid,                            
        ENTRY_Invalid,
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2,                         
        ENTRY_CopyBytes3Or5,                      
        ENTRY_Invalid,                            
        ENTRY_Invalid, 
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2,                         
        ENTRY_CopyBytes3Or5,                      
        ENTRY_CopyBytesSegment,                   
        ENTRY_Invalid,                            
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2,                         
        ENTRY_CopyBytes3Or5,                      
        ENTRY_CopyBytesSegment,     
        ENTRY_Invalid, 
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2,                         
        ENTRY_CopyBytes3Or5,                      
        ENTRY_CopyBytesSegment,   
        ENTRY_Invalid,  
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2,                         
        ENTRY_CopyBytes3Or5,                      
        ENTRY_CopyBytesSegment,       
        ENTRY_Invalid, 
        ENTRY_CopyBytesRax,                       
        ENTRY_CopyBytesRax,                       
        ENTRY_CopyBytesRax,                       
        ENTRY_CopyBytesRax,                       
        ENTRY_CopyBytesRax,                       
        ENTRY_CopyBytesRax,                       
        ENTRY_CopyBytesRax,                       
        ENTRY_CopyBytesRax,                       
        ENTRY_CopyBytesRax,                       
        ENTRY_CopyBytesRax,                       
        ENTRY_CopyBytesRax,                       
        ENTRY_CopyBytesRax,                       
        ENTRY_CopyBytesRax,                       
        ENTRY_CopyBytesRax,                       
        ENTRY_CopyBytesRax,                       
        ENTRY_CopyBytesRax,                       
        ENTRY_CopyBytes1,                         
        ENTRY_CopyBytes1,                         
        ENTRY_CopyBytes1,                         
        ENTRY_CopyBytes1,                         
        ENTRY_CopyBytes1,                         
        ENTRY_CopyBytes1,                         
        ENTRY_CopyBytes1,                         
        ENTRY_CopyBytes1,                         
        ENTRY_CopyBytes1,                         
        ENTRY_CopyBytes1,                         
        ENTRY_CopyBytes1,                         
        ENTRY_CopyBytes1,                         
        ENTRY_CopyBytes1,                         
        ENTRY_CopyBytes1,                         
        ENTRY_CopyBytes1,                         
        ENTRY_CopyBytes1,    
        ENTRY_Invalid,                            
        ENTRY_Invalid,                            
        ENTRY_CopyEvex,   
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytesSegment,                   
        ENTRY_CopyBytesSegment,                   
        ENTRY_Copy66,                             
        ENTRY_Copy67,                             
        ENTRY_CopyBytes3Or5,                      
        ENTRY_CopyBytes2ModOperand,               
        ENTRY_CopyBytes2,                         
        ENTRY_CopyBytes2Mod1,                     
        ENTRY_CopyBytes1,                         
        ENTRY_CopyBytes1,                         
        ENTRY_CopyBytes1,                         
        ENTRY_CopyBytes1,                         
        ENTRY_CopyBytes2Jump,                     
        ENTRY_CopyBytes2Jump,                     
        ENTRY_CopyBytes2Jump,                     
        ENTRY_CopyBytes2Jump,                     
        ENTRY_CopyBytes2Jump,                     
        ENTRY_CopyBytes2Jump,                     
        ENTRY_CopyBytes2Jump,                     
        ENTRY_CopyBytes2Jump,                     
        ENTRY_CopyBytes2Jump,                     
        ENTRY_CopyBytes2Jump,                     
        ENTRY_CopyBytes2Jump,                     
        ENTRY_CopyBytes2Jump,                     
        ENTRY_CopyBytes2Jump,                     
        ENTRY_CopyBytes2Jump,                     
        ENTRY_CopyBytes2Jump,                     
        ENTRY_CopyBytes2Jump,                     
        ENTRY_CopyBytes2Mod1,                     
        ENTRY_CopyBytes2ModOperand,     
        ENTRY_Invalid,      
        ENTRY_CopyBytes2Mod1,                     
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyXop,                            
        ENTRY_CopyBytes1,                         
        ENTRY_CopyBytes1,                         
        ENTRY_CopyBytes1,                         
        ENTRY_CopyBytes1,                         
        ENTRY_CopyBytes1,                         
        ENTRY_CopyBytes1,                         
        ENTRY_CopyBytes1,                         
        ENTRY_CopyBytes1,                         
        ENTRY_CopyBytes1,                         
        ENTRY_CopyBytes1, 
        ENTRY_Invalid,  
        ENTRY_CopyBytes1,                         
        ENTRY_CopyBytes1,                         
        ENTRY_CopyBytes1,                         
        ENTRY_CopyBytes1,                         
        ENTRY_CopyBytes1,                         
        ENTRY_CopyBytes1Address,                  
        ENTRY_CopyBytes1Address,                  
        ENTRY_CopyBytes1Address,                  
        ENTRY_CopyBytes1Address,                  
        ENTRY_CopyBytes1,                         
        ENTRY_CopyBytes1,                         
        ENTRY_CopyBytes1,                         
        ENTRY_CopyBytes1,                         
        ENTRY_CopyBytes2,                         
        ENTRY_CopyBytes3Or5,                      
        ENTRY_CopyBytes1,                         
        ENTRY_CopyBytes1,                         
        ENTRY_CopyBytes1,                         
        ENTRY_CopyBytes1,                         
        ENTRY_CopyBytes1,                         
        ENTRY_CopyBytes1,                         
        ENTRY_CopyBytes2,                         
        ENTRY_CopyBytes2,                         
        ENTRY_CopyBytes2,                         
        ENTRY_CopyBytes2,                         
        ENTRY_CopyBytes2,                         
        ENTRY_CopyBytes2,                         
        ENTRY_CopyBytes2,                         
        ENTRY_CopyBytes2,                         
        ENTRY_CopyBytes3Or5Rax,                   
        ENTRY_CopyBytes3Or5Rax,                   
        ENTRY_CopyBytes3Or5Rax,                   
        ENTRY_CopyBytes3Or5Rax,                   
        ENTRY_CopyBytes3Or5Rax,                   
        ENTRY_CopyBytes3Or5Rax,                   
        ENTRY_CopyBytes3Or5Rax,                   
        ENTRY_CopyBytes3Or5Rax,                   
        ENTRY_CopyBytes2Mod1,                     
        ENTRY_CopyBytes2Mod1,                     
        ENTRY_CopyBytes3,                         
        ENTRY_CopyBytes1,                         
        ENTRY_CopyVex3,                           
        ENTRY_CopyVex2,                           
        ENTRY_CopyBytes2Mod1,                     
        ENTRY_CopyBytes2ModOperand,               
        ENTRY_CopyBytes4,                         
        ENTRY_CopyBytes1,                         
        ENTRY_CopyBytes3Dynamic,                  
        ENTRY_CopyBytes1Dynamic,                  
        ENTRY_CopyBytes1Dynamic,                  
        ENTRY_CopyBytes2Dynamic,
        ENTRY_Invalid,     
        ENTRY_CopyBytes1Dynamic,                  
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,  
        ENTRY_Invalid,                            
        ENTRY_Invalid,  
        ENTRY_Invalid,                            
        ENTRY_CopyBytes1,                         
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2CantJump,                 
        ENTRY_CopyBytes2CantJump,                 
        ENTRY_CopyBytes2CantJump,                 
        ENTRY_CopyBytes2CantJump,                 
        ENTRY_CopyBytes2,                         
        ENTRY_CopyBytes2,                         
        ENTRY_CopyBytes2,                         
        ENTRY_CopyBytes2,                         
        ENTRY_CopyBytes3Or5Target,                
        ENTRY_CopyBytes3Or5Target,  
        ENTRY_Invalid, 
        ENTRY_CopyBytes2Jump,                     
        ENTRY_CopyBytes1,                         
        ENTRY_CopyBytes1,                         
        ENTRY_CopyBytes1,                         
        ENTRY_CopyBytes1,                         
        ENTRY_CopyBytesPrefix,                    
        ENTRY_CopyBytes1Dynamic,                  
        ENTRY_CopyF2,                             
        ENTRY_CopyF3,                             
        ENTRY_CopyBytes1,   
        ENTRY_CopyBytes1,   
        ENTRY_CopyF6,       
        ENTRY_CopyF7,       
        ENTRY_CopyBytes1,   
        ENTRY_CopyBytes1,   
        ENTRY_CopyBytes1,   
        ENTRY_CopyBytes1,   
        ENTRY_CopyBytes1,   
        ENTRY_CopyBytes1,   
        ENTRY_CopyBytes2Mod,
        ENTRY_CopyFF,       
    };
    public static COPYENTRY[] s_rceCopyTable0F =
    {
        ENTRY_CopyBytes2Mod, 
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_Invalid,                            
        ENTRY_CopyBytes1,                         
        ENTRY_CopyBytes1,                         
        ENTRY_CopyBytes1,                         
        ENTRY_CopyBytes1,                         
        ENTRY_CopyBytes1,                         
        ENTRY_Invalid,                            
        ENTRY_CopyBytes1,                         
        ENTRY_Invalid,                            
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes1,                         
        ENTRY_CopyBytes2Mod1,                     
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod, 
        ENTRY_Invalid, 
        ENTRY_Invalid,
        ENTRY_Invalid,      
        ENTRY_Invalid,                            
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes1,                         
        ENTRY_CopyBytes1,                         
        ENTRY_CopyBytes1,                         
        ENTRY_CopyBytes1,                         
        ENTRY_CopyBytes1,                         
        ENTRY_CopyBytes1,                         
        ENTRY_Invalid,                            
        ENTRY_CopyBytes1,                         
        ENTRY_CopyBytes3Mod,                      
        ENTRY_Invalid,                            
        ENTRY_CopyBytes3Mod1,                     
        ENTRY_Invalid,                            
        ENTRY_Invalid,                            
        ENTRY_Invalid,                            
        ENTRY_Invalid,                            
        ENTRY_Invalid,                            
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod1,                     
        ENTRY_CopyBytes2Mod1,                     
        ENTRY_CopyBytes2Mod1,                     
        ENTRY_CopyBytes2Mod1,                     
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes1,
        ENTRY_Copy0F78,
        ENTRY_CopyBytes2Mod,                      
        ENTRY_Invalid,                            
        ENTRY_Invalid,                            
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes3Or5Target,                
        ENTRY_CopyBytes3Or5Target,                
        ENTRY_CopyBytes3Or5Target,                
        ENTRY_CopyBytes3Or5Target,                
        ENTRY_CopyBytes3Or5Target,                
        ENTRY_CopyBytes3Or5Target,                
        ENTRY_CopyBytes3Or5Target,                
        ENTRY_CopyBytes3Or5Target,                
        ENTRY_CopyBytes3Or5Target,                
        ENTRY_CopyBytes3Or5Target,                
        ENTRY_CopyBytes3Or5Target,                
        ENTRY_CopyBytes3Or5Target,                
        ENTRY_CopyBytes3Or5Target,                
        ENTRY_CopyBytes3Or5Target,                
        ENTRY_CopyBytes3Or5Target,                
        ENTRY_CopyBytes3Or5Target,                
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes1,                         
        ENTRY_CopyBytes1,                         
        ENTRY_CopyBytes1,                         
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod1,                     
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes1,                         
        ENTRY_CopyBytes1,                         
        ENTRY_CopyBytes1,                         
        ENTRY_CopyBytes2Mod,                      
        ENTRY_CopyBytes2Mod1,                     
        ENTRY_CopyBytes2Mod,
        ENTRY_CopyBytes2Mod,
        ENTRY_CopyBytes2Mod,
        ENTRY_CopyBytes2Mod,
        ENTRY_CopyBytes2Mod,
        ENTRY_CopyBytes2Mod,
        ENTRY_CopyBytes2Mod,
        ENTRY_CopyBytes2Mod,
        ENTRY_CopyBytes2Mod,
        ENTRY_CopyBytes2Mod,
        ENTRY_CopyBytes2Mod,
        ENTRY_CopyBytes2Mod,   
        ENTRY_Invalid,                           
        ENTRY_CopyBytes2Mod1,                    
        ENTRY_CopyBytes2Mod,                     
        ENTRY_CopyBytes2Mod,                     
        ENTRY_CopyBytes2Mod,                     
        ENTRY_CopyBytes2Mod,                     
        ENTRY_CopyBytes2Mod,                     
        ENTRY_CopyBytes2Mod,                     
        ENTRY_CopyBytes2Mod,                     
        ENTRY_CopyBytes2Mod1,                    
        ENTRY_CopyBytes2Mod,                     
        ENTRY_CopyBytes2Mod1,                    
        ENTRY_CopyBytes2Mod1,                    
        ENTRY_CopyBytes2Mod1,                    
        ENTRY_CopyBytes2Mod,                     
        ENTRY_CopyBytes1,                        
        ENTRY_CopyBytes1,                        
        ENTRY_CopyBytes1,                        
        ENTRY_CopyBytes1,                        
        ENTRY_CopyBytes1,                        
        ENTRY_CopyBytes1,                        
        ENTRY_CopyBytes1,                        
        ENTRY_CopyBytes1,                        
        ENTRY_CopyBytes2Mod,                     
        ENTRY_CopyBytes2Mod,                     
        ENTRY_CopyBytes2Mod,                     
        ENTRY_CopyBytes2Mod,                     
        ENTRY_CopyBytes2Mod,                     
        ENTRY_CopyBytes2Mod,                     
        ENTRY_CopyBytes2Mod,                     
        ENTRY_CopyBytes2Mod,                     
        ENTRY_CopyBytes2Mod,                     
        ENTRY_CopyBytes2Mod,                     
        ENTRY_CopyBytes2Mod,                     
        ENTRY_CopyBytes2Mod,                     
        ENTRY_CopyBytes2Mod,                     
        ENTRY_CopyBytes2Mod,                     
        ENTRY_CopyBytes2Mod,                     
        ENTRY_CopyBytes2Mod,                     
        ENTRY_CopyBytes2Mod,                    
        ENTRY_CopyBytes2Mod,                     
        ENTRY_CopyBytes2Mod,                     
        ENTRY_CopyBytes2Mod,                     
        ENTRY_CopyBytes2Mod,                     
        ENTRY_CopyBytes2Mod,                     
        ENTRY_CopyBytes2Mod,                     
        ENTRY_CopyBytes2Mod,                     
        ENTRY_CopyBytes2Mod,                     
        ENTRY_CopyBytes2Mod,                     
        ENTRY_CopyBytes2Mod,                     
        ENTRY_CopyBytes2Mod,                     
        ENTRY_CopyBytes2Mod,                     
        ENTRY_CopyBytes2Mod,                     
        ENTRY_CopyBytes2Mod,                     
        ENTRY_CopyBytes2Mod,                     
        ENTRY_CopyBytes2Mod,                     
        ENTRY_CopyBytes2Mod,                     
        ENTRY_CopyBytes2Mod,                     
        ENTRY_CopyBytes2Mod,                     
        ENTRY_CopyBytes2Mod,                     
        ENTRY_CopyBytes2Mod,                     
        ENTRY_CopyBytes2Mod,                     
        ENTRY_CopyBytes2Mod,                     
        ENTRY_CopyBytes2Mod,                     
        ENTRY_CopyBytes2Mod,                     
        ENTRY_CopyBytes2Mod,                     
        ENTRY_CopyBytes2Mod,                     
        ENTRY_CopyBytes2Mod,                     
        ENTRY_CopyBytes2Mod,                     
        ENTRY_CopyBytes2Mod,                     
        ENTRY_Invalid,                           
    };
}

public unsafe struct CDetourDis
{
    public CDetourDis(byte** ppbTarget, int* plExtra)
    {
        m_bOperandOverride = m_bAddressOverride = m_bRaxOverride = m_bF2 = m_bF3 = m_bVex = m_bEvex = false;

        m_ppbTarget = (nint)ppbTarget != 0 ? ppbTarget : (byte**)New((nint)m_pbScratchTarget);
        m_plExtra = (nint)plExtra != 0? plExtra : New(m_lScratchExtra);

        *m_ppbTarget = (byte*)0;
        *m_plExtra = 0;
    }

    public bool m_bOperandOverride;
    public bool m_bAddressOverride;
    public bool m_bRaxOverride;
    public bool m_bVex;
    public bool m_bEvex;
    public bool m_bF2;
    public bool m_bF3;
    public byte m_nSegmentOverride;

    public byte** m_ppbTarget = (byte**)New((nint)New((byte)0));
    public int* m_plExtra = New(0);

    public int m_lScratchExtra;
    public byte* m_pbScratchTarget = New((byte)0);
    public fixed byte m_rbScratchDst[64];

    public byte* CopyInstruction(byte* pbDst, byte* pbSrc)
    {
        if (pbDst == null)
        {
            fixed (byte* m_rbScratchDstPtr = m_rbScratchDst)
                pbDst = m_rbScratchDstPtr;
        }
        if (pbSrc == null)
            return null;

        CDetourDis t = this;
        COPYENTRY pEntry = Disasm.s_rceCopyTable[pbSrc[0]];
        return ((delegate* unmanaged<CDetourDis*, COPYENTRY*, byte*, byte*, byte*>)pEntry.pfCopy)(&t, &pEntry, pbDst, pbSrc);
    }

    public byte* AdjustTarget(byte* pbDst, byte* pbSrc, uint cbOp, uint cbTargetOffset, uint cbTargetSize)
    {
        byte* pbTarget = null;
        long nOldOffset;
        long nNewOffset;
        void* pvTargetAddr = &pbDst[cbTargetOffset];

        switch (cbTargetSize)
        {
            case 1:
                nOldOffset = **(byte**)&pvTargetAddr;
                break;       
            case 2:          
                nOldOffset = **(short**)&pvTargetAddr;
                break;       
            case 4:          
                nOldOffset = **(int**)&pvTargetAddr;
                break;       
            case 8:          
                nOldOffset = **(long**)&pvTargetAddr;
                break;
            default:
                nOldOffset = 0;
                break;
        }

        pbTarget = pbSrc + cbOp + nOldOffset;
        nNewOffset = nOldOffset - (pbDst - pbSrc);

        switch (cbTargetSize)
        {
            case 1:
                **(byte**)&pvTargetAddr = (byte)nNewOffset;
                if (nNewOffset < SCHAR_MIN || nNewOffset > SCHAR_MAX)                
                    *m_plExtra = sizeof(uint) - 1;
                break;
            case 2:
                **(short**)&pvTargetAddr = (short)nNewOffset;
                if (nNewOffset < SHRT_MIN || nNewOffset > SHRT_MAX)
                    *m_plExtra = sizeof(uint) - 2;
                break;
            case 4:
                **(int**)&pvTargetAddr = (int)nNewOffset;
                if (nNewOffset < LONG_MIN || nNewOffset > LONG_MAX)
                    *m_plExtra = sizeof(uint) - 4;
                break;
            case 8:
                **(long**)&pvTargetAddr = nNewOffset;
                break;
        }
        return pbTarget;
    }
}