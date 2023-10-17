using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.JavaScript;
using System.Text;
using System.Threading.Tasks;

namespace Cetours;

public unsafe struct COPYENTRY
{
    public COPYENTRY(uint nFixedSize = 4, uint nFixedSize16 = 4, uint nModOffset = 4, uint nRelOffset = 4, uint nFlagBits = 4, void* pfCopy = null) { }

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

    public static void* CopyBytesPtr = (delegate* unmanaged<CDetourDis, COPYENTRY*, byte*, byte*, byte*>)&CopyBytes;
    public static COPYENTRY ENTRY_DataIgnored = new(0, 0, 0, 0, 0);
    public static COPYENTRY ENTRY_CopyBytes1 = new(1, 1, 0, 0, 0, CopyBytesPtr);
    public static COPYENTRY ENTRY_CopyBytes1Address = new(9, 5, 0, 0, ADDRESS, CopyBytesPtr);
    public static COPYENTRY ENTRY_CopyBytes1Dynamic = new(1, 1, 0, 0, DYNAMIC, CopyBytesPtr);
    public static COPYENTRY ENTRY_CopyBytes2 = new(2, 2, 0, 0, 0, CopyBytesPtr);
    public static COPYENTRY ENTRY_CopyBytes2Jump = new(ENTRY_DataIgnored CopyBytesJump);
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
    public static COPYENTRY ENTRY_CopyBytesPrefix = new(ENTRY_DataIgnored CopyBytesPrefix);
    public static COPYENTRY ENTRY_CopyBytesSegment = new(ENTRY_DataIgnored CopyBytesSegment);
    public static COPYENTRY ENTRY_CopyBytesRax = new(ENTRY_DataIgnored CopyBytesRax);
    public static COPYENTRY ENTRY_CopyF2 = new(ENTRY_DataIgnored CopyF2);
    public static COPYENTRY ENTRY_CopyF3 = new(ENTRY_DataIgnored CopyF3);
    public static COPYENTRY ENTRY_Copy0F = new(ENTRY_DataIgnored Copy0F);
    public static COPYENTRY ENTRY_Copy0F78 = new(ENTRY_DataIgnored Copy0F78);
    public static COPYENTRY ENTRY_Copy0F00 = new(ENTRY_DataIgnored Copy0F00); 
    public static COPYENTRY ENTRY_Copy0FB8 = new(ENTRY_DataIgnored Copy0FB8); 
    public static COPYENTRY ENTRY_Copy66 = new(ENTRY_DataIgnored Copy66);
    public static COPYENTRY ENTRY_Copy67 = new(ENTRY_DataIgnored Copy67);
    public static COPYENTRY ENTRY_CopyF6 = new(ENTRY_DataIgnored CopyF6);
    public static COPYENTRY ENTRY_CopyF7 = new(ENTRY_DataIgnored CopyF7);
    public static COPYENTRY ENTRY_CopyFF = new(ENTRY_DataIgnored CopyFF);
    public static COPYENTRY ENTRY_CopyVex2 = new(ENTRY_DataIgnored CopyVex2);
    public static COPYENTRY ENTRY_CopyVex3 = new(ENTRY_DataIgnored CopyVex3);
    public static COPYENTRY ENTRY_CopyEvex = new(ENTRY_DataIgnored CopyEvex); 
    public static COPYENTRY ENTRY_CopyXop = new(ENTRY_DataIgnored CopyXop);  
    public static COPYENTRY ENTRY_CopyBytesXop = new(5, 5, 4, 0, 0, CopyBytesPtr); 
    public static COPYENTRY ENTRY_CopyBytesXop1 = new(6, 6, 4, 0, 0, CopyBytesPtr); 
    public static COPYENTRY ENTRY_CopyBytesXop4 = new(9, 9, 4, 0, 0, CopyBytesPtr); 
    public static COPYENTRY ENTRY_Invalid = new(ENTRY_DataIgnored Invalid);

    [UnmanagedCallersOnly]
    public static byte* CopyBytes(CDetourDis t, COPYENTRY* pEntry, byte* pbDst, byte* pbSrc)
    {
        uint nBytesFixed;

        uint nModOffset = pEntry->nModOffset;
        uint nFlagBits = pEntry->nFlagBits;
        uint nFixedSize = pEntry->nFixedSize;
        uint nFixedSize16 = pEntry->nFixedSize16;

        if ((nFlagBits & ADDRESS) != 0)
        {
            nBytesFixed = t.m_bAddressOverride ? nFixedSize16 : nFixedSize;
        }
        else if (t.m_bRaxOverride)
        {
            nBytesFixed = (uint)(nFixedSize + (((nFlagBits & RAX) != 0) ? 4 : 0));
        }
        else
        {
            nBytesFixed = t.m_bOperandOverride ? nFixedSize16 : nFixedSize;
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
            *t.m_ppbTarget = t.AdjustTarget(pbDst, pbSrc, nBytes, nRelOffset, cbTarget);
            if (pEntry->nRelOffset == 0)
            {
                *t.m_ppbTarget = null;
            }
        }
        if ((nFlagBits & NOENLARGE) != 0)
        {
            *t.m_plExtra = -*t.m_plExtra;
        }
        if ((nFlagBits & DYNAMIC) != 0)
        {
            *t.m_ppbTarget = (byte*)DETOUR_INSTRUCTION_TARGET_DYNAMIC;
        }
        return pbSrc + nBytes;
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
}

public unsafe struct CDetourDis
{
    public CDetourDis(byte** ppbTarget, int* plExtra)
    {

    }

    public bool m_bOperandOverride;
    public bool m_bAddressOverride;
    public bool m_bRaxOverride;
    public bool m_bVex;
    public bool m_bEvex;
    public bool m_bF2;
    public bool m_bF3;
    public byte m_nSegmentOverride;

    public byte** m_ppbTarget;
    public int* m_plExtra;

    public int m_lScratchExtra;
    public byte* m_pbScratchTarget;
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

        COPYENTRY pEntry = Disasm.s_rceCopyTable[pbSrc[0]];
        return ((delegate* unmanaged<CDetourDis, COPYENTRY*, byte*, byte*, byte*>)pEntry.pfCopy)(this, &pEntry, pbDst, pbSrc);
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
                nOldOffset = (long)*(byte**)pvTargetAddr;
                break;
            case 2:
                nOldOffset = (long)*(short**)pvTargetAddr;
                break;
            case 4:
                nOldOffset = (long)*(int**)pvTargetAddr;
                break;
            case 8:
                nOldOffset = (long)*(long**)pvTargetAddr;
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
                *(byte**)pvTargetAddr = (byte*)nNewOffset;
                if (nNewOffset < SCHAR_MIN || nNewOffset > SCHAR_MAX)                
                    *m_plExtra = sizeof(uint) - 1;
                break;
            case 2:
                *(short**)pvTargetAddr = (short*)nNewOffset;
                if (nNewOffset < SHRT_MIN || nNewOffset > SHRT_MAX)
                    *m_plExtra = sizeof(uint) - 2;
                break;
            case 4:
                *(int**)pvTargetAddr = (int*)nNewOffset;
                if (nNewOffset < LONG_MIN || nNewOffset > LONG_MAX)
                    *m_plExtra = sizeof(uint) - 4;
                break;
            case 8:
                *(long**)pvTargetAddr = (long*)nNewOffset;
                break;
        }
        return pbTarget;
    }
}