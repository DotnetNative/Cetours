using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Reflection.Metadata;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Cetours;
public static unsafe class Detours
{
    public static int s_nPendingThreadId = 0;
    public static int s_nPendingError = NO_ERROR;
    public static bool s_fRetainRegions = false;
    public static bool s_fIgnoreTooSmall = false;
    public static void** s_ppPendingError = null;
    public static DetourThread* s_pPendingThreads = null;
    public static DetourOperation* s_pPendingOperations = null;
    public static DETOUR_REGION* s_pRegions = null;
    public static DETOUR_REGION* s_pRegion = null;
    public static uint DETOUR_REGION_SIZE = 0x10000;
    public static uint DETOUR_TRAMPOLINES_PER_REGION = (uint)((DETOUR_REGION_SIZE / sizeof(DETOUR_TRAMPOLINE)) - 1);
    public static uint DETOUR_REGION_SIGNATURE = ((byte)'R' << 24) + ((byte)'r' << 16) + ((byte)'t' << 8) + (byte)'d';

    public static void* s_pSystemRegionLowerBound = (void*)(nint)0x70000000;
    public static void* s_pSystemRegionUpperBound = (void*)(nint)0x80000000;

    public static int DetourTransactionBegin()
    {
        s_nPendingThreadId = GetCurrentThreadId();

        s_pPendingOperations = null;
        s_pPendingThreads = null;
        s_ppPendingError = null;

        s_nPendingError = detour_writable_trampoline_regions();

        return s_nPendingError;
    }

    public static int detour_writable_trampoline_regions()
    {
        for (DETOUR_REGION* pRegion = s_pRegions; pRegion != null; pRegion = pRegion->pNext)
        {
            int dwOld;
            if (!VirtualProtect(pRegion, DETOUR_REGION_SIZE, PAGE_EXECUTE_READWRITE, &dwOld))
                return GetLastError();
        }
        return NO_ERROR;
    }

    public static int DetourUpdateThread(nint hThread)
    {
        if (hThread == GetCurrentThread())
            return NO_ERROR;

        DetourThread* t = New(new DetourThread());

        SuspendThread(hThread);

        t->hThread = hThread;
        t->pNext = s_pPendingThreads;
        s_pPendingThreads = t;

        return NO_ERROR;
    }

    public static int DetourTransactionCommit()
    {
        return DetourTransactionCommitEx(null);
    }

    public static int DetourTransactionCommitEx(void*** pppFailedPointer)
    {
        if (pppFailedPointer != null)
            *pppFailedPointer = s_ppPendingError;

        if (s_nPendingThreadId != GetCurrentThreadId())
            return ERROR_INVALID_OPERATION;

        if (s_nPendingError != NO_ERROR)
        {
            // Exception - DetourTransactionAbort();
            return s_nPendingError;
        }

        DetourOperation* o;
        DetourThread* t;
        bool freed = false;

        for (o = s_pPendingOperations; o != null; o = o->pNext)
        {
            if (o->fIsRemove)
            {
                CopyMemory(o->pbTarget, o->pTrampoline->rbRestore, o->pTrampoline->cbRestore);

                *o->ppbPointer = o->pbTarget;
            }
            else
            {
                detour_gen_jmp_indirect(o->pTrampoline->rbCodeIn, &o->pTrampoline->pbDetour);
                byte* pbCode = detour_gen_jmp_immediate(o->pbTarget, o->pTrampoline->rbCodeIn);
                pbCode = detour_gen_brk(pbCode, o->pTrampoline->pbRemain);
                *o->ppbPointer = o->pTrampoline->rbCode;
            }
        }

        for (t = s_pPendingThreads; t != null; t = t->pNext)
        {
            CONTEXT cxt;
            cxt.ContextFlags = CONTEXT_CONTROL;

            if (GetThreadContext(t->hThread, &cxt))
            {
                for (o = s_pPendingOperations; o != null; o = o->pNext)
                {
                    if (o->fIsRemove)
                    {
                        if (cxt.Rip >= (long)o->pTrampoline && cxt.Rip < ((long)o->pTrampoline + sizeof(DETOUR_TRAMPOLINE)))
                        {

                            cxt.Rip = ((long)o->pbTarget + detour_align_from_trampoline(o->pTrampoline, (byte)(cxt.Rip - (long)o->pTrampoline)));

                            SetThreadContext(t->hThread, &cxt);
                        }
                    }
                    else
                    {
                        if (cxt.Rip >= (long)o->pbTarget && cxt.Rip < ((long)o->pbTarget + o->pTrampoline->cbRestore))
                        {

                            cxt.Rip = ((long)o->pTrampoline + detour_align_from_target(o->pTrampoline, (byte)(cxt.Rip - (long)o->pbTarget)));

                            SetThreadContext(t->hThread, &cxt);
                        }
                    }
                }
            }
        }

        nint hProcess = GetCurrentProcess();
        for (o = s_pPendingOperations; o != null;)
        {
            int dwOld;
            VirtualProtect(o->pbTarget, o->pTrampoline->cbRestore, (int)o->dwPerm, &dwOld);
            FlushInstructionCache(hProcess, o->pbTarget, o->pTrampoline->cbRestore);

            if (o->fIsRemove && o->pTrampoline != null)
            {
                detour_free_trampoline(o->pTrampoline);
                o->pTrampoline = null;
                freed = true;
            }

            DetourOperation* n = o->pNext;
            //delete o;
            o = n;
        }
        s_pPendingOperations = null;

        if (freed && !s_fRetainRegions)
        {
            detour_free_unused_trampoline_regions();
        }

        detour_runnable_trampoline_regions();

        for (t = s_pPendingThreads; t != null;)
        {
            ResumeThread(t->hThread);

            DetourThread* n = t->pNext;
            //delete t;
            t = n;
        }
        s_pPendingThreads = null;
        s_nPendingThreadId = 0;

        if (pppFailedPointer != null)
        {
            *pppFailedPointer = s_ppPendingError;
        }

        return s_nPendingError;
    }

    public static byte* detour_gen_jmp_indirect(byte* pbCode, byte** ppbJmpVal)
    {
        byte* pbJmpSrc = pbCode + 6;
        *pbCode++ = 0xff;
        *pbCode++ = 0x25;
        *(*(int**)pbCode)++ = (int)((byte*)ppbJmpVal - pbJmpSrc);
        return pbCode;
    }

    public static byte* detour_gen_jmp_immediate(byte* pbCode, byte* pbJmpVal)
    {
        byte* pbJmpSrc = pbCode + 5;
        *pbCode++ = 0xE9;
        *(*(int**)pbCode)++ = (int)(pbJmpVal - pbJmpSrc);
        return pbCode;
    }

    public static byte* detour_gen_brk(byte* pbCode, byte* pbLimit)
    {
        while (pbCode < pbLimit)
            *pbCode++ = 0xcc;
        return pbCode;
    }

    public static byte detour_align_from_trampoline(DETOUR_TRAMPOLINE* pTrampoline, byte obTrampoline)
    {
        for (int n = 0; n < 8; n++)
            if (((_DETOUR_ALIGN*)pTrampoline->rAlign + n)->obTrampoline == obTrampoline)
                return ((_DETOUR_ALIGN*)pTrampoline->rAlign + n)->obTarget;
        return 0;
    }

    public static int detour_align_from_target(DETOUR_TRAMPOLINE* pTrampoline, int obTarget)
    {
        for (int n = 0; n < 8; n++)
            if (((_DETOUR_ALIGN*)pTrampoline->rAlign + n)->obTarget == obTarget)
                return ((_DETOUR_ALIGN*)pTrampoline->rAlign + n)->obTrampoline;
        return 0;
    }

    public static void detour_free_trampoline(DETOUR_TRAMPOLINE* pTrampoline)
    {
        DETOUR_REGION* pRegion = (DETOUR_REGION*)((nint)pTrampoline & ~(nint)0xffff);

        Copy(pTrampoline, new byte[sizeof(DETOUR_TRAMPOLINE)]);
        pTrampoline->pbRemain = (byte*)pRegion->pFree;
        pRegion->pFree = pTrampoline;
    }

    public static void detour_free_unused_trampoline_regions()
    {
        DETOUR_REGION** ppRegionBase = (DETOUR_REGION**)New((nint)s_pRegions);
        DETOUR_REGION* pRegion = s_pRegions;

        while (pRegion != null)
        {
            if (detour_is_region_empty(pRegion))
            {
                *ppRegionBase = pRegion->pNext;

                VirtualFree((nint)pRegion, 0, MEM_RELEASE);
                s_pRegion = null;
            }
            else
            {
                ppRegionBase = &pRegion->pNext;
            }
            pRegion = *ppRegionBase;
        }

        Free(ppRegionBase);
    }

    public static bool detour_is_region_empty(DETOUR_REGION* pRegion)
    {
        if (pRegion->dwSignature != DETOUR_REGION_SIGNATURE)
            return false;

        byte* pbRegionBeg = (byte*)pRegion;
        byte* pbRegionLim = pbRegionBeg + DETOUR_REGION_SIZE;

        DETOUR_TRAMPOLINE* pTrampoline = ((DETOUR_TRAMPOLINE*)pRegion) + 1;
        for (int i = 0; i < DETOUR_TRAMPOLINES_PER_REGION; i++)
            if (pTrampoline[i].pbRemain != null && (pTrampoline[i].pbRemain < pbRegionBeg || pTrampoline[i].pbRemain >= pbRegionLim))
                return false;

        return true;
    }

    public static void detour_runnable_trampoline_regions()
    {
        nint hProcess = GetCurrentProcess();

        for (DETOUR_REGION* pRegion = s_pRegions; pRegion != null; pRegion = pRegion->pNext)
        {
            int dwOld;
            VirtualProtect(pRegion, DETOUR_REGION_SIZE, PAGE_EXECUTE_READ, &dwOld);
            FlushInstructionCache(hProcess, pRegion, DETOUR_REGION_SIZE);
        }
    }

    public static int DetourAttach(void** ppPointer, void* pDetour)
    {
        return DetourAttachEx(ppPointer, pDetour, null, null, null);
    }

    public static int DetourAttachEx(void** ppPointer, void* pDetour, DETOUR_TRAMPOLINE** ppRealTrampoline, void** ppRealTarget, void** ppRealDetour)
    {
        int error = NO_ERROR;

        if (ppRealTrampoline != null)
            *ppRealTrampoline = null;

        if (ppRealTarget != null)
            *ppRealTarget = null;

        if (ppRealDetour != null)
            *ppRealDetour = null;

        if (pDetour == null)
            return ERROR_INVALID_PARAMETER;

        if (s_nPendingThreadId != GetCurrentThreadId())
            return ERROR_INVALID_OPERATION;

        if (s_nPendingError != NO_ERROR)
            return s_nPendingError;

        if (ppPointer == null)
        {
            return ERROR_INVALID_HANDLE;
        }

        if (*ppPointer == null)
        {
            error = ERROR_INVALID_HANDLE;
            s_nPendingError = error;
            s_ppPendingError = ppPointer;

            return error;
        }

        byte* pbTarget = (byte*)*ppPointer;
        DETOUR_TRAMPOLINE* pTrampoline = null;
        DetourOperation* o = null;

        pbTarget = (byte*)DetourCodeFromPointer(pbTarget, null);
        pDetour = DetourCodeFromPointer(pDetour, null);
        if (pDetour == (void*)pbTarget)
        {
            if (s_fIgnoreTooSmall)
            {
                stop();
                return error;
            }
            else
            {

                fail();
                return error;
            }
        }

        if (ppRealTarget != null)
            *ppRealTarget = pbTarget;

        if (ppRealDetour != null)
            *ppRealDetour = pDetour;

        o = New(new DetourOperation());
        if (o == null)
        {
            error = ERROR_NOT_ENOUGH_MEMORY;

            fail();
            return error;
        }

        pTrampoline = detour_alloc_trampoline(pbTarget);
        if (pTrampoline == null)
        {
            error = ERROR_NOT_ENOUGH_MEMORY;

            fail();
            return error;
        }

        if (ppRealTrampoline != null)
        {
            *ppRealTrampoline = pTrampoline;
        }

        memset(pTrampoline->rAlign, 0, sizeof(short) * 8);

        byte* pbSrc = pbTarget;
        byte* pbTrampoline = pTrampoline->rbCode;

        byte* pbPool = pbTrampoline + (sizeof(byte) * 30);
        uint cbTarget = 0;
        uint cbJump = SIZE_OF_JMP;
        uint nAlign = 0;

        while (cbTarget < cbJump)
        {
            byte* pbOp = pbSrc;
            int lExtra = 0;

            pbSrc = (byte*)DetourCopyInstruction(pbTrampoline, (void**)&pbPool, pbSrc, null, &lExtra);
            pbTrampoline += (pbSrc - pbOp) + lExtra;
            cbTarget = (uint)(pbSrc - pbTarget);
            ((_DETOUR_ALIGN*)(pTrampoline->rAlign + nAlign))->obTarget = (byte)cbTarget;
            ((_DETOUR_ALIGN*)(pTrampoline->rAlign + nAlign))->obTrampoline = (byte)(pbTrampoline - pTrampoline->rbCode);
            nAlign++;

            if (nAlign >= 8)
            {
                break;
            }

            if (detour_does_code_end_function(pbOp))
            {
                break;
            }
        }

        while (cbTarget < cbJump)
        {
            uint cFiller = detour_is_code_filler(pbSrc);
            if (cFiller == 0)
            {
                break;
            }

            pbSrc += cFiller;
            cbTarget = (uint)(pbSrc - pbTarget);
        }

        if (cbTarget < cbJump || nAlign > 8)
        {
            error = ERROR_INVALID_BLOCK;
            if (s_fIgnoreTooSmall)
            {
                fail();
                return error;
            }
            else
            {
                fail();
                return error;
            }
        }

        //if (pbTrampoline > pbPool)
        //    __debugbreak();

        pTrampoline->cbCode = (byte)(pbTrampoline - pTrampoline->rbCode);
        pTrampoline->cbRestore = (byte)cbTarget;
        CopyMemory(pTrampoline->rbRestore, pbTarget, (int)cbTarget);

        if (cbTarget > (sizeof(byte) * 30) - cbJump)
        {
            error = ERROR_INVALID_HANDLE;

            fail();
            return error;
        }

        pTrampoline->pbRemain = pbTarget + cbTarget;
        pTrampoline->pbDetour = (byte*)pDetour;

        pbTrampoline = pTrampoline->rbCode + pTrampoline->cbCode;
        pbTrampoline = detour_gen_jmp_indirect(pbTrampoline, &pTrampoline->pbRemain);
        pbTrampoline = detour_gen_brk(pbTrampoline, pbPool);

        //(void)pbTrampoline;

        int dwOld = 0;
        if (!VirtualProtect(pbTarget, cbTarget, PAGE_EXECUTE_READWRITE, &dwOld))
        {
            error = GetLastError();

            fail();
        }

        o->fIsRemove = false;
        o->ppbPointer = (byte**)ppPointer;
        o->pTrampoline = pTrampoline;
        o->pbTarget = pbTarget;
        o->dwPerm = (uint)dwOld;
        o->pNext = s_pPendingOperations;
        s_pPendingOperations = o;

        return NO_ERROR;

        void fail()
        {
            s_nPendingError = error;
            stop();
        }

        void stop()
        {
            if (pTrampoline != null)
            {
                detour_free_trampoline(pTrampoline);
                pTrampoline = null;
                if (ppRealTrampoline != null)
                    *ppRealTrampoline = null;
            }
            if (o != null)
            {
                Free(o);
                o = null;
            }
            if (ppRealDetour != null)
                *ppRealDetour = null;
            if (ppRealTarget != null)
                *ppRealTarget = null;
            s_ppPendingError = ppPointer;
        }
    }

    public static DETOUR_TRAMPOLINE* detour_alloc_trampoline(byte* pbTarget)
    {
        DETOUR_TRAMPOLINE** pLo = null;
        DETOUR_TRAMPOLINE** pHi = null;

        detour_find_jmp_bounds(pbTarget, pLo, pHi);

        DETOUR_TRAMPOLINE* pTrampoline = null;

        if (s_pRegion == null && s_pRegions != null)
            s_pRegion = s_pRegions;

        if (s_pRegion != null && s_pRegion->pFree != null && s_pRegion->pFree >= pLo && s_pRegion->pFree <= pHi)
        {
            return found_region();
        }

        for (s_pRegion = s_pRegions; s_pRegion != null; s_pRegion = s_pRegion->pNext)
        {
            if (s_pRegion != null && s_pRegion->pFree != null &&
                s_pRegion->pFree >= pLo && s_pRegion->pFree <= pHi)
            {
                return found_region();
            }
        }

        pbTarget = pbTarget - (uint)((nint)pbTarget & 0xffff);

        void* pbNewlyAllocated = detour_alloc_trampoline_allocate_new(pbTarget, *pLo, *pHi);
        if (pbNewlyAllocated != null)
        {
            s_pRegion = (DETOUR_REGION*)pbNewlyAllocated;
            s_pRegion->dwSignature = DETOUR_REGION_SIGNATURE;
            s_pRegion->pFree = null;
            s_pRegion->pNext = s_pRegions;
            s_pRegions = s_pRegion;

            byte* pFree = null;
            pTrampoline = ((DETOUR_TRAMPOLINE*)s_pRegion) + 1;
            for (int i = (int)DETOUR_TRAMPOLINES_PER_REGION - 1; i > 1; i--)
            {
                pTrampoline[i].pbRemain = pFree;
                pFree = (byte*)&pTrampoline[i];
            }
            s_pRegion->pFree = (DETOUR_TRAMPOLINE*)pFree;
            return found_region();
        }

        return null;

        DETOUR_TRAMPOLINE* found_region()
        {
            pTrampoline = s_pRegion->pFree;
            if (pTrampoline < pLo || pTrampoline > pHi)
            {
                return null;
            }
            s_pRegion->pFree = (DETOUR_TRAMPOLINE*)pTrampoline->pbRemain;
            memset(pTrampoline, 0xcc, sizeof(DETOUR_TRAMPOLINE));
            return pTrampoline;
        }
    }

    public static void detour_find_jmp_bounds(byte* pbCode, DETOUR_TRAMPOLINE** ppLower, DETOUR_TRAMPOLINE** ppUpper)
    {
        nuint lo = detour_2gb_below((nuint)pbCode);
        nuint hi = detour_2gb_above((nuint)pbCode);

        if (pbCode[0] == 0xff && pbCode[1] == 0x25)
        {
            byte* pbNew = pbCode + 6 + *(int*)&pbCode[2];

            if (pbNew < pbCode)
            {
                hi = detour_2gb_above((nuint)pbNew);
            }
            else
            {
                lo = detour_2gb_below((nuint)pbNew);
            }
        }
        else if (pbCode[0] == 0xe9)
        {
            byte* pbNew = pbCode + 5 + *(int*)&pbCode[1];

            if (pbNew < pbCode)
            {
                hi = detour_2gb_above((nuint)pbNew);
            }
            else
            {
                lo = detour_2gb_below((nuint)pbNew);
            }
        }

        *ppLower = (DETOUR_TRAMPOLINE*)lo;
        *ppUpper = (DETOUR_TRAMPOLINE*)hi;
    }

    public static nuint detour_2gb_below(nuint address)
    {
        return (address > (nuint)0x7ff80000) ? address - 0x7ff80000 : 0x80000;
    }

    public static nuint detour_2gb_above(nuint address)
    {
        return (address < (nuint)0xffffffff80000000) ? address + 0x7ff80000 : (nuint)0xfffffffffff80000;
    }

    public static bool detour_does_code_end_function(byte* pbCode)
    {
        if (pbCode[0] == 0xeb ||
            pbCode[0] == 0xe9 ||
            pbCode[0] == 0xe0 ||
            pbCode[0] == 0xc2 ||
            pbCode[0] == 0xc3 ||
            pbCode[0] == 0xcc)
        {
            return true;
        }
        else if (pbCode[0] == 0xf3 && pbCode[1] == 0xc3)
        {
            return true;
        }
        else if (pbCode[0] == 0xff && pbCode[1] == 0x25)
        {
            return true;
        }
        else if ((pbCode[0] == 0x26 ||
            pbCode[0] == 0x2e ||
            pbCode[0] == 0x36 ||
            pbCode[0] == 0x3e ||
            pbCode[0] == 0x64 ||
            pbCode[0] == 0x65) &&
            pbCode[1] == 0xff &&
            pbCode[2] == 0x25)
        {
            return true;
        }
        return false;
    }


    public static uint detour_is_code_filler(byte* pbCode)
    {
        if (pbCode[0] == 0x90)
            return 1;

        if (pbCode[0] == 0x66 && pbCode[1] == 0x90)
            return 2;

        if (pbCode[0] == 0x0F && pbCode[1] == 0x1F && pbCode[2] == 0x00)
            return 3;

        if (pbCode[0] == 0x0F && pbCode[1] == 0x1F && pbCode[2] == 0x40 &&
            pbCode[3] == 0x00)
            return 4;

        if (pbCode[0] == 0x0F && pbCode[1] == 0x1F && pbCode[2] == 0x44 &&
            pbCode[3] == 0x00 && pbCode[4] == 0x00)
            return 5;

        if (pbCode[0] == 0x66 && pbCode[1] == 0x0F && pbCode[2] == 0x1F &&
            pbCode[3] == 0x44 && pbCode[4] == 0x00 && pbCode[5] == 0x00)
            return 6;

        if (pbCode[0] == 0x0F && pbCode[1] == 0x1F && pbCode[2] == 0x80 &&
            pbCode[3] == 0x00 && pbCode[4] == 0x00 && pbCode[5] == 0x00 &&
            pbCode[6] == 0x00)
            return 7;

        if (pbCode[0] == 0x0F && pbCode[1] == 0x1F && pbCode[2] == 0x84 &&
            pbCode[3] == 0x00 && pbCode[4] == 0x00 && pbCode[5] == 0x00 &&
            pbCode[6] == 0x00 && pbCode[7] == 0x00)
            return 8;

        if (pbCode[0] == 0x66 && pbCode[1] == 0x0F && pbCode[2] == 0x1F &&
            pbCode[3] == 0x84 && pbCode[4] == 0x00 && pbCode[5] == 0x00 &&
            pbCode[6] == 0x00 && pbCode[7] == 0x00 && pbCode[8] == 0x00)
            return 9;

        if (pbCode[0] == 0x66 && pbCode[1] == 0x66 && pbCode[2] == 0x0F &&
            pbCode[3] == 0x1F && pbCode[4] == 0x84 && pbCode[5] == 0x00 &&
            pbCode[6] == 0x00 && pbCode[7] == 0x00 && pbCode[8] == 0x00 &&
            pbCode[9] == 0x00)
            return 10;

        if (pbCode[0] == 0x66 && pbCode[1] == 0x66 && pbCode[2] == 0x66 &&
            pbCode[3] == 0x0F && pbCode[4] == 0x1F && pbCode[5] == 0x84 &&
            pbCode[6] == 0x00 && pbCode[7] == 0x00 && pbCode[8] == 0x00 &&
            pbCode[9] == 0x00 && pbCode[10] == 0x00)
            return 11;

        if (pbCode[0] == 0xcc)
            return 1;
        return 0;
    }


    public static void* detour_alloc_trampoline_allocate_new(void* pbTarget, DETOUR_TRAMPOLINE* pLo, DETOUR_TRAMPOLINE* pHi)
    {
        void* pbTry = null;

        if (pbTry == null && pbTarget > (void*)0x40000000)
        {
            pbTry = detour_alloc_region_from_hi((byte*)pLo, (byte*)pbTarget - 0x40000000);
        }
        if (pbTry == null && pbTarget < (void*)0xffffffff40000000)
        {
            pbTry = detour_alloc_region_from_lo((byte*)pbTarget + 0x40000000, (byte*)pHi);
        }
        if (pbTry == null && pbTarget > (void*)0x40000000)
        {
            pbTry = detour_alloc_region_from_lo((byte*)pbTarget - 0x40000000, (byte*)pbTarget);
        }
        if (pbTry == null && pbTarget < (void*)0xffffffff40000000)
        {
            pbTry = detour_alloc_region_from_hi((byte*)pbTarget, (byte*)pbTarget + 0x40000000);
        }

        if (pbTry == null)
        {
            pbTry = detour_alloc_region_from_hi((byte*)pLo, (byte*)pbTarget);
        }
        if (pbTry == null)
        {
            pbTry = detour_alloc_region_from_lo((byte*)pbTarget, (byte*)pHi);
        }

        return pbTry;
    }

    public static void* detour_alloc_region_from_lo(byte* pbLo, byte* pbHi)
    {
        byte* pbTry = detour_alloc_round_up_to_region(pbLo);

        for (; pbTry < pbHi;)
        {
            MEMORY_BASIC_INFORMATION mbi = new();

            if (pbTry >= s_pSystemRegionLowerBound && pbTry <= s_pSystemRegionUpperBound)
            {
                pbTry += 0x08000000;
                continue;
            }

            if (VirtualQuery(pbTry, &mbi, sizeof(MEMORY_BASIC_INFORMATION)) == 0)
            {
                break;
            }

            if (mbi.State == MEM_FREE && mbi.RegionSize >= DETOUR_REGION_SIZE)
            {

                void* pv = VirtualAlloc(pbTry, DETOUR_REGION_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                if (pv != null)
                {
                    return pv;
                }
                else if (GetLastError() == ERROR_DYNAMIC_CODE_BLOCKED)
                {
                    return null;
                }
                pbTry += DETOUR_REGION_SIZE;
            }
            else
            {
                pbTry = detour_alloc_round_up_to_region((byte*)mbi.BaseAddress + mbi.RegionSize);
            }
        }
        return null;
    }

    static void* detour_alloc_region_from_hi(byte* pbLo, byte* pbHi)
    {
        byte* pbTry = detour_alloc_round_down_to_region(pbHi - DETOUR_REGION_SIZE);

        for (; pbTry > pbLo;)
        {
            MEMORY_BASIC_INFORMATION mbi = new();

            if (pbTry >= s_pSystemRegionLowerBound && pbTry <= s_pSystemRegionUpperBound)
            {
                pbTry -= 0x08000000;
                continue;
            }

            if (VirtualQuery(pbTry, &mbi, sizeof(MEMORY_BASIC_INFORMATION)) == 0)
            {
                break;
            }

            if (mbi.State == MEM_FREE && mbi.RegionSize >= DETOUR_REGION_SIZE)
            {

                void* pv = VirtualAlloc(pbTry, DETOUR_REGION_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                if (pv != null)
                {
                    return pv;
                }
                else if (GetLastError() == ERROR_DYNAMIC_CODE_BLOCKED)
                {
                    return null;
                }
                pbTry -= DETOUR_REGION_SIZE;
            }
            else
            {
                pbTry = detour_alloc_round_down_to_region((byte*)mbi.AllocationBase - DETOUR_REGION_SIZE);
            }
        }
        return null;
    }

    public static byte* detour_alloc_round_up_to_region(byte* pbTry)
    {
        nint extra = ((nint)pbTry) & (nint)(DETOUR_REGION_SIZE - 1);
        if (extra != 0)
        {
            nint adjust = (nint)DETOUR_REGION_SIZE - extra;
            pbTry += adjust;
        }
        return pbTry;
    }

    public static byte* detour_alloc_round_down_to_region(byte* pbTry)
    {
        nint extra = ((nint)pbTry) & (nint)(DETOUR_REGION_SIZE - 1);
        if (extra != 0)
        {
            pbTry -= extra;
        }
        return pbTry;
    }
}