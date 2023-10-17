using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;
using static Memory.MemEx;

public unsafe class Modules
{
    public static bool DetourRestoreAfterWith()
    {
        void* pvData;
        int cbData;

        pvData = DetourFindPayloadEx(DETOUR_EXE_RESTORE_GUID_PTR, &cbData);

        if (pvData != null && cbData != 0)
            return DetourRestoreAfterWithEx(pvData, cbData);

        return false;
    }

    public static bool DetourRestoreAfterWithEx(void* pvData, int cbData)
    {
        DETOUR_EXE_RESTORE* pder = (DETOUR_EXE_RESTORE*)pvData;

        if (pder->cb != sizeof(DETOUR_EXE_RESTORE) || pder->cb > cbData)
            return false;

        int dwPermIdh = ~0;
        int dwPermInh = ~0;
        int dwPermClr = ~0;
        int dwIgnore;
        bool fSucceeded = false;
        bool fUpdated32To64 = false;

        if (pder->pclr != null && pder->clr.Flags != ((DETOUR_CLR_HEADER*)pder->pclr)->Flags)
            fUpdated32To64 = true;

        if (DetourVirtualProtectSameExecute(pder->pidh, pder->cbidh, PAGE_EXECUTE_READWRITE, &dwPermIdh))
        {
            if (DetourVirtualProtectSameExecute(pder->pinh, pder->cbinh, PAGE_EXECUTE_READWRITE, &dwPermInh))
            {
                CopyMemory(pder->pidh, &pder->idh, pder->cbidh);
                CopyMemory(pder->pinh, &pder->union_unnamed.inh, pder->cbinh);

                if (pder->pclr != null && !fUpdated32To64)
                {
                    if (DetourVirtualProtectSameExecute(pder->pclr, pder->cbclr, PAGE_EXECUTE_READWRITE, &dwPermClr))
                    {
                        CopyMemory(pder->pclr, &pder->clr, pder->cbclr);
                        VirtualProtect(pder->pclr, pder->cbclr, dwPermClr, &dwIgnore);
                        fSucceeded = true;
                    }
                }
                else fSucceeded = true;
                VirtualProtect(pder->pinh, pder->cbinh, dwPermInh, &dwIgnore);
            }
            VirtualProtect(pder->pidh, pder->cbidh, dwPermIdh, &dwIgnore);
        }

        if (fSucceeded)
        {
            DetourFreePayload(pder);
            pder = null;
        }

        return fSucceeded;
    }

    public static bool DetourFreePayload(void* pvData)
    {
        bool fSucceeded = false;

        nint hModule = DetourGetContainingModule(pvData);
        if (hModule != 0)
        {
            fSucceeded = VirtualFree(hModule, 0, MEM_RELEASE);
            if (fSucceeded)
                hModule = 0;
        }

        return fSucceeded;
    }


    public static nint DetourGetContainingModule(void* pvAddr)
    {
        MEMORY_BASIC_INFORMATION mbi = new();

        try
        {
            if (VirtualQuery((byte*)pvAddr, &mbi, sizeof(MEMORY_BASIC_INFORMATION)) <= 0)
                return 0;

            if ((mbi.State != MEM_COMMIT) || ((mbi.Protect & 0xff) == PAGE_NOACCESS) || ((mbi.Protect & PAGE_GUARD) != 0))
                return 0;

            IMAGE_DOS_HEADER* pDosHeader = (IMAGE_DOS_HEADER*)mbi.AllocationBase;
            if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
                return 0;

            IMAGE_NT_HEADERS* pNtHeader = (IMAGE_NT_HEADERS*)((byte*)pDosHeader + pDosHeader->e_lfanew);
            if (pNtHeader->Signature != IMAGE_NT_SIGNATURE)
                return 0;

            if (pNtHeader->FileHeader.SizeOfOptionalHeader == 0)
                return 0;

            return (nint)pDosHeader;
        }
        catch { }

        return 0;
    }

    public static bool DetourVirtualProtectSameExecute(void* pAddress, long nSize, int dwNewProtect, int* pdwOldProtect)
    {
        return DetourVirtualProtectSameExecuteEx(GetCurrentProcess(), pAddress, nSize, dwNewProtect, pdwOldProtect);
    }

    public static bool DetourVirtualProtectSameExecuteEx(nint hProcess, void* pAddress, long nSize, int dwNewProtect, int* pdwOldProtect)
    {
        MEMORY_BASIC_INFORMATION mbi = new();

        if (VirtualQueryEx(hProcess, pAddress, &mbi, sizeof(MEMORY_BASIC_INFORMATION)) == 0)
            return false;

        return VirtualProtectEx(hProcess, pAddress, nSize, DetourPageProtectAdjustExecute(mbi.Protect, dwNewProtect), pdwOldProtect);
    }

    public static int DetourPageProtectAdjustExecute(int dwOldProtect, int dwNewProtect)
    {
        bool fOldExecute = (dwOldProtect & DETOUR_PAGE_EXECUTE_ALL) != 0;
        bool fNewExecute = (dwNewProtect & DETOUR_PAGE_EXECUTE_ALL) != 0;

        if (fOldExecute && !fNewExecute)
        {
            dwNewProtect = ((dwNewProtect & DETOUR_PAGE_NO_EXECUTE_ALL) << 4) | (dwNewProtect & DETOUR_PAGE_ATTRIBUTES);
        }
        else if (!fOldExecute && fNewExecute)
        {
            dwNewProtect = ((dwNewProtect & DETOUR_PAGE_EXECUTE_ALL) >> 4) | (dwNewProtect & DETOUR_PAGE_ATTRIBUTES);
        }
        return dwNewProtect;
    }

    public static void* DetourFindPayloadEx(GUID* rguid, int* pcbData)
    {
        for (nint hMod = 0; (hMod = DetourEnumerateModules(hMod)) != 0;)
        {
            void* pvData;

            pvData = DetourFindPayload(hMod, rguid, pcbData);
            if (pvData != null)
                return pvData;
        }

        return null;
    }

    public static nint DetourEnumerateModules(nint hModuleLast)
    {
        byte* pbLast = (byte*)hModuleLast + MM_ALLOCATION_GRANULARITY;

        MEMORY_BASIC_INFORMATION mbi = new MEMORY_BASIC_INFORMATION();

        for (; ; pbLast = (byte*)mbi.BaseAddress + mbi.RegionSize)
        {
            if (VirtualQuery(pbLast, &mbi, sizeof(MEMORY_BASIC_INFORMATION)) <= 0)
                break;

            if (mbi.State != MEM_COMMIT || (mbi.Protect & 0xff) == PAGE_NOACCESS || (mbi.Protect & PAGE_GUARD) != 0)
                continue;

            try {
                IMAGE_DOS_HEADER* pDosHeader = (IMAGE_DOS_HEADER*)pbLast;
                if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE || (int)pDosHeader->e_lfanew > mbi.RegionSize || (int)pDosHeader->e_lfanew < sizeof(IMAGE_DOS_HEADER))
                    continue;

                IMAGE_NT_HEADERS* pNtHeader = (IMAGE_NT_HEADERS*)((byte*)pDosHeader + pDosHeader->e_lfanew);
                if (pNtHeader->Signature != IMAGE_NT_SIGNATURE)
                    continue;

                return (nint)pDosHeader;
            }
            catch
            {
                continue;
            }
        }
        return 0;
    }


    public static void* DetourFindPayload(nint hModule, GUID* rguid, int* pcbData)
    {
        byte* pbData = null;
        if (pcbData != null)
            *pcbData = 0;

        DETOUR_LOADED_BINARY* pBinary = GetPayloadSectionFromModule(hModule);
        if (pBinary == null)
            return null;

        try {
            DETOUR_SECTION_HEADER* pHeader = (DETOUR_SECTION_HEADER*)pBinary;
            if (pHeader->cbHeaderSize < sizeof(DETOUR_SECTION_HEADER) || pHeader->nSignature != DETOUR_SECTION_HEADER_SIGNATURE)
                return null;

            byte* pbBeg = ((byte*)pHeader) + pHeader->nDataOffset;
            byte* pbEnd = ((byte*)pHeader) + pHeader->cbDataSize;

            for (pbData = pbBeg; pbData < pbEnd;) {
                DETOUR_SECTION_RECORD* pSection = (DETOUR_SECTION_RECORD *)pbData;

                if (DetourAreSameGuid(&pSection->guid, rguid)) {
                    if (pcbData != null) {
                        *pcbData = pSection->cbBytes - sizeof(DETOUR_SECTION_RECORD);
                    }
                    return (byte*)(pSection + 1);
                }

                pbData = (byte*)pSection + pSection->cbBytes;
            }
        }
        catch { }
        return null;
    }

    public static bool DetourAreSameGuid(GUID* left, GUID* right)
    {
        return
            left->Data1 == right->Data1 &&
            left->Data2 == right->Data2 &&
            left->Data3 == right->Data3 &&
            left->Data4[0] == right->Data4[0] &&
            left->Data4[1] == right->Data4[1] &&
            left->Data4[2] == right->Data4[2] &&
            left->Data4[3] == right->Data4[3] &&
            left->Data4[4] == right->Data4[4] &&
            left->Data4[5] == right->Data4[5] &&
            left->Data4[6] == right->Data4[6] &&
            left->Data4[7] == right->Data4[7];
    }

    public static DETOUR_LOADED_BINARY* GetPayloadSectionFromModule(nint hModule)
    {
        IMAGE_DOS_HEADER* pDosHeader = (IMAGE_DOS_HEADER*)hModule;
        if (hModule == null)
            pDosHeader = (IMAGE_DOS_HEADER*)GetModuleHandle(null);

        try {
            if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
                return null;

            IMAGE_NT_HEADERS* pNtHeader = (IMAGE_NT_HEADERS*)((byte*)pDosHeader + pDosHeader->e_lfanew);
            if (pNtHeader->Signature != IMAGE_NT_SIGNATURE)
                return null;

            if (pNtHeader->FileHeader.SizeOfOptionalHeader == 0)
                return null;

            IMAGE_SECTION_HEADER* pSectionHeaders = (IMAGE_SECTION_HEADER*)((byte*)pNtHeader + sizeof(int) + sizeof(IMAGE_FILE_HEADER) + pNtHeader->FileHeader.SizeOfOptionalHeader);

            for (int n = 0; n < pNtHeader->FileHeader.NumberOfSections; n++)
            {
                /*if (strcmp(pSectionHeaders[n].Name, ".detour") == 0)*/
                if (fullstrcmp(pSectionHeaders[n].Name, DETOUR_STR_BYTES_PTR, 8))
                {
                    if (pSectionHeaders[n].VirtualAddress == 0 || pSectionHeaders[n].SizeOfRawData == 0)
                        break;

                    byte* pbData = (byte*)pDosHeader + pSectionHeaders[n].VirtualAddress;
                    DETOUR_SECTION_HEADER* pHeader = (DETOUR_SECTION_HEADER*)pbData;
                    if (pHeader->cbHeaderSize < sizeof(DETOUR_SECTION_HEADER) || pHeader->nSignature != DETOUR_SECTION_HEADER_SIGNATURE)
                        break;

                    if (pHeader->nDataOffset == 0)
                        pHeader->nDataOffset = pHeader->cbHeaderSize;

                    return (DETOUR_LOADED_BINARY*)pHeader;
                }
            }
        }
        catch { }

        return null;
    }
}