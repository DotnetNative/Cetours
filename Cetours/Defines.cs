global using static ExternalFunctions;
global using static Memory.MemEx;
global using static Interop;
global using static Defines;
global using Cetours;

//global using ADDRESS = _tagADDRESS64;
//global using ADDRESS64 = _tagADDRESS64;
global using GUID = _GUID;
global using DETOUR_SECTION_HEADER = _DETOUR_SECTION_HEADER;
global using DETOUR_SECTION_RECORD = _DETOUR_SECTION_RECORD;
global using IMAGE_DOS_HEADER = _IMAGE_DOS_HEADER;
global using IMAGE_NT_HEADERS64 = _IMAGE_NT_HEADERS64;
global using IMAGE_NT_HEADERS = _IMAGE_NT_HEADERS64;
global using IMAGE_FILE_HEADER = _IMAGE_FILE_HEADER;
global using IMAGE_OPTIONAL_HEADER64 = _IMAGE_OPTIONAL_HEADER64;
global using IMAGE_DATA_DIRECTORY = _IMAGE_DATA_DIRECTORY;
global using IMAGE_SECTION_HEADER = _IMAGE_SECTION_HEADER;
global using MEMORY_BASIC_INFORMATION = _MEMORY_BASIC_INFORMATION;
global using DETOUR_EXE_RESTORE = _DETOUR_EXE_RESTORE;
global using DETOUR_CLR_HEADER = _DETOUR_CLR_HEADER;
global using IMAGE_OPTIONAL_HEADER32 = _IMAGE_OPTIONAL_HEADER;
global using IMAGE_NT_HEADERS32 = _IMAGE_NT_HEADERS;
global using DETOUR_TRAMPOLINE = _DETOUR_TRAMPOLINE;
global using CONTEXT = _CONTEXT;
global using M128A = _M128A;
global using XSAVE_FORMAT = _XSAVE_FORMAT;
global using XMM_SAVE_AREA32 = _XSAVE_FORMAT;

using System;
using System.Runtime.InteropServices;
using System.Text;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices.JavaScript;
using System.Reflection.Metadata;

public unsafe class Defines
{
    public static GUID DETOUR_EXE_RESTORE_GUID = new(0xbda26f34, 0xbc82, 0x4829, 0x9e, 0x64, 0x74, 0x2c, 0x4, 0xc8, 0x4f, 0xa0);
    public static GUID* DETOUR_EXE_RESTORE_GUID_PTR = New(DETOUR_EXE_RESTORE_GUID);

    public const short IMAGE_DOS_SIGNATURE = 0x5A4D;
    public const nint DETOUR_INSTRUCTION_TARGET_DYNAMIC = -1;
    public const int
        MM_ALLOCATION_GRANULARITY = 0x10000,
        DETOUR_SECTION_HEADER_SIGNATURE = 0x727444,
        IMAGE_NT_SIGNATURE = 0x4550,
        IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16,
        IMAGE_SIZEOF_SHORT_NAME = 8,
        MEM_COMMIT = 0x1000,
        PAGE_NOACCESS = 0x1,
        PAGE_READONLY = 0x02,
        PAGE_READWRITE = 0x04,
        PAGE_WRITECOPY = 0x08,
        PAGE_GUARD = 0x100,
        MEM_RESERVE = 0x00002000,
        DETOUR_MAX_SUPPORTED_IMAGE_SECTION_HEADERS = 32,
        PAGE_EXECUTE = 0x10,
        PAGE_EXECUTE_READ = 0x20,
        PAGE_EXECUTE_READWRITE = 0x40,
        PAGE_EXECUTE_WRITECOPY = 0x80,
        MEM_FREE = 0x10000,
        DETOUR_PAGE_EXECUTE_ALL = PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY,
        DETOUR_PAGE_NO_EXECUTE_ALL = PAGE_NOACCESS | PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY,
        DETOUR_PAGE_ATTRIBUTES = ~(DETOUR_PAGE_EXECUTE_ALL | DETOUR_PAGE_NO_EXECUTE_ALL),
        MEM_RELEASE = 0x8000,
        NO_ERROR = 0,
        ERROR_INVALID_OPERATION = 4317,
        ERROR_INVALID_PARAMETER = 87,
        ERROR_INVALID_HANDLE = 6,
        ERROR_NOT_ENOUGH_MEMORY = 8,
        ERROR_INVALID_BLOCK = 9,
        ERROR_DYNAMIC_CODE_BLOCKED = 1655,
        CONTEXT_AMD64 = 0x100000,
        CONTEXT_CONTROL = CONTEXT_AMD64 | 0x1,
        CONTEXT_INTEGER = CONTEXT_AMD64 | 0x2,
        CONTEXT_SEGMENTS = CONTEXT_AMD64 | 0x04,
        CONTEXT_FLOATING_POINT = CONTEXT_AMD64 | 0x8,
        CONTEXT_DEBUG_REGISTERS = CONTEXT_AMD64 | 0x10,
        SIZE_OF_JMP = 5,
        DYNAMIC = 1,
        ADDRESS = 2,
        NOENLARGE = 4,
        RAX = 8,
        SIB = 0x10,
        RIP = 0x20,
        NOTSIB = 0x0f,
        SCHAR_MIN = -128,
        SCHAR_MAX = 127,
        UCHAR_MAX = 0xff,
        CHAR_MIN = SCHAR_MIN,
        CHAR_MAX = SCHAR_MAX,
        SHRT_MIN = -32768,
        SHRT_MAX = 32767,
        LONG_MIN = -2147483647 - 1,
        LONG_MAX = 2147483647,
        IMAGE_DIRECTORY_ENTRY_IAT = 12
        ;
    public static byte[] DETOUR_STR_BYTES = Encoding.ASCII.GetBytes(".detour\0");
    public static byte* DETOUR_STR_BYTES_PTR = AllocFrom(DETOUR_STR_BYTES);
}

public struct DETOUR_LOADED_BINARY { }

public unsafe struct _GUID
{
    public _GUID(uint data1, ushort data2, ushort data3, params byte[] data4)
    {
        Data1 = data1;
        Data2 = data2;
        Data3 = data3;
        fixed (byte* data4Ptr = Data4)
            Copy(data4Ptr, data4);
    }

    public uint Data1;
    public ushort Data2;
    public ushort Data3;
    public fixed byte Data4[8];
}

public struct _DETOUR_SECTION_HEADER
{
    public int cbHeaderSize;
    public int nSignature;
    public int nDataOffset;
    public int cbDataSize;

    public int nOriginalImportVirtualAddress;
    public int nOriginalImportSize;
    public int nOriginalBoundImportVirtualAddress;
    public int nOriginalBoundImportSize;

    public int nOriginalIatVirtualAddress;
    public int nOriginalIatSize;
    public int nOriginalSizeOfImage;
    public int cbPrePE;

    public int nOriginalClrFlags;
    public int reserved1;
    public int reserved2;
    public int reserved3;
}

public struct _DETOUR_SECTION_RECORD
{
    public int cbBytes;
    public int nReserved;
    public GUID guid;
}

public unsafe struct _IMAGE_DOS_HEADER
{
    public short e_magic;   
    public short e_cblp;    
    public short e_cp;      
    public short e_crlc;    
    public short e_cparhdr; 
    public short e_minalloc;
    public short e_maxalloc;
    public short e_ss;      
    public short e_sp;      
    public short e_csum;    
    public short e_ip;      
    public short e_cs;      
    public short e_lfarlc;  
    public short e_ovno;    
    public fixed short e_res[4];  
    public short e_oemid;   
    public short e_oeminfo; 
    public fixed short e_res2[10];
    public long e_lfanew;  
}

[StructLayout(LayoutKind.Sequential)]
public struct _IMAGE_NT_HEADERS64
{
    public const int SIZE = sizeof(int) + IMAGE_FILE_HEADER.SIZE + IMAGE_OPTIONAL_HEADER64.SIZE;

    public int Signature;
    public IMAGE_FILE_HEADER FileHeader;
    public IMAGE_OPTIONAL_HEADER64 OptionalHeader;
}

public struct _IMAGE_FILE_HEADER
{
    public const int SIZE = sizeof(short) + sizeof(short) + sizeof(int) + sizeof(int) + sizeof(int) + sizeof(short) + sizeof(short);

    public short Machine;
    public short NumberOfSections;
    public int TimeDateStamp;
    public int PointerToSymbolTable;
    public int NumberOfSymbols;
    public short SizeOfOptionalHeader;
    public short Characteristics;
}

public unsafe struct _IMAGE_OPTIONAL_HEADER64
{
    public const int SIZE = sizeof(short) + sizeof(byte) + sizeof(byte) + sizeof(int) + sizeof(int) + sizeof(int) + sizeof(int) + sizeof(int) + sizeof(ulong) + sizeof(int) + sizeof(int) + sizeof(short) + sizeof(short) + sizeof(short) + sizeof(short) + sizeof(short) + sizeof(short) + sizeof(int) + sizeof(int) + sizeof(int) + sizeof(int) + sizeof(short) + sizeof(short) + sizeof(ulong) + sizeof(ulong) + sizeof(ulong) + sizeof(ulong) + sizeof(int) + sizeof(int) + (sizeof(long) * IMAGE_NUMBEROF_DIRECTORY_ENTRIES);
    public short Magic;
    public byte MajorLinkerVersion;
    public byte MinorLinkerVersion;
    public int SizeOfCode;
    public int SizeOfInitializedData;
    public int SizeOfUninitializedData;
    public int AddressOfEntryPoint;
    public int BaseOfCode;
    public ulong ImageBase;
    public int SectionAlignment;
    public int FileAlignment;
    public short MajorOperatingSystemVersion;
    public short MinorOperatingSystemVersion;
    public short MajorImageVersion;
    public short MinorImageVersion;
    public short MajorSubsystemVersion;
    public short MinorSubsystemVersion;
    public int Win32VersionValue;
    public int SizeOfImage;
    public int SizeOfHeaders;
    public int CheckSum;
    public short Subsystem;
    public short DllCharacteristics;
    public ulong SizeOfStackReserve;
    public ulong SizeOfStackCommit;
    public ulong SizeOfHeapReserve;
    public ulong SizeOfHeapCommit;
    public int LoaderFlags;
    public int NumberOfRvaAndSizes;
    public fixed long/*IMAGE_DATA_DIRECTORY*/ DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
}

public struct _IMAGE_DATA_DIRECTORY
{
    public int VirtualAddress;
    public int Size;
}

public unsafe struct _IMAGE_SECTION_HEADER
{
    public const int SIZE = sizeof(byte) * IMAGE_SIZEOF_SHORT_NAME + _IMAGE_SECTION_HEADER_Union_Misc.SIZE + sizeof(int) + sizeof(int) + sizeof(int) + sizeof(int) + sizeof(int) + sizeof(short) + sizeof(short) + sizeof(int);

    public fixed byte Name[IMAGE_SIZEOF_SHORT_NAME];
    public _IMAGE_SECTION_HEADER_Union_Misc Misc;
    public int VirtualAddress;
    public int SizeOfRawData;
    public int PointerToRawData;
    public int PointerToRelocations;
    public int PointerToLinenumbers;
    public short NumberOfRelocations;
    public short NumberOfLinenumbers;
    public int Characteristics;
}

[StructLayout(LayoutKind.Explicit)]
public struct _IMAGE_SECTION_HEADER_Union_Misc
{
    public const int SIZE = sizeof(int);

    [FieldOffset(0)]
    public int PhysicalAddress;
    [FieldOffset(0)]
    public int VirtualSize;
}

public unsafe struct _MEMORY_BASIC_INFORMATION
{
    public void* BaseAddress;
    public void* AllocationBase;
    public void* AllocationProtect;
    public short PartitionId;
    public nint RegionSize;
    public int State;
    public int Protect;
    public int Type;
};

public unsafe struct _DETOUR_EXE_RESTORE
{
    public int cb;
    public int cbidh;
    public int cbinh;
    public int cbclr;

    public byte* pidh;
    public byte* pinh;
    public byte* pclr;

    public IMAGE_DOS_HEADER idh;
    public _DETOUR_EXE_RESTORE_Union_unnamed union_unnamed;
    public DETOUR_CLR_HEADER clr;
}

public unsafe struct _DETOUR_EXE_RESTORE_Union_unnamed
{
    public IMAGE_NT_HEADERS inh;
    public IMAGE_NT_HEADERS32 inh32;
    public IMAGE_NT_HEADERS64 inh64;

    public fixed byte raw[IMAGE_NT_HEADERS64.SIZE + IMAGE_SECTION_HEADER.SIZE * DETOUR_MAX_SUPPORTED_IMAGE_SECTION_HEADERS];
}

public struct _DETOUR_CLR_HEADER
{
    public uint cb;
    public ushort MajorRuntimeVersion;
    public ushort MinorRuntimeVersion;

    public IMAGE_DATA_DIRECTORY MetaData;
    public ushort Flags;
}

public struct _IMAGE_NT_HEADERS
{
    int Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER32 OptionalHeader;
}

public unsafe struct _IMAGE_OPTIONAL_HEADER
{
    public int Magic;
    public byte MajorLinkerVersion;
    public byte MinorLinkerVersion;
    public int SizeOfCode;
    public int SizeOfInitializedData;
    public int SizeOfUninitializedData;
    public int AddressOfEntryPoint;
    public int BaseOfCode;
    public int BaseOfData;
    public int ImageBase;
    public int SectionAlignment;
    public int FileAlignment;
    public short MajorOperatingSystemVersion;
    public short MinorOperatingSystemVersion;
    public short MajorImageVersion;
    public short MinorImageVersion;
    public short MajorSubsystemVersion;
    public short MinorSubsystemVersion;
    public int Win32VersionValue;
    public int SizeOfImage;
    public int SizeOfHeaders;
    public int CheckSum;
    public short Subsystem;
    public short DllCharacteristics;
    public int SizeOfStackReserve;
    public int SizeOfStackCommit;
    public int SizeOfHeapReserve;
    public int SizeOfHeapCommit;
    public int LoaderFlags;
    public int NumberOfRvaAndSizes;
    public fixed long/*IMAGE_DATA_DIRECTORY*/ DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
};

public unsafe struct DetourThread
{
    public DetourThread* pNext;
    public nint hThread;
};

public unsafe struct DetourOperation
{
    public DetourOperation* pNext;
    public bool fIsRemove;
    public byte** ppbPointer;
    public byte* pbTarget;
    public DETOUR_TRAMPOLINE* pTrampoline;
    public uint dwPerm;
};

public unsafe struct _DETOUR_TRAMPOLINE
{
    public fixed byte rbCode[30];
    public byte cbCode;
    public byte cbCodeBreak;
    public fixed byte rbRestore[30];
    public byte cbRestore;
    public byte cbRestoreBreak;
    public fixed short/*_DETOUR_ALIGN*/ rAlign[8];
    public byte* pbRemain;
    public byte* pbDetour;
    public fixed byte rbCodeIn[8];
};

public struct _DETOUR_ALIGN
{
    public _DETOUR_ALIGN() { }

    public byte obTarget = 3;
    public byte obTrampoline = 5;
};

public unsafe struct DETOUR_REGION
{
    public uint dwSignature;
    public DETOUR_REGION* pNext;
    public DETOUR_TRAMPOLINE* pFree;
};

[StructLayout(LayoutKind.Sequential, Pack = 16)]
public unsafe struct _CONTEXT {
    public long P1Home;
    public long P2Home;
    public long P3Home;
    public long P4Home;
    public long P5Home;
    public long P6Home;
    public int ContextFlags;
    public int MxCsr;
    public short SegCs;
    public short SegDs;
    public short SegEs;
    public short SegFs;
    public short SegGs;
    public short SegSs;
    public int EFlags;
    public long Dr0;
    public long Dr1;
    public long Dr2;
    public long Dr3;
    public long Dr6;
    public long Dr7;
    public long Rax;
    public long Rcx;
    public long Rdx;
    public long Rbx;
    public long Rsp;
    public long Rbp;
    public long Rsi;
    public long Rdi;
    public long R8;
    public long R9;
    public long R10;
    public long R11;
    public long R12;
    public long R13;
    public long R14;
    public long R15;
    public long Rip;
    public _CONTEXT_Union_DUMMYUNIONNAME DUMMYUNIONNAME;
    public fixed long VectorRegisterAAA[26 * 2];
    public long VectorControl;
    public long DebugControl;
    public long LastBranchToRip;
    public long LastBranchFromRip;
    public long LastExceptionToRip;
    public long LastExceptionFromRip;
}

public unsafe struct _CONTEXT_Union_DUMMYUNIONNAME
{
    public XMM_SAVE_AREA32 FltSave;
    public DUMMYSTRUCTNAME DUMMYSTRUCTNAME;
}

public unsafe struct DUMMYSTRUCTNAME
{
    public fixed long HeaderAAA[2 * 2];
    public fixed long LegacyAAA[8 * 2];
    public M128A Xmm0;
    public M128A Xmm1;
    public M128A Xmm2;
    public M128A Xmm3;
    public M128A Xmm4;
    public M128A Xmm5;
    public M128A Xmm6;
    public M128A Xmm7;
    public M128A Xmm8;
    public M128A Xmm9;
    public M128A Xmm10;
    public M128A Xmm11;
    public M128A Xmm12;
    public M128A Xmm13;
    public M128A Xmm14;
    public M128A Xmm15;
}

[StructLayout(LayoutKind.Sequential, Pack = 16)]
public struct _M128A
{
    public ulong Low;
    public long High;
}

[StructLayout(LayoutKind.Sequential, Pack = 16)]
public unsafe struct _XSAVE_FORMAT {
    short   ControlWord;
    short StatusWord;
    byte TagWord;
    byte Reserved1;
    short ErrorOpcode;
    int ErrorOffset;
    short ErrorSelector;
    short Reserved2;
    int DataOffset;
    short DataSelector;
    short Reserved3;
    int MxCsr;
    int MxCsr_Mask;
    fixed long FloatRegistersAAA[8 * 2];
    fixed long XmmRegistersAAA[16 * 2];
    fixed byte Reserved4[96];
}

public enum ADDRESS_MODE
{
    AddrMode1616,
    AddrMode1632,
    AddrModeReal,
    AddrModeFlat
}

public struct _tagADDRESS64
{
    public long Offset;
    public short Segment;
    public ADDRESS_MODE Mode;
}