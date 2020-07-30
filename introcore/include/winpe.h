/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _WINPE_H_
#define _WINPE_H_

/// NOTE: This file contains MZ/PE related structures. As they are publicly documented in multiple sources, they
/// will not be described here at all. The definitions here have been taken from the Windows SDK.

#include "winguest.h"
#include "winumcache.h"


// MZ & PE signatures.
#define IMAGE_DOS_SIGNATURE     0x5A4D      // MZ signature.
#define IMAGE_NT_SIGNATURE      0x00004550  // PE00 signature.

// Data directories.
#define IMAGE_DIRECTORY_ENTRY_EXPORT          0   // Export Directory
#define IMAGE_DIRECTORY_ENTRY_IMPORT          1   // Import Directory
#define IMAGE_DIRECTORY_ENTRY_RESOURCE        2   // Resource Directory
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION       3   // Exception Directory
#define IMAGE_DIRECTORY_ENTRY_SECURITY        4   // Security Directory
#define IMAGE_DIRECTORY_ENTRY_BASERELOC       5   // Base Relocation Table
#define IMAGE_DIRECTORY_ENTRY_DEBUG           6   // Debug Directory
//      IMAGE_DIRECTORY_ENTRY_COPYRIGHT       7   // (X86 usage)
#define IMAGE_DIRECTORY_ENTRY_ARCHITECTURE    7   // Architecture Specific Data
#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR       8   // RVA of GP
#define IMAGE_DIRECTORY_ENTRY_TLS             9   // TLS Directory
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    10   // Load Configuration Directory
#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   11   // Bound Import Directory in headers
#define IMAGE_DIRECTORY_ENTRY_IAT            12   // Import Address Table
#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   13   // Delay Load Import Descriptors
#define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 14   // COM Runtime descriptor

// DOS header.
typedef struct _IMAGE_DOS_HEADER
{
    UINT16  e_magic;                     // Magic number
    UINT16  e_cblp;                      // Bytes on last page of file
    UINT16  e_cp;                        // Pages in file
    UINT16  e_crlc;                      // Relocations
    UINT16  e_cparhdr;                   // Size of header in paragraphs
    UINT16  e_minalloc;                  // Minimum extra paragraphs needed
    UINT16  e_maxalloc;                  // Maximum extra paragraphs needed
    UINT16  e_ss;                        // Initial (relative) SS value
    UINT16  e_sp;                        // Initial SP value
    UINT16  e_csum;                      // Checksum
    UINT16  e_ip;                        // Initial IP value
    UINT16  e_cs;                        // Initial (relative) CS value
    UINT16  e_lfarlc;                    // File address of relocation table
    UINT16  e_ovno;                      // Overlay number
    UINT16  e_res[4];                    // Reserved words
    UINT16  e_oemid;                     // OEM identifier (for e_oeminfo)
    UINT16  e_oeminfo;                   // OEM information; e_oemid specific
    UINT16  e_res2[10];                  // Reserved words
    INT32   e_lfanew;                    // File address of new exe header
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

// File header.
typedef struct _IMAGE_FILE_HEADER
{
    UINT16  Machine;
    UINT16  NumberOfSections;
    UINT32  TimeDateStamp;
    UINT32  PointerToSymbolTable;
    UINT32  NumberOfSymbols;
    UINT16  SizeOfOptionalHeader;
    UINT16  Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

// Size of the section name.
#define IMAGE_SIZEOF_SHORT_NAME              8u

// Section header.
typedef struct _IMAGE_SECTION_HEADER
{
    UINT8   Name[IMAGE_SIZEOF_SHORT_NAME];
    union
    {
        UINT32  PhysicalAddress;
        UINT32  VirtualSize;
    } Misc;
    UINT32  VirtualAddress;
    UINT32  SizeOfRawData;
    UINT32  PointerToRawData;
    UINT32  PointerToRelocations;
    UINT32  PointerToLinenumbers;
    UINT16  NumberOfRelocations;
    UINT16  NumberOfLinenumbers;
    UINT32  Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

// Data directory.
typedef struct _IMAGE_DATA_DIRECTORY
{
    UINT32  VirtualAddress;
    UINT32  Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

// Maximum number of data directories.
#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES    16

// Resource data entry.
typedef struct _IMAGE_RESOURCE_DATA_ENTRY
{
    UINT32  OffsetToData;
    UINT32  Size;
    UINT32  CodePage;
    UINT32  Reserved;
} IMAGE_RESOURCE_DATA_ENTRY, *PIMAGE_RESOURCE_DATA_ENTRY;

// Resource directory entry.
typedef struct _IMAGE_RESOURCE_DIRECTORY_ENTRY
{
    union
    {
        struct
        {
            UINT32 NameOffset : 31;
            UINT32 NameIsString : 1;
        };
        UINT32  Name;
        UINT16  Id;
    };
    union
    {
        UINT32  OffsetToData;
        struct
        {
            UINT32  OffsetToDirectory : 31;
            UINT32  DataIsDirectory : 1;
        };
    };
} IMAGE_RESOURCE_DIRECTORY_ENTRY, *PIMAGE_RESOURCE_DIRECTORY_ENTRY;

// Optional header.
typedef struct _IMAGE_OPTIONAL_HEADER
{
    //
    // Standard fields.
    //

    UINT16  Magic;
    UINT8   MajorLinkerVersion;
    UINT8   MinorLinkerVersion;
    UINT32  SizeOfCode;
    UINT32  SizeOfInitializedData;
    UINT32  SizeOfUninitializedData;
    UINT32  AddressOfEntryPoint;
    UINT32  BaseOfCode;
    UINT32  BaseOfData;

    //
    // NT additional fields.
    //

    UINT32  ImageBase;
    UINT32  SectionAlignment;
    UINT32  FileAlignment;
    UINT16  MajorOperatingSystemVersion;
    UINT16  MinorOperatingSystemVersion;
    UINT16  MajorImageVersion;
    UINT16  MinorImageVersion;
    UINT16  MajorSubsystemVersion;
    UINT16  MinorSubsystemVersion;
    UINT32  Win32VersionValue;
    UINT32  SizeOfImage;
    UINT32  SizeOfHeaders;
    UINT32  CheckSum;
    UINT16  Subsystem;
    UINT16  DllCharacteristics;
    UINT32  SizeOfStackReserve;
    UINT32  SizeOfStackCommit;
    UINT32  SizeOfHeapReserve;
    UINT32  SizeOfHeapCommit;
    UINT32  LoaderFlags;
    UINT32  NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;

typedef struct _IMAGE_OPTIONAL_HEADER64
{
    UINT16  Magic;
    UINT8   MajorLinkerVersion;
    UINT8   MinorLinkerVersion;
    UINT32  SizeOfCode;
    UINT32  SizeOfInitializedData;
    UINT32  SizeOfUninitializedData;
    UINT32  AddressOfEntryPoint;
    UINT32  BaseOfCode;
    UINT64  ImageBase;
    UINT32  SectionAlignment;
    UINT32  FileAlignment;
    UINT16  MajorOperatingSystemVersion;
    UINT16  MinorOperatingSystemVersion;
    UINT16  MajorImageVersion;
    UINT16  MinorImageVersion;
    UINT16  MajorSubsystemVersion;
    UINT16  MinorSubsystemVersion;
    UINT32  Win32VersionValue;
    UINT32  SizeOfImage;
    UINT32  SizeOfHeaders;
    UINT32  CheckSum;
    UINT16  Subsystem;
    UINT16  DllCharacteristics;
    UINT64  SizeOfStackReserve;
    UINT64  SizeOfStackCommit;
    UINT64  SizeOfHeapReserve;
    UINT64  SizeOfHeapCommit;
    UINT32  LoaderFlags;
    UINT32  NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;

typedef struct _IMAGE_NT_HEADERS64
{
    UINT32 Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;

typedef struct _IMAGE_NT_HEADERS
{
    UINT32 Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;


typedef struct _IMAGE_IMPORT_DESCRIPTOR
{
    union
    {
        UINT32  Characteristics;        // 0 for terminating null import descriptor
        UINT32  LookupTable;            // Import Lookup Table RVA (pecoff_v8.docx pg 76)
    } u;
    UINT32  TimeDateStamp;              // 0 if not bound,
    // -1 if bound, and real date\time stamp
    //     in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (new BIND)
    // O.W. date/time stamp of DLL bound to (Old BIND)

    UINT32  ForwarderChain;             // -1 if no forwarders
    UINT32  Name;
    UINT32  FirstThunk;                 // RVA to IAT (if bound this IAT has actual addresses)
} IMAGE_IMPORT_DESCRIPTOR;
typedef IMAGE_IMPORT_DESCRIPTOR *PIMAGE_IMPORT_DESCRIPTOR;

typedef struct _IMAGE_IMPORT_BY_NAME
{
    UINT16  Hint;
    UINT8   Name[1];
} IMAGE_IMPORT_BY_NAME, *PIMAGE_IMPORT_BY_NAME;


// 8 Byte packing needed here
#pragma pack(push)
#pragma pack(8)
typedef struct _IMAGE_THUNK_DATA64
{
    union
    {
        UINT64 ForwarderString;  // PUCHAR
        UINT64 Function;         // PULONG
        UINT64 Ordinal;
        UINT64 AddressOfData;    // IMAGE_IMPORT_BY_NAME
    } u1;
} IMAGE_THUNK_DATA64, *PIMAGE_THUNK_DATA64;
#pragma pack(pop)

// Back to 4 byte packing
typedef struct _IMAGE_THUNK_DATA32
{
    union
    {
        UINT32 ForwarderString;      // PUCHAR
        UINT32 Function;             // PULONG
        UINT32 Ordinal;
        UINT32 AddressOfData;        // IMAGE_IMPORT_BY_NAME
    } u1;
} IMAGE_THUNK_DATA32, *PIMAGE_THUNK_DATA32;


//
// Based relocation format.
//
typedef struct _IMAGE_BASE_RELOCATION
{
    UINT32   VirtualAddress;
    UINT32   SizeOfBlock;
    //  UINT16  TypeOffset[1];
} IMAGE_BASE_RELOCATION;
typedef IMAGE_BASE_RELOCATION *PIMAGE_BASE_RELOCATION;



//
// IMAGE_FIRST_SECTION doesn't need 32/64 versions since the file header is the same either way.
//
#define IMAGE_FIRST_SECTION( ntheader ) ((IMAGE_SECTION_HEADER)        \
    ((size_t *)(ntheader) +                                            \
     FIELD_OFFSET( IMAGE_NT_HEADERS, OptionalHeader ) +                 \
     ((ntheader))->FileHeader.SizeOfOptionalHeader   \
    ))

//
// Based relocation types.
//
#define IMAGE_REL_BASED_ABSOLUTE              0
#define IMAGE_REL_BASED_HIGH                  1
#define IMAGE_REL_BASED_LOW                   2
#define IMAGE_REL_BASED_HIGHLOW               3
#define IMAGE_REL_BASED_HIGHADJ               4
#define IMAGE_REL_BASED_MIPS_JMPADDR          5
// end_winnt
#define IMAGE_REL_BASED_SECTION               6
#define IMAGE_REL_BASED_REL32                 7
//      IMAGE_REL_BASED_VXD_RELATIVE          8
// begin_winnt
#define IMAGE_REL_BASED_MIPS_JMPADDR16        9
#define IMAGE_REL_BASED_IA64_IMM64            9
#define IMAGE_REL_BASED_DIR64                 10



typedef struct _IMAGE_EXPORT_DIRECTORY
{
    UINT32  Characteristics;
    UINT32  TimeDateStamp;
    UINT16  MajorVersion;
    UINT16  MinorVersion;
    UINT32  Name;
    UINT32  Base;
    UINT32  NumberOfFunctions;
    UINT32  NumberOfNames;
    UINT32  AddressOfFunctions;     // RVA from base of image
    UINT32  AddressOfNames;         // RVA from base of image
    UINT32  AddressOfNameOrdinals;  // RVA from base of image
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;

typedef struct _IMAGE_RESOURCE_DIRECTORY
{
    UINT32  Characteristics;
    UINT32  TimeDateStamp;
    UINT16  MajorVersion;
    UINT16  MinorVersion;
    UINT16  NumberOfNamedEntries;
    UINT16  NumberOfIdEntries;
    //  IMAGE_RESOURCE_DIRECTORY_ENTRY DirectoryEntries[];
} IMAGE_RESOURCE_DIRECTORY, *PIMAGE_RESOURCE_DIRECTORY;


//
// New format import descriptors pointed to by DataDirectory[ IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT ]
//

typedef struct _IMAGE_BOUND_IMPORT_DESCRIPTOR
{
    UINT32  TimeDateStamp;
    UINT16  OffsetModuleName;
    UINT16  NumberOfModuleForwarderRefs;
    // Array of zero or more IMAGE_BOUND_FORWARDER_REF follows
} IMAGE_BOUND_IMPORT_DESCRIPTOR, *PIMAGE_BOUND_IMPORT_DESCRIPTOR;



//
// Exception structures on 64 bit windows
//
#pragma pack(push)
#pragma pack(1)
typedef struct _RUNTIME_FUNCTION
{
    UINT32 BeginAddress;
    UINT32 EndAddress;
    UINT32 UnwindData;
} RUNTIME_FUNCTION, *PRUNTIME_FUNCTION;
#ifdef INT_COMPILER_MSVC
//warning C4214: nonstandard extension used: bit field types other than int (compiling source file agent.c)
#pragma warning(push)
#pragma warning(disable:4214)
#endif
typedef struct _UNWIND_INFO
{
    UINT8 Version : 3;
    UINT8 Flags : 5;
    UINT8 SizeOfProlog;
    UINT8 CountOfCodes;
    UINT8 FrameRegister : 4;
    UINT8 FrameOffset : 4;
    struct
    {
        UINT8 CodeOffset;
        UINT8 UnwindOp : 4;
        UINT8 OpInfo : 4;
    } UnwindCode[1];
} UNWIND_INFO, *PUNWIND_INFO;
#ifdef INT_COMPILER_MSVC
#pragma warning(pop)
#endif

#pragma pack(pop)

//
// UNWIND_INFO.Flags defines.
// These aren't actually flags, but values! So don't use them like Flags & .... but like Flags == ...
//
#define UNW_FLAG_NHANDLER                   0x00000000
#define UNW_FLAG_EHANDLER                   0x00000001
#define UNW_FLAG_UHANDLER                   0x00000002
#define UNW_FLAG_FHANDLER                   0x00000003         // unofficial
#define UNW_FLAG_CHAININFO                  0x00000004

//
// Section characteristics.
//
//      IMAGE_SCN_TYPE_REG                   0x00000000  // Reserved.
//      IMAGE_SCN_TYPE_DSECT                 0x00000001  // Reserved.
//      IMAGE_SCN_TYPE_NOLOAD                0x00000002  // Reserved.
//      IMAGE_SCN_TYPE_GROUP                 0x00000004  // Reserved.
#define IMAGE_SCN_TYPE_NO_PAD                0x00000008  // Reserved.
//      IMAGE_SCN_TYPE_COPY                  0x00000010  // Reserved.

#define IMAGE_SCN_CNT_CODE                   0x00000020  // Section contains code.
#define IMAGE_SCN_CNT_INITIALIZED_DATA       0x00000040  // Section contains initialized data.
#define IMAGE_SCN_CNT_UNINITIALIZED_DATA     0x00000080  // Section contains uninitialized data.

#define IMAGE_SCN_LNK_OTHER                  0x00000100  // Reserved.
#define IMAGE_SCN_LNK_INFO                   0x00000200  // Section contains comments or some other type of information.
//      IMAGE_SCN_TYPE_OVER                  0x00000400  // Reserved.
#define IMAGE_SCN_LNK_REMOVE                 0x00000800  // Section contents will not become part of image.
#define IMAGE_SCN_LNK_COMDAT                 0x00001000  // Section contents comdat.
//                                           0x00002000  // Reserved.
//      IMAGE_SCN_MEM_PROTECTED - Obsolete   0x00004000

// Reset speculative exceptions handling bits in the TLB entries for this section.
#define IMAGE_SCN_NO_DEFER_SPEC_EXC          0x00004000

// Section content can be accessed relative to GP
#define IMAGE_SCN_GPREL                      0x00008000

#define IMAGE_SCN_MEM_FARDATA                0x00008000
//      IMAGE_SCN_MEM_SYSHEAP  - Obsolete    0x00010000
#define IMAGE_SCN_MEM_PURGEABLE              0x00020000
#define IMAGE_SCN_MEM_16BIT                  0x00020000
#define IMAGE_SCN_MEM_LOCKED                 0x00040000
#define IMAGE_SCN_MEM_PRELOAD                0x00080000

#define IMAGE_SCN_ALIGN_1BYTES               0x00100000  //
#define IMAGE_SCN_ALIGN_2BYTES               0x00200000  //
#define IMAGE_SCN_ALIGN_4BYTES               0x00300000  //
#define IMAGE_SCN_ALIGN_8BYTES               0x00400000  //
#define IMAGE_SCN_ALIGN_16BYTES              0x00500000  // Default alignment if no others are specified.
#define IMAGE_SCN_ALIGN_32BYTES              0x00600000  //
#define IMAGE_SCN_ALIGN_64BYTES              0x00700000  //
#define IMAGE_SCN_ALIGN_128BYTES             0x00800000  //
#define IMAGE_SCN_ALIGN_256BYTES             0x00900000  //
#define IMAGE_SCN_ALIGN_512BYTES             0x00A00000  //
#define IMAGE_SCN_ALIGN_1024BYTES            0x00B00000  //
#define IMAGE_SCN_ALIGN_2048BYTES            0x00C00000  //
#define IMAGE_SCN_ALIGN_4096BYTES            0x00D00000  //
#define IMAGE_SCN_ALIGN_8192BYTES            0x00E00000  //
// Unused                                    0x00F00000
#define IMAGE_SCN_ALIGN_MASK                 0x00F00000

#define IMAGE_SCN_LNK_NRELOC_OVFL            0x01000000  // Section contains extended relocations.
#define IMAGE_SCN_MEM_DISCARDABLE            0x02000000  // Section can be discarded.
#define IMAGE_SCN_MEM_NOT_CACHED             0x04000000  // Section is not cachable.
#define IMAGE_SCN_MEM_NOT_PAGED              0x08000000  // Section is not pageable.
#define IMAGE_SCN_MEM_SHARED                 0x10000000  // Section is shareable.
#define IMAGE_SCN_MEM_EXECUTE                0x20000000  // Section is executable.
#define IMAGE_SCN_MEM_READ                   0x40000000  // Section is readable.
#define IMAGE_SCN_MEM_WRITE                  0x80000000  // Section is writeable.

//
// Image machine types
//
#define IMAGE_FILE_MACHINE_UNKNOWN           0
#define IMAGE_FILE_MACHINE_I386              0x014c  // Intel 386.
#define IMAGE_FILE_MACHINE_R3000             0x0162  // MIPS little-endian, 0x160 big-endian
#define IMAGE_FILE_MACHINE_R4000             0x0166  // MIPS little-endian
#define IMAGE_FILE_MACHINE_R10000            0x0168  // MIPS little-endian
#define IMAGE_FILE_MACHINE_WCEMIPSV2         0x0169  // MIPS little-endian WCE v2
#define IMAGE_FILE_MACHINE_ALPHA             0x0184  // Alpha_AXP
#define IMAGE_FILE_MACHINE_SH3               0x01a2  // SH3 little-endian
#define IMAGE_FILE_MACHINE_SH3DSP            0x01a3
#define IMAGE_FILE_MACHINE_SH3E              0x01a4  // SH3E little-endian
#define IMAGE_FILE_MACHINE_SH4               0x01a6  // SH4 little-endian
#define IMAGE_FILE_MACHINE_SH5               0x01a8  // SH5
#define IMAGE_FILE_MACHINE_ARM               0x01c0  // ARM Little-Endian
#define IMAGE_FILE_MACHINE_THUMB             0x01c2
#define IMAGE_FILE_MACHINE_AM33              0x01d3
#define IMAGE_FILE_MACHINE_POWERPC           0x01F0  // IBM PowerPC Little-Endian
#define IMAGE_FILE_MACHINE_POWERPCFP         0x01f1
#define IMAGE_FILE_MACHINE_IA64              0x0200  // Intel 64
#define IMAGE_FILE_MACHINE_MIPS16            0x0266  // MIPS
#define IMAGE_FILE_MACHINE_ALPHA64           0x0284  // ALPHA64
#define IMAGE_FILE_MACHINE_MIPSFPU           0x0366  // MIPS
#define IMAGE_FILE_MACHINE_MIPSFPU16         0x0466  // MIPS
#define IMAGE_FILE_MACHINE_AXP64             IMAGE_FILE_MACHINE_ALPHA64
#define IMAGE_FILE_MACHINE_TRICORE           0x0520  // Infineon
#define IMAGE_FILE_MACHINE_CEF               0x0CEF
#define IMAGE_FILE_MACHINE_EBC               0x0EBC  // EFI Byte Code
#define IMAGE_FILE_MACHINE_AMD64             0x8664  // AMD64 (K8)
#define IMAGE_FILE_MACHINE_M32R              0x9041  // M32R little-endian
#define IMAGE_FILE_MACHINE_CEE               0xC0EE

//
// Image subsystem definitions
//
#define IMAGE_SUBSYSTEM_UNKNOWN              0   // Unknown subsystem.
#define IMAGE_SUBSYSTEM_NATIVE               1   // Image doesn't require a subsystem.
#define IMAGE_SUBSYSTEM_WINDOWS_GUI          2   // Image runs in the Windows GUI subsystem.
#define IMAGE_SUBSYSTEM_WINDOWS_CUI          3   // Image runs in the Windows character subsystem.
#define IMAGE_SUBSYSTEM_OS2_CUI              5   // image runs in the OS/2 character subsystem.
#define IMAGE_SUBSYSTEM_POSIX_CUI            7   // image runs in the Posix character subsystem.
#define IMAGE_SUBSYSTEM_NATIVE_WINDOWS       8   // image is a native Win9x driver.
#define IMAGE_SUBSYSTEM_WINDOWS_CE_GUI       9   // Image runs in the Windows CE subsystem.
#define IMAGE_SUBSYSTEM_EFI_APPLICATION      10  //
#define IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER  11   //
#define IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER   12  //
#define IMAGE_SUBSYSTEM_EFI_ROM              13
#define IMAGE_SUBSYSTEM_XBOX                 14
#define IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION 16

//
// DllCharacteristics Entries
//

//      IMAGE_LIBRARY_PROCESS_INIT            0x0001     // Reserved.
//      IMAGE_LIBRARY_PROCESS_TERM            0x0002     // Reserved.
//      IMAGE_LIBRARY_THREAD_INIT             0x0004     // Reserved.
//      IMAGE_LIBRARY_THREAD_TERM             0x0008     // Reserved.
#define IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE 0x0040     // DLL can move.
#define IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY    0x0080     // Code Integrity Image
#define IMAGE_DLLCHARACTERISTICS_NX_COMPAT    0x0100     // Image is NX compatible
#define IMAGE_DLLCHARACTERISTICS_NO_ISOLATION 0x0200     // Image understands isolation and doesn't want it

// Image does not use SEH.  No SE handler may reside in this image
#define IMAGE_DLLCHARACTERISTICS_NO_SEH       0x0400

#define IMAGE_DLLCHARACTERISTICS_NO_BIND      0x0800     // Do not bind this image.
//                                            0x1000     // Reserved.
#define IMAGE_DLLCHARACTERISTICS_WDM_DRIVER   0x2000     // Driver uses WDM model
//                                            0x4000     // Reserved.
#define IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE     0x8000


#define IMAGE_OPTIONAL_HEADER_PE32            0x010b
#define IMAGE_OPTIONAL_HEADER_PE64            0x020b


///
/// Unwind information.
///
typedef struct _INTRO_UNWIND_INFO
{
    UINT8 Version : 3;
    UINT8 Flags : 5;
    UINT8 SizeOfProlog;
    UINT8 CountOfCodes;
    UINT8 FrameRegister : 4;
    UINT8 FrameOffset : 4;
    struct
    {
        UINT8 CodeOffset;
        UINT8 UnwindOp : 4;
        UINT8 OpInfo : 4;
    } UnwindCode[];
} INTRO_UNWIND_INFO, * PINTRO_UNWIND_INFO;



typedef struct _WIN_UNEXPORTED_FUNCTION WIN_UNEXPORTED_FUNCTION;


/// The maximum size of a path (260 characters on windows).
#define MAX_PATH            260u

/// The maximum length (in bytes) of a function.
#define MAX_FUNC_LENGTH     0xa00

#define MAX_FILE_ALIGNMENT  0x10000
#define MIN_FILE_ALIGNMENT  0x200

/// the maximum number of sections limited by the Windows loader
/// see https://msdn.microsoft.com/en-us/library/windows/desktop/ms680547(v=vs.85).aspx#file_headers
#define MAX_NUMBER_SECTIONS 96

///
/// Intro PE info structure.
///
typedef struct _INTRO_PE_INFO
{
    BOOLEAN     Image64Bit;         ///< True if the image is 64 bit.
    WORD        Subsystem;          ///< Subsystem.
    WORD        Machine;            ///< Machine type.
    DWORD       SizeOfImage;        ///< Size of the image.
    DWORD       TimeDateStamp;      ///< Time/date stamp.
    DWORD       EntryPoint;         ///< Entry point (RVA).
    QWORD       SectionOffset;      ///< Offset of the first section header.
    QWORD       NumberOfSections;   ///< Number of sections.
    DWORD       SectionAlignment;   ///< Sections alignment.
    QWORD       ImageBase;          ///< Image base.
} INTRO_PE_INFO, *PINTRO_PE_INFO;


//
// PE stuff
//
INTSTATUS
IntPeGetRuntimeFunction(
    _In_ QWORD ImageBase,
    _In_opt_ BYTE *ImageBaseBuffer,
    _In_ DWORD Rva,
    _Out_ RUNTIME_FUNCTION *RuntimeFunction
    );

INTSTATUS
IntPeGetRuntimeFunctionInBuffer(
    _In_ QWORD ImageBase,
    _In_ BYTE *Buffer,
    _In_ DWORD BufferSize,
    _In_ DWORD Rva,
    _Out_ RUNTIME_FUNCTION *RuntimeFunction
    );

INTSTATUS
IntPeParseUnwindData(
    _In_ QWORD ImageBase,
    _In_opt_ BYTE *ImageBaseBuffer,
    _In_ RUNTIME_FUNCTION *RuntimeFunction,
    _In_opt_ DWORD RipOffset,
    _Out_opt_ DWORD *ReservedStack,
    _Out_opt_ DWORD *BeginAddress,
    _Out_opt_ BOOLEAN *InterruptFunction,
    _Out_opt_ BOOLEAN *ExceptionFunction,
    _Out_opt_ BOOLEAN *HasFramePointer
    );

INTSTATUS
IntPeParseUnwindDataInBuffer(
    _In_ QWORD ImageBase,
    _In_ BYTE *Buffer,
    _In_ DWORD BufferSize,
    _In_ RUNTIME_FUNCTION *RuntimeFunction,
    _In_opt_ DWORD RipOffset,
    _Out_opt_ DWORD *ReservedStack,
    _Out_opt_ DWORD *BeginAddress,
    _Out_opt_ BOOLEAN *InterruptFunction,
    _Out_opt_ BOOLEAN *ExceptionFunction,
    _Out_opt_ BOOLEAN *HasFramePointer
    );

INTSTATUS
IntPeFindFunctionStartInBuffer(
    _In_ QWORD ImageBase,
    _In_ BYTE *Buffer,
    _In_ DWORD BufferSize,
    _In_ DWORD Rva,
    _Out_ DWORD *BeginAddress
    );

INTSTATUS
IntPeFindExportByNameInBuffer(
    _In_ QWORD ImageBase,
    _In_bytecount_(BufferSize) BYTE *Buffer,
    _In_ DWORD BufferSize,
    _In_z_ const char *Name,
    _Out_ DWORD *ExportRva
    );

INTSTATUS
IntPeFindKernelExport(
    _In_z_ const char *Name,
    _Out_ QWORD *ExportGva
    );

INTSTATUS
IntPeFindExportByName(
    _In_ QWORD ImageBase,
    _In_opt_ BYTE *ImageBaseBuffer,
    _In_z_ CHAR *Name,
    _Out_ DWORD *ExportRva
    );

INTSTATUS
IntPeFindExportByOrdinal(
    _In_ QWORD ImageBase,
    _In_opt_ BYTE *ImageBaseBuffer,
    _In_ DWORD Ordinal,
    _Out_ DWORD *ExportRva
    );

INTSTATUS
IntPeGetExportNameByRva(
    _In_ QWORD ImageBase,
    _In_opt_ BYTE *ImageBaseBuffer,
    _In_ DWORD Rva,
    _In_ DWORD ExportNameSize,
    _Out_writes_z_(ExportNameSize) CHAR *ExportName
    );

INTSTATUS
IntPeGetExportNameByRvaInBuffer(
    _In_ QWORD ImageBase,
    _In_ BYTE *Buffer,
    _In_ DWORD BufferSize,
    _In_ DWORD Rva,
    _In_ DWORD ExportNameSize,
    _Out_writes_z_(ExportNameSize) CHAR *ExportName
    );

INTSTATUS
IntPeFindExportByRvaInBuffer(
    _In_ QWORD ImageBase,
    _In_ BYTE *Buffer,
    _In_ DWORD BufferSize,
    _In_ DWORD Rva
    );

INTSTATUS
IntPeFindExportByRva(
    _In_ QWORD ImageBase,
    _In_opt_ BYTE *ImageBaseBuffer,
    _In_ DWORD Rva
    );

INTSTATUS
IntPeFindFunctionStart(
    _In_ QWORD ImageBase,
    _In_opt_ BYTE *ImageBaseBuffer,
    _In_ DWORD Rva,
    _Out_ DWORD *BeginAddress
    );

INTSTATUS
IntPeGetSectionHeaderByRva(
    _In_ QWORD ImageBase,
    _In_opt_ BYTE *ImageBaseBuffer,
    _In_ DWORD GuestRva,
    _Out_ IMAGE_SECTION_HEADER *SectionHeader
    );

INTSTATUS
IntPeGetSectionHeaderByIndex(
    _In_ QWORD ImageBase,
    _In_opt_ BYTE *ImageBaseBuffer,
    _In_ DWORD Index,
    _Out_ IMAGE_SECTION_HEADER *SectionHeader
    );

INTSTATUS
IntPeGetSectionHeadersByName(
    _In_ QWORD ImageBase,
    _In_opt_ BYTE *ImageBaseBuffer,
    _In_reads_or_z_(8) PCHAR Name,
    _In_ DWORD NumberOfSectionHeadersAllocated,
    _In_ QWORD Cr3,
    _Out_ IMAGE_SECTION_HEADER *SectionHeaders,
    _Out_opt_ DWORD *NumberOfSectionHeadersFilled
    );

#define IntPeGetSectionHeaderByName(Base, Buff, Name, Cr3, Sec)  \
    IntPeGetSectionHeadersByName((Base), (Buff), (Name), 1, (Cr3), (Sec), NULL)

INTSTATUS
IntPeGetDirectory(
    _In_ QWORD ImageBase,
    _In_opt_ BYTE *ImageBaseBuffer,
    _In_ DWORD DirectoryEntry,
    _Out_ IMAGE_DATA_DIRECTORY *Directory
    );

INTSTATUS
IntPeValidateHeader(
    _In_ QWORD ImageBase,
    _In_opt_ BYTE *ImageBaseBuffer,
    _In_opt_ DWORD ImageBaseBufferSize,
    _Out_opt_ INTRO_PE_INFO *PeInfo,
    _In_opt_ QWORD Cr3
    );

INTSTATUS
IntPeListSectionsHeaders(
    _In_ QWORD ImageBase,
    _In_opt_ BYTE *ImageBuffer,
    _In_opt_ DWORD ImageBufferSize,
    _Out_ DWORD *FirstSectionOffset,
    _Out_ DWORD *SectionCount
    );

INTSTATUS
IntPeFindFunctionByPattern(
    _In_ QWORD ImageBase,
    _In_ WIN_UNEXPORTED_FUNCTION_PATTERN *Pattern,
    _In_ BOOLEAN IgnoreSectionHint,
    _Out_ DWORD *Rva
    );

INTSTATUS
IntPeFindFunctionByPatternInBuffer(
    _In_bytecount_(BufferSize) BYTE *Buffer,
    _In_ DWORD BufferSize,
    _In_ WIN_UNEXPORTED_FUNCTION_PATTERN *Pattern,
    _In_ BOOLEAN IgnoreSectionHint,
    _Out_ DWORD *Rva
    );

#endif
