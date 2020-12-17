/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "serializers.h"
#include "guests.h"
#include "lixmm.h"
#include "winprocesshp.h"
#include "codeblocks.h"
#include "crc32.h"
#include "lixfiles.h"


#pragma pack(push, 1)

///
/// @brief Describes the serialized exception type.
///
typedef enum _SERIALIZER_EXCEPTION_TYPE
{
    serializerExceptionTypeKm = 0,      ///< Used for kernel-mode exceptions.
    serializerExceptionTypeUm = 1,      ///< Used for user-mode exceptions.
    serializerExceptionTypeKmUm = 2     ///< Used for kernel-user mode exceptions.
} SERIALIZER_EXCEPTION_TYPE;


///
/// @brief Describes the header of the serializer buffer.
///
typedef struct _SERIALIZER_HEADER
{
    DWORD       SerializedType;         ///< The type of the serialized exception (#SERIALIZER_EXCEPTION_TYPE)
    DWORD       Guest;                  ///< The operation system.
    DWORD       Event;                  ///< The intro event type.
    WORD        Size;                   ///< The size (bytes) of the serializer buffer.
    DWORD       Arch;                   ///< The architecture of the current guest.
} SERIALIZER_HEADER;


///
/// @brief Describes the header for each serialized item.
///
typedef struct _SERIALIZER_OBJECT_HEADER
{
    DWORD       Version;                    ///< The version of the serialized object (used for compatibility).
    WORD        Type;                       ///< The type of the sterilized object.
    WORD        Size;                       ///< The size of the serialized object.
} SERIALIZER_OBJECT_HEADER;


///
/// @brief Describes a serialized string.
///
typedef struct _SERIALIZER_STRING
{
    DWORD   Length;                     ///< The length of the string.
    BYTE    Encode;                     ///< The encode type of the string (utf-8, utf-16).
    CHAR    String[0];                  ///< The content of the string.
} SERIALIZER_STRING, *PSERIALIZER_STRING;


///
/// @brief Describes a serialized intObjKmOriginator object.
///
typedef struct _SERIALIZER_EXCEPTION_KM_ORIGINATOR
{
    BYTE _Reserved;                     ///< Unused.
} SERIALIZER_EXCEPTION_KM_ORIGINATOR, *PSERIALIZER_EXCEPTION_KM_ORIGINATOR;

///
/// @brief Describes a serialized intObjUmOriginator object.
///
typedef struct _SERIALIZER_EXCEPTION_UM_ORIGINATOR
{
    BYTE _Reserved;                     ///< Unused.
} SERIALIZER_EXCEPTION_UM_ORIGINATOR, *PSERIALIZER_EXCEPTION_UM_ORIGINATOR;


///
/// @brief Describes a serialized intObjVictim object.
///
typedef struct _SERIALIZER_EXCEPTION_VICTIM
{
    INTRO_OBJECT_TYPE   Type;               ///< The type of the victim object.
    ZONE_TYPE           ZoneType;           ///< The zone-type of the victim object.
    QWORD               ZoneFlags;          ///< The zone-flags of the victim object.
} SERIALIZER_EXCEPTION_VICTIM, *PSERIALIZER_EXCEPTION_VICTIM;


///
/// @brief Describes a serialized intObjEpt object.
///
typedef struct _SERIALIZER_EPT
{
    QWORD   Gva;                            ///< The written/read/exec guest virtual address.
    QWORD   Gpa;                            ///< The written/read/exec guest physical address.
    BYTE    Type;                           ///< The violation type.
} SERIALIZER_EPT, *PSERIALIZER_EPT;


///
/// @brief Describes a serialized intObjMsr object.
///
typedef struct _SERIALIZER_MSR
{
    DWORD   Msr;                            ///< The written MSR.
} SERIALIZER_MSR, *PSERIALIZER_MSR;


///
/// @brief Describes a serialized intObjCr object.
///
typedef struct _SERIALIZER_CR
{
    DWORD   Cr;                             ///< The written CR.
} SERIALIZER_CR, *PSERIALIZER_CR;


///
/// @brief Describes a serialized intObjDtr object.
///
typedef struct _SERIALIZER_DTR
{
    DWORD   Type;                           ///< The type of the modified DTR.
} SERIALIZER_DTR, *PSERIALIZER_DTR;


///
/// @brief Describes a serialized intObjIdt object.
///
typedef struct _SERIALIZER_IDT
{
    DWORD   Entry;                          ///< The modified entry from the IDT.
} SERIALIZER_IDT, *PSERIALIZER_IDT;


///
/// @brief Describes a serialized intObjInjection object.
///
typedef struct _SERIALIZER_INJECTION
{
    QWORD   Gva;                            ///< The guest virtual address in which the injection occurs.
    DWORD   Length;                         ///< The length of the injection.
    DWORD   Type;                           ///< The injection type.
} SERIALIZER_INJECTION, *PSERIALIZER_INJECTION;


///
/// @brief Describes a serialized intObjLixProcess object.
///
typedef struct _SERIALIZER_LIX_PROCESS
{
    QWORD Gva;                              ///< The guest virtual address of the task_struct.
    QWORD RealParent;                       ///< The guest virtual address of the task_struct->real_parent.
    QWORD ActualParent;                     ///< The guest virtual address of the parent process.
    QWORD Parent;                           ///< The guest virtual address of the task_struct->parent.
    QWORD MmGva;                            ///< The guest virtual address of the task_struct->mm.
    QWORD Cr3;                              ///< The CR3.
    DWORD Pid;                              ///< The PID.
    DWORD Tgid;                             ///< The TGID.
    DWORD Flags;                            ///< The protection flags.
} SERIALIZER_LIX_PROCESS, *PSERIALIZER_LIX_PROCESS;


///
/// @brief Describes a serialized intObjWinProcess object.
///
typedef struct _SERIALIZER_WIN_PROCESS
{
    QWORD EprocessAddress;                  ///< This will be the address of the EPROCESS.
    QWORD ParentEprocess;                   ///< The EPROCESS of the parent process.
    QWORD RealParentEprocess;               ///< The active EPROCESS at the moment of creation.
    QWORD Cr3;                              ///< Process PDBR. Includes PCID.
    QWORD UserCr3;                          ///< Process user PDBR. Includes PCID.
    DWORD Pid;                              ///< Process ID (the one used by Windows).
    QWORD Peb64Address;                     ///< PEB 64 address (on x86 OSes, this will be 0).
    QWORD Peb32Address;                     ///< PEB 32 address (on pure x64 processes, this will be 0).
    QWORD MainModuleAddress;                ///< The address of the main module.
    QWORD Flags;                            ///< The protection flags.
} SERIALIZER_WIN_PROCESS, *PSERIALIZER_WIN_PROCESS;


///
/// @brief Describes a serialized intObjLixVma object.
///
typedef struct _SERIALIZER_LIX_VMA
{
    QWORD Start;                            ///< Start of the memory described by the VMA.
    QWORD End;                              ///< End of the memory described by the VMA.
    /// @brief  The guest virtual address of the vm_area_struct this structure is based on.
    QWORD Gva;
    QWORD Flags;                            ///< Flags for the VMA.
    QWORD File;                             ///< The guest virtual address of the file this VMA maps to.
} SERIALIZER_LIX_VMA, *PSERIALIZER_LIX_VMA;


///
/// @brief Describes a serialized intObjWinVad object.
///
typedef struct _SERIALIZER_WIN_VAD
{
    QWORD StartPage;                        ///< The first page in the VAD.
    QWORD EndPage;                          ///< The last page in the VAD.
    /// @brief  The guest virtual address at which the corresponding Windows _MMVAD structure is located.
    QWORD VadGva;
    DWORD VadProtection;                    ///< The protection as represented inside the Windows kernel.
    DWORD VadType;                          ///< The type of the VAD.
    DWORD Protection;                       ///< VAD protection as represented by Introcore.
    DWORD ExecCount;                        ///< The number of execution violations triggered by pages inside this VAD.
    DWORD Flags;                            ///< The flags of the VAD.
} SERIALIZER_WIN_VAD, *PSERIALIZER_WIN_VAD;


///
/// @brief Describes a serialized intObjKernelDriver object.
///
typedef struct _SERIALIZER_KERNEL_DRIVER
{
    QWORD ObjectGva;                        ///< The guest virtual address at which this object resides.
    /// @brief  The guest virtual address of the kernel module that owns this driver object.
    QWORD BaseVa;
    QWORD Size;                             ///< The size of the kernel module that owns this driver object.
    QWORD EntryPoint;                       ///< The entry point of this driver.
} SERIALIZER_KERNEL_DRIVER, *PSERIALIZER_KERNEL_DRIVER;


///
/// @brief Describes a serialized intObjWinKernelDriver object.
///
typedef struct _SERIALIZER_WIN_KERNEL_DRIVER
{
    DWORD TimeDateStamp;                    ///< The driver's internal timestamp (from the _IMAGE_FILE_HEADER).
} SERIALIZER_WIN_KERNEL_DRIVER, *PSERIALIZER_WIN_KERNEL_DRIVER;


///
/// @brief Describes a serialized intObjLixKernelModule object.
///
typedef struct _SERIALIZER_LIX_KERNEL_MODULE
{
    struct
    {
        QWORD       Base;                   ///< The base guest virtual address of the section.
        DWORD       Size;                   ///< The total size of the section.
        DWORD       TextSize;               ///< The size of the .text (code usually).
        DWORD       RoSize;                 ///< The size of the .rodata (read-only).
    } InitLayout;

    struct
    {
        QWORD       Base;                   ///< The base guest virtual address of the section.
        DWORD       Size;                   ///< The total size of the section.
        DWORD       TextSize;               ///< The size of the .text (code usually).
        DWORD       RoSize;                 ///< The size of the .rodata (read-only).
    } CoreLayout;
} SERIALIZER_LIX_KERNEL_MODULE, *PSERIALIZER_LIX_KERNEL_MODULE;


///
/// @brief Describes a serialized intObjKernelDrvObject object.
///
typedef struct _SERIALIZER_KERNEL_DRV_OBJECT
{
    /// @brief  The guest virtual address of the guest _DRIVER_OBJECT represented by this structure.
    QWORD Gva;
    /// @brief  The guest physical address of the guest _DRIVER_OBJECT represented by this structure.
    QWORD Gpa;
    // /@brief  The guest virtual address of the _FAST_IO_DISPATCH structure used by this driver object.
    QWORD FastIOTableAddress;
} SERIALIZER_KERNEL_DRV_OBJECT, *PSERIALIZER_KERNEL_DRV_OBJECT;


///
/// @brief Describes a serialized intObjWinModule object.
///
typedef struct _SERIALIZER_WIN_MODULE
{
    QWORD VirtualBase;                      ///< Guest virtual address of the loaded module.
    DWORD Size;                             ///< Virtual size of the module.
} SERIALIZER_WIN_MODULE, *PSERIALIZER_WIN_MODULE;


///
/// @brief Describes a serialized intObjInstrux object.
///
typedef struct _SERIALIZER_INSTRUX
{
    QWORD   Rip;                            ///< The guest virtual address of the instruction.
    BYTE    Bytes[16];                      ///< The instruction bytes.
} SERIALIZER_INSTRUX, *PSERIALIZER_INSTRUX;


///
/// @brief Describes a serialized intObjArchRegs object.
///
typedef struct _SERIALIZER_ARCH_REGS
{
    QWORD Rax;
    QWORD Rcx;
    QWORD Rdx;
    QWORD Rbx;
    QWORD Rsp;
    QWORD Rbp;
    QWORD Rsi;
    QWORD Rdi;
    QWORD R8;
    QWORD R9;
    QWORD R10;
    QWORD R11;
    QWORD R12;
    QWORD R13;
    QWORD R14;
    QWORD R15;
    QWORD Cr2;
    QWORD Flags;
    QWORD Dr7;
    QWORD Rip;
    QWORD Cr0;
    QWORD Cr4;
    QWORD Cr3;
    QWORD Cr8;
    QWORD IdtBase;
    QWORD IdtLimit;
    QWORD GdtBase;
    QWORD GdtLimit;
} SERIALIZER_ARCH_REGS, *PSERIALIZER_ARCH_REGS;


///
/// @brief Describes a serialized intObjWriteInfo object.
///
typedef struct _SERIALIZER_WRITE_INFO
{
    DWORD AccessSize;                       ///< The original value. Only the first Size bytes are valid.
    QWORD OldValue[8];                      ///< The written value. Only the first Size bytes are valid.
    QWORD NewValue[8];                      ///< The size of the access.
} SERIALIZER_WRITE_INFO, *PSERIALIZER_WRITE_INFO;


///
/// @brief Describes a serialized intObjExecInfo object.
///
typedef struct _SERIALIZER_READ_INFO
{
    DWORD AccessSize;                       ///< The original value. Only the first Size bytes are valid.
    QWORD Value[8];                         ///< The read value. Only the first Size bytes are valid.
} SERIALIZER_READ_INFO, *PSERIALIZER_READ_INFO;


///
/// @brief Describes a serialized intObjExecInfo object.
///
typedef struct _SERIALIZER_EXEC_INFO
{
    QWORD       Rsp;        ///< The value of the guest RSP register at the moment of execution.
    QWORD       StackBase;  ///< The stack base for the thread that attempted the execution.
    QWORD       StackLimit; ///< The stack limit for the thread that attempted the execution.
    DWORD       Length;     ///< The length of the instruction.
} SERIALIZER_EXEC_INFO, *PSERIALIZER_EXEC_INFO;


///
/// @brief Describes a serialized intObjCodeBlocks object.
///
typedef struct _SERIALIZER_CODE_BLOCKS
{
    QWORD   StartAddress;                   ///< The guest linear address from which the code blocks were extracted.
    QWORD   Rip;                            ///< The value of the guest RIP at the moment of the alert.
    /// @brief  Index in the CodeBlocks array for the pattern extracted for the instruction at Rip.
    DWORD   RipCbIndex;
    DWORD   Count;                          ///< The number of available entries in the CodeBlocks array.
    DWORD   Content[0];                     ///< Array of actual code block items.
} SERIALIZER_CODE_BLOCKS, *PSERIALIZER_CODE_BLOCKS;


///
/// @brief Describes a serialized intObjRipCode object.
///
typedef struct _SERIALIZER_RIP_CODE
{
    DWORD   CsType;                         ///< The type of the code segment. Can be one of the IG_CS_TYPE values.
    DWORD   Length;                         ///< The length of the code array.
    BYTE    Code[0];                        ///< The contents of the guest memory page that contains the RIP.
} SERIALIZER_RIP_CODE, *PSERIALIZER_RIP_CODE;


///
/// @brief Describes a serialized intObjRawDump object.
///
typedef struct _SERIALIZER_RAW_DUMP
{
    DWORD   Length;                         ///< The length of the Raw field.
    BYTE    Raw[0];                         ///< The raw dump of the injection.
} SERIALIZER_RAW_DUMP, *PSERIALIZER_RAW_DUMP;


///
/// @brief Describes a serialized intObjExport object.
///
typedef struct _SERIALIZER_EXPORT
{
    DWORD   Count;                          ///< The number of the exports.
    DWORD   Delta;                          ///< The offset inside the affected function at which the access was made.
    BYTE    Exports[0];                     ///< The name of the accessed function, if any.
} SERIALIZER_EXPORT, *PSERIALIZER_EXPORT;


///
/// @brief Describes a serialized intObjDpiWinDebug
///
typedef struct _SERIALIZER_DPI_WIN_DEBUG
{
    QWORD  Debugger;                        ///< The debugger of the current process. May or may not be the parent.
} SERIALIZER_DPI_WIN_DEBUG, *PSERIALIZER_DPI_WIN_DEBUG;


///
/// @brief Describes a serialized intObjDpiWinStolenToken
///
typedef struct _SERIALIZER_DPI_WIN_STOLEN_TOKEN
{
    QWORD StolenFrom;                       ///< The process from which the token was stolen.
} SERIALIZER_DPI_WIN_STOLEN_TOKEN, *PSERIALIZER_DPI_WIN_STOLEN_TOKEN;


///
/// @brief Describes a serialized intObjDpiWinHeapSpray
///
typedef struct _SERIALIZER_DPI_WIN_HEAP_SPRAY
{
    struct
    {
        DWORD Mapped : 1;               ///< The bit is set if the i-th page could be mapped.
        /// @brief The bit is set if the i-th page was detected as malicious by shemu.
        DWORD Detected : 1;
        /// @brief  The number of heap values in the page. Since the max value can be 1024, 11 bits are needed.
        DWORD HeapValCount : 11;
        /// @brief  The offset where the detection on the given page was given, if Detection is equal to 1.
        DWORD Offset : 12;
        DWORD Executable : 1;           ///< True if the page is executable in the translation.
        DWORD Reserved : 7;             ///< Reserved for further use.
    } HeapPages[0xF];

    QWORD ShellcodeFlags;               ///< The shellcode flags given by shemu on the detected page.

    BYTE DetectedPage[0x1000];          ///< The page which was detected through shemu as malicious.
    BYTE MaxHeapValPageContent[0x1000]; ///< The copied page which has the most heap values in it.
} SERIALIZER_DPI_WIN_HEAP_SPRAY, *PSERIALIZER_DPI_WIN_HEAP_SPRAY;


///
/// @brief Describes a serialized intObjDpiWinThreadStart
///
typedef struct _SERIALIZER_DPI_WIN_THREAD_START
{
    QWORD   ShellcodeFlags;         ///< The shellcode flags given by shemu on the detected page.
    QWORD   StartAddress;           ///< The address where the thread started executing.
    BYTE    StartPage[0x1000];      ///< The copied page from where the thread started executing.
} SERIALIZER_DPI_WIN_THREAD_START, *PSERIALIZER_DPI_WIN_THREAD_START;


///
/// @brief Describes a serialized intObjDpiWinTokenPrivs
///
typedef struct _SERIALIZER_DPI_WIN_TOKEN_PRIVS
{
    QWORD OldEnabled;                   ///< The old Privileges.Enabled value in the parent's token.
    /// @brief  The new Privileges.Enabled value in the parent's token, which was deemed malicious.
    QWORD NewEnabled;
    QWORD OldPresent;                   ///< The old Privileges.Present value in the parent's token.
    /// @brief The new Privileges.Present value in the parent's token, which was deemed malicious.
    QWORD NewPresent;
} SERIALIZER_DPI_WIN_TOKEN_PRIVS, *PSERIALIZER_DPI_WIN_TOKEN_PRIVS;


///
/// @brief Describes a serialized intObjDpiPivotedStack
///
typedef struct _SERIALIZER_DPI_PIVOTED_STACK
{
    QWORD   CurrentStack;               ///< The current stack of the parent process.
    QWORD   StackBase;                  ///< The known stack base of the parent process.
    QWORD   StackLimit;                 ///< The known stack limit of the parent process.
    QWORD   Wow64CurrentStack;          ///< The current stack of the parent process in WoW64 mode.
    QWORD   Wow64StackBase;             ///< The known stack base of the parent process in WoW64 mode.
    QWORD   Wow64StackLimit;            ///< The known stack limit of the parent process in WoW64 mode.
    BYTE    TrapFrameContent[512];      ///< The content of the trap frame where the current stack has been found.
} SERIALIZER_DPI_PIVOTED_STACK, *PSERIALIZER_DPI_PIVOTED_STACK;


///
/// @brief Describes a serialized intObjDpiWinSecDesc
///
typedef struct _SERIALIZER_DPI_WIN_SEC_DESC
{
    /// @brief If the parent security descriptor has been stolen, this variable may indicate (in case we find it)
    /// the victim process (where security descriptor has been stolen from) - it can be NULL.
    QWORD SecDescStolenFromEproc;
                                 
    QWORD OldPtrValue;              ///< Old value.
    QWORD NewPtrValue;              ///< New value.

    ACL OldSacl;                    ///< The old SACL header.
    ACL OldDacl;                    ///< The old DACL header.

    ACL NewSacl;                    ///< The new SACL header.
    ACL NewDacl;                    ///< The new DACL header.
} SERIALIZER_DPI_WIN_SEC_DESC, *PSERIALIZER_DPI_WIN_SEC_DESC;


///
/// @brief Describes a serialized intObjDpiWinAclEdit
///
typedef struct _SERIALIZER_DPI_WIN_ACL_EDIT
{
    ACL OldSacl;                    ///< The old SACL header.
    ACL OldDacl;                    ///< The old DACL header.

    ACL NewSacl;                    ///< The new SACL header.
    ACL NewDacl;                    ///< The new DACL header.
} SERIALIZER_DPI_WIN_ACL_EDIT, *PSERIALIZER_DPI_WIN_ACL_EDIT;


///
/// @brief Describes a serialized intObjDpi object.
///
typedef struct _SERIALIZER_DPI
{
    DWORD       Flags;                      ///< The DPI flags.
} SERIALIZER_DPI, *PSERIALIZER_DPI;

#pragma pack(pop)


///
/// @brief Describes the type of a serialize object.
///
enum
{
    intObjNone = 0,

    /// @brief  Used to notify the deserializer that the next objects contains the originator.
    intObjStartOriginator,
    /// @brief  Used to notify the deserializer that the all the originator's objects has been parsed.
    intObjEndOriginator,
    /// @brief  Used to notify the deserializer that the next objects contains the victim.
    intObjStartVictim,
    /// @brief  Used to notify the deserializer that the all the victim's objects has been parsed.
    intObjEndVictim,
    /// @brief  Used to notify the deserializer that the next objects contains the misc.
    intObjStartMisc,
    /// @brief  Used to notify the deserializer that the all the misc objects has been parsed.
    intObjEndMisc,

    intObjVictim,                           ///< Used for the victim object.

    intObjEpt,                              ///< Used for the EPT object.
    intObjMsr,                              ///< Used for the MSR object.
    intObjCr,                               ///< Used for the CR object.
    intObjDtr,                              ///< Used for the DTR object.
    intObjIdt,                              ///< Used for the IDT object.
    intObjIntegrity,                        ///< Used for the Integrity object.
    intObjInjection,                        ///< Used for the Injection object.

    intObjWinProcess,                       ///< Used for the windows process object.
    intObjWinProcessParent,                 ///< Used for the windows parent process object.
    intObjLixProcess,                       ///< Used for the Linux task object.
    intObjLixProcessParent,                 ///< Used for the Linux parent task object.

    intObjKernelDriver,                     ///< Used for the kernel driver object.
    intObjKernelDriverReturn,               ///< Used for the return kernel driver object.
    intObjWinKernelDriver,                  ///< Used for the windows kernel driver object.
    intObjWinKernelDriverReturn,            ///< Used for the windows kernel driver object.
    intObjLixKernelModule,                  ///< Used for the Linux kernel module object.
    intObjLixKernelModuleReturn,            ///< Used for the Linux kernel module object.
    intObjKernelDrvObject,                  ///< Used for the windows driver obj object.

    intObjWinVad,                           ///< Used for the windows VAD object.
    intObjLixVma,                           ///< Used for the Linux VMA object.

    intObjWinModule,                        ///< Used for the windows module object.
    intObjWinModuleReturn,                  ///< Used for the windows return module object.

    intObjInstrux,                          ///< Used for the instruction object.
    intObjWriteInfo,                        ///< Used for the write info object.
    intObjReadInfo,                         ///< Used for the read info object.
    intObjExecInfo,                         ///< Used for the execution info object.
    intObjArchRegs,                         ///< Used for the registers object.
    intObjCodeBlocks,                       ///< Used for the code-blocks object.
    intObjRipCode,                          ///< Used for the code object.
    intObjRawDump,                          ///< Used for the injection raw dump object.
    intObjExport,                           ///< Used for the export object.
    intObjDpi,                              ///< Used for the DPI object.
    intObjDpiWinDebug,                      ///< Used for the DPI debug object.
    intObjDpiWinPivotedStack,               ///< Used for the DPI pivoted stack object.
    intObjDpiWinStolenToken,                ///< Used for the DPI stolen token object.
    intObjDpiWinTokenPrivs,                 ///< Used for the DPI token privs object.
    intObjDpiWinThreadStart,                ///< Used for the DPI thread start object.
    intObjDpiWinHeapSpray,                  ///< Used for the DPI heap spray object.
    intObjDpiWinSecDesc,                    ///< Used for the DPI security descriptor objects.
    intObjDpiWinAclEdit,                    ///< Used for the DPI ACL objects.
};


///
/// @brief Describes the encoding type of a string.
///
enum
{
    stringEncodeUtf8 = 0,                   ///< The string encoding type 'utf-8'.
    stringEncodeUtf16                       ///< The string encoding type 'utf-16'.
};

#define MAX_SERIALIZER_LENGTH   (16 * ONE_KILOBYTE)

static BYTE gSerializerBuffer[MAX_SERIALIZER_LENGTH] = { 0 };
static BYTE *gCurrentPtr = NULL;
static QWORD gSerializerCurrentId = 0;

static CODE_BLOCK_PATTERN gCodeBlocksPattern[PAGE_SIZE / sizeof(CODE_BLOCK_PATTERN)];
static DWORD gCodeBlocksPatternLength = 0;
static CODE_BLOCK gCodeBlocks[PAGE_SIZE / sizeof(CODE_BLOCK)];

const char gBase64Chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

#define Base64EncSize(Length)   (((((Length) + 2) / 3) * 4) + 1)

static char gBase64Buffer[Base64EncSize(sizeof(gSerializerBuffer))] = {0};



static void
IntSerializeBlockToBase64(
    _In_ const BYTE *In,
    _Out_writes_(4) BYTE *Out,
    _In_ size_t Length
    )
///
/// @brief  Converts the provided binary buffer to base64.
///
/// @param[in]  In      The input buffer.
/// @param[out] Out     The output buffer.
/// @param[in]  Length  The length of the input buffer.
///
{
    Out[0] = gBase64Chars[In[0] >> 2];
    Out[1] = gBase64Chars[((In[0] & 0x03) << 4) | ((In[1] & 0xf0) >> 4)];
    Out[2] = (BYTE) (Length > 1 ? gBase64Chars[((In[1] & 0x0f) << 2) | ((In[2] & 0xc0) >> 6)] : '=');
    Out[3] = (BYTE) (Length > 2 ? gBase64Chars[In[2] & 0x3f] : '=');
}


static char *
IntSerializerBase64Get(
    _Out_ DWORD *Length
    )
///
/// @brief  Converts the serialized buffer to base64.
///
/// @param[out] Length  The length of the base64 buffer.
///
/// @retval     A pointer to the beginning of the base64 buffer.
///
{
    size_t len = gCurrentPtr - gSerializerBuffer;

    *Length = (DWORD)Base64EncSize(len);

    BYTE *out = (BYTE *)gBase64Buffer;
    const BYTE *in = gSerializerBuffer;

    for (size_t i = 0; i < len; i += 3)
    {
        size_t size = ((len - i) < 4) ? (len - i) : 4;

        IntSerializeBlockToBase64(in, out, size);

        out += 4;
        in += 3;
    }

    *out = 0;

    return gBase64Buffer;
}


static DWORD
IntSerializeCurrentOffset(
    void
    )
///
/// @brief  Get the current offset (length) of the serialized buffer.
///
/// @retval     The current offset (length) of the serialized buffer.
///
{
    return (DWORD)(gCurrentPtr - gSerializerBuffer);
}


static void
IntSerializeIncrementCurrentPtr(
    _In_ const DWORD Size
    )
///
/// @brief  Increment the current pointer to the serializer buffer with the provided size.
///
/// @param[in]  Size    The size to increment with.
///
{
    gCurrentPtr += Size;
}


static QWORD
IntSerializeCurrentId(
    void
    )
///
/// @brief  Increment the current serializer alert ID and returns it.
///
/// @retval     The current serializer alert ID.
///
{
    return gSerializerCurrentId;
}


static void
IntSerializeIncrementCurrentId(
    void
    )
///
/// @brief  Increment the current serializer alert ID.
///
{
    gSerializerCurrentId++;
}


static void
IntSerializeDump(
    void
    )
///
/// @brief  Dumps the serialized buffer (base64 format).
///
{
    DWORD length = 0;
    CHAR *pBase64 = IntSerializerBase64Get(&length);

    UNREFERENCED_LOCAL_VARIABLE(pBase64);

    // NOTE: for now we'll only execute the algorithm etc, but don't log anything since
    // the logs get pretty easily to even 300 GB in size...

    TRACE("[SERIALIZER] Start Serializer ID -> 0x%llx\n", IntSerializeCurrentId());
    for (DWORD index = 0; index < length; index += 1000)
    {
        TRACE("[SERIALIZER] %.1000s", pBase64 + index);
    }
    TRACE("[SERIALIZER] End Serializer ID -> 0x%llx\n", IntSerializeCurrentId());
}


static BOOLEAN
IntSerializeValidObjectSize(
    _In_ DWORD Size
    )
///
/// @brief Checks if the serializer buffer overflows.
///
/// @param[in]  Size    The size of the object.
///
/// @retval     True if the buffer doesn't overflows, otherwise false.
///
{
    QWORD crt = (QWORD)(gCurrentPtr - gSerializerBuffer) + (QWORD)Size;

    if (crt > sizeof(gSerializerBuffer))
    {
        ERROR("[ERROR] Serilizer buffer overflows! Current offset = 0x%llx, Buffer Size = 0x%0llx, "
              "Required size = 0x%x\n",
              (QWORD)(gCurrentPtr - gSerializerBuffer), (QWORD)sizeof(gSerializerBuffer), Size);

        return FALSE;
    }

    return TRUE;
}


static void *
IntSerializeCurrentPtr(
    _In_ DWORD Size
    )
///
/// @brief  Returns the current pointer to serializer buffer and checks for overflows.
///
/// @param[in]  Size    The size of the object.
///
/// @retval     A pointer inside the #gSerializerBuffer, otherwise, if the buffer overflows, a null pointer.
///
{
    if (!IntSerializeValidObjectSize(Size))
    {
        return NULL;
    }

    return gCurrentPtr;
}


static SERIALIZER_OBJECT_HEADER *
IntSerializeObjectHeader(
    _In_ const DWORD Version,
    _In_ const DWORD Type
    )
///
/// @brief  Creates a #SERIALIZER_OBJECT_HEADER object and fill the fields with the provided parameters.
///
/// @param[in]  Version     The version of the header object.
/// @param[in]  Type        The type of the header object.
///
/// @retval     A pointer to the newly created object.
/// @retval     NULL if the gSerializerBuffer overflows.
///
{
    SERIALIZER_OBJECT_HEADER *pHeader = IntSerializeCurrentPtr(sizeof(*pHeader));

    if (!pHeader)
    {
        return NULL;
    }

    pHeader->Version = Version;
    pHeader->Type = (WORD)Type;
    pHeader->Size = 0;

    IntSerializeIncrementCurrentPtr(sizeof(*pHeader));

    return pHeader;
}


static BOOLEAN
IntSerializeStringIsWcharAscii(
    _In_ const void *String,
    _In_ DWORD Size
    )
///
/// @brief Checks if the provided string contains WCHARS.
///
/// @param[in]  String      A string.
/// @param[in]  Size        The size of the string.
///
/// @retval     True if the provided string contains WCHARs, otherwise false.
///
{
    const BYTE *pStr = String;

    for (DWORD index = 0; index < Size; index++)
    {
        if (pStr[index] > 0x7f)
        {
            return FALSE;
        }
    }

    return TRUE;
}


static void
IntSerializeString(
    const void *String,
    _In_ DWORD Size,
    _In_ DWORD Encode,
    _Inout_ SERIALIZER_OBJECT_HEADER *Header
    )
///
/// @brief  Serialize the provided string.
///
/// @param[in]  String      A string.
/// @param[in]  Size        The size of the string.
/// @param[in]  Encode      The encode type of string.
/// @param[out] Header      The header of the serialized object.
///
{
    SERIALIZER_STRING *pObject = NULL;
    DWORD size = 0;

    if (String != NULL && Size != 0)
    {
        switch (Encode)
        {
        case stringEncodeUtf8 :
            pObject = IntSerializeCurrentPtr(sizeof(*pObject) + Size);
            if (!pObject)
            {
                return;
            }

            pObject->Length = Size;
            pObject->Encode = (BYTE)Encode;

            memcpy(pObject->String, String, pObject->Length);

            Header->Size += (WORD)(sizeof(*pObject) + pObject->Length);
            size = pObject->Length;

            break;

        case stringEncodeUtf16 :
            if (IntSerializeStringIsWcharAscii(String, Size))
            {
                pObject = IntSerializeCurrentPtr(sizeof(*pObject) + Size);
                if (!pObject)
                {
                    return;
                }

                pObject->Encode = stringEncodeUtf8;
                pObject->Length = Size / 2;

                utf16toutf8(pObject->String, String, pObject->Length);

                Header->Size += (WORD)(sizeof(*pObject) + pObject->Length);
                size = pObject->Length;
            }
            else
            {
                pObject = IntSerializeCurrentPtr(sizeof(*pObject) + Size);
                if (!pObject)
                {
                    return;
                }

                pObject->Encode = (BYTE)Encode;
                pObject->Length = Size;

                memcpy(pObject->String, String, pObject->Length * sizeof(WCHAR));

                Header->Size += (WORD)(sizeof(*pObject) + pObject->Length * sizeof(WCHAR));
                size = (WORD)(pObject->Length * sizeof(WCHAR));
            }
            break;

        default:
            LOG("[ERROR] Should not reach here. Encode %d \n", Encode);
        }
    }
    else
    {
        pObject = IntSerializeCurrentPtr(sizeof(*pObject));
        if (!pObject)
        {
            return;
        }

        pObject->Length = 0;
        pObject->Encode = (BYTE)Encode;

        Header->Size += sizeof(*pObject);
    }

    IntSerializeIncrementCurrentPtr(sizeof(*pObject) + size);
}


static void
IntSerializeEpt(
    _In_ const EXCEPTION_VICTIM_EPT *Ept,
    _In_ const EXCEPTION_VICTIM_ZONE *Victim
    )
///
/// @brief  Serialize the provided EPT object.
///
/// @param[in]  Ept     The EPT violation.
/// @param[in]  Victim  The victim object.
///
{
#define VICTIM_SERIALIZER_EPT_VERSION 1

    SERIALIZER_OBJECT_HEADER *pHeader = IntSerializeObjectHeader(VICTIM_SERIALIZER_EPT_VERSION, intObjEpt);
    if (!pHeader)
    {
        return;
    }

    SERIALIZER_EPT *pObject = IntSerializeCurrentPtr(sizeof(*pObject));
    if (!pObject)
    {
        return;
    }

    pObject->Gva = Ept->Gva;
    pObject->Gpa = Ept->Gpa;
    pObject->Type = IG_EPT_HOOK_NONE;

    if (Victim->ZoneFlags & ZONE_WRITE)
    {
        pObject->Type = IG_EPT_HOOK_WRITE;
    }
    else if (Victim->ZoneFlags & ZONE_READ)
    {
        pObject->Type = IG_EPT_HOOK_READ;
    }
    else if (Victim->ZoneFlags & ZONE_EXECUTE)
    {
        pObject->Type = IG_EPT_HOOK_EXECUTE;
    }

    pHeader->Size = sizeof(*pObject);

    IntSerializeIncrementCurrentPtr(sizeof(*pObject));
}


static void
IntSerializeCr(
    _In_ const EXCEPTION_VICTIM_CR *Cr
    )
///
/// @brief  Serialize the provided CR object.
///
/// @param[in]  Cr      The CR violation.
///
{
#define VICTIM_SERIALIZER_CR_VERSION 1

    SERIALIZER_OBJECT_HEADER *pHeader = IntSerializeObjectHeader(VICTIM_SERIALIZER_CR_VERSION, intObjCr);
    if (!pHeader)
    {
        return;
    }

    SERIALIZER_CR *pObject = IntSerializeCurrentPtr(sizeof(*pObject));
    if (!pObject)
    {
        return;
    }

    pObject->Cr = Cr->Cr;

    pHeader->Size = sizeof(*pObject);

    IntSerializeIncrementCurrentPtr(sizeof(*pObject));
}


static void
IntSerializeIdt(
    _In_ const EXCEPTION_VICTIM_ZONE *Victim
    )
///
/// @brief  Serialize the provided IDT object.
///
/// @param[in]  Victim      The victim object.
///
{
#define VICTIM_SERIALIZER_IDT_VERSION 1

    SERIALIZER_OBJECT_HEADER *pHeader = IntSerializeObjectHeader(VICTIM_SERIALIZER_IDT_VERSION, intObjIdt);
    if (!pHeader)
    {
        return;
    }

    SERIALIZER_IDT *pObject = IntSerializeCurrentPtr(sizeof(*pObject));
    if (!pObject)
    {
        return;
    }

    pObject->Entry = (DWORD)((Victim->Ept.Gva - Victim->Object.BaseAddress) /
                             (gGuest.Guest64 ? DESCRIPTOR_SIZE_64 : DESCRIPTOR_SIZE_32));

    pHeader->Size = sizeof(*pObject);

    IntSerializeIncrementCurrentPtr(sizeof(*pObject));
}


static void
IntSerializeMsr(
    _In_ const EXCEPTION_VICTIM_MSR *Msr
    )
///
/// @brief  Serialize the provided MSR object.
///
/// @param[in]  Msr      The MSR violation.
///
{
#define VICTIM_SERIALIZER_MSR_VERSION 1

    SERIALIZER_OBJECT_HEADER *pHeader = IntSerializeObjectHeader(VICTIM_SERIALIZER_MSR_VERSION, intObjMsr);
    if (!pHeader)
    {
        return;
    }

    SERIALIZER_MSR *pObject = IntSerializeCurrentPtr(sizeof(*pObject));
    if (!pObject)
    {
        return;
    }

    pObject->Msr = Msr->Msr;

    pHeader->Size = sizeof(*pObject);

    IntSerializeIncrementCurrentPtr(sizeof(*pObject));
}


static void
IntSerializeDtr(
    _In_ const EXCEPTION_VICTIM_DTR *Dtr
    )
///
/// @brief  Serialize the provided DTR object.
///
/// @param[in]  Dtr      The DTR violation.
///
{
#define VICTIM_SERIALIZER_DTR_VERSION 1

    SERIALIZER_OBJECT_HEADER *pHeader = IntSerializeObjectHeader(VICTIM_SERIALIZER_DTR_VERSION, intObjDtr);
    if (!pHeader)
    {
        return;
    }

    SERIALIZER_DTR *pObject = IntSerializeCurrentPtr(sizeof(*pObject));
    if (!pObject)
    {
        return;
    }

    pObject->Type = Dtr->Type;

    pHeader->Size = sizeof(*pObject);

    IntSerializeIncrementCurrentPtr(sizeof(*pObject));
}


static void
IntSerializeInjection(
    _In_ const EXCEPTION_VICTIM_INJECTION *Injection,
    _In_ const EXCEPTION_VICTIM_ZONE *Victim
    )
///
/// @brief  Serialize the provided Injection object.
///
/// @param[in]  Injection   The injection violation.
/// @param[in]  Victim      The victim object.
///
{
#define VICTIM_SERIALIZER_INJECTION_VERSION         1

    SERIALIZER_OBJECT_HEADER *pHeader = IntSerializeObjectHeader(VICTIM_SERIALIZER_INJECTION_VERSION, intObjInjection);
    if (!pHeader)
    {
        return;
    }

    SERIALIZER_INJECTION *pObject = IntSerializeCurrentPtr(sizeof(*pObject));
    if (!pObject)
    {
        return;
    }

    pObject->Gva = Injection->Gva;
    pObject->Length = Injection->Length;
    pObject->Type = 0;

    if (Victim->ZoneFlags & ZONE_WRITE)
    {
        if (Victim->ZoneFlags & ZONE_PROC_THREAD_CTX)
        {
            pObject->Type = memCopyViolationSetContextThread;
        }
        else if (Victim->ZoneFlags & ZONE_PROC_THREAD_APC)
        {
            pObject->Type = memCopyViolationQueueApcThread;
        }
        else if (Victim->ZoneFlags & ZONE_PROC_INSTRUMENT)
        {
            pObject->Type = memCopyViolationInstrument;
        }
        else
        {
            pObject->Type = memCopyViolationWrite;
        }
    }

    if (Victim->ZoneFlags & ZONE_READ)
    {
        pObject->Type = memCopyViolationRead;
    }

    pHeader->Size = sizeof(*pObject);

    IntSerializeIncrementCurrentPtr(sizeof(*pObject));
}


static void
IntSerializeWinProcess(
    _In_ const WIN_PROCESS_OBJECT *Process,
    _In_ const DWORD ObjectType
    )
///
/// @brief  Serialize the provided #WIN_PROCESS_OBJECT object.
///
/// @param[in]  Process     The process object.
/// @param[in]  ObjectType  The type of the provided process (#intObjWinProcess, #intObjWinProcessParent).
///
{
    if (Process == NULL)
    {
        return;
    }

#define WIN_PROCESS_SERIALIZER_VERSION 1

    SERIALIZER_OBJECT_HEADER *pHeader = IntSerializeObjectHeader(WIN_PROCESS_SERIALIZER_VERSION, ObjectType);
    if (!pHeader)
    {
        return;
    }

    SERIALIZER_WIN_PROCESS *pObject = IntSerializeCurrentPtr(sizeof(*pObject));
    if (!pObject)
    {
        return;
    }

    pObject->EprocessAddress = Process->EprocessAddress;
    pObject->ParentEprocess = Process->ParentEprocess;
    pObject->RealParentEprocess = Process->RealParentEprocess;
    pObject->Cr3 = Process->Cr3;
    pObject->UserCr3 = Process->UserCr3;
    pObject->Pid = Process->Pid;
    pObject->Peb64Address = Process->Peb64Address;
    pObject->Peb32Address = Process->Peb32Address;
    pObject->MainModuleAddress = Process->MainModuleAddress;
    pObject->Flags = Process->Flags;

    pHeader->Size = sizeof(*pObject);
    IntSerializeIncrementCurrentPtr(sizeof(*pObject));

    IntSerializeString(Process->Name, sizeof(Process->Name), stringEncodeUtf8, pHeader);
    IntSerializeString(Process->Path != NULL ? Process->Path->Path : NULL,
                       Process->Path != NULL ? Process->Path->PathSize : 0,
                       stringEncodeUtf16,
                       pHeader);
    IntSerializeString(Process->CommandLine, Process->CommandLineSize, stringEncodeUtf8, pHeader);
}


static void
IntSerializeLixProcess(
    _In_ const LIX_TASK_OBJECT *Process,
    _In_ const DWORD ObjectType
    )
///
/// @brief  Serialize the provided #LIX_TASK_OBJECT object.
///
/// @param[in]  Process     The process object.
/// @param[in]  ObjectType  The type of the provided process (intObjLixProcess, intObjLixProcessParent).
///
{
    if (Process == NULL)
    {
        return;
    }

#define LIX_PROCESS_SERIALIZER_VERSION 1

    SERIALIZER_OBJECT_HEADER *pHeader = IntSerializeObjectHeader(LIX_PROCESS_SERIALIZER_VERSION, ObjectType);
    if (!pHeader)
    {
        return;
    }

    SERIALIZER_LIX_PROCESS *pObject = IntSerializeCurrentPtr(sizeof(*pObject));
    if (!pObject)
    {
        return;
    }

    pObject->Gva = Process->Gva;
    pObject->RealParent = Process->RealParent;
    pObject->Parent = Process->Parent;
    pObject->ActualParent = Process->ActualParent;
    pObject->MmGva = Process->MmGva;
    pObject->Cr3 = Process->Cr3;
    pObject->Pid = Process->Pid;
    pObject->Tgid = Process->Tgid;

    pHeader->Size = sizeof(*pObject);
    IntSerializeIncrementCurrentPtr(sizeof(*pObject));

    IntSerializeString(Process->Path != NULL ? Process->Path->Name : NULL,
                       Process->Path != NULL ? (DWORD)Process->Path->NameLength : 0,
                       stringEncodeUtf8,
                       pHeader);
    IntSerializeString(Process->Path != NULL ? Process->Path->Path : NULL,
                       Process->Path != NULL ? (DWORD)Process->Path->PathLength : 0,
                       stringEncodeUtf8,
                       pHeader);
    IntSerializeString(Process->CmdLine, Process->CmdLineLength + 1, stringEncodeUtf8, pHeader);
}


static void
IntSerializeProcess(
    _In_ void *Process,
    _In_ const DWORD ObjectType
    )
///
/// @brief  Serialize the provided process object.
///
/// @param[in]  Process     The process object.
/// @param[in]  ObjectType  The type of the provided process.
///
{
    if (gGuest.OSType == introGuestLinux)
    {
        IntSerializeLixProcess(Process, ObjectType);
    }
    else if (gGuest.OSType == introGuestWindows)
    {
        IntSerializeWinProcess(Process, ObjectType);
    }
}


void
IntSerializeWinVad(
    _In_ const VAD *Vad
    )
///
/// @brief  Serialize the provided #VAD object.
///
/// @param[in]  Vad     The windows VAD object.
///
{
    if (Vad == NULL)
    {
        return;
    }

#define WIN_VAD_SERIALIZER_VERSION 1

    SERIALIZER_OBJECT_HEADER *pHeader = IntSerializeObjectHeader(WIN_VAD_SERIALIZER_VERSION, intObjWinVad);
    if (!pHeader)
    {
        return;
    }

    SERIALIZER_WIN_VAD *pObject = IntSerializeCurrentPtr(sizeof(*pObject));
    if (!pObject)
    {
        return;
    }

    pObject->StartPage = Vad->StartPage;
    pObject->EndPage = Vad->EndPage;
    pObject->VadGva = Vad->VadGva;
    pObject->VadProtection = Vad->VadProtection;
    pObject->VadType = Vad->VadType;
    pObject->Protection = Vad->Protection;
    pObject->ExecCount = Vad->ExecCount;
    pObject->Flags = Vad->StaticScan | Vad->IsStack | Vad->HugeVad | Vad->IsIgnored | Vad->NoChange |
                     Vad->PrivateFixup | Vad->DeleteInProgress;

    pHeader->Size = sizeof(*pObject);
    IntSerializeIncrementCurrentPtr(sizeof(*pObject));

    IntSerializeString(Vad->Path != NULL ? Vad->Path->Path : NULL,
                       Vad->Path != NULL ? Vad->Path->PathSize : 0,
                       stringEncodeUtf16,
                       pHeader);
}


static void
IntSerializeLixVma(
    _In_ const LIX_VMA *Vma
    )
///
/// @brief  Serialize the provided #LIX_VMA object.
///
/// @param[in]  Vma     The Linux VMA object.
///
{
    if (NULL == Vma)
    {
        return;
    }

#define LIX_VMA_SERIALIZER_VERSION 1

    INTSTATUS status = INT_STATUS_SUCCESS;
    char *pFilePath = NULL;
    DWORD filePathLength = 0;

    SERIALIZER_OBJECT_HEADER *pHeader = IntSerializeObjectHeader(LIX_VMA_SERIALIZER_VERSION, intObjLixVma);
    if (!pHeader)
    {
        return;
    }

    SERIALIZER_LIX_VMA *pObject = IntSerializeCurrentPtr(sizeof(*pObject));
    if (!pObject)
    {
        return;
    }

    pObject->Start = Vma->Start;
    pObject->End = Vma->End;
    pObject->Gva = Vma->Gva;
    pObject->Flags = Vma->Flags;
    pObject->File = Vma->File;

    pHeader->Size = sizeof(*pObject);
    IntSerializeIncrementCurrentPtr(sizeof(*pObject));

    status = IntLixFileGetPath(Vma->File, &pFilePath, &filePathLength);
    if (INT_SUCCESS(status))
    {
        IntSerializeString(pFilePath, filePathLength, stringEncodeUtf8, pHeader);
    }
    else
    {
        IntSerializeString(NULL, 0, stringEncodeUtf8, pHeader);
    }
}


static void
IntSerializeVad(
    _In_ const void *Vad
    )
///
/// @brief  Serialize the provided VAD/vma object.
///
/// @param[in]  Vad     The VAD/vma object.
///
{
    if (gGuest.OSType == introGuestLinux)
    {
        IntSerializeLixVma(Vad);
    }
    else if (gGuest.OSType == introGuestWindows)
    {
        IntSerializeWinVad(Vad);
    }
}


static void
IntSerializeWinKernelDriver(
    _In_ const KERNEL_DRIVER *Driver,
    _In_ DWORD ObjectType
    )
///
/// @brief  Serialize the provided #KERNEL_DRIVER object.
///
/// @param[in]  Driver      The windows kernel-driver object.
/// @param[in]  ObjectType  The type of serializer object.
///
{
    if (Driver == NULL)
    {
        return;
    }

#define WIN_KERNEL_DRIVER_SERIALIZER_VERSION 1

    SERIALIZER_OBJECT_HEADER *pHeader = IntSerializeObjectHeader(WIN_KERNEL_DRIVER_SERIALIZER_VERSION, ObjectType);
    if (!pHeader)
    {
        return;
    }

    SERIALIZER_WIN_KERNEL_DRIVER *pObject = IntSerializeCurrentPtr(sizeof(*pObject));
    if (!pObject)
    {
        return;
    }

    pObject->TimeDateStamp = Driver->Win.TimeDateStamp;

    pHeader->Size = sizeof(*pObject);
    IntSerializeIncrementCurrentPtr(sizeof(*pObject));

    IntSerializeString(Driver->Win.Path, Driver->Win.PathLength * 2 + sizeof(WCHAR), stringEncodeUtf16, pHeader);
}


static void
IntSerializeLixKernelModule(
    _In_ const KERNEL_DRIVER *Driver,
    _In_ DWORD ObjecType
    )
///
/// @brief  Serialize the provided #KERNEL_DRIVER object.
///
/// @param[in]  Driver      The Linux kernel-module object.
/// @param[in]  ObjecType   The type of serializer object.
///
{
#define LIX_KERNEL_MODULE_SERIALIZER_VERSION 1

    SERIALIZER_OBJECT_HEADER *pHeader = IntSerializeObjectHeader(LIX_KERNEL_MODULE_SERIALIZER_VERSION, ObjecType);
    if (!pHeader)
    {
        return;
    }

    SERIALIZER_LIX_KERNEL_MODULE *pObject = IntSerializeCurrentPtr(sizeof(*pObject));
    if (!pObject)
    {
        return;
    }

    pObject->InitLayout.Base = Driver->Lix.InitLayout.Base;
    pObject->InitLayout.Size = Driver->Lix.InitLayout.Size;
    pObject->InitLayout.TextSize = Driver->Lix.InitLayout.TextSize;
    pObject->InitLayout.RoSize = Driver->Lix.InitLayout.RoSize;
    pObject->CoreLayout.Base = Driver->Lix.CoreLayout.Base;
    pObject->CoreLayout.Size = Driver->Lix.CoreLayout.Size;
    pObject->CoreLayout.TextSize = Driver->Lix.CoreLayout.TextSize;
    pObject->CoreLayout.RoSize = Driver->Lix.CoreLayout.RoSize;

    pHeader->Size = sizeof(*pObject);
    IntSerializeIncrementCurrentPtr(sizeof(*pObject));

    IntSerializeString(Driver->Name, (DWORD)Driver->NameLength, stringEncodeUtf8, pHeader);
}


static void
IntSerializeKernelDrvObject(
    _In_ const WIN_DRIVER_OBJECT *DrvObject
    )
///
/// @brief  Serialize the provided #WIN_DRIVER_OBJECT object.
///
/// @param[in]  DrvObject     The windows drv-obj object.
///
{
    if (DrvObject == NULL)
    {
        return;
    }
#define KERNEL_DRV_OBJECT_SERIALIZER_VERSION 1

    SERIALIZER_OBJECT_HEADER *pHeader = IntSerializeObjectHeader(KERNEL_DRV_OBJECT_SERIALIZER_VERSION,
                                                                 intObjKernelDrvObject);
    if (!pHeader)
    {
        return;
    }

    SERIALIZER_KERNEL_DRV_OBJECT *pObject = IntSerializeCurrentPtr(sizeof(*pObject));
    if (!pObject)
    {
        return;
    }

    pObject->Gva = DrvObject->DriverObjectGva;
    pObject->Gpa = DrvObject->DriverObjectGpa;
    pObject->FastIOTableAddress = DrvObject->FastIOTableAddress;

    pHeader->Size = sizeof(*pObject);
    IntSerializeIncrementCurrentPtr(sizeof(*pObject));

    IntSerializeString(DrvObject->Name, DrvObject->NameLen, stringEncodeUtf16, pHeader);
}


static void
IntSerializeKernelDriver(
    _In_opt_ const EXCEPTION_KM_ORIGINATOR *Originator,
    _In_opt_ const KERNEL_DRIVER *Driver,
    _In_ const DWORD ObjectType
    )
///
/// @brief  Serialize the provided #KERNEL_DRIVER object.
///
/// @param[in]  Originator  The originator object.
/// @param[in]  Driver      The kernel-driver object.
/// @param[in]  ObjectType  The type of the kernel-driver (intObjKernelDriver, intObjKernelDriverReturn).
///
{
#define KERNEL_DRIVER_SERIALIZER_VERSION 1

    const KERNEL_DRIVER *pDriver = NULL;
    const CHAR *pSection = NULL;

    if (Driver != NULL)
    {
        pDriver = Driver;
    }
    else
    {
        if (Originator == NULL)
        {
            return;
        }

        if (ObjectType == intObjKernelDriver)
        {
            pDriver = Originator->Original.Driver;
            pSection = Originator->Original.Section;
        }
        else if (ObjectType == intObjKernelDriverReturn)
        {
            pDriver = Originator->Return.Driver;
            pSection = Originator->Return.Section;
        }
        else
        {
            return;
        }
    }

    if (pDriver == NULL)
    {
        return;
    }

    SERIALIZER_OBJECT_HEADER *pHeader = IntSerializeObjectHeader(KERNEL_DRIVER_SERIALIZER_VERSION, ObjectType);
    if (!pHeader)
    {
        return;
    }

    SERIALIZER_KERNEL_DRIVER *pObject = IntSerializeCurrentPtr(sizeof(*pObject));
    if (!pObject)
    {
        return;
    }

    pObject->ObjectGva = pDriver->ObjectGva;
    pObject->BaseVa = pDriver->BaseVa;
    pObject->Size = pDriver->Size;
    pObject->EntryPoint = pDriver->EntryPoint;

    pHeader->Size = sizeof(*pObject);
    IntSerializeIncrementCurrentPtr(sizeof(*pObject));

    if (pSection != NULL)
    {
        IntSerializeString(pSection, pSection[0] == 0 ? 0 : 9, stringEncodeUtf8, pHeader);
    }
    else
    {
        IntSerializeString(pSection, 0, stringEncodeUtf8, pHeader);
    }

    if (gGuest.OSType == introGuestWindows)
    {
        IntSerializeWinKernelDriver(pDriver,
                                    ObjectType == intObjKernelDriver ?
                                    intObjWinKernelDriver : intObjWinKernelDriverReturn);
    }
    else if (gGuest.OSType == introGuestLinux)
    {
        IntSerializeLixKernelModule(pDriver,
                                    ObjectType == intObjKernelDriver ?
                                    intObjLixKernelModule : intObjLixKernelModuleReturn);
    }
}


static void
IntSerializeWinModule(
    _In_ const WIN_PROCESS_MODULE *Module,
    _In_ const DWORD ObjectType
    )
///
/// @brief  Serialize the provided #WIN_PROCESS_MODULE object.
///
/// @param[in]  Module      The windows module object.
/// @param[in]  ObjectType  The type of the windows module. (intObjWinModule, intObjWinModuleReturn).
///
{
    if (Module == NULL)
    {
        return;
    }

#define WIN_PROCESS_MODULE_SERIALIZER_VERSION 1

    SERIALIZER_OBJECT_HEADER *pHeader = IntSerializeObjectHeader(WIN_PROCESS_MODULE_SERIALIZER_VERSION, ObjectType);
    if (!pHeader)
    {
        return;
    }

    SERIALIZER_WIN_MODULE *pObject = IntSerializeCurrentPtr(sizeof(*pObject));
    if (!pObject)
    {
        return;
    }

    pObject->VirtualBase = Module->VirtualBase;
    pObject->Size = Module->Size;

    pHeader->Size = sizeof(*pObject);
    IntSerializeIncrementCurrentPtr(sizeof(*pObject));

    IntSerializeString(Module->Path->Path, Module->Path->PathSize, stringEncodeUtf16, pHeader);
}


void
IntSerializeInstruction(
    _In_ INSTRUX *Instruction,
    _In_ const QWORD Rip
    )
///
/// @brief  Serialize the provided INSTRUX object.
///
/// @param[in]  Instruction     The instruction object.
/// @param[in]  Rip             The value of the guest RIP register when the event was generated
///
{
    if (Instruction == NULL)
    {
        return;
    }

#define INSTRUX_SERIALIZER_VERSION       1

    SERIALIZER_OBJECT_HEADER *pHeader = IntSerializeObjectHeader(INSTRUX_SERIALIZER_VERSION, intObjInstrux);
    if (!pHeader)
    {
        return;
    }

    SERIALIZER_INSTRUX *pObject = IntSerializeCurrentPtr(sizeof(*pObject));
    if (!pObject)
    {
        return;
    }

    pObject->Rip = Rip;
    memcpy(pObject->Bytes, Instruction->InstructionBytes, sizeof(pObject->Bytes));

    pHeader->Size = sizeof(*pObject);
    IntSerializeIncrementCurrentPtr(sizeof(*pObject));
}


static void
IntSerializeWriteInfo(
    _In_ const EXCEPTION_VICTIM_ZONE *Victim
    )
///
/// @brief  Serialize the write violation information.
///
/// @param[in]  Victim      The victim object.
///
{
    if (Victim == NULL)
    {
        return;
    }

#define WRITE_INFO_SERIALIZER_VERSION       1

    SERIALIZER_OBJECT_HEADER *pHeader = IntSerializeObjectHeader(WRITE_INFO_SERIALIZER_VERSION, intObjWriteInfo);
    if (!pHeader)
    {
        return;
    }

    SERIALIZER_WRITE_INFO *pObject = IntSerializeCurrentPtr(sizeof(*pObject));
    if (!pObject)
    {
        return;
    }

    pObject->AccessSize = Victim->WriteInfo.AccessSize;
    memcpy(pObject->OldValue, Victim->WriteInfo.OldValue, MIN(sizeof(pObject->OldValue), pObject->AccessSize));
    memcpy(pObject->NewValue, Victim->WriteInfo.NewValue, MIN(sizeof(pObject->NewValue), pObject->AccessSize));

    pHeader->Size = sizeof(*pObject);
    IntSerializeIncrementCurrentPtr(sizeof(*pObject));
}


static void
IntSerializeReadInfo(
    _In_ const EXCEPTION_VICTIM_ZONE *Victim
    )
///
/// @brief  Serialize the read violation information.
///
/// @param[in]  Victim      The victim object.
///
{
    if (Victim == NULL)
    {
        return;
    }

#define READ_INFO_SERIALIZER_VERSION       1

    SERIALIZER_OBJECT_HEADER *pHeader = IntSerializeObjectHeader(READ_INFO_SERIALIZER_VERSION, intObjReadInfo);
    if (!pHeader)
    {
        return;
    }

    SERIALIZER_READ_INFO *pObject = IntSerializeCurrentPtr(sizeof(*pObject));
    if (!pObject)
    {
        return;
    }

    pObject->AccessSize = Victim->ReadInfo.AccessSize;
    memcpy(pObject->Value, Victim->ReadInfo.Value, MIN(sizeof(pObject->Value), pObject->AccessSize));

    pHeader->Size = sizeof(*pObject);
    IntSerializeIncrementCurrentPtr(sizeof(*pObject));
}


static void
IntSerializeExecInfo(
    _In_ const EXCEPTION_VICTIM_ZONE *Victim
    )
///
/// @brief  Serialize the execution violation information.
///
/// @param[in]  Victim      The victim object.
///
{
    if (Victim == NULL)
    {
        return;
    }

#define EXEC_INFO_SERIALIZER_VERSION       1

    SERIALIZER_OBJECT_HEADER *pHeader = IntSerializeObjectHeader(EXEC_INFO_SERIALIZER_VERSION, intObjExecInfo);
    if (!pHeader)
    {
        return;
    }

    SERIALIZER_EXEC_INFO *pObject = IntSerializeCurrentPtr(sizeof(*pObject));
    if (!pObject)
    {
        return;
    }

    pObject->Rsp = Victim->ExecInfo.Rsp;
    pObject->Length = Victim->ExecInfo.Length;
    pObject->StackBase = Victim->ExecInfo.StackBase;
    pObject->StackLimit = Victim->ExecInfo.StackLimit;

    pHeader->Size = sizeof(*pObject);
    IntSerializeIncrementCurrentPtr(sizeof(*pObject));
}


static void
IntSerializeAccessInfo(
    _In_ const EXCEPTION_VICTIM_ZONE *Victim
    )
///
/// @brief  Serialize the read/write/exec violation information.
///
/// @param[in]  Victim      The victim object.
///`
{
    if (Victim->ZoneFlags & ZONE_WRITE)
    {
        IntSerializeWriteInfo(Victim);
    }
    else if (Victim->ZoneFlags & ZONE_READ)
    {
        IntSerializeReadInfo(Victim);
    }
    else if (Victim->ZoneFlags & ZONE_EXECUTE)
    {
        IntSerializeExecInfo(Victim);
    }
}


static void
IntSerializeRawDump(
    _In_ const EXCEPTION_UM_ORIGINATOR *Originator,
    _In_ const EXCEPTION_VICTIM_ZONE *Victim
    )
///
/// @brief  Serialize the raw dump for the injection violation.
///
/// @param[in]  Originator  The originator object.
/// @param[in]  Victim      The victim object.
///
{
    if (Victim == NULL)
    {
        return;
    }

    if (Originator == NULL)
    {
        return;
    }

#define RAW_DUMP_SERIALIZER_VERSION       1

    SERIALIZER_OBJECT_HEADER *pHeader = IntSerializeObjectHeader(RAW_DUMP_SERIALIZER_VERSION, intObjRawDump);
    if (!pHeader)
    {
        return;
    }

    SERIALIZER_RAW_DUMP *pObject = IntSerializeCurrentPtr(sizeof(*pObject) + Victim->Injection.Length);
    if (!pObject)
    {
        return;
    }

    pObject->Length = Victim->Injection.Length;

    if (gGuest.OSType == introGuestLinux)
    {
        IntVirtMemRead(Originator->SourceVA, Victim->Injection.Length, Originator->LixProc->Cr3, pObject->Raw, NULL);
    }
    else if (gGuest.OSType == introGuestWindows)
    {
        IntVirtMemRead(Originator->SourceVA, Victim->Injection.Length, Originator->WinProc->Cr3, pObject->Raw, NULL);
    }

    pHeader->Size = (WORD)(sizeof(*pObject) + pObject->Length);
    IntSerializeIncrementCurrentPtr(sizeof(*pObject) + pObject->Length);
}


static void
IntSerializeRipCode(
    void
    )
///
/// @brief  Serialize the guest memory page that contains the RIP at which the violation attempt was detected.
///
{

#define RIP_CODE_SERIALIZER_VERSION 1
    INTSTATUS status = INT_STATUS_SUCCESS;

    SERIALIZER_OBJECT_HEADER *pHeader = IntSerializeObjectHeader(RIP_CODE_SERIALIZER_VERSION, intObjRipCode);
    if (!pHeader)
    {
        return;
    }

    SERIALIZER_RIP_CODE *pObject = IntSerializeCurrentPtr(sizeof(*pObject) + PAGE_SIZE);
    if (!pObject)
    {
        return;
    }

    status = IntGetCurrentMode(IG_CURRENT_VCPU, &pObject->CsType);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntGetCurrentMode failed: 0x%08x\n", status);
        pObject->CsType = IG_CS_TYPE_INVALID;
    }

    pObject->Length = PAGE_SIZE;

    IntVirtMemRead(gVcpu->Regs.Rip & PAGE_MASK, PAGE_SIZE, gVcpu->Regs.Cr3, pObject->Code, NULL);

    pHeader->Size = (WORD)(sizeof(*pObject) + pObject->Length);
    IntSerializeIncrementCurrentPtr(sizeof(*pObject) + pObject->Length);
}


static void
IntSerializeCodeBlocksGetExtractRange(
    _In_ QWORD Rip,
    _In_ BOOLEAN Execute,
    _Out_ DWORD *Start,
    _Out_ DWORD *End
    )
///
/// @brief  Computes the range from which the code-blocks should be extracted.
///
/// For execute violation the end offset may be in the next page.
///
/// @param[in]  Rip         The value of the guest RIP at the moment of the alert.
/// @param[in]  Execute     If the alert is an execution attempt.
/// @param[out] Start       The start offset relative to the RIP's page.
/// @param[out] End         The end offset relative to the RIP's page.
///
{
    DWORD startOffset = 0;
    DWORD endOffset = 0;

    startOffset = endOffset = Rip & PAGE_OFFSET;

    if (!Execute)
    {
        if (startOffset > EXCEPTION_CODEBLOCKS_OFFSET)
        {
            if (endOffset + EXCEPTION_CODEBLOCKS_OFFSET < PAGE_SIZE)
            {
                startOffset -= EXCEPTION_CODEBLOCKS_OFFSET;
                endOffset += EXCEPTION_CODEBLOCKS_OFFSET - 1;
            }
            else
            {
                startOffset = PAGE_SIZE - (EXCEPTION_CODEBLOCKS_OFFSET * 2);
                endOffset = PAGE_SIZE - 1;
            }

        }
        else
        {
            startOffset = 0;
            endOffset = (EXCEPTION_CODEBLOCKS_OFFSET * 2) - 1;
        }
    }
    else
    {
        endOffset += EXCEPTION_CODEBLOCKS_OFFSET - 1;
    }

    *Start = startOffset;
    *End = endOffset;
}


static CB_EXTRACT_LEVEL
IntSerializeCodeBlocksGetExtractLevel(
    _In_ QWORD Rip
    )
///
/// @brief  Get the code-blocks extraction level.
///
/// @param[in]  Rip         The value of the guest RIP at the moment of the alert.
///
{
    if (gGuest.OSType == introGuestWindows)
    {
        if (IS_KERNEL_POINTER_WIN(gGuest.Guest64, Rip))
        {
            return cbLevelNormal;
        }
        else
        {
            return cbLevelMedium;
        }
    }
    else if (gGuest.OSType == introGuestLinux)
    {
        if (IS_KERNEL_POINTER_LIX(Rip))
        {
            return cbLevelNormal;
        }
        else
        {
            return cbLevelMedium;
        }
    }

    return cbLevelNormal;
}


static void
IntSerializeCodeBlocksPattern(
    _In_ CODE_BLOCK *CodeBlocks,
    _In_ DWORD Count,
    _In_ QWORD Rip,
    _In_ BOOLEAN Execute,
    _Out_ SERIALIZER_CODE_BLOCKS *Object
    )
///
/// @brief  Iterates through all extracted code-blocks patterns and serialize the patterns.
///
/// @param[in]  CodeBlocks  An array of code-blocks pattern.
/// @param[in]  Count       The number of code-blocks pattern from CodeBlocks.
/// @param[in]  Rip         The value of the guest RIP at the moment of the alert.
/// @param[in]  Execute     If the alert is an execution attempt.
/// @param[in]  Object      The serializer header object.
///
{
    DWORD startCb = 0;
    DWORD ripCb = 0;

    if (!Execute)
    {
        DWORD previous = gCodeBlocks[0].OffsetStart;
        DWORD ripOffset = Rip & PAGE_OFFSET;

        // We must find where the RIP is inside the extracted codeblocks
        for (DWORD index = 0; index < Count; index++)
        {
            if (index == 0 && CodeBlocks[index].OffsetStart >= ripOffset)
            {
                ripCb = 0;
                break;
            }
            else if (index == Count - 1 || (previous <= ripOffset && ripOffset <= gCodeBlocks[index].OffsetStart))
            {
                ripCb = index;
                break;
            }

            previous = gCodeBlocks[index].OffsetStart;
        }

        if (Count <= ALERT_MAX_CODEBLOCKS || (ripCb <= ALERT_MAX_CODEBLOCKS / 2))
        {
            // [0; MIN(ALERT_MAX_CODEBLOCKS, cbCount)]
            startCb = 0;
        }
        else if (Count - ripCb < ALERT_MAX_CODEBLOCKS)
        {
            // [cbCount - ALERT_MAX_CODEBLOCKS; cbCount]
            startCb = Count >= ALERT_MAX_CODEBLOCKS ? Count - ALERT_MAX_CODEBLOCKS : 0;
        }
        else
        {
            // save before & after RIP
            startCb = ripCb - (ALERT_MAX_CODEBLOCKS / 2);
        }
    }
    else
    {
        startCb = 0;
    }

    Object->StartAddress = (Rip & PAGE_MASK) + CodeBlocks[startCb].OffsetStart;
    Object->Rip = Rip;
    Object->Count = 0;

    for (DWORD index = startCb; index < Count; index++)
    {
        Object->Content[Object->Count] = Crc32Compute(CodeBlocks[index].Chunks,
                                                      CODE_BLOCK_CHUNKS_COUNT,
                                                      INITIAL_CRC_VALUE);

        if (index == ripCb)
        {
            Object->RipCbIndex = Object->Count;
        }

        Object->Count++;

        if (Object->Count >= ALERT_MAX_CODEBLOCKS)
        {
            break;
        }
    }
}


static INTSTATUS
IntSerializeExtractCodeBlocks(
    _In_ QWORD Rip,
    _In_ QWORD Cr3,
    _In_ BOOLEAN Execute,
    _Out_ SERIALIZER_CODE_BLOCKS *Object
    )
///
/// @brief  Extract the code-blocks for the current exception.
///
/// This function calls the _IntSerializeCodeBlocksPattern to serialize the extracted code-blocks.
///
/// @param[in]  Rip         The value of the guest RIP at the moment of the alert.
/// @param[in]  Cr3         The value
/// @param[in]  Execute     If the alert is an execution attempt.
/// @param[in]  Object      The serializer header object.
///
/// @retval     #INT_STATUS_SUCCESS                 On success.
/// @retval     #INT_STATUS_DATA_BUFFER_TOO_SMALL   If the we could not extract enough code-blocks.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;
    void *pContent = NULL;
    DWORD mode = 0;
    DWORD startOffset = 0;
    DWORD endOffset = 0;
    CB_EXTRACT_LEVEL extractLevel = IntSerializeCodeBlocksGetExtractLevel(Rip);
    DWORD cbCount = 0;

    status = IntGetCurrentMode(IG_CURRENT_VCPU, &mode);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntGetCurrentMode failed: 0x%08x\n", status);
        return status;
    }

    if ((mode != IG_CS_TYPE_32B) && (mode != IG_CS_TYPE_64B))
    {
        ERROR("[ERROR] Unsupported CS type: %d\n", mode);
        return status;
    }

    IntSerializeCodeBlocksGetExtractRange(Rip, Execute, &startOffset, &endOffset);

    status = IntVirtMemMap((Rip & PAGE_MASK) + startOffset, endOffset - startOffset, Cr3, 0, &pContent);
    if (!INT_SUCCESS(status))
    {
        if (Execute)
        {
            WARNING("[WARNING] Failed to map range [0x%016llx - 0x%016llx], try to map range [0x%016llx - 0x%016llx]",
                    (Rip & PAGE_MASK) + startOffset, (Rip & PAGE_MASK) + startOffset + (endOffset - startOffset),
                    (Rip & PAGE_MASK) + startOffset,  (Rip & PAGE_MASK) + startOffset + (PAGE_SIZE - startOffset));
            status = IntVirtMemMap((Rip & PAGE_MASK) + startOffset,
                                   PAGE_SIZE - startOffset,
                                   Cr3,
                                   0,
                                   &pContent);
            if (!INT_SUCCESS(status))
            {
                WARNING("[WARNING] IntVirtMemMap failed for RIP %llx and cr3 %llx: 0x%08x\n",
                        Rip & PAGE_MASK, Cr3, status);
                return status;
            }

            endOffset = PAGE_SIZE;
        }
        else
        {
            WARNING("[WARNING] IntVirtMemMap failed for RIP %llx and cr3 %llx: 0x%08x\n",
                    Rip & PAGE_MASK, Cr3, status);
            return status;
        }
    }

    status = IntFragExtractCodePattern(pContent,
                                       startOffset,
                                       endOffset - startOffset,
                                       mode,
                                       extractLevel,
                                       PAGE_SIZE / sizeof(CODE_BLOCK_PATTERN),
                                       gCodeBlocksPattern,
                                       &gCodeBlocksPatternLength);
    if (!INT_SUCCESS(status))
    {
        if (status == INT_STATUS_DATA_BUFFER_TOO_SMALL)
        {
            WARNING("[WARNNING] Buffer too small to extract codeblocks (size %d): 0x%08x\n",
                    endOffset - startOffset,
                    status);
        }
        else
        {
            ERROR("[ERROR] IntFragExtractCodePattern: 0x%08x\n", status);
        }

        goto _exit;
    }

    if (gCodeBlocksPatternLength < CODE_BLOCK_CHUNKS_COUNT)
    {
        WARNING("[WARNING] Could not extract enough code-blocks from RIP %llx: %d\n",
                Rip,
                gCodeBlocksPatternLength);

        status = INT_STATUS_DATA_BUFFER_TOO_SMALL;
        goto _exit;
    }

    for (DWORD i = 0; i < gCodeBlocksPatternLength - CODE_BLOCK_CHUNKS_COUNT; i++)
    {
        if (cbLevelNormal == extractLevel &&
            (codeInsCall != gCodeBlocksPattern[i].Value &&
             codeInsJmp != gCodeBlocksPattern[i].Value))
        {
            continue;
        }

        if (cbLevelMedium == extractLevel &&
            (codeInsCall != gCodeBlocksPattern[i].Value &&
             codeInsJmp != gCodeBlocksPattern[i].Value &&
             codeInsMovMem != gCodeBlocksPattern[i].Value &&
             codeInsMovFsGs != gCodeBlocksPattern[i].Value))
        {
            continue;
        }

        gCodeBlocks[cbCount].PivotInstruction = gCodeBlocksPattern[i].Value;
        gCodeBlocks[cbCount].OffsetStart = gCodeBlocksPattern[i].Offset;

        // Extract from offset, CODE_BLOCK_CHUNKS_COUNT forward
        for (DWORD j = 0; j < CODE_BLOCK_CHUNKS_COUNT; j++)
        {
            gCodeBlocks[cbCount].Chunks[j] = gCodeBlocksPattern[i + j].Value;
            gCodeBlocks[cbCount].Size++;
        }

        ++cbCount;

        if (cbCount >= sizeof(gCodeBlocks) / sizeof(gCodeBlocks[0]))
        {
            break;
        }
    }


    if (IntSerializeValidObjectSize(sizeof(DWORD) * MIN(ALERT_MAX_CODEBLOCKS, cbCount)))
    {
        IntSerializeCodeBlocksPattern(gCodeBlocks, cbCount, Rip, Execute, Object);
    }
    else
    {
        status = INT_STATUS_DATA_BUFFER_TOO_SMALL;
        goto _exit;
    }

_exit:
    IntVirtMemUnmap(&pContent);

    return status;
}


static void
IntSerializeCodeBlocks(
    _In_ QWORD Rip,
    _In_ QWORD Cr3,
    _In_ BOOLEAN Execute
    )
///
/// @brief  Serialize the extracted code-blocks for the current exception.
///
/// @param[in]  Rip         The value of the guest RIP at the moment of the alert.
/// @param[in]  Cr3         The value
/// @param[in]  Execute     If the alert is an execution attempt.
///
{
#define CODE_BLOCKS_SERIALIZER_VERSION 1

    if (Rip == 0)
    {
        return;
    }

    SERIALIZER_OBJECT_HEADER *pHeader = IntSerializeObjectHeader(CODE_BLOCKS_SERIALIZER_VERSION, intObjCodeBlocks);
    if (!pHeader)
    {
        return;
    }

    SERIALIZER_CODE_BLOCKS *pObject = IntSerializeCurrentPtr(sizeof(*pObject));
    if (!pObject)
    {
        return;
    }

    memzero(pObject, sizeof(*pObject));

    INTSTATUS status = IntSerializeExtractCodeBlocks(Rip, Cr3, Execute, pObject);
    if (!INT_SUCCESS(status))
    {
        WARNING("[WARNING] IntSerializeExtractCodeBlocks failed with status: 0x%08x\n", status);
    }

    pHeader->Size = (WORD)(sizeof(*pObject) + pObject->Count * sizeof(DWORD));
    IntSerializeIncrementCurrentPtr(sizeof(*pObject) + pObject->Count * sizeof(DWORD));
}


static void
IntSerializeArchRegs(
    void
    )
///
/// @brief  Serialize the guest registers.
///
{
#define ARCH_REGS_SERIALIZER_VERSION 1

    SERIALIZER_OBJECT_HEADER *pHeader = IntSerializeObjectHeader(RIP_CODE_SERIALIZER_VERSION, intObjArchRegs);
    if (!pHeader)
    {
        return;
    }

    SERIALIZER_ARCH_REGS *pObject = IntSerializeCurrentPtr(sizeof(*pObject));
    if (!pObject)
    {
        return;
    }

    memcpy(pObject, &gVcpu->Regs, sizeof(*pObject));

    pHeader->Size += sizeof(*pObject);
    IntSerializeIncrementCurrentPtr(sizeof(*pObject));
}


static void
IntSerializeDpiWinDebug(
    _In_ const EXCEPTION_UM_ORIGINATOR *Originator,
    _In_ const EXCEPTION_VICTIM_ZONE *Victim
    )
///
/// @brief  Serialize the DPI debug flags info (Windows).
///
/// @param[in]  Originator  The originator object.
/// @param[in]  Victim      The victim object.
///
{
#define DPI_WIN_DEBUG_SERIALIZER_VERSION 1
    UNREFERENCED_PARAMETER(Originator);

    WIN_PROCESS_OBJECT *pProcess = Victim->Object.WinProc;
    if (!pProcess)
    {
        return;
    }

    SERIALIZER_OBJECT_HEADER *pHeader = IntSerializeObjectHeader(DPI_WIN_DEBUG_SERIALIZER_VERSION, intObjDpiWinDebug);
    if (!pHeader)
    {
        return;
    }

    SERIALIZER_DPI_WIN_DEBUG *pObject = IntSerializeCurrentPtr(sizeof(*pObject));
    if (!pObject)
    {
        return;
    }

    pObject->Debugger = pProcess->CreationInfo.DebuggerEprocess;

    pHeader->Size += sizeof(*pObject);
    IntSerializeIncrementCurrentPtr(sizeof(*pObject));

    IntSerializeWinProcess(IntWinProcFindObjectByEprocess(pProcess->CreationInfo.DebuggerEprocess), intObjWinProcess);
}


static void
IntSerializeDpiWinPivotedStack(
    _In_ const EXCEPTION_UM_ORIGINATOR *Originator,
    _In_ const EXCEPTION_VICTIM_ZONE *Victim
    )
///
/// @brief  Serialize the DPI pivoted stack info (Windows).
///
/// @param[in]  Originator  The originator object.
/// @param[in]  Victim      The victim object.
///
{
#define DPI_WIN_PIVOTET_STACK_SERIALIZER_VERSION 1
    UNREFERENCED_PARAMETER(Victim);

    DWORD trapFrameSize = gGuest.Guest64 ? sizeof(KTRAP_FRAME64) : sizeof(KTRAP_FRAME32);

    WIN_PROCESS_OBJECT *pProcess = Originator->WinProc;
    if (!pProcess)
    {
        return;
    }

    SERIALIZER_OBJECT_HEADER *pHeader = IntSerializeObjectHeader(DPI_WIN_PIVOTET_STACK_SERIALIZER_VERSION,
                                                                 intObjDpiWinPivotedStack);
    if (!pHeader)
    {
        return;
    }

    SERIALIZER_DPI_PIVOTED_STACK *pObject = IntSerializeCurrentPtr(sizeof(*pObject));
    if (!pObject)
    {
        return;
    }

    pObject->CurrentStack = pProcess->DpiExtraInfo.DpiPivotedStackExtraInfo.CurrentStack;
    pObject->StackBase = pProcess->DpiExtraInfo.DpiPivotedStackExtraInfo.StackBase;
    pObject->StackLimit = pProcess->DpiExtraInfo.DpiPivotedStackExtraInfo.StackLimit;
    pObject->Wow64CurrentStack = pProcess->DpiExtraInfo.DpiPivotedStackExtraInfo.CurrentWow64Stack;
    pObject->Wow64StackBase = pProcess->DpiExtraInfo.DpiPivotedStackExtraInfo.Wow64StackBase;
    pObject->Wow64StackLimit = pProcess->DpiExtraInfo.DpiPivotedStackExtraInfo.Wow64StackLimit;

    IntVirtMemRead(pProcess->DpiExtraInfo.DpiPivotedStackExtraInfo.TrapFrameAddress,
                   MIN(trapFrameSize, sizeof(pObject->TrapFrameContent)), gGuest.Mm.SystemCr3, pObject->TrapFrameContent,
                   NULL);

    pHeader->Size += sizeof(*pObject);
    IntSerializeIncrementCurrentPtr(sizeof(*pObject));
}


static void
IntSerializeDpiWinStolenToken(
    _In_ const EXCEPTION_UM_ORIGINATOR *Originator,
    _In_ const EXCEPTION_VICTIM_ZONE *Victim
    )
///
/// @brief  Serialize the DPI stolen token info (Windows).
///
/// @param[in]  Originator  The originator object.
/// @param[in]  Victim      The victim object.
///
{
#define DPI_WIN_STOLEN_TOKEN_SERIALIZER_VERSION 1
    UNREFERENCED_PARAMETER(Victim);

    WIN_PROCESS_OBJECT *pProcess = Originator->WinProc;
    if (!pProcess)
    {
        return;
    }

    SERIALIZER_OBJECT_HEADER *pHeader = IntSerializeObjectHeader(DPI_WIN_STOLEN_TOKEN_SERIALIZER_VERSION,
                                                                 intObjDpiWinStolenToken);
    if (!pHeader)
    {
        return;
    }

    SERIALIZER_DPI_WIN_STOLEN_TOKEN *pObject = IntSerializeCurrentPtr(sizeof(*pObject));
    if (!pObject)
    {
        return;
    }

    pObject->StolenFrom = pProcess->DpiExtraInfo.DpiStolenTokenExtraInfo.StolenFromEprocess;

    pHeader->Size += sizeof(*pObject);
    IntSerializeIncrementCurrentPtr(sizeof(*pObject));

    IntSerializeWinProcess(IntWinProcFindObjectByEprocess(pObject->StolenFrom), intObjWinProcess);
}


static void
IntSerializeDpiWinHeapSpray(
    _In_ const EXCEPTION_UM_ORIGINATOR *Originator,
    _In_ const EXCEPTION_VICTIM_ZONE *Victim
    )
///
/// @brief  Serialize the DPI heap spray info (Windows).
///
/// @param[in]  Originator  The originator object.
/// @param[in]  Victim      The victim object.
///
{
#define DPI_WIN_HEAP_SPRAY_SERIALIZER_VERSION 1

    UNREFERENCED_PARAMETER(Victim);

    WORD maxNumberOfHeapVals = 0;
    DWORD detectedPage = 0;
    DWORD maxPageHeapVals = 0;

    WIN_PROCESS_OBJECT *pProcess = Originator->WinProc;
    if (!pProcess)
    {
        return;
    }

    SERIALIZER_OBJECT_HEADER *pHeader = IntSerializeObjectHeader(DPI_WIN_HEAP_SPRAY_SERIALIZER_VERSION, intObjDpiWinHeapSpray);
    if (!pHeader)
    {
        return;
    }

    SERIALIZER_DPI_WIN_HEAP_SPRAY *pObject = IntSerializeCurrentPtr(sizeof(*pObject));
    if (!pObject)
    {
        return;
    }

    pObject->ShellcodeFlags = pProcess->DpiExtraInfo.DpiHeapSprayExtraInfo.ShellcodeFlags;

    for (DWORD val = 1; val <= HEAP_SPRAY_NR_PAGES; val++)
    {
        DWORD checkedPage = ((val << 24) | (val << 16) | (val << 8) | val) & PAGE_MASK;

        pObject->HeapPages[val - 1].Mapped = pProcess->DpiExtraInfo.DpiHeapSprayExtraInfo.HeapPages[val - 1].Mapped;
        pObject->HeapPages[val - 1].Detected = pProcess->DpiExtraInfo.DpiHeapSprayExtraInfo.HeapPages[val - 1].Detected;
        pObject->HeapPages[val - 1].HeapValCount =
            pProcess->DpiExtraInfo.DpiHeapSprayExtraInfo.HeapPages[val - 1].HeapValCount;
        pObject->HeapPages[val - 1].Offset = pProcess->DpiExtraInfo.DpiHeapSprayExtraInfo.HeapPages[val - 1].Offset;
        pObject->HeapPages[val - 1].Executable =
            pProcess->DpiExtraInfo.DpiHeapSprayExtraInfo.HeapPages[val - 1].Executable;

        if (pProcess->DpiExtraInfo.DpiHeapSprayExtraInfo.HeapPages[val - 1].Detected)
        {
            detectedPage = checkedPage;
        }

        // Use >= so that we are sure that we will get at least one page even if there are no heap values.
        if (pProcess->DpiExtraInfo.DpiHeapSprayExtraInfo.HeapPages[val - 1].HeapValCount >= maxNumberOfHeapVals &&
                pProcess->DpiExtraInfo.DpiHeapSprayExtraInfo.HeapPages[val - 1].Mapped)
        {
            maxNumberOfHeapVals = (WORD)pProcess->DpiExtraInfo.DpiHeapSprayExtraInfo.HeapPages[val - 1].HeapValCount;
            maxPageHeapVals = checkedPage;
        }
    }

    // At this point we might not have any detected page, but only pages exceeding the max heap values heuristic,
    // so don't bother to complete it if not needed.
    if (0 != detectedPage)
    {
        IntVirtMemRead(detectedPage, PAGE_SIZE, pProcess->Cr3, pObject->DetectedPage, NULL);
    }

    IntVirtMemRead(maxPageHeapVals, PAGE_SIZE, pProcess->Cr3, pObject->MaxHeapValPageContent, NULL);

    pHeader->Size += sizeof(*pObject);
    IntSerializeIncrementCurrentPtr(sizeof(*pObject));
}


static void
IntSerializeDpiWinTokenPrivs(
    _In_ const EXCEPTION_UM_ORIGINATOR *Originator,
    _In_ const EXCEPTION_VICTIM_ZONE *Victim
    )
///
/// @brief  Serialize the DPI token privs info (Windows).
///
/// @param[in]  Originator  The originator object.
/// @param[in]  Victim      The victim object.
///
{
#define DPI_WIN_TOKEN_PRIVS_SERIALIZER_VERSION 1

    UNREFERENCED_PARAMETER(Victim);

    WIN_PROCESS_OBJECT *pProcess = Originator->WinProc;
    if (!pProcess)
    {
        return;
    }

    SERIALIZER_OBJECT_HEADER *pHeader = IntSerializeObjectHeader(DPI_WIN_TOKEN_PRIVS_SERIALIZER_VERSION,
                                                                 intObjDpiWinTokenPrivs);
    if (!pHeader)
    {
        return;
    }

    SERIALIZER_DPI_WIN_TOKEN_PRIVS *pObject = IntSerializeCurrentPtr(sizeof(*pObject));
    if (!pObject)
    {
        return;
    }

    pObject->OldEnabled = pProcess->DpiExtraInfo.DpiTokenPrivsExtraInfo.OldEnabled;
    pObject->OldPresent = pProcess->DpiExtraInfo.DpiTokenPrivsExtraInfo.OldPresent;
    pObject->NewEnabled = pProcess->DpiExtraInfo.DpiTokenPrivsExtraInfo.NewEnabled;
    pObject->NewPresent = pProcess->DpiExtraInfo.DpiTokenPrivsExtraInfo.NewPresent;

    pHeader->Size += sizeof(*pObject);
    IntSerializeIncrementCurrentPtr(sizeof(*pObject));
}


static void
IntSerializeDpiWinThreadStart(
    _In_ const EXCEPTION_UM_ORIGINATOR *Originator,
    _In_ const EXCEPTION_VICTIM_ZONE *Victim
    )
///
/// @brief  Serialize the DPI start thread info (Windows).
///
/// @param[in]  Originator  The originator object.
/// @param[in]  Victim      The victim object.
///
{
#define DPI_WIN_THREAD_START_SERIALIZER_VERSION 1
    UNREFERENCED_PARAMETER(Victim);

    WIN_PROCESS_OBJECT *pProcess = Originator->WinProc;
    if (!pProcess)
    {
        return;
    }

    SERIALIZER_OBJECT_HEADER *pHeader = IntSerializeObjectHeader(DPI_WIN_THREAD_START_SERIALIZER_VERSION,
                                                                 intObjDpiWinThreadStart);
    if (!pHeader)
    {
        return;
    }

    SERIALIZER_DPI_WIN_THREAD_START *pObject = IntSerializeCurrentPtr(sizeof(*pObject));
    if (!pObject)
    {
        return;
    }

    pObject->ShellcodeFlags = pProcess->DpiExtraInfo.DpiThreadStartExtraInfo.ShellcodeFlags;
    pObject->StartAddress = pProcess->DpiExtraInfo.DpiThreadStartExtraInfo.StartAddress;

    IntVirtMemRead(pProcess->DpiExtraInfo.DpiThreadStartExtraInfo.StartAddress & PAGE_MASK, PAGE_SIZE, pProcess->Cr3,
            pObject->StartPage, NULL);

    pHeader->Size += sizeof(*pObject);
    IntSerializeIncrementCurrentPtr(sizeof(*pObject));
}


static void
IntSerializeDpiWinSecDesc(
    _In_ const EXCEPTION_UM_ORIGINATOR *Originator,
    _In_ const EXCEPTION_VICTIM_ZONE *Victim
    )
///
/// @brief  Serialize the DPI altered Security Descriptor info (Windows).
///
/// @param[in]  Originator  The originator object.
/// @param[in]  Victim      The victim object.
///
{
#define DPI_WIN_SEC_DESC_SERIALIZER_VERSION 1

    WIN_PROCESS_OBJECT *pProcess = Originator->WinProc;
    if (!pProcess)
    {
        return;
    }

    SERIALIZER_OBJECT_HEADER *pHeader = IntSerializeObjectHeader(DPI_WIN_SEC_DESC_SERIALIZER_VERSION,
                                                                 intObjDpiWinSecDesc);
    if (!pHeader)
    {
        return;
    }

    SERIALIZER_DPI_WIN_SEC_DESC *pObject = IntSerializeCurrentPtr(sizeof(*pObject));
    if (!pObject)
    {
        return;
    }

    pObject->SecDescStolenFromEproc =
        pProcess->DpiExtraInfo.DpiSecDescAclExtraInfo.SecDescStolenFromEproc;


    pObject->OldPtrValue = Victim->Object.WinProc->DpiExtraInfo.DpiSecDescAclExtraInfo.OldPtrValue;
    pObject->NewPtrValue = Victim->Object.WinProc->DpiExtraInfo.DpiSecDescAclExtraInfo.NewPtrValue;

    memcpy(&pObject->OldSacl, &Victim->Object.WinProc->DpiExtraInfo.DpiSecDescAclExtraInfo.OldSacl, sizeof(ACL));
    memcpy(&pObject->OldDacl, &Victim->Object.WinProc->DpiExtraInfo.DpiSecDescAclExtraInfo.OldDacl, sizeof(ACL));
    memcpy(&pObject->NewSacl, &Victim->Object.WinProc->DpiExtraInfo.DpiSecDescAclExtraInfo.NewSacl, sizeof(ACL));
    memcpy(&pObject->NewDacl, &Victim->Object.WinProc->DpiExtraInfo.DpiSecDescAclExtraInfo.NewDacl, sizeof(ACL));

    IntSerializeWinProcess(IntWinProcFindObjectByEprocess(pObject->SecDescStolenFromEproc),
                           intObjDpiWinSecDesc);

    pHeader->Size += sizeof(*pObject);
    IntSerializeIncrementCurrentPtr(sizeof(*pObject));
}


static void
IntSerializeDpiWinAclEdit(
    _In_ const EXCEPTION_UM_ORIGINATOR *Originator,
    _In_ const EXCEPTION_VICTIM_ZONE *Victim
    )
///
/// @brief  Serialize the DPI ACL edit info (Windows).
///
/// @param[in]  Originator  The originator object.
/// @param[in]  Victim      The victim object.
///
{
#define DPI_WIN_ACL_SERIALIZER_VERSION 1

    WIN_PROCESS_OBJECT *pProcess = Originator->WinProc;
    if (!pProcess)
    {
        return;
    }

    SERIALIZER_OBJECT_HEADER *pHeader = IntSerializeObjectHeader(DPI_WIN_ACL_SERIALIZER_VERSION,
                                                                 intObjDpiWinAclEdit);
    if (!pHeader)
    {
        return;
    }

    SERIALIZER_DPI_WIN_ACL_EDIT *pObject = IntSerializeCurrentPtr(sizeof(*pObject));
    if (!pObject)
    {
        return;
    }

    memcpy(&pObject->OldSacl, &Victim->Object.WinProc->DpiExtraInfo.DpiSecDescAclExtraInfo.OldSacl, sizeof(ACL));
    memcpy(&pObject->OldDacl, &Victim->Object.WinProc->DpiExtraInfo.DpiSecDescAclExtraInfo.OldDacl, sizeof(ACL));
    memcpy(&pObject->NewSacl, &Victim->Object.WinProc->DpiExtraInfo.DpiSecDescAclExtraInfo.NewSacl, sizeof(ACL));
    memcpy(&pObject->NewDacl, &Victim->Object.WinProc->DpiExtraInfo.DpiSecDescAclExtraInfo.NewDacl, sizeof(ACL));

    pHeader->Size += sizeof(*pObject);
    IntSerializeIncrementCurrentPtr(sizeof(*pObject));
}


static void
IntSerializeWinDpiInfo(
    const _In_ EXCEPTION_UM_ORIGINATOR *Originator,
    const _In_ EXCEPTION_VICTIM_ZONE *Victim
    )
///
/// @brief  Serialize the DPI extra information.
///
/// @param[in]  Originator  The originator object.
/// @param[in]  Victim      The victim object.
///
{
    switch (Originator->PcType)
    {
        case INT_PC_VIOLATION_DPI_DEBUG_FLAG:
            IntSerializeDpiWinDebug(Originator, Victim);
            break;

        case INT_PC_VIOLATION_DPI_PIVOTED_STACK:
            IntSerializeDpiWinPivotedStack(Originator, Victim);
            break;

        case INT_PC_VIOLATION_DPI_STOLEN_TOKEN:
            IntSerializeDpiWinStolenToken(Originator, Victim);
            break;

        case INT_PC_VIOLATION_DPI_HEAP_SPRAY:
            IntSerializeDpiWinHeapSpray(Originator, Victim);
            break;

        case INT_PC_VIOLATION_DPI_TOKEN_PRIVS:
            IntSerializeDpiWinTokenPrivs(Originator, Victim);
            break;

        case INT_PC_VIOLATION_DPI_THREAD_START:
            IntSerializeDpiWinThreadStart(Originator, Victim);
            break;

        case INT_PC_VIOLATION_DPI_SEC_DESC:
            IntSerializeDpiWinSecDesc(Originator, Victim);
            break;

        case INT_PC_VIOLATION_DPI_ACL_EDIT:
            IntSerializeDpiWinAclEdit(Originator, Victim);
            break;

        default:
            break;
    }
}


static void
IntSerializeDpi(
    _In_ const EXCEPTION_UM_ORIGINATOR *Originator
    )
///
/// @brief  Serialize the DPI flags.
///
/// @param[in]  Originator      The originator object.
///
{
#define DPI_SERIALIZER_VERSION 1

    SERIALIZER_OBJECT_HEADER *pHeader = IntSerializeObjectHeader(DPI_SERIALIZER_VERSION, intObjDpi);
    if (!pHeader)
    {
        return;
    }

    SERIALIZER_DPI *pObject = IntSerializeCurrentPtr(sizeof(*pObject));
    if (!pObject)
    {
        return;
    }

    pObject->Flags = Originator->PcType;

    pHeader->Size += sizeof(*pObject);
    IntSerializeIncrementCurrentPtr(sizeof(*pObject));
}


static void
IntSerializeExport(
    _In_ const EXCEPTION_VICTIM_ZONE *Victim
    )
///
/// @brief  Serialize the modified exports.
///
/// @param[in]  Victim      The victim object.
///
{
    WINUM_CACHE_EXPORT *pExport = NULL;

    if (Victim->Object.Library.Export == NULL)
    {
        pExport = IntWinUmCacheGetExportFromRange(Victim->Object.Library.WinMod, Victim->Ept.Gva, 0x20);
    }
    else
    {
        pExport = Victim->Object.Library.Export;
    }

    if (!pExport)
    {
        return;
    }

#define EXPORT_SERIALIZER_VERSION 1

    SERIALIZER_OBJECT_HEADER *pHeader = IntSerializeObjectHeader(EXPORT_SERIALIZER_VERSION, intObjExport);
    if (!pHeader)
    {
        return;
    }

    SERIALIZER_EXPORT *pObject = IntSerializeCurrentPtr(sizeof(*pObject));
    if (!pObject)
    {
        return;
    }

    pObject->Count = pExport->NumberOfOffsets;
    pObject->Delta = (DWORD)(Victim->Ept.Gva - Victim->Object.Library.WinMod->VirtualBase - pExport->Rva);

    pHeader->Size = sizeof(*pObject);
    IntSerializeIncrementCurrentPtr(sizeof(*pObject));

    for (DWORD index = 0; index < pExport->NumberOfOffsets; index++)
    {
        IntSerializeString(pExport->Names[index], pExport->NameLens[index], stringEncodeUtf8, pHeader);
    }
}


static void
IntSerializeWinUmOriginator(
    _In_ const EXCEPTION_UM_ORIGINATOR *Originator,
    _In_ const EXCEPTION_VICTIM_ZONE *Victim
    )
///
/// @brief  Serialize the information about windows user-mode originator.
///
/// @param[in]  Originator  The originator object.
/// @param[in]  Victim      The victim object.
///
{
    UNREFERENCED_PARAMETER(Victim);

    IntSerializeProcess(Originator->Process, intObjWinProcess);
    IntSerializeProcess(IntWinProcFindObjectByEprocess(Originator->WinProc->ParentEprocess), intObjWinProcessParent);

    IntSerializeWinModule(Originator->WinLib, intObjWinModule);

    if (Originator->Return.Library && Originator->Return.Rip != Originator->Rip)
    {
        IntSerializeWinModule(Originator->Return.WinLib, intObjWinModuleReturn);
    }
}


void
IntSerializeLixUmOriginator(
    _In_ const EXCEPTION_UM_ORIGINATOR *Originator,
    _In_ const EXCEPTION_VICTIM_ZONE *Victim
    )
///
/// @brief  Serialize the information about Linux user-mode originator.
///
/// @param[in]  Originator  The originator object.
/// @param[in]  Victim      The victim object.
///
{
    UNREFERENCED_PARAMETER(Victim);

    IntSerializeProcess(Originator->Process, intObjLixProcess);
    IntSerializeProcess(IntLixTaskFindByGva(Originator->LixProc->Parent), intObjLixProcessParent);

    IntSerializeInstruction(Originator->Instruction, Originator->Rip);
    IntSerializeCodeBlocks(Originator->Rip, Originator->LixProc->Cr3, Originator->Execute);
}


static void
IntSerializeUmOriginator(
    _In_ const EXCEPTION_UM_ORIGINATOR *Originator,
    _In_ const EXCEPTION_VICTIM_ZONE *Victim
    )
///
/// @brief  Serialize the information about user-mode originator.
///
/// @param[in]  Originator  The originator object.
/// @param[in]  Victim      The victim object.
///
{

#define START_ORIGINATOR_SERIALZIER_VERSION     1
#define END_ORIGINATOR_SERIALZIER_VERSION       1

    IntSerializeObjectHeader(START_ORIGINATOR_SERIALZIER_VERSION, intObjStartOriginator);

    if (gGuest.OSType == introGuestLinux)
    {
        IntSerializeLixUmOriginator(Originator, Victim);
    }
    else if (gGuest.OSType == introGuestWindows)
    {
        IntSerializeWinUmOriginator(Originator, Victim);
    }

    IntSerializeObjectHeader(END_ORIGINATOR_SERIALZIER_VERSION, intObjEndOriginator);
}


static void
IntSerializeLixUmVictim(
    _In_ const EXCEPTION_UM_ORIGINATOR *Originator,
    _In_ const EXCEPTION_VICTIM_ZONE *Victim
    )
///
/// @brief  Serialize the information about Linux user-mode victim.
///
/// @param[in]  Originator  The originator object.
/// @param[in]  Victim      The victim object.
///
{
#define LIX_VICTIM_SERIALIZER_VERSION       1

    UNREFERENCED_PARAMETER(Originator);

    SERIALIZER_OBJECT_HEADER *pHeader = IntSerializeObjectHeader(LIX_VICTIM_SERIALIZER_VERSION, intObjVictim);
    if (!pHeader)
    {
        return;
    }

    SERIALIZER_EXCEPTION_VICTIM *pObject = IntSerializeCurrentPtr(sizeof(*pObject));
    if (!pObject)
    {
        return;
    }

    pObject->Type = Victim->Object.Type;
    pObject->ZoneType = Victim->ZoneType;
    pObject->ZoneFlags = Victim->ZoneFlags;

    pHeader->Size = sizeof(*pObject);
    IntSerializeIncrementCurrentPtr(sizeof(*pObject));

    IntSerializeProcess(Victim->Object.Process, intObjLixProcess);
    IntSerializeProcess(IntLixTaskFindByGva(Victim->Object.LixProc->Parent), intObjLixProcessParent);

    IntSerializeVad(Victim->Object.Vad);
}


static void
IntSerializeWinUmVictim(
    _In_ const EXCEPTION_UM_ORIGINATOR *Originator,
    _In_ const EXCEPTION_VICTIM_ZONE *Victim
    )
///
/// @brief  Serialize the information about user-mode windows victim.
///
/// @param[in]  Originator  The originator object.
/// @param[in]  Victim      The victim object.
///
{
#define WIN_VICTIM_SERIALIZER_VERSION       1
    UNREFERENCED_PARAMETER(Originator);

    SERIALIZER_OBJECT_HEADER *pHeader = IntSerializeObjectHeader(WIN_VICTIM_SERIALIZER_VERSION, intObjVictim);
    if (!pHeader)
    {
        return;
    }

    SERIALIZER_EXCEPTION_VICTIM *pObject = IntSerializeCurrentPtr(sizeof(*pObject));
    if (!pObject)
    {
        return;
    }

    pObject->Type = Victim->Object.Type;
    pObject->ZoneType = Victim->ZoneType;
    pObject->ZoneFlags = Victim->ZoneFlags;

    pHeader->Size = sizeof(*pObject);
    IntSerializeIncrementCurrentPtr(sizeof(*pObject));

    if ((Victim->ZoneType == exceptionZoneProcess) ||
        (Victim->Object.Type == introObjectTypeUmGenericNxZone) ||
        (Victim->Object.Type == introObjectTypeSudExec))
    {
        IntSerializeProcess(Victim->Object.Process, intObjWinProcess);
        IntSerializeProcess(IntWinProcFindObjectByEprocess(Victim->Object.WinProc->ParentEprocess),
                            intObjWinProcessParent);

        IntSerializeWinModule(Victim->Object.Library.WinMod, intObjWinModule);
        IntSerializeVad(Victim->Object.Vad);
    }
    else if (Victim->Object.Type == introObjectTypeUmModule)
    {
        IntSerializeProcess(Victim->Object.Process, intObjWinProcess);
        IntSerializeWinModule(Victim->Object.Library.WinMod, intObjWinModule);
    }
}


static void
IntSerializeWinUmMisc(
    _In_ const EXCEPTION_UM_ORIGINATOR *Originator,
    _In_ const EXCEPTION_VICTIM_ZONE *Victim
    )
///
/// @brief  Serialize the misc information for windows user-mode alert.
///
/// @param[in]  Originator  The originator object.
/// @param[in]  Victim      The victim object.
///
{
    UNREFERENCED_PARAMETER(Originator);

    if ((Victim->ZoneType == exceptionZoneProcess) ||
        (Victim->Object.Type == introObjectTypeUmGenericNxZone) ||
        (Victim->Object.Type == introObjectTypeSudExec))
    {
        if (Victim->ZoneType == exceptionZoneProcess)
        {
            IntSerializeInjection(&Victim->Injection, Victim);
            IntSerializeRawDump(Originator, Victim);
        }
        else
        {
            IntSerializeEpt(&Victim->Ept, Victim);
            IntSerializeAccessInfo(Victim);
        }
    }
    else if (Victim->Object.Type == introObjectTypeUmModule)
    {
        IntSerializeInstruction(Originator->Instruction, Originator->Rip);
        IntSerializeExport(Victim);
        IntSerializeAccessInfo(Victim);
        IntSerializeEpt(&Victim->Ept, Victim);
    }

    if (Originator->PcType)
    {
        IntSerializeDpi(Originator);
        IntSerializeWinDpiInfo(Originator, Victim);
    }

    IntSerializeCodeBlocks(Originator->Rip, Originator->WinProc->Cr3, Originator->Execute);
    IntSerializeRipCode();
}


static void
IntSerializeLixUmMisc(
    _In_ const EXCEPTION_UM_ORIGINATOR *Originator,
    _In_ const EXCEPTION_VICTIM_ZONE *Victim
    )
///
/// @brief  Serialize the misc information for Linux user-mode alert.
///
/// @param[in]  Originator  The originator object.
/// @param[in]  Victim      The victim object.
///
{
    UNREFERENCED_PARAMETER(Originator);

    if (Victim->ZoneType == exceptionZoneProcess)
    {
        IntSerializeInjection(&Victim->Injection, Victim);
        IntSerializeRawDump(Originator, Victim);

        if (Originator->PcType)
        {
            IntSerializeDpi(Originator);
        }
    }
    else
    {
        IntSerializeEpt(&Victim->Ept, Victim);
        IntSerializeAccessInfo(Victim);
    }

    IntSerializeCodeBlocks(Originator->Rip, Originator->LixProc->Cr3, Originator->Execute);
    IntSerializeRipCode();
}


static void
IntSerializeUmMisc(
    _In_ const EXCEPTION_UM_ORIGINATOR *Originator,
    _In_ const EXCEPTION_VICTIM_ZONE *Victim
    )
///
/// @brief  Serialize the misc information for user-mode alert.
///
/// @param[in]  Originator  The originator object.
/// @param[in]  Victim      The victim object.
///
{
#define START_MISC_SERIALZIER_VERSION     1
#define END_MISC_SERIALZIER_VERSION       1

    IntSerializeObjectHeader(START_MISC_SERIALZIER_VERSION, intObjStartMisc);

    if (gGuest.OSType == introGuestLinux)
    {
        IntSerializeLixUmMisc(Originator, Victim);
    }
    else if (gGuest.OSType == introGuestWindows)
    {
        IntSerializeWinUmMisc(Originator, Victim);
    }

    IntSerializeObjectHeader(END_MISC_SERIALZIER_VERSION, intObjEndMisc);
}


static void
IntSerializeUmVictim(
    _In_ const EXCEPTION_UM_ORIGINATOR *Originator,
    _In_ const EXCEPTION_VICTIM_ZONE *Victim
    )
///
/// @brief  Serialize the information about user-mode victim.
///
/// @param[in]  Originator  The originator object.
/// @param[in]  Victim      The victim object.
///
{
#define START_VICTIM_SERIALZIER_VERSION     1
#define END_VICTIM_SERIALZIER_VERSION       1

    IntSerializeObjectHeader(START_VICTIM_SERIALZIER_VERSION, intObjStartVictim);

    if (gGuest.OSType == introGuestLinux)
    {
        IntSerializeLixUmVictim(Originator, Victim);
    }
    else if (gGuest.OSType == introGuestWindows)
    {
        IntSerializeWinUmVictim(Originator, Victim);
    }

    IntSerializeObjectHeader(END_VICTIM_SERIALZIER_VERSION, intObjEndVictim);
}


void
IntSerializeWinKmOriginator(
    _In_ const EXCEPTION_KM_ORIGINATOR *Originator,
    _In_ const EXCEPTION_VICTIM_ZONE *Victim
    )
///
/// @brief  Serialize the information about windows kernel-mode originator.
///
/// @param[in]  Originator  The originator object.
/// @param[in]  Victim      The victim object.
///
{
#define KM_ORIGINATOR_SERIALZIER_VERSION   1

    UNREFERENCED_PARAMETER(Victim);

    IntSerializeKernelDriver(Originator, NULL, intObjKernelDriver);
    IntSerializeKernelDriver(Originator, NULL, intObjKernelDriverReturn);
}


void
IntSerializeLixKmOriginator(
    _In_ const EXCEPTION_KM_ORIGINATOR *Originator,
    _In_ const EXCEPTION_VICTIM_ZONE *Victim
    )
///
/// @brief  Serialize the information about Linux kernel-mode originator.
///
/// @param[in]  Originator  The originator object.
/// @param[in]  Victim      The victim object.
///
{
#define KM_ORIGINATOR_SERIALZIER_VERSION   1

    UNREFERENCED_PARAMETER(Victim);

    IntSerializeKernelDriver(Originator, NULL, intObjKernelDriver);
    IntSerializeKernelDriver(Originator, NULL, intObjKernelDriverReturn);

    IntSerializeInstruction(Originator->Instruction, Originator->Original.Rip);
}


void
IntSerializeKmOriginator(
    _In_ const EXCEPTION_KM_ORIGINATOR *Originator,
    _In_ const EXCEPTION_VICTIM_ZONE *Victim
    )
///
/// @brief  Serialize the information about kernel-mode originator.
///
/// @param[in]  Originator  The originator object.
/// @param[in]  Victim      The victim object.
///
{
    IntSerializeObjectHeader(START_ORIGINATOR_SERIALZIER_VERSION, intObjStartOriginator);

    if (gGuest.OSType == introGuestLinux)
    {
        IntSerializeLixKmOriginator(Originator, Victim);
    }
    else if (gGuest.OSType == introGuestWindows)
    {
        IntSerializeWinKmOriginator(Originator, Victim);
    }

    IntSerializeObjectHeader(END_ORIGINATOR_SERIALZIER_VERSION, intObjEndOriginator);
}


static void
IntSerializeWinKmVictim(
    _In_ const EXCEPTION_KM_ORIGINATOR *Originator,
    _In_ const EXCEPTION_VICTIM_ZONE *Victim
    )
///
/// @brief  Serialize the information about Windows kernel-mode victim.
///
/// @param[in]  Originator  The originator object.
/// @param[in]  Victim      The victim object.
///
{
#define WIN_KM_VICTIM_SERIALIZER_VERSION   1

    UNREFERENCED_PARAMETER(Originator);

    SERIALIZER_OBJECT_HEADER *pHeader = IntSerializeObjectHeader(WIN_KM_VICTIM_SERIALIZER_VERSION, intObjVictim);
    if (!pHeader)
    {
        return;
    }

    SERIALIZER_EXCEPTION_VICTIM *pObject = IntSerializeCurrentPtr(sizeof(*pObject));
    if (!pObject)
    {
        return;
    }

    pObject->Type = Victim->Object.Type;
    pObject->ZoneType = Victim->ZoneType;
    pObject->ZoneFlags = Victim->ZoneFlags;

    pHeader->Size = sizeof(*pObject);
    IntSerializeIncrementCurrentPtr(sizeof(*pObject));

    switch (Victim->ZoneType)
    {
    case exceptionZoneCr:
        IntSerializeCr(&Victim->Cr);
        break;

    case exceptionZoneMsr:
        IntSerializeMsr(&Victim->Msr);
        break;

    case exceptionZoneDtr:
        IntSerializeDtr(&Victim->Dtr);
        break;
    case exceptionZoneEpt:
        IntSerializeEpt(&Victim->Ept, Victim);
        break;

    default:
        break;
    }

    switch (Victim->Object.Type)
    {
    case introObjectTypeIdt:
        IntSerializeIdt(Victim);
        break;

    case introObjectTypeSsdt:
    case introObjectTypeVeAgent:
    case introObjectTypeKmModule:
        IntSerializeKernelDriver(NULL, Victim->Object.Module.Module, intObjKernelDriver);
        break;

    case introObjectTypeDriverObject:
    case introObjectTypeFastIoDispatch:
        IntSerializeKernelDrvObject(Victim->Object.DriverObject);
        break;

    default:
        break;
    }
}


static void
IntSerializeLixKmVictim(
    _In_ const EXCEPTION_KM_ORIGINATOR *Originator,
    _In_ const EXCEPTION_VICTIM_ZONE *Victim
    )
///
/// @brief  Serialize the information about Linux kernel-mode victim.
///
/// @param[in]  Originator  The originator object.
/// @param[in]  Victim      The victim object.
///

{
#define LIX_KM_VICTIM_SERIALIZER_VERSION   1

    UNREFERENCED_PARAMETER(Originator);

    SERIALIZER_OBJECT_HEADER *pHeader = IntSerializeObjectHeader(LIX_KM_VICTIM_SERIALIZER_VERSION, intObjVictim);
    if (!pHeader)
    {
        return;
    }

    SERIALIZER_EXCEPTION_VICTIM *pObject = IntSerializeCurrentPtr(sizeof(*pObject));
    if (!pObject)
    {
        return;
    }

    pObject->Type = Victim->Object.Type;
    pObject->ZoneType = Victim->ZoneType;
    pObject->ZoneFlags = Victim->ZoneFlags;

    pHeader->Size = sizeof(*pObject);
    IntSerializeIncrementCurrentPtr(sizeof(*pObject));

    switch (Victim->ZoneType)
    {
    case exceptionZoneCr:
        IntSerializeCr(&Victim->Cr);
        break;

    case exceptionZoneMsr:
        IntSerializeMsr(&Victim->Msr);
        break;

    case exceptionZoneDtr:
        IntSerializeDtr(&Victim->Dtr);
        break;

    case exceptionZoneEpt:
        IntSerializeEpt(&Victim->Ept, Victim);
        break;

    default:
        break;
    }

    switch (Victim->Object.Type)
    {
    case introObjectTypeVdso:
    case introObjectTypeVsyscall:
    case introObjectTypeKmModule:
        IntSerializeKernelDriver(NULL, Victim->Object.Module.Module, intObjKernelDriver);
        break;

    default:
        break;
    }
}


static void
IntSerializeKmVictim(
    _In_ const EXCEPTION_KM_ORIGINATOR *Originator,
    _In_ const EXCEPTION_VICTIM_ZONE *Victim
    )
///
/// @brief  Serialize the information about kernel-mode victim.
///
/// @param[in]  Originator  The originator object.
/// @param[in]  Victim      The victim object.
///

{
    IntSerializeObjectHeader(START_VICTIM_SERIALZIER_VERSION, intObjStartVictim);

    if (gGuest.OSType == introGuestLinux)
    {
        IntSerializeLixKmVictim(Originator, Victim);
    }
    else if (gGuest.OSType == introGuestWindows)
    {
        IntSerializeWinKmVictim(Originator, Victim);
    }

    IntSerializeObjectHeader(END_VICTIM_SERIALZIER_VERSION, intObjEndVictim);
}


static void
IntSerializeLixKmMisc(
    _In_ const EXCEPTION_KM_ORIGINATOR *Originator,
    _In_ const EXCEPTION_VICTIM_ZONE *Victim
    )
///
/// @brief  Serialize the misc information for Linux kernel-mode alert.
///
/// @param[in]  Originator  The originator object.
/// @param[in]  Victim      The victim object.
///
{
    IntSerializeCodeBlocks(Originator->Original.Rip, gGuest.Mm.SystemCr3, FALSE);
    IntSerializeCodeBlocks(Originator->Return.Rip, gGuest.Mm.SystemCr3, FALSE);

    IntSerializeInstruction(Originator->Instruction, Originator->Original.Rip);
    IntSerializeAccessInfo(Victim);

    IntSerializeArchRegs();
    IntSerializeRipCode();
}


static void
IntSerializeWinKmMisc(
    _In_ const EXCEPTION_KM_ORIGINATOR *Originator,
    _In_ const EXCEPTION_VICTIM_ZONE *Victim
    )
///
/// @brief  Serialize the misc information for windows kernel-mode alert.
///
/// @param[in]  Originator  The originator object.
/// @param[in]  Victim      The victim object.
///
{

    IntSerializeCodeBlocks(Originator->Original.Rip, gGuest.Mm.SystemCr3, FALSE);
    IntSerializeCodeBlocks(Originator->Return.Rip, gGuest.Mm.SystemCr3, FALSE);

    IntSerializeInstruction(Originator->Instruction, Originator->Original.Rip);
    IntSerializeAccessInfo(Victim);

    IntSerializeEpt(&Victim->Ept, Victim);

    IntSerializeArchRegs();
    IntSerializeRipCode();

    if (Victim->Object.Type == introObjectTypeUmModule)
    {
        IntSerializeExport(Victim);
    }
}


static void
IntSerializeKmMisc(
    _In_ const EXCEPTION_KM_ORIGINATOR *Originator,
    _In_ const EXCEPTION_VICTIM_ZONE *Victim
    )
///
/// @brief  Serialize the misc information for kernel-mode alert.
///
/// @param[in]  Originator  The originator object.
/// @param[in]  Victim      The victim object.
///
{
#define START_MISC_SERIALZIER_VERSION     1
#define END_MISC_SERIALZIER_VERSION       1

    UNREFERENCED_PARAMETER(Originator);
    UNREFERENCED_PARAMETER(Victim);

    IntSerializeObjectHeader(START_MISC_SERIALZIER_VERSION, intObjStartMisc);

    if (gGuest.OSType == introGuestLinux)
    {
        IntSerializeLixKmMisc(Originator, Victim);
    }
    else if (gGuest.OSType == introGuestWindows)
    {
        IntSerializeWinKmMisc(Originator, Victim);
    }

    IntSerializeObjectHeader(END_MISC_SERIALZIER_VERSION, intObjEndMisc);
}


static void
IntSerializeHeader(
    _In_ SERIALIZER_EXCEPTION_TYPE SerializerType,
    _In_ INTRO_EVENT_TYPE EventClass
    )
///
/// @brief  Serialize the header of the serializer buffer.
///
/// @param[in]  SerializerType  The type of the serializer exception.
/// @param[in]  EventClass      The type of event.
///
{
    SERIALIZER_HEADER *pHeader = IntSerializeCurrentPtr(sizeof(*pHeader));
    if (!pHeader)
    {
        return;
    }

    pHeader->SerializedType = SerializerType;
    pHeader->Guest = gGuest.OSType;
    pHeader->Event = EventClass;
    pHeader->Size = 0;
    pHeader->Arch = gGuest.Guest64;

    IntSerializeIncrementCurrentPtr(sizeof(*pHeader));
}


static void
IntSerializeKmException(
    _In_ const void *Originator,
    _In_ const void *Victim,
    _In_ INTRO_EVENT_TYPE EventClass
    )
///
/// @brief  Serialize the kernel-mode exception.
///
/// @param[in]  Originator  The originator object.
/// @param[in]  Victim      The victim object.
/// @param[in]  EventClass  The type of event.
///
{
    IntSerializeHeader(serializerExceptionTypeKm, EventClass);

    IntSerializeKmOriginator(Originator, Victim);
    IntSerializeKmVictim(Originator, Victim);
    IntSerializeKmMisc(Originator, Victim);
}


static void
IntSerializeUmException(
    _In_ const void *Originator,
    _In_ const void *Victim,
    _In_ INTRO_EVENT_TYPE EventClass
    )
///
/// @brief  Serialize the user-mode exception.
///
/// @param[in]  Originator  The originator object.
/// @param[in]  Victim      The victim object.
/// @param[in]  EventClass  The type of event.
///
{
    IntSerializeHeader(serializerExceptionTypeUm, EventClass);

    IntSerializeUmOriginator(Originator, Victim);
    IntSerializeUmVictim(Originator, Victim);
    IntSerializeUmMisc(Originator, Victim);
}


static void
IntSerializeKernelUserException(
    _In_ const void *Originator,
    _In_ const void *Victim,
    _In_ INTRO_EVENT_TYPE EventClass
    )
///
/// @brief  Serialize the kernel-user mode exception.
///
/// @param[in]  Originator  The originator object.
/// @param[in]  Victim      The victim object.
/// @param[in]  EventClass  The type of event.
///
{
    IntSerializeHeader(serializerExceptionTypeKmUm, EventClass);

    IntSerializeKmOriginator(Originator, Victim);
    IntSerializeUmVictim(Originator, Victim);
    IntSerializeKmMisc(Originator, Victim);
}

void
IntSerializeStart(
    void
    )
///
/// @brief Set the current serializer pointer to the beginning of the buffer and generated a new alert-ID.
///
{
    IntSerializeIncrementCurrentId();
    gCurrentPtr = gSerializerBuffer;
}


void
IntSerializeException(
    _In_ void *Victim,
    _In_ void *Originator,
    _In_ DWORD Type,
    _In_ INTRO_ACTION Action,
    _In_ INTRO_ACTION_REASON Reason,
    _In_ INTRO_EVENT_TYPE EventClass
    )
///
/// @brief  The entry point of the serializer; will serialize the provided exception if the violation is blocked or
/// the feedback flag is set.
///
/// The base64 buffer is logged.
///
/// @param[in]  Originator  The originator object.
/// @param[in]  Victim      The victim object.
/// @param[in]  Type        The type of the exception (user-mode/kernel-mode).
/// @param[in]  Action      The action that was taken as the result of this alert.
/// @param[in]  Reason      The reason for which Action was taken.
/// @param[in]  EventClass  The type of event.
///
{
    if ((introGuestNotAllowed != Action) && (introReasonAllowedFeedback != Reason))
    {
        return;
    }

    IntSerializeStart();

    switch (Type)
    {
    case exceptionTypeKm:
        IntSerializeKmException(Originator, Victim, EventClass);
        break;

    case exceptionTypeUm:
        IntSerializeUmException(Originator, Victim, EventClass);
        break;

    case exceptionTypeKmUm:
        IntSerializeKernelUserException(Originator, Victim, EventClass);
        break;

    default:
        ERROR("[ERROR] Unsupported exception type (%d) ...", Type);
    }

    IntSerializeDump();
}
