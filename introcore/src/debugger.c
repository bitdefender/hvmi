/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "debugger.h"
#include "codeblocks.h"
#include "decoder.h"
#include "deployer.h"
#include "gpacache.h"
#include "hook.h"
#include "hook_cr.h"
#include "icache.h"
#include "introapi.h"
#include "kernvm.h"
#include "memcloak.h"
#include "ptfilter.h"
#include "swapmem.h"
#include "vasmonitor.h"
#include "vecore.h"
#include "visibility.h"
#include "winnet.h"
#include "winpe.h"
#include "winpfn.h"
#include "winprocesshp.h"
#include "lixksym.h"

BOOLEAN gFailAllocs = FALSE;
BOOLEAN gInsideDebugger = FALSE;

extern LIST_HEAD gWinProcesses;
extern BOOLEAN gLoadPtDriver;
extern BOOLEAN gUnloadPtDriver;
extern BOOLEAN gInjectVeLoader;
extern BOOLEAN gInjectVeUnloader;


typedef void (*PFUNC_DebuggerFunctionArgs)(
    _In_ DWORD Argc,
    _In_ const char *Argv[]
    );

typedef void (*PFUNC_DebuggerFunctionNoArgs)(
    void
    );


static INTSTATUS
DbgSwapCallback(
    _In_ void *Context,
    _In_ QWORD Cr3,
    _In_ QWORD VirtualAddress,
    _In_ QWORD PhysicalAddress,
    _In_reads_bytes_(DataSize) void *Data,
    _In_ DWORD DataSize,
    _In_ DWORD Flags
    )
{
    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(Data);

    LOG("[DEBUG] Swapped %d bytes from GLA 0x%016llx, GPA 0x%016llx, CR3 0x%016llx, flags %d\n",
        DataSize, VirtualAddress, PhysicalAddress, Cr3, Flags);

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
DbgVaModificationHandler(
    _In_ void *Context,
    _In_ QWORD VirtualAddress,
    _In_ QWORD OldEntry,
    _In_ QWORD NewEntry,
    _In_ QWORD OldPageSize,
    _In_ QWORD NewPageSize
    )
{
#if LOG_LEVEL == 0
    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(VirtualAddress);
    UNREFERENCED_PARAMETER(OldEntry);
    UNREFERENCED_PARAMETER(NewEntry);
    UNREFERENCED_PARAMETER(OldPageSize);
    UNREFERENCED_PARAMETER(NewPageSize);
#endif

    LOG("Modified GVA 0x%016llx, Context %p, from 0x%016llx to 0x%016llx, size 0x%016llx to 0x%016llx\n",
        VirtualAddress, Context, OldEntry, NewEntry, OldPageSize, NewPageSize);

    return INT_STATUS_SUCCESS;
}


static QWORD gTargetPML4;


static INTSTATUS
DbgVaSpaceIterationCallback(
    _In_ QWORD Cr3,
    _In_ QWORD VirtualAddress,
    _In_ QWORD Entry,
    _In_ QWORD PageSize
    )
{
    if ((Entry & PHYS_PAGE_MASK) == gTargetPML4)
    {
        LOG("[ITVA] CR3 0x%016llx, GVA 0x%016llx -> GPA 0x%016llx, size %llx ********\n",
            Cr3, VirtualAddress, Entry, PageSize);
    }

    return INT_STATUS_SUCCESS;
}


static QWORD gPagesRead, gPagesWrite, gPagesDirty;
static BYTE *gPagesBitmap = NULL;


static INTSTATUS
DbgVaSpaceIterationCallbackCount(
    _In_ QWORD Cr3,
    _In_ QWORD VirtualAddress,
    _In_ QWORD PhysicalAddress,
    _In_ QWORD PageSize
    )
{
    UNREFERENCED_PARAMETER(PageSize);
    UNREFERENCED_PARAMETER(Cr3);

    // Ignore physical pages that were already touched.
    if (_bittestandset64((INT64 *)gPagesBitmap, (PhysicalAddress & PHYS_PAGE_MASK) >> 12))
    {
        return INT_STATUS_SUCCESS;
    }

    if (Cr3 == gGuest.Mm.SystemCr3)
    {
        // Kernel space.
        if (VirtualAddress >= 0xFFFF800000000000)
        {
            if (PhysicalAddress & PT_RW)
            {
                gPagesWrite++;
            }
            else
            {
                gPagesRead++;
            }

            if (PhysicalAddress & PT_D)
            {
                gPagesDirty++;
            }
        }
    }
    else
    {
        // User space.
        if (VirtualAddress < 0xFFFF800000000000)
        {
            if (PhysicalAddress & PT_RW)
            {
                gPagesWrite++;
            }
            else
            {
                gPagesRead++;
            }

            if (PhysicalAddress & PT_D)
            {
                gPagesDirty++;
            }
        }
    }

    return INT_STATUS_SUCCESS;
}


static void
IntDbgCheckHooks(
    void
    )
{
    INTSTATUS status;
    DWORD i, j;
    BYTE r, w, x;
    LIST_ENTRY *list, *table;

    if (NULL == gHooks)
    {
        return;
    }

    for (j = 0; j < 3; j++)
    {
        if (0 == j)
        {
            table = gHooks->GpaHooks.GpaHooksRead;
        }
        else if (1 == j)
        {
            table = gHooks->GpaHooks.GpaHooksWrite;
        }
        else
        {
            table = gHooks->GpaHooks.GpaHooksExecute;
        }

        for (i = 0; i < GPA_HOOK_TABLE_SIZE; i++)
        {
            list = table[i].Flink;

            while (list != &table[i])
            {
                PHOOK_GPA pHook = CONTAINING_RECORD(list, HOOK_GPA, Link);

                list = list->Flink;

                status = IntGetEPTPageProtection(gGuest.UntrustedEptIndex, pHook->GpaPage, &r, &w, &x);
                if (!INT_SUCCESS(status))
                {
                    ERROR("[ERROR] IntGetEPTPageProtection failed: 0x%08x\n", status);
                }

                if ((pHook->Header.EptHookType == IG_EPT_HOOK_READ) && (1 == r))
                {
                    ERROR("[ERROR] Invalid {read} internal state: hook %p\n", pHook);
                }

                if ((pHook->Header.EptHookType == IG_EPT_HOOK_WRITE) && (1 == w))
                {
                    ERROR("[ERROR] Invalid {write} internal state: hook %p\n", pHook);
                }

                if ((pHook->Header.EptHookType == IG_EPT_HOOK_EXECUTE) && (1 == x))
                {
                    ERROR("[ERROR] Invalid {execute} internal state: hook %p\n", pHook);
                }
            }
        }
    }
}



static void
DbgDumpKmException(
    _In_ KM_EXCEPTION *Exception
    )
{
    LOG("%p : OriginatorName: %08x, Victim: %08x, Flg: %08x, Type: %02d, Sig: %d\n",
        Exception, Exception->OriginatorNameHash,
        Exception->VictimNameHash, Exception->Flags, Exception->Type, Exception->SigCount);

    if (Exception->SigCount > 0)
    {
        char siglist[256];
        char *l = siglist;
        int ret, rem = sizeof(siglist);

        ret = snprintf(l, rem, "--> Signatures:");
        if (ret < 0 || ret >= rem)
        {
            ERROR("[ERROR] snprintf error: %d, size %d\n", ret, rem);
            return;
        }
        else
        {
            rem -= ret;
            l += ret;
        }

        for (DWORD i = 0; i < Exception->SigCount; i++)
        {
            ret = snprintf(l, rem, " 0x%04x", Exception->Signatures[i].Value);
            if (ret < 0 || ret >= rem)
            {
                ERROR("[ERROR] snprintf error: %d, size %d\n", ret, rem);
                break;
            }
            else
            {
                rem -= ret;
                l += ret;
            }
        }

        LOG("%s\n", siglist);
    }
}


static void
DbgDumpUmException(
    _In_ UM_EXCEPTION *Exception
    )
{
    LOG("%p : Originator: %08x, Victim: %08x, Process: %08x, Flg: %08x, Type: %02d, Sig: %d\n",
        Exception, Exception->OriginatorNameHash, Exception->Victim.NameHash,
        Exception->Victim.ProcessHash, Exception->Flags, Exception->Type, Exception->SigCount);

    if (Exception->SigCount > 0)
    {
        char siglist[256];
        char *l = siglist;
        int ret, rem = sizeof(siglist);

        ret = snprintf(l, rem, "--> Signatures:");
        if (ret < 0 || ret >= rem)
        {
            ERROR("[ERROR] snprintf error: %d, size %d\n", ret, rem);
            return;
        }
        else
        {
            rem -= ret;
            l += ret;
        }

        for (DWORD i = 0; i < Exception->SigCount; i++)
        {
            ret = snprintf(l, rem, " 0x%04x", Exception->Signatures[i].Value);
            if (ret < 0 || ret >= rem)
            {
                ERROR("[ERROR] snprintf error: %d, size %d\n", ret, rem);
                break;
            }
            else
            {
                rem -= ret;
                l += ret;
            }
        }

        LOG("%s\n", siglist);
    }

}


static void
DbgDumpUmExceptionGlobMatch(
    _In_ UM_EXCEPTION_GLOB *Exception
    )
{
    LOG("%p : Originator: %s, Victim: %s, Process: %s, Flg: %08x, Type: %02d, Sig: %d\n",
        Exception, Exception->OriginatorNameGlob, Exception->Victim.NameGlob,
        Exception->Victim.ProcessGlob, Exception->Flags, Exception->Type, Exception->SigCount);

    if (Exception->SigCount > 0)
    {
        char siglist[256];
        char *l = siglist;
        int ret, rem = sizeof(siglist);

        ret = snprintf(l, rem, "--> Signatures:");
        if (ret < 0 || ret >= rem)
        {
            ERROR("[ERROR] snprintf error: %d, size %d\n", ret, rem);
            return;
        }
        else
        {
            rem -= ret;
            l += ret;
        }

        for (DWORD i = 0; i < Exception->SigCount; i++)
        {
            ret = snprintf(l, rem, " 0x%4x", Exception->Signatures[i].Value);
            if (ret < 0 || ret >= rem)
            {
                ERROR("[ERROR] snprintf error: %d, size %d\n", ret, rem);
                break;
            }
            else
            {
                rem -= ret;
                l += ret;
            }
        }

        LOG("%s\n", siglist);
    }

}


static INTSTATUS
DbgCrWriteTestCallback(
    _In_opt_ void *Context,
    _In_ DWORD Cr,
    _In_ QWORD OldValue,
    _In_ QWORD NewValue,
    _Out_ INTRO_ACTION *Action
    )
{
    UNREFERENCED_PARAMETER(Context);
#if LOG_LEVEL == 0
    UNREFERENCED_PARAMETER(NewValue);
    UNREFERENCED_PARAMETER(OldValue);
    UNREFERENCED_PARAMETER(Cr);
#endif

    LOG("[CPU %d] Written CR%d from 0x0x%016llx to 0x0x%016llx\n", gVcpu->Index, Cr, OldValue, NewValue);

    *Action = introGuestAllowed;

    return INT_STATUS_SUCCESS;
}


#ifdef DEBUG_MEM_ALLOCS

typedef struct _DBG_ALLOCATION
{
    LIST_ENTRY      Link;
    RBNODE          RbNode;
    void            *Address;
    DWORD           Size;
    DWORD           Tag;
    const char      *File;
    DWORD           Line;
} DBG_ALLOCATION, *PDBG_ALLOCATION;


_Function_class_(FUNC_RbTreeNodeFree) static void
IntDbgFreeAllocNode(
    _Inout_ RBNODE *Node
    )
{
    UNREFERENCED_PARAMETER(Node);
}


_Function_class_(FUNC_RbTreeNodeCompare) static int
IntDbgCompareAllocNode(
    _In_ RBNODE *Left,
    _In_ RBNODE *Right
    )
{
    DBG_ALLOCATION *p1 = CONTAINING_RECORD(Left, DBG_ALLOCATION, RbNode);
    DBG_ALLOCATION *p2 = CONTAINING_RECORD(Right, DBG_ALLOCATION, RbNode);
    size_t a1, a2;

    a1 = (size_t)p1->Address;
    a2 = (size_t)p2->Address;

    if (a1 < a2)
    {
        return -1;
    }
    else if (a1 > a2)
    {
        return 1;
    }
    else
    {
        return 0;
    }
}


static size_t gTotalMemUsed = 0;
static size_t gTotalAllocations = 0;
static size_t gTotalFrees = 0;

static size_t gMaxMemUsed = 0;
static size_t gMaxAllocations = 0;

static RBTREE gAllocTree = RB_TREE_INIT(gAllocTree, IntDbgFreeAllocNode, IntDbgCompareAllocNode);
static LIST_HEAD gAllocations = LIST_HEAD_INIT(gAllocations);


__attribute__((malloc))
__attribute__ ((alloc_size (1)))
__must_check void *
IntDbgAllocMem(
    _In_ size_t Size,
    _In_ DWORD Tag,
    _In_ const char *FileName,
    _In_ DWORD Line
    )
{
    DBG_ALLOCATION *pAlloc;
    void *addr = NULL;

    addr = IntAllocWithTag(Size, Tag, FileName, Line);
    if (NULL == addr)
    {
        return NULL;
    }

    pAlloc = IntAllocWithTag(sizeof(*pAlloc), IC_TAG_ALLOC, FileName, Line);
    if (NULL == pAlloc)
    {
        IntFreeWithTag(&addr, Tag, __LINE__);
        return NULL;
    }

    pAlloc->Address = addr;
    pAlloc->Size = Size;
    pAlloc->Tag = Tag;
    pAlloc->File = FileName;
    pAlloc->Line = Line;

    InsertTailList(&gAllocations, &pAlloc->Link);
    RbInsertNode(&gAllocTree, &pAlloc->RbNode);

    gTotalAllocations++;
    gTotalMemUsed += Size;

    if (gTotalMemUsed > gMaxMemUsed)
    {
        gMaxMemUsed = gTotalMemUsed;
    }

    if (gTotalAllocations > gMaxAllocations)
    {
        gMaxAllocations = gTotalAllocations;
    }

    return addr;
}


INTSTATUS
IntDbgFreeMem(
    _Inout_ _At_(*Address, _Post_null_) void **Address,
    _In_ DWORD Tag,
    _In_ DWORD Line
    )
{
    DBG_ALLOCATION target;
    RBNODE *result;

    target.Address = *Address;
    gTotalFrees++;

    INTSTATUS status = RbLookupNode(&gAllocTree, &target.RbNode, &result);
    if (INT_SUCCESS(status) && result)
    {
        DBG_ALLOCATION *pAlloc = CONTAINING_RECORD(result, DBG_ALLOCATION, RbNode);

        if (Tag != pAlloc->Tag)
        {
            ERROR("[ERROR] Tag different from what was requested: %08x != %08x for allocation from %s:%d\n",
                  pAlloc->Tag, Tag, pAlloc->File, pAlloc->Line);
        }

        gTotalMemUsed -= pAlloc->Size;

        RemoveEntryList(&pAlloc->Link);
        RbDeleteNode(&gAllocTree, &pAlloc->RbNode);

        gUpIface.MemFreeWithTagAndInfo(Address, IC_TAG_ALLOC, __FILE_TAG__, Line);
    }
    else
    {
        ERROR("[CRITICAL] Trying to free an invalid address: %p\n", *Address);
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntDbgDumpAllocs(
    _In_opt_ DWORD Tag
    )
{
    LIST_ENTRY *list;

    QWORD size = 0;
    QWORD total = 0;

    list = gAllocations.Flink;
    while (list != &gAllocations)
    {
        DBG_ALLOCATION *pAlloc = CONTAINING_RECORD(list, DBG_ALLOCATION, Link);
        list = list->Flink;

        if (0 == Tag || Tag == pAlloc->Tag)
        {
            LOG("Alloc: %p:%6d, tag %08x (%c%c%c%c), from %s:%d\n",
                pAlloc->Address,
                pAlloc->Size,
                pAlloc->Tag,
                (pAlloc->Tag & 0xFF),
                (pAlloc->Tag >>  8) & 0xFF,
                (pAlloc->Tag >> 16) & 0xFF,
                (pAlloc->Tag >> 24) & 0xFF,
                pAlloc->File,
                pAlloc->Line);

            total++;
            size += pAlloc->Size;
        }
    }

    LOG("%lld allocations with %lld bytes\n", total, size);
    LOG("Total memory allocated: %lld bytes\n", gTotalMemUsed);

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntDbgCheckAllocs(
    void
    )
{
    LIST_ENTRY *list;

    list = gAllocations.Flink;
    while (list != &gAllocations)
    {
        DBG_ALLOCATION *pAlloc = CONTAINING_RECORD(list, DBG_ALLOCATION, Link);
        BYTE *pp = (BYTE *)pAlloc->Address - 8;

        if (*((QWORD *)pp) != 0xBDBDBDBDBDBDBDBD)
        {
            LOG("Buffer underflow for alloc at %p (struct: %p)!\n", pAlloc->Address, pAlloc);
        }

        if (*((QWORD *)(pp + 8 + pAlloc->Size)) != 0xBDBDBDBDBDBDBDBD)
        {
            LOG("Buffer overflow for alloc at %p (struct: %p)!\n", pAlloc->Address, pAlloc);
        }

        list = list->Flink;
    }

    LOG("Total memory allocated: %lld bytes\n", gTotalMemUsed);

    return INT_STATUS_SUCCESS;
}

#endif



static void
DbgShowHelp(
    void
    );


static void
DbgDumpGuestModules(
    void
    )
{
    INTSTATUS status;
    QWORD currentModule;
    DWORD count = 0;

    currentModule = gWinGuest->PsLoadedModuleList;
    if (currentModule == 0)
    {
        LOG("gWinGuest->PsLoadedModuleList is 0\n");
        return;
    }

    if (gGuest.Guest64)
    {
        status = IntKernVirtMemFetchQword(currentModule, &currentModule);
    }
    else
    {
        status = IntKernVirtMemFetchDword(currentModule, (DWORD *) &currentModule);
        currentModule &= 0xFFFFFFFF;
    }
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Failed getting the Flink value of MODULE at 0x%016llx: 0x%08x\n", currentModule, status);
        return;
    }

    while (currentModule != gWinGuest->PsLoadedModuleList)
    {
        LDR_DATA_TABLE_ENTRY32 *pModEntry32 = NULL;
        LDR_DATA_TABLE_ENTRY64 *pModEntry64 = NULL;
        WCHAR moduleName[MAX_PATH] = {0};
        DWORD nameLength, sizeOfImage;
        QWORD nameAddress, moduleBase;

        if (gGuest.Guest64)
        {
            status = IntVirtMemMap(currentModule, sizeof(*pModEntry64), 0, 0, &pModEntry64);
        }
        else
        {
            status = IntVirtMemMap(currentModule, sizeof(*pModEntry32), 0, 0, &pModEntry32);
        }
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] Failed to map the modules info at 0x%016llx: 0x%08x\n", currentModule, status);
            break;
        }

        if (gGuest.Guest64)
        {
            nameLength = 0xFFFF & pModEntry64->DriverPath.Length;
            nameAddress = pModEntry64->DriverPath.Buffer;
            moduleBase = pModEntry64->DllBase;
            sizeOfImage = 0xffffffff & pModEntry64->SizeOfImage;
        }
        else
        {
            nameLength = 0xFFFF & pModEntry32->DriverPath.Length;
            nameAddress = FIX_GUEST_POINTER(FALSE, pModEntry32->DriverPath.Buffer);
            moduleBase = 0xffffffff & pModEntry32->DllBase;
            sizeOfImage = pModEntry32->SizeOfImage;
        }

        if (nameLength > MAX_PATH)
        {
            nameLength = MAX_PATH;
        }

        // Copy the name into the given buffer. Safe, nameLength is truncated to MAX_PATH.
        status = IntKernVirtMemRead(nameAddress, nameLength, moduleName, NULL);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] Failed reading module's path from VA 0x%016llx with length %x: 0x%08x\n",
                  nameAddress, nameLength, status);
            goto _next;
        }

        moduleName[nameLength / 2] = 0;

        LOG("  #%03d Base: 0x%016llx, SizeOfImage: 0x%08x, Path: %s\n",
            count++, moduleBase, sizeOfImage, utf16_for_log(moduleName));

_next:
        if (gGuest.Guest64)
        {
            currentModule = pModEntry64->InLoadOrderLinks.Flink;
            IntVirtMemUnmap(&pModEntry64);
        }
        else
        {
            currentModule = pModEntry32->InLoadOrderLinks.Flink;
            currentModule &= 0xFFFFFFFF;
            IntVirtMemUnmap(&pModEntry32);
        }
    }
}


static void
DbgInjectPf(
    _In_ DWORD Argc,
    _In_ const char *Argv[]
    )
{
    INTSTATUS status;
    QWORD address;
    DWORD write;

    if (Argc < 3)
    {
        ERROR("[ERROR] Invalid number of arguments!");
        return;
    }

    address = strtoull(Argv[1], NULL, 0);
    write = (DWORD)strtoull(Argv[3], NULL, 0);

    status = IntInjectExceptionInGuest(VECTOR_PF, address, write != 0, 0);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntInjectExceptionInGuest failed: 0x%08x\n", status);
    }
}


static void
DbgDumpPfn(
    _In_ DWORD Argc,
    _In_ const char *Argv[]
    )
{
    QWORD address, gpa, pfnAddress;
    DWORD pfnSize;
    PBYTE pfnBuffer;
    INTSTATUS status;
    WORD refCount, flags;

    if (gWinGuest->MmPfnDatabase == 0)
    {
        ERROR("[ERROR] MmPfnDatabase is 0\n");
        return;
    }

    if (Argc < 3)
    {
        ERROR("[ERROR] Invalid number of arguments!\n");
        return;
    }

    address = strtoull(Argv[2], NULL, 0);
    if (0 == address)
    {
        ERROR("[ERROR] %s is not a valid address\n", Argv[2]);
        return;
    }

    if (Argv[1][0] == 'v')
    {
        status = IntTranslateVirtualAddress(address, gGuest.Mm.SystemCr3, &gpa);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] GVA 0x%016llx to GPA failed: 0x%08x\n", address, status);
            return;
        }
    }
    else if (Argv[1][0] == 'p')
    {
        gpa = address;
    }
    else
    {
        ERROR("[ERROR] Give `v` or `p` for the address type\n");
        return;
    }

    pfnAddress = WIN_PFN_GET_STRUCT_VA(gWinGuest->MmPfnDatabase, gpa);
    if (gGuest.Guest64 || !gGuest.PaeEnabled)
    {
        pfnSize = WIN_KM_FIELD(Mmpfn, Size);
    }
    else
    {
        pfnSize = WIN_KM_FIELD(Mmpfn, PaeSize);
    }

    status = IntVirtMemMap(pfnAddress, pfnSize, 0, 0, &pfnBuffer);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Failed mapping PFN structure from 0x%016llx: 0x%08x\n", pfnAddress, status);
        return;
    }

    LOG("PFN %llx at 0x%016llx for GPA 0x%016llx\n", gpa >> 12, pfnAddress, gpa);

    if (gGuest.Guest64)
    {
        LOG("PteAddress: 0x%016llx\n", *(QWORD *)(pfnBuffer + WIN_KM_FIELD(Mmpfn, Pte)));
    }
    else if (gGuest.PaeEnabled)
    {
        LOG("PteAddress: 0x%08x\n", *(DWORD *)(pfnBuffer + WIN_KM_FIELD(Mmpfn, PaePte)));
    }
    else
    {
        LOG("PteAddress: 0x%08x\n", *(DWORD *)(pfnBuffer + WIN_KM_FIELD(Mmpfn, Pte)));
    }

    if (gGuest.Guest64 || !gGuest.PaeEnabled)
    {
        refCount = *(WORD *)(pfnBuffer + WIN_KM_FIELD(Mmpfn, RefCount));
        flags = *(WORD *)(pfnBuffer + WIN_KM_FIELD(Mmpfn, Flags));
    }
    else
    {
        refCount = *(WORD *)(pfnBuffer + WIN_KM_FIELD(Mmpfn, PaeRefCount));
        flags = *(WORD *)(pfnBuffer + WIN_KM_FIELD(Mmpfn, PaeFlags));
    }

    LOG("RefCount: %x\t\tFlags: %x\n", refCount, flags);

    IntVirtMemUnmap(&pfnBuffer);
}


static void
DbgDumpCodeblocks(
    _In_ DWORD Argc,
    _In_ const char *Argv[]
    )
{
    QWORD addressStart, rip;
    DWORD length, level;
    PBYTE code;
    INTSTATUS status;

    if (Argc < 2)
    {
        ERROR("[ERROR] Minimum number of arguments expected: 2\n");
        return;
    }

    addressStart = strtoull(Argv[1], NULL, 0);
    if (0 == addressStart)
    {
        WARNING("[WARNING] %s is not a valid address\n", Argv[1]);
        return;
    }

    if (Argc > 2)
    {
        length = strtoul(Argv[2], NULL, 0);
        if (0 == length)
        {
            WARNING("[WARNING] %s is not a valid length\n", Argv[2]);
            return;
        }
    }
    else
    {
        // By default we go to the end of the page
        length = PAGE_REMAINING(addressStart);
    }

    if (Argc > 3)
    {
        rip = strtoul(Argv[3], NULL, 0);
        if (0 == rip)
        {
            WARNING("[WARNING] %s is not a valid rip\n", Argv[3]);
            return;
        }
    }
    else
    {
        rip = addressStart;
    }

    if (Argc > 4)
    {
        level = strtoul(Argv[4], NULL, 0);
        if (1 != level && 2 != level)
        {
            WARNING("[WARNING] %s is not a valid level\n", Argv[4]);
            return;
        }
    }
    else
    {
        level = cbLevelNormal;
    }

    code = HpAllocWithTag(length, IC_TAG_CDBK);
    if (NULL == code)
    {
        return;
    }

    status = IntKernVirtMemRead(addressStart, length, code, NULL);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Failed reading from GVA 0x%016llx: 0x%08x\n", addressStart, length);
        goto _clean_leave;
    }

    LOG("[CODEBLOCKS] Dumping codeblocks for RIP 0x%016llx (from 0x%016llx to 0x%016llx)\n",
        rip, addressStart, addressStart + length);

    status = IntFragDumpBlocks(code,
                               addressStart,
                               length,
                               gGuest.Guest64 ? IG_CS_TYPE_64B : IG_CS_TYPE_32B,
                               (BYTE)level,
                               rip,
                               FALSE);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Failed extracting blocks from VA 0x%016llx: 0x%08x\n", addressStart, status);
    }

_clean_leave:
    HpFreeAndNullWithTag(&code, IC_TAG_CDBK);
}


static void
DbgDumpExceptions(
    void
    )
{
    DWORD i, id;
    LIST_ENTRY *list;
    PEXCEPTIONS pExceptions;
    DWORD totalKernel;
    DWORD totalUser;

    pExceptions = gGuest.Exceptions;
    if (NULL == pExceptions)
    {
        LOG("[DBGINTRO] There are no exceptions loaded!\n");
        return;
    }

    totalKernel = 0;

    LOG("[DBGINTRO] Kernel exceptions:\n");

    list = pExceptions->NoNameKernelExceptions.Flink;
    while (list != &pExceptions->NoNameKernelExceptions)
    {
        KM_EXCEPTION *pException = CONTAINING_RECORD(list, KM_EXCEPTION, Link);
        list = list->Flink;

        DbgDumpKmException(pException);

        totalKernel++;
    }

    list = pExceptions->GenericKernelExceptions.Flink;
    while (list != &pExceptions->GenericKernelExceptions)
    {
        KM_EXCEPTION *pException = CONTAINING_RECORD(list, KM_EXCEPTION, Link);
        list = list->Flink;

        DbgDumpKmException(pException);

        totalKernel++;
    }

    for (id = 0; id < EXCEPTION_TABLE_SIZE; id++)
    {
        list = pExceptions->KernelExceptions[id].Flink;
        while (list != &pExceptions->KernelExceptions[id])
        {
            KM_EXCEPTION *pException = CONTAINING_RECORD(list, KM_EXCEPTION, Link);
            list = list->Flink;

            DbgDumpKmException(pException);

            totalKernel++;
        }
    }

    LOG("[DBGINTRO] User exceptions:\n");

    totalUser = 0;
    list = pExceptions->GenericUserExceptions.Flink;
    while (list != &pExceptions->GenericUserExceptions)
    {
        UM_EXCEPTION *pException = CONTAINING_RECORD(list, UM_EXCEPTION, Link);
        list = list->Flink;

        DbgDumpUmException(pException);

        totalUser++;
    }

    totalUser = 0;
    list = pExceptions->NoNameUserExceptions.Flink;
    while (list != &pExceptions->NoNameUserExceptions)
    {
        UM_EXCEPTION *pException = CONTAINING_RECORD(list, UM_EXCEPTION, Link);
        list = list->Flink;

        DbgDumpUmException(pException);

        totalUser++;
    }

    totalUser = 0;
    list = pExceptions->GlobUserExceptions.Flink;
    while (list != &pExceptions->GlobUserExceptions)
    {
        UM_EXCEPTION_GLOB *pException = CONTAINING_RECORD(list, UM_EXCEPTION_GLOB, Link);
        list = list->Flink;

        DbgDumpUmExceptionGlobMatch(pException);

        totalUser++;

    }

    // 4. User exceptions (per table)
    for (id = 0; id < EXCEPTION_TABLE_SIZE; id++)
    {
        list = pExceptions->UserExceptions[id].Flink;
        while (list != &pExceptions->UserExceptions[id])
        {
            UM_EXCEPTION *pException = CONTAINING_RECORD(list, UM_EXCEPTION, Link);
            list = list->Flink;

            DbgDumpUmException(pException);

            totalUser++;
        }
    }

    LOG("[DBGINTRO] Codeblocks signatures:\n");
    list = pExceptions->CbSignatures.Flink;
    while (list != &pExceptions->CbSignatures)
    {
        SIG_CODEBLOCKS *pSignature = CONTAINING_RECORD(list, SIG_CODEBLOCKS, Link);
        SIG_CODEBLOCK_HASH *pSigHash;
        list = list->Flink;

        LOG("%p : Id: %04x, Flags: %08x, Score: %02d, Lists: %02d\n",
            pSignature, pSignature->Id.Value, pSignature->Flags, pSignature->Score, pSignature->ListsCount);

        pSigHash = (SIG_CODEBLOCK_HASH *)pSignature->Object;
        for (i = 0; i < pSignature->ListsCount; i++)
        {
            DWORD hashSize = sizeof(SIG_CODEBLOCK_HASH) + pSigHash->Count * sizeof(DWORD);

            char hashes[256];
            char *l = hashes;
            int ret, rem = sizeof(hashes);

            ret = snprintf(l, rem, "--> List(%u):", pSigHash->Count);
            if (ret < 0 || ret >= rem)
            {
                ERROR("[ERROR] snprintf error: %d, size %d\n", ret, rem);
                return;
            }
            else
            {
                rem -= ret;
                l += ret;
            }

            for (DWORD j = 0; j < pSigHash->Count; j++)
            {
                ret = snprintf(l, rem, " %08x", pSigHash->Hashes[j]);
                if (ret < 0 || ret >= rem)
                {
                    ERROR("[ERROR] snprintf error: %d, size %d\n", ret, rem);
                    break;
                }
                else
                {
                    rem -= ret;
                    l += ret;
                }
            }

            LOG("%s\n", hashes);

            // advance to the next hash list
            pSigHash = (SIG_CODEBLOCK_HASH *)((BYTE *)pSigHash + hashSize);
        }
    }

    LOG("[DBGINTRO] Export signatures:\n");
    list = pExceptions->ExportSignatures.Flink;
    while (list != &pExceptions->ExportSignatures)
    {
        SIG_EXPORT *pSignature = CONTAINING_RECORD(list, SIG_EXPORT, Link);
        SIG_EXPORT_HASH *pSigHash;
        list = list->Flink;

        LOG("%p : Id: %04x, Flags: %08x, Library: %08x, Lists: %02d\n",
            pSignature, pSignature->Id.Value, pSignature->Flags, pSignature->LibraryNameHash, pSignature->ListsCount);

        pSigHash = (SIG_EXPORT_HASH *)pSignature->Object;
        for (DWORD j = 0; j < pSignature->ListsCount; j++)
        {
            LOG("--> List(%d): Delta: %02x, Hash: %08x\n", j, pSigHash[j].Delta, pSigHash[j].Hash);
        }
    }

    LOG("[DBGINTRO] Value signatures:\n");
    list = pExceptions->ValueSignatures.Flink;
    while (list != &pExceptions->ValueSignatures)
    {
        SIG_VALUE *pSignature = CONTAINING_RECORD(list, SIG_VALUE, Link);
        SIG_VALUE_HASH *pSigHash;
        list = list->Flink;

        LOG("%p : Id: %04x, Flags: %08x, Score: %02d, Lists: %02d\n",
            pSignature, pSignature->Id.Value, pSignature->Flags, pSignature->Score, pSignature->ListsCount);

        pSigHash = (SIG_VALUE_HASH *)pSignature->Object;
        for (DWORD j = 0; j < pSignature->ListsCount; j++)
        {
            LOG("--> List(%d): Offset: %02x, Size: %02x, Hash: %08x\n",
                j, pSigHash[j].Offset, pSigHash[j].Size, pSigHash[j].Hash);
        }
    }

    LOG("[DBGINTRO] Idt signatures:\n");
    list = pExceptions->IdtSignatures.Flink;
    while (list != &pExceptions->IdtSignatures)
    {
        PSIG_IDT pSignature = CONTAINING_RECORD(list, SIG_IDT, Link);
        list = list->Flink;

        LOG("%p : Id: %04x, Flags: %08x, Entry: %0d \n",
            pSignature, pSignature->Id.Value, pSignature->Flags, pSignature->Entry);
    }

    LOG("[DBGINTRO] Value code signatures:\n");
    list = pExceptions->ValueCodeSignatures.Flink;
    while (list != &pExceptions->ValueCodeSignatures)
    {
        PSIG_VALUE_CODE pSignature = CONTAINING_RECORD(list, SIG_VALUE_CODE, Link);
        PWORD pPattern;
        list = list->Flink;

        LOG("%p : Id: %04x, Flags: %08x, Offset: %02d, Length: %02d\n",
            pSignature, pSignature->Id.Value, pSignature->Flags, pSignature->Offset, pSignature->Length);

        pPattern = (PWORD)pSignature->Object;
        for (DWORD j = 0; j < pSignature->Length; j++)
        {
            LOG("--> Item(%d): %02x\n", j, pPattern[j]);
        }
    }

    LOG("[DBGINTRO] Version OS signatures:\n");
    list = pExceptions->VersionOsSignatures.Flink;
    while (list != &pExceptions->VersionOsSignatures)
    {
        SIG_VERSION_OS *pSignature = CONTAINING_RECORD(list, SIG_VERSION_OS, Link);
        list = list->Flink;

        LOG("%p : Id: %04x, Flags: %08x, Minimum: 0x%llx, Maximum: 0x%llx\n",
            pSignature, pSignature->Id.Value, pSignature->Flags, pSignature->Minimum.Value, pSignature->Maximum.Value);
    }

    LOG("[DBGINTRO] Version Introcore signatures:\n");
    list = pExceptions->VersionIntroSignatures.Flink;
    while (list != &pExceptions->VersionIntroSignatures)
    {
        SIG_VERSION_INTRO *pSignature = CONTAINING_RECORD(list, SIG_VERSION_INTRO, Link);
        list = list->Flink;

        LOG("%p : Id: %04x, Flags: %08x, Minimum: %d.%d.%d, Maximum: %d.%d.%d\n",
            pSignature, pSignature->Id.Value, pSignature->Flags,
            pSignature->Minimum.Major, pSignature->Minimum.Minor, pSignature->Minimum.Revision,
            pSignature->Maximum.Major, pSignature->Maximum.Minor, pSignature->Maximum.Revision);
    }

    LOG("[DBGINTRO] Process creation signatures:\n");
    list = pExceptions->ProcessCreationSignatures.Flink;
    while (list != &pExceptions->ProcessCreationSignatures)
    {
        SIG_PROCESS_CREATION *pSignature = CONTAINING_RECORD(list, SIG_PROCESS_CREATION, Link);
        list = list->Flink;

        LOG("%p : Id: %04x, Flags: %08x, Create-Mask: 0x%08x\n",
            pSignature, pSignature->Id.Value, pSignature->Flags, pSignature->CreateMask);
    }
}


static void
DbgDumpHooksGva(
    void
    )
{
    DWORD count;
    LIST_ENTRY *list;

    if (NULL == gHooks)
    {
        return;
    }

    LOG("GVA hooks:\n");

    count = 0;

    list = &gHooks->GvaHooks.GvaHooks;
    while (list != &gHooks->GvaHooks.GvaHooks)
    {
        HOOK_GVA *pHook = CONTAINING_RECORD(list, HOOK_GVA, Link);

        LOG("%04d: GVA: 0x%016llx, Offset: %04x, Length: %04x, Flags: %08x, "
            "Type: %d, integrity: %s, writable: %s, GPA hook: %p\n",
            count++,
            pHook->GvaPage, pHook->Offset, pHook->Length, pHook->Header.Flags, pHook->Header.EptHookType,
            pHook->IsIntegrityOn ? "yes" : "no",
            pHook->IsPageWritable ? "yes" : "no", pHook->GpaHook);

        list = list->Flink;
    }


    list = gHooks->GvaHooks.RemovedHooksList.Flink;

    LOG("Removed hooks queue:\n");

    while (list != &gHooks->GvaHooks.RemovedHooksList)
    {
        HOOK_GVA *pHook = CONTAINING_RECORD(list, HOOK_GVA, Link);

        LOG("%04d: GVA: 0x%016llx, Offset: %04x, Length: %04x, Flags: %08x, Type: %d, GPA hook: %p\n",
            count++,
            pHook->GvaPage, pHook->Offset, pHook->Length, pHook->Header.Flags, pHook->Header.EptHookType,
            pHook->GpaHook);

        list = list->Flink;
    }
}


static void
DbgDumpProcesses(
    void
    )
{
    if (gGuest.OSType == introGuestWindows)
    {
        IntWinProcDump();
    }
    else if (gGuest.OSType == introGuestLinux)
    {
        IntLixTaskDump();
    }
}


static void
DbgProcAdd(
    _In_ DWORD Argc,
    _In_ const char *Argv[]
    )
{
    CHAR fullPath[MAX_PATH];

    if (Argc < 3)
    {
        ERROR("[ERROR] Invalid number of arguments!\n");
        return;
    }

    if (Argc > 3 || Argv[1][0] == '\'' || Argv[1][0] == '\"')
    {
        DWORD arg;
        size_t last = 0;

        memset(fullPath, 0, sizeof(fullPath));

        for (arg = 1; arg < Argc - 1; arg++)
        {
            size_t len = strlen(Argv[arg]);

            if (arg == 1)
            {
                // Starts with ' or " (probably surrounded by it)
                if (Argv[arg][0] == '\"' || Argv[arg][0] == '\'')
                {
                    // Skip the ' or "
                    strlcpy(&fullPath[last], &Argv[arg][1], sizeof(fullPath) - last);
                    len--;
                }
                else
                {
                    strlcpy(&fullPath[last], Argv[arg], sizeof(fullPath) - last);
                }
            }
            else
            {
                strlcpy(&fullPath[last], Argv[arg], sizeof(fullPath) - last);
            }

            last += len;

            if (arg < Argc - 2)
            {
                fullPath[last] = ' ';
                last++;
            }
            else // the last one
            {
                // Ends with ' or " (probably surrounded by it)
                if (fullPath[last - 1] == '\"' || fullPath[last - 1] == '\'')
                {
                    // Delete the ' or "
                    fullPath[last - 1] = 0;
                }
            }
        }

        IntAddRemoveProtectedProcessUtf8(gIntHandle, fullPath, strtoul(Argv[Argc - 1], 0, 0), TRUE, 0);
    }
    else
    {
        IntAddRemoveProtectedProcessUtf8(gIntHandle, Argv[1], strtoul(Argv[2], 0, 0), TRUE, 0);
    }

}


static void
DbgProcRem(
    _In_ DWORD Argc,
    _In_ const char *Argv[]
    )
{
    CHAR fullPath[MAX_PATH];

    if (Argc < 2)
    {
        ERROR("[ERROR] Invalid number of arguments!\n");
        return;
    }

    if (Argc > 2 || Argv[1][0] == '\'' || Argv[1][0] == '\"')
    {
        DWORD arg;
        size_t last = 0;

        memset(fullPath, 0, sizeof(fullPath));

        for (arg = 1; arg < Argc; arg++)
        {
            size_t len = strlen(Argv[arg]);

            if (arg == 1)
            {
                // Starts with ' or " (probably surrounded by it)
                if (Argv[arg][0] == '\"' || Argv[arg][0] == '\'')
                {
                    // Skip the ' or "
                    strlcpy(&fullPath[last], &Argv[arg][1], sizeof(fullPath) - last);
                    len--;
                }
                else
                {
                    strlcpy(&fullPath[last], Argv[arg], sizeof(fullPath) - last);
                }
            }
            else
            {
                strlcpy(&fullPath[last], Argv[arg], sizeof(fullPath) - last);
            }

            last += len;

            if (arg < Argc - 1)
            {
                fullPath[last] = ' ';
                last++;
            }
            else // the last one
            {
                // Ends with ' or " (probably surrounded by it)
                if (fullPath[last - 1] == '\"' || fullPath[last - 1] == '\'')
                {
                    // Delete the ' or "
                    fullPath[last - 1] = 0;
                }
            }
        }

        IntAddRemoveProtectedProcessUtf8(gIntHandle, fullPath, 0, FALSE, 0);
    }
    else
    {
        IntAddRemoveProtectedProcessUtf8(gIntHandle, Argv[1], 0, FALSE, 0);
    }
}


static void
DbgProcClear(
    void
    )
{
    IntRemoveAllProtectedProcesses(gIntHandle);
}


static void
DbgProcList(
    void
    )
{
    if (gGuest.OSType == introGuestWindows)
    {
        IntWinProcDumpProtected();
    }
    else if (gGuest.OSType == introGuestLinux)
    {
        IntLixTaskDumpProtected();
    }
}


static void
DbgDumpGpaCache(
    void
    )
{
    IntGpaCacheDump(gGuest.GpaCache);
}


static void
DbgDisasm(
    _In_ DWORD Argc,
    _In_ const char *Argv[]
    )
{
    QWORD address;
    DWORD size;

    if (Argc < 3)
    {
        ERROR("[ERROR] Invalid number of arguments!\n");
        return;
    }

    address = strtoull(Argv[1], NULL, 0);
    if (0 == address)
    {
        ERROR("[ERROR] %s is not a valid address\n", Argv[1]);
        return;
    }

    size = strtoul(Argv[2], NULL, 0);
    if (0 == size)
    {
        ERROR("[ERROR] %s is not a valid size\n", Argv[2]);
    }

    IntDisasmGva(address, size);
}


static void
DbgInjectAgent(
    _In_ DWORD Argc,
    _In_ const char *Argv[]
    )
{
    INTSTATUS status;
    DWORD tag;
    const char *name;

    if (Argc < 3)
    {
        ERROR("[ERROR] Invalid number of arguments!\n");
        return;
    }

    name = Argv[1];
    tag = strtoul(Argv[2], NULL, 0);

    status = IntDepInjectProcess(tag, NULL, 0, name, Argv[3]);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntDepInjectAgent failed: 0x%08x\n", status);
    }
}


static void
DbgInjectFileAgent(
    _In_ DWORD Argc,
    _In_ const char *Argv[]
    )
{
    INTSTATUS status;
    const char *name;
    CHAR *content = "abcdefghijklmnopqrstuvwxyz";

    if (Argc < 2)
    {
        ERROR("[ERROR] Invalid number of arguments!\n");
        return;
    }

    name = Argv[1];

    status = IntDepInjectFile((PBYTE)content, 27, name);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntDepInjectAgent failed: 0x%08x\n", status);
    }
}


static void
DbgSearchVaSpace(
    _In_ DWORD Argc,
    _In_ const char *Argv[]
    )
{
    QWORD cr3;

    if (Argc < 2)
    {
        ERROR("[ERROR] Invalid number of arguments!\n");
        return;
    }

    cr3 = strtoull(Argv[1], NULL, 0);
    gTargetPML4 = strtoull(Argv[2], NULL, 0);

    LOG("[DBGINTRO] Begin iterate VA space 0x%016llx, search for 0x%016llx!\n", cr3, gTargetPML4);

    IntIterateVirtualAddressSpace(cr3, DbgVaSpaceIterationCallback);

    LOG("[DBGINTRO] Done!\n");
}


static void
DbgIterateVaSpace(
    void
    )
{
    LIST_ENTRY *list;

    gPagesRead = gPagesWrite = gPagesDirty = 0;
    gTargetPML4 = 0;

    gPagesBitmap = HpAllocWithTag(ONE_MEGABYTE, IC_TAG_ALLOC);
    if (NULL == gPagesBitmap)
    {
        return;
    }

    list = gWinProcesses.Flink;
    while (list != &gWinProcesses)
    {
        PWIN_PROCESS_OBJECT pProc = CONTAINING_RECORD(list, WIN_PROCESS_OBJECT, Link);

        list = list->Flink;

        LOG("[DBGINTRO] Iterating VA space of process %s with CR3 %llx\n", pProc->Name, pProc->Cr3);

        IntIterateVirtualAddressSpace(pProc->Cr3, DbgVaSpaceIterationCallbackCount);
    }

    LOG("[DBGINTRO] %lld total present physical pages, %lld readable pages, %lld writable pages, %lld dirty pages\n",
        gPagesRead + gPagesWrite, gPagesRead, gPagesWrite, gPagesDirty);

    HpFreeAndNullWithTag(&gPagesBitmap, IC_TAG_ALLOC);
}


static void
DbgDumpTranslation(
    _In_ DWORD Argc,
    _In_ const char *Argv[]
    )
{
    QWORD gla = 0, cr3 = 0;
    INTSTATUS status = INT_STATUS_SUCCESS;
    VA_TRANSLATION tr = { 0 };

    if (Argc != 3)
    {
        ERROR("[ERROR] Invalid number of arguments!\n");
        return;
    }

    cr3 = strtoull(Argv[1], 0, 0);
    gla = strtoull(Argv[2], 0, 0);

    status = IntTranslateVirtualAddressEx(gla, cr3, TRFLG_NONE, &tr);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntTranslateVirtualAddressEx failed: 0x%08x\n", status);
    }
    else
    {
        LOG("%llx translated to %llx, %d levels, user: %d, write: %d, exec: %d\n",
            gla, tr.PhysicalAddress, tr.MappingsCount, tr.IsUser, tr.IsWritable, tr.IsExecutable);

        for (DWORD i = 0; i < tr.MappingsCount; i++)
        {
            LOG("    %d: %llx = %llx\n", i, tr.MappingsTrace[i], tr.MappingsEntries[i]);
        }
    }
}


static void
DbgPtsHook(
    _In_ DWORD Argc,
    _In_ const char *Argv[]
    )
{
    INTSTATUS status;
    PHOOK_PTS pPts;
    QWORD va;
    QWORD cr3;
    QWORD id;

    if (Argc != 4)
    {
        ERROR("[ERROR] Invalid number of arguments!\n");
        return;
    }

    cr3 = strtoull(Argv[1], NULL, 0);
    va  = strtoull(Argv[2], NULL, 0);
    id  = strtoull(Argv[3], NULL, 0);

    status = IntHookPtsSetHook(cr3, va, DbgVaModificationHandler, (void *)id, NULL, 0, &pPts);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntHookPtSetHook failed: 0x%08x\n", status);
    }
    else
    {
        LOG("-> %p\n", pPts);
    }
}


static void
DbgPtsUnhook(
    _In_ DWORD Argc,
    _In_ const char *Argv[]
    )
{
    INTSTATUS status;
    PHOOK_PTS pPts;

    if (Argc != 2)
    {
        ERROR("[ERROR] Invalid number of arguments!\n");
        return;
    }

    pPts = (PHOOK_PTS)strtoull(Argv[1], NULL, 0);

    // We can't commit the hook, since other CPU blocked in the debugger may have hooks locks.
    status = IntHookPtsRemoveHook((HOOK_PTS **)&pPts, 0);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntHookPtsRemoveHook failed: 0x%08x\n", status);
    }
}


static void
DbgPtsWrite(
    _In_ DWORD Argc,
    _In_ const char *Argv[]
    )
{
    INTSTATUS status;
    QWORD oldvalue, newvalue;
    PHOOK_PTS_ENTRY pPts;

    if (Argc != 4)
    {
        ERROR("[ERROR] Invalid number of arguments!\n");
        return;
    }

    pPts = (PHOOK_PTS_ENTRY)strtoull(Argv[1], NULL, 0);

    oldvalue = strtoull(Argv[2], NULL, 0);

    newvalue = strtoull(Argv[3], NULL, 0);

    status = IntHookPtsWriteEntry(pPts, oldvalue, newvalue);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntHookPtsWriteEntry failed: 0x%08x\n", status);
    }
}


static void
DbgDumpCpuState(
    void
    )
{
    for (DWORD i = 0; i < gGuest.CpuCount; i++)
    {
        LOG("Cpu %d state -> %d (%s)\n", i, gGuest.VcpuArray[i].State,
            gGuest.VcpuArray[i].State == CPU_STATE_ACTIVE ? "Active" :
            gGuest.VcpuArray[i].State == CPU_STATE_EPT_VIOLATION ? "EPT violation" :
            gGuest.VcpuArray[i].State == CPU_STATE_MSR_VIOLATION ? "MSR violation" :
            gGuest.VcpuArray[i].State == CPU_STATE_VMCALL ? "VMCALL" :
            gGuest.VcpuArray[i].State == CPU_STATE_TIMER ? "Timer" :
            gGuest.VcpuArray[i].State == CPU_STATE_CR_WRITE ? "CR Write" :
            gGuest.VcpuArray[i].State == CPU_STATE_DTR_LOAD ? "DTR Load" :
            gGuest.VcpuArray[i].State == CPU_STATE_XCR_WRITE ? "XCR Write" : "Unknown");
    }
}


static void
DbgLogCoreOptions(
    void
    )
{
    LOG("Guest options: 0x%016llx\n", gGuest.CoreOptions.Current);
}


static void
DbgSetCoreOptions(
    _In_ DWORD Argc,
    _In_ const char *Argv[]
    )
{
    QWORD newValue;

    if (Argc < 2)
    {
        ERROR("[ERROR] Invalid number of arguments!\n");
        return;
    }

    newValue = strtoull(Argv[1], NULL, 0);

    LOG("Old guest options 0x%016llx, new guest options 0x%016llx\n", gGuest.CoreOptions.Current, newValue);

    IntGuestUpdateCoreOptions(newValue);
}


static void
DbgLogCurrentProcess(
    void
    )
{
    WIN_PROCESS_OBJECT const *proc = IntWinGetCurrentProcess();

    if (NULL == proc)
    {
        ERROR("[ERROR] No process found for the current CR3: 0x%016llx\n", gVcpu->Regs.Cr3);
    }
    else
    {
        LOG("Current process: 0x%016llx, PID %d, ImageName '%s'\n", proc->EprocessAddress, proc->Pid, proc->Name);
    }
}


static void
DbgFindKsym(
    _In_ DWORD Argc,
    _In_ const char *Argv[]
    )
{
    QWORD gva, symEnd;
    CHAR symName[LIX_SYMBOL_NAME_LEN] = {0};
    INTSTATUS status;

    if (Argc != 2)
    {
        ERROR("[ERROR] Invalid number of arguments!\n");
        return;
    }

    symEnd = 0;

    // Let's be reasonable, and assume we will give a hex number (0x...)
    if (Argv[1][0] == '0')
    {
        gva = strtoull(Argv[1], 0, 0);

        status = IntKsymFindByAddress(gva, sizeof(symName), symName, NULL, &symEnd);
        if (!INT_SUCCESS(status))
        {
            LOG("No symbol at GVA 0x%016llx\n", gva);
        }
        else
        {
            LOG("Symbol at GVA 0x%016llx -> 0x%016llx: %s\n", gva, symEnd, symName);
        }
    }
    else
    {
        gva = IntKsymFindByName(Argv[1], &symEnd);
        if (!gva)
        {
            LOG("Can't find symbol %s\n", Argv[1]);
        }
        else
        {
            LOG("Symbol %s at GVA 0x%016llx -> 0x%016llx\n", symName, gva, symEnd);
        }
    }
}


static void
DbgLogKpcr(
    void
    )
{
    for (DWORD i = 0; i < gGuest.CpuCount; i++)
    {
        QWORD pcrBase = 0;
        INTSTATUS status = 0;

        if (!gGuest.VcpuArray[i].IdtBase)
        {
            LOG("CPU %d seems to be inactive, will skip.\n", i);
            continue;
        }

        status = IntFindKernelPcr(i, &pcrBase);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntFindKernelPcr failed for %d: 0x%08x\n", i, status);
            continue;
        }
        else if (INT_STATUS_NOT_NEEDED_HINT == status)
        {
            LOG("CPU %d seems to be inactive, will skip.\n", i);
            continue;
        }

        LOG("KPCR on CPU %d is 0x%016llx\n", i, pcrBase);
    }
}


static void
DbgDumpProcToken(
    _In_ DWORD Argc,
    _In_ const char *Argv[]
    )
{
    INTSTATUS status;
    INTRO_WIN_TOKEN *pToken;
    DWORD pid;

    if (Argc != 2)
    {
        ERROR("[ERROR] Invalid number of arguments!\n");
        return;
    }

    pid = strtoul(Argv[1], 0, 0);

    pToken = HpAllocWithTag(sizeof(*pToken), IC_TAG_DEBUG);
    if (NULL == pToken)
    {
        return;
    }

    status = IntWinGetAccessTokenFromProcess(pid, 0, pToken);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntWinGetAccessTokenFromProcess failed for %d: 0x%x\n", pid, status);
    }
    else
    {
        IntWinDumpToken(pToken);
    }

    HpFreeAndNullWithTag(&pToken, IC_TAG_DEBUG);
}


static void
DbgDumpEthreadToken(
    _In_ DWORD Argc,
    _In_ const char *Argv[]
    )
{
    QWORD ethread;
    INTSTATUS status;
    INTRO_WIN_TOKEN *pToken;

    if (Argc != 2)
    {
        ERROR("[ERROR] Invalid number of arguments!\n");
        return;
    }

    pToken = HpAllocWithTag(sizeof(*pToken), IC_TAG_DEBUG);
    if (NULL == pToken)
    {
        return;
    }

    ethread = strtoull(Argv[1], 0, 0);

    status = IntWinGetAccesTokenFromThread(ethread, pToken);
    if (INT_STATUS_NOT_FOUND == status)
    {
        LOG("No Impersonation Token found for Ethread %llx\n", ethread);
    }
    else if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntWinGetAccesTokenFromThread failed for %llx: 0x%x\n", ethread, status);
    }
    else
    {
        IntWinDumpToken(pToken);
    }

    HpFreeAndNullWithTag(&pToken, IC_TAG_DEBUG);
}


static void
DbgDumpVaSpace(
    _In_ DWORD Argc,
    _In_ const char *Argv[]
    )
{
    QWORD cr3;
    INTSTATUS status;

    if (Argc != 2)
    {
        ERROR("[ERROR] Invalid number of arguments!\n");
        return;
    }

    cr3 = strtoull(Argv[1], NULL, 0);

    status = IntVasDump(cr3);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntVasDump failed: 0x%08x\n", status);
    }
}


static void
DbgSwap(
    _In_ DWORD Argc,
    _In_ const char *Argv[]
    )
{
    QWORD cr3;
    QWORD gla;
    DWORD len;
    DWORD mod;
    INTSTATUS status;

    if (Argc < 5)
    {
        ERROR("[ERROR] Invalid number of arguments!\n");
        return;
    }

    cr3 = strtoull(Argv[1], NULL, 0);
    gla = strtoull(Argv[2], NULL, 0);
    len = strtoul(Argv[3], NULL, 0);
    mod = strtoul(Argv[4], NULL, 0);

    status = IntSwapMemReadData(cr3, gla, len, mod, NULL, 0, DbgSwapCallback, NULL, NULL);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntSwapMemReadData failed: 0x%08x\n", status);
    }
}


static void
DbgDumpVadRoot(
    _In_ DWORD Argc,
    _In_ const char *Argv[]
    )
{
    QWORD root;
    INTSTATUS status;

    if (Argc < 2)
    {
        ERROR("[ERROR] Invalid number of arguments!\n");
        return;
    }

    if (2 == Argc)
    {
        root = strtoull(Argv[1], NULL, 0);
    }
    else
    {
        QWORD eproc, rootPtr;

        if (0 != strncasecmp(Argv[1], "eproc", sizeof("eproc")))
        {
            return;
        }

        eproc = strtoull(Argv[2], NULL, 0);
        rootPtr = eproc + WIN_KM_FIELD(Process, VadRoot);

        LOG("Fetching VAD root @ 0x%016llx from eprocess 0x%016llx\n", eproc, rootPtr);

        status = IntKernVirtMemFetchQword(rootPtr, &root);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntKernVirtMemFetchQword failed: 0x%08x\n", status);
            return;
        }
    }

    if (!IS_KERNEL_POINTER_WIN(gGuest.Guest64, root))
    {
        ERROR("[ERROR] VAD Root must be a kernel pointer! 0x%016llx\n", root);
        return;
    }

    status = IntWinVadInOrderRecursiveTraversal(root, 0, IntWinVadShortDump, NULL);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntWinVadInOrderTraversal failed: 0x%08x\n", status);
    }
}


static void
DbgDumpVads(
    _In_ DWORD Argc,
    _In_ const char *Argv[]
    )
{
    const char *pName = NULL;

    if (Argc >= 2)
    {
        pName = Argv[1];
    }

    LOG("Dumping VADs for %s...\n", pName ? pName : "all processes");

    IntWinProcDumpVads(pName);
}


static void
DbgVadFind(
    _In_ DWORD Argc,
    _In_ const char *Argv[]
    )
{
    QWORD vadroot, startpage, endpage, res;

    if (Argc != 4)
    {
        ERROR("[ERROR] Invalid number of arguments!\n");
        return;
    }

    vadroot = strtoull(Argv[1], 0, 0);
    startpage = strtoull(Argv[2], 0, 0);
    endpage = strtoull(Argv[3], 0, 0);

    LOG("Searching for VAD [%llx, %llx] starting with %llx...\n", startpage, endpage, vadroot);

    res = IntWinVadFindNodeInGuestSpace(vadroot, startpage, endpage, 0, 0, FALSE);

    LOG("Found VAD at %llx\n", res);
}


static void
DbgLogFilePath(
    _In_ DWORD Argc,
    _In_ const char *Argv[]
    )
{
    UNREFERENCED_PARAMETER(Argc);
    UNREFERENCED_PARAMETER(Argv);

    WARNING("[WARNING] Not implemented\n");
}


static void
DbgLoadPt(
    void
    )
{
    gLoadPtDriver = TRUE;
}


static void
DbgUnloadPt(
    void
    )
{
    gUnloadPtDriver = TRUE;
}


static void
DbgLoadVe(
    void
    )
{
    gInjectVeLoader = TRUE;
}


static void
DbgUnloadVe(
    void
    )
{
    gInjectVeUnloader = TRUE;
}


static void
DbgTestSse(
    _In_ DWORD Argc,
    _In_ const char *Argv[]
    )
{
    DWORD i, count;
    BYTE instruction[16];
    INSTRUX instrux;
    MEMADDR glas[32];
    CHAR text[ND_MIN_BUF_SIZE];

    if (Argc < 2)
    {
        ERROR("[ERROR] Invalid number of arguments!\n");
        return;
    }

    /*
      Instructions to test:
      VPGATHERDD xmm1, [rax + xmm2], xmm3 ---- 0xC4 0xE2 0x61 0x90 0x0C 0x10
      VPGATHERQQ xmm1, [rax + xmm2], xmm3 ---- 0xC4 0xE2 0xE1 0x91 0x0C 0x10
      VPGATHERDD ymm1, [rax + ymm2], ymm3 ---- 0xC4 0xE2 0x65 0x90 0x0C 0x10
      VPGATHERQQ ymm1, [rax + ymm2], ymm3 ---- 0xC4 0xE2 0xE5 0x91 0x0C 0x10

      VPGATHERDD xmm1, [rax + xmm15 * 8], xmm3 ---- 0xC4 0xA2 0x61 0x90 0x0C 0xF8
      VPGATHERQQ xmm1, [rax + xmm15 * 8], xmm3 ---- 0xC4 0xA2 0xE1 0x91 0x0C 0xF8
      VPGATHERDD ymm1, [rax + ymm13 * 4], ymm3 ---- 0xC4 0xA2 0x65 0x90 0x0C 0xA8
      VPGATHERQQ ymm1, [rax + ymm13 * 4], ymm3 ---- 0xC4 0xA2 0xE5 0x91 0x0C 0xA8

      VPSCATTERDD [rax + zmm17], zmm23 ---- 0x62 0xE2 0x7D 0x40 0xA0 0x3C 0x08
      VPSCATTERQQ [rax + zmm17], zmm23 ---- 0x62 0xE2 0xFD 0x40 0xA1 0x3C 0x08
    */

    for (i = 1; i < Argc; i++)
    {
        instruction[i - 1] = (BYTE)strtoul(Argv[i], NULL, 0);
    }

    IntDecDecodeInstructionFromBuffer(instruction, 16, IG_CS_TYPE_64B, &instrux);

    NdToText(&instrux, 0, ND_MIN_BUF_SIZE, text);

    count = 32;

    IntDecGetAccessedMem(&instrux, NULL, NULL, glas, &count);

    LOG("Got %d accesses for '%s':\n", count, text);

    for (i = 0; i < count; i++)
    {
        LOG("    Access at %llx, size %d, access %d\n", glas[i].Gla, glas[i].Size, glas[i].Access);
    }
}


static void
DbgTestRead(
    _In_ DWORD Argc,
    _In_ const char *Argv[]
    )
{
    INTSTATUS status;
    QWORD va;
    BYTE patchedData[16] = { 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF };
    BYTE origData[16];
    void *pClk;

    if (Argc < 2)
    {
        ERROR("[ERROR] Invalid number of arguments!\n");
        return;
    }

    va = strtoull(Argv[1], NULL, 0);

    status = IntKernVirtMemRead(va, sizeof(origData), &origData, NULL);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemRead failed: 0x%08x\n", status);
        return;
    }

    status = IntMemClkCloakRegion(va, 0, 16, 0, patchedData, origData, NULL, &pClk);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntMemClkCloakRegion failed: 0x%08x\n", status);
        return;
    }
}


static void
DbgTestCrHookSet(
    _In_ DWORD Argc,
    _In_ const char *Argv[]
    )
{
    PHOOK_CR hook;
    DWORD cr;
    INTSTATUS status;

    if (Argc < 2)
    {
        ERROR("[ERROR] Invalid number of arguments!\n");
        return;
    }

    cr = strtoul(Argv[1], NULL, 0);

    status = IntHookCrSetHook(cr, 0, DbgCrWriteTestCallback, NULL, &hook);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntHookCrSetHook failed: 0x%08x\n", status);
    }
    else
    {
        LOG("HOOK -> %p\n", hook);
    }
}


static void
DbgTestCrHookRem(
    _In_ DWORD Argc,
    _In_ const char *Argv[]
    )
{
    QWORD hook;
    INTSTATUS status;

    if (Argc < 2)
    {
        ERROR("[ERROR] Invalid number of arguments!\n");
        return;
    }

    hook = strtoull(Argv[1], NULL, 0);

    status = IntHookCrRemoveHook((PHOOK_CR)hook);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntHookCrRemoveHook failed: 0x%08x\n", status);
    }
}


static void
DbgFailAllocs(
    void
    )
{
    gFailAllocs = !gFailAllocs;

    LOG("gFailAllocs is now %d\n", gFailAllocs);
}


static void
DbgCheckEpt(
    void
    )
{
    for (QWORD page = 0; page < 8 * 1024 * 1024; page++)
    {
        BYTE r, w, x;
        INTSTATUS status = IntGetEPTPageProtection(gGuest.UntrustedEptIndex, page << 12, &r, &w, &x);
        if (INT_SUCCESS(status))
        {
            if (r && !w)
            {
                LOG("EPT check failed on: %llx\n", page << 12);
            }
        }
    }
}


static void
DbgSetLogLevel(
    _In_ DWORD Argc,
    _In_ const char *Argv[]
    )
{
    IG_LOG_LEVEL logLevel;

    if (Argc < 2)
    {
        ERROR("[ERROR] Invalid number of arguments!\n");
        return;
    }

    logLevel = (DWORD)strtoull(Argv[1], NULL, 0);
    if (logLevel > intLogLevelCritical)
    {
        ERROR("[ERROR] Invalid log level %d\n", logLevel);
    }

    gLogLevel = logLevel;
}

#include "swapgs.h"

BOOLEAN swapgsMit = FALSE;

static void
DbgMitigateSwapgs(
    _In_ DWORD Argc,
    _In_ const char *Argv[]
    )
{
    UNREFERENCED_LOCAL_VARIABLE(Argc);
    UNREFERENCED_LOCAL_VARIABLE(Argv);

    if (!swapgsMit)
    {
        IntSwapgsStartMitigation();
        LOG("Enabled SWAPGS mitigation!\n");
        swapgsMit = TRUE;
    }
    else
    {
        IntSwapgsUninit();
        LOG("Disabled SWAPGS mitigation!\n");
        swapgsMit = FALSE;
    }
}


typedef struct _DEBUGGER_COMMAND
{
    const char *Command;
    const char *Help;
    const char *Parameters;

    union
    {
        PFUNC_DebuggerFunctionArgs   FunctionArgs;
        PFUNC_DebuggerFunctionNoArgs FunctionNoArgs;
    };
} DEBUGGER_COMMAND;


static DEBUGGER_COMMAND gDbgCommands[] =
{
    {
        .Command = "!help",
        .Help = "show help",
        .FunctionNoArgs = DbgShowHelp,
    },
    {
        .Command = "!stats",
        .Help = "timing statistics for introspection callbacks",
        .FunctionNoArgs = IntStatsDumpAll,
    },
    {
        .Command = "!resetstats",
        .Help = "reset all the introcore statistics",
        .FunctionNoArgs = IntStatsResetAll,
    },
#ifdef DEBUG_MEM_ALLOCS
    {
        .Command = "!allocs",
        .Help = "lists active memory allocations",
        .FunctionNoArgs = IntDbgDumpAllocs,
    },
    {
        .Command = "!check_allocs",
        .Help = "checks the current heap allocations for corruption",
        .FunctionNoArgs = IntDbgCheckAllocs,
    },
#endif
    {
        .Command = "!detours",
        .Help = "list the detours",
        .FunctionNoArgs = IntDetDumpDetours,
    },
    {
        .Command = "!pfnlocks",
        .Help = "list the pfn locked pages (windows only)",
        .FunctionNoArgs = IntWinPfnDump,
    },
    {
        .Command = "!drivers_intro",
        .Help = "lists the drivers list inside the introspection",
        .FunctionNoArgs = IntDriverDump,
    },
    {
        .Command = "!drivers_guest",
        .Help = "lists the drivers loaded inside the guest",
        .FunctionNoArgs = DbgDumpGuestModules,
    },
    {
        .Command = "!gpf",
        .Help = "force page fault in guest",
        .Parameters = "gva: uint64; cr3: uint64; write: 0|1",
        .FunctionArgs = DbgInjectPf,
    },
    {
        .Command = "!pfn",
        .Help = "dump the pfn contents of the given virtual/physical address",
        .Parameters = "type: char v|p; addr: uint64",
        .FunctionArgs = DbgDumpPfn,
    },
    {
        .Command = "!dumpcb",
        .Help = "dump codeblocks from the given address",
        .Parameters = "gva: uint64; length: uint32 [default=end of page]; "
                      "rip: uint64 [default=gva]; level: uint32 [default=1]",
        .FunctionArgs = DbgDumpCodeblocks,
    },
    {
        .Command = "!exceptions",
        .Help = "dump exceptions",
        .FunctionNoArgs = DbgDumpExceptions,
    },
    {
        .Command = "!hooks_gpa",
        .Help = "dump gpa hooks",
        .FunctionNoArgs = IntHookGpaDump,
    },
    {
        .Command = "!hooks_gva",
        .Help = "dump gva hooks",
        .FunctionNoArgs = DbgDumpHooksGva,
    },
    {
        .Command = "!hooks_check",
        .Help = "check hooks",
        .FunctionNoArgs = IntDbgCheckHooks,
    },
    {
        .Command = "!processes",
        .Help = "dump the list of active processes",
        .FunctionNoArgs = DbgDumpProcesses,
    },
    {
        .Command = "!process_tree",
        .Help = "dump the list of active processes as a tree (linux only)",
        .FunctionNoArgs = IntLixTaskDumpAsTree,
    },
    {
        .Command = "!procadd",
        .Help = "adds the process to the protected processes list",
        .Parameters = "process: string; protection: uint64",
        .FunctionArgs = DbgProcAdd,
    },
    {
        .Command = "!procrem",
        .Help = "removes the process from the protected processes",
        .Parameters = "process: string",
        .FunctionArgs = DbgProcRem,
    },
    {
        .Command = "!procclr",
        .Help = "remove all the protected processes",
        .FunctionNoArgs = DbgProcClear,
    },
    {
        .Command = "!proclst",
        .Help = "dump the list of protected processes",
        .FunctionNoArgs = DbgProcList,
    },
    {
        .Command = "!icache",
        .Help = "dump the instruction cache",
        .FunctionNoArgs = IntIcDumpIcache,
    },
    {
        .Command = "!gpacache",
        .Help = "dump the gpa cache",
        .FunctionNoArgs = DbgDumpGpaCache,
    },
    {
        .Command = "!disasm",
        .Help = "disassembles instructions from the given address",
        .Parameters = "gva: uint64; size: uint32",
        .FunctionArgs = DbgDisasm,
    },
    {
        .Command = "!integrity",
        .Help = "dump the integrity zones",
        .FunctionNoArgs = IntIntegrityDump,
    },
    {
        .Command = "!agent_inj",
        .Help = "inject an agent with the given name and tag",
        .Parameters = "name: string; tag: uint32",
        .FunctionArgs = DbgInjectAgent,
    },
    {
        .Command = "!file_inj",
        .Help = "inject an file agent with the given name",
        .Parameters = "name: string",
        .FunctionArgs = DbgInjectFileAgent,
    },
    {
        .Command = "!itva",
        .Help = "iterate the given VA space, searching for a specific pml4",
        .Parameters = "cr3: uint64; pml4: uint64",
        .FunctionArgs = DbgSearchVaSpace,
    },
    {
        .Command = "!itvaall",
        .Help = "iterate the VA space of all processes",
        .FunctionNoArgs = DbgIterateVaSpace,
    },
    {
        .Command = "!pwalk",
        .Help = "dump the GVA -> GPA translation",
        .Parameters = "gva: uin64; cr3: uint64",
        .FunctionArgs = DbgDumpTranslation,
    },
    {
        .Command = "!pts_hook",
        .Help = "place a hook for the given GVA inside the given VA-space",
        .Parameters = "cr3: uint64; va: uint64; id: uint64",
        .FunctionArgs = DbgPtsHook,
    },
    {
        .Command = "!pts_unhook",
        .Help = "remove the given hook",
        .Parameters = "pts: HOOK_PTS",
        .FunctionArgs = DbgPtsUnhook,
    },
    {
        .Command = "!pts_dump",
        .Help = "dump all the PTS hooks",
        .FunctionNoArgs = IntHookPtsDump,
    },
    {
        .Command = "!pts_write",
        .Help = "simulate a write inside the given pts entry",
        .Parameters = "pts: HOOK_PTS_ENTRY; oldvalue: uint64; newvalue: uint64",
        .FunctionArgs = DbgPtsWrite,
    },
    {
        .Command = "!cpus",
        .Help = "dump the cpu state",
        .FunctionNoArgs = DbgDumpCpuState,
    },
    {
        .Command = "!get_options",
        .Help = "dump the introcore current options",
        .FunctionNoArgs = DbgLogCoreOptions,
    },
    {
        .Command = "!set_options",
        .Help = "set the introcore current options",
        .Parameters = "options: uint64",
        .FunctionArgs = DbgSetCoreOptions,
    },
    {
        .Command = "!curproc",
        .Help = "dump the current process (windows only)",
        .FunctionNoArgs = DbgLogCurrentProcess,
    },
    {
        .Command = "!findksym",
        .Help = "dump the symbol name at the given address or address of the given symbol name",
        .Parameters = "gva|name: uint64|string",
        .FunctionArgs = DbgFindKsym,
    },
    {
        .Command = "!winpcr",
        .Help = "log the KPCR for all cpus (windows only)",
        .FunctionNoArgs = DbgLogKpcr,
    },
    {
        .Command = "!ptoken",
        .Help = "dump the process token for the given process (windows only)",
        .Parameters = "pid: uint32",
        .FunctionArgs = DbgDumpProcToken,
    },
    {
        .Command = "!ttoken",
        .Help = "dump the process token for the given ethread (windows only)",
        .Parameters = "ethread: uint64",
        .FunctionArgs = DbgDumpEthreadToken,
    },
    {
        .Command = "!vasdump",
        .Help = "dump the whole VA space of the given CR3",
        .Parameters = "cr3: uint64",
        .FunctionArgs = DbgDumpVaSpace,
    },
    {
        .Command = "!swap",
        .Help = "make the given GVA present (injecting a #PF if needed)",
        .Parameters = "cr3: uint64; gva: uin64; length: uint32; options: uint32",
        .FunctionArgs = DbgSwap,
    },
    {
        .Command = "!transactions",
        .Help = "dump the swap transactions",
        .FunctionNoArgs = IntSwapMemDump,
    },
    {
        .Command = "!vad",
        .Help = "dump all the vads for the given vad root (windows only)",
        .Parameters = "vad_root: uint64",
        .FunctionArgs = DbgDumpVadRoot,
    },
    {
        .Command = "!dump_vads",
        .Help = "dump the vad for the given process (or all process)",
        .Parameters = "name: string [optional]",
        .FunctionArgs = DbgDumpVads,
    },
    {
        .Command = "!findvad",
        .Help = "find and dump the given VAD inside de the given vad root (windows only)",
        .Parameters = "vadroot: uint64; startpage: uint64; endpage: uint64",
        .FunctionArgs = DbgVadFind,
    },
    {
        .Command = "!showfile",
        .Help = "log the file path for the given `struct file` (linux only)",
        .Parameters = "struct_file: uint64",
        .FunctionArgs = DbgLogFilePath,
    },
    {
        .Command = "!exploitguard",
        .Help = "dump the exploit guard mitigation flags for all processes (windows only)",
        .FunctionNoArgs = IntWinProcDumpEgFlags,
    },
    {
        .Command = "!netscan",
        .Help = "dump all the opened connections (windows only)",
        .FunctionNoArgs = IntWinNetDumpConnections,
    },
    {
        .Command = "!dump_clk",
        .Help = "dump all memory cloaks",
        .FunctionNoArgs = IntMemClkDump,
    },
    {
        .Command = "!pt_load",
        .Help = "inject the pt loader",
        .FunctionNoArgs = DbgLoadPt,
    },
    {
        .Command = "!pt_unload",
        .Help = "inject the pt unloader",
        .FunctionNoArgs = DbgUnloadPt,
    },
    {
        .Command = "!ptstatsall",
        .Help = "dump the pt stats",
        .FunctionNoArgs = IntPtiDumpStats,
    },
    {
        .Command = "!ve_load",
        .Help = "inject the ve loader",
        .FunctionNoArgs = DbgLoadVe,
    },
    {
        .Command = "!ve_unload",
        .Help = "inject the ve unloader",
        .FunctionNoArgs = DbgUnloadVe,
    },
    {
        .Command = "!veinfo",
        .Help = "dump the ve pages",
        .FunctionNoArgs = IntVeDumpVeInfoPages,
    },
    {
        .Command = "!vestats",
        .Help = "dump the ve stats",
        .FunctionNoArgs = IntVeDumpStats,
    },
    {
        .Command = "!testsse",
        .Help = "test sse instructions (access size)",
        .Parameters = "instr_bytes: BYTE[]",
        .FunctionArgs = DbgTestSse,
    },
    {
        .Command = "!testread",
        .Help = "put a memcloak on the given GVA (16 bytes)",
        .Parameters = "gva: uint64",
        .FunctionArgs = DbgTestRead,
    },
    {
        .Command = "!testcrhookset",
        .Help = "set a hook on the given CR",
        .Parameters = "cr: uint32",
        .FunctionArgs = DbgTestCrHookSet,
    },
    {
        .Command = "!testcrhookrem",
        .Help = "remove the given cr hook",
        .Parameters = "cr_hook: HOOK_CR",
        .FunctionArgs = DbgTestCrHookRem,
    },
    {
        .Command = "!failallocs",
        .Help = "fail allocations",
        .FunctionNoArgs = DbgFailAllocs,
    },
    {
        .Command = "!checkept",
        .Help = "preform an EPT check",
        .FunctionNoArgs = DbgCheckEpt,
    },
    {
        .Command = "!setloglevel",
        .Help = "sets the log level",
        .Parameters = "log_level: IG_LOG_LEVEL",
        .FunctionArgs = DbgSetLogLevel,
    },
    {
        .Command = "!swapgsmit",
        .Help = "mitigate SWAPGS",
        .FunctionArgs = DbgMitigateSwapgs,
    },


};


static void
DbgShowHelp(
    void
    )
{
    for (DWORD i = 0; i < ARRAYSIZE(gDbgCommands) - 1; i++)
    {
        for (DWORD j = i; j < ARRAYSIZE(gDbgCommands); j++)
        {
            if (strcmp(gDbgCommands[i].Command, gDbgCommands[j].Command) > 0)
            {
                DEBUGGER_COMMAND cmd = gDbgCommands[i];
                gDbgCommands[i] = gDbgCommands[j];
                gDbgCommands[j] = cmd;
            }
        }
    }

    for (DWORD i = 0; i < ARRAYSIZE(gDbgCommands); i++)
    {
        const DEBUGGER_COMMAND *cmd = &gDbgCommands[i];

        NLOG("%-17s %s\n", cmd->Command, cmd->Help);

        if (cmd->Parameters)
        {
            NLOG("                  %s\n", cmd->Parameters);
        }
    }
}


//
// IntDbgProcessCommand
//
INTSTATUS
IntDbgProcessCommand(
    _In_ DWORD Argc,
    _In_ const char *Argv[]
    )
{
    BOOLEAN found = FALSE;

    if (NULL == Argv)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    // Ignore empty commands (shouldn't really happen).
    if (Argc == 0)
    {
        return INT_STATUS_SUCCESS;
    }

    gInsideDebugger = TRUE;

    for (DWORD i = 0; i < ARRAYSIZE(gDbgCommands); i++)
    {
        DEBUGGER_COMMAND *pCmd = &gDbgCommands[i];

        if (0 != strcmp(pCmd->Command, Argv[0]))
        {
            continue;
        }

        if (pCmd->Parameters)
        {
            pCmd->FunctionArgs(Argc, Argv);
        }
        else
        {
            pCmd->FunctionNoArgs();
        }

        found = TRUE;

        break;
    }

    if (!found)
    {
        ERROR("[ERROR] Invalid command: `%s`\n", Argv[0]);
    }

    gInsideDebugger = FALSE;

    return INT_STATUS_SUCCESS;
}
