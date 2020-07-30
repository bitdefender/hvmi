/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "winumcache.h"
#include "crc32.h"
#include "guests.h"
#include "swapmem.h"
#include "winpe.h"
#include "winummodule.h"


///
/// @file winumcache.c
///
/// @brief This module manages module and exports caches.
///
/// Whenever a protected module is loaded, we will create a cache entry representing the module. Inside this cache
/// entry, we will store information regarding the headers and the headers themselves. In addition, we will read
/// and parse all the exports of the indicated module. Note that there is a single cache instance allocated for
/// a given protected module, no matter how many times that module has been loaded, and no matter how many processes
/// have loaded that module. When the first instance of a protected module is loaded, the cache is created and
/// the exports read. Instances loaded after this will simply reference the already existing cache entry. The cache
/// entries will be removed during uninit only.
/// An exception to this mechanism are dirty caches. A cache is considered dirty if it was created from a module
/// loaded by a process that was already created when Introcore was activated. In these cases, we cannot trust
/// the contents of that particular cache, so we will mark it Dirty. Dirty caches are NOT re-used - this means that
/// a Dirty cache is local and private to one module only, and it will be removed when that modules is unloaded.
/// Caches created from freshly created process are NOT dirty, and they can be reused by all subsequent loaded modules.
///


///
/// The list of hashes for libraries we wish to cache.
///
const DWORD gExportedDirsToCache[] =
{
    NAMEHASH_NTDLL,
    NAMEHASH_KERNEL32,
    NAMEHASH_KERNELBASE,
    NAMEHASH_USER32,
    NAMEHASH_WS2_32,
    NAMEHASH_WININET,
    NAMEHASH_WOW64,
    NAMEHASH_WOW64CPU,
    NAMEHASH_WOW64WIN
};

extern LIST_HEAD gWinProcesses;

LIST_HEAD gWinUmCaches = LIST_HEAD_INIT(gWinUmCaches);


_Function_class_(FUNC_RbTreeNodeFree) static void
IntWinModCacheExportNodeFree(
    _Inout_ RBNODE *Node
    )
///
/// @brief RB tree free function.
///
/// NOTE: Does nothing.
///
/// @param[in, out] Node    The RB tree node to be freed.
///
{
    UNREFERENCED_PARAMETER(Node);
}


_Function_class_(FUNC_RbTreeNodeCompare) static int
IntWinModCacheExportNodeCompare(
    _In_ RBNODE *Left,
    _In_ RBNODE *Right
    )
///
/// @brief Compares two RB tree nodes, representing cached exports.
///
/// This function will compare the RVAs of the two #WINUM_CACHE_EXPORT structures described by Left and Right.
///
/// @param[in]  Left    The left node.
/// @param[in]  Right   The right node.
///
/// @returns -1 if Left < Right, 0 if Left == Right, 1 if Left > Right.
///
{
    WINUM_CACHE_EXPORT *pExport1 = CONTAINING_RECORD(Left, WINUM_CACHE_EXPORT, RbNode);
    WINUM_CACHE_EXPORT *pExport2 = CONTAINING_RECORD(Right, WINUM_CACHE_EXPORT, RbNode);

    if (pExport1->Rva < pExport2->Rva)
    {
        return -1;
    }
    else if (pExport1->Rva > pExport2->Rva)
    {
        return 1;
    }

    return 0;
}


_Function_class_(FUNC_RbTreeNodeCustomCompare) static int
IntWinModCacheExportNodeCompareWithErorr(
    _In_ RBNODE *Node,
    _In_ void *Key
    )
///
/// @brief Checks if the provided key is inside the given RB tree node.
///
/// The function checks if the provided key (first DWORD) is inside the given node, with a limit given by the
/// second DWORD in the key argument. The node is a #WINUM_CACHE_EXPORT structure, and the Rva field is used for
/// comparison.
///
/// @param[in]  Node    The RB tree node.
/// @param[in]  Key     A tuple containing two DWORDs: the first DWORD is the value to find, while the second
///                     DWORD is the limit within the RB tree node.
///
/// @returns -1 if the node is smaller than the key, 0 if they are equal, 1 if the node is larger.
///
{
    WINUM_CACHE_EXPORT *pExport = CONTAINING_RECORD(Node, WINUM_CACHE_EXPORT, RbNode);
    DWORD *pair = (DWORD *)Key;

    if (pair[0] >= pExport->Rva && pair[0] < pExport->Rva + pair[1])
    {
        return 0;
    }
    else if (pExport->Rva < pair[0])
    {
        return -1;
    }
    else
    {
        return 1;
    }
}


_Function_class_(FUNC_RbTreeWalkCallback)
static BOOLEAN
IntWinModCacheFixNamePointers(
    _In_ RBNODE *Node,
    _In_ void *Module
    )
///
/// @brief Fixes the names, lens and hashes inside the given RB node, provided the info inside the module.
///
/// Given Module, it will fix the Names, NameLens and NameHashes inside the #WINUM_CACHE_EXPORT structure
/// represented by the the Node argument based on the cache belonging to the module. It will also check
/// if the memory related instructions (memcpy, memset, etc.) have been identified in the ntdll module,
/// in which case the MemoryFuncsRead field inside the exports cache will be set.
///
/// @param[in]  Node    The RB tree node, representing a #WINUM_CACHE_EXPORT structure.
/// @param[in]  Module  The module from which the cache will be used to fixup the names.
///
/// @returns True.
///
{
    WIN_PROCESS_MODULE *pMod = Module;
    WINUM_MODULE_CACHE *pCache = pMod->Cache;

    WINUM_CACHE_EXPORT *pExport = CONTAINING_RECORD(Node, WINUM_CACHE_EXPORT, RbNode);

    for (DWORD i = 0; i < pExport->NumberOfOffsets; i++)
    {
        pExport->Names[i] = pCache->Exports.Names + (pExport->NameOffsets[i] - pCache->Exports.StartNames);
        // It's okay to typecast to DWORD here, we don't parse images larger than 2G anyway.
        pExport->NameLens[i] = (DWORD)strlen(pExport->Names[i]);
        pExport->NameHashes[i] = Crc32Compute(pExport->Names[i], pExport->NameLens[i], INITIAL_CRC_VALUE);

        if (pMod->Path->NameHash == NAMEHASH_NTDLL && !pCache->MemoryFuncsRead)
        {
            switch (pExport->NameLens[i])
            {
            case 6:
                if (0 == strcmp(pExport->Names[i], "memcpy"))
                {
                    pCache->MemFuncs.MemcpyRva = pExport->Rva;
                }
                else if (0 == strcmp(pExport->Names[i], "memset"))
                {
                    pCache->MemFuncs.MemsetRva = pExport->Rva;
                }
                break;
            case 7:
                if (0 == strcmp(pExport->Names[i], "memmove"))
                {
                    pCache->MemFuncs.MemmoveRva = pExport->Rva;
                }
                break;
            case 8:
                if (0 == strcmp(pExport->Names[i], "memcpy_s"))
                {
                    pCache->MemFuncs.MemcpySRva = pExport->Rva;
                }
                break;
            case 9:
                if (0 == strcmp(pExport->Names[i], "memmove_s"))
                {
                    pCache->MemFuncs.MemmoveSRva = pExport->Rva;
                }
                break;

            default:
                break;
            }

            if (pCache->MemFuncs.MemcpyRva != 0 &&
                pCache->MemFuncs.MemcpySRva != 0 &&
                pCache->MemFuncs.MemmoveRva != 0 &&
                pCache->MemFuncs.MemmoveSRva != 0 &&
                pCache->MemFuncs.MemsetRva != 0)
            {
                pCache->MemoryFuncsRead = TRUE;
            }

        }
    }

    return TRUE;
}


WINUM_CACHE_EXPORT *
IntWinUmCacheGetExportFromRange(
    _In_ WIN_PROCESS_MODULE *Module,
    _In_ QWORD Gva,
    _In_ DWORD Length
    )
///
/// @brief Tries to find an export in the range [Gva - Length, Gva].
///
/// Given Module, it will try to find a valid export which lies at most Length bytes before the provided Gva.
///
/// @param[in]  Module  The module where the export is searched.
/// @param[in]  Gva     Gva to start the search at.
/// @param[in]  Length  Maximum number of bytes to search backwards to see if an export is found.
///
/// @returns A pointer to the #WINUM_CACHE_EXPORT structure, if an export is found, or NULL if no export is found.
///
{
    if (Module == NULL)
    {
        return NULL;
    }

    for (QWORD crtGva = Gva; Gva - crtGva < Length; crtGva--)
    {
        WINUM_CACHE_EXPORT *pExport = IntWinUmModCacheExportFind(Module, (DWORD)(crtGva - Module->VirtualBase), 0);

        if (pExport != NULL)
        {
            return pExport;
        }
    }

    return NULL;
}


WINUM_CACHE_EXPORT *
IntWinUmModCacheExportFind(
    _In_ WIN_PROCESS_MODULE *Module,
    _In_ DWORD Rva,
    _In_ DWORD ErrorRange
    )
///
/// @brief Tries to find an export in the range [Rva, Rva + ErrorRange].
///
/// Given Module, it will try to find a valid export which lies within the [Rva, Rva + ErrorRange] interval.
///
/// @param[in]  Module      The module where the export is searched.
/// @param[in]  Rva         Rva to start the search at.
/// @param[in]  ErrorRange  Maximum interval to search after the provided Rva.
///
/// @returns A pointer to the #WINUM_CACHE_EXPORT structure, if an export is found, or NULL if no export is found.
///
{
    WINUM_CACHE_EXPORT target = {0};
    WINUM_MODULE_CACHE *pCache;
    PRBNODE found;

    pCache = Module->Cache;
    if (NULL == pCache || !pCache->ExportDirRead)
    {
        return NULL;
    }

    target.Rva = Rva;
    found = NULL;

    if (0 == ErrorRange)
    {
        RbLookupNode(&pCache->Exports.Tree, &target.RbNode, &found);
    }
    else
    {
        DWORD pair[2] = { 0 };
        pair[0] = Rva;
        pair[1] = ErrorRange;

        RbLookupNodeCustomCompare(&pCache->Exports.Tree,
                                  IntWinModCacheExportNodeCompareWithErorr,
                                  pair,
                                  &found);
    }

    if (NULL == found)
    {
        return NULL;
    }

    return CONTAINING_RECORD(found, WINUM_CACHE_EXPORT, RbNode);
}


static INTSTATUS
IntWinModCancelExportTransactions(
    _In_ WINUM_MODULE_CACHE *Cache
    )
///
/// @brief Cancels all pending swap transactions, in any process, for the provided Cache.
///
/// @param[in]  Cache   The module cache whose transactions we wish to cancel.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    INTSTATUS status, finalStatus = INT_STATUS_SUCCESS;

    list_for_each(gWinProcesses, WIN_PROCESS_OBJECT, pProc)
    {
        if (pProc->Subsystemx64 != NULL)
        {
            list_for_each(pProc->Subsystemx64->ProcessModules, WIN_PROCESS_MODULE, pMod)
            {
                if (pMod->Cache == Cache && pMod->ExportsSwapHandle != NULL)
                {
                    status = IntSwapMemRemoveTransaction(pMod->ExportsSwapHandle);
                    if (!INT_SUCCESS(status))
                    {
                        ERROR("[ERROR] IntSwapMemRemoveTransaction failed: 0x%08x\n", status);
                        finalStatus = status;
                    }

                    pMod->ExportsSwapHandle = NULL;
                }
            }
        }

        if (pProc->Subsystemx86 != NULL)
        {
            list_for_each(pProc->Subsystemx86->ProcessModules, WIN_PROCESS_MODULE, pMod)
            {
                if (pMod->Cache == Cache && pMod->ExportsSwapHandle != NULL)
                {
                    status = IntSwapMemRemoveTransaction(pMod->ExportsSwapHandle);
                    if (!INT_SUCCESS(status))
                    {
                        ERROR("[ERROR] IntSwapMemRemoveTransaction failed: 0x%08x\n", status);
                        finalStatus = status;
                    }

                    pMod->ExportsSwapHandle = NULL;
                }
            }
        }
    }

    return finalStatus;
}


static INTSTATUS
IntWinModHandleExportsInMemory(
    _In_ void *Context,
    _In_ QWORD Cr3,
    _In_ QWORD VirtualAddress,
    _In_ QWORD PhysicalAddress,
    _In_reads_bytes_(DataSize) void *Data,
    _In_ DWORD DataSize,
    _In_ DWORD Flags
    )
///
/// @brief Called as soon as the exports section of a module is swapped in.
///
/// This function will initialize the cache structure for the exports of the given module. In addition, it
/// will cancel all existing transactions for this module's exports, since they were already read (the exports
/// are read a single time no matter how many instances of the associated module exist). The exports of the
/// given module will be read and stored in a RB tree structure for easy & fast lookup.
/// NOTE: At most #WINUMCACHE_MAX_EXPORTS exports will be cached. This means that if a module has more than
/// #WINUMCACHE_MAX_EXPORTS exports, only the first #WINUMCACHE_MAX_EXPORTS will be cached.
///
/// @param[in]  Context         The context, representing the #WIN_PROCESS_MODULE structure whose exports have just
///                             been swapped in.
/// @param[in]  Cr3             The virtual address space. Will usually be the current Cr3.
/// @param[in]  VirtualAddress  The virtual address that of the first page of the exports.
/// @param[in]  PhysicalAddress Physical address of the first exports page.
/// @param[in]  Data            Exports data buffer.
/// @param[in]  DataSize        The size of the read data.
/// @param[in]  Flags           Unused.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INVALID_OBJECT_TYPE If any malformation of the PE file or exports directory is detected.
/// @retval #INT_STATUS_INSUFFICIENT_RESOURCES If a memory alloc fails.
///
{
    WIN_PROCESS_MODULE *pMod;
    WINUM_MODULE_CACHE *pCache;
    const IMAGE_EXPORT_DIRECTORY *exportDir;
    INTSTATUS status;
    PBYTE buffer;

    UNREFERENCED_PARAMETER(Cr3);
    UNREFERENCED_PARAMETER(VirtualAddress);
    UNREFERENCED_PARAMETER(DataSize);
    UNREFERENCED_PARAMETER(PhysicalAddress);
    UNREFERENCED_PARAMETER(Flags);

    pMod = (WIN_PROCESS_MODULE *)Context;
    pCache = pMod->Cache;

    pMod->ExportsSwapHandle = NULL;

    // We already completed our Exports cache from a swap handle, so no bother
    if (pCache->Exports.Array != NULL)
    {
        TRACE("[INFO] Export cache for %s is already completed, bailing out\n", utf16_for_log(pMod->Path->Path));
        return INT_STATUS_SUCCESS;
    }

    status = IntWinModCancelExportTransactions(pCache);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntWinModCancelExportTransactions failed: 0x%08x\n", status);
    }

    pCache->Exports.StartNames = DWORD_MAX;
    pCache->Exports.EndNames = 0;

    buffer = Data;
    exportDir = (PIMAGE_EXPORT_DIRECTORY)Data;

    if (exportDir->NumberOfNames > WINUMCACHE_MAX_EXPORTS)
    {
        WARNING("[WARNING] NumberOfNames is %d for module %s\n",
                exportDir->NumberOfNames, utf16_for_log(pMod->Path->Path));
    }

    if ((exportDir->AddressOfNameOrdinals >= pCache->Info.EatRva + pCache->Info.EatSize) ||
        (exportDir->AddressOfNameOrdinals < pCache->Info.EatRva) ||
        (exportDir->AddressOfNameOrdinals + exportDir->NumberOfNames * 2 >= pCache->Info.EatRva + pCache->Info.EatSize))
    {
        WARNING("[WARNING] AddressOfNameOrdinals %08x points outside of EAT %08x:%08x, %d names\n",
                exportDir->AddressOfNameOrdinals, pCache->Info.EatRva, pCache->Info.EatSize, exportDir->NumberOfNames);

        status = INT_STATUS_INVALID_OBJECT_TYPE;
        goto _err_exit;
    }

    if ((exportDir->AddressOfFunctions >= pCache->Info.EatRva + pCache->Info.EatSize) ||
        (exportDir->AddressOfFunctions < pCache->Info.EatRva) ||
        (exportDir->AddressOfFunctions + exportDir->NumberOfFunctions * 4 >=
            pCache->Info.EatRva + pCache->Info.EatSize))
    {
        WARNING("[WARNING] AddressOfFunctions %08x points outside of Eat %08x:%08x, %d functions\n",
                exportDir->AddressOfFunctions, pCache->Info.EatRva, pCache->Info.EatSize,
                exportDir->NumberOfFunctions);

        status = INT_STATUS_INVALID_OBJECT_TYPE;
        goto _err_exit;
    }

    // We can't check more than this since names size are variable. There are more checks below anyway.
    // NOTE: we could impose a minimum of 2 chars per name (one letter + NULL terminator)
    if ((exportDir->AddressOfNames >= pCache->Info.EatRva + pCache->Info.EatSize) ||
        (exportDir->AddressOfNames < pCache->Info.EatRva))
    {
        WARNING("[WARNING] AddressOfNames %08x points outside of Eat %08x:%08x, %d names\n",
                exportDir->AddressOfNames, pCache->Info.EatRva, pCache->Info.EatSize, exportDir->NumberOfNames);

        status = INT_STATUS_INVALID_OBJECT_TYPE;
        goto _err_exit;
    }

    pCache->Exports.Array = HpAllocWithTag(MIN(WINUMCACHE_MAX_EXPORTS,
                                               exportDir->NumberOfNames) * sizeof(*pCache->Exports.Array),
                                           IC_TAG_EXPCH);
    if (NULL == pCache->Exports.Array)
    {
        status = INT_STATUS_INSUFFICIENT_RESOURCES;
        goto _err_exit;
    }

    for (DWORD i = 0; i < MIN(WINUMCACHE_MAX_EXPORTS, exportDir->NumberOfNames); i++)
    {
        DWORD offset, exportRva, namePointer, length;
        char *name;
        WORD exportOrdinal;
        WINUM_CACHE_EXPORT *pExport, target;
        RBNODE *retNode = NULL;

        status = INT_STATUS_INVALID_OBJECT_TYPE;

        offset = (exportDir->AddressOfNameOrdinals - pCache->Info.EatRva) + i * 2;
        if (offset + sizeof(WORD) > pCache->Info.EatSize)
        {
            ERROR("[WARNING] Name ordinal %08x outside of EAT %08x:%08x (AddressOfNameOrdinals at %08x)\n",
                  offset, pCache->Info.EatRva, pCache->Info.EatRva + pCache->Info.EatSize,
                  exportDir->AddressOfNameOrdinals);

            goto _err_exit;
        }

        exportOrdinal = *(WORD *)(buffer + offset);

        if (exportOrdinal > exportDir->NumberOfFunctions)
        {
            ERROR("[WARNING] We have export ordinal %d, but only %d functions, %d names!\n",
                  exportOrdinal, exportDir->NumberOfFunctions, exportDir->NumberOfNames);

            goto _err_exit;
        }

        offset = (exportDir->AddressOfFunctions - pCache->Info.EatRva) + exportOrdinal * 4;
        if (offset + sizeof(DWORD) > pCache->Info.EatSize)
        {
            ERROR("[WARNING] Function offset %08x outside of EAT %08x:%08x (AddressOfFunctions at %08x)\n",
                  offset, pCache->Info.EatRva, pCache->Info.EatRva + pCache->Info.EatSize,
                  exportDir->AddressOfFunctions);

            goto _err_exit;
        }

        exportRva = *(DWORD *)(buffer + offset);

        offset = (exportDir->AddressOfNames - pCache->Info.EatRva) + i * 4;
        if (offset + sizeof(DWORD) > pCache->Info.EatSize)
        {
            ERROR("[WARNING] Name offset %08x outside of EAT %08x:%08x (AddressOfNames at %08x)\n",
                  offset, pCache->Info.EatRva, pCache->Info.EatRva + pCache->Info.EatSize,
                  exportDir->AddressOfNames);

            goto _err_exit;
        }

        namePointer = *(DWORD *)(buffer + offset) - pCache->Info.EatRva;
        if (namePointer >= pCache->Info.EatSize)
        {
            ERROR("[WARNING] Name pointer %08x outside of EAT %08x:%08x\n",
                  namePointer, pCache->Info.EatRva, pCache->Info.EatRva + pCache->Info.EatSize);
            goto _err_exit;
        }

        length = 0;
        name = (char *)buffer + namePointer;
        while (*name)
        {
            length++;
            name++;

            if (namePointer + length >= pCache->Info.EatSize)
            {
                ERROR("[WARNING] Name pointer %08x will be outside of EAT %08x:%08x after %d bytes\n",
                      namePointer, pCache->Info.EatRva,
                      pCache->Info.EatRva + pCache->Info.EatSize, length);
                goto _err_exit;
            }
        }

        if (namePointer + length >= pCache->Info.EatSize)
        {
            goto _err_exit;
        }

        if (pCache->Exports.StartNames > namePointer)
        {
            pCache->Exports.StartNames = namePointer;
        }

        if (pCache->Exports.EndNames < namePointer + length + 1)
        {
            pCache->Exports.EndNames = namePointer + length + 1;
        }

        target.Rva = exportRva;
        if (!INT_SUCCESS(RbLookupNode(&pCache->Exports.Tree, &target.RbNode, &retNode)) || retNode == NULL)
        {
            pExport = &pCache->Exports.Array[i];
        }
        else
        {
            pExport = CONTAINING_RECORD(retNode, WINUM_CACHE_EXPORT, RbNode);
        }

        pExport->Rva = exportRva;

        if (pExport->NumberOfOffsets < MAX_OFFSETS_PER_NAME)
        {
            pExport->NameOffsets[pExport->NumberOfOffsets++] = namePointer;
        }

        status = RbInsertNode(&pCache->Exports.Tree, &pExport->RbNode);
        if (INT_STATUS_KEY_ALREADY_EXISTS == status)
        {
            continue;
        }
    }

    if (pCache->Exports.StartNames >= pCache->Exports.EndNames)
    {
        ERROR("[ERROR] Start of names (%x) it's after (or equal tot he end of names (%x)\n",
              pCache->Exports.StartNames, pCache->Exports.EndNames);
        goto _err_exit;
    }

    pCache->Exports.Names = HpAllocWithTag(pCache->Exports.EndNames - pCache->Exports.StartNames, IC_TAG_NAME);
    if (NULL == pCache->Exports.Names)
    {
        status = INT_STATUS_INSUFFICIENT_RESOURCES;
        goto _err_exit;
    }

    memcpy(pCache->Exports.Names,
           buffer + pCache->Exports.StartNames,
           pCache->Exports.EndNames - pCache->Exports.StartNames);

    RbWalkInorderTree(&pCache->Exports.Tree, IntWinModCacheFixNamePointers, pMod);

    pCache->ExportDirRead = TRUE;

    return INT_STATUS_SUCCESS;

_err_exit:

    // This may make the Introcore inject a #PF any time this dll is loaded into a process.
    RbUninit(&pCache->Exports.Tree);

    if (pCache->Exports.Array)
    {
        HpFreeAndNullWithTag(&pCache->Exports.Array, IC_TAG_EXPCH);
    }

    return status;
}


static BOOLEAN
IntWinUmModMustCacheExports(
    _In_ DWORD NameHash
    )
///
/// @brief Checks of the exports of a module need to be cached.
///
/// @param[in]  NameHash    The hash of the module to be checked. If the hash is in the #gExportedDirsToCache
///                         array, its exports will be cached.
///
/// @returns True if the exports of the indicated module should be cached. False otherwise.
///
{
    for (DWORD i = 0; i < ARRAYSIZE(gExportedDirsToCache); i++)
    {
        if (gExportedDirsToCache[i] == NameHash)
        {
            return TRUE;
        }
    }

    return FALSE;
}


static WINUM_MODULE_CACHE *
IntWinModCacheCreate(
    _In_ WIN_PROCESS_MODULE *Module
    )
///
/// @brief Creates an exports cache entry for the provided module.
///
/// @param[in]  Module  The module for which the exports cache will be created.
///
/// @returns The newly created exports cache. NULL if a memory alloc fails.
///
{
    WINUM_MODULE_CACHE *pCache = HpAllocWithTag(sizeof(*pCache), IC_TAG_MODCH);
    if (NULL == pCache)
    {
        return NULL;
    }

    pCache->ModuleNameHash = Module->Path->NameHash;
    pCache->Wow64 = gGuest.Guest64 && (Module->Subsystem->SubsystemType == winSubsys32Bit);
    pCache->Dirty = Module->Subsystem->Process->StaticDetected != 0 || Module->Subsystem->Process->LateProtection;

    TRACE("[WINUMCACHE] Create cache for module '%s', wow64: %d, dirty: %d.\n",
          utf16_for_log(Module->Path->Name), pCache->Wow64, pCache->Dirty);

    InsertTailList(&gWinUmCaches, &pCache->Link);

    return pCache;
}


static INTSTATUS
IntWinUmModCacheFillExports(
    _In_ WIN_PROCESS_MODULE *Module
    )
///
/// @brief Fills the exports cache of the provided module with each exported symbol.
///
/// NOTE: Export sections larger than #ONE_MEGABYTE will not be parsed.
///
/// @param[in]  Module  The module whose exports will be read & cached.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_ALREADY_INITIALIZED_HINT If the exports of this module have already been cached.
/// @retval #INT_STATUS_NOT_NEEDED_HINT If there's no need to cache the exports of this module.
/// @retval #INT_STATUS_NOT_SUPPORTED If the exports section exceeds #ONE_MEGABYTE in size.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;
    WINUM_MODULE_CACHE *pCache = Module->Cache;

    if (NULL != pCache->Exports.Array)
    {
        TRACE("[INFO] Already filled cache for module %s\n", utf16_for_log(Module->Path->Path));
        return INT_STATUS_ALREADY_INITIALIZED_HINT;
    }

    RbPreinit(&pCache->Exports.Tree);

    RbInit(&pCache->Exports.Tree, IntWinModCacheExportNodeFree, IntWinModCacheExportNodeCompare);

    if (!IntWinUmModMustCacheExports(Module->Path->NameHash))
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    if ((pCache->Info.EatRva >= pCache->Info.SizeOfImage) ||
        ((QWORD)pCache->Info.EatRva + pCache->Info.EatSize > pCache->Info.SizeOfImage))
    {
        ERROR("[ERROR] EAT %08x:%08x points outside image (%08x) for module %s!\n",
              pCache->Info.EatRva, pCache->Info.EatSize, pCache->Info.SizeOfImage,
              utf16_for_log(Module->Path->Path));

        status = INT_STATUS_INVALID_OBJECT_TYPE;
        goto _cleanup_and_exit;
    }

    if (pCache->Info.EatSize > ONE_MEGABYTE)
    {
        ERROR("[WARNING] Module '%s' has EAT bigger than 1 MB: %08x:%08x\n",
              utf16_for_log(Module->Path->Path), pCache->Info.EatRva, pCache->Info.EatSize);

        status = INT_STATUS_NOT_SUPPORTED;
        goto _cleanup_and_exit;
    }

    status = IntSwapMemReadData(Module->Subsystem->Process->Cr3,
                                Module->VirtualBase + pCache->Info.EatRva,
                                pCache->Info.EatSize,
                                SWAPMEM_OPT_UM_FAULT,
                                Module,
                                0,
                                IntWinModHandleExportsInMemory,
                                NULL,
                                &Module->ExportsSwapHandle);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntSwapMemReadData failed for 0x%016llx, 0x%x: 0x%08x\n",
              Module->VirtualBase + pCache->Info.EatRva, pCache->Info.EatSize, status);
    }

_cleanup_and_exit:
    if (!INT_SUCCESS(status))
    {
        RbUninit(&pCache->Exports.Tree);
    }
    else
    {
        TRACE("[WINUMCACHE] Fill export cache for module '%s', wow64 %d.\n",
              utf16_for_log(Module->Path->Name), pCache->Wow64);
    }

    return status;
}


static INTSTATUS
IntWinUmModCacheFillHeaders(
    _In_ WIN_PROCESS_MODULE *Module,
    _In_ BYTE *Headers
    )
///
/// @brief Fills MZ/PE headers information for the provided module.
///
/// This function will allocate the headers page, it will validate the MZ/PE headers of this module, and it will
/// fill some basic info inside the cache structure (such as IAT/EAT RVA). It will not read the exports.
///
/// @param[in]  Module  The module for which the headers info will be initialized.
/// @param[in]  Headers A pointer to a buffer containing the MZ/PE if the indicated module.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_ALREADY_INITIALIZED_HINT If the headers have already been filled.
///
{
    INTSTATUS status;
    WINUM_MODULE_CACHE *pCache = Module->Cache;
    IMAGE_DATA_DIRECTORY iatDirectory = { 0 };
    IMAGE_DATA_DIRECTORY eatDirectory = { 0 };
    INTRO_PE_INFO peInfo = { 0 };

    if (pCache->Headers != NULL)
    {
        return INT_STATUS_ALREADY_INITIALIZED_HINT;
    }

    status = IntPeValidateHeader(Module->VirtualBase, Headers, PAGE_SIZE, &peInfo, 0);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] We have invalid headers for module '%s'!\n",
              utf16_for_log(Module->Path->Name));
        return status;
    }

    status = IntPeGetDirectory(Module->VirtualBase, Headers, IMAGE_DIRECTORY_ENTRY_IAT, &iatDirectory);
    if (!INT_SUCCESS(status) && status != INT_STATUS_NOT_FOUND)
    {
        ERROR("[ERROR] IntPeGetDirectory failed: 0x%08x\n", status);
        return status;
    }

    status = IntPeGetDirectory(Module->VirtualBase, Headers, IMAGE_DIRECTORY_ENTRY_EXPORT, &eatDirectory);
    if (!INT_SUCCESS(status) && status != INT_STATUS_NOT_FOUND)
    {
        ERROR("[ERROR] IntPeGetDirectory failed: 0x%08x\n", status);
        return status;
    }

    pCache->Headers = HpAllocWithTag(PAGE_SIZE, IC_TAG_HDRS);
    if (NULL == pCache->Headers)
    {
        return status;
    }

    memcpy(pCache->Headers, Headers, 4096);

    TRACE("[WINUMCACHE] Fill header cache for module '%s', wow64: %d\n",
          utf16_for_log(Module->Path->Name), pCache->Wow64);

    pCache->Info.IatRva = iatDirectory.VirtualAddress;
    pCache->Info.IatSize = iatDirectory.Size;

    pCache->Info.EatRva = eatDirectory.VirtualAddress;
    pCache->Info.EatSize = eatDirectory.Size;

    pCache->Info.SizeOfImage = peInfo.SizeOfImage;
    pCache->Info.TimeDateStamp = peInfo.TimeDateStamp;
    Module->Size = peInfo.SizeOfImage;

    Module->Is64BitModule = peInfo.Image64Bit;

    if ((Module->Is64BitModule && (Module->Subsystem->SubsystemType != winSubsys64Bit)) ||
        (!Module->Is64BitModule && (Module->Subsystem->SubsystemType == winSubsys64Bit)))
    {
        ERROR("[ERROR] %d/%d invalid for module '%s'\n",
              Module->Is64BitModule, (Module->Subsystem->SubsystemType == winSubsys64Bit),
              utf16_for_log(Module->Path->Path));
    }

    if (pCache->Info.SizeOfImage > Module->Size)
    {
        WARNING("[WARNING] Shady image size for module '%s': 0x%x/0x%x\n",
                utf16_for_log(Module->Path->Path), pCache->Info.SizeOfImage, Module->Size);
    }

    if ((pCache->Info.IatRva >= pCache->Info.SizeOfImage) ||
        (pCache->Info.IatSize > pCache->Info.SizeOfImage) ||
        ((QWORD)pCache->Info.IatRva + pCache->Info.IatSize > pCache->Info.SizeOfImage))
    {
        WARNING("[WARNING] Shady IAT for module '%s': RVA = %x, size = 0x%x\n",
                utf16_for_log(Module->Path->Path), pCache->Info.IatRva, pCache->Info.IatSize);
    }

    if ((pCache->Info.EatRva >= pCache->Info.SizeOfImage) ||
        (pCache->Info.EatSize > pCache->Info.SizeOfImage) ||
        ((QWORD)pCache->Info.EatRva + pCache->Info.EatSize > pCache->Info.SizeOfImage))
    {
        WARNING("[WARNING] Shady EAT for module %s: RVA = %x, size = 0x%x, image size = 0x%x\n",
                utf16_for_log(Module->Path->Path), pCache->Info.EatRva,
                pCache->Info.EatSize, pCache->Info.SizeOfImage);
    }

    return INT_STATUS_SUCCESS;
}


static WINUM_MODULE_CACHE *
IntWinUmModCacheFetch(
    _In_ WIN_PROCESS_MODULE *Module
    )
///
/// @brief Returns the cache associated with the provided module.
///
/// This function will iterate the global list of caches, trying to find the cache associated with the provided
/// module.
/// NOTE: Dirty caches (those identified statically) are ignored.
///
/// @param[in]  Module  The module for which we wish to find a cache entry.
///
/// @returns A pointer to a #WINUM_MODULE_CACHE structure, if a module cache is found. NULL otherwise.
///
{
    BOOLEAN wow64 = gGuest.Guest64 && (Module->Subsystem->SubsystemType == winSubsys32Bit);

    LIST_ENTRY *list = gWinUmCaches.Flink;
    while (list != &gWinUmCaches)
    {
        WINUM_MODULE_CACHE *pCache = CONTAINING_RECORD(list, WINUM_MODULE_CACHE, Link);
        list = list->Flink;

        if (pCache->ModuleNameHash == Module->Path->NameHash &&
            pCache->Wow64 == wow64 &&
            !pCache->Dirty)
        {
            TRACE("[WINUMCACHE] Reuse cache for module '%s'\n", utf16_for_log(Module->Path->Name));
            return pCache;
        }
    }

    return NULL;
}


void
IntWinUmModCacheGet(
    _In_ WIN_PROCESS_MODULE *Module
    )
///
/// @brief Initializes the cache for the provided module.
///
/// If a cache already exists for the indicated module (because an instance of it has already been loaded),
/// it will be used for this module as well. Otherwise, a new cache will be created for this module. If other
/// instances of this module get loaded, they will be able to reuse the same cache structure.
///
/// @param[in]  Module  The module for which the cache is to be created.
///
{
    Module->Cache = IntWinUmModCacheFetch(Module);
    if (NULL != Module->Cache)
    {
        return;
    }

    Module->Cache = IntWinModCacheCreate(Module);
}


static void
IntWinUmCacheRemoveCache(
    _In_ WINUM_MODULE_CACHE *Cache
    )
///
/// @brief Removes a module cache.
///
/// This function will permanently remove the cache entry. Care must be taken to ensure that no modules reference
/// this cache structure (ie, all instances of the module for which this cache was created have unloaded).
///
/// @param[in]  Cache   The cache entry to be removed.
///
{
    if (NULL == Cache)
    {
        return;
    }

    RemoveEntryList(&Cache->Link);

    if (Cache->Exports.Array != NULL)
    {
        RbUninit(&Cache->Exports.Tree);
        HpFreeAndNullWithTag(&Cache->Exports.Array, IC_TAG_EXPCH);
    }

    if (NULL != Cache->Exports.Names)
    {
        HpFreeAndNullWithTag(&Cache->Exports.Names, IC_TAG_NAME);
    }

    if (Cache->Headers != NULL)
    {
        HpFreeAndNullWithTag(&Cache->Headers, IC_TAG_HDRS);
    }

    HpFreeAndNullWithTag(&Cache, IC_TAG_MODCH);
}


void
IntWinUmModCacheRelease(
    _In_ WINUM_MODULE_CACHE *Cache
    )
///
/// @brief Removes a module cache, if it was written (it's dirty).
///
/// NOTE: This function gets called when a module is unloaded. However, we will not destroy the cache,
/// unless it is dirty (it has been loaded statically).
///
/// @param[in]  Cache   The cache to be removed if dirty.
///
{
    if (NULL == Cache)
    {
        return;
    }

    if (Cache->Dirty)
    {
        IntWinUmCacheRemoveCache(Cache);
    }
}


INTSTATUS
IntWinUmModCacheSetHeaders(
    _In_ WIN_PROCESS_MODULE *Module,
    _In_reads_bytes_(4096) BYTE *Headers
    )
///
/// @brief Sets the MZ/PE headers in the cache of a given module.
///
/// @param[in]  Module  The module whose headers are to be set.
/// @param[in]  Headers Buffer containing the MZ/PE headers.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    INTSTATUS status;

    if (Module == NULL)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    status = IntWinUmModCacheFillHeaders(Module, Headers);
    if (!INT_SUCCESS(status))
    {
        WARNING("[WARNING] Failed to fill header cache with status: 0x%08X.\n", status);
        return status;
    }

    status = IntWinUmModCacheFillExports(Module);
    if (!INT_SUCCESS(status))
    {
        WARNING("[WARNING] Failed to fill export cache with status: 0x%08X.\n", status);
    }

    return status;
}


BOOLEAN
IntWinUmCacheIsExportDirRead(
    _In_ WIN_PROCESS_MODULE *Module
    )
///
/// @brief Checks if the exports directory of the given module has been read.
///
/// @returns True if the exports dir has been read, or false otherwise.
///
{
    if (NULL == Module || NULL == Module->Cache)
    {
        return FALSE;
    }

    return Module->Cache->ExportDirRead;
}


void
IntWinUmCacheUninit(
    void
    )
///
/// @brief Uninit the module cache system. This will remove all cache entries. Use this during Introcore uninit.
///
{
    LIST_ENTRY *list = gWinUmCaches.Flink;
    while (list != &gWinUmCaches)
    {
        WINUM_MODULE_CACHE *pCache = CONTAINING_RECORD(list, WINUM_MODULE_CACHE, Link);

        list = list->Flink;

        IntWinUmCacheRemoveCache(pCache);
    }
}
