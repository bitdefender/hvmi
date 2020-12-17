/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "winvad.h"
#include "hook.h"
#include "processor.h"
#include "swapmem.h"
#include "winprocesshp.h"
#include "shellcode.h"
#include "winummodule.h"
#include "winthread.h"
#include "exceptions.h"
#include "alerts.h"
#include "scan_engines.h"
#include "winnet.h"

/// The maximum number of tries to make when searching for a VAD inside the guest.
#define VAD_SEARCH_LIMIT 1000
/// The maximum number of execution from a VAD that Introcore will take into consideration.
#define MAX_VAD_EXECS   64u

static INTSTATUS
IntWinVadHandleInsertGeneric(
    _Inout_ WIN_PROCESS_OBJECT *Process,
    _In_ QWORD VadAddress,
    _In_ BOOLEAN StaticScan,
    _Out_opt_ VAD **Vad
    );


static __forceinline BYTE *
IntWinVadMapShortVad(
    _In_ QWORD Gva
    )
///
/// @brief      Maps a _MMVAD_SHORT structure inside Introcore.
///
/// This maps the minimum size needed for Introcore to properly parse the VAD. This size is defined by CAMI, see
/// #winKmFieldVadShortSize.
///
/// @param[in]  Gva     Guest virtual address to map. No checks are done on this address.
///
/// @returns    A pointer to a memory area that contains the mapped VAD. #IntVirtMemUnmap should be used to unmap this
/// when it is no longer needed. Internally, #IntVirtMemMap is used to map the VAD. If it fails, this function will
/// return NULL.
///
{
    void *ptr = NULL;

    if (!INT_SUCCESS(IntVirtMemMap(Gva, WIN_KM_FIELD(VadShort, Size), gGuest.Mm.SystemCr3, 0, &ptr)))
    {
        return NULL;
    }

    return ptr;
}

/// @brief       Gives a pointer to a field of a _MMVAD_SHORT structure.
///
/// @param[in]  type_   The type of the field.
/// @param[in]  ptr_    The pointer to the base of the VAD. This is the start of the buffer in which the VAD structure
///                     was read (for example, the pointer returned by #IntWinVadMapShortVad). The buffer should be
///                     large enough for the requested field to be inside it.
/// @param[in]  field_  The name of the field. This is the same name that would be used for the #WIN_KM_FIELD macro.
///
/// @returns    A pointer of type type_ inside the VAD buffer.
#define VAD_SHORT_FIELD_PTR(type_, ptr_, field_) (type_ *)((BYTE *)(ptr_) + WIN_KM_FIELD(VadShort, field_))

/// @brief       Gives a pointer to a field of a _MMVAD_LONG structure.
///
/// @param[in]  type_   The type of the field.
/// @param[in]  ptr_    The pointer to the base of the VAD. This is the start of the buffer in which the VAD structure
///                     was read. The buffer should be large enough for the requested field to be inside it.
/// @param[in]  field_  The name of the field. This is the same name that would be used for the #WIN_KM_FIELD macro.
///
/// @returns    A pointer of type type_ inside the VAD buffer.
#define VAD_LONG_FIELD_PTR(type_, ptr_, field_) (type_ *)((BYTE *)(ptr_) + WIN_KM_FIELD(VadLong, field_))

/// @brief      Reads a byte from a VAD short buffer.
///
/// This is useful for reading _MMVAD_SHORT fields that have a size of a BYTE.
///
/// @param[in]  ptr_    The pointer to the base of the VAD. This is the start of the buffer in which the VAD structure
///                     was read (for example, the pointer returned by #IntWinVadMapShortVad). The buffer should be
///                     large enough for the requested field to be inside it.
/// @param[in]  field_  The name of the field. This is the same name that would be used for the #WIN_KM_FIELD macro.
///
/// @returns    The first byte of the field_ value inside the _MMVAD_SHORT structure.
#define VadShortByte(ptr_, field_) *VAD_SHORT_FIELD_PTR(BYTE, ptr_, field_)

/// @brief      Reads a word from a VAD short buffer.
///
/// This is useful for reading _MMVAD_SHORT fields that have a size of a WORD.
///
/// @param[in]  ptr_    The pointer to the base of the VAD. This is the start of the buffer in which the VAD structure
///                     was read (for example, the pointer returned by #IntWinVadMapShortVad). The buffer should be
///                     large enough for the requested field to be inside it.
/// @param[in]  field_  The name of the field. This is the same name that would be used for the #WIN_KM_FIELD macro.
///
/// @returns    The first word of the field_ value inside the _MMVAD_SHORT structure.
#define VadShortWord(ptr_, field_) *VAD_SHORT_FIELD_PTR(WORD, ptr_, field_)

/// @brief      Reads a dword from a VAD short buffer.
///
/// This is useful for reading _MMVAD_SHORT fields that have a size of a DWORD.
///
/// @param[in]  ptr_    The pointer to the base of the VAD. This is the start of the buffer in which the VAD structure
///                     was read (for example, the pointer returned by #IntWinVadMapShortVad). The buffer should be
///                     large enough for the requested field to be inside it.
/// @param[in]  field_  The name of the field. This is the same name that would be used for the #WIN_KM_FIELD macro.
///
/// @returns    The first dword of the field_ value inside the _MMVAD_SHORT structure.
#define VadShortDword(ptr_, field_) *VAD_SHORT_FIELD_PTR(DWORD, ptr_, field_)

/// @brief      Reads a qword from a VAD short buffer.
///
/// This is useful for reading _MMVAD_SHORT fields that have a size of a QWORD.
///
/// @param[in]  ptr_    The pointer to the base of the VAD. This is the start of the buffer in which the VAD structure
///                     was read (for example, the pointer returned by #IntWinVadMapShortVad). The buffer should be
///                     large enough for the requested field to be inside it.
/// @param[in]  field_  The name of the field. This is the same name that would be used for the #WIN_KM_FIELD macro.
///
/// @returns    The first qword of the field_ value inside the _MMVAD_SHORT structure.
#define VadShortQword(ptr_, field_) *VAD_SHORT_FIELD_PTR(QWORD, ptr_, field_)

/// @brief      Reads a guest pointer from a VAD short buffer.
///
/// This is useful for reading _MMVAD_SHORT fields that have the size of a guest pointer (#GUEST_STATE.WordSize). This
/// means that it will read either a DWORD or a QWORD.
///
/// @param[in]  ptr_    The pointer to the base of the VAD. This is the start of the buffer in which the VAD structure
///                     was read (for example, the pointer returned by #IntWinVadMapShortVad). The buffer should be
///                     large enough for the requested field to be inside it.
/// @param[in]  field_  The name of the field. This is the same name that would be used for the #WIN_KM_FIELD macro.
///
/// @returns    The first DWORD or QWORD of the field_ value inside the _MMVAD_SHORT structure.
#define VadShortPtrSize(ptr_, field_) gGuest.Guest64 ? VadShortQword(ptr_, field_) : VadShortDword(ptr_, field_)

/// @brief      Reads a certain size from a VAD short buffer.
///
/// @param[in]  size_   Size to read. Valid sizes are 1, 2, 4, or 8. For other sizes memcpy is better suited. No
///                     checks are done on the size.
/// @param[in]  ptr_    The pointer to the base of the VAD. This is the start of the buffer in which the VAD structure
///                     was read (for example, the pointer returned by #IntWinVadMapShortVad). The buffer should be
///                     large enough for the requested field to be inside it.
/// @param[in]  field_  The name of the field. This is the same name that would be used for the #WIN_KM_FIELD macro.
///
/// @returns    The value obtained from the field_. 0 Will be returned for unsupported sizes.
#define VadShortAnySize(size_, ptr_, field_)    (size_) == 8 ? VadShortQword(ptr_, field_) : \
                                                (size_) == 4 ? VadShortDword(ptr_, field_) : \
                                                (size_) == 2 ? VadShortWord(ptr_, field_) : \
                                                (size_) == 1 ? VadShortByte(ptr_, field_) : 0


static __forceinline BOOLEAN
IntWinVadIsProbablyNaCl(
    _In_ VAD const *Vad
    )
///
/// @brief      Checks if a VAD is used by the Chrome's NaCl mechanism.
///
/// @param[in]  Vad     The VAD structure to check.
///
/// @returns    True if the VAD is probably used by NaCl; False if it is not used.
///
{
    // NaCl regions come in chunks of 16 pages as private memory, ignore them
    return Vad->Process->HasNaClEnabled && 16 == Vad->PageCount && VadNone == Vad->VadType;
}


static BOOLEAN
IntWinVadIsProbablyDominoJava(
    _In_ VAD const *Vad
    )
///
/// @brief      Checks if a VAD is used by Domino Java.
///
/// Java IBM Domino VADs are ignored if their type is Private, protection is #VAD_PROT_EXECUTE_READWRITE and
/// the j9jit.dll is already loaded in the current process (the #WIN_PROCESS_OBJECT.IsDominoJava flag is set).
///
/// @param[in]  Vad     The VAD structure to check.
///
/// @returns    True if the VAD is probably used by Domino Java; False if it is not used.
///

{
    return Vad->VadType == VadNone &&
           (Vad->VadProtection & VAD_PROT_EXECUTE_READWRITE) &&
           Vad->Process->IsDominoJava &&
           !Vad->Process->FirstDominoJavaIgnored;
}


static INTSTATUS
IntWinVadRemoveRange(
    _Inout_ VAD *Vad,
    _In_ QWORD StartPage,
    _In_ QWORD EndPage
    )
///
/// @brief          Removes a memory range from a VAD.
///
/// This will remove the execution hook for all the pages in the given range, and will free the #VAD_PAGE structures
/// for the given range. The [StartPage, EndPage] range is inclusive.
///
/// Errors encountered while unhooking the pages are logged, but are not propagated back to the caller.
///
/// @param[in, out] Vad         The VAD for which the range is removed.
/// @param[in]      StartPage   The first page in the VAD.
/// @param[in]      EndPage     The last page in the VAD.
///
/// @retval         #INT_STATUS_SUCCESS in case of success.
/// @retval         #INT_STATUS_NOT_NEEDED_HINT if there are no pages allocated for this VAD.
///
{
    INTSTATUS status;

    if (NULL == Vad->VadPages)
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    for (QWORD curpg = (StartPage & PAGE_MASK); curpg <= (EndPage & PAGE_MASK); curpg += PAGE_SIZE)
    {
        DWORD pos = (DWORD)((curpg - Vad->StartPage) >> 12);

        if (NULL == Vad->VadPages[pos])
        {
            continue;
        }

        if (NULL != Vad->VadPages[pos]->ExecHook)
        {
            // The page was hooked
            status = IntHookGvaRemoveHook((HOOK_GVA **)&Vad->VadPages[pos]->ExecHook, 0);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntHookGvaRemoveHook failed: 0x%08x\n", status);
            }
        }

        HpFreeAndNullWithTag(&Vad->VadPages[pos], IC_TAG_VAD_PAGE);
    }

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntWinVadRemoveAllPages(
    _Inout_ VAD *Vad
    )
///
/// @brief          Removes all pages from a VAD.
///
/// This unhooks and frees all the entries in the #VAD.VadPages array and frees the array itself at the end.
///
/// @param[in, out] Vad     The VAD for which the pages will be removed.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value
///
{
    INTSTATUS status;

    status = INT_STATUS_SUCCESS;
    if (NULL != Vad->VadPages)
    {
        status = IntWinVadRemoveRange(Vad, Vad->StartPage, Vad->EndPage);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntWinVadRemoveRange failed for VAD 0x%016llx: 0x%08x\n", Vad->VadGva, status);
        }

        HpFreeAndNullWithTag(&Vad->VadPages, IC_TAG_VAD_PGARR);
    }

    return status;
}


void
IntWinVadDestroyObject(
    _Inout_ VAD **Vad
    )
///
/// @brief  Frees a VAD and all the resources held by it.
///
/// This will remove any pending #IntSwapMemReadData transactions, will remove all the #VAD_PAGE structures for the
/// VAD, and if this VAD maps a module, that module will be unloaded, as well as dereferencing the #WINUM_PATH cache
/// entry.
///
/// @param[in, out] Vad     Holds a pointer to the VAD to be destroyed. On return, this will point to NULL.
///
{
    INTSTATUS status;
    PVAD pVad;

    if (NULL == Vad || NULL == *Vad)
    {
        return;
    }

    pVad = *Vad;
    *Vad = NULL;

    // Remove the VAD transaction, if any.
    if (pVad->PathSwapHandle)
    {
        status = IntSwapMemRemoveTransaction(pVad->PathSwapHandle);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntSwapMemRemoveTransactionsForAddress failed: 0x%08x\n", status);
        }

        pVad->PathSwapHandle = NULL;
    }

    if ((VadImageMap == pVad->VadType) && (NULL != pVad->Path))
    {
        status = IntWinModHandleUnloadFromVad(pVad->Process, pVad);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntWinModHandleUnloadFromVad failed: 0x%08x\n", status);
        }
    }

    IntWinUmPathDereference(&pVad->Path);

    // Remove all the pages from this VAD.
    IntWinVadRemoveAllPages(pVad);

    HpFreeAndNullWithTag(&pVad, IC_TAG_VAD);
}


_Function_class_(FUNC_RbTreeNodeFree) static void
IntWinVadRbTreeNodeFree(
    _Inout_ RBNODE *Node
    )
///
/// @brief          The node free callback used by the #WIN_PROCESS_OBJECT.VadTree tree.
///
/// @param[in, out] Node    Pointer to the node to be freed.
///
{
    PVAD pVad = CONTAINING_RECORD(Node, VAD, RbNode);

    IntWinVadDestroyObject(&pVad);
}


_Function_class_(FUNC_RbTreeNodeCompare) static int
IntWinVadRbTreeNodeCompare(
    _In_ RBNODE const *Left,
    _In_ RBNODE const *Right
    )
///
/// @brief      The node compare callback used by the #WIN_PROCESS_OBJECT.VadTree tree.
///
/// This compares the ranges that two VADs map.
///
/// @param[in]  Left    First node to compare.
/// @param[in]  Right   Second node to compare.
///
/// @retval     -1 if the range of the Left VAD is lower in memory than that of the Right VAD.
/// @retval     1 if the range of the Left VAD is higher in memory than tat of the Left VAD.
/// @retval     0 in all other cases. This means that the VADs overlap in some way, but a process can not have
/// overlapping VADs, so this means that the Left and Right VADs are the same.
///
{
    VAD const *p1 = CONTAINING_RECORD(Left, VAD, RbNode);
    VAD const *p2 = CONTAINING_RECORD(Right, VAD, RbNode);

    if (p1->EndPage < p2->StartPage)
    {
        return -1;
    }
    else if (p1->StartPage > p2->EndPage)
    {
        return 1;
    }
    else
    {
        return 0;
    }
}


_Function_class_(FUNC_RbTreeNodeCustomCompare) static int
IntWinVadRbTreeNodeCompareVa(
    _In_ RBNODE const *Node,
    _In_ void *Key
    )
///
/// @brief      Custom compare function for a VAD #RBTREE. This will compare VADs against a given guest virtual address.
///
/// @param[in]  Node    Node to be compared.
/// @param[in]  Key     Key to compare against. In this case, the key is a guest virtual address.
///
/// @retval     0 if Key is inside the memory range mapped by the VAD.
/// @retval     -1 if the Key is lower in memory than the start of the memory range mapped by the VAD.
/// @retval     1 if the Key is higher in memory than the end of the memory range mapped by the VAD.
///
{
    QWORD gva = (QWORD)Key;
    VAD const *vad = CONTAINING_RECORD(Node, VAD, RbNode);

    if (gva >= vad->StartPage && gva < vad->StartPage + vad->PageCount * PAGE_SIZE)
    {
        return 0;
    }
    else if (vad->StartPage < gva)
    {
        return -1;
    }
    else
    {
        return 1;
    }
}


_Function_class_(FUNC_RbTreeNodeCustomCompare) static int
IntWinVadRbTreeNodeCompareBases(
    _In_ RBNODE const *Node,
    _In_ void *Key
    )
///
/// @brief      Custom compare function for a VAD #RBTREE. This will compare a VAD start page with a given guest
/// virtual address.
///
/// @param[in]  Node    Node to be compared.
/// @param[in]  Key     Key to compare against. In this case, the key is a guest virtual address.
///
/// @retval     0 if Key is the same as the #VAD.StartPage.
/// @retval     -1 if the Key is lower in memory than the start of the memory range mapped by the VAD.
/// @retval     1 if the Key is higher in memory than the end of the memory range mapped by the VAD.
///
{
    QWORD base = (QWORD)Key;
    VAD const *vad = CONTAINING_RECORD(Node, VAD, RbNode);

    if (base == vad->StartPage)
    {
        return 0;
    }
    else if (vad->StartPage < base)
    {
        return -1;
    }
    else
    {
        return 1;
    }
}


void
IntWinVadProcessInit(
    _Inout_ WIN_PROCESS_OBJECT *Process
    )
///
/// @brief  Initializes a #WIN_PROCESS_OBJECT.VadTree.
///
/// This will call RbPreInit and RbInit for the tree and set #IntWinVadRbTreeNodeFree as the #RBTREE.NodeFree
/// function and #IntWinVadRbTreeNodeCompare as the #RBTREE.NodeCompare function.
///
/// @param[in, out] Process The process for which the VAD tree will be initialized.
///
{
    RbPreinit(&Process->VadTree);

    RbInit(&Process->VadTree, IntWinVadRbTreeNodeFree, IntWinVadRbTreeNodeCompare);
}


static DWORD
IntWinVadVmProtectionToIntroProtection(
    _In_ DWORD VmProtection
    )
///
/// @brief  Converts Windows memory protection constants to Introcore protection flags.
///
/// @param[in]  VmProtection    A Windows memory protection constant.
///                             See https://docs.microsoft.com/en-us/windows/win32/memory/memory-protection-constants
///
/// @returns    Introcore protection rights. This will be a combination of #PROT_READ, #PROT_WRITE, and #PROT_EXEC. If
///             VmProtection is #WIN_MM_PAGE_NOACCESS the return value is 0.
///
{
    // High bits represent NoCache, Guard & WriteCombine.
    VmProtection &= 0xFF;

    switch (VmProtection)
    {
    case WIN_MM_PAGE_NOACCESS:
        return 0;
    case WIN_MM_PAGE_READONLY:
        return PROT_READ;
    case WIN_MM_PAGE_READWRITE:
        return PROT_READ | PROT_WRITE;
    case WIN_MM_PAGE_WRITECOPY:
        return PROT_READ | PROT_WRITE;
    case WIN_MM_PAGE_EXECUTE:
        return PROT_EXEC;
    case WIN_MM_PAGE_EXECUTE_READ:
        return PROT_READ | PROT_EXEC;
    case WIN_MM_PAGE_EXECUTE_READWRITE:
        return PROT_READ | PROT_WRITE | PROT_EXEC;
    case WIN_MM_PAGE_EXECUTE_WRITECOPY:
        return PROT_READ | PROT_WRITE | PROT_EXEC;
    default:
        return 0;
    }
}


static DWORD
IntWinVadVadProtectionToIntroProtection(
    _In_ WIN_VAD_PROT VadProtection
    )
///
/// @brief  Converts Windows VAD protection rights to Introcore protection rights.
///
/// @param[in]  VadProtection   The VAD protection rights.
///
/// @returns    Introcore protection rights. This will be a combination of #PROT_READ, #PROT_WRITE, and #PROT_EXEC.
///             For unknown VAD protection rights, the value returned is 0.
///
{
    // High bits represent NoCache, Guard & WriteCombine.
    VadProtection &= 0xFF;

    switch (VadProtection)
    {
    case VAD_PROT_NOACCESS:
        return 0;
    case VAD_PROT_READONLY:
        return PROT_READ;
    case VAD_PROT_READWRITE:
        return PROT_READ | PROT_WRITE;
    case VAD_PROT_WRITECOPY:
        return PROT_READ | PROT_WRITE;
    case VAD_PROT_EXECUTE:
        return PROT_EXEC;
    case VAD_PROT_EXECUTE_READ:
        return PROT_READ | PROT_EXEC;
    case VAD_PROT_EXECUTE_READWRITE:
        return PROT_READ | PROT_WRITE | PROT_EXEC;
    case VAD_PROT_EXECUTE_WRITECOPY:
        return PROT_READ | PROT_WRITE | PROT_EXEC;
    default:
        return 0;
    }
}


static DWORD
IntWinVadVadProtectionToVmProtection(
    _In_ WIN_VAD_PROT VadProtection
    )
///
/// @brief  Converts Windows VAD protection rights to a Windows memory protection constant.
///
/// @param[in]  VadProtection   The VAD protection rights.
///
/// @returns    One of the Windows memory protection constants.
///             See https://docs.microsoft.com/en-us/windows/win32/memory/memory-protection-constants
///
{
    // High bits represent NoCache, Guard & WriteCombine.
    VadProtection &= 0xFF;

    switch (VadProtection)
    {
    case VAD_PROT_NOACCESS:
        return WIN_MM_PAGE_NOACCESS;
    case VAD_PROT_READONLY:
        return WIN_MM_PAGE_READONLY;
    case VAD_PROT_READWRITE:
        return WIN_MM_PAGE_READWRITE;
    case VAD_PROT_WRITECOPY:
        return WIN_MM_PAGE_WRITECOPY;
    case VAD_PROT_EXECUTE:
        return WIN_MM_PAGE_EXECUTE;
    case VAD_PROT_EXECUTE_READ:
        return WIN_MM_PAGE_EXECUTE_READ;
    case VAD_PROT_EXECUTE_READWRITE:
        return WIN_MM_PAGE_EXECUTE_READWRITE;
    case VAD_PROT_EXECUTE_WRITECOPY:
        return WIN_MM_PAGE_EXECUTE_WRITECOPY;
    default:
        return 0;
    }
}


VAD *
IntWinVadFindByVa(
    _In_ WIN_PROCESS_OBJECT *Process,
    _In_ QWORD Va
    )
///
/// @brief  Finds a VAD that contains a given guest virtual address.
///
/// @param[in]  Process The process that owns the VAD tree in which the search is done.
/// @param[in]  Va      The VA for which the search is done.
///
/// @returns    A pointer to a #VAD that contains the given guest virtual address, or NULL if no VAD is found.
///
{
    PRBNODE found = NULL;

    RbLookupNodeCustomCompare(&Process->VadTree, IntWinVadRbTreeNodeCompareVa, (void *)Va, &found);

    if (!found)
    {
        return NULL;
    }

    return CONTAINING_RECORD(found, VAD, RbNode);
}


static VAD *
IntWinVadFindByRange(
    _In_ PWIN_PROCESS_OBJECT Process,
    _In_ QWORD StartPage,
    _In_ QWORD EndPage
    )
///
/// @brief  Finds a VAD by the range it maps.
///
/// The [StartPage, EndPage] range is inclusive.
///
/// @param[in]  Process     The process that owns the VAD tree in which the search is done.
/// @param[in]  StartPage   The first page in the searched range.
/// @param[in]  EndPage     The last page in the searched range.
///
/// @returns    A pointer to a #VAD that matches the given guest virtual address range, or NULL if no VAD is found.
///
{
    VAD target;
    PRBNODE found;

    target.StartPage = StartPage;
    target.EndPage = EndPage;

    found = NULL;

    RbLookupNode(&Process->VadTree, &target.RbNode, &found);

    if (!found)
    {
        return NULL;
    }

    return CONTAINING_RECORD(found, VAD, RbNode);
}


static PVAD
IntWinVadFindByBase(
    _In_ PWIN_PROCESS_OBJECT Process,
    _In_ QWORD Base
    )
///
/// @brief  Finds a VAD by the start of the virtual address range it represents.
///
/// The [StartPage, EndPage] range is inclusive.
///
/// @param[in]  Process The process that owns the VAD tree in which the search is done.
/// @param[in]  Base    The base of the virtual address range.
///
/// @returns    A pointer to a #VAD that starts with Base, or NULL if no VAD is found.
///
{
    PRBNODE found = NULL;

    RbLookupNodeCustomCompare(&Process->VadTree, IntWinVadRbTreeNodeCompareBases, (void *)Base, &found);

    if (!found)
    {
        return NULL;
    }

    return CONTAINING_RECORD(found, VAD, RbNode);
}


static INTSTATUS
IntWinVadAdjustRange(
    _Inout_ VAD *Vad,
    _In_ QWORD NewStartPage,
    _In_ QWORD NewEndPage
    )
///
/// @brief  Modifies the range of pages owned by a VAD.
///
/// This can happen when the guest deletes part of a VAD. In that case we remove the #VAD_PAGE structures allocated
/// for that range and we shrink the #VAD.VadPages array and will adjust #VAD.PageCount, #VAD.StartPage, and
/// #VAD.EndPage.
///
/// The [NewStartPage, NewEndPage] range is inclusive. All the pages that are not in this range will be removed.
/// The range must be included in the current [#VAD.StartPage, #VAD.EndPage] range.
///
/// @param[in, out] Vad             The VAD to adjust.
/// @param[in]      NewStartPage    The new #VAD.StartPage value.
/// @param[out]     NewEndPage      The new #VAD.EndPage value.
///
/// @retval         #INT_STATUS_SUCCESS in case of success.
/// @retval         #INT_STATUS_INSUFFICIENT_RESOURCES if the new #VAD.VadPages array can not be allocated.
///
{
    INTSTATUS status;
    VAD_PAGE **pNewVadPages = NULL;
    QWORD newPageCount = 0, newPageIdx = 0;

    // New current pages array contains the region [Vad->StartPage, Vad->EndPage]. We need to adjust that region to
    // hold only [NewStartPage, NewOldPage].
    newPageCount = ((NewEndPage - NewStartPage) >> 12) + 1;

    if (NULL == Vad->VadPages)
    {
        goto no_array;
    }

    pNewVadPages = HpAllocWithTag(sizeof(*pNewVadPages) * newPageCount, IC_TAG_VAD_PGARR);
    if (NULL == pNewVadPages)
    {
        return INT_STATUS_INSUFFICIENT_RESOURCES;
    }

    for (QWORD curpg = (Vad->StartPage & PAGE_MASK); curpg <= (Vad->EndPage & PAGE_MASK); curpg += PAGE_SIZE)
    {
        QWORD pos = ((curpg - Vad->StartPage) >> 12);

        if (curpg >= NewStartPage && curpg <= NewEndPage)
        {
            if (NULL == Vad->VadPages[pos])
            {
                pNewVadPages[newPageIdx++] = NULL;
            }
            else
            {
                Vad->VadPages[pos]->RangeStart = MAX(Vad->VadPages[pos]->RangeStart, NewStartPage);
                Vad->VadPages[pos]->RangeEnd = MIN(Vad->VadPages[pos]->RangeEnd, NewEndPage);

                pNewVadPages[newPageIdx++] = Vad->VadPages[pos];
            }
        }
        else
        {
            if (NULL != Vad->VadPages[pos])
            {
                if (NULL != Vad->VadPages[pos]->ExecHook)
                {
                    // The page was hooked
                    status = IntHookGvaRemoveHook((HOOK_GVA **)&Vad->VadPages[pos]->ExecHook, 0);
                    if (!INT_SUCCESS(status))
                    {
                        ERROR("[ERROR] IntHookGvaRemoveHook failed: 0x%08x\n", status);
                    }
                }

                HpFreeAndNullWithTag(&Vad->VadPages[pos], IC_TAG_VAD_PAGE);
            }
        }
    }

    HpFreeAndNullWithTag(&Vad->VadPages, IC_TAG_VAD_PGARR);

    Vad->VadPages = pNewVadPages;

no_array:
    Vad->StartPage = NewStartPage;
    Vad->EndPage = NewEndPage;
    Vad->PageCount = newPageCount;

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntWinVadIsExecSuspicious(
    _In_ WIN_PROCESS_OBJECT* Process,
    _In_ QWORD VirtualAddress,
    _In_ QWORD PhysicalAddress,
    _Out_ INTRO_ACTION* Action
    )
///
/// @brief Handle code execution from a memory page.
///
/// This function will determine if the instruction execution inside the indicated page is caused by an exploit or not.
/// The main indicators we look after are:
/// 1. The code location. If the executed instructions are located on the stack, we will generate an alert;
/// 2. The stack location. If the stack has been pivoted (RSP points outside the known stack), we will generate an
/// alert.
/// 3. The code behavior. We will emulate instructions starting with VirtualAddress and see if they behave like a
/// shellcode.
/// In addition to these, if 1, 2 & 3 all deem the action legitimate, we will asynchronously request the AV engines to
/// scan the page too. If the AV engines trigger a detection, we won't be able to block the exploit, however, since
/// the detection would be thrown after the code has executed.
///
/// @param[in]  Process         The process which owns the page.
/// @param[in]  VirtualAddress  The executed virtual address.
/// @param[in]  PhysicalAddress The executed physical address (VirtualAddress translates to it).
/// @param[in]  Action          Desired action.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
///
{
    INTSTATUS status;
    QWORD scflags;
    PIG_ARCH_REGS regs;
    PINSTRUX instrux;
    char text[ND_MIN_BUF_SIZE] = { 0 };
    BOOLEAN bRspOut, bIsStack;
    QWORD tibBase, stackBase, stackLimit;
    BOOLEAN detected, feedback;
    INTRO_ACTION_REASON reason;
    BOOLEAN isCurrentProcess;

    EXCEPTION_UM_ORIGINATOR originator = { 0 };
    EXCEPTION_VICTIM_ZONE victim = { 0 };

    scflags = 0;
    tibBase = stackBase = stackLimit = 0;
    detected = feedback = FALSE;

    if (NULL == Process)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (NULL == Action)
    {
        return INT_STATUS_INVALID_PARAMETER_4;
    }

    *Action = introGuestAllowed;
    reason = introReasonAllowed;

    regs = &gVcpu->Regs;
    instrux = &gVcpu->Instruction;

    isCurrentProcess = Process->Cr3 == regs->Cr3;

    status = IntWinThrGetCurrentStackBaseAndLimit(&tibBase, &stackBase, &stackLimit);
    if ((INT_STATUS_PAGE_NOT_PRESENT == status) || (INT_STATUS_NO_MAPPING_STRUCTURES == status))
    {
        LOG("TIB is not present! Will inject #PF for %llx!\n", tibBase);

        // We just blocked an instruction being executed inside user-mode. It is safe to inject a #PF right now.
        // NOTE: We do not save a handle for this swap event (this is the only one) since this page may be executed
        // in the context of multiple threads, which would mean multiple swap-in attempts; therefore, we don't use
        // a context or a callback for this swap, which will be removed when terminating the process, if needed.
        status = IntSwapMemReadData(regs->Cr3, tibBase, 32, SWAPMEM_OPT_UM_FAULT | SWAPMEM_OPT_NO_DUPS,
                                    NULL, 0, NULL, NULL, NULL);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntSwapMemReadData failed: 0x%08x\n", status);
            return status;
        }
        else
        {
            *Action = introGuestRetry;
            return INT_STATUS_SUCCESS;
        }
    }
    else if (!INT_SUCCESS(status))
    {
        // If we couldn't read the TIB and the stack base/stack limit, assume the stack is OK - we still need to
        // validate the code!
        ERROR("[ERROR] IntWinThrGetCurrentStackBaseAndLimit failed: 0x%08x\n", status);
        stackLimit = stackBase = 0;
    }

    /// 1. Check if the ESP points inside the (known) actual (current) stack;
    /// 2. Check if the address is on the current stack;
    /// 3. Check if the page contains shellcode.
    if ((stackLimit == 0) && (stackBase == 0))
    {
        bRspOut = bIsStack = FALSE;
    }
    else
    {
        // Take a 3 page safety margin - the usual size of the guard region; we may have a RSP that points slightly
        // out of the stack area, but within the guard area.
        bRspOut = ((regs->Rsp < stackLimit - 0x3000) || (regs->Rsp >= stackBase));
        bIsStack = (VirtualAddress >= stackLimit) && (VirtualAddress < stackBase);
    }

    status = IntShcIsSuspiciousCode(VirtualAddress, PhysicalAddress, IG_CS_TYPE_INVALID, regs, &scflags);
    if (!INT_SUCCESS(status))
    {
        scflags = 0;
    }

    if (bRspOut || bIsStack)
    {
        // Pivoted stack or executions on the stack trigger detection directly.
        detected = TRUE;
    }
    else if (0 != scflags)
    {
        detected = TRUE;

        // Shellcode flags (as set by the shellcode emulator) may be overridden via CAMI. A flag marked for feedback
        // will cause the alert to be logged & sent, but no actual detection will appear. Note that we force feedback
        // for shellcode flags if and only if all the reported flags are marked as feedback. If there is a single
        // shellcode flag set that is not feedback, a normal detection will be generated.
        if ((scflags & gGuest.ShemuOptions.Feedback) == scflags)
        {
            feedback = TRUE;
        }
    }

    if (!detected)
    {
        // We did not find malicious activity, send context to the scan engine if we have the options set, but only
        // once, for the current process
        if (isCurrentProcess && !!(gGuest.CoreOptions.Current & INTRO_OPT_NOTIFY_ENGINES))
        {
            INTRO_EXEC_INFO executionInfo = { 0 };

            executionInfo.Rsp = regs->Rsp;
            executionInfo.StackBase = stackBase;
            executionInfo.StackLimit = stackLimit;
            executionInfo.Length = instrux->Length;

            status = IntWinEngExecSendNotification(Process, regs, &executionInfo);
            if (!INT_SUCCESS(status))
            {
                WARNING("[WARNING] IntWinEngExecSendNotification failed: 0x%08x\n", status);
            }
        }

        // Since the engines scan is asynchronous we can't do anything else, but exit
        goto _send_notification;
    }

    status = IntExceptUserGetExecOriginator(Process, &originator);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Failed getting originator: 0x%08x\n", status);
        goto _send_notification;
    }

    status = IntExceptGetVictimEpt(Process,
                                   PhysicalAddress,
                                   VirtualAddress,
                                   introObjectTypeUmGenericNxZone,
                                   ZONE_EXECUTE,
                                   &victim);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Failed getting modified zone: 0x%08x\n", status);
        goto _send_notification;
    }

    IntExcept(&victim, &originator, exceptionTypeUm, Action, &reason, introEventEptViolation);
    // Override the action & reason, if we have shemu feedback only.
    if ((*Action == introGuestNotAllowed) && feedback)
    {
        *Action = introGuestAllowed;
        reason = introReasonAllowedFeedback;
    }

_send_notification:
    // Since we can get here for other processes, not only the current one, we have to make sure we don't send an
    // alert and we don't inject a #UD unless we are doing it for the current process. We still want to analyze the
    // code in order to properly mark the page as non-malicious, if needed
    if (IntPolicyProcTakeAction(PROC_OPT_PROT_EXPLOIT, Process, Action, &reason) && isCurrentProcess)
    {
        EVENT_EPT_VIOLATION* pEptViol = &gAlert.Ept;

        memzero(pEptViol, sizeof(*pEptViol));

        status = NdToText(instrux, regs->Rip, ND_MIN_BUF_SIZE, text);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] NdToText failed: 0x%08x\n", status);
            return status;
        }

        LOG("[VADNX] [CPU %d] EXPLOIT detected! Execution attempted at 0x%016llx! Instruction: %s\n",
            gVcpu->Index, regs->Rip, text);

        LOG("[VADNX] Current address: %llx, current stack: %llx, known stack: %llx/%llx, TIB: %llx\n",
            regs->Rip, regs->Rsp, stackBase, stackLimit, tibBase);

        LOG("[VADNX] RSP out: %d; Is stack: %d; Shellcode flags: %llx;\n",
            bRspOut, bIsStack, scflags);

        IntDumpCodeAndRegs(regs->Rip, PhysicalAddress, regs);

        pEptViol->Header.Action = *Action;
        pEptViol->Header.Reason = reason;
        pEptViol->Header.MitreID = idExploitClientExec;

        IntAlertEptFillFromVictimZone(&victim, pEptViol);

        IntAlertFillCpuContext(TRUE, &pEptViol->Header.CpuContext);

        IntAlertFillWinProcess(Process, &pEptViol->Header.CurrentProcess);

        IntAlertFillWinUmModule(originator.Return.Library, &pEptViol->Originator.ReturnModule);
        pEptViol->ReturnRip = originator.Return.Rip;

        pEptViol->Header.Flags = IntAlertProcGetFlags(PROC_OPT_PROT_EXPLOIT, Process, reason, 0);

        IntAlertFillCodeBlocks(regs->Rip, regs->Cr3, TRUE, &pEptViol->CodeBlocks);
        IntAlertFillExecContext(0, &pEptViol->ExecContext);

        IntAlertFillVersionInfo(&pEptViol->Header);

        status = IntNotifyIntroEvent(introEventEptViolation, pEptViol, sizeof(*pEptViol));
        if (!INT_SUCCESS(status))
        {
            WARNING("[WARNING] IntNotifyIntroEvent failed: 0x%08x\n", status);
        }

        status = IntWinNetSendProcessConnections(Process);
        if (!INT_SUCCESS(status))
        {
            WARNING("[WARNING] IntWinNetSendProcessConnections failed: 0x%08x\n", status);
        }
    }

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntWinVadHandlePageExecution(
    _Inout_ VAD_PAGE *Context,
    _In_ void const *Hook,
    _In_ QWORD Address,
    _Out_ INTRO_ACTION *Action
    )
///
/// @brief  Handles execution attempts from a page owned by a monitored VAD.
///
/// This is the EPT handler set by #IntWinVadHandleProtectGeneric for protected VADs.
///
/// It uses #IntWinVadIsExecSuspicious to decide if the code the guest attempted to execute is malicious or not.
/// If the execution should be blocked and the #PROC_OPT_KILL_ON_EXPLOIT protection flag is set for the
/// current process, the process will be killed by injecting a \#UD in its context and Action will be set to
/// #introGuestRetry, not #introGuestNotAllowed. This is because we want the instruction to be retried by the guest,
/// so that the invalid opcode exception can be delivered for the RIP that generated the violation. If the flag is not
/// set, the execution will be blocked by skipping the current instruction. This means that for pages with malicious
/// instructions the guest will generate one exit for every instruction. This can cause serious performance problems.
///
/// If the execution is allowed the hook is removed. Since we analyze multiple instructions in the page this is OK,
/// as on the following exits the same code will be analyzed again.
///
/// While the process could have an exception handler set and catch the EXCEPTION_ILLEGAL_INSTRUCTION that will be
/// forwarded by the kernel to the process, this is not a problem, as the page will still be hooked and further
/// attempts of executing from it will end up back here - essentially blocking the execution even if the \#UD does
/// not kill the process.
///
/// However, there is an issue with this blocking mechanism. The probability of it happening seems extremely low, but
/// at least theoretically this chain of events is possible:
///     1. the guest tries to execute code from a monitored page.
///     2. an EPT violation is triggered.
///     3. we conclude that the page is malicious and we block the attempt by injecting an \#UD and setting Action
/// to #introGuestRetry.
///     4. the \#UD is not injected, as an interrupt with a higher priority is waiting to be injected, so the
/// hypervisor injects that.
///     5. the injected interrupt is handled by the guest kernel, then the interrupted user mode thread resumes
/// execution from the same RIP that previously generated and EPT violation, causing us to go back to step 1.
///
/// In theory, it is possible for step 3 to happen each and every time, causing an infinite loop and making the guest
/// look like it hanged.
///
/// Just because #IntInjectExceptionInGuest succeeded,it does not mean that the exception will actually be injected
/// now, as other exceptions, with a higher priority, may be waiting to be injected. After the guest resumes execution
/// we will be notified about this via the #PFUNC_IntEventInjectionCallback mechanism. This does not mean that the
/// execution attempt will succeed, as the guest will be retrying the same instruction and we will handle it again.
/// But it can generate multiple alerts for the same action, and that can be confusing. So we keep a list of
/// injected \#UDs, identified by: the process CR3, the RIP from which the guest attempted the execution, the guest
/// virtual address of the _ETHREAD structure for the thread that attempted the execution. See udlist.c for details
/// about this list. On an execution attempt, before trying to analyze the code and before sending an alert, we check
/// if we already tried to inject an \#UD for the current context. If there is a previously failed injection we try
/// it again, as the code could not have been modified in the meantime. When the injection succeeds, the entry is
/// removed from the list.
///
/// Since shared memory pages can be executable, this poses a problem, as this callback will be invoked for each
/// process that is protected with the #PROC_OPT_PROT_EXPLOIT option. This is problematic for a series of reasons:
/// first, we want to send only one alert for the process that actually tried to execute from that page; second, we
/// want to kill only the process that actually attempted the execution. However, we can't simply ignore the invocations
/// done for processes that are not the current process, because if the page is clean we will end up removing
/// the hook only for the current process, but the execution permissions in the EPT will remain unchanged, as multiple
/// processes will have hooked it. In this case we want to analyze the page for every process and remove the hook
/// as needed. However, in order to send the alert only once and to kill only the current process (if needed), the
/// action block action will be taken only for the current process. Due to the way #IntWinVadIsExecSuspicious
/// works, the execution attempt will be logged more than once.
///
/// This becomes a bit more problematic when the page is shared between processes that are protected and processes
/// that are not protected. If a process that is not protected attempts the execution we allow the action, but it will
/// still trigger a EPT  violation for every instruction in that page, which can slow down the guest.
///
/// @param[in]  Context The page for which this callback was invoked.
/// @param[in]  Hook    The hook for which this callback was invoked. Ignored.
/// @param[in]  Address The guest physical address from which the guest attempted the execution.
/// @param[out] Action  The action to be taken.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value
///
{
    INTSTATUS status;
    PVAD_PAGE pPage;
    PWIN_PROCESS_OBJECT pProc;
    PIG_ARCH_REGS regs;
    QWORD currentThread = 0;
    INFO_UD_PENDING *entryPendingUD = NULL;
    BOOLEAN isCurrentProcess;

    UNREFERENCED_PARAMETER(Hook);

    // Default action = allow.
    *Action = introGuestAllowed;

    pPage = Context;
    pProc = pPage->Vad->Process;
    regs = &gVcpu->Regs;
    isCurrentProcess = pProc->Cr3 == regs->Cr3;

    // If this is a shared memory region between two protected processes, the hook will be invoked for both, but the
    // current process is the one that triggered the violation, so ignore the others
    if (!isCurrentProcess)
    {
        // If this page is shared between multiple processes, we can be in one of the following cases:
        //  1. process a.exe and b.exe share the same page; a.exe is protected, while b.exe is not - if b.exe fetches
        // instructions from that page, an EPT violation will be generated; since the page is not hooked in the
        // current process (b.exe), we allow the execution. This can pretty much freeze the guest in two situations:
        //   i.  for each instruction that the guest tries to execute from the monitored page while in the context
        // of b.exe, an EPT violation will be triggered
        //   ii. if an interrupt is pending and is delivered to the guest, the same instruction ends up being retried
        // in an infinite loop
        //  2. both a.exe, and b.exe are protected against exploits. b.exe executes code from the shared page, an
        // EPT violation is triggered and introcore inspects the code from that page and considers that it is not
        // malicious, marking the page as legitimate and removing the hook from that page. Since the same page is
        // hooked more than once, the EPT hook is still in place, and further attempts made by b.exe to execute code
        // from that page will trigger new EPT violations.
        // https://lists.xenproject.org/archives/html/xen-devel/2019-01/msg00900.html is also relevant
        // In the first case, we will allow the action, which will remove the hook on that page, but will still
        // keep the VAD. The second case is handled partially in IntShcWinHandlePageExecution, as it is more tricky.
        // We have to keep in mind that the page may indeed contain malicious code, and that we can't make any
        // assumptions about the order in which the hooks are invoked, for example, if we have a.exe, b.exe and c.exe
        // all sharing the same page, and b.exe is the current process and the hooks are invoked in order (first for a,
        // then for b and lastly for c) we want to keep the hook in all processes, but send the alert only for b.exe.
        // So we have to analyze code and then take an action.
        // If the code is clean, the page will be marked as clean in all processes, and unhooked from all
        // processes; if it is malicious, it will remain hooked in all processes, but the alert will be sent only
        // for the current process.
        PWIN_PROCESS_OBJECT pCurrentProcess = IntWinProcFindObjectByCr3(regs->Cr3);
        if (!pCurrentProcess->ProtExploits)
        {
            TRACE("[WINVAD] Removing VAD hook on 0x%016llx for process `%s` (Cr3 0x%016llx). "
                  "Current process is `%s` (Cr3 0x%016llx)\n",
                  pPage->Address, pProc->Name, pProc->Cr3, pCurrentProcess->Name, pCurrentProcess->Cr3);

            status = INT_STATUS_NOT_NEEDED_HINT;
            *Action = introGuestAllowed;
            goto cleanup_and_exit;
        }
    }

    // We keep a list of tuples (CR3, RIP, ETHREAD) for all the injected/pending UDs
    // If a tuple comes more than once it means that the requested #UD did not happen before and now we will just
    // request another #UD; without checking again and without generating duplicated alerts for the same execution.
    // The list cleanup takes place:
    // 1. when #UD is successfully injected --> IntHandleEventInjection (using gVcpu->Exception.CurrentUD which stores
    // the allocated addresses for a tuple)
    // 2. when a process terminates --> IntWinProcDeleteProcessObject (using the CR3)

    status = IntWinThrGetCurrentThread(gVcpu->Index, &currentThread);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntWinThrGetCurrentThread failed: 0x%08x\n", status);
        return status;
    }

    entryPendingUD = IntUDGetEntry(regs->Cr3, regs->Rip, currentThread);
    if (NULL != entryPendingUD)
    {
        goto retry_inject_ud;
    }

    if (IntWinVadIsProbablyDominoJava(pPage->Vad))
    {
        pPage->Vad->Process->FirstDominoJavaIgnored = TRUE;
        pPage->Vad->IsIgnored = 1;
        pPage->Legitimate = TRUE;
        status = INT_STATUS_SUCCESS;
        goto cleanup_and_exit;
    }

    status = IntWinVadIsExecSuspicious(pProc, regs->Rip, Address, Action);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntWinVadIsExecSuspicious failed: 0x%08x\n", status);
        goto cleanup_and_exit;
    }

    // If the actions is allowed, remove the hook on the page/region.
    if (introGuestAllowed == *Action)
    {
        pPage->Legitimate = TRUE;
    }

    IntPolicyProcForceBetaIfNeeded(PROC_OPT_PROT_EXPLOIT, pProc, Action);

cleanup_and_exit:
    // Remove the exec hook if we allow the action.
    if ((introGuestAllowed == *Action) && (NULL != pPage->ExecHook))
    {
        // Remove the hook on this page, only if we didn't block anything. If we did, we will maintain the hook in
        // order to block further execution attempts. We also remove the hook if we're in BETA mode - otherwise,
        // there will be lots & lots of alerts, that may end up hanging the process.
        status = IntHookGvaRemoveHook((HOOK_GVA **)&pPage->ExecHook, 0);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHookGvaRemoveHook failed: 0x%08x\n", status);
        }

        // Since we removed the protection from this page, it is safe to return introGuestRetry. This will re-enter the
        // guest at the same instruction, and it will execute it natively. Returning introGuestAllowed will simply
        // cause the instruction to be emulated, which is not ideal. In addition, returning anything else than
        // introGuestRetry on an execution attempt, will cause the EPT violation handler to dissect the instruction
        // and to call the EPT handler for every memory access made by the instruction; in certain cases, this may lead
        // to weird scenarios: for example, if we have a piece of code outside any module which places a memory hook,
        // the following would happen:
        // 1. The code executes & triggers an EPT exec violation;
        // 2. Introcore deems the attempt legitimate, and returns allowed instead of retry;
        // 3. The EPT callback will dissect the instruction, and it will analyze any other memory accesses;
        // 4. If the instruction that triggered the execution EPT violation also makes a write on a shared module,
        //    we would see this, and we would call the appropriate EPT handlers BUT this will happen without triggering
        //    the CoW inside the guest.
        *Action = introGuestRetry;

        // If the entire VAD was created executable, and the first page executed was deemed legitimate, then remove
        // the protection on the entire memory region.
        if (pPage->Legitimate)
        {
            pPage->Vad->ExecCount++;

            status = IntWinVadRemoveRange(pPage->Vad, pPage->RangeStart, pPage->RangeEnd);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntWinVadRemoveRanges failed: 0x%08x\n", status);
            }
        }
    }

retry_inject_ud:
    // Terminate the process, if we decided to or if #UD already pending, inject it again
    if ((INT_SUCCESS(status) && (introGuestNotAllowed == *Action) && ((NULL != pProc) && pProc->ProtKillExploit) &&
         isCurrentProcess) ||
        NULL != entryPendingUD)
    {
        INTSTATUS status2;

        // If we already injected the same entry, there's no need for another injection, most probably causing an error
        if (entryPendingUD != NULL && gVcpu->CurrentUD == entryPendingUD)
        {
            goto _skip_inject;
        }

        status2 = IntInjectExceptionInGuest(VECTOR_UD, 0, NO_ERRORCODE, gVcpu->Index);
        if (!INT_SUCCESS(status2))
        {
            ERROR("[ERROR] IntInjectExceptionInGuest failed, process will not be killed: %08x\n", status2);
        }
        else
        {
            if (NULL == entryPendingUD)
            {
                // If not already pending, add to the list of pending UDs and store the allocated address
                // in entryPendingUD
                status = IntUDAddToPendingList(regs->Cr3, regs->Rip, currentThread, &entryPendingUD);
                if (!INT_SUCCESS(status))
                {
                    ERROR("[ERROR] IntUDAddToPendingList failed: 0x%08x\n", status);
                    return status;
                }
            }

            // Set gVcpu->CurrentUD pointer to the allocated address for the tuple
            gVcpu->CurrentUD = entryPendingUD;
        }

_skip_inject:
        *Action = introGuestRetry;
    }

    return status;
}


static INTSTATUS
IntWinVadHandleFilePathInMemory(
    _Inout_ VAD *Context,
    _In_ QWORD Cr3,
    _In_ QWORD VirtualAddress,
    _In_ QWORD PhysicalAddress,
    _In_reads_bytes_(DataSize) void *Data,
    _In_ DWORD DataSize,
    _In_ DWORD Flags
    )
///
/// @brief  Handles the swap-in of a file path taken from a Windows VAD structure.
///
/// This is the #IntSwapMemReadData callback set by #IntWinVadFetchImageName for the path to the image mapped
/// by a long VAD.
/// After this function returns, #VAD.PathSwapHandle will be set to NULL.
///
/// @param[in]  Context         The VAD from which the path is obtained.
/// @param[in]  Cr3             The CR3 in which the swap-in was made. Ignored.
/// @param[in]  VirtualAddress  The guest virtual address from which Data is read. Ignored.
/// @param[in]  PhysicalAddress The guest physical address to which VirtualAddress translates to. Ignored.
/// @param[in]  Data            Data obtained from the guest. This will be the path.
/// @param[in]  DataSize        The size of the Data buffer.
/// @param[in]  Flags           Ignored.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value
///
{
    PVAD pVad = Context;

    UNREFERENCED_PARAMETER(Cr3);
    UNREFERENCED_PARAMETER(VirtualAddress);
    UNREFERENCED_PARAMETER(PhysicalAddress);
    UNREFERENCED_PARAMETER(Flags);

    pVad->PathSwapHandle = NULL;

    pVad->Path = IntWinUmPathCreate(Data, DataSize, pVad->SubsectionGva);

    return IntWinModHandleLoadFromVad(pVad->Process, pVad);
}


INTSTATUS
IntWinVadRemoveProcessTree(
    _Inout_ WIN_PROCESS_OBJECT *Process
    )
///
/// @brief  Removes the VAD tree from a process.
///
/// @param[in, out] Process The process for which the tree is removed.
///
/// @retval #INT_STATUS_SUCCESS in case of success.
/// @retval #INT_STATUS_INVALID_PARAMETER_1 if Process is NULL.
///
{
    if (NULL == Process)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    RbUninit(&Process->VadTree);

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntWinVadFetchVadFromMemory(
    _In_ QWORD VadGva,
    _Out_ VAD *Vad,
    _In_ BOOLEAN FailOnCorruptRange
    )
///
/// @brief  Reads a _MMVAD structure from the Windows kernel and creates a corresponding #VAD structure.
///
/// This function does not initialize any fields related to the optional #VAD.Path field. For that, the
/// #IntWinVadFetchImageName function must be used.
///
/// @param[in]  VadGva              The guest virtual address of the _MMVAD structure.
/// @param[out] Vad                 On success, will be initialized with the relevant information about the VAD,
///                                 except the Path.
/// @param[in]  FailOnCorruptRange  Exit with an error if the range described by StartPage and EndPage is not a valid
///                                 range (EndPage must not be less than StartPage).
///
/// @retval     #INT_STATUS_SUCCESS in case of success.
/// @retval     #INT_STATUS_INSUFFICIENT_RESOURCES if the VAD structure could not be mapped.
/// @retval     #INT_STATUS_INVALID_DATA_STATE if FailOnCorruptRange is TRUE, and the range described by StartPage and
///             EndPage is not valid.
///
{
    BYTE *vadBuffer = IntWinVadMapShortVad(VadGva);
    QWORD flags = 0;
    QWORD startVpn, endVpn;

    if (NULL == vadBuffer)
    {
        return INT_STATUS_INSUFFICIENT_RESOURCES;
    }

    Vad->VadGva = VadGva;

    // Parent, Left, and Right are always pointers, so read WordSize from the guest
    Vad->Parent = VadShortPtrSize(vadBuffer, Parent);
    Vad->Left = VadShortPtrSize(vadBuffer, Left);
    Vad->Right = VadShortPtrSize(vadBuffer, Right);

    startVpn = endVpn = 0;
    // Starting and Ending Vpn can have different sizes and sometimes can be extended by another High byte
    if (WIN_KM_FIELD(VadShort, VpnSize) == 4)
    {
        startVpn = VadShortDword(vadBuffer, StartingVpn);
        endVpn = VadShortDword(vadBuffer, EndingVpn);
    }
    else
    {
        startVpn = VadShortQword(vadBuffer, StartingVpn);
        endVpn = VadShortQword(vadBuffer, EndingVpn);
    }

    // Add the extra byte if it is present
    if (0 != WIN_KM_FIELD(VadShort, StartingVpnHigh))
    {
        startVpn |= ((QWORD)VadShortByte(vadBuffer, StartingVpnHigh) << 32);
    }
    if (0 != WIN_KM_FIELD(VadShort, EndingVpnHigh))
    {
        endVpn |= ((QWORD)VadShortByte(vadBuffer, EndingVpnHigh) << 32);
    }

    Vad->StartPage = startVpn << 12;
    Vad->EndPage = endVpn << 12;

    if (FailOnCorruptRange && Vad->EndPage < Vad->StartPage)
    {
        ERROR("[ERROR] VAD EndPage is before StartPage: start = 0x%016llx, end = 0x%016llx, vad at 0x%016llx\n",
              Vad->StartPage, Vad->EndPage, VadGva);
        IntVirtMemUnmap(&vadBuffer);
        return INT_STATUS_INVALID_DATA_STATE;
    }

    // The Flags field can have different sizes, so read it into a QWORD
    flags = VadShortAnySize(WIN_KM_FIELD(VadShort, FlagsSize), vadBuffer, Flags);

    // Type and Protection are 3 and 5 bits long, but are not the same bits always, so normalize them
    Vad->VadType = (flags >> WIN_KM_FIELD(VadFlags, TypeShift)) & WIN_KM_FIELD(VadFlags, TypeMask);
    Vad->VadProtection = (flags >> WIN_KM_FIELD(VadFlags, ProtectionShift)) & WIN_KM_FIELD(VadFlags, ProtectionMask);

    // NoChange is always 1 bit and it is present on all Windows versions, so check for it
    Vad->NoChange = 0 != (flags & BIT(WIN_KM_FIELD(VadFlags, NoChangeBit)));

    // DeleteInProgress and PrivateFixup are always 1-bit wide, but are not present on all Windows versions, so it is
    // easier to check them directly against a mask instead of the method used for NoChange; if they are not used,
    // the mask is 0
    Vad->DeleteInProgress = 0 != (flags & WIN_KM_FIELD(VadFlags, DeleteInProgressMask));
    Vad->PrivateFixup = 0 != (flags & WIN_KM_FIELD(VadFlags, PrivateFixupMask));

    Vad->PageCount = (((Vad->EndPage - Vad->StartPage) >> 12) + 1);
    Vad->Protection = IntWinVadVadProtectionToIntroProtection(Vad->VadProtection);

    Vad->HugeVad = (Vad->PageCount * sizeof(VAD_PAGE) >= 4 * ONE_GIGABYTE);
    Vad->Path = NULL;
    Vad->Process = NULL;

    IntVirtMemUnmap(&vadBuffer);

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntWinVadFetchImageName(
    _Inout_ VAD *Vad
    )
///
/// @brief  Reads the path of the image file mapped by a _MMVAD_LONG structure.
///
/// #IntSwapMemReadData is used to read the path, so it will not be available until #IntWinVadHandleFilePathInMemory
/// will be invoked.
///
/// @param[in, out] Vad The VAD for which to read the image name. This must already be initialized by
///                     #IntWinVadFetchVadFromMemory.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value
///
{
    DWORD len = 0;
    QWORD pathGva = 0;
    QWORD tmp = 0;
    DWORD subsecOffsetInVad;
    DWORD ctlAreaOffsetInSubsec;
    DWORD fileObjectOffsetInCtlArea;
    DWORD fileLengthOffsetInFileObject;
    DWORD fileBufferOffsetInFileObject;
    INTSTATUS status;

    if (NULL != Vad->Path)
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    subsecOffsetInVad = WIN_KM_FIELD(VadLong, Subsection);
    ctlAreaOffsetInSubsec = WIN_KM_FIELD(Ungrouped, SubsectionCtlArea);
    fileObjectOffsetInCtlArea = WIN_KM_FIELD(Ungrouped, CtlAreaFile);
    fileLengthOffsetInFileObject = WIN_KM_FIELD(FileObject, NameLength);
    fileBufferOffsetInFileObject = WIN_KM_FIELD(FileObject, NameBuffer);

    // Read the _SUBSECTION address.
    status = IntKernVirtMemRead(Vad->VadGva + subsecOffsetInVad, gGuest.WordSize, &tmp, NULL);
    if (!INT_SUCCESS(status))
    {
        return status;
    }

    if (0 == tmp)
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    Vad->SubsectionGva = tmp;
    Vad->Path = IntWinUmPathFetchAndReferenceBySubsection(Vad->SubsectionGva);

    if (NULL != Vad->Path)
    {
        // If we can reuse the path, then we can already consider it is a module load
        return IntWinModHandleLoadFromVad(Vad->Process, Vad);
    }

    // Read the _CONTROL_AREA address.
    status = IntKernVirtMemRead(tmp + ctlAreaOffsetInSubsec, gGuest.WordSize, &tmp, NULL);
    if (!INT_SUCCESS(status))
    {
        return status;
    }

    if (0 == tmp)
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    // Read the _FILE_OBJECT address.
    status = IntKernVirtMemRead(tmp + fileObjectOffsetInCtlArea, gGuest.WordSize, &tmp, NULL);
    if (!INT_SUCCESS(status))
    {
        return status;
    }

    tmp = EX_FAST_REF_TO_PTR(gGuest.Guest64, tmp);

    if (0 == tmp)
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    status = IntKernVirtMemRead(tmp + fileLengthOffsetInFileObject, sizeof(WORD), &len, NULL);
    if (!INT_SUCCESS(status))
    {
        return status;
    }

    status = IntKernVirtMemRead(tmp + fileBufferOffsetInFileObject, gGuest.WordSize, &pathGva, NULL);
    if (!INT_SUCCESS(status))
    {
        return status;
    }

    status = IntSwapMemReadData(0, pathGva, len, SWAPMEM_OPT_BP_FAULT, Vad, 0,
                                IntWinVadHandleFilePathInMemory, NULL, &Vad->PathSwapHandle);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntSwapMemReadData failed: 0x%08x\n", status);
    }

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntWinVadCreateObject(
    _In_ WIN_PROCESS_OBJECT *Process,
    _In_ QWORD VadGva,
    _Out_ VAD **Vad,
    _In_ BOOLEAN StaticScan
    )
///
/// @brief  Creates and initializes a #VAD structure.
///
/// The VAD is initialized using #IntWinVadFetchVadFromMemory. If the type of the VAD is #VadImageMap the path
/// of the image will be obtained with #IntWinVadFetchImageName. If the type is not #VadNone, or #VadImageMap, or
/// #VadWriteWatch, the VAD is ignored.
///
/// @param[in]  Process     The process that owns the VAD.
/// @param[in]  VadGva      The guest virtual address of the _MMVAD structure.
/// @param[out] Vad         On success, and if the VAD is not ignored, will contain a pointer to the allocated and
///                         initialized VAD structure. The caller must free this VAD and release any resources held by
///                         it using #IntWinVadDestroyObject.
/// @param[in]  StaticScan  True if this VAD was discovered by a static scan, instead of being discovered when it
///                         was created.
///
/// @retval     #INT_STATUS_SUCCESS in case of success. This is the only case in which Vad will not point to NULL.
/// @retval     #INT_STATUS_NOT_NEEDED_HINT if the VAD is ignored.
/// @retval     #INT_STATUS_INSUFFICIENT_RESOURCES if not enough memory is available.
///
{
    INTSTATUS status;

    VAD *pVad = HpAllocWithTag(sizeof(*pVad), IC_TAG_VAD);
    if (NULL == pVad)
    {
        return INT_STATUS_INSUFFICIENT_RESOURCES;
    }

    // We want to fail if the memory range described by this VAD is not valid.
    status = IntWinVadFetchVadFromMemory(VadGva, pVad, TRUE);
    if (!INT_SUCCESS(status))
    {
        HpFreeAndNullWithTag(&pVad, IC_TAG_VAD);
        ERROR("[ERROR] IntWinVadFetchVadFromMemory failed from GVA %llx: 0x%08x\n", VadGva, status);
        return status;
    }

    // We don't handle other VAD types except for VadNone and VadImageMap.
    if ((pVad->VadType != VadNone) && (pVad->VadType != VadImageMap) && (pVad->VadType != VadWriteWatch))
    {
        TRACE("[WINVAD] Vad with type %d created at [0x%016llx, 0x%016llx]. Will ignore it.\n",
              pVad->VadType, pVad->StartPage, pVad->EndPage);
        HpFreeAndNullWithTag(&pVad, IC_TAG_VAD);
        *Vad = NULL;
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    pVad->Process = Process;
    pVad->Path = NULL;
    pVad->VadPages = NULL;
    pVad->StaticScan = StaticScan;

    if (VadImageMap == pVad->VadType)
    {
        status = IntWinVadFetchImageName(pVad);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntWinVadFetchImageName failed for VAD 0x%016llx: 0x%08x\n", pVad->VadGva, status);
        }
    }

    *Vad = pVad;

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntWinVadShortDump(
    _In_ QWORD VadNodeGva,
    _In_ DWORD Level,
    _In_opt_ void *Context
    )
///
/// @brief  Prints a _MMVAD_SHORT structure.
///
/// @param[in]  VadNodeGva  The guest virtual address of the _MMVAD_SHORT structure.
/// @param[in]  Level       The level at which the node is located inside the VAD tree.
/// @param[in]  Context     Ignored.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value
///
{
    const PCHAR prot[] =
    {
        "noaccess", "readonly", "execute", "execute-read", "readwrite",
        "writecopy", "execute-readwrite", "execute-writecopy"
    };
    VAD vad = {0};
    INTSTATUS status;

    UNREFERENCED_PARAMETER(Context);

    if (!IS_KERNEL_POINTER_WIN(gGuest.Guest64, VadNodeGva))
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    // We simply dump guest memory, we do not care if the range is valid or not.
    status = IntWinVadFetchVadFromMemory(VadNodeGva, &vad, FALSE);
    if (!INT_SUCCESS(status))
    {
        return status;
    }

    NLOG("0x%016llx (%d): [0x%016llx, 0x%016llx]: Type: %d Prot: 0x%04x (%s)\n",
         VadNodeGva, Level, vad.StartPage, vad.EndPage, vad.VadType, vad.VadProtection,
         vad.VadProtection >= ARRAYSIZE(prot) ? "" : prot[vad.VadProtection]);

    return INT_STATUS_SUCCESS;
}


_Function_class_(FUNC_RbTreeWalkCallback)
BOOLEAN
IntWinVadDump(
    _In_ VAD const *Vad,
    _In_ void *Context
    )
///
/// @brief  Prints a #VAD structure.
///
/// @param[in]  Vad     Pointer to the structure to be printed.
/// @param[in]  Context Ignored.
///
/// @retval False if Vad is NULL; otherwise True.
///
{
    QWORD i;
    const char *vadTypes[] =
    {
        "VadNone",
        "VadDevicePhysicalMemory",
        "VadImageMap",
        "VadAwe",
        "VadWriteWatch",
        "VadLargePages",
        "VadRotatePhysical",
        "VadLargePageSection",
    };

    UNREFERENCED_PARAMETER(Context);

    if (NULL == Vad)
    {
        return FALSE;
    }

    NLOG("            VAD @ 0x%016llx for [0x%016llx, 0x%016llx], type %-24s, protection: 0x%08x (%c%c%c) "
         "Ignored: %d, ExecCount: %d",
         Vad->VadGva, Vad->StartPage, Vad->EndPage,
         Vad->VadType < sizeof(vadTypes) / sizeof(vadTypes[0]) ? vadTypes[Vad->VadType] : "unknown",
         Vad->VadProtection,
         (Vad->Protection & PROT_READ) ? 'R' : '-',
         (Vad->Protection & PROT_WRITE) ? 'W' : '-',
         (Vad->Protection & PROT_EXEC) ? 'X' : '-',
         Vad->IsIgnored,
         Vad->ExecCount);

    if (NULL != Vad->Path)
    {
        NLOG(", path '%s'\n", utf16_for_log(Vad->Path->Path));
    }
    else
    {
        NLOG("\n");
    }

    if (NULL != Vad->VadPages)
    {
        for (i = 0; i < Vad->PageCount; i++)
        {
            if (NULL != Vad->VadPages[i])
            {
                NLOG("                PAGE @ %llx, protection %c%c%c, hook at %p\n",
                     Vad->VadPages[i]->Address,
                     (Vad->VadPages[i]->Protection & PROT_READ) ? 'R' : '-',
                     (Vad->VadPages[i]->Protection & PROT_WRITE) ? 'W' : '-',
                     (Vad->VadPages[i]->Protection & PROT_EXEC) ? 'X' : '-',
                     Vad->VadPages[i]->ExecHook);
            }
        }
    }

    return TRUE;
}


_Function_class_(FUNC_RbTreeWalkCallback) static
BOOLEAN
IntWinVadRemoveRanges(
    _Inout_ VAD *Vad,
    _In_ void *Context
    )
///
/// @brief          Removes all pages from a VAD.
///
/// This is simply a wrapper over #IntWinVadRemoveAllPages. We needed a wrapper in order to have the right type
/// for #RbWalkInorderTree.
///
/// @param[in, out] Vad     The VAD for which the pages will be removed.
/// @param[in]      Context Ignored.
///
/// @retval False if Vad is NULL; otherwise True.
///
{
    UNREFERENCED_PARAMETER(Context);

    if (NULL == Vad)
    {
        return FALSE;
    }

    IntWinVadRemoveAllPages(Vad);

    return TRUE;
}


void
IntWinVadStopExploitMonitor(
    _Inout_ WIN_PROCESS_OBJECT *Process
    )
///
/// @brief  Disables the exploit monitoring for a process.
///
/// @param[in, out] Process The process for which to stop the exploit protection.
///
{
    RbWalkInorderTree(&Process->VadTree, (PFUNC_RbTreeWalkCallback)IntWinVadRemoveRanges, NULL);
}


QWORD
IntWinVadFindNodeInGuestSpace(
    _In_ QWORD VadRoot,
    _In_ QWORD StartPage,
    _In_ QWORD EndPage,
    _In_ DWORD Level,
    _In_ QWORD OldStartPage,
    _In_ BOOLEAN LastBranchRight
    )
///
/// @brief  Searches for a VAD node inside a guest VAD tree.
///
/// This performs an in-order recursive traversal of the guest VAD tree.
///
/// The [StartPage, EndPage] range is inclusive.
///
/// @param[in]  VadRoot         The root of the VAD tree. This is usually the value of the VadRoot field of an
///                             _EPROCESS structure.
/// @param[in]  StartPage       The first page of the searched VAD.
/// @param[in]  EndPage         The last page of the searched VAD.
/// @param[in]  Level           The level for which this function is invoked. Should be 0 when starting a new search.
/// @param[in]  OldStartPage    The start page for the VAD at the previous level. Should be 0  when starting a new
///                             search.
/// @param[in]  LastBranchRight True if the last branch taken was the right one. Should be False when starting a new
///                             search.
///
/// @returns    The guest virtual address of the searched VAD, or 0 if no VAD was found.
///
{
    INTSTATUS status;
    VAD vad = { 0 };
    // Workaround for Windows 7/8: the first level isn't in fact a VAD, and we have to follow the right branch.
    const BOOLEAN notAVad = (gGuest.OSVersion <= 9200) && (0 == Level);

    if (!IS_KERNEL_POINTER_WIN(gGuest.Guest64, VadRoot))
    {
        return 0;
    }

    if (Level >= VAD_SEARCH_LIMIT)
    {
        ERROR("[ERROR] Max recursion level reached, will bail out\n");
        return 0;
    }

    VadRoot = RTL_BALANCED_NODE_PARENT_TO_PTR(VadRoot);

    // If this is not actually a VAD we allow errors in the memory range that it describes. We are interested only in
    // the Left and Right branch values. In the other cases we want to bail out if the range is not valid, because
    // our search algorithm will no longer work if Start > End.
    status = IntWinVadFetchVadFromMemory(VadRoot, &vad, !notAVad);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntWinVadFetchVadFromMemory failed: 0x%08x\n", status);
        return 0;
    }

    if (notAVad)
    {
        return IntWinVadFindNodeInGuestSpace(vad.Right, StartPage, EndPage, Level + 1, 0, TRUE);
    }

    if (Level > 0 && vad.StartPage <= OldStartPage && LastBranchRight)
    {
        ERROR("[ERROR] The in-guest VAD tree seems to be corrupted! Last branch right, "
              "current start page: 0x%16llx, old start page: 0x%16llx\n",
              vad.StartPage, OldStartPage);
        return 0;
    }

    if (Level > 0 && vad.StartPage >= OldStartPage && !LastBranchRight)
    {
        ERROR("[ERROR] The in-guest VAD tree seems to be corrupted! Last branch left, "
              "current start page: 0x%16llx, old start page: 0x%16llx\n",
              vad.StartPage, OldStartPage);
        return 0;
    }

    if (StartPage > vad.EndPage)
    {
        return IntWinVadFindNodeInGuestSpace(vad.Right, StartPage, EndPage, Level + 1, vad.StartPage, TRUE);
    }
    else if (EndPage < vad.StartPage)
    {
        return IntWinVadFindNodeInGuestSpace(vad.Left, StartPage, EndPage, Level + 1, vad.StartPage, FALSE);
    }
    else if (StartPage >= vad.StartPage && EndPage <= vad.EndPage)
    {
        return vad.VadGva;
    }

    return 0;
}


INTSTATUS
IntWinVadInOrderRecursiveTraversal(
    _In_ QWORD VadNodeGva,
    _In_ DWORD Level,
    _In_ PFUNC_WinVadTraversalCallback Callback,
    _In_opt_ void *Context
    )
///
/// @brief  Traverses a guest VAD tree.
///
/// This function is recursive and will call itself for every node in the tree, starting from VadNodeGva. The
/// tree is traversed in order. Recursion is stopped after we go past level 64.
///
/// @param[in]  VadNodeGva  The guest virtual address of the node for which this function was called. When starting
///                         a new traversal this should be the root of the tree.
/// @param[in]  Level       The level for which this function is called. It is used in order to know when to stop
///                         the traversal, for trees that seem to have more levels than we can handle. Should be 0
///                         when starting a new search.
/// @param[in]  Callback    Callback to be invoked for every node in the tree. Errors returned by this callback are
///                         not propagated back to the caller.
/// @param[in]  Context     Optional context to be passed to Callback each time it is invoked.
///
/// @retval     #INT_STATUS_SUCCESS in case of success.
/// @retval     #INT_STATUS_INVALID_PARAMETER_1 if VadNodeGva is not a valid kernel pointer.
/// @retval     #INT_STATUS_INVALID_PARAMETER_3 if Callback is NULL.
///
{
    INTSTATUS status;
    QWORD left;
    QWORD right;
    INTSTATUS failStatus = INT_STATUS_SUCCESS;
    VAD vad = { 0 };
    // Workaround for Windows 7/8: the first level isn't in fact a VAD.
    const BOOLEAN notAVad = (gGuest.OSVersion <= 9200) && (0 == Level);
#define MAX_LEVEL 64

    if (!IS_KERNEL_POINTER_WIN(gGuest.Guest64, VadNodeGva))
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (NULL == Callback)
    {
        return INT_STATUS_INVALID_PARAMETER_3;
    }

    if (Level > MAX_LEVEL)
    {
        ERROR("[ERROR] Too much recursion: requested level: %d, max level: %d\n", Level, MAX_LEVEL);
        return INT_STATUS_BUFFER_OVERFLOW;
    }

    // On OSs with _MM_AVL_TABLE in the root, we should convert it to ptr by stripping the last 2 bits.
    // Otherwise the structure might be off by some bits and invalid data could be read from the guest.
    if (notAVad)
    {
        VadNodeGva = RTL_BALANCED_NODE_PARENT_TO_PTR(VadNodeGva);
    }

    // If this is not actually a VAD we allow errors in the memory range that it describes. We are interested only in
    // the Left and Right branch values.
    status = IntWinVadFetchVadFromMemory(VadNodeGva, &vad, !notAVad);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntWinVadFetchVadFromMemory failed for 0x%016llx: 0x%08x\n", VadNodeGva, status);
        return status;
    }

    left = vad.Left;
    right = vad.Right;

    if (IS_KERNEL_POINTER_WIN(gGuest.Guest64, left))
    {
        status = IntWinVadInOrderRecursiveTraversal(left, Level + 1, Callback, Context);
        if (!INT_SUCCESS(status))
        {
            failStatus = status;
        }
    }

    if (notAVad)
    {
        // Windows 7 and Windows 8 hold in _EPROCESS.VadRoot a _MM_AVL_TABLE struct. It's Parent points to itself,
        // the children may be NULL or valid tree nodes, skip the callback for the fake root
        TRACE("[WINVAD] -------> Special Win 7/8 case: 0x%016llx is not an actual VAD. Left = 0x%016llx "
              "Right = 0x%016llx\n", VadNodeGva, left, right);
    }
    else
    {
        Callback(VadNodeGva, Level, Context);
    }

    if (IS_KERNEL_POINTER_WIN(gGuest.Guest64, right))
    {
        status = IntWinVadInOrderRecursiveTraversal(right, Level + 1, Callback, Context);
        if (!INT_SUCCESS(status))
        {
            failStatus = status;
        }
    }

    return failStatus;
}


INTSTATUS
IntWinVadWalkTree(
    _In_ PWIN_PROCESS_OBJECT Process,
    _In_ PFUNC_RbTreeWalkCallback Callback
    )
///
/// @brief  Walks the VAD tree of a process.
///
/// @param[in]  Process     The process for which the walk is done.
/// @param[in]  Callback    Callback to be invoked for each node in the tree. If the callback returns False, the
///                         walk is stopped. No context is passed to Callback.
///
/// @retval     #INT_STATUS_SUCCESS in case of success.
/// @retval     #INT_STATUS_INVALID_PARAMETER_1 is Process is NULL.
/// @retval     #INT_STATUS_INVALID_PARAMETER_2 is Callback is NULL.
///
{
    if (NULL == Process)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (NULL == Callback)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    RbWalkInorderTree(&Process->VadTree, Callback, NULL);

    return INT_STATUS_SUCCESS;
}


static PVAD
IntWinVadRescanVad(
    _Inout_ WIN_PROCESS_OBJECT *Process,
    _In_ QWORD StartPage,
    _In_ QWORD EndPage
    )
///
/// @brief  Searches for a VAD inside the guest tree and inserts it into our VAD tree.
///
/// The [StartPage, EndPage] range is inclusive.
///
/// Since the guest is running while we're searching for the VAD, sometimes, modifications will take place inside
/// the tree exactly when we're parsing it. This means that we could end up not finding this range, because, for
/// example, a node above our searched node was removed. This can easily be mitigated by attempting several times
/// to search for the VAD - usually, the VAD will be found in the second attempt. We limit this search to 1000 tries.
///
/// @param[in, out] Process     The process for which the search is done.
/// @param[in]      StartPage   The first page of the searched VAD.
/// @param[in]      EndPage     The last page of the searched VAD.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value
///
{
    INTSTATUS status;
    PVAD pVad;
    QWORD vadroot = 0, vadgva = 0;

    status = IntKernVirtMemRead(Process->EprocessAddress + WIN_KM_FIELD(Process, VadRoot),
                                gGuest.WordSize, &vadroot, NULL);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemRead failed: 0x%08x\n", status);
        return NULL;
    }

    for (DWORD tries = 0; tries < VAD_SEARCH_LIMIT; tries++)
    {
        vadgva = IntWinVadFindNodeInGuestSpace(vadroot, StartPage, EndPage, 0, 0, FALSE);
        if (0 != vadgva)
        {
            TRACE("[WINVAD] VAD for range [0x%016llx, 0x%016llx] found at 0x%016llx. Tries: %u\n",
                  StartPage, EndPage, vadgva, tries);
            break;
        }
    }

    if (0 == vadgva)
    {
        LOG("IntWinVadFindNodeInGuestSpace failed for range [0x%016llx, 0x%016llx] in process %u\n",
            StartPage, EndPage, Process->Pid);
        return NULL;
    }

    status = IntWinVadHandleInsertGeneric(Process, vadgva, FALSE, &pVad);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntWinVadHandleInsertGeneric failed for VAD %llx: 0x%08x\n", vadgva, status);
        return NULL;
    }

    return pVad;
}


VAD *
IntWinVadFindAndUpdateIfNecessary(
    _Inout_ WIN_PROCESS_OBJECT *Process,
    _In_ QWORD StartHint,
    _In_ QWORD LengthHint
    )
///
/// @brief  Searches for a VAD in the Introcore VAD tree. If no VAD is found, or if the found one does not fully
/// contain the searched range, it will re-scan the guest tree in order to find a matching VAD. If the VAD is taken
/// from the guest, it is inserted in the VAD tree of the given process.
///
/// @param[in]  Process     The process for which the search is done.
/// @param[in]  StartHint   The start page of the range by which to search for the VAD.
/// @param[in]  LengthHint  The length of the range by which to search for the VAD. The last page in the range will
///                         be StartHint + LengthHint -1, rounded down to page size.
///
/// @returns    The found #VAD structure, or the newly created #VAD structure. NULL if the VAD is not found neither
///             in the Introcore tree, nor the guest tree.
///
{
    const QWORD startPage = StartHint & PAGE_MASK;
    const QWORD endPage = (StartHint + LengthHint - 1) & PAGE_MASK;
    VAD *vad = IntWinVadFindByRange(Process, startPage, endPage);
    if (NULL != vad && startPage >= vad->StartPage && endPage <= vad->EndPage)
    {
        return vad;
    }

    vad = IntWinVadRescanVad(Process, startPage, endPage);
    if (NULL == vad)
    {
        LOG("IntWinVadRescanVad failed for [0x%016llx, 0x%016llx] in process %u\n",
            startPage, endPage, Process->Pid);
    }

    return vad;
}


static INTSTATUS
IntWinVadHandleProtectGeneric(
    _Inout_ WIN_PROCESS_OBJECT *Process,
    _In_ QWORD StartPage,
    _In_ QWORD EndPage,
    _In_ DWORD VmProtection,
    _In_ BOOLEAN AtInsertion
    )
///
/// @brief  Handles a VAD protection change.
///
/// This is the common handler for these changes and it should be invoked after the OS-specific handlers gathers
/// the needed information from the guest.
///
/// It will update every page in the [StartPage, EndPage] range (the range is inclusive). The #VAD_PAGE.RangeStart
/// for each of these pages will be set to the minimum between the current RangeStart and the supplied StartPage; the
/// #VAD_PAGE.RangeEnd for each of these paged will be set to the maximum between the current RangeEnd and the
/// supplied EndPage, in order to keep the ranges as large as possible.
///
/// If the guest adds the execution rights for these pages, we hook them against executions; if the right is removed
/// we remove our hooks.
///
/// @param[in]  Process         The process for which the change is done.
/// @param[in]  StartPage       The start of the modified range.
/// @param[in]  EndPage         The end of the modified range.
/// @param[in]  VmProtection    The Windows memory protection constant used for this range.
///                             See https://docs.microsoft.com/en-us/windows/win32/memory/memory-protection-constants
/// @param[in]  AtInsertion     True if this function is called as a result of a new VAD being inserted in the
///                             guest VAD tree; False in all other situations (for example, as a result of a
///                             VirtualProtect call). This is used to determine if we should ignore this change,
///                             because a user mode program may request a protection change after a VAD is allocated,
///                             but if the NoChange flag is set, the kernel will ignore that request.
///
/// @retval     #INT_STATUS_SUCCESS in case of success.
/// @retval     #INT_STATUS_INVALID_PARAMETER_MIX if EndPage is lower than StartPage.
/// @retval     #INT_STATUS_INVALID_PARAMETER_2 if StartPage is not inside the VAD.
/// @retval     #INT_STATUS_INVALID_PARAMETER_3 if EndPage is not inside the VAD.
/// @retval     #INT_STATUS_NOT_INITIALIZED_HINT if the VAD is not found neither in our tree, nor in the guest
///             tree. This is not a problem, as user mode code can request protection changes for invalid address
///             ranges.
/// @retval     #INT_STATUS_NOT_NEEDED_HINT if this is a huge VAD, or a mapped executable file, or an attempt to
///             change the protection for a VAD that has the NoChange flag set.
/// @retval     #INT_STATUS_INSUFFICIENT_RESOURCES if not enough memory is available.
///

{
    INTSTATUS status;
    PVAD pVad;
    DWORD newprot;

    if (EndPage < StartPage)
    {
        return INT_STATUS_INVALID_PARAMETER_MIX;
    }

    // Get the associated VAD.
    pVad = IntWinVadFindByRange(Process, StartPage, EndPage);
    if (NULL == pVad)
    {
        QWORD vadroot = 0, vadgva = 0;

        TRACE("[WINVAD] Range [%llx, %llx] not cached, searching guest space for VAD...\n", StartPage, EndPage);

        status = IntKernVirtMemRead(Process->EprocessAddress + WIN_KM_FIELD(Process, VadRoot),
                                    gGuest.WordSize,
                                    &vadroot,
                                    NULL);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntKernVirtMemRead failed: 0x%08x\n", status);
            return status;
        }

        for (DWORD tries = 0; tries < VAD_SEARCH_LIMIT; tries++)
        {
            vadgva = IntWinVadFindNodeInGuestSpace(vadroot, StartPage, EndPage, 0, 0, FALSE);
            if (0 != vadgva)
            {
                break;
            }
        }

        if (0 == vadgva)
        {
            // We'll only warn and return an informational status as there might be in-guest race conditions.
            // For example, calling VirtualProtectEx on a previously freed memory region.
            WARNING("[WARNING] IntWinVadFindNodeInGuestSpacefailed to find a VAD for range [%llx, %llx] "
                    "in process %d\n", StartPage, EndPage, Process->Pid);
            return INT_STATUS_NOT_INITIALIZED_HINT;
        }

        TRACE("[WINVAD] VAD for range [%llx, %llx] found at %llx\n", StartPage, EndPage, vadgva);

        status = IntWinVadHandleInsertGeneric(Process, vadgva, FALSE, &pVad);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntWinVadHandleInsertGeneric failed for VAD %llx: 0x%08x\n", vadgva, status);
            return status;
        }
    }

    if ((StartPage < pVad->StartPage) || (StartPage > pVad->EndPage))
    {
        ERROR("[ERROR] The start page lies outside the VAD range: 0x%016llx vs [0x%016llx, 0x%016llx]\n",
              StartPage, pVad->StartPage, pVad->EndPage);
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    if ((EndPage < pVad->StartPage) || (EndPage > pVad->EndPage))
    {
        ERROR("[ERROR] The end page lies outside the VAD range: 0x%016llx vs [0x%016llx, 0x%016llx]\n",
              EndPage, pVad->StartPage, pVad->EndPage);
        return INT_STATUS_INVALID_PARAMETER_3;
    }

    if (pVad->HugeVad)
    {
        WARNING("[WARNING] Protecting range [0x%016llx, 0x%016llx] of huge VAD [0x%016llx, 0x%016llx] "
                "with %llu pages at GVA 0x%016llx\n",
                StartPage, EndPage, pVad->StartPage, pVad->EndPage, pVad->PageCount, pVad->VadGva);
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    pVad->IsIgnored = IntWinVadIsProbablyNaCl(pVad);
    if (pVad->IsIgnored)
    {
        TRACE("[INFO] Ignoring VAD @ 0x%016llx [0x%016llx, 0x%016llx] for process `%s` (%d)\n",
              pVad->VadGva, pVad->StartPage, pVad->EndPage, Process->Name, Process->Pid);
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    // We are not interested in mapped executable files, so we will skip them.
    if (((pVad->VadType == VadImageMap) && (pVad->PageCount > 2)) ||
        (VadRotatePhysical == pVad->VadType) ||
        (VadDevicePhysicalMemory == pVad->VadType) ||
        !pVad->Process->ProtExploits ||
        (pVad->ExecCount > MIN((pVad->PageCount / 20), MAX_VAD_EXECS)))
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    // If the function was called due to some VirtualProtect call (or commit with different rights)
    // and the Vad.u.VadFlags.NoChange is set, we should bail out, as the OS won't apply the protections to it.
    if (pVad->NoChange && !AtInsertion)
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    // Compute the simplified protection mask.
    newprot = IntWinVadVmProtectionToIntroProtection(VmProtection);
    if (VmProtection & WIN_MM_PAGE_GUARD)
    {
        pVad->IsStack = TRUE;
    }

    // If the pages array was not allocated, do so now.
    if (NULL == pVad->VadPages)
    {
        pVad->VadPages = HpAllocWithTag(sizeof(*pVad->VadPages) * pVad->PageCount, IC_TAG_VAD_PGARR);
        if (NULL == pVad->VadPages)
        {
            return INT_STATUS_INSUFFICIENT_RESOURCES;
        }
    }

    for (QWORD curpg = (StartPage & PAGE_MASK); curpg <= (EndPage & PAGE_MASK); curpg += PAGE_SIZE)
    {
        DWORD pos = (DWORD)((curpg - pVad->StartPage) >> 12);

        if (NULL == pVad->VadPages[pos])
        {
            pVad->VadPages[pos] = HpAllocWithTag(sizeof(**pVad->VadPages), IC_TAG_VAD_PAGE);
            if (NULL == pVad->VadPages[pos])
            {
                return INT_STATUS_INSUFFICIENT_RESOURCES;
            }

            // So we can do MIN/MAX on them.
            pVad->VadPages[pos]->RangeStart = 0xFFFFFFFFFFFFFFFF;
            pVad->VadPages[pos]->RangeEnd = 0;

            // The old page protection was given by the VAD protection.
            pVad->VadPages[pos]->Vad = pVad;
            pVad->VadPages[pos]->Address = curpg;
            pVad->VadPages[pos]->VmProtection = VmProtection;
            pVad->VadPages[pos]->Protection = newprot;
        }
        else
        {
            pVad->VadPages[pos]->VmProtection = VmProtection;
            pVad->VadPages[pos]->Protection = newprot;
        }

        // We always store the maximum range, in order to remove as many pages when we detect a legitimate execution.
        pVad->VadPages[pos]->RangeStart = MIN(pVad->VadPages[pos]->RangeStart, StartPage);
        pVad->VadPages[pos]->RangeEnd = MAX(pVad->VadPages[pos]->RangeEnd, EndPage);

        if ((0 != (newprot & PROT_EXEC)) &&
            (NULL == pVad->VadPages[pos]->ExecHook) && (!pVad->VadPages[pos]->Legitimate))
        {
            status = IntHookGvaSetHook(Process->Cr3, curpg, PAGE_SIZE, IG_EPT_HOOK_EXECUTE,
                                       IntWinVadHandlePageExecution, pVad->VadPages[pos], NULL, 0,
                                       (PHOOK_GVA *)&pVad->VadPages[pos]->ExecHook);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntHookGvaSetHook failed: 0x%08x\n", status);
            }
        }

        // The page was executable, and now it is not.
        if (0 == (newprot & PROT_EXEC) && (NULL != pVad->VadPages[pos]->ExecHook))
        {
            status = IntHookGvaRemoveHook((HOOK_GVA **)&pVad->VadPages[pos]->ExecHook, 0);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntHookGvaRemoveHook failed: 0x%08x\n", status);
            }
        }
    }

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntWinVadReimportProcessTree(
    _Inout_ WIN_PROCESS_OBJECT *Process
    )
///
/// @brief  Re-scans and re-imports the VAD tree of a process.
///
/// This will remove all entries in the current tree and re-create it.
///
/// @param[in, out] Process The process for which the re-import is done.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value
///
{
    INTSTATUS status;

    status = IntWinVadRemoveProcessTree(Process);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntWinVadRemoveProcessTree failed: 0x%08x\n", status);
        return status;
    }

    status = IntWinVadImportProcessTree(Process);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntWinVadImportProcessTree failed: 0x%08x\n", status);
        return status;
    }

    return status;
}


static INTSTATUS
IntWinVadHandleDeleteGeneric(
    _Inout_ WIN_PROCESS_OBJECT *Process,
    _In_ QWORD StartPage,
    _In_ QWORD EndPage,
    _In_ DWORD Level
    )
///
/// @brief  Handles the deletion of a VAD or of memory range from a VAD.
///
/// This is the common handler for these changes and it should be invoked after the OS-specific handler gathers
/// the needed information from the guest.
///
/// The [StartPage, EndPage] range is inclusive.
///
/// The function will attempt to find a VAD by the provided range. If no VAD is found nothing is done. This is
/// expected since we ignore certain VAD types, but we may still receive deletion events for them.
///
/// When a VAD is found there are 4 possible cases:
///     - #VAD.StartPage and #VAD.EndPage match the provided StartPage and EndPage: this means that the entire VAD
/// is deleted - we handle this by removing the VAD node from the #WIN_PROCESS_OBJECT.VadTree and by destroying the
/// VAD itself with #IntWinVadDestroyObject.
///     - #VAD.StartPage matches StartPage, but #VAD.EndPage is higher than EndPage: this means that a lower sub-range
/// of the VAD is deleted - this is handled by adjusting the VAD range with #IntWinVadAdjustRange.
///     - #VAD.EndPage matches EndPage, but #VAD.StartPage is lower than StartPage: this means that an upper sub-range
/// of the VAD is deleted, similar to the previous case - we handle this in the same way, with #IntWinVadAdjustRange.
///     - #VAD.StartPage and #VAD.EndPage are both contained inside the VAD: meaning that an internal sub-range is
/// deleted - this is not supported or expected, as VADs can not be split by the Windows kernel. This is usually a
/// a sign that we missed a VAD transition somewhere. In this case we pause the guest, re-import the VAD tree with
/// #IntWinVadReimportProcessTree and re-try the deletion. This is the only case in which this function is recursive and
/// it is the reason for which we only allow for Level to be 0 or 1. If this fails, Introcore will try to break
/// into a debugger.
///
/// Due to the way #IntWinVadFindByRange works, we will always be in a case in which [StartPage, EndPage] are included
/// inside the VAD, and we can not expect for StartPage to be lower than #VAD.StartPage, or EndPage to be higher than
/// #VAD.EndPage.
///
/// @param[in, out] Process     The process that owns the deleted VAD.
/// @param[in]      StartPage   The start of the deleted memory range.
/// @param[in]      EndPage     The last page in the deleted memory range.
/// @param[in]      Level       The number of times this function recursed. Should be 0 when invoked to delete a range.
///                             If Level is higher than 1 the function bails out.
///
/// @retval     #INT_STATUS_SUCCESS in case of success.
/// @retval     #INT_STATUS_INVALID_PARAMETER_4 if Level is greater or equal to 2.
/// @retval     #INT_STATUS_INVALID_PARAMETER_2 if End page is less than StartPage.
///
{
    INTSTATUS status;
    PVAD pVad;

    if (Level >= 2)
    {
        WARNING("[WARNING] Exceeded max recursion level for VAD deletion @ [0x%016llx, 0x%016llx] %s:%d\n",
                StartPage, EndPage, Process->Name, Process->Pid);
        IntDbgEnterDebugger();
        return INT_STATUS_INVALID_PARAMETER_4;
    }

    if (EndPage < StartPage)
    {
        WARNING("[WARNING] EndPage is LESS than StartPage: [0x%016llx, 0x%016llx]\n", StartPage, EndPage);
        IntDbgEnterDebugger();
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    pVad = IntWinVadFindByRange(Process, StartPage, EndPage);
    if (NULL == pVad)
    {
        // Since we ignore all VAD types except for VadNone and VadImageMap, we don't have to log error here or
        // return an error.
    }
    else if ((StartPage == pVad->StartPage) && (EndPage == pVad->EndPage))
    {
        RbDeleteNode(&Process->VadTree, &pVad->RbNode);

        IntWinVadDestroyObject(&pVad);
    }
    else if (StartPage == pVad->StartPage)
    {
        // Only the lower sub-range is deleted
        QWORD newStart = EndPage + PAGE_SIZE;

        TRACE("[WINVAD] Adjusting VAD 0x%016llx. Old start: 0x%016llx New start: 0x%016llx "
              "for process %s:%d (0x%016llx)\n",
              pVad->VadGva, pVad->StartPage, newStart, Process->Name, Process->Pid, Process->EprocessAddress);

        status = IntWinVadAdjustRange(pVad, newStart, pVad->EndPage);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntWinVadAdjustRange failed for [0x%016llx, 0x%016llx] in VAD 0x%016llx "
                  "process 0x%016llx: 0x%08x\n",
                  StartPage, EndPage, pVad->VadGva, Process->EprocessAddress, status);
        }
    }
    else if (EndPage == pVad->EndPage)
    {
        // Only the upper sub-range is deleted
        QWORD newEnd = StartPage - PAGE_SIZE;

        TRACE("[WINVAD] Adjusting VAD 0x%016llx. Old end: 0x%016llx New end: 0x%016llx for process %s:%d (0x%016llx)\n",
              pVad->VadGva, pVad->EndPage, newEnd, Process->Name, Process->Pid, Process->EprocessAddress);

        status = IntWinVadAdjustRange(pVad, pVad->StartPage, newEnd);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntWinVadAdjustRange failed for [0x%016llx, 0x%016llx] in VAD 0x%016llx "
                  "process 0x%016llx: 0x%08x\n",
                  StartPage, EndPage, pVad->VadGva, Process->EprocessAddress, status);
        }
    }
    else
    {
        TRACE("[WINVAD] Guest attempts to delete VAD [%016llx, %016llx], but we matched with VAD [%016llx, %016llx]"
              ",  will reimport process tree for %s:%d\n",
              StartPage, EndPage, pVad->StartPage, pVad->EndPage,
              Process->Name, Process->Pid);

        IntPauseVcpus();

        status = IntWinVadReimportProcessTree(Process);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntWinVadReimportProcessTree failed: 0x%08x\n", status);
            goto _resume_maybe_enter_dbg;
        }

        status = IntWinVadHandleDeleteGeneric(Process, StartPage, EndPage, Level + 1);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntWinVadHandleDeleteGeneric failed: 0x%08x\n", status);
            goto _resume_maybe_enter_dbg;
        }

_resume_maybe_enter_dbg:
        IntResumeVcpus();

        if (!INT_SUCCESS(status))
        {
            IntDbgEnterDebugger();
        }
    }

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntWinVadHandleInsertGeneric(
    _Inout_ WIN_PROCESS_OBJECT *Process,
    _In_ QWORD VadAddress,
    _In_ BOOLEAN StaticScan,
    _Out_opt_ VAD **Vad
    )
///
/// @brief  Handles the insertion of a VAD into a process VAD tree.
///
/// This is the common handler for these changes and it should be invoked after the OS-specific handler gathers
/// the needed information from the guest.
///
/// If #WIN_PROCESS_OBJECT.MonitorVad is False we do not insert the VAD in the VAD tree and do not monitor it. This
/// can happen when we initially protect a process, but after we obtain its main module path we decide to remove that
/// protection.
///
/// When importing an entire VAD tree we may race with the guest: some threads may be freeing memory in the process
/// while we import the tree. The main problem with this is that if parts of that freed memory are reused, when
/// a VAD is created we will fail to insert it into our VAD tree because it overlaps with an existing one.
/// The solution is to delete any overlapping VADs. Note that protecting a freed VAD should have no impact because if
/// that memory is not reused we will only place a hook on their corresponding page table entries, which should not
/// have an impact as those will be unused until the VAs are reallocated, in which case we will delete the old hooks
/// anyway. In theory, for each page in a new VAD there can be an overlapping VAD, so we try to insert the new VAD as
/// many times as there are pages in it.
///
/// If needed, the VAD is monitored using #IntWinVadHandleProtectGeneric.
///
/// @param[in, out] Process     The process that owns the VAD.
/// @param[in]      VadAddress  The guest virtual address of the _MMVAD structure.
/// @param[in]      StaticScan  True if this VAD was discovered by a memory scan instead of being discovered when it
///                             was created.
/// @param[out]     Vad         On success, will contain a pointer to the new #VAD structure. May be NULL.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value.
///

{
    INTSTATUS status;
    PVAD pVad = NULL;
    BOOLEAN previouslyMonitored;

    if (Vad != NULL)
    {
        *Vad = NULL;
    }

    previouslyMonitored = !!(Process->MonitorVad);

    status = IntWinVadCreateObject(Process, VadAddress, &pVad, StaticScan);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntWinVadCreateObject failed: 0x%08x\n", status);

        return status;
    }

    if (NULL != pVad && Process->MonitorVad)
    {
        BOOLEAN hugeNoWrite;
        const QWORD maxTries = pVad->PageCount + 1;
        QWORD tryCount = 0;

        do
        {
            PVAD toRemove;

            status = RbInsertNode(&Process->VadTree, &pVad->RbNode);
            if (INT_STATUS_KEY_ALREADY_EXISTS != status)
            {
                // We managed to insert it (or another error occurred), break out of the loop
                break;
            }

            WARNING("[WARNING] [WINVAD] Special case `INT_STATUS_KEY_ALREADY_EXISTS` while inserting 0x%016llx "
                    "[0x%016llx, 0x%016llx] in 0x%016llx (PID %u)\n",
                    pVad->VadGva, pVad->StartPage, pVad->EndPage, Process->EprocessAddress, Process->Pid);

            toRemove = IntWinVadFindByRange(Process, pVad->StartPage, pVad->EndPage);
            if (NULL == toRemove)
            {
                ERROR("[ERROR] IntWinVadFindByRange failed for [%016llx, %016llx]\n", pVad->StartPage, pVad->EndPage);
                IntDbgEnterDebugger();
                IntWinVadDestroyObject(&pVad);

                return status;
            }

            status = IntWinVadHandleDeleteGeneric(Process, toRemove->StartPage, toRemove->EndPage, 0);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntWinVadHandleDeleteGeneric failed for [0x%016llx, 0x%016llx] "
                      "in process 0x%016llx: 0x%08x\n",
                      toRemove->StartPage, toRemove->EndPage, Process->EprocessAddress, status);
            }

            tryCount++;
        } while (tryCount < maxTries);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] RbInsertNode failed for [0x%016llx, 0x%016llx] in process PID %u: 0x%08x\n",
                  pVad->StartPage, pVad->EndPage, Process->Pid, status);
            IntDbgEnterDebugger();
            IntWinVadDestroyObject(&pVad);

            return status;
        }

        pVad->IsIgnored = IntWinVadIsProbablyNaCl(pVad);
        if (pVad->IsIgnored)
        {
            TRACE("[INFO] Ignoring VAD @ 0x%016llx [0x%016llx, 0x%016llx] for process `%s` (%d)\n",
                  pVad->VadGva, pVad->StartPage, pVad->EndPage, Process->Name, Process->Pid);
        }

        hugeNoWrite = (pVad->PageCount >= 65536) && (0 == (pVad->Protection & PROT_WRITE));

        // If needed, monitor these pages.
        if ((!pVad->IsIgnored) && (!hugeNoWrite) && (pVad->Protection & PROT_EXEC) &&
            ((pVad->VadType != VadImageMap) || (pVad->PageCount <= 2)))
        {
            status = IntWinVadHandleProtectGeneric(Process, pVad->StartPage, pVad->EndPage,
                                                   IntWinVadVadProtectionToVmProtection(pVad->VadProtection), TRUE);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntWinVadHandleProtectGeneric failed: 0x%08x\n", status);
            }
        }
    }
    else if (pVad != NULL && previouslyMonitored)
    {
        //
        // We decided on the current VAD (which is also the main module) that VAD should not be monitored
        // anymore. Thus the current VAD should be destroyed. Note that the VADs inserted before this
        // would have already been destroyed, due to the fact that we called IntWinVadRemoveProcessTree,
        // but the current VAD has not got the chance to be added into the tree - thus it will be leaked
        // otherwise.
        // Also, a big note to this is the fact that a caller might externally call this function mistakenly
        // for non-protected (and non-vad-monitored) processes. As a safe guard, we'll destroy the VAD only
        // if it was decided in IntWinVadCreateObject that from now on we should not monitor vad anymore.
        //
        IntWinVadDestroyObject(&pVad);
    }

    if (Vad != NULL)
    {
        *Vad = pVad;
    }
    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntWinVadStaticInsertNodeIntoProcess(
    _In_ QWORD VadNodeGva,
    _In_ DWORD Level,
    _Inout_ WIN_PROCESS_OBJECT *Process
    )
///
/// @brief  Inserts a VAD found by a memory scan inside a Introcore process VAD tree.
///
/// @param[in]      VadNodeGva  The guest virtual address of the VAD node in the guest VAD tree.
/// @param[in]      Level       The level at which the node is found.
/// @param[in, out] Process     The process that owns the VAD.
///
/// @retval     #INT_STATUS_SUCCESS in case of success.
/// @retval     #INT_STATUS_INVALID_PARAMETER_1 if VadNodeGva is not a valid kernel pointer.
/// @retval     #INT_STATUS_NOT_NEEDED_HINT if #WIN_PROCESS_OBJECT.MonitorVad is False. While walking the guest
///             VAD tree, we may decide to remove the protection of this process, based on the process main module, in
///             which case we no longer care about the VADs.
///
{
    INTSTATUS status;

    UNREFERENCED_PARAMETER(Level);

    if (!IS_KERNEL_POINTER_WIN(gGuest.Guest64, VadNodeGva))
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    // It is possible that during VAD iteration we decided to remove the process protection (based on the Main Module)
    // Thus, don't insert the current node if MonitorVad was cleared.
    if (!Process->MonitorVad)
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    status = IntWinVadHandleInsertGeneric(Process, VadNodeGva, TRUE, NULL);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntWinVadHandleInsertGeneric failed for 0x%016llx in process %d: 0x%08x\n",
              VadNodeGva, Process->Pid, status);
        return status;
    }

    TRACE("[WINVAD] VAD 0x%016llx found at static scan on level %d\n", VadNodeGva, Level);

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntWinVadImportProcessTree(
    _Inout_ WIN_PROCESS_OBJECT *Process
    )
///
/// @brief  Scans the guest VAD tree and imports the nodes into our VAD tree.
///
/// @param[in, out] Process The process for which the scan is done. On success, #WIN_PROCESS_OBJECT.VadTree will be
///                         populated wit the relevant VADs.
///
/// @retval     #INT_STATUS_SUCCESS in case of success.
/// @retval     #INT_STATUS_INVALID_PARAMETER_1 if Process is NULL.
/// @retval     #INT_STATUS_NOT_NEEDED_HINT if the process VAD root is not yet initialized. This means that the process
///             does not have any VADs yet, and we will detect all the VADs we need dynamically when they are created.
///
{
    INTSTATUS status;
    QWORD root = 0;

    if (NULL == Process)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    status = IntKernVirtMemRead(Process->EprocessAddress + WIN_KM_FIELD(Process, VadRoot),
                                gGuest.WordSize,
                                &root,
                                NULL);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemRead failed: 0x%08x\n", status);
        return status;
    }

    if (0 == root)
    {
        TRACE("[WINVAD] Skipping static scan for process 0x%016llx because root @ 0x%016llx is 0\n",
              Process->EprocessAddress, Process->EprocessAddress + WIN_KM_FIELD(Process, VadRoot));
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    TRACE("[WINVAD] Starting static scan for process 0x%016llx from root @ 0x%016llx = 0x%016llx\n",
          Process->EprocessAddress,
          Process->EprocessAddress + WIN_KM_FIELD(Process, VadRoot),
          root);

    status = IntWinVadInOrderRecursiveTraversal(root, 0, IntWinVadStaticInsertNodeIntoProcess, Process);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntWinVadInOrderRecursiveTraversal failed for root 0x%016llx: 0x%08x\n", root, status);
        return status;
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntWinVadHandleInsert(
    _In_ void const  *Detour
    )
///
/// @brief      The detour handler that will be invoked when the guest inserts a new VAD in the tree.
/// @ingroup    group_detours
///
/// This is the detour handler for the MiInsertVad guest API.
///
/// It will gather from the guest two pieces of information: the guest virtual address of the _MMVAD structure, and
/// the guest virtual address of the _EPROCESS that owns it. If the process for which the insertion is done is known
/// by Introcore and if VAD monitoring is enabled for it, #IntWinVadHandleInsertGeneric will handle the insertion.
/// Since this could be invoked before the process is inserted in our list of processes, any VADs inserted for an
/// unknown process will be ignored. Those will be detected later by a static memory scan done with
/// #IntWinVadImportProcessTree.
///
/// @param[in]  Detour  The detour for which this callback is invoked.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value.
///
{
    INTSTATUS status;
    WIN_PROCESS_OBJECT *pProc;
    QWORD args[2];
    QWORD vadGva;
    QWORD eprocessGva;

    if (NULL == Detour)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    // the parameters are the same on x86 as on x64
    // RCX: pointer to a MMVAD or MMVAD_SHORT structure. Private VADs (created by VirtualAlloc(Ex) calls) are
    // always MMVAD_SHORT
    // RDX: pointer to the EPROCESS structure of the process for which the VAD is created. This might not be in
    // the process list yet
    status = IntDetGetArguments(Detour, 2, args);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntDetGetArguments failed: 0x%08x\n", status);
        goto cleanup_and_exit;
    }

    vadGva = args[0];
    eprocessGva = args[1];

    // Get the process object.
    pProc = IntWinProcFindObjectByEprocess(eprocessGva);
    if (!pProc || !pProc->MonitorVad)
    {
        status = INT_STATUS_NOT_NEEDED_HINT;
        goto cleanup_and_exit;
    }

    status = IntWinVadHandleInsertGeneric(pProc, vadGva, FALSE, NULL);
    if (INT_STATUS_NOT_FOUND != status && !INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntWinVadHandleInsertionGeneric failed for process 0x%016llx VAD 0x%016llx: 0x%08x\n",
              eprocessGva, vadGva, status);
        goto cleanup_and_exit;
    }

    status = INT_STATUS_SUCCESS;

cleanup_and_exit:

    return status;
}


INTSTATUS
IntWinVadHandleInsertPrivate(
    _In_ void const *Detour
    )
///
/// @brief      The detour handler that will be invoked when the guest inserts a new VAD in the tree.
/// @ingroup    group_detours
///
/// This is the detour handler for the MiInsertPrivateVad guest API.
///
/// It will obtain the guest virtual address of the new _MMVAD structure and will delegate the insertion handling
/// to #IntWinVadHandleInsertGeneric. The process that owns the VAD is always the current process, which is obtained
/// by searching it by the currently loaded CR3. Since this could be invoked before the process is inserted in our
/// list of processes, any VADs inserted for an unknown process will be ignored. Those will be detected later by
/// a static memory scan done with #IntWinVadImportProcessTree.
///
/// @param[in]  Detour  The detour for which this callback is invoked.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value.
///
{
    INTSTATUS status;
    PWIN_PROCESS_OBJECT pProc = NULL;
    PIG_ARCH_REGS pRegs = NULL;
    QWORD vadGva = 0;

    if (NULL == Detour)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    pRegs = &gVcpu->Regs;

    status = IntDetGetArgument(Detour, 0, NULL, 0, &vadGva);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntDetGetArgument failed: 0x%08x\n", status);
        goto cleanup_and_exit;
    }

    pProc = IntWinProcFindObjectByCr3(pRegs->Cr3);
    if (!pProc || !pProc->MonitorVad)
    {
        status = INT_STATUS_NOT_NEEDED_HINT;
        goto cleanup_and_exit;
    }

    status = IntWinVadHandleInsertGeneric(pProc, vadGva, FALSE, NULL);
    if (INT_STATUS_NOT_FOUND != status && !INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntWinVadHandleInsertionGeneric failed for process 0x%016llx VAD 0x%016llx: 0x%08x\n",
              pProc->EprocessAddress, vadGva, status);
        goto cleanup_and_exit;
    }

    status = INT_STATUS_SUCCESS;

cleanup_and_exit:

    return status;
}

_Function_class_(PFUNC_PreDetourCallback)
INTSTATUS
IntWinPatchVadHandleCommit(
    _In_ QWORD FunctionAddress,
    _Inout_ API_HOOK_HANDLER *Handler,
    _In_ void *Descriptor
    )
///
/// @brief      This is the #PFUNC_PreDetourCallback for the MiCommitExistingVad guest API detour.
/// @ingroup    group_detours
///
/// It will be invoked before the detour is placed inside the guest and will patch the detour handler with the values
/// of #winKmFieldPcrCurrentThread, #winKmFieldThreadAttachedProcess, #winKmFieldThreadProcess, and
/// #winKmFieldProcessSpare. For 32-bit kernels it will also patch the stack location at which the VmProtection
/// parameter is located.
///
/// @param[in]      FunctionAddress Guest virtual address of the hooked function. Ignored.
/// @param[in, out] Handler         The hook handler structure. This will have the #API_HOOK_HANDLER.Code byte array
///                                 changed.
/// @param[in]      Descriptor      Pointer to a structure that describes the hook and the detour handler.
///
/// @returns    #INT_STATUS_SUCCESS is always returned.
///
{
    API_HOOK_HANDLER *pHandler = Handler;

    UNREFERENCED_PARAMETER(FunctionAddress);
    UNREFERENCED_PARAMETER(Descriptor);

    if (gGuest.Guest64)
    {
        *(DWORD *)(pHandler->Code + 0x0d) = WIN_KM_FIELD(Pcr, CurrentThread);

        *(DWORD *)(pHandler->Code + 0x14) = WIN_KM_FIELD(Thread, AttachedProcess);

        *(DWORD *)(pHandler->Code + 0x1f) = WIN_KM_FIELD(Thread, Process);

        *(DWORD *)(pHandler->Code + 0x25) = WIN_KM_FIELD(Process, Spare);
        *(DWORD *)(pHandler->Code + 0x2d) = WIN_KM_FIELD(Process, Spare);
    }
    else
    {
        if (gGuest.OSVersion < WIN_BUILD_8_1)
        {
            // Stdcall
            *(BYTE *)(pHandler->Code + 0x3) = 0x10;
        }
        else
        {
            // Fastcall
            *(BYTE *)(pHandler->Code + 0x3) = 0x8;
        }

        *(DWORD *)(pHandler->Code + 0x0c) = WIN_KM_FIELD(Pcr, CurrentThread);

        *(DWORD *)(pHandler->Code + 0x12) = WIN_KM_FIELD(Thread, AttachedProcess);

        *(DWORD *)(pHandler->Code + 0x1c) = WIN_KM_FIELD(Thread, Process);

        *(DWORD *)(pHandler->Code + 0x22) = WIN_KM_FIELD(Process, Spare);
        *(DWORD *)(pHandler->Code + 0x2a) = WIN_KM_FIELD(Process, Spare);
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntWinVadHandleCommit(
    _In_ void const *Detour
    )
///
/// @brief      The detour handler that will be invoked when an existing VAD is committed by the guest.
/// @ingroup    group_detours
///
/// This is the detour handler for the MiCommitExistingVad guest API. Due to the way we ignore certain VADs, this can
/// be invoked either when protection is changed for a known VAD, in which case we have to adjust our protection; or,
/// when protection is changed for a previously unknown VAD in a way that makes it relevant for Introcore, in which
/// case we treat as a newly created VAD.
///
/// This function will obtain 4 parameters from the guest: the guest virtual address of the _MMVAD structure, that
/// first page of the modified memory range, the size of the modified memory range, and the protection applied for
/// the given memory range.
/// This means that for the VAD at the found GVA, the pages in the range [start, start + length - 1] have their
/// protection policy modified. These changes are always done for the current process.
///
/// First, we obtain the current process, searching it by the currently loaded CR3. If the process is not protected,
/// or if VADs are not monitored for it, we bail out.
///
/// Then, we try to find a matching VAD in our tree by the start of the modified memory range. If a VAD is found, it
/// can be an old VAD that we haven't removed yet - this can be checked by comparing the guest virtual address of
/// the _MMVAD structure with the known address in #VAD.VadGva. If they match, we simply compute the start and end
/// of the range, and delegate the changes to #IntWinVadHandleProtectGeneric. If they don't match, we first try
/// to insert the VAD now using #IntWinVadHandleInsertGeneric (this will remove any old overlapping VADs).
/// If no VAD is found, it means that we ignored it up until this point, so we insert it now into our tree using
/// #IntWinVadHandleInsertGeneric, then we handle the protection changes with #IntWinVadHandleProtectGeneric. This
/// two-step method is needed because the insert function will look only at the memory protection rights in the
/// _MMVAD structure, which will be the original protection rights, not the newly set rights for the given range.
///
/// @param[in]  Detour  The detour for which this callback is invoked.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value.
///
{
    WIN_PROCESS_OBJECT *pProc;
    IG_ARCH_REGS *regs;
    INTSTATUS status;
    QWORD gvaVad;
    QWORD protPage;
    QWORD protSize;
    DWORD vmProt;
    QWORD endPage;
    QWORD args[4] = {0};
    VAD *pVad;

    STATS_ENTER(statsVadCommitExisting);

    regs = &gVcpu->Regs;
    pProc = IntWinProcFindObjectByCr3(regs->Cr3);

    if (!pProc || !pProc->Protected || !pProc->MonitorVad)
    {
        // Nothing to do
        goto cleanup_and_exit;
    }

    status = IntDetGetArguments(Detour, 4, args);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntDetGetArgument failed: 0x%08x\n", status);
        goto cleanup_and_exit;
    }

    gvaVad = args[0];
    protPage = args[1];
    protSize = args[2];
    vmProt = (DWORD)args[3];

    // Try to find an existing VAD
    pVad = IntWinVadFindByVa(pProc, protPage);
    if (NULL != pVad)
    {
        if (gvaVad != pVad->VadGva)
        {
            // This VAD was deleted in the meantime, try to get it back
            status = IntWinVadHandleInsertGeneric(pProc, gvaVad, FALSE, NULL);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntWinVadHandleInsertGeneric failed for 0x%016llx: 0x%08x\n", gvaVad, status);
                goto cleanup_and_exit;
            }
        }
    }
    else
    {
        status = IntWinVadHandleInsertGeneric(pProc, gvaVad, FALSE, NULL);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntWinVadHandleInsertGeneric failed for 0x%016llx: 0x%08x\n", gvaVad, status);
            goto cleanup_and_exit;
        }
    }

    // Now apply the protection change. Note that VAD ranges are inclusive, so the end page is the last page
    // contained by the VAD
    endPage = (protPage + protSize - 1) & PAGE_MASK;
    protPage &= PAGE_MASK;

    status = IntWinVadHandleProtectGeneric(pProc, protPage, endPage, vmProt, FALSE);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntWinVadHandleProtectGeneric failed for [0x%016llx, 0x%016llx]: 0x%08x\n",
              protPage, endPage, status);
        goto cleanup_and_exit;
    }

cleanup_and_exit:
    STATS_EXIT(statsVadCommitExisting);

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntWinVadHandleInsertMap(
    _In_ void const *Detour
    )
///
/// @brief      The detour handler that will be invoked when a VAD is inserted in the guest VAD tree.
/// @ingroup    group_detours
///
/// This is the detour handler for the MiGetWsAndInsertVad guest API.
///
/// The process that owns the VAD is always the current process, which is obtained by using the currently loaded CR3.
///
/// This function obtains the guest virtual address of the _MMVAD structure and delegates the insertion to
/// #IntWinVadHandleInsertGeneric.
///
/// @param[in]  Detour  The detour for which this callback is invoked.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value.
///
{
    INTSTATUS status;
    PIG_ARCH_REGS pRegs;
    PWIN_PROCESS_OBJECT pProc;
    QWORD vadGva;

    if (NULL == Detour)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    pRegs = &gVcpu->Regs;

    status = IntDetGetArgument(Detour, 0, NULL, 0, &vadGva);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntDetGetArgument failed: 0x%08x\n", status);
        return status;
    }

    pProc = IntWinProcFindObjectByCr3(pRegs->Cr3);
    if (NULL == pProc || !pProc->MonitorVad)
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    status = IntWinVadHandleInsertGeneric(pProc, vadGva, FALSE, NULL);
    if (INT_STATUS_NOT_FOUND != status && !INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntWinVadHandleInsertionGeneric failed for VAD 0x%016llx: 0x%08x\n", vadGva, status);
    }

    return status;
}


INTSTATUS
IntWinVadHandleDeleteVaRange(
    _In_ void const *Detour
    )
///
/// @brief      The detour handler that will be invoked when a memory range contained by a VAD is deleted.
/// @ingroup    group_detours
///
/// This is the detour handler for the MiDeleteVirtualAddresses guest API.
///
/// The process that owns the VAD is always the current process, which is obtained by using the currently loaded CR3.
///
/// This function obtains the start and end of the deleted range and passes the information to
/// #IntWinVadHandleDeleteGeneric.
/// The deleted range is always inclusive and is always contained in a single VAD and it is either the entire VAD,
/// or a sub-range of it.
///
/// @param[in]  Detour  The detour for which this callback is invoked.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value.
///
{
    QWORD startPage;
    QWORD endPage;
    PIG_ARCH_REGS pRegs;
    PWIN_PROCESS_OBJECT pProcess;
    QWORD args[2];
    INTSTATUS status;

    if (NULL == Detour)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    pRegs = &gVcpu->Regs;

    status = IntDetGetArguments(Detour, 2, args);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntDetGetArguments failed: 0x%08x\n", status);
        return status;
    }

    startPage = args[0];
    endPage = args[1];

    // Align addresses to page boundaries
    startPage &= PAGE_MASK;
    endPage &= PAGE_MASK;

    // This function is always executed in the context of the process from who's address space the pages are removed
    // so we can simply get it by the current Cr3
    pProcess = IntWinProcFindObjectByCr3(pRegs->Cr3);
    if (!pProcess || !pProcess->MonitorVad)
    {
        // No process was created yet, or the process is not VAD monitored - bail out.
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    // Delete the VAD from our internal tree.
    status = IntWinVadHandleDeleteGeneric(pProcess, startPage, endPage, 0);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntWinVadHandleDeleteGeneric failed: 0x%08x\n", status);
        return status;
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntWinVadHandleFinishVadDeletion(
    _In_ void const *Detour
    )
///
/// @brief      The detour handler that will be invoked when a memory range contained by a VAD is deleted.
/// @ingroup    group_detours
///
/// This is the detour handler for the MiFinishVadDeletion guest API.
///
/// The process that owns the VAD is always the current process, which is obtained by using the currently loaded CR3.
///
/// This function obtains the start and end of the deleted range and passes the information to
/// #IntWinVadHandleDeleteGeneric.
/// The deleted range is always inclusive and is always contained in a single VAD and it is either the entire VAD,
/// or a sub-range of it.
///
/// @param[in]  Detour  The detour for which this callback is invoked.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value.
///
{
    QWORD startPage;
    QWORD endPage;
    PIG_ARCH_REGS pRegs;
    PWIN_PROCESS_OBJECT pProcess;
    QWORD args[2];
    INTSTATUS status;

    if (NULL == Detour)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    pRegs = &gVcpu->Regs;

    status = IntDetGetArguments(Detour, 2, args);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntDetGetArguments failed: 0x%08x\n", status);
        return status;
    }

    startPage = args[0];
    endPage = args[1];

    // Align addresses to page boundaries
    startPage &= PAGE_MASK;
    endPage &= PAGE_MASK;

    // This function is always executed in the context of the process from who's address space the pages are removed
    // so we can simply get it by the current Cr3
    pProcess = IntWinProcFindObjectByCr3(pRegs->Cr3);
    if (!pProcess || !pProcess->MonitorVad)
    {
        // No process was created yet, or the process is not VAD monitored - bail out.
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    // Delete the VAD from our internal tree.
    status = IntWinVadHandleDeleteGeneric(pProcess, startPage, endPage, 0);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntWinVadHandleDeleteGeneric failed: 0x%08x\n", status);
        return status;
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntWinVadHandleVirtualProtect(
    _In_ void const *Detour
    )
///
/// @brief      The detour handler that will be invoked when a memory range contained by a VAD has the protection
/// rights changed.
/// @ingroup    group_detours
///
/// This is the detour handler for the MiProtectVirtualMemory guest API, which usually gets called as a result of
/// a user-mode application calling an API like VirtualProtect.
///
/// Since a process can change the protection rights for memory ranges inside other processes, the first thing
/// this function does is to obtain the destination _EPROCESS guest virtual address. If that process is not protected,
/// it bails out.
///
/// Then, it will obtain the guest virtual addresses at which the start and the length of the modified range are
/// stored, as well as the new protection rights, which will be represented by one of the Windows memory protection
/// constants (see https://docs.microsoft.com/en-us/windows/win32/memory/memory-protection-constants). The range for
/// which the new rights are applied will always be contained inside a single VAD and will be inclusive.
/// #IntWinVadHandleProtectGeneric will take care of the actual changes.
///
/// Note that even if the length of the range is less than a 4K page, the rights for the entire page are changed, so
/// the upper limit of the range is always the last modified page.
///
/// @param[in]  Detour  The detour for which this callback is invoked.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value.
///
{
    INTSTATUS status;
    QWORD dstEproc = 0;
    QWORD baseGva = 0;
    QWORD startPage = 0;
    QWORD endPage = 0;
    QWORD length = 0;
    QWORD newRights; // WIN_MM_PAGE_* constants (as passed to VirtualProtect(Ex))
    WIN_PROCESS_OBJECT *pDestProc;
    QWORD args[4];

    status = IntDetGetArgument(Detour, 0, NULL, 0, &dstEproc);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntDetGetArgument failed: 0x%08x\n", status);
        goto cleanup_and_exit;
    }

    pDestProc = IntWinProcFindObjectByEprocess(dstEproc);
    if (!pDestProc || !pDestProc->MonitorVad || !pDestProc->ProtExploits)
    {
        status = INT_STATUS_NOT_NEEDED_HINT;
        goto cleanup_and_exit;
    }

    status = IntDetGetArguments(Detour, 4, args);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntDetGetArguments failed: 0x%08x\n", status);
        goto cleanup_and_exit;
    }

    status = IntKernVirtMemRead(args[1], gGuest.WordSize, &baseGva, NULL);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemRead failed: 0x%08x\n", status);
        goto cleanup_and_exit;
    }

    status = IntKernVirtMemRead(args[2], gGuest.WordSize, &length, NULL);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemRead failed: 0x%08x\n", status);
        goto cleanup_and_exit;
    }

    newRights = args[3] & 0xFFFFFFFF;

    // VirtualProtect documentation: The region of affected pages includes all pages containing one or more bytes in
    // the range from the lpAddress parameter to (lpAddress+dwSize). This means that a 2-byte range straddling a page
    // boundary causes the protection attributes of both pages to be changed.

    endPage = (baseGva + length - 1) & PAGE_MASK;
    startPage = baseGva & PAGE_MASK;

    status = IntWinVadHandleProtectGeneric(pDestProc, startPage, endPage, (DWORD)newRights, FALSE);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntWinVadHandleProtectGeneric failed for [0x%016llx, 0x%016llx] in process 0x%016llx: 0x%08x\n",
              startPage, endPage, pDestProc->EprocessAddress, status);
        goto cleanup_and_exit;
    }

cleanup_and_exit:

    return status;
}


BOOLEAN
IntWinVadIsInTree(
    _In_ const VAD *Vad
    )
///
/// @brief  Checks if a VAD is inserted in a guest VAD tree.
///
/// This function checks that the node for the provided VAD has a valid parent, and that the parent it points to
/// has the VAD either as the Left, or as the Right child.
///
/// @param[in]  Vad The VAD that will be checked.
///
/// @retval     True if the VAD is inserted in a tree.
/// @retval     False if the VAD is not inserted in a tree.
///
{
    INTSTATUS status;
    VAD dummy = { 0 };
    VAD parent = { 0 };

    if (NULL == Vad)
    {
        return FALSE;
    }

    // We allow possible corrupt ranges.
    status = IntWinVadFetchVadFromMemory(Vad->VadGva, &dummy, FALSE);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Could not fetch VAD 0x%016llx from memory: 0x%08x\n", Vad->VadGva, status);
        return FALSE;
    }

    // If the parent value is not a valid kernel pointer, we can assume the VAD was not inserted yet. The parent value
    // seems to always be 0xFFFFFFFE on x86/0xFFFFFFFFFFFFFFFE on x64, but we allow a more relaxed interval, for safety.
    if (!IS_KERNEL_POINTER_WIN(gGuest.Guest64, dummy.Parent) ||
        (dummy.Parent == 0) ||
        ((dummy.Parent >= 0xFFFFFFF0) && (dummy.Parent <= 0xFFFFFFFF)) ||
        ((dummy.Parent >= 0xFFFFFFFFFFFFFFF0) && (dummy.Parent <= 0xFFFFFFFFFFFFFFFF)))
    {
        return FALSE;
    }

    // Red is bit 0 and Balance is bit 1. We allow possible corrupt ranges.
    status = IntWinVadFetchVadFromMemory(dummy.Parent & (~3), &parent, FALSE);
    if (!INT_SUCCESS(status))
    {
        WARNING("[WARNING] IntWinVadFetchVadFromMemory failed for parent 0x%016llx: 0x%08x\n",
                dummy.Parent & (~3), status);
        return FALSE;
    }

    // We can also verify for now that the parent has either the left or right node the current VAD
    if (parent.Left != Vad->VadGva && parent.Right != Vad->VadGva)
    {
        WARNING("[WARNING] The current VAD's parent doesn't have as a child 0x%016llx "
                "(left 0x%016llx, right: 0x%016llx)\n",
                Vad->VadGva, parent.Left, parent.Right);
        return FALSE;
    }

    if (Vad->NoChange != Vad->PrivateFixup || Vad->DeleteInProgress)
    {
        WARNING("[WARNING] NoChange is %d, PrivateFixup is %d, DeleteInProgress is %d, "
                "the VAD doesn't seem to be considered in the tree!\n",
                Vad->NoChange, Vad->PrivateFixup, Vad->DeleteInProgress);
        return FALSE;
    }


    return TRUE;
}


_Function_class_(PFUNC_PreDetourCallback)
INTSTATUS
IntWinVadPatchInsertPrivate(
    _In_ QWORD FunctionAddress,
    _Inout_ API_HOOK_HANDLER *Handler,
    _In_ void *Descriptor
    )
///
/// @brief      This is the #PFUNC_PreDetourCallback for the MiInsertPrivateVad guest API detour.
/// @ingroup    group_detours
///
/// It will be invoked before the detour is placed inside the guest and will patch the detour handler with the value
/// of #winKmFieldProcessSpare.
///
/// @param[in]      FunctionAddress Guest virtual address of the hooked function. Ignored.
/// @param[in, out] Handler         The hook handler structure. This will have the #API_HOOK_HANDLER.Code byte array
///                                 changed.
/// @param[in]      Descriptor      Pointer to a structure that describes the hook and the detour handler.
///
/// @returns    #INT_STATUS_SUCCESS is always returned.
///
{
    API_HOOK_HANDLER *pHandler = Handler;

    UNREFERENCED_PARAMETER(FunctionAddress);
    UNREFERENCED_PARAMETER(Descriptor);

    if (gGuest.Guest64)
    {
        if (gGuest.OSVersion == 9600)
        {
            *(DWORD *)(&pHandler->Code[9]) = WIN_KM_FIELD(Process, Spare);
            *(DWORD *)(&pHandler->Code[18]) = WIN_KM_FIELD(Process, Spare);
        }
        else
        {
            *(DWORD *)(&pHandler->Code[37]) = WIN_KM_FIELD(Process, Spare);
            *(DWORD *)(&pHandler->Code[45]) = WIN_KM_FIELD(Process, Spare);
        }
    }
    else
    {
        if (gGuest.OSVersion >= 7600 && gGuest.OSVersion <= 7602)
        {
            *(DWORD *)(&pHandler->Code[30]) = WIN_KM_FIELD(Process, Spare);
        }
        else if (gGuest.OSVersion == 9200)
        {
            *(DWORD *)(&pHandler->Code[7]) = WIN_KM_FIELD(Process, Spare);
        }
        else if (gGuest.OSVersion >= 9600)
        {
            *(DWORD *)(&pHandler->Code[13]) = WIN_KM_FIELD(Process, Spare);
        }
    }

    return INT_STATUS_SUCCESS;
}


_Function_class_(PFUNC_PreDetourCallback)
INTSTATUS
IntWinVadPatchInsertMap(
    _In_ QWORD FunctionAddress,
    _Inout_ API_HOOK_HANDLER *Handler,
    _In_ void *Descriptor
    )
///
/// @brief      This is the #PFUNC_PreDetourCallback for the MiGetWsAndInsertVad guest API detour.
/// @ingroup    group_detours
///
/// It will be invoked before the detour is placed inside the guest and will patch the detour handler with the value
/// of #winKmFieldProcessSpare.
///
/// @param[in]      FunctionAddress Guest virtual address of the hooked function. Ignored.
/// @param[in, out] Handler         The hook handler structure. This will have the #API_HOOK_HANDLER.Code byte array
///                                 changed.
/// @param[in]      Descriptor      Pointer to a structure that describes the hook and the detour handler.
///
/// @returns    #INT_STATUS_SUCCESS is always returned.
///
{
    API_HOOK_HANDLER *pHandler = Handler;

    UNREFERENCED_PARAMETER(FunctionAddress);
    UNREFERENCED_PARAMETER(Handler);
    UNREFERENCED_PARAMETER(Descriptor);

    if (gGuest.Guest64)
    {
        *(DWORD *)(&pHandler->Code[37]) = WIN_KM_FIELD(Process, Spare);
        *(DWORD *)(&pHandler->Code[45]) = WIN_KM_FIELD(Process, Spare);
    }
    else
    {
        if (gGuest.OSVersion >= 7600 && gGuest.OSVersion <= 7602)
        {
            *(DWORD *)(&pHandler->Code[30]) = WIN_KM_FIELD(Process, Spare);
        }
        else if (gGuest.OSVersion >= 9200)
        {
            *(DWORD *)(&pHandler->Code[33]) = WIN_KM_FIELD(Process, Spare);
        }
    }

    return INT_STATUS_SUCCESS;
}


_Function_class_(PFUNC_PreDetourCallback)
INTSTATUS
IntWinVadPatchVirtualProtect(
    _In_ QWORD FunctionAddress,
    _Inout_ API_HOOK_HANDLER *Handler,
    _In_ void *Descriptor
    )
///
/// @brief      This is the #PFUNC_PreDetourCallback for the MiProtectVirtualMemory guest API detour.
/// @ingroup    group_detours
///
/// It will be invoked before the detour is placed inside the guest and will patch the detour handler with the value
/// of #winKmFieldProcessSpare.
///
/// @param[in]      FunctionAddress Guest virtual address of the hooked function. Ignored.
/// @param[in, out] Handler         The hook handler structure. This will have the #API_HOOK_HANDLER.Code byte array
///                                 changed.
/// @param[in]      Descriptor      Pointer to a structure that describes the hook and the detour handler.
///
/// @returns    #INT_STATUS_SUCCESS is always returned.
///
{
    API_HOOK_HANDLER *pHandler = Handler;

    UNREFERENCED_PARAMETER(FunctionAddress);
    UNREFERENCED_PARAMETER(Descriptor);

    if (gGuest.Guest64)
    {
        if (gGuest.OSVersion >= 7600 && gGuest.OSVersion <= 9200)
        {
            *(DWORD *)(&pHandler->Code[8]) = WIN_KM_FIELD(Process, Spare);
            *(DWORD *)(&pHandler->Code[16]) = WIN_KM_FIELD(Process, Spare);
        }
        else if (gGuest.OSVersion >= 9600)
        {
            *(DWORD *)(&pHandler->Code[9]) = WIN_KM_FIELD(Process, Spare);
            *(DWORD *)(&pHandler->Code[17]) = WIN_KM_FIELD(Process, Spare);
        }
    }
    else
    {
        if (gGuest.OSVersion >= 7600 && gGuest.OSVersion <= 9200)
        {
            *(DWORD *)(&pHandler->Code[14]) = WIN_KM_FIELD(Process, Spare);
        }
        else if (gGuest.OSVersion >= 9600)
        {
            *(DWORD *)(&pHandler->Code[9]) = WIN_KM_FIELD(Process, Spare);
            *(DWORD *)(&pHandler->Code[17]) = WIN_KM_FIELD(Process, Spare);
        }
    }

    return INT_STATUS_SUCCESS;
}


_Function_class_(PFUNC_PreDetourCallback)
INTSTATUS
IntWinVadPatchDeleteVaRange(
    _In_ QWORD FunctionAddress,
    _Inout_ API_HOOK_HANDLER *Handler,
    _In_ void *Descriptor
    )
///
/// @brief      This is the #PFUNC_PreDetourCallback for the MiDeleteVirtualAddresses guest API detour.
/// @ingroup    group_detours
///
/// It will be invoked before the detour is placed inside the guest and will patch the detour handler with the value
/// of #winKmFieldProcessSpare.
///
/// @param[in]      FunctionAddress Guest virtual address of the hooked function. Ignored.
/// @param[in, out] Handler         The hook handler structure. This will have the #API_HOOK_HANDLER.Code byte array
///                                 changed.
/// @param[in]      Descriptor      Pointer to a structure that describes the hook and the detour handler.
///
/// @returns    #INT_STATUS_SUCCESS is always returned.
///
{
    API_HOOK_HANDLER *pHandler = Handler;

    UNREFERENCED_PARAMETER(FunctionAddress);
    UNREFERENCED_PARAMETER(Descriptor);

    if (gGuest.Guest64)
    {
        *(DWORD *)(&pHandler->Code[31]) = WIN_KM_FIELD(Process, Spare);
        *(DWORD *)(&pHandler->Code[39]) = WIN_KM_FIELD(Process, Spare);
    }
    else
    {
        if (gGuest.OSVersion >= 7600 && gGuest.OSVersion <= 7602)
        {
            *(DWORD *)(&pHandler->Code[24]) = WIN_KM_FIELD(Process, Spare);
        }
        else if (gGuest.OSVersion >= 9200 && gGuest.OSVersion <= 16299)
        {
            *(DWORD *)(&pHandler->Code[27]) = WIN_KM_FIELD(Process, Spare);
        }
    }

    return INT_STATUS_SUCCESS;
}


_Function_class_(PFUNC_PreDetourCallback)
INTSTATUS
IntWinVadPatchFinishVadDeletion(
    _In_ QWORD FunctionAddress,
    _Inout_ API_HOOK_HANDLER *Handler,
    _In_ void *Descriptor
    )
///
/// @brief      This is the #PFUNC_PreDetourCallback for the MiFinishVadDeletion guest API detour.
/// @ingroup    group_detours
///
/// It will be invoked before the detour is placed inside the guest and will patch the detour handler with the value
/// of #winKmFieldProcessSpare.
///
/// @param[in]      FunctionAddress Guest virtual address of the hooked function. Ignored.
/// @param[in, out] Handler         The hook handler structure. This will have the #API_HOOK_HANDLER.Code byte array
///                                 changed.
/// @param[in]      Descriptor      Pointer to a structure that describes the hook and the detour handler.
///
/// @returns    #INT_STATUS_SUCCESS is always returned.
///
{
    API_HOOK_HANDLER *pHandler = Handler;

    UNREFERENCED_PARAMETER(FunctionAddress);
    UNREFERENCED_PARAMETER(Descriptor);

    if (gGuest.Guest64)
    {
        *(DWORD *)(&pHandler->Code[37]) = WIN_KM_FIELD(Process, Spare);
        *(DWORD *)(&pHandler->Code[45]) = WIN_KM_FIELD(Process, Spare);
    }
    else
    {
        if (gGuest.OSVersion >= 17134)
        {
            *(DWORD *)(&pHandler->Code[27]) = WIN_KM_FIELD(Process, Spare);
        }
    }

    return INT_STATUS_SUCCESS;
}


_Function_class_(PFUNC_PreDetourCallback)
INTSTATUS
IntWinVadPatchInsert(
    _In_ QWORD FunctionAddress,
    _Inout_ API_HOOK_HANDLER *Handler,
    _In_ void *Descriptor
    )
///
/// @brief      This is the #PFUNC_PreDetourCallback for the MiInsertVad guest API detour.
/// @ingroup    group_detours
///
/// It will be invoked before the detour is placed inside the guest and will patch the detour handler with the value
/// of #winKmFieldProcessSpare.
///
/// @param[in]      FunctionAddress Guest virtual address of the hooked function. Ignored.
/// @param[in, out] Handler         The hook handler structure. This will have the #API_HOOK_HANDLER.Code byte array
///                                 changed.
/// @param[in]      Descriptor      Pointer to a structure that describes the hook and the detour handler.
///
/// @returns    #INT_STATUS_SUCCESS is always returned.
///
{
    API_HOOK_HANDLER *pHandler = Handler;

    UNREFERENCED_PARAMETER(FunctionAddress);
    UNREFERENCED_PARAMETER(Descriptor);

    if (gGuest.Guest64)
    {
        if (gGuest.OSVersion >= 10240)
        {
            *(DWORD *)(&pHandler->Code[8]) = WIN_KM_FIELD(Process, Spare);
            *(DWORD *)(&pHandler->Code[16]) = WIN_KM_FIELD(Process, Spare);
        }
    }
    else
    {
        if (gGuest.OSVersion >= 18363)
        {
            *(DWORD *)(&pHandler->Code[9]) = WIN_KM_FIELD(Process, Spare);
        }
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntWinVadProcImportMainModuleVad(
    _Inout_ WIN_PROCESS_OBJECT *Process
    )
///
/// @brief  Imports the VAD that describes the main module of a process.
///
/// @param[in, out] Process The process that owns the VAD.
///
/// @retval     #INT_STATUS_SUCCESS in case of success.
/// @retval     #INT_STATUS_INVALID_PARAMETER_1 if Process is NULL.
///
{
    INTSTATUS status;
    QWORD vadRoot;
    QWORD vadNode;

    vadNode = 0;
    vadRoot = 0;

    if (NULL == Process)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    status = IntKernVirtMemRead(Process->EprocessAddress + WIN_KM_FIELD(Process, VadRoot),
                                gGuest.WordSize,
                                &vadRoot,
                                NULL);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemRead failed: 0x%08x\n", status);
        return status;
    }

    vadNode = IntWinVadFindNodeInGuestSpace(vadRoot,
                                            Process->MainModuleAddress & PAGE_MASK,
                                            Process->MainModuleAddress & PAGE_MASK,
                                            0,
                                            0,
                                            FALSE);
    if (!vadNode)
    {
        // We cannot get a valid VAD - skipping.
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    // Note that we don't want to insert a vad in the tree here, we just want to get a vad object for
    // the main module vad. This will get destroyed at process uninit, therefore there is no need to
    // cleanup this vad during the RbTree uninit. Also, since the VAD might have been previously loaded
    // inside the process, we will consider it as "static scanned".
    status = IntWinVadCreateObject(Process, vadNode, (VAD **)&Process->MainModuleVad, TRUE);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntWinVadCreateObject failed: 0x%08x\n", status);
        return status;
    }

    return INT_STATUS_SUCCESS;
}

INTSTATUS
IntWinVadFetchByRange(
    _In_ QWORD VadRoot,
    _In_ QWORD StartPage,
    _In_ QWORD EndPage,
    _Out_ VAD *Vad
    )
///
/// @brief Fetches and returns a VAD object containing the range represented by [StartPage, EndPage].
///
/// Note: The VAD is just completed with the relevant information, there's no need to call #IntWinVadDestroyObject
/// on the returned VAD.
///
/// @param[in]  VadRoot     The vad root from where to start the search. It is read from the guest, as the VadRoot field
///                         in the EPROCESS structure.
/// @param[in]  StartPage   The page which represents the start of the range that must be contained in the returned VAD.
/// @param[in]  EndPage     The page which represents the end of the range that must be contained in the returned VAD.
/// @param[out] Vad         The returned VAD object.
///
/// @retval     #INT_STATUS_SUCCESS                 On success.
/// @retval     #INT_STATUS_INVALID_PARAMETER_1     If the given VadRoot is equal to 0.
/// @retval     #INT_STATUS_INVALID_PARAMETER_4     If the given VAD object is NULL.
/// @retval     #INT_STATUS_NOT_FOUND               If there is no such VAD in the tree represented by the given root
///                                                 such that it contains [StartPage, EndPage].
///

{
    QWORD vadNode = 0;

    if (0 == VadRoot)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (NULL == Vad)
    {
        return INT_STATUS_INVALID_PARAMETER_4;
    }

    for (DWORD tries = 0; tries < VAD_SEARCH_LIMIT; tries++)
    {
        vadNode = IntWinVadFindNodeInGuestSpace(VadRoot,
                                                StartPage & PAGE_MASK,
                                                EndPage & PAGE_MASK,
                                                0,
                                                0,
                                                FALSE);
        if (0 != vadNode)
        {
            TRACE("[WINVAD] VAD for range [0x%016llx, 0x%016llx] found at 0x%016llx. Tries: %u\n",
                  StartPage, EndPage, vadNode, tries);
            break;
        }
    }
    
    if (0 == vadNode)
    {
        ERROR("[ERROR] Vad [0x%016llx, 0x%016llx] not found starting from root 0x%016llx\n",
              StartPage,
              EndPage,
              VadRoot);

        return INT_STATUS_NOT_FOUND;
    }

    return IntWinVadFetchVadFromMemory(vadNode, Vad, TRUE);
}


#undef VAD_SHORT_FIELD_PTR
#undef VAD_LONG_FIELD_PTR

#undef VadShortByte
#undef VadShortWord
#undef VadShortDword
#undef VadShortQword
#undef VadShortPtrSize
#undef VadShortAnySize
