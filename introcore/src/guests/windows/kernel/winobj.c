/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
///
/// @file   winobj.c
///
/// @brief  This file contains the logic that parses the Windows Kernel object namespace
/// in order to find an object of interest.
///
/// Currently, it is needed only for discovering driver objects, so it is a bit specialized for that task.
///
/// The namespace is organized in directories, starting from the root directory ("\", kernel global:
/// ObpRootDirectoryObject).
/// Each directory contains other directories and/or objects.
///
/// Each object is preceded in memory by an object header. This is mandatory. Additionally, one or more optional
/// headers may be present.
///
/// An allocation looks like this:
///
/// @code
/// --------------------------------
/// |       Pool Header            |
/// ================================
/// |     Process Info Header      |   ^
/// --------------------------------   |
/// |      Quota Info Header       |   |
/// --------------------------------   |
/// |      Handle Info Header      |   | Optional Headers (always in this order)
/// --------------------------------   | (Presence is controlled by bits in the InfoMask field from the Object Header)
/// |       Name Info Header       |   |
/// --------------------------------   |
/// |     Creator Info Header      |   V
/// ================================
/// |        Object Header         |
/// ================================
/// |           Object             | <-- Overlaps Body field from the Object Header
/// --------------------------------
/// @endcode
///
/// The InfoMask field from the Object Header tells us which Optional Headers are present:
///
/// -----------------------------------------
/// | Value  | Type                         |
/// |--------|------------------------------|
/// |  0x01  | _OBJECT_HEADER_CREATOR_INFO  |
/// |  0x02  | _OBJECT_HEADER_NAME_INFO     |
/// |  0x04  | _OBJECT_HEADER_HANDLE_INFO   |
/// |  0x08  | _OBJECT_HEADER_QUOTA_INFO    |
/// |  0x10  | _OBJECT_HEADER_PROCESS_INFO  |
/// -----------------------------------------
///
/// Each Directory has an array of 37 entries; each entry is a linked list of _OBJECT_DIRECTORY_ENTRY structures
///
/// Let's look at an example from a Windows memory dump, to see how the namespace is organized.
/// First, we can look at the root of the namespace (not all entries are listed): (note that the name of the object
/// shouldn't actually be put in double quotes, but I want to avoid a GCC warning, and for that I have to make sure
/// no comment line ends with a back slash)
/// @code
///     0: kd> !object "\"
///     Object: ffff970b5d219ea0  Type: (ffff8702eaa86520) Directory
///         ObjectHeader: ffff970b5d219e70 (new version)
///         HandleCount: 0  PointerCount: 48
///         Directory Object: 00000000  Name: "\"
///
///         Hash Address          Type                      Name
///         ---- -------          ----                      ----
///          01  ffff8702ec9e3750 Mutant                    PendingRenameMutex
///         ...
///          23  ffff8702eb59e790 Device                    Ntfs
///              ffff970b5d7e7960 Directory                 FileSystem
///              ffff970b5d217c00 Directory                 KernelObjects
///         ...
///          36  ffff8702ee011270 Event                     SAM_SERVICE_STARTED
///              ffff970b5d7e7b20 Directory                 Driver
/// @endcode
/// We can see the two directories that interest us: FileSystem (hash 23), and Driver (hash 36). We can
/// also see that the root is located at address 0xffff970b5d219ea0 inside the kernel and that its type is Directory.
/// We can dump it:
/// @code
///     0: kd> dt nt!_OBJECT_DIRECTORY -v -b ffff970b5d219ea0
///     struct _OBJECT_DIRECTORY, 8 elements, 0x160 bytes
///        +0x000 HashBuckets      : (37 elements)
///         [00] (null)
///         [01] 0xffff970b`5d8cb060
///         ...
///         [23] 0xffff970b`5dcacd00
///         ...
///         [35] (null)
///         [36] 0xffff970b`652be730
///        +0x128 Lock             : struct _EX_PUSH_LOCK, 7 elements, 0x8 bytes
///        +0x130 DeviceMap        : (null)
///        +0x138 ShadowDirectory  : (null)
///        +0x140 SessionId        : 0xffffffff
///        +0x148 NamespaceEntry   : (null)
///        +0x150 SessionObject    : (null)
///        +0x158 Flags            : 0
/// @endcode
/// The HashBuckets fields contains the objects listed above with the "!object" command (not all entries
/// are shown, to keep the list short). We can further look at entries 23 and 36:
/// @code
///     0: kd> dt nt!_OBJECT_DIRECTORY_ENTRY 0xffff970b`5dcacd00
///        +0x000 ChainLink        : 0xffff970b`5d7e4720 _OBJECT_DIRECTORY_ENTRY
///        +0x008 Object           : 0xffff8702`eb59e790 Void
///        +0x010 HashValue        : 0xa70094
///     0: kd> !object 0xffff8702`eb59e790
///     Object: ffff8702eb59e790  Type: (ffff8702eaa7f940) Device
///         ObjectHeader: ffff8702eb59e760 (new version)
///         HandleCount: 0  PointerCount: 2
///         Directory Object: ffff970b5d219ea0  Name: Ntfs
///     0: kd> dt nt!_OBJECT_DIRECTORY_ENTRY 0xffff970b`5d7e4720
///        +0x000 ChainLink        : 0xffff970b`5d2167c0 _OBJECT_DIRECTORY_ENTRY
///        +0x008 Object           : 0xffff970b`5d7e7960 Void
///        +0x010 HashValue        : 0x200fa1a2
///     0: kd> !object 0xffff970b`5d7e7960
///     Object: ffff970b5d7e7960  Type: (ffff8702eaa86520) Directory
///         ObjectHeader: ffff970b5d7e7930 (new version)
///         HandleCount: 0  PointerCount: 34
///         Directory Object: ffff970b5d219ea0  Name: FileSystem
///
///         Hash Address          Type                      Name
///         ---- -------          ----                      ----
///          02  ffff8702ee2ae060 Driver                    mrxsmb10
///         ...
///              ffff8702edafd060 Driver                    wcifs
///              ffff970b5d7e8ba0 Directory                 Filters
///          ...
///          35  ffff8702eb5a3340 Device                    UdfsCdRomRecognizer
/// @endcode
/// Each pointer in the HashBuckets array points to a _OBJECT_DIRECTORY_ENTRY structure. The Object field
/// of this structure points to the actual object. Dumping the structure for index 23 we see that it is
/// a device object, which does not interest us, but the ChainLink field will point to another _OBJECT_DIRECTORY_ENTRY
/// structure. Dumping that we get our entry for the Driver entry, which is also an _OBJECT_DIRECTORY structure. It can
/// contain driver objects, device objects or other directories. FileSystem is similar. We can manually dump each
/// individual driver object using the same method and obtain _OBJECT_DIRECTORY_ENTRIES like this, which will point to
/// a _DRIVER_OBJECT:
/// @code
///     0: kd> dt nt!_OBJECT_DIRECTORY_ENTRY 0xffff970b`6600c9a0
///        +0x000 ChainLink        : 0xffff970b`65fec5b0 _OBJECT_DIRECTORY_ENTRY
///        +0x008 Object           : 0xffff8702`ee2ae060 Void
///        +0x010 HashValue        : 0x293829f
///     0: kd> !object 0xffff8702`ee2ae060
///     Object: ffff8702ee2ae060  Type: (ffff8702eaa779e0) Driver
///         ObjectHeader: ffff8702ee2ae030 (new version)
///         HandleCount: 0  PointerCount: 2
///         Directory Object: ffff970b5d7e7960  Name: mrxsmb10
/// @endcode
/// What we haven't seen so far is the name of the objects, which is not included inside the objects. We know that
/// before the object itself there is an _OBJECT_HEADER structure, which has its Body field (at offset 0x30 in our
/// case) overlapping the object, so we start by looking at the InfoMask field in that structure:
/// @code
///     0 : kd > dt nt !_OBJECT_HEADER InfoMask (0xffff970b5d7e7b20 - 0x30)
///                  + 0x01a InfoMask : 0x2 ''
/// @endcode
/// This means that only the _OBJECT_HEADER_NAME_INFO optional header is present:
/// @code
///     0: kd> dt nt!_OBJECT_HEADER_NAME_INFO (ffff970b5d7e7b20 - 0x50)
///        +0x000 Directory        : 0xffff970b`5d219ea0 _OBJECT_DIRECTORY
///        +0x008 Name             : _UNICODE_STRING "Driver"
///        +0x018 ReferenceCount   : 0n0
///        +0x01c Reserved         : 0
/// @endcode
/// As for the pool tag, we can now go one step further and look at the _POOL_HEADER:
/// @code
///     0: kd> dt nt!_POOL_HEADER PoolTag (ffff970b5d7e7b20 - 0x60)
///        +0x004 PoolTag : 0x65726944
///     0: kd> db ffff970b5d7e7b20 - 0x5c L4
///        ffff970b`5d7e7ac4  44 69 72 65       Dire
/// @endcode
///
/// #IntWinGuestFindDriversNamespace follows a similar strategy during the search, but it needs to
/// account for the structures being in paged memory, so it will use IntSwapMemRead to force page
/// faults for any pages that may not be present during the search.
///

#include "winobj.h"
#include "guests.h"
#include "swapmem.h"
#include "windrvobj.h"
#include "winpe.h"

/// @brief  Allocation tag for the _OBJECT_DIRECTORY Windows kernel structure.
///
/// Stands for 'Dire'
#define WIN_POOL_TAG_DIRECTORY 0x65726944 // Dire

/// @brief  Allocation tag for the _OBJECT_DIRECTORY Windows 7 kernel structure.
///
/// Almost the same as WIN_POOL_TAG_DIRECTORY
#define WIN_POOL_TAG_DIRECTORY_7 0xe5726944

/// @brief  Allocation tag for the _OBJECT_TYPE Windows kernel structure.
///
/// Stands for 'ObjT'
#define WIN_POOL_TAG_OBJECT 0x546a624f

/// @brief  Allocation tag for the _OBJECT_TYPE Windows 7 kernel structure.
///
/// Almost the same as WIN_POOL_TAG_OBJECT
#define WIN_POOL_TAG_OBJECT_7 0xd46a624f

///
/// @brief Info Mask flags from the Object Header.
///
/// If one of these bits is set, the corresponding header is present.
///
typedef enum
{
    IM_FLG_CREATOR_INFO = 0x01, ///< Set if  _OBJECT_HEADER_CREATOR_INFO is present.
    IM_FLG_NAME_INFO    = 0x02, ///< Set if _OBJECT_HEADER_NAME_INFO is present.
    IM_FLG_HANDLE_INFO  = 0x04, ///< Set if _OBJECT_HEADER_HANDLE_INFO is present.
    IM_FLG_QUOTA_INFO   = 0x08, ///< Set if _OBJECT_HEADER_QUOTA_INFO is present.
    IM_FLG_PROCESS_INFO = 0x10, ///< Set if _OBJECT_HEADER_PROCESS_INFO is present.
} IM_FLG;


// Optional Header sizes
#define HEADER_SIZE_CREATOR_INFO64     0x20     ///< 32-bit _OBJECT_HEADER_CREATOR_INFO size.
#define HEADER_SIZE_CREATOR_INFO32     0x10     ///< 64-bit _OBJECT_HEADER_CREATOR_INFO size.
#define HEADER_SIZE_CREATOR_INFO(is64) (is64) ? HEADER_SIZE_CREATOR_INFO64 : HEADER_SIZE_CREATOR_INFO32

#define HEADER_SIZE_NAME_INFO64     0x20    ///< 32-bit _OBJECT_HEADER_NAME_INFO size.
#define HEADER_SIZE_NAME_INFO32     0x10    ///< 64-bit _OBJECT_HEADER_NAME_INFO size.
#define HEADER_SIZE_NAME_INFO(is64) (is64) ? HEADER_SIZE_NAME_INFO64 : HEADER_SIZE_NAME_INFO32

#define HEADER_SIZE_HANDLE_INFO64     0x10  ///< 32-bit _OBJECT_HEADER_HANDLE_INFO size.
#define HEADER_SIZE_HANDLE_INFO32     0x08  ///< 64-bit _OBJECT_HEADER_HANDLE_INFO size.
#define HEADER_SIZE_HANDLE_INFO(is64) (is64) ? HEADER_SIZE_HANDLE_INFO64 : HEADER_SIZE_HANDLE_INFO32

#define HEADER_SIZE_QUOTA_INFO64     0x20   ///< 32-bit _OBJECT_HEADER_QUOTA_INFO size.
#define HEADER_SIZE_QUOTA_INFO32     0x10   ///< 64-bit _OBJECT_HEADER_QUOTA_INFO size.
#define HEADER_SIZE_QUOTA_INFO(is64) (is64) ? HEADER_SIZE_QUOTA_INFO64 : HEADER_SIZE_QUOTA_INFO32

#define HEADER_SIZE_PROC_INFO64     0x10    ///< 32-bit _OBJECT_HEADER_PROCESS_INFO size.
#define HEADER_SIZE_PROC_INFO32     0x08    ///< 64-bit _OBJECT_HEADER_PROCESS_INFO size.
#define HEADER_SIZE_PROC_INFO(is64) (is64) ? HEADER_SIZE_PROC_INFO64 : HEADER_SIZE_PROC_INFO32


/// The size of the headers before a Root Directory allocation on 64-bit Windows.
#define ROOT_DIR_POOL_HEADER_OFF64 0x60
/// The size of the headers before a Root Directory allocation on 32-bit Windows.
#define ROOT_DIR_POOL_HEADER_OFF32 0x30


// Known type index values
#define TYPE_IDX_TYPE 2 ///< The index of the type Type in the type arrays.


#define OBJECT_DIR_ENTRY_COUNT 37   ///< The maximum number of entries in an object directory.


///
/// @brief  A context structure used to pass information between the various callbacks that search for a Root Directory.
///
typedef struct _ROOT_SEARCH_CTX
{
    QWORD   RootGva;        ///< The guest linear address of the possible root directory.
    void   *SwapHandle;     ///< The swap handle used for this search. NULL if no page swap-in is needed.
    /// True if the callback for this context has not been invoked yet, False if it has been invoked.
    BOOLEAN Waiting;
} ROOT_SEARCH_CTX, *PROOT_SEARCH_CTX;

///
/// @brief  A context structure used to pass information between the various callbacks that search for an object.
///
typedef struct _WINOBJ_SWAPCTX
{
    LIST_ENTRY Link;        ///< Entry in the gSwapHandles list.

    void *SwapHandle;       ///< The swap handle used for this search. NULL if no page swap-in is needed.
    QWORD ObjectGva;        ///< The guest linear address at which this object is locates.
    DWORD Id;               ///< The ID of this object (used for debugging).
} WINOBJ_SWAPCTX, *PWINOBJ_SWAPCTX;

#define ROOT_HINT_PTR_COUNT 3   ///< The number of hint pointers around a root candidate.

///
/// @brief  Hint structure used to search for possible object namespace root directory entries.
///
typedef struct _ROOT_HINT
{
    QWORD FoundAt;                       ///< The address from which the candidate was extracted.
    QWORD Pointers[ROOT_HINT_PTR_COUNT]; ///< Pointers around the candidate.
} ROOT_HINT, *PROOT_HINT;

/// @brief  The possible addresses at which the root directory may be located.
///
/// At the start of the search, this list is populated with possible addresses
/// inside the guest kernel at which the root directory of the namespace is possible
/// to be located. Every address in this list is then checked against a series of invariants
/// in order to find the actual entry.
static ROOT_SEARCH_CTX gPossibleRootGvas[32] = {0};

/// @brief  The number of valid entries inside the gPossibleRootGvas array.
static DWORD gRootCount = 0;

/// @brief  The number of directory entries left to check
static DWORD gDirEntriesToCheck = OBJECT_DIR_ENTRY_COUNT;

/// @brief  The count of pending driver objects to be checked.
///
/// As long as this is above 0, there are still #IntWinObjHandleDriverDirectoryEntryInMemory
/// callbacks waiting to be invoked by the swap memory read mechanism.
static DWORD gPendingDrivers = 0;

/// @brief  The number of found driver objects.
static DWORD gFoundDrivers = 0;

/// @brief  Set to True when the search must be aborted.
///
/// This allows introcore to stop the search if an error forces it to stop.
static BOOLEAN gStop = FALSE;

/// @brief  List of all the swap handles used by the namespace parser.
///
/// The swap handled used by gPossibleRootGvas are not listed here.
static LIST_ENTRY gSwapHandles;


static void
IntWinObjCheckDrvDirSearchState(
    void
    )
///
/// @brief  Checks if the search is still going, or if it finished with success or with an error.
///
/// If a stop has not been requested, it looks at the number of directory entries left to check for
/// the root directory. If there are no more entries left to check, and if there are no other
/// callbacks waiting to be invoked then the search is over. If we reached that point without
/// finding both the "Driver" and the "FileSystem" namespace entries, then the search failed, and we set
/// an appropriate error state and stop Introcore. If both entries were found, there may still be
/// driver objects pending to be swapped in (gPendingDrivers > 0). If that's the case, we do nothing, and
/// wait some more. If there are no more pending driver objects we can finalize the search.
///
{
    if (!gStop)
    {
        if ((0 == gDirEntriesToCheck) && IsListEmpty(&gSwapHandles) &&
            (0 == gWinGuest->DriverDirectory || 0 == gWinGuest->FileSystemDirectory))
        {
            ERROR("[ERROR] Finished parsing the root directory, but not all drivers were found. "
                  "`Driver` @ 0x%016llx `FileSystem` @ 0x%016llx\n",
                  gWinGuest->DriverDirectory, gWinGuest->FileSystemDirectory);

            IntGuestSetIntroErrorState(intErrGuestStructureNotFound, NULL);

            gGuest.DisableOnReturn = TRUE;
            gStop = TRUE;
        }

        if (0 != gWinGuest->DriverDirectory && 0 != gWinGuest->FileSystemDirectory)
        {
            if (0 == gPendingDrivers)
            {
                LOG("[WINOBJ] Search over. `Driver` @ 0x%016llx `FileSystem` @ 0x%016llx. Pending drivers = 0\n",
                    gWinGuest->DriverDirectory, gWinGuest->FileSystemDirectory);
                gStop = TRUE;
                IntWinObjCleanup();
            }
            else
            {
                LOG("[WINOBJ] Search not over. `Driver` @ 0x%016llx `FileSystem` @ 0x%016llx. Pending drivers = %u\n",
                    gWinGuest->DriverDirectory, gWinGuest->FileSystemDirectory, gPendingDrivers);
            }
        }
    }
}


static BOOLEAN
IntWinObjIsRootSearchOver(
    void)
{
    for (DWORD i = 0; i < gRootCount; i++)
    {
        if (gPossibleRootGvas[i].Waiting)
        {
            return FALSE;
        }
    }

    return TRUE;
}


static void
IntWinObjCancelRootTransactions(
    void
    )
///
/// @brief  Cancels any pending swap memory reads left for the root directory.
///
{
    for (DWORD i = 0; i < gRootCount; i++)
    {
        if (NULL != gPossibleRootGvas[i].SwapHandle)
        {
            INTSTATUS status = IntSwapMemRemoveTransaction(gPossibleRootGvas[i].SwapHandle);
            if (!INT_SUCCESS(status))
            {
                WARNING("[WARNING] IntSwapMemRemoveTransaction failed for 0x%016llx (Handle %p): 0x%08x\n",
                        gPossibleRootGvas[i].RootGva, gPossibleRootGvas[i].SwapHandle, status);
            }

            gPossibleRootGvas[i].SwapHandle = NULL;
        }

        gPossibleRootGvas[i].Waiting = FALSE;
    }

    gRootCount = 0;
}


static INTSTATUS
IntWinObjGetObjectNameInfo(
    _In_ QWORD ObjectGva,
    _Out_ QWORD *BufferGva,
    _Out_opt_ WORD *Length,
    _Out_opt_ QWORD *ParentDirGva
    )
///
/// @brief  Returns the name information for kernel objects that have one.
///
/// This information is available for objects that have the _OBJECT_HEADER_NAME_INFO header
/// This function assumes that it can read the object header(s).
///
/// @param[in]  ObjectGva   The address at which the object is found inside the guest kernel.
/// @param[out] BufferGva   The address of the object name inside the guest kernel.
/// @param[out] Length      The length of the object name, in characters. May be NULL.
/// @param[out] ParentDirGva    The address of the object's parent directory inside the guest kernel. May be NULL.
///
/// @retval #INT_STATUS_SUCCESS in case of success.
/// @retval #INT_STATUS_NOT_FOUND if the object does not have the header present.
///
{
    INTSTATUS status;
    QWORD infoMaskGva;
    DWORD sizeToSubtract = 0;
    BYTE infoMask = 0;
    DWORD creatorInfoSize;

    // If the Name Info Header is present we have the following layout: Name Info, Creator Info (optional), Object
    // Header, Object;
    // We need to go back at least sizeof(OBJECT_HEADER_NAME_INFO) + sizeof(OBJECT_HEADER),
    // but the Body field overlaps the object
    if (gGuest.Guest64)
    {
        sizeToSubtract += OFFSET_OF(OBJECT_HEADER64, Body) + HEADER_SIZE_NAME_INFO64;
        infoMaskGva = ObjectGva - OFFSET_OF(OBJECT_HEADER64, Body) + OFFSET_OF(OBJECT_HEADER64, InfoMask);
        creatorInfoSize = HEADER_SIZE_CREATOR_INFO64;
    }
    else
    {
        sizeToSubtract += OFFSET_OF(OBJECT_HEADER32, Body) + HEADER_SIZE_NAME_INFO32;
        infoMaskGva = ObjectGva - OFFSET_OF(OBJECT_HEADER32, Body) + OFFSET_OF(OBJECT_HEADER32, InfoMask);
        creatorInfoSize = HEADER_SIZE_CREATOR_INFO32;
    }

    status = IntKernVirtMemRead(infoMaskGva, sizeof(infoMask), &infoMask, NULL);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemRead failed for 0x%016llx: 0x%08x\n", infoMaskGva, status);
        return status;
    }

    if (0 == (IM_FLG_NAME_INFO & infoMask))
    {
        return INT_STATUS_NOT_FOUND;
    }

    // Add the creator info, if it exists
    if (0 != (IM_FLG_CREATOR_INFO & infoMask))
    {
        sizeToSubtract += creatorInfoSize;
    }

    if (gGuest.Guest64)
    {
        OBJECT_NAME64 objNameInfo = {0};

        status = IntKernVirtMemRead(ObjectGva - sizeToSubtract, sizeof(objNameInfo), &objNameInfo, NULL);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntKernVirtMemRead failed: 0x%08x\n", status);
            return status;
        }

        *BufferGva = objNameInfo.Name.Buffer;
        if (NULL != Length)
        {
            *Length = objNameInfo.Name.Length;
        }

        if (NULL != ParentDirGva)
        {
            *ParentDirGva = objNameInfo.Directory;
        }
    }
    else
    {
        OBJECT_NAME32 objNameInfo = {0};

        status = IntKernVirtMemRead(ObjectGva - sizeToSubtract, sizeof(objNameInfo), &objNameInfo, NULL);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntKernVirtMemRead failed: 0x%08x\n", status);
            return status;
        }

        *BufferGva = objNameInfo.Name.Buffer;
        if (NULL != Length)
        {
            *Length = objNameInfo.Name.Length;
        }

        if (NULL != ParentDirGva)
        {
            *ParentDirGva = objNameInfo.Directory;
        }
    }

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntWinObjHandleDriverDirectoryEntryInMemory(
    _In_ WINOBJ_SWAPCTX *Context,
    _In_ QWORD Cr3,
    _In_ QWORD Gva,
    _In_ QWORD Gpa,
    _In_ void *Data,
    _In_ DWORD DataSize,
    _In_ DWORD Flags
    )
///
/// @brief  This callback is invoked for namespace directory entries that may represent driver objects.
///
/// Since the Driver and FileSystem directories may contain both driver and device objects, this
/// function still needs to validate the entries before treating them as driver objects.
/// If an object is indeed a driver object, it will be saved to the Introcore list of driver objects and
/// the gFoundDrivers counter will be incremented; if not, it will be ignored.
/// Once this is done, the Context is removed from the gSwapHandles list and any resources held up by it
/// are freed.
/// This is a IntSwapMemRead callback for reads initiated by #IntWinObjParseDriverDirectory and
/// #IntWinObjHandleDriverDirectoryEntryInMemory itself. This recursion is needed as each directory
/// entry is in fact a linked list, and after parsing the first entry we need to move to the next and so on
/// and this function has the best context for reading the next entry. For cases in which the page is not
/// present and the read will be done asynchronously, this function also increments the gPendingDrivers
/// counter, to account for the fact that a swap-in is still pending.
///
/// @param[in]  Context     The search context, as passed to IntSwapMemRead.
/// @param[in]  Cr3         Ignored.
/// @param[in]  Gva         Ignored. This information is already present in Context.
/// @param[in]  Gpa         Ignored
/// @param[in]  Data        The data taken from the guest. This will be a _OBJECT_DIRECTORY_ENTRY kernel structure.
///                         This pointer is only valid until this function returns.
/// @param[in]  DataSize    Ignored. This information is already present in Context.
/// @param[in]  Flags       A combination of flags describing the way in which the data was read. This function
///                         checks only for the #SWAPMEM_FLAG_ASYNC_CALL flag. If it is present, it means that it
///                         was invoked asynchronously, in which case it may be the last callback in the chain of
///                         callbacks used in the search, so it must also finalize the search. This check is done even
///                         if this function sets up another swap memory read, as that one may be done for a page that
///                         is already present, in which case it will be invoked synchronously.
///
{
    QWORD next = 0;
    QWORD drvObjGva = 0;
    DWORD sizeToRead;
    INTSTATUS status;
    PWINOBJ_SWAPCTX pSwapCtx = Context;

    UNREFERENCED_PARAMETER(Cr3);
    UNREFERENCED_PARAMETER(Gva);
    UNREFERENCED_PARAMETER(Gpa);
    UNREFERENCED_PARAMETER(DataSize);

    // Remove this swap handle from the list
    RemoveEntryList(&pSwapCtx->Link);
    HpFreeAndNullWithTag(&pSwapCtx, IC_TAG_WINOBJ_SWAP);

    if (gGuest.Guest64)
    {
        next = ((OBJECT_DIRECTORY_ENTRY64 *)Data)->Chain;
        drvObjGva = ((OBJECT_DIRECTORY_ENTRY64 *)Data)->Object;
        sizeToRead = sizeof(OBJECT_DIRECTORY_ENTRY64);
    }
    else
    {
        next = ((OBJECT_DIRECTORY_ENTRY32 *)Data)->Chain;
        drvObjGva = ((OBJECT_DIRECTORY_ENTRY32 *)Data)->Object;
        sizeToRead = sizeof(OBJECT_DIRECTORY_ENTRY32);
    }

    if (IntWinDrvObjIsValidDriverObject(drvObjGva))
    {
        PWIN_DRIVER_OBJECT pDrvObj = NULL;

        status = IntWinDrvObjCreateFromAddress(drvObjGva, TRUE, &pDrvObj);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntWinDrvObjCreateDriverObject failed for 0x%016llx: 0x%08x\n", drvObjGva, status);
        }
        else
        {
            gFoundDrivers++;
        }
    }

    // It should be 0 for the last entry in the linked list, but let's try to not inject a #PF on some random numbers
    if (IS_KERNEL_POINTER_WIN(gGuest.Guest64, next))
    {
        WINOBJ_SWAPCTX *pNextCtx;
        void *swapHandle = NULL;

        pNextCtx = HpAllocWithTag(sizeof(*pNextCtx), IC_TAG_WINOBJ_SWAP);
        if (NULL == pNextCtx)
        {
            return INT_STATUS_INSUFFICIENT_RESOURCES;
        }

        pNextCtx->Id = __LINE__;
        pNextCtx->ObjectGva = next;
        InsertTailList(&gSwapHandles, &pNextCtx->Link);

        status = IntSwapMemReadData(0,
                                    next,
                                    sizeToRead,
                                    SWAPMEM_OPT_BP_FAULT,
                                    pNextCtx,
                                    0,
                                    IntWinObjHandleDriverDirectoryEntryInMemory,
                                    NULL,
                                    &swapHandle);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntSwapMemReadData failoed: 0x%08x\n", status);
            RemoveEntryList(&pNextCtx->Link);
            HpFreeAndNullWithTag(&pNextCtx, IC_TAG_WINOBJ_SWAP);
        }
        else if (NULL != swapHandle)
        {
            gPendingDrivers++;
            pNextCtx->SwapHandle = swapHandle;
        }
    }

    // If this was an async call, check if it was the last and if we managed to find what we were searching for; if
    // the call is synchronous the caller will do this check
    if (0 != (SWAPMEM_FLAG_ASYNC_CALL & Flags))
    {
        gPendingDrivers--;
        IntWinObjCheckDrvDirSearchState();
    }

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntWinObjParseDriverDirectory(
    _In_ WINOBJ_SWAPCTX *Context,
    _In_ QWORD Cr3,
    _In_ QWORD Gva,
    _In_ QWORD Gpa,
    _In_ void *Data,
    _In_ DWORD DataSize,
    _In_ DWORD Flags
    )
///
/// @brief  This callback is invoked for namespace entries that may represent driver directories.
///
/// This callback will be invoked for every top level directory in the root namespace. The read is
/// initiated by #IntWinObjHandleObjectInMemory.
/// The first thing it does is to check if the directory it was invoked for is one that contains driver objects.
/// There are two such directories: "Driver" and "FileSystem". This check is done by name. If this
/// is not one of the directories we are looking for, it is ignored. Once the check is done,
/// Context is removed from the gSwapHandles list and any resources held by it are freed.
/// If this is one of the directories we are looking for, we begin to parse it. Since the name information
/// and the object itself are part of the same allocation, we can safely access the entire object in this
/// callback, so we can read the HashBuckets array of the _OBJECT_DIRECTORY structure and begin parsing
/// each entry one by one. The entries in the array may not be present in memory, so one IntSwapMemRead
/// call is used for both of them, passing #IntWinObjHandleDriverDirectoryEntryInMemory as the callback.
/// For cases in which the page is not present and the read will be done asynchronously, this function also
/// increments the gPendingDrivers counter, to account for the fact that a swap-in is still pending.
/// Note that not all entries are valid, some may be NULL.
///
/// @param[in]  Context     The search context, as passed to IntSwapMemRead.
/// @param[in]  Cr3         Ignored.
/// @param[in]  Gva         Ignored. This information is already present in Context.
/// @param[in]  Gpa         Ignored.
/// @param[in]  Data        The data taken from the guest. This will be a _OBJECT_DIRECTORY kernel structure.
///                         This pointer is only valid until this function returns.
/// @param[in]  DataSize    Ignored. This information is already present in Context.
/// @param[in]  Flags       A combination of flags describing the way in which the data was read. This function
///                         checks only for the #SWAPMEM_FLAG_ASYNC_CALL flag. If it is present, it means that it
///                         was invoked asynchronously, in which case it may be the last callback in the chain of
///                         callbacks used in the search, so it must also finalize the search. Even if this function
///                         sets up another IntSwapMemRead call, we can not let only that callback do this check, as it
///                         is indeed possible for this to be the last swap memory callback invoked if all the directory
///                         entries for which we set up a swap memory read are already present in memory, so they are
///                         invoked synchronously.
///
{
    PWINOBJ_SWAPCTX pCtx = Context;
    QWORD objectGva = pCtx->ObjectGva;
    INTSTATUS status = INT_STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(Cr3);
    UNREFERENCED_PARAMETER(Gva);
    UNREFERENCED_PARAMETER(Gpa);

    RemoveEntryList(&pCtx->Link);
    HpFreeAndNullWithTag(&pCtx, IC_TAG_WINOBJ_SWAP);

    // Note: this is a guest read string, so we're not sure that it's NULL terminated. Use wstrncasecmp_len instead
    // of wstrcasecmp.
    if (0 == wstrncasecmp_len(Data, u"Driver", DataSize / 2, CWSTRLEN(u"Driver")))
    {
        LOG("[NAMESPACE] Found `Driver` directory @ 0x%016llx\n", objectGva);
        gWinGuest->DriverDirectory = objectGva;
    }
    else if (0 == wstrncasecmp_len(Data, u"FileSystem", DataSize / 2, CWSTRLEN((u"FileSystem"))))
    {
        LOG("[NAMESPACE] Found `FileSystem` directory @ 0x%016llx\n", objectGva);
        gWinGuest->FileSystemDirectory = objectGva;
    }
    else
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    if (gGuest.Guest64)
    {
        QWORD entries[OBJECT_DIR_ENTRY_COUNT] = {0};

        status = IntKernVirtMemRead(objectGva, sizeof(entries), entries, NULL);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntKernVirtMemRead failed: 0x%08x\n", status);
            return status;
        }

        for (DWORD i = 0; i < OBJECT_DIR_ENTRY_COUNT; i++)
        {
            if (IS_KERNEL_POINTER_WIN(gGuest.Guest64, entries[i]))
            {
                WINOBJ_SWAPCTX *pNextCtx;
                void *swapHandle = NULL;

                pNextCtx = HpAllocWithTag(sizeof(*pNextCtx), IC_TAG_WINOBJ_SWAP);
                if (NULL == pNextCtx)
                {
                    continue;
                }

                pNextCtx->Id = __LINE__;
                pNextCtx->ObjectGva = entries[i];
                InsertTailList(&gSwapHandles, &pNextCtx->Link);

                status = IntSwapMemReadData(0,
                                            entries[i],
                                            sizeof(OBJECT_DIRECTORY_ENTRY64),
                                            SWAPMEM_OPT_BP_FAULT,
                                            pNextCtx,
                                            0,
                                            IntWinObjHandleDriverDirectoryEntryInMemory,
                                            NULL,
                                            &swapHandle);
                if (!INT_SUCCESS(status))
                {
                    ERROR("[ERROR] IntSwapMemReadData failed: 0x%08x\n", status);
                    RemoveEntryList(&pNextCtx->Link);
                    HpFreeAndNullWithTag(&pNextCtx, IC_TAG_WINOBJ_SWAP);
                }
                else if (NULL != swapHandle)
                {
                    gPendingDrivers++;
                    pNextCtx->SwapHandle = swapHandle;
                }
            }
        }
    }
    else
    {
        DWORD entries[OBJECT_DIR_ENTRY_COUNT] = {0};

        status = IntKernVirtMemRead(objectGva, sizeof(entries), entries, NULL);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntKernVirtMemRead failed: 0x%08x\n", status);
            return status;
        }

        for (DWORD i = 0; i < OBJECT_DIR_ENTRY_COUNT; i++)
        {
            if (IS_KERNEL_POINTER_WIN(gGuest.Guest64, entries[i]))
            {
                WINOBJ_SWAPCTX *pNextCtx;
                void *swapHandle = NULL;

                pNextCtx = HpAllocWithTag(sizeof(*pNextCtx), IC_TAG_WINOBJ_SWAP);
                if (NULL == pNextCtx)
                {
                    continue;
                }

                pNextCtx->Id = __LINE__;
                pNextCtx->ObjectGva = entries[i];
                InsertTailList(&gSwapHandles, &pNextCtx->Link);

                status = IntSwapMemReadData(0,
                                            entries[i],
                                            sizeof(OBJECT_DIRECTORY_ENTRY32),
                                            SWAPMEM_OPT_BP_FAULT,
                                            pNextCtx,
                                            0,
                                            IntWinObjHandleDriverDirectoryEntryInMemory,
                                            NULL,
                                            &swapHandle);
                if (!INT_SUCCESS(status))
                {
                    ERROR("[ERROR] IntSwapMemReadData failed: 0x%08x\n", status);
                    RemoveEntryList(&pNextCtx->Link);
                    HpFreeAndNullWithTag(&pNextCtx, IC_TAG_WINOBJ_SWAP);
                }
                else if (NULL != swapHandle)
                {
                    gPendingDrivers++;
                    pNextCtx->SwapHandle = swapHandle;
                }
            }
        }
    }

    // If this was an async call, check if it was the last and if we managed to find what we were searching for; if
    // the call is synchronous the caller will do this check
    if (0 != (SWAPMEM_FLAG_ASYNC_CALL & Flags))
    {
        IntWinObjCheckDrvDirSearchState();
    }

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntWinObjHandleObjectInMemory(
    _In_ WINOBJ_SWAPCTX *Context,
    _In_ QWORD Cr3,
    _In_ QWORD Gva,
    _In_ QWORD Gpa,
    _In_ void *Data,
    _In_ DWORD DataSize,
    _In_ DWORD Flags
    )
///
/// @brief  This callback is invoked for each object in an object directory entries list.
///
/// This callback will be invoked for every object inside an object directory list of _OBJECT_DIRECTORY_ENTRY
/// structures. The read is initiated by #IntWinObjHandleDirectoryEntryInMemory.
/// It simply obtains the name information for that object and sets up another IntSwapMemRead call
/// for the buffer that represents the object name, with #IntWinObjParseDriverDirectory as the callback.
/// It also removed Context from the gSwapHandles list and frees any resources held by it.
///
/// @param[in]  Context     The search context, as passed to IntSwapMemRead.
/// @param[in]  Cr3         Ignored.
/// @param[in]  Gva         Ignored. This information is already present in Context.
/// @param[in]  Gpa         Ignored.
/// @param[in]  Data        Ignored. We only want to bring the page in memory.
/// @param[in]  DataSize    Ignored.
/// @param[in]  Flags       A combination of flags describing the way in which the data was read. This function
///                         checks only for the #SWAPMEM_FLAG_ASYNC_CALL flag. If it is present, it means that it
///                         was invoked asynchronously, in which case it may be the last callback in the chain of
///                         callbacks used in the search, so it must also finalize the search. Even if this function
///                         sets up another IntSwapMemRead call, we can not let only that callback do this check, as it
///                         is indeed possible for this to be the last swap memory callback invoked if the page we are
///                         trying to read is already present.
///
{
    QWORD objectGva;
    INTSTATUS status = INT_STATUS_SUCCESS;
    QWORD parentDirGva = 0;
    QWORD nameBufferGva = 0;
    WORD nameLength = 0;
    PWINOBJ_SWAPCTX pDrvDirCtx;
    PWINOBJ_SWAPCTX pCurrentCtx = Context;
    void *swapHandle;

    UNREFERENCED_PARAMETER(Cr3);
    UNREFERENCED_PARAMETER(Gva);
    UNREFERENCED_PARAMETER(Gpa);
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(DataSize);

    objectGva = pCurrentCtx->ObjectGva;

    RemoveEntryList(&pCurrentCtx->Link);
    HpFreeAndNullWithTag(&pCurrentCtx, IC_TAG_WINOBJ_SWAP);

    status = IntWinObjGetObjectNameInfo(objectGva, &nameBufferGva, &nameLength, &parentDirGva);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntWinObjGetObjectNameInfo failed for 0x%016llx: 0x%08x\n", objectGva, status);
        status = INT_STATUS_SUCCESS;
        goto cleanup_and_exit;
    }

    // Sanity check
    if ((!IS_KERNEL_POINTER_WIN(gGuest.Guest64, nameBufferGva)) || nameLength >= 32)
    {
        status = INT_STATUS_SUCCESS;
        goto cleanup_and_exit;
    }

    pDrvDirCtx = HpAllocWithTag(sizeof(*pDrvDirCtx), IC_TAG_WINOBJ_SWAP);
    if (NULL == pDrvDirCtx)
    {
        status = INT_STATUS_INSUFFICIENT_RESOURCES;
        goto cleanup_and_exit;
    }

    pDrvDirCtx->Id = __LINE__;
    pDrvDirCtx->ObjectGva = objectGva;
    InsertTailList(&gSwapHandles, &pDrvDirCtx->Link);

    status = IntSwapMemReadData(0,
                                nameBufferGva,
                                nameLength,
                                SWAPMEM_OPT_BP_FAULT,
                                pDrvDirCtx,
                                0,
                                IntWinObjParseDriverDirectory,
                                NULL,
                                &swapHandle);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntSwapMemReadData failed: 0x%08x\n", status);
        RemoveEntryList(&pDrvDirCtx->Link);
        HpFreeAndNullWithTag(&pDrvDirCtx, IC_TAG_WINOBJ_SWAP);
    }
    else if (NULL != swapHandle)
    {
        pDrvDirCtx->SwapHandle = swapHandle;
    }

cleanup_and_exit:
    // If this was an async call, check if it was the last and if we managed to find what we were searching for; if
    // the call is synchronous the caller will do this check
    if (0 != (SWAPMEM_FLAG_ASYNC_CALL & Flags))
    {
        IntWinObjCheckDrvDirSearchState();
    }

    return status;
}


static INTSTATUS
IntWinObjHandleDirectoryEntryInMemory(
    _In_ WINOBJ_SWAPCTX *Context,
    _In_ QWORD Cr3,
    _In_ QWORD Gva,
    _In_ QWORD Gpa,
    _In_ void *Data,
    _In_ DWORD DataSize,
    _In_ DWORD Flags
    )
///
/// @brief  This callback is invoked for each object contained in the root namespace.
///
/// This callback will be invoked for every object directory inside the root namespace, the read is
/// initiated by #IntWinObjHandleRootDirTagInMemory. It will set up a IntSwapMemRead call that will
/// allow us to read the address of the name buffer inside the _OBJECT_HEADER_NAME_INFO header of
/// this object, with #IntWinObjHandleObjectInMemory as the target.
/// It will also set up another IntSwapMemRead call with itself as the target, in order to parse the next
/// entry in this chain of entries.
/// Context will be removed from the gSwapHandles list and any resources held by it will be freed.
/// If this is the last entry in the current bucket (or if an error prevents us from reading the next entry),
/// the gDirEntriesToCheck will be decremented. In case of error we don't stop the search right away because
/// we may not actually need the next entry and it is easier to let the search finish on its own than stopping
/// it here. If the search ends without all the expected results, the error will be reported.
///
/// @param[in]  Context     The search context, as passed to IntSwapMemRead.
/// @param[in]  Cr3         Ignored.
/// @param[in]  Gva         Ignored. This information is already present in Context.
/// @param[in]  Gpa         Ignored
/// @param[in]  Data        The data read from the guest. This will be a _OBJECT_DIRECTORY_ENTRY kernel structure.
/// @param[in]  DataSize    Ignored.
/// @param[in]  Flags       Ignored.
///

{
    QWORD next;
    QWORD objectGva;
    DWORD sizeToRead;
    INTSTATUS status = INT_STATUS_SUCCESS;
    PWINOBJ_SWAPCTX pDrvDirCtx = NULL;
    PWINOBJ_SWAPCTX pCurrentCtx = Context;
    void *swapHandle;

    UNREFERENCED_PARAMETER(Cr3);
    UNREFERENCED_PARAMETER(Gva);
    UNREFERENCED_PARAMETER(Gpa);
    UNREFERENCED_PARAMETER(DataSize);
    UNREFERENCED_PARAMETER(Flags);

    RemoveEntryList(&pCurrentCtx->Link);
    HpFreeAndNullWithTag(&pCurrentCtx, IC_TAG_WINOBJ_SWAP);

    if (gGuest.Guest64)
    {
        POBJECT_DIRECTORY_ENTRY64 pEntry = (OBJECT_DIRECTORY_ENTRY64 *)Data;

        next = pEntry->Chain;
        objectGva = pEntry->Object;
        sizeToRead = sizeof(OBJECT_DIRECTORY_ENTRY64);
    }
    else
    {
        POBJECT_DIRECTORY_ENTRY32 pEntry = (OBJECT_DIRECTORY_ENTRY32 *)Data;

        next = pEntry->Chain;
        objectGva = pEntry->Object;
        sizeToRead = sizeof(OBJECT_DIRECTORY_ENTRY32);
    }

    // Don't bother if this is not a kernel pointer
    if (!IS_KERNEL_POINTER_WIN(gGuest.Guest64, objectGva))
    {
        goto next_entry;
    }

    pDrvDirCtx = HpAllocWithTag(sizeof(*pDrvDirCtx), IC_TAG_WINOBJ_SWAP);
    if (NULL == pDrvDirCtx)
    {
        status = INT_STATUS_INSUFFICIENT_RESOURCES;
        goto next_entry;
    }

    pDrvDirCtx->Id = __LINE__;
    pDrvDirCtx->ObjectGva = objectGva;
    InsertTailList(&gSwapHandles, &pDrvDirCtx->Link);

    status = IntSwapMemReadData(0,
                                objectGva,
                                1, // The size doesn't really matter, we just want to make the page present
                                SWAPMEM_OPT_BP_FAULT,
                                pDrvDirCtx,
                                0,
                                IntWinObjHandleObjectInMemory,
                                NULL,
                                &swapHandle);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntSwapMemReadData failed: 0x%08x\n", status);
        RemoveEntryList(&pDrvDirCtx->Link);
        HpFreeAndNullWithTag(&pDrvDirCtx, IC_TAG_WINOBJ_SWAP);
    }
    else if (NULL != swapHandle)
    {
        pDrvDirCtx->SwapHandle = swapHandle;
    }

next_entry:

    if (IS_KERNEL_POINTER_WIN(gGuest.Guest64, next))
    {
        WINOBJ_SWAPCTX *pDirEntryCtx;
        swapHandle = NULL;

        pDirEntryCtx = HpAllocWithTag(sizeof(*pDirEntryCtx), IC_TAG_WINOBJ_SWAP);
        if (NULL == pDirEntryCtx)
        {
            return INT_STATUS_INSUFFICIENT_RESOURCES;
        }

        pDirEntryCtx->Id = __LINE__;
        pDirEntryCtx->ObjectGva = next;
        InsertTailList(&gSwapHandles, &pDirEntryCtx->Link);

        status = IntSwapMemReadData(0,
                                    next,
                                    sizeToRead,
                                    SWAPMEM_OPT_BP_FAULT,
                                    pDirEntryCtx,
                                    0,
                                    IntWinObjHandleDirectoryEntryInMemory,
                                    NULL,
                                    &swapHandle);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntSwapMemReadData failed: 0x%08x\n", status);
            RemoveEntryList(&pDirEntryCtx->Link);
            HpFreeAndNullWithTag(&pDirEntryCtx, IC_TAG_WINOBJ_SWAP);

            // We failed to inject the #PF, there is nothing else we can do other than consider this bucket "done"
            gDirEntriesToCheck--;
            IntWinObjCheckDrvDirSearchState();
        }
        else if (NULL != swapHandle)
        {
            pDirEntryCtx->SwapHandle = swapHandle;
        }
    }
    else
    {
        // This is the last entry in this bucket, mark it as done
        gDirEntriesToCheck--;
        IntWinObjCheckDrvDirSearchState();
    }

    return status;
}


static INTSTATUS
IntWinObjHandleRootDirTagInMemory(
    _In_ ROOT_SEARCH_CTX *Context,
    _In_ QWORD Cr3,
    _In_ QWORD Gva,
    _In_ QWORD Gpa,
    _In_ void *Data,
    _In_ DWORD DataSize,
    _In_ DWORD Flags
    )
///
/// @brief  This callback is invoked for every candidate root directory namespace object.
///
/// This is a IntSwapMemRead callback for a read initiated by IntWinGuestFindDriversNamespace. It checks
/// if the candidate is indeed the root of the object namespace. It if is, it cancels all the other
/// root directory checks that are pending and starts the next phase of the search, looking for specific
/// top-level directories.
/// If this is the last entry in the current bucket (or if an error prevents us from reading the next entry),
/// the gDirEntriesToCheck will be decremented. In case of error we don't stop the search right away because
/// we may not actually need the next entry and it is easier to let the search finish on its own than stopping
/// it here. If the search ends without all the expected results, the error will be reported.
///
/// @param[in]  Context     The search context, as passed to IntSwapMemRead.
/// @param[in]  Cr3         Ignored.
/// @param[in]  Gva         The guest virtual address at which the Data was read from.
/// @param[in]  Gpa         Ignored.
/// @param[in]  Data        The data read from the guest. This will be a DWORD with the allocation tag. This pointer
///                         is valid until this function returns.
/// @param[in]  DataSize    Ignored.
/// @param[in]  Flags       Ignored.
///
{
    DWORD tag = *(DWORD *)Data;
    PROOT_SEARCH_CTX pCtx = Context;
    QWORD objGva = pCtx->RootGva;
    INTSTATUS status;
    QWORD parentDirGva = 0;
    QWORD nameBufferGva = 0;
    WORD nameLength = 0;

    UNREFERENCED_PARAMETER(Cr3);
    UNREFERENCED_PARAMETER(Gpa);
    UNREFERENCED_PARAMETER(DataSize);
    UNREFERENCED_PARAMETER(Flags);

    pCtx->SwapHandle = NULL;
    pCtx->Waiting = FALSE;

    if ((gGuest.OSVersion < 9200 && WIN_POOL_TAG_DIRECTORY_7 != tag) ||
        (gGuest.OSVersion >= 9200 && WIN_POOL_TAG_DIRECTORY != tag))
    {
        TRACE("[NAMESPACE] Skipping tag 0x%08x @ 0x%016llx for object 0x%016llx!\n",
              tag, Gva, objGva);
        status = INT_STATUS_NOT_NEEDED_HINT;
        goto _check_state_and_exit;
    }

    LOG("[NAMESPACE] Found tag 0x%08x @ 0x%016llx for object 0x%016llx!\n", tag, Gva, objGva);

    // We know this page is in memory because we get here only if it already was in memory, or we injected a #PF
    // to bring it in memory
    status = IntWinObjGetObjectNameInfo(objGva, &nameBufferGva, &nameLength, &parentDirGva);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntWinObjGetObjectNameInfo failed for 0x%016llx: 0x%08x\n", objGva, status);
        goto _check_state_and_exit;
    }

    if (0 != parentDirGva)
    {
        TRACE("[NAMESPACE] Skipping object 0x%016llx because it's parent directory is not NULL\n", objGva);
        status = INT_STATUS_NOT_NEEDED_HINT;
        goto _check_state_and_exit;
    }

    if (2 != nameLength || !IS_KERNEL_POINTER_WIN(gGuest.Guest64, nameBufferGva))
    {
        status = INT_STATUS_NOT_NEEDED_HINT;
        goto _check_state_and_exit;
    }

    LOG("[NAMESPACE] Found Root Directory (`\\`) @ 0x%016llx!\n", objGva);
    gWinGuest->ObpRootDirectoryObject = objGva;

    // Root found, cancel all other transactions
    IntWinObjCancelRootTransactions();

    if (gGuest.Guest64)
    {
        QWORD entries[OBJECT_DIR_ENTRY_COUNT] = {0};

        status = IntKernVirtMemRead(objGva, sizeof(entries), entries, NULL);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntKernVirtMemRead failed: 0x%08x\n", status);
            goto _check_state_and_exit;
        }

        for (DWORD i = 0; i < OBJECT_DIR_ENTRY_COUNT; i++)
        {
            if (IS_KERNEL_POINTER_WIN(gGuest.Guest64, entries[i]))
            {
                WINOBJ_SWAPCTX *pDirEntryCtx;
                void *swapHandle = NULL;

                pDirEntryCtx = HpAllocWithTag(sizeof(*pDirEntryCtx), IC_TAG_WINOBJ_SWAP);
                if (NULL == pDirEntryCtx)
                {
                    continue;
                }

                pDirEntryCtx->Id = __LINE__;
                pDirEntryCtx->ObjectGva = entries[i];
                InsertTailList(&gSwapHandles, &pDirEntryCtx->Link);

                status = IntSwapMemReadData(0,
                                            entries[i],
                                            sizeof(OBJECT_DIRECTORY_ENTRY64),
                                            SWAPMEM_OPT_BP_FAULT,
                                            pDirEntryCtx,
                                            0,
                                            IntWinObjHandleDirectoryEntryInMemory,
                                            NULL,
                                            &swapHandle);
                if (!INT_SUCCESS(status))
                {
                    ERROR("[ERROR] IntSwapMemReadData failed: 0x%08x\n", status);
                    RemoveEntryList(&pDirEntryCtx->Link);
                    HpFreeAndNullWithTag(&pDirEntryCtx, IC_TAG_WINOBJ_SWAP);

                    gDirEntriesToCheck--;
                    IntWinObjCheckDrvDirSearchState();
                }
                else if (NULL != swapHandle)
                {
                    pDirEntryCtx->SwapHandle = swapHandle;
                }
            }
            else
            {
                // This entry is empty, so there's nothing to check here
                gDirEntriesToCheck--;
                IntWinObjCheckDrvDirSearchState();
            }
        }
    }
    else
    {
        DWORD entries[OBJECT_DIR_ENTRY_COUNT] = {0};

        status = IntKernVirtMemRead(objGva, sizeof(entries), entries, NULL);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntKernVirtMemRead failed: 0x%08x\n", status);
            goto _check_state_and_exit;
        }

        for (DWORD i = 0; i < OBJECT_DIR_ENTRY_COUNT; i++)
        {
            if (IS_KERNEL_POINTER_WIN(gGuest.Guest64, entries[i]))
            {
                WINOBJ_SWAPCTX *pDirEntryCtx;
                void *swapHandle = NULL;

                pDirEntryCtx = HpAllocWithTag(sizeof(*pDirEntryCtx), IC_TAG_WINOBJ_SWAP);
                if (NULL == pDirEntryCtx)
                {
                    status = INT_STATUS_INSUFFICIENT_RESOURCES;
                    continue;
                }

                pDirEntryCtx->Id = __LINE__;
                pDirEntryCtx->ObjectGva = entries[i];
                InsertTailList(&gSwapHandles, &pDirEntryCtx->Link);

                status = IntSwapMemReadData(0,
                                            entries[i],
                                            sizeof(OBJECT_DIRECTORY_ENTRY32),
                                            SWAPMEM_OPT_BP_FAULT,
                                            pDirEntryCtx,
                                            0,
                                            IntWinObjHandleDirectoryEntryInMemory,
                                            NULL,
                                            &swapHandle);
                if (!INT_SUCCESS(status))
                {
                    ERROR("[ERROR] IntSwapMemReadData failed: 0x%08x\n", status);
                    RemoveEntryList(&pDirEntryCtx->Link);
                    HpFreeAndNullWithTag(&pDirEntryCtx, IC_TAG_WINOBJ_SWAP);

                    gDirEntriesToCheck--;
                    IntWinObjCheckDrvDirSearchState();
                }
                else if (NULL != swapHandle)
                {
                    pDirEntryCtx->SwapHandle = swapHandle;
                }
            }
            else
            {
                // This entry is empty, so there's nothing to check here
                gDirEntriesToCheck--;
                IntWinObjCheckDrvDirSearchState();
            }
        }
    }

_check_state_and_exit:
    if (IntWinObjIsRootSearchOver() && 0 == gWinGuest->ObpRootDirectoryObject)
    {
        ERROR("[ERROR] Could not find ObpRootDirectoryObject!\n");

        IntGuestSetIntroErrorState(intErrGuestStructureNotFound, NULL);
        gGuest.DisableOnReturn = TRUE;
    }
    else
    {
        IntWinObjCheckDrvDirSearchState();
    }

    return status;
}


INTSTATUS
IntWinObjFindRootDirectory(
    _In_ PROOT_HINT Hint,
    _Out_ QWORD *PossibleRoot
    )
///
/// @brief  Returns a possible object namespace root directory.
///
/// This is based on some heuristic checks, the address returned by this function
/// needs extended validation, but that involves memory that may be paged out, so
/// it is not done by this function. Instead, the caller needs to do those checks
/// on the possible values obtained.
///
/// @param[in]  Hint            Search area from which to extract a possible root pointer.
/// @param[out] PossibleRoot    The address of a possible root pointer.
///
/// @retval     #INT_SUCCESS in case of success.
/// @retval     #INT_STATUS_NOT_NEEDED_HINT if a root pointer was already found or if the
///             supplied hint those not point to a valid object.
/// @retval     #INT_STATUS_INVALID_PARAMETER_1 if no hint is provided.
/// @retval     #INT_STATUS_INVALID_PARAMETER_2 if no valid output buffer is provided.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;
    WORD foundTypes = 0;
    const WORD expectedTypes = 1;
    QWORD root = 0;
    DWORD delta;

    if (NULL == Hint)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (NULL == PossibleRoot)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    if (0 != gWinGuest->ObpRootDirectoryObject)
    {
        *PossibleRoot = gWinGuest->ObpRootDirectoryObject;
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    delta = gGuest.Guest64 ? ROOT_DIR_POOL_HEADER_OFF64 : ROOT_DIR_POOL_HEADER_OFF32;

    // ObpRootDirectoryObject is before, after or between two type objects from non-paged pool.
    // The actual layout is not the same on every OS version.

    for (DWORD i = 0; i < ROOT_HINT_PTR_COUNT; i++)
    {
        // We allow NULL pointers around the root
        if (0 == Hint->Pointers[i])
        {
            continue;
        }

        status = IntWinObjIsTypeObject(Hint->Pointers[i]);
        if (!INT_SUCCESS(status))
        {
            if ((0 == root) &&
                // the root and it's headers must be in the same page
                ((Hint->Pointers[i] & PAGE_MASK) == ((Hint->Pointers[i] - delta) & PAGE_MASK)))
            {
                root = Hint->Pointers[i];
            }
            else
            {
                *PossibleRoot = 0;
                return INT_STATUS_NOT_NEEDED_HINT;
            }
        }
        else
        {
            foundTypes++;
        }
    }

    if ((foundTypes < expectedTypes) || !IS_KERNEL_POINTER_WIN(gGuest.Guest64, root))
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    status = INT_STATUS_SUCCESS;

    for (size_t i = 0; i < ROOT_HINT_PTR_COUNT; i++)
    {
        if (root == Hint->Pointers[i])
        {
            LOG("[NAMESPACE] Found possible root @ 0x%016llx = 0x%016llx\n",
                Hint->FoundAt + i * gGuest.WordSize, Hint->Pointers[i]);
        }
        else
        {
            LOG("[NAMESPACE] Found type @ 0x%016llx = 0x%016llx\n",
                Hint->FoundAt + i * gGuest.WordSize, Hint->Pointers[i]);
        }
    }

    *PossibleRoot = root;

    return status;
}


INTSTATUS
IntWinObjIsTypeObject(
    _In_ QWORD Gva
    )
///
/// @brief  Checks if the supplied guest memory location holds a valid type object.
///
/// Gva must point to a valid _OBJECT_TYPE structure. In order to ensure this the following invariants are checked:
///     - the DefaultObject field must be a valid kernel pointer
///     - the Name.Buffer field must be a valid kernel pointer
///     - the TypeList.Blink field must be a valid kernel pointer
///     - the TypeList.Flink must be a valid kernel pointer
///     - the pool tag of the allocation must be WIN_POOL_TAG_OBJECT_7 for Windows 7 and
///     WIN_POOL_TAG_OBJECT for newer version
///     - the allocation must be from non paged pool (the PoolType field of the _POOL_HEADER
///     structure must have the #NonPagedPool bit set)
///     - the PoolType field of the _POOL_HEADER can not be #DontUseThisType
///     - the PoolType field of the _POOL_HEADER can not be #DontUseThisTypeSession
///
/// Since the allocation must be done from the non paged pool, we must be able to read the object
/// and its headers at any time, so if any of the IntKernVirtMemRead calls fails, this can not
/// be a valid type object.
///
/// @param[in]  Gva     Guest virtual address to check.
///
/// @retval     #INT_STATUS_SUCCESS if this is a valid kernel object.
/// @retval     #INT_STATUS_NOT_FOUND if this is not a valid kernel object.
///
{
    POOL_HEADER poolHeader = {0};
    INTSTATUS status;
    DWORD poolTag;
    DWORD poolType;

    if (!IS_KERNEL_POINTER_WIN(gGuest.Guest64, Gva))
    {
        return INT_STATUS_NOT_FOUND;
    }

    // It must be readable as it is in non-paged pool
    if (gGuest.Guest64)
    {
        OBJECT_TYPE64 typeObj = {0};

        status = IntKernVirtMemRead(Gva, sizeof(typeObj), &typeObj, NULL);
        if (!INT_SUCCESS(status))
        {
            return INT_STATUS_NOT_FOUND;
        }

        if (!IS_KERNEL_POINTER_WIN(gGuest.Guest64, typeObj.DefaultObject) ||
            !IS_KERNEL_POINTER_WIN(gGuest.Guest64, typeObj.Name.Buffer))
        {
            return INT_STATUS_NOT_FOUND;
        }

        if (typeObj.Name.Length > typeObj.Name.MaximumLength)
        {
            return INT_STATUS_NOT_FOUND;
        }

        if ((!IS_KERNEL_POINTER_WIN(gGuest.Guest64, typeObj.TypeList.Blink)) ||
            (!IS_KERNEL_POINTER_WIN(gGuest.Guest64, typeObj.TypeList.Flink)))
        {
            return INT_STATUS_NOT_FOUND;
        }
    }
    else
    {
        OBJECT_TYPE32 typeObj = {0};

        status = IntKernVirtMemRead(Gva, sizeof(typeObj), &typeObj, NULL);
        if (!INT_SUCCESS(status))
        {
            return INT_STATUS_NOT_FOUND;
        }

        if (!IS_KERNEL_POINTER_WIN(gGuest.Guest64, typeObj.DefaultObject) ||
            !IS_KERNEL_POINTER_WIN(gGuest.Guest64, typeObj.Name.Buffer))
        {
            return INT_STATUS_NOT_FOUND;
        }

        if (typeObj.Name.Length > typeObj.Name.MaximumLength)
        {
            return INT_STATUS_NOT_FOUND;
        }

        if ((!IS_KERNEL_POINTER_WIN(gGuest.Guest64, typeObj.TypeList.Blink)) ||
            (!IS_KERNEL_POINTER_WIN(gGuest.Guest64, typeObj.TypeList.Flink)))
        {
            return INT_STATUS_NOT_FOUND;
        }
    }

    status = IntWinObjGetPoolHeaderForObject(Gva, &poolHeader);
    if (!INT_SUCCESS(status))
    {
        TRACE("[INFO] IntWinObjGetPoolHeaderForObject failed for 0x%016llx: 0x%08x\n", Gva, status);
        return INT_STATUS_NOT_FOUND;
    }

    poolTag = gGuest.Guest64 ? poolHeader.Header64.PoolTag : poolHeader.Header32.PoolTag;

    if ((gGuest.OSVersion < 9200 && WIN_POOL_TAG_OBJECT_7 != poolTag) ||
        (gGuest.OSVersion >= 9200 && WIN_POOL_TAG_OBJECT != poolTag))
    {
        return INT_STATUS_NOT_FOUND;
    }

    poolType = gGuest.Guest64 ? poolHeader.Header64.PoolType : poolHeader.Header32.PoolType;

    // An _OBJECT_TYPE is always in the paged pool and it never uses a "DontUseThisType" pool allocation
    if (0 != (BIT(NonPagedPool) & poolType) &&
        DontUseThisType != poolType &&
        DontUseThisTypeSession != poolType)
    {
        return INT_STATUS_NOT_FOUND;
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntWinObjGetPoolHeaderForObject(
    _In_ QWORD ObjectGva,
    _Out_ POOL_HEADER *PoolHeader
    )
///
/// @brief  Reads the _POOL_HEADER structure for a given kernel object.
///
/// This function assumes that the object comes from the non paged pool, or it is readable
/// at the moment.
///
/// @param[in]  ObjectGva   The guest virtual address at which the object is located.
/// @param[out] PoolHeader  On success, will contain the contents of the _POOL_HEADER. The
///                         caller must allocate a large enough buffer for this information.
///
/// @retval     #INT_STATUS_SUCCESS in case of success.
/// @retval     #INT_STATUS_INVALID_PARAMETER_1 if ObjectGva is not a valid kernel address.
/// @retval     #INT_STATUS_INVALID_PARAMETER_2 if PoolHeader is NULL
/// @retval     #INT_STATUS_NOT_FOUND if the address at which the pool header should be located
///             is not a kernel address.
///
{
    INTSTATUS status;
    DWORD delta;

    if (!IS_KERNEL_POINTER_WIN(gGuest.Guest64, ObjectGva))
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (NULL == PoolHeader)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    if (gGuest.Guest64)
    {
        delta = HEADER_SIZE_CREATOR_INFO64 + HEADER_SIZE_NAME_INFO64 +
                WIN_POOL_HEADER_SIZE64 + OFFSET_OF(OBJECT_HEADER64, Body);
    }
    else
    {
        delta = HEADER_SIZE_CREATOR_INFO32 + HEADER_SIZE_NAME_INFO32 +
                WIN_POOL_HEADER_SIZE32 + OFFSET_OF(OBJECT_HEADER32, Body);
    }

    if (!IS_KERNEL_POINTER_WIN(gGuest.Guest64, ObjectGva - delta))
    {
        return INT_STATUS_NOT_FOUND;
    }

    status = IntKernVirtMemRead(ObjectGva - delta,
                                gGuest.Guest64 ? sizeof(POOL_HEADER64) : sizeof(POOL_HEADER32),
                                PoolHeader, NULL);
    if (!INT_SUCCESS(status))
    {
        TRACE("[INFO] IntKernVirtMemRead failed for 0x%016llx: 0x%08x\n", ObjectGva - delta, status);
    }

    return status;
}


static void
IntWinObjReinitGlobalState(
    void
    )
///
/// @brief  Resets the global search state
///
{
    memset(gPossibleRootGvas, 0, sizeof(gPossibleRootGvas));
    gRootCount = 0;
    gDirEntriesToCheck = OBJECT_DIR_ENTRY_COUNT;
    gStop = FALSE;
    InitializeListHead(&gSwapHandles);
}


static INTSTATUS
IntWinGuestFindDriversNamespaceNoBuffer(
    void
    )
///
/// @brief  Runs the driver object namespace search ignoring the gGuest.KernelBuffer and reading
/// the data directly from the guest memory.
///
/// In certain initialization scenarios the buffer may not contain all the information needed
/// for a successful search (for example, on a resume from hibernate, the buffer may contain old
/// information, because we can read certain parts of the kernel before Windows updates them). These
/// situations are rare, but if a search fails it can be retried in this way.
/// This function behaves in a similar way to IntWinGuestFindDriversNamespace.
///
/// @returns    #INT_STATUS_SUCCESS in case of success, or an error INTSTATUS value.
///
{
    //
    // This could be merged into IntWinGuestFindDriversNamespace and handle everything in one place, but that will make
    // everything harder to read and more error-prone
    //

    IMAGE_SECTION_HEADER sec = {0};
    INTSTATUS status;
    DWORD pageCount;

    IntWinObjReinitGlobalState();

    status = IntPeGetSectionHeadersByName(gGuest.KernelVa, NULL, ".data", 1, gGuest.Mm.SystemCr3, &sec, NULL);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntPeGetSectionHeadersByName failed for `.data`: 0x%08x\n", status);
        return status;
    }

    pageCount = ROUND_UP(sec.Misc.VirtualSize, PAGE_SIZE) / PAGE_SIZE;
    for (size_t i = 0; i < pageCount; i++)
    {
        QWORD targetGva = gGuest.KernelVa + sec.VirtualAddress + i * PAGE_SIZE;
        PBYTE page = NULL;
        DWORD ptrCount;

        status = IntVirtMemMap(targetGva, PAGE_SIZE, 0, 0, &page);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntVirtMemMap failed for 0x%016llx: 0x%08x\n", targetGva, status);
            continue;
        }

        if (i == pageCount - 1)
        {
            ptrCount = (sec.Misc.VirtualSize & PAGE_OFFSET) / gGuest.WordSize;
        }
        else
        {
            ptrCount = PAGE_SIZE / gGuest.WordSize;
        }

        for (DWORD j = 0; j < ptrCount; j++)
        {
            ROOT_HINT hint = {0};
            QWORD root = 0;

            hint.FoundAt = targetGva;

            // Make sure we don't try to read pointers from two pages when we mapped only one
            if (j + ROOT_HINT_PTR_COUNT < ptrCount)
            {
                for (DWORD k = 0; k < ROOT_HINT_PTR_COUNT; k++)
                {
                    hint.Pointers[k] = gGuest.Guest64 ? ((QWORD *)page)[j + k] : ((DWORD *)page)[j + k];
                }
            }
            // There's no point in doing this for the last page
            else if (i < ptrCount - 1)
            {
                if (gGuest.Guest64)
                {
                    status = IntKernVirtMemRead(hint.FoundAt, sizeof(hint.Pointers), hint.Pointers, NULL);
                }
                else
                {
                    DWORD temp[ROOT_HINT_PTR_COUNT] = {0};

                    status = IntKernVirtMemRead(hint.FoundAt, sizeof(temp), temp, NULL);
                    for (DWORD k = 0; k < ROOT_HINT_PTR_COUNT; k++)
                    {
                        hint.Pointers[k] = temp[k];
                    }
                }
                if (!INT_SUCCESS(status))
                {
                    ERROR("[ERROR] IntKernVirtMemRead failed for 0x%016llx: 0x%08x\n", hint.FoundAt, status);
                    goto _continue;
                }
            }

            status = IntWinObjFindRootDirectory(&hint, &root);
            if (!INT_SUCCESS(status) && INT_STATUS_NOT_FOUND != status)
            {
                ERROR("[ERROR] IntWinObjFindRootDirectory for 0x%016llx: 0x%08x\n", hint.FoundAt, status);
            }
            else if (INT_STATUS_SUCCESS == status)
            {
                if (gRootCount < ARRAYSIZE(gPossibleRootGvas))
                {
                    gPossibleRootGvas[gRootCount].RootGva = root;
                    gPossibleRootGvas[gRootCount].Waiting = TRUE;
                    gPossibleRootGvas[gRootCount].SwapHandle = NULL;
                    gRootCount++;
                }
                else
                {
                    break;
                }
            }

_continue:
            targetGva += gGuest.WordSize;
        }

        IntVirtMemUnmap(&page);
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntWinGuestFindDriversNamespace(
    void
    )
///
/// @brief  Runs the driver object namespace search.
///
/// This starts the search for kernel driver objects, but when this function returns
/// not all objects are found yet, as a big part of the search can (and will, in most
/// situations) be executed asynchronously.
/// The search starts by looking for the root of the object namespace. This is an
/// _OBJECT_DIRECTORY structure used by the kernel with the name "\".
///
/// There is not a clear and easy way of figuring out where this exists inside the kernel,
/// especially if Introcore is started long before the guest has booted. In order to obtain it,
/// we look for a series of pointers inside the kernel .data section, as the pointer to this
/// object will be saved in a global inside the kernel. This is based on some weak heuristics and
/// invariants check which will produce a series of candidate pointers. Then, more serious checks
/// are done on those candidates. We do this in order to reduce the search area, as most of the
/// checks need to read from paged memory, and are done by a series of IntSwapMemRead calls that
/// will page-in the needed memory pages, if they are not present. Doing this for all the pointers
/// in the .data section may impact performance and will introduce a large window in which no driver
/// objects are protected. If no candidates are found, the search is tried again, this time ignoring
/// the gGuest.KernelBuffer contents, using the #IntWinGuestFindDriversNamespaceNoBuffer function. If
/// the search for candidates fails again, an error of type #intErrGuestStructureNotFound is reported
/// and the search stops.
///
/// The search starts by reading the allocation tag for each of the candidates and checking it
/// against known-good values. This phase is done by #IntWinObjHandleRootDirTagInMemory. Once a valid
/// candidate is found, all the others are ignored and their subsequent #IntWinObjHandleRootDirTagInMemory
/// invocations are canceled. If no good allocation tag is found, an error of type intErrGuestStructureNotFound
/// is reported and the search stops.
///
/// Next, every entry in the root's HashBuckets fields is parsed. This is an array of #OBJECT_DIR_ENTRY_COUNT
/// pointers to _OBJECT_DIRECTORY_ENTRY structures. Some may be NULL and are ignored. These may reside in
/// paged pool, so they might be swapped out, so another round of swap-ins is scheduled using
/// #IntWinObjHandleDirectoryEntryInMemory as a handler.
///
/// There, we want to obtain the name of the object, but since the the name may also be swapped out,
/// we simply register a new swap-in request, with #IntWinObjHandleObjectInMemory as the handler.
/// Also, since every _OBJECT_DIRECTORY_ENTRY may point to another _OBJECT_DIRECTORY_ENTRY, another swap-in
/// is scheduled for the ChainLink member of the _OBJECT_DIRECTORY_ENTRY structure, having the same target,
/// #IntWinObjHandleDirectoryEntryInMemory.
///
/// Once the name information is obtained, another IntSwapMemRead is issued for the buffer itself,
/// using #IntWinObjParseDriverDirectory as the callback.
///
/// Once that callback gets invoked, the name is checked against the two directories that contain driver
/// objects: "Driver" and "FileSystem". If the name matches, we iterate the HashBuckets entries of this
/// directory and issue another IntSwapMemRead, this time for the driver object, setting the handler
/// to #IntWinObjHandleDriverDirectoryEntryInMemory.
///
/// Inside #IntWinObjHandleDriverDirectoryEntryInMemory, a _OBJECT_DIRECTORY_ENTRY structure is obtained.
/// The Object field of this structure can point to a _DRIVER_OBJECT or a _DEVICE_OBJECT structure. The
/// object is validated to be a valid driver object using IntWinDrvObjIsValidDriverObject, and if it is
/// it is added to introcore list of driver objects; otherwise, it is ignored. Similar to the other
/// functions that parse a _OBJECT_DIRECTORY_ENTRY. this function sets up another swap-in, for the next
/// entry in the object list, setting itself as the handler for that read.
///
/// At any point, any of the IntSwapMemRead callbacks may be the last callback that is invoked in a
/// synchronous manner, so all of the callbacks check for this. If it happens, they finalize the search
/// and check for errors. If errors were encountered, they are reported to the integrator and the introspection
/// engine will be unloaded.
///
/// Note, however, that there is no way of ensuring that all driver objects allocated before introcore started
/// are successfully detected. Doing this requires access to the list of all the currently used driver objects, and
/// this is exactly what we are trying to obtain here.
///
/// @retval     #INT_STATUS_SUCCESS if successful.
/// @retval     #INT_STATUS_NOT_FOUND if an error was encountered early in the search process.
///
/// @remarks    Even if this function exits with success, errors may be encountered while the search is conducted, in
///             which case those will be reported with the #GLUE_IFACE.NotifyIntrospectionErrorState mechanism and
///             introcore will be unloaded.
///
{
    IMAGE_SECTION_HEADER sec = {0};
    INTSTATUS status;
    DWORD ptrCount;
    BOOLEAN useBuffer = TRUE;

    if (gRootCount || gPendingDrivers || gFoundDrivers)
    {
        WARNING("[WARNING] A find for drivers namespace is already in progress... "
                "root = %u, pending = %u, found = %u\n",
                gRootCount,
                gPendingDrivers,
                gFoundDrivers);

        return INT_STATUS_NOT_NEEDED_HINT;
    }

    IntWinObjReinitGlobalState();

_retry:
    if (!useBuffer)
    {
        TRACE("[NAMESPACE] Kernel buffer not present, will fetch objects directly from memory!\n");

        status = IntWinGuestFindDriversNamespaceNoBuffer();
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntWinGuestFindDriversNamespaceNoBuffer failed: 0x%08x\n", status);
        }

        // failure or not, we need to go through this check
        goto _check_roots;
    }

    status = IntPeGetSectionHeadersByName(gGuest.KernelVa, gWinGuest->KernelBuffer, ".data", 1,
                                          gGuest.Mm.SystemCr3, &sec, NULL);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntPeGetSectionHeadersByName failed for `.data`: 0x%08x\n", status);
        goto _check_roots;
    }

    ptrCount = sec.Misc.VirtualSize / gGuest.WordSize - ROOT_HINT_PTR_COUNT;

    for (DWORD i = 0; i < ptrCount; i++)
    {
        DWORD bufferOffset = sec.VirtualAddress + i * gGuest.WordSize;
        void *target;
        ROOT_HINT hint;
        QWORD root = 0;

        if (bufferOffset > gWinGuest->KernelBufferSize)
        {
            ERROR("[CRITICAL ERROR] RVA 0x%08x is outside the kernel buffer (size = 0x%08x)\n",
                  bufferOffset, gWinGuest->KernelBufferSize);
            break;
        }

        target = gWinGuest->KernelBuffer + bufferOffset;
        hint.FoundAt = gGuest.KernelVa + bufferOffset;

        for (DWORD k = 0; k < ROOT_HINT_PTR_COUNT; k++)
        {
            hint.Pointers[k] = gGuest.Guest64 ? ((QWORD *)target)[k] : ((DWORD *)target)[k];
        }

        status = IntWinObjFindRootDirectory(&hint, &root);
        if (!INT_SUCCESS(status) && INT_STATUS_NOT_FOUND != status)
        {
            ERROR("[ERROR] IntWinObjFindRootDirectory for 0x%016llx: 0x%08x\n", hint.FoundAt, status);
        }
        else if (INT_STATUS_SUCCESS == status)
        {
            if (gRootCount < ARRAYSIZE(gPossibleRootGvas))
            {
                gPossibleRootGvas[gRootCount].RootGva = root;
                gPossibleRootGvas[gRootCount].Waiting = TRUE;
                gPossibleRootGvas[gRootCount].SwapHandle = NULL;
                gRootCount++;
            }
            else
            {
                break;
            }
        }
    }

    if (0 == gRootCount && useBuffer)
    {
        WARNING("[WINOBJ] Found 0 possible root pointers inside the kernel buffer, will retry without it!\n");
        useBuffer = FALSE;
        goto _retry;
    }

_check_roots:
    LOG("[NAMESPACE] Will check %d possible root pointers...\n", gRootCount);

    for (DWORD i = 0; i < gRootCount; i++)
    {
        DWORD poolHeaderOffset = gGuest.Guest64 ? ROOT_DIR_POOL_HEADER_OFF64 : ROOT_DIR_POOL_HEADER_OFF32;
        QWORD root = gPossibleRootGvas[i].RootGva;

        TRACE("[NAMESPACE] Trying 0x%016llx (%d) with 0x%016llx...\n",
              root, i, root - poolHeaderOffset + OFFSET_OF(POOL_HEADER32, PoolTag));

        // It is ok to use the field offset of PoolTag inside POOL_HEADER32 because it is the same offset as
        // POOL_HEADER64.
        status = IntSwapMemReadData(0,
                                    root - poolHeaderOffset + OFFSET_OF(POOL_HEADER32, PoolTag),
                                    sizeof(DWORD),
                                    SWAPMEM_OPT_BP_FAULT,
                                    &gPossibleRootGvas[i],
                                    0,
                                    IntWinObjHandleRootDirTagInMemory,
                                    NULL,
                                    &gPossibleRootGvas[i].SwapHandle);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntSwapMemReadData failed for 0x%016llx: 0x%08x\n", root - poolHeaderOffset, status);
            gPossibleRootGvas[i].Waiting = FALSE;
        }

        // If the root was already found in a sync manner, bail out now (all transactions were canceled
        // in IntWinObjHandleRootDirTagInMemory)
        if (0 != gWinGuest->ObpRootDirectoryObject)
        {
            return INT_STATUS_SUCCESS;
        }
    }

    status = INT_STATUS_SUCCESS;

    if (0 == gRootCount || (IntWinObjIsRootSearchOver() && 0 == gWinGuest->ObpRootDirectoryObject))
    {
        ERROR("[ERROR] Could not find ObpRootDirectoryObject!\n");

        IntGuestSetIntroErrorState(intErrGuestStructureNotFound, NULL);
        gGuest.DisableOnReturn = TRUE;

        status = INT_STATUS_NOT_FOUND;
    }
    else
    {
        IntWinObjCheckDrvDirSearchState();
    }

    return status;
}


void
IntWinObjCleanup(
    void
    )
///
/// @brief  Cleans up any resources allocated by the object search.
///
/// This will cancel any pending swap memory transactions and will free any memory allocated for the contexts
/// used by those reads.
///
{
    PLIST_ENTRY entry = gSwapHandles.Flink;
    DWORD remCount = 0;

    // First, the root transactions (if any)
    IntWinObjCancelRootTransactions();
    TRACE("[WINOBJ] Root transactions removed: %d\n", gRootCount);

    if (NULL == entry)
    {
        TRACE("[WINOBJ] No swap handles are present, nothing to clean\n");
        return;
    }

    // Now, everything else
    while (entry != &gSwapHandles)
    {
        PWINOBJ_SWAPCTX pCtx = CONTAINING_RECORD(entry, WINOBJ_SWAPCTX, Link);
        INTSTATUS status;

        entry = entry->Flink;

        TRACE("[WINOBJ] Removing swap handle %p for %llx ID = %u\n",
              pCtx->SwapHandle, pCtx->ObjectGva, pCtx->Id);

        RemoveEntryList(&pCtx->Link);

        status = IntSwapMemRemoveTransaction(pCtx->SwapHandle);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntSwapMemRemoveTransaction failed: 0x%08x\n", status);
        }

        HpFreeAndNullWithTag(&pCtx, IC_TAG_WINOBJ_SWAP);
        remCount++;
    }

    TRACE("[WINOBJ] Queued transactions removed: %d\n", remCount);
    CRITICAL("[WINOBJ] Cleanup done with %u pending drivers. Found = %u\n", gPendingDrivers, gFoundDrivers);
}
