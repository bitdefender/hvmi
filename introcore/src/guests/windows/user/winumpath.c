/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "winumpath.h"
#include "crc32.h"
#include "introcore.h"


///
/// @file winumpath.c
///
/// @brief  This module provides a caching facility for windows user-mode paths, as well as a way
///         of encapsulating the paths in #WINUM_PATH objects.
///
/// As many user-mode modules are common in Windows, many of them being located in the System32
/// folder, there is obviously no point in keeping the exactly same path of a module loaded
/// in two different processes twice. For this reason, this module will cache the paths extracted
/// from the guest, identifying them uniquely by the subsection guest virtual address (see
/// #IntWinUmPathFetchBySubsection for a more detailed explanation), and instead of duplicating
/// the objects, they will be referenced in other modules where the path objects are used by
/// subsequently calling #IntWinUmPathReference/#IntWinUmPathFetchAndReferenceBySubsection.
/// This modules also provides an encapsulation of the path objects, keeping the path, the
/// name, the hash, the reference count and the subsection gva, in order to be easily accessed
/// by a caller who uses the path objects provided.
/// Note: failure to dereference a path when it is not used anymore in guest will always
/// result in path mismatch. For example, if a path is not used anymore in the guest
/// then the subsection gva will most likely be re-used for another path. Due to failure
/// to dereference the path, the introcore engine will think that it's the same path as before
/// when fetching it from the cache provided by this module. Thus, there might be false
/// positives (e.g. mismatch ntdll for any other module) or loss of protection (e.g. mismatch
/// process path for unprotected process path), which should be avoided by always dereferencing
/// the path when it is not used anymore.
///


///
/// String placeholder for invalid paths.
///
static WCHAR gInvalidModulePath[8] = u"<error>";


///
/// Path object describing an invalid path.
///
static WINUM_PATH gInvalidUmPath =
{
    .Path = gInvalidModulePath,
    .Name = gInvalidModulePath,

    .PathSize = CWSTRLEN(gInvalidModulePath) * 2,
    .NameSize = CWSTRLEN(gInvalidModulePath) * 2,

    .NameHash = INITIAL_CRC_VALUE,

    .RefCount = 1,

    .SubsectionGva = 0,
};


static
_Function_class_(FUNC_RbTreeNodeFree) void
IntWinUmPathRbTreeNodeFree(
    _Inout_ RBNODE *Node
    )
///
/// @brief  Function called whenever a node from the red-black tree is freed.
///
/// @param[in, out] Node    The red-black tree which is currently freed.
{
    UNREFERENCED_PARAMETER(Node);
}


static
_Function_class_(FUNC_RbTreeNodeCompare) int
IntWinUmPathRbTreeNodeCompare(
    _In_ RBNODE *Left,
    _In_ RBNODE *Right
    )
///
/// @brief  Function used for comparison of two red-black tree nodes describing two
///         different paths.
///
/// The comparison is done based on the guest virtual address of the subsection
/// associated with each path object.
///
/// @param[in]  Left    The first node to be compared.
/// @param[in]  Right   The second node to be compared.
///
/// @retval -1  If the first node has a subsection which is less than the second node's
///             subsection.
///         1   If the second node has a subsection which is less than the first node's
///             subsection.
///         0   If the subsections are equal. Note that in this case the left and right
///             nodes should describe exactly the same path objects.
///
{
    WINUM_PATH *p1 = CONTAINING_RECORD(Left, WINUM_PATH, RbNode);
    WINUM_PATH *p2 = CONTAINING_RECORD(Right, WINUM_PATH, RbNode);

    if (p1->SubsectionGva < p2->SubsectionGva)
    {
        return -1;
    }
    else if (p1->SubsectionGva > p2->SubsectionGva)
    {
        return 1;
    }
    else
    {
        return 0;
    }
}


///
/// Global red-black tree containing all the cached paths.
///
static RBTREE gPaths = RB_TREE_INIT(gPaths, IntWinUmPathRbTreeNodeFree, IntWinUmPathRbTreeNodeCompare);


static WINUM_PATH *
IntWinUmPathFetchBySubsection(
    _In_ QWORD SubsectionGva
    )
///
/// @brief  Fetches a path object by the given unique identifier, which is the
///         subsection virtual address.
///
/// Two subsections, described inside the guest as nt!_SUBSECTION structure
/// will always have the same FILE_OBJECT pointer associated with them if the
/// subsections reside at the same address. Thus, the FILE_OBJECT associated
/// to them will contain the path string. Every VAD which describes a mapped
/// file will have a subsection, therefore, the subsection structure address
/// will always be an unique identifier for paths associated to VADs inside
/// the guest.
///
/// @param[in]  SubsectionGva   The guest virtual address of the subsection
///                             structure, which is considered an unique
///                             identifier for paths.
///
/// @returns    The #WINUM_PATH object associated with the given Subsection gva,
///             if it exists, otherwise NULL.
///
{
    RBNODE *result;
    WINUM_PATH target;
    INTSTATUS status;

    target.SubsectionGva = SubsectionGva;

    status = RbLookupNode(&gPaths, &target.RbNode, &result);
    if (!INT_SUCCESS(status))
    {
        return NULL;
    }

    return CONTAINING_RECORD(result, WINUM_PATH, RbNode);
}


__nonnull() static void
IntWinUmPathFree(
    _In_ WINUM_PATH *Path
    )
///
/// @brief  Releases resources associated to a #WINUM_PATH object.
///
/// @param[in]  Path    The #WINUM_PATH object which is desired to be freed.
///
{
    if (Path->Path)
    {
        HpFreeAndNullWithTag(&Path->Path, IC_TAG_UMPT);
    }

    HpFreeAndNullWithTag(&Path, IC_TAG_PTHP);
}


WINUM_PATH *
IntWinUmPathCreate(
    _In_ const WCHAR *Path,
    _In_ DWORD PathSize,
    _In_ QWORD SubsectionGva
    )
///
/// @brief  Creates a #WINUM_PATH object from the given parameters.
///
/// Provided the path string which was read from the guest, the total length of the path and the subsection guest
/// virtual address from which the path string was read, which will serve as a unique identifier for the given
/// path, this function will create a path object based on those.
/// Note that if any error occurs, #gInvalidUmPath will be returned by this function. This function may get called on
/// already cached paths, in which case a warning will be issued and the cached path will be fetched from the cache
/// and the reference count will be incremented.
///
/// @param[in]  Path            The path string which was read from the guest.
/// @param[in]  PathSize        The total number of bytes the path contains.
/// @param[in]  SubsectionGva   The guest virtual address of the subsection from which the path was fetched.
///
/// @returns    The created #WINUM_PATH object in case of success or the already cached path if the path exists in the
///             #gPaths red-black tree. #gInvalidUmPath in case of error.
///
{
    WINUM_PATH *pPath;
    INTSTATUS status;

    // Expecting at least one character and the NULL terminator. The path length cannot exceed a word in length.
    if ((PathSize < 2) || (PathSize > 0xFFFF))
    {
        ERROR("[ERROR] Path size (%d) is invalid for module\n", PathSize);
        return &gInvalidUmPath;
    }

    pPath = HpAllocWithTag(sizeof(*pPath), IC_TAG_PTHP);
    if (NULL == pPath)
    {
        return &gInvalidUmPath;
    }

    pPath->RefCount = 1;
    pPath->PathSize = PathSize;
    pPath->SubsectionGva = SubsectionGva;

    // Copy the module path. PathLength + 2 OK - PathLength is less than 0xFFFF and PathLength is DWORD.
    pPath->Path = HpAllocWithTag(PathSize + 2ull, IC_TAG_UMPT);
    if (NULL == pPath->Path)
    {
        HpFreeAndNullWithTag(&pPath, IC_TAG_PTHP);

        return &gInvalidUmPath;
    }
    else
    {
        DWORD i = 0, ni = 0;

        for (i = 0; i < pPath->PathSize / 2; i++)
        {
            pPath->Path[i] = ((Path[i] >= u'A') && (Path[i] <= u'Z')) ? (Path[i] | 0x20) : Path[i];

            if (pPath->Path[i] == u'\\')
            {
                ni = i + 1;
            }
        }

        pPath->Path[i] = 0;

        pPath->Name = pPath->Path + ni;
        pPath->NameSize = ((pPath->PathSize / 2) - ni) * 2;
        pPath->NameHash = Crc32Wstring(pPath->Name, INITIAL_CRC_VALUE);

        if (0 == ni)
        {
            WARNING("[WARNING] Path `%s` seems to be incomplete\n", utf16_for_log(pPath->Path));
        }

        status = RbInsertNode(&gPaths, &pPath->RbNode);
        if (!INT_SUCCESS(status))
        {
            IntWinUmPathFree(pPath);

            // This will happen in the following pretty stressful case:
            // 1. N processes load the same dll at ~ the same time
            // 2. The dll subsection is not cached
            // 3. The module path is swapped out from guest memory
            // Then, introcore will inject N page faults for each process to fetch the module path from memory, the
            // first page fault will call IntWinUmPathCreate (which will insert the first path in the red-black tree),
            // but the following page fault callbacks will also call IntWinUmPathCreate for each process,
            // resulting in the same subsection, thus the same key
            if (INT_STATUS_KEY_ALREADY_EXISTS == status)
            {
                WARNING("[WARNING] IntWinUmPathCreate called with duplicated subsection: %llx Path: %s!\n",
                        SubsectionGva, Path ? utf16_for_log(Path) : "");

                return IntWinUmPathFetchAndReferenceBySubsection(SubsectionGva);
            }

            ERROR("[ERROR] RbInsertNode failed: 0x%08x\n", status);

            return &gInvalidUmPath;
        }
    }

    return pPath;
}


WINUM_PATH *
IntWinUmPathReference(
    _In_ WINUM_PATH *Path
    )
///
/// @brief  Increases the reference count of the given #WINUM_PATH object.
///
/// Calling this function means that one uses a reference to a Path object
/// and desires that the path should not be freed until one calls the
/// #IntWinUmPathDereference function on the path.
///
/// @param[in]  Path    The #WINUM_PATH object for which the reference count
///                     will be incremented.
/// @returns    The path after the reference count was incremented.
///
{
    Path->RefCount++;

    return Path;
}


WINUM_PATH *
IntWinUmPathFetchAndReferenceBySubsection(
    _In_ QWORD SubsectionGva
    )
///
/// @brief  Fetches a #WINUM_PATH object by the unique identifier and increments the
///         reference counter on it.
///
/// @param[in]  SubsectionGva   The guest virtual address of the subsection where the
///                             path is found. Serves as a unique identifier.
///
/// @returns    The #WINUM_PATH object uniquely identified by the given SubsectionGva.
///             If no path exists having the given subsection, the return value will be
///             NULL.
///
{
    WINUM_PATH *pPath = IntWinUmPathFetchBySubsection(SubsectionGva);
    if (NULL != pPath)
    {
        pPath->RefCount++;
    }

    return pPath;
}


void
IntWinUmPathDereference(
    _Inout_ WINUM_PATH **Path
    )
///
/// @brief  Dereferences a #WINUM_PATH object, releasing the resources if the reference
///         count has reached 0.
///
/// When all the callers to #IntWinUmPathReference/#IntWinUmPathFetchAndReferenceBySubsection
/// or after a path creation has been made, decide that the path should no longer be used,
/// this function will get called and the reference count will reach 0. When reaching 0,
/// the resources (that means the Path string where the path is saved, as well as the
/// path object) will be released. This function will also set to NULL the object given
/// as parameter.
///
/// @param[in]  Path    A pointer to the #WINUM_PATH object which should be dereferenced
///                     or freed if the reference counter reaches 0.
///
{
    WINUM_PATH *pPath;

    if (NULL == Path)
    {
        return;
    }

    pPath = *Path;
    *Path = NULL;

    if (NULL == pPath || pPath == &gInvalidUmPath)
    {
        return;
    }

    if (--pPath->RefCount > 0)
    {
        return;
    }

    RbDeleteNode(&gPaths, &pPath->RbNode);

    IntWinUmPathFree(pPath);
}
