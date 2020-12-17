/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "lixfiles.h"
#include "guests.h"


///
/// @brief Describes an entry from dentry-cache.
///
typedef struct _DENTRY_PATH
{
    LIST_ENTRY  Link;           ///< ///< List entry element.

    char        *Path;          ///< The content of the path (string).
    DWORD       Length;         ///< The length of the path.

    QWORD       Gva;            ///< The guest virtual address of the 'struct dentry'.
} DENTRY_PATH, *PDENTRY_PATH;


///
/// @brief Describes a path that will be cached.
///
typedef struct _DENTRY_STRING
{
    char    *String;            ///< The path (string).
    DWORD   Length;             ///< The length of the path.
} DENTRY_STRING, *PDENTRY_STRING;


///
/// @brief An array that contains the paths that will be cached.
///
/// NOTE: Add path in descending order by length.
///
static DENTRY_STRING gLixDentryCacheStrings[] =
{
    {  .String = "/lib/x86_64-linux-gnu/",   .Length = CSTRLEN("/lib/x86_64-linux-gnu/")    },
    {  .String = "/usr/lib/",                .Length = CSTRLEN("/usr/lib/")                 },
    {  .String = "/usr/bin/",                .Length = CSTRLEN("/usr/bin/")                 },
    {  .String = "/usr/",                    .Length = CSTRLEN("/usr/")                     },
    {  .String = "/bin/",                    .Length = CSTRLEN("/bin/")                     },
    {  .String = "/sbin/",                   .Length = CSTRLEN("/sbin/")                    },
    {  .String = "/lib/",                   .Length = CSTRLEN("/lib/")                     },
};

///
/// @brief A list that contains the cached entries.
///
static LIST_HEAD gLixDentryCache = LIST_HEAD_INIT(gLixDentryCache);

static char gLixPath[PAGE_SIZE] = { 0 };


#define for_each_dentry(_var_name)      list_for_each(gLixDentryCache, DENTRY_PATH, _var_name)


static BOOLEAN
IntLixFileCachePathIsValid(
    _In_ char *Path
    )
///
/// @brief  Verify if the provided path starts with at least one entry from #gLixDentryCacheStrings.
///
/// @param[in]  Path    The path to be verified.
///
/// @retval     True if the provided Path starts with at least one entry from #gLixDentryCacheStrings, otherwise false.
///
///
{
    for (DWORD index = 0; index < ARRAYSIZE(gLixDentryCacheStrings); index++)
    {
        if (memcmp(gLixDentryCacheStrings[index].String, Path, gLixDentryCacheStrings[index].Length) == 0)
        {
            return TRUE;
        }
    }

    return FALSE;
}


void
IntLixFilesCacheUninit(
    void
    )
///
/// @brief  Removes and frees the entries of the dentry-cache.
///
{
    for_each_dentry(pDentry)
    {
        RemoveEntryList(&pDentry->Link);

        if (pDentry->Path)
        {
            HpFreeAndNullWithTag(&pDentry->Path, IC_TAG_NAME);
        }

        HpFreeAndNullWithTag(&pDentry, IC_TAG_NAME);
    }
}


CHAR *
IntLixFileCacheCreateDentryPath(
    _In_ char *Path,
    _In_ DWORD Length,
    _In_ QWORD DentryGva
    )
///
/// @brief  Creates a new cache entry and returns the path string from the newly created entry.
///
/// If we already have a dentry that contains the provided path, we just update it with the new DentryGva.
///
/// @param[in]  Path        The path that will be cached.
/// @param[in]  Length      The length of the path.
/// @param[in]  DentryGva   The guest virtual address of the 'struct dentry' that contains the provided path.
///
/// @retval     On success, returns the path string from the newly created cache-entry; otherwise returns NULL.
///
{
    for_each_dentry(pExtDentry)
    {
        if (pExtDentry->Length == Length && 0 == strcmp(pExtDentry->Path, Path))
        {
            LOG("[LIX-FILES] Update cache for path '%s' with length %d from %llx to %llx\n",
                pExtDentry->Path, pExtDentry->Length, pExtDentry->Gva, DentryGva);

            pExtDentry->Gva = DentryGva;

            return pExtDentry->Path;
        }
    }

    if (Length > sizeof(gLixPath))
    {
        ERROR("[ERROR] The length (0x%x) of the 'd_entry' path exceed the our internal buffer\n", Length);
        return NULL;
    }

    DENTRY_PATH *pDentry = HpAllocWithTag(sizeof(*pDentry), IC_TAG_NAME);
    if (NULL == pDentry)
    {
        return NULL;
    }

    pDentry->Path = HpAllocWithTag((size_t)Length + 1, IC_TAG_NAME);
    if (NULL == pDentry->Path)
    {
        HpFreeAndNullWithTag(&pDentry, IC_TAG_NAME);

        return NULL;
    }

    pDentry->Gva = DentryGva;
    pDentry->Length = Length;
    memcpy(pDentry->Path, Path, Length);

    pDentry->Path[Length] = 0;

    InsertTailList(&gLixDentryCache, &pDentry->Link);

    return pDentry->Path;
}


DENTRY_PATH *
IntLixFileCacheFindDentry(
    _In_ QWORD DentryGva
    )
///
/// @brief  Search for an entry that has the provided DentryGva in the #gLixDentryCache array.
///
/// @param[in]  DentryGva   The guest virtual address of the 'struct dentry'.
///
/// @retval     On success, returns the path for the provided DentryGva; otherwise returns NULL.
///
{
    for_each_dentry(pDentry)
    {
        if (pDentry->Gva == DentryGva)
        {
            return pDentry;
        }
    }

    return NULL;
}


INTSTATUS
IntLixFileGetDentry(
    _In_ QWORD File,
    _Out_ QWORD *Dentry
    )
///
/// @brief Reads the value of the dentry field of the 'struct file'.
///
/// @param[in]  File        The guest virtual address of the 'struct file'
/// @param[in]  Dentry      The guest virtual address of the 'struct dentry'.
///
/// @retval     #INT_STATUS_SUCCESS         On success.
/// @retval     #INT_STATUS_NOT_SUPPORTED   If the guest virtual address of the 'struct dentry' is not a kernel pointer.
///
{
    INTSTATUS status = IntKernVirtMemFetchQword(File + LIX_FIELD(Ungrouped, FileDentry), Dentry);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemFetchQword failed with status: 0x%08x\n", status);
        return status;
    }

    if (!IS_KERNEL_POINTER_LIX(*Dentry))
    {
        ERROR("[ERROR] The value of the dentry is not a linux-kernel pointer!\n");
        return INT_STATUS_NOT_SUPPORTED;
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntLixDentryGetName(
    _In_ QWORD Dentry,
    _Outptr_ char **FileName,
    _Out_opt_ DWORD *NameLength
    )
///
/// @brief Gets the file-name that corresponds to the provided Dentry (guest virtual address).
///
/// NOTE: The caller must free the file-name.
///
/// @param[in]  Dentry          The guest virtual address of the 'struct dentry'.
/// @param[in]  FileName        On success, contains a pointer to the file-name.
/// @param[in]  NameLength      On success, the length of the file-name.
///
/// @retval     #INT_STATUS_SUCCESS                 On success.
/// @retval     #INT_STATUS_INSUFFICIENT_RESOURCES  If the alloc fails.
/// @retval     #INT_STATUS_INVALID_DATA_SIZE       If the length of the file-name is invalid.
/// @retval     #INT_STATUS_INVALID_PARAMETER_1     If the pointer to the 'struct dentry' is not a kernel pointer.
/// @retval     #INT_STATUS_INVALID_PARAMETER_2     If the pointer to the file-name parameter is invalid.
///
{
    INTSTATUS status;
    LIX_QSTR qstr;

    if (!IS_KERNEL_POINTER_LIX(Dentry))
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (FileName == NULL)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    status = IntKernVirtMemRead(Dentry + LIX_FIELD(Dentry, Name), sizeof(qstr), &qstr, NULL);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemRead failed for GVA 0x%016llx: 0x%08x\n",
              Dentry + LIX_FIELD(Dentry, Name), status);
        return status;
    }

    if (qstr.Length == 0 || !IS_KERNEL_POINTER_LIX(qstr.Name))
    {
        ERROR("[ERROR] Invalid q_str {%llx; %d} dentry %llx\n", qstr.Name, qstr.Length, Dentry);
        return INT_STATUS_INVALID_DATA_SIZE;
    }

    DWORD readLen = MIN(qstr.Length, LIX_MAX_PATH);

    char *fileName = HpAllocWithTag(readLen + 1ull, IC_TAG_NAME);
    if (NULL == fileName)
    {
        return INT_STATUS_INSUFFICIENT_RESOURCES;
    }

    status = IntKernVirtMemRead(qstr.Name, readLen, fileName, NULL);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemRead failed for GVA 0x%016llx: 0x%08x\n", qstr.Name, status);
        HpFreeAndNullWithTag(&fileName, IC_TAG_NAME);
        return status;
    }

    *FileName = fileName;

    if (NameLength)
    {
        *NameLength = readLen;
    }

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntLixFileReadDentry(
    _In_ QWORD DentryGva,
    _Out_ char *Name,
    _Out_ DWORD *Length
    )
///
/// @brief Reads the name and the length form 'struct dentry'.
///
/// @param[in]  DentryGva       The guest virtual address of the 'struct dentry'.
/// @param[in]  Name            On success, contains the content of the dentry.d_name
/// @param[in]  Length          On success, the length of the dentry.d_name.
///
/// @retval     #INT_STATUS_SUCCESS                 On success.
/// @retval     #INT_STATUS_INVALID_DATA_SIZE       If the length of the file-name is invalid.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;
    LIX_QSTR qstr = { 0 };

    status = IntKernVirtMemRead(DentryGva + LIX_FIELD(Dentry, Name), sizeof(qstr), &qstr, NULL);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemRead failed for GVA 0x%016llx: 0x%08x\n",
              DentryGva + LIX_FIELD(Dentry, Name), status);
        return status;
    }

    if (qstr.Length == 0 || qstr.Length >= LIX_MAX_PATH)
    {
        ERROR("[ERROR] Invalid q_str length in dentry %llx: %d)\n", DentryGva, qstr.Length);
        return INT_STATUS_INVALID_DATA_SIZE;
    }

    status = IntKernVirtMemRead(qstr.Name, qstr.Length, Name, NULL);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemRead failed for GVA 0x%016llx: 0x%08x\n", qstr.Name, status);
        return status;
    }

    *(Name + qstr.Length) = 0;

    *Length = qstr.Length;

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntLixFileGetPath(
    _In_ QWORD FileStructGva,
    _Out_ char **Path,
    _Out_opt_ DWORD *Length
    )
///
/// @brief Gets the path that corresponds to the provided FileStructGva (guest virtual address of the 'struct file').
///
/// For each iteration the parent of the dentry is fetched; the loop of iteration ends when the dentry.parent is equal
/// with the current dentry guest virtual address or the dentry.parent is not a valid kernel guest virtual address.
///
/// @param[in]  FileStructGva   The guest virtual address of the 'struct file'.
/// @param[out] Path            On success, contains a pointer to the path of the file.
/// @param[out] Length          On success, the length of the path.
///
/// @retval     #INT_STATUS_SUCCESS                 On success.
/// @retval     #INT_STATUS_INVALID_PARAMETER_1     If the pointer to the 'struct dentry' is not a kernel pointer.
/// @retval     #INT_STATUS_INVALID_PARAMETER_2     If the pointer to the Path parameter is invalid.
/// @retval     #INT_STATUS_NOT_SUPPORTED           If the guest virtual address of the 'struct dentry' is not a kernel
///                                                 pointer.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;
    DENTRY_PATH *pDentry = NULL;
    QWORD cacheDentryGva = 0;
    QWORD crtDentryGva = 0;
    QWORD parentDentry = 0;
    QWORD prevHashList = 0;
    DWORD fileNameLength = 0;
    DWORD dentryLevel = 0;
    INT32 index = 0;
    char tmpOutput[LIX_MAX_PATH] = { 0 };

    if (!IS_KERNEL_POINTER_LIX(FileStructGva))
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (Path == NULL)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    *Path = NULL;

    status = IntLixFileGetDentry(FileStructGva, &crtDentryGva);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntLixFileGetDentry failed for file %llx: 0x%08x\n", FileStructGva, status);
        return status;
    }

    status = IntKernVirtMemFetchQword(crtDentryGva + LIX_FIELD(Dentry, Parent), &parentDentry);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemFetchQword failed for GVA 0x%016llx: 0x%08x\n",
              crtDentryGva + LIX_FIELD(Dentry, Parent), status);
        return status;
    }

    status = IntKernVirtMemFetchQword(crtDentryGva + LIX_FIELD(Dentry, HashList) + sizeof(QWORD), &prevHashList);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemFetchQword failed for GVA 0x%016llx: 0x%08x\n",
              crtDentryGva + LIX_FIELD(Dentry, HashList) + sizeof(QWORD), status);
        return status;
    }

    if (!prevHashList && crtDentryGva == parentDentry)
    {
        DWORD length = CSTRLEN("(deleted)");
        gLixPath[sizeof(gLixPath) - 1] = 0;
        memcpy(gLixPath + sizeof(gLixPath) - length - 1, "(deleted)", length);
        *Path = gLixPath + sizeof(gLixPath) - length - 1;

        if (Length)
        {
            *Length = length;
        }

        return INT_STATUS_SUCCESS;
    }

    status = IntLixFileReadDentry(crtDentryGva, tmpOutput, &fileNameLength);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntLixFileReadDentry failed for dentry @ 0x%016llx : %08x", crtDentryGva, status);
        return status;
    }

    index = sizeof(gLixPath) -1;
    gLixPath[index] = 0;

    // fileNameLength is ok, it can be maximum LIX_MAX_PATH (256). Check out IntLixFileReadDentry.
    index -= fileNameLength;
    memcpy(gLixPath + index, tmpOutput, fileNameLength);

    index--;
    gLixPath[index] = '/';

    status = IntKernVirtMemFetchQword(crtDentryGva + LIX_FIELD(Dentry, Parent), &crtDentryGva);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemFetchQword failed for GVA 0x%016llx: 0x%08x\n",
              crtDentryGva + LIX_FIELD(Dentry, Parent), status);
        return status;
    }

    if (!IS_KERNEL_POINTER_LIX(crtDentryGva))
    {
        return INT_STATUS_NOT_SUPPORTED;
    }

    cacheDentryGva = crtDentryGva;

    while (crtDentryGva && dentryLevel < LIX_MAX_DENTRY_DEPTH)
    {
        QWORD dentryParentGva = 0;
        DWORD crtNameLength = 0;

        pDentry = IntLixFileCacheFindDentry(crtDentryGva);
        if (pDentry)
        {
            break;
        }

        status = IntLixFileReadDentry(crtDentryGva, tmpOutput, &crtNameLength);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntLixFileReadDentry failed for dentry @ 0x%016llx : %08x", crtDentryGva, status);
            return status;
        }

        status = IntKernVirtMemFetchQword(crtDentryGva + LIX_FIELD(Dentry, Parent), &dentryParentGva);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntKernVirtMemFetchQword failed for GVA 0x%016llx: 0x%08x\n",
                  crtDentryGva + LIX_FIELD(Dentry, Parent), status);
            return status;
        }

        // crtNameLength can be max LIX_MAX_PATH.
        index -= crtNameLength;
        if (index <= 0)
        {
            ERROR("[ERROR] Path for file 0x%llx is too big\n", FileStructGva);
            return INT_STATUS_INVALID_DATA_SIZE;
        }

        memcpy(gLixPath + index, tmpOutput, crtNameLength);
        if (dentryParentGva != crtDentryGva)
        {
            index--;
            gLixPath[index] = '/';
        }
        else if (index < (INT32)sizeof(gLixPath) - 1)
        {
            // 99.9% of cases the parent is '/', so handle that
            if (gLixPath[index] == '/' && gLixPath[index + 1] == '/')
            {
                index++;
            }
        }

        if (!IS_KERNEL_POINTER_LIX(dentryParentGva))
        {
            ERROR("[ERROR] Got to a invalid parent %llx in dentry %llx!\n", dentryParentGva, crtDentryGva);
            break;
        }
        else if (dentryParentGva == crtDentryGva)
        {
            break;
        }

        crtDentryGva = dentryParentGva;

        dentryLevel++;
    }

    if (!pDentry && IntLixFileCachePathIsValid(gLixPath + index))
    {
        IntLixFileCacheCreateDentryPath(gLixPath + index,
                                        sizeof(gLixPath) - index - fileNameLength - 1,
                                        cacheDentryGva);
    }
    else if (pDentry)
    {
        // The length of the 'd_entry' path is validated when the cache entry is created.
        INT32 size = index - pDentry->Length + sizeof(char);

        if (size < 0)
        {
            ERROR("[ERROR] The length (0x%08x) of the 'd_entry' path underflows the our buffer (0x%08x)\n",
                  pDentry->Length, index);
            return INT_STATUS_INVALID_DATA_SIZE;
        }

        memcpy(gLixPath + index - pDentry->Length + 1, pDentry->Path, pDentry->Length);
        index -= pDentry->Length - 1;
    }

    *Path = gLixPath + index;

    if (Length != NULL)
    {
        *Length = sizeof(gLixPath) - index - 1;
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntLixGetFileName(
    _In_ QWORD FileStruct,
    _Outptr_ char **FileName,
    _Out_opt_ DWORD *NameLength,
    _Out_opt_ QWORD *DentryGva
    )
///
/// @brief Gets the file-name that corresponds to the provided FileStruct (guest virtual address).
///
/// @param[in]  FileStruct      The guest virtual address of the 'struct file'.
/// @param[in]  FileName        On success, contains a pointer to the file-name.
/// @param[in]  NameLength      The length of the file-name.
/// @param[in]  DentryGva       The guest virtual address of the 'struct dentry'.
///
/// @retval     #INT_STATUS_SUCCESS                 On success.
/// @retval     #INT_STATUS_INVALID_PARAMETER_1     If the pointer to the 'struct file' is not a kernel pointer.
/// @retval     #INT_STATUS_INVALID_PARAMETER_2     If the pointer to the file-name parameter is invalid.
///
{

    QWORD dentry;
    INTSTATUS status;

    if (!IS_KERNEL_POINTER_LIX(FileStruct))
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (NULL == FileName)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    status = IntLixFileGetDentry(FileStruct, &dentry);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntLixFileGetDentry failed for file %llx: 0x%08x\n", FileStruct, status);
        return status;
    }

    if (DentryGva)
    {
        *DentryGva = dentry;
    }

    return IntLixDentryGetName(dentry, FileName, NameLength);
}
