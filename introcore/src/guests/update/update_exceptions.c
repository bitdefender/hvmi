/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
///
/// @file       update_exceptions.c
/// @ingroup    group_exceptions
/// @brief      Handles exception updates.
///

#include "update_exceptions.h"
#include "alert_exceptions.h"
#include "guests.h"
#include "utils.h"

/// Validate that an object fits inside the exception buffer.
#define UPDATE_VALIDATE_FILE_SIZE       0x1
/// Validate the size of the exception header.
#define UPDATE_VALIDATE_HEADER_SIZE     0x2
/// All exception validation options.
#define UPDATE_VALIDATE_ALL             (UPDATE_VALIDATE_FILE_SIZE | UPDATE_VALIDATE_HEADER_SIZE)

/// The current signature ID. Changes every time a new ID is generated.
static EXCEPTION_SIGNATURE_ID gCurrentSignatureId = { .Field = { .Value = BIT(22) / 2, .Type = 0} };

///
/// @brief Contains the information about the sizes of an entry (exception/signature) and about the size of the
/// exceptions file.
///
typedef struct _UPDATE_ITEM_SIZE
{
    DWORD   EntrySize;              ///< The size of the current exception/signature.
    DWORD   RemainingFileSize;      ///< The remaining bytes for the exceptions file.
} UPDATE_ITEM_SIZE, *PUPDATE_ITEM_SIZE;


INTSTATUS
IntUpdateGetVersion(
    _Out_ WORD *MajorVersion,
    _Out_ WORD *MinorVersion,
    _Out_ DWORD *BuildNumber
    )
///
/// @brief Get the version of the loaded exceptions binary file.
///
/// @param[out] MajorVersion     The major version of the exceptions.
/// @param[out] MinorVersion     The minor version of the exceptions.
/// @param[out] BuildNumber      The build number of the exceptions.
///
/// @retval #INT_STATUS_SUCCESS              On success.
/// @retval #INT_STATUS_INVALID_PARAMETER_1  If the MajorVersion is null.
/// @retval #INT_STATUS_INVALID_PARAMETER_2  If the MinorVersion is null.
/// @retval #INT_STATUS_INVALID_PARAMETER_3  If the BuildNumber is null.
/// @retval #INT_STATUS_NOT_INITIALIZED      If the exceptions is not loaded.
///
{
    if (NULL == MajorVersion)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (NULL == MinorVersion)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    if (NULL == BuildNumber)
    {
        return INT_STATUS_INVALID_PARAMETER_3;
    }

    if (NULL == gGuest.Exceptions || !gGuest.Exceptions->Loaded)
    {
        return INT_STATUS_NOT_INITIALIZED;
    }

    *MajorVersion = gGuest.Exceptions->Version.Major;
    *MinorVersion = gGuest.Exceptions->Version.Minor;
    *BuildNumber = gGuest.Exceptions->Version.Build;

    return INT_STATUS_SUCCESS;
}


static __forceinline EXCEPTION_SIGNATURE_ID
IntUpdateGetUniqueSigId(
    _In_ EXCEPTION_SIGNATURE_TYPE Type
    )
///
/// @brief Get an unique signature ID for a given type.
///
/// @param[in] Type              The type of the signature.
///
/// @retval An unique ID.
///
{
    gCurrentSignatureId.Field.Value++;
    gCurrentSignatureId.Field.Type = Type;

    return gCurrentSignatureId;
}


static BOOLEAN
IntUpdateIsValidEntry(
    _In_ DWORD Size,
    _In_ UPDATE_ITEM_SIZE *Item,
    _In_ DWORD Flags
    )
///
/// @brief Checks if the provided Size can be read from the exceptions file without exceeding its size.
///
/// @param[in] Size     The size of the entry to be read.
/// @param[in] Item     The information about the current entry size and the file size.
/// @param[in] Flags    The size (header/file) to be validated.
///
/// @retval     True if the size of the entry is not valid, otherwise false.
///
{
    if (Flags & UPDATE_VALIDATE_HEADER_SIZE)
    {
        if (Size != Item->EntrySize)
        {
            ERROR("[ERROR] The exceptions file is corrupted. The size of the entry (%d) is different from the size "
                  "provided by the header (%d)\n", Size, Item->EntrySize);
            return FALSE;
        }
    }

    if (Flags & UPDATE_VALIDATE_FILE_SIZE)
    {
        if (Size > Item->RemainingFileSize)
        {
            ERROR("[ERROR] The exceptions file is corrupted. The size of the entry (%d) exceed the remaining size "
                  "of the exceptions file (%d)\n", Size, Item->RemainingFileSize);
            return FALSE;
        }
    }

    return TRUE;
}


static INTSTATUS
IntUpdateAddKernelException(
    _In_ UPDATE_KM_EXCEPTION *UpdateException,
    _In_ UPDATE_ITEM_SIZE *Item
    )
///
/// @brief Creates a new kernel-exception and adds it to our internal list.
///
/// The exception is added to the appropriate list as follows:
///     - if the originator name is #kmExcNameAny the exception is added to the generic exceptions list
///     - if the originator name is #kmExcNameNone the exception is added to the no-name exceptions list
///     - if the #EXCEPTION_FLG_FEEDBACK is set the exception is added to the generic/no-name feedback list
///
/// @param[in] UpdateException  The data from the binary file.
/// @param[in] Item             The information about the current entry size and the file size.
///
/// @retval #INT_STATUS_SUCCESS                 On success.
/// @retval #INT_STATUS_NOT_NEEDED_HINT         If the exception has the ignore flag or the flags don't match the
///                                             operating system.
/// @retval #INT_STATUS_INSUFFICIENT_RESOURCES  If not enough memory is available.
///
{
    DWORD extraSize;
    KM_EXCEPTION *pException;
    LIST_HEAD *head;

    if (!IntUpdateIsValidEntry(sizeof(*UpdateException), Item, UPDATE_VALIDATE_FILE_SIZE))
    {
        return INT_STATUS_INVALID_DATA_STATE;
    }

    extraSize = UpdateException->SigCount * sizeof(EXCEPTION_SIGNATURE_ID);

    if (!IntUpdateIsValidEntry(sizeof(*UpdateException) + extraSize, Item, UPDATE_VALIDATE_ALL))
    {
        return INT_STATUS_INVALID_DATA_STATE;
    }

    if ((gGuest.OSType == introGuestWindows && (UpdateException->Flags & EXCEPTION_FLG_LINUX)) ||
        (gGuest.OSType == introGuestLinux && !(UpdateException->Flags & EXCEPTION_FLG_LINUX)))
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    if (UpdateException->Flags & EXCEPTION_FLG_IGNORE)
    {
        TRACE("[UPDATE] Dropped an ignored KM exception. No problem here!\n");
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    // SigCount is a WORD, multiplied by sizeof(EXCEPTION_SIGNATURE_ID), so the size won't overflow.
    pException = HpAllocWithTag(sizeof(*pException) + extraSize, IC_TAG_EXKM);
    if (NULL == pException)
    {
        return INT_STATUS_INSUFFICIENT_RESOURCES;
    }

    pException->OriginatorNameHash = UpdateException->Originator.NameHash;
    pException->VictimNameHash = UpdateException->VictimNameHash;
    pException->Flags = UpdateException->Flags;
    pException->Type = UpdateException->Type;
    pException->SigCount = UpdateException->SigCount;

    // This is an old exceptions.bin, so add the write flag manually
    if (0 == (pException->Flags & (EXCEPTION_FLG_READ | EXCEPTION_FLG_WRITE | EXCEPTION_FLG_EXECUTE)))
    {
        pException->Flags |= EXCEPTION_FLG_WRITE;
    }

    // Only copy if we have signatures
    if (UpdateException->SigCount > 0)
    {
        memcpy(&pException->Signatures[0], &UpdateException->SigIds[0],
               UpdateException->SigCount * sizeof(EXCEPTION_SIGNATURE_ID));
    }

    //
    // Now, let's find in which list this exception is
    //
    if (pException->OriginatorNameHash == kmExcNameAny)
    {
        if (UpdateException->Flags & EXCEPTION_FLG_FEEDBACK)
        {
            head = &gGuest.Exceptions->KernelFeedbackExceptions;
        }
        else
        {
            head = &gGuest.Exceptions->GenericKernelExceptions;
        }
    }
    else if (pException->OriginatorNameHash == kmExcNameNone)
    {
        if (UpdateException->Flags & EXCEPTION_FLG_FEEDBACK)
        {
            head = &gGuest.Exceptions->KernelFeedbackExceptions;
        }
        else
        {
            head = &gGuest.Exceptions->NoNameKernelExceptions;
        }
    }
    else
    {
        if (UpdateException->Flags & EXCEPTION_FLG_FEEDBACK)
        {
            head = &gGuest.Exceptions->KernelFeedbackExceptions;
        }
        else
        {
            DWORD id = EXCEPTION_TABLE_ID(pException->OriginatorNameHash);
            head = &gGuest.Exceptions->KernelExceptions[id];
        }
    }

    InsertTailList(head, &pException->Link);

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntUpdateAddKernelUserException(
    _In_ UPDATE_KUM_EXCEPTION *UpdateException,
    _In_ UPDATE_ITEM_SIZE *Item
    )
///
/// @brief Creates a new kernel-user mode exception and adds it to our internal list.
///
/// The exception is added to the appropriate list as follows:
///     - if the originator name is #kmExcNameAny the exception is added to the generic exceptions list
///     - if the originator name is #kmExcNameNone the exception is added to the no-name exceptions list
///     - if the #EXCEPTION_FLG_FEEDBACK is set the exception is added to the generic/no-name feedback list
///
/// @param[in] UpdateException  The data from the binary file.
/// @param[in] Item             The information about the current entry size and the file size.
///
/// @retval #INT_STATUS_SUCCESS                 On success.
/// @retval #INT_STATUS_NOT_NEEDED_HINT         If the exception has the ignore flag or the flags don't match the
///                                             operating system.
/// @retval #INT_STATUS_INSUFFICIENT_RESOURCES  If not enough memory is available.
///
{
    DWORD extraSize;
    KUM_EXCEPTION *pException;
    LIST_HEAD *head;

    if (!IntUpdateIsValidEntry(sizeof(*UpdateException), Item, UPDATE_VALIDATE_FILE_SIZE))
    {
        return INT_STATUS_INVALID_DATA_STATE;
    }

    extraSize = UpdateException->SigCount * sizeof(EXCEPTION_SIGNATURE_ID);

    if (!IntUpdateIsValidEntry(sizeof(*UpdateException) + extraSize, Item, UPDATE_VALIDATE_ALL))
    {
        return INT_STATUS_INVALID_DATA_STATE;
    }

    if ((gGuest.OSType == introGuestWindows && (UpdateException->Flags & EXCEPTION_FLG_LINUX)) ||
        (gGuest.OSType == introGuestLinux && !(UpdateException->Flags & EXCEPTION_FLG_LINUX)))
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    if (UpdateException->Flags & EXCEPTION_FLG_IGNORE)
    {
        TRACE("[UPDATE] Dropped an ignored KM exception. No problem here!\n");
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    // SigCount is a WORD, multiplied by sizeof(EXCEPTION_SIGNATURE_ID), so the size won't overflow.
    pException = HpAllocWithTag(sizeof(*pException) + extraSize, IC_TAG_EXKU);
    if (NULL == pException)
    {
        return INT_STATUS_INSUFFICIENT_RESOURCES;
    }

    pException->Originator.NameHash = UpdateException->Originator.NameHash;
    pException->Victim.NameHash = UpdateException->Victim.NameHash;
    pException->Victim.ProcessHash = UpdateException->Victim.ProcessHash;
    pException->Flags = UpdateException->Flags;
    pException->Type = UpdateException->Type;
    pException->SigCount = UpdateException->SigCount;

    // Only copy if we have signatures
    if (UpdateException->SigCount > 0)
    {
        memcpy(&pException->Signatures[0], &UpdateException->SigIds[0],
               UpdateException->SigCount * sizeof(EXCEPTION_SIGNATURE_ID));
    }

    //
    // Now, let's find in which list this exception is
    //
    if (pException->Originator.NameHash == kumExcNameAny)
    {
        if (UpdateException->Flags & EXCEPTION_FLG_FEEDBACK)
        {
            head = &gGuest.Exceptions->KernelUserFeedbackExceptions;
        }
        else
        {
            head = &gGuest.Exceptions->GenericKernelUserExceptions;
        }
    }
    else if (pException->Originator.NameHash == kumExcNameNone)
    {
        if (UpdateException->Flags & EXCEPTION_FLG_FEEDBACK)
        {
            head = &gGuest.Exceptions->KernelUserFeedbackExceptions;
        }
        else
        {
            head = &gGuest.Exceptions->NoNameKernelExceptions;
        }
    }
    else
    {
        if (UpdateException->Flags & EXCEPTION_FLG_FEEDBACK)
        {
            head = &gGuest.Exceptions->KernelUserFeedbackExceptions;
        }
        else
        {
            DWORD id = EXCEPTION_TABLE_ID(pException->Originator.NameHash);
            head = &gGuest.Exceptions->KernelUserExceptions[id];
        }
    }

    InsertTailList(head, &pException->Link);

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntUpdateAddUserException(
    _In_ UPDATE_UM_EXCEPTION *UpdateException,
    _In_ UPDATE_ITEM_SIZE *Item
    )
///
/// @brief Creates a new user-exception and adds it to our internal list.
///
/// The exception is added to the appropriate list as follows:
///     - if the originator name is #umExcNameAny the exception is added to the generic exceptions list
///     - if the originator name is #umExcNameNone the exception is added to the no-name exceptions list
///     - if the #EXCEPTION_FLG_FEEDBACK is set the exception is added to the generic/no-name feedback list
///     - if the type of the exception is umObjProcessCreation the exception is added to the process-creation
/// exceptions list.
///
/// @param[in] UpdateException  The data from the binary file.
/// @param[in] Item             The information about the current entry size and the file size.
///
/// @retval #INT_STATUS_SUCCESS                 On success.
/// @retval #INT_STATUS_NOT_NEEDED_HINT         If the exception has the ignore flag or the flags don't match the
///                                             operating system.
/// @retval #INT_STATUS_INSUFFICIENT_RESOURCES  If not enough memory is available.
///
{
    DWORD extraSize;
    UM_EXCEPTION *pException;
    LIST_HEAD *head;

    if (!IntUpdateIsValidEntry(sizeof(*UpdateException), Item, UPDATE_VALIDATE_FILE_SIZE))
    {
        return INT_STATUS_INVALID_DATA_STATE;
    }

    extraSize = UpdateException->SigCount * sizeof(EXCEPTION_SIGNATURE_ID);

    if (!IntUpdateIsValidEntry(sizeof(*UpdateException) + extraSize, Item, UPDATE_VALIDATE_ALL))
    {
        return INT_STATUS_INVALID_DATA_STATE;
    }

    if ((gGuest.OSType == introGuestWindows && (UpdateException->Flags & EXCEPTION_FLG_LINUX)) ||
        (gGuest.OSType == introGuestLinux && !(UpdateException->Flags & EXCEPTION_FLG_LINUX)))
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    if (UpdateException->Flags & EXCEPTION_FLG_IGNORE)
    {
        TRACE("[UPDATE] Dropped an ignored UM exception. No problem here!\n");
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    pException = HpAllocWithTag(sizeof(*pException) + extraSize, IC_TAG_EXUM);
    if (NULL == pException)
    {
        return INT_STATUS_INSUFFICIENT_RESOURCES;
    }

    pException->OriginatorNameHash = UpdateException->OriginatorNameHash;
    pException->Victim.NameHash = UpdateException->Victim.NameHash;
    pException->Victim.ProcessHash = UpdateException->Victim.ProcessHash;
    pException->Flags = UpdateException->Flags;
    pException->Type = UpdateException->Type;
    pException->SigCount = UpdateException->SigCount;

    // This is an old exceptions.bin, so add the write/exec flag manually
    if (0 == (pException->Flags & (EXCEPTION_FLG_READ | EXCEPTION_FLG_WRITE | EXCEPTION_FLG_EXECUTE)))
    {
        if (pException->Type == umObjNxZone)
        {
            pException->Flags |= EXCEPTION_FLG_EXECUTE;
        }
        else
        {
            pException->Flags |= EXCEPTION_FLG_WRITE;
        }
    }

    if (UpdateException->SigCount > 0)
    {
        // We have calculated the size occupied by the exception, so it's safe to use memcpy for signatures
        memcpy(pException->Signatures, UpdateException->SigIds,
               UpdateException->SigCount * sizeof(EXCEPTION_SIGNATURE_ID));
    }

    // Now, let's find in which list this exception is
    if (pException->Type == umObjProcessCreation)
    {
        if (UpdateException->Flags & EXCEPTION_FLG_FEEDBACK)
        {
            head = &gGuest.Exceptions->ProcessCreationFeedbackExceptions;
        }
        else
        {
            head = &gGuest.Exceptions->ProcessCreationExceptions;
        }
    }
    else if (pException->OriginatorNameHash == umExcNameAny)
    {
        if (UpdateException->Flags & EXCEPTION_FLG_FEEDBACK)
        {
            head = &gGuest.Exceptions->UserFeedbackExceptions;
        }
        else
        {
            head = &gGuest.Exceptions->GenericUserExceptions;
        }
    }
    else if (pException->OriginatorNameHash == umExcNameNone)
    {
        if (UpdateException->Flags & EXCEPTION_FLG_FEEDBACK)
        {
            head = &gGuest.Exceptions->UserFeedbackExceptions;
        }
        else
        {
            head = &gGuest.Exceptions->NoNameUserExceptions;
        }
    }
    else
    {
        if (UpdateException->Flags & EXCEPTION_FLG_FEEDBACK)
        {
            head = &gGuest.Exceptions->UserFeedbackExceptions;
        }
        else
        {
            DWORD id = EXCEPTION_TABLE_ID(pException->OriginatorNameHash);
            head = &gGuest.Exceptions->UserExceptions[id];
        }
    }

    InsertTailList(head, &pException->Link);

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntUpdateAddUserExceptionGlob(
    _In_ UPDATE_UM_EXCEPTION_GLOB *UpdateException,
    _In_ UPDATE_ITEM_SIZE *Item
    )
///
/// @brief Creates a new glob user-exception  and adds it to our internal list.
///
/// @param[in] UpdateException  The data from the binary file.
/// @param[in] Item             The information about the current entry size and the file size.
///
/// @retval #INT_STATUS_SUCCESS                 On success.
/// @retval #INT_STATUS_NOT_NEEDED_HINT         If the exception has the ignore flag or the flags don't match the
///                                             operating system.
/// @retval #INT_STATUS_INSUFFICIENT_RESOURCES  If not enough memory is available.
/// @retval #INT_STATUS_NOT_SUPPORTED           If the originator or the victim fields content is longer that
///                                             #EXCEPTION_UM_GLOB_LENGTH.
///
{
    DWORD extraSize = 0;
    DWORD size = 0;
    DWORD remainingSize = Item->RemainingFileSize;
    char *pOriginatorName = NULL;
    size_t originatorNameLen = 0;
    char *pVictimName = NULL;
    size_t victimNameLen = 0;
    char *pProcName = NULL;
    size_t procNameLen = 0;
    UM_EXCEPTION_GLOB *pException;

    if (!IntUpdateIsValidEntry(sizeof(*UpdateException), Item, UPDATE_VALIDATE_FILE_SIZE))
    {
        return INT_STATUS_INVALID_DATA_STATE;
    }

    size = sizeof(UpdateException->Flags) + sizeof(UpdateException->Type) + sizeof(UpdateException->_Reserved)
           + sizeof(UpdateException->SigCount);
    remainingSize -= size;

    if (UpdateException->Flags & EXCEPTION_FLG_IGNORE)
    {
        TRACE("[UPDATE] Dropped an ignored UM exception. No problem here!\n");
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    pOriginatorName = UpdateException->OriginatorNameGlob;
    originatorNameLen = strlen_s(pOriginatorName, MIN((DWORD)EXCEPTION_UM_GLOB_LENGTH, remainingSize)) + 1;
    size += (DWORD)originatorNameLen;
    remainingSize -= (DWORD)originatorNameLen;

    if (originatorNameLen <= 1)
    {
        ERROR("[ERROR] The originator name length is invalid (%zu)\n", originatorNameLen);
        return INT_STATUS_INVALID_DATA_STATE;
    }

    if (!IntUpdateIsValidEntry(sizeof(*UpdateException) + size, Item, UPDATE_VALIDATE_FILE_SIZE))
    {
        return INT_STATUS_INVALID_DATA_STATE;
    }

    if (originatorNameLen > EXCEPTION_UM_GLOB_LENGTH)
    {
        ERROR("[ERROR] Originator Name length is longer than the supported one (%d)\n", EXCEPTION_UM_GLOB_LENGTH);
        return INT_STATUS_NOT_SUPPORTED;
    }

    pVictimName = pOriginatorName + originatorNameLen;
    victimNameLen = strlen_s(pVictimName, MIN((DWORD)EXCEPTION_UM_GLOB_LENGTH, remainingSize)) + 1;
    size += (DWORD)victimNameLen;
    remainingSize -= (DWORD)victimNameLen;

    if (victimNameLen <= 1)
    {
        ERROR("[ERROR] The victim name length is invalid (%zu)\n", victimNameLen);
        return INT_STATUS_INVALID_DATA_STATE;
    }

    if (!IntUpdateIsValidEntry(sizeof(*UpdateException) + size, Item, UPDATE_VALIDATE_FILE_SIZE))
    {
        return INT_STATUS_INVALID_DATA_STATE;
    }

    if (victimNameLen > EXCEPTION_UM_GLOB_LENGTH)
    {
        ERROR("[ERROR] Victim Name length is longer than the supported one (%d)\n", EXCEPTION_UM_GLOB_LENGTH);
        return INT_STATUS_NOT_SUPPORTED;
    }

    pProcName = pVictimName + victimNameLen;
    procNameLen = strlen_s(pProcName, MIN((DWORD)EXCEPTION_UM_GLOB_LENGTH, remainingSize)) + 1;
    size += (DWORD)procNameLen;

    if (procNameLen <= 1)
    {
        ERROR("[ERROR] The process name length is invalid (%zu)\n", procNameLen);
        return INT_STATUS_INVALID_DATA_STATE;
    }


    if (!IntUpdateIsValidEntry(sizeof(*UpdateException) + size, Item, UPDATE_VALIDATE_FILE_SIZE))
    {
        return INT_STATUS_INVALID_DATA_STATE;
    }

    if (procNameLen > EXCEPTION_UM_GLOB_LENGTH)
    {
        ERROR("[ERROR] Victim Process length is longer than the supported one (%d)\n", EXCEPTION_UM_GLOB_LENGTH);
        return INT_STATUS_NOT_SUPPORTED;
    }

    extraSize = UpdateException->SigCount * sizeof(EXCEPTION_SIGNATURE_ID);
    size += extraSize;

    if (!IntUpdateIsValidEntry(size, Item, UPDATE_VALIDATE_ALL))
    {
        return INT_STATUS_INVALID_OBJECT_TYPE;
    }

    if ((gGuest.OSType == introGuestWindows && (UpdateException->Flags & EXCEPTION_FLG_LINUX)) ||
        (gGuest.OSType == introGuestLinux && !(UpdateException->Flags & EXCEPTION_FLG_LINUX)))
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    pException = HpAllocWithTag(sizeof(*pException) + extraSize, IC_TAG_EXUM);
    if (NULL == pException)
    {
        return INT_STATUS_INSUFFICIENT_RESOURCES;
    }

    pException->Flags = UpdateException->Flags;
    pException->Type = UpdateException->Type;
    pException->SigCount = UpdateException->SigCount;

    if (originatorNameLen > 1)
    {
        strlcpy(pException->OriginatorNameGlob, pOriginatorName, sizeof(pException->OriginatorNameGlob));
    }

    if (victimNameLen > 1)
    {
        strlcpy(pException->Victim.NameGlob, pVictimName, sizeof(pException->Victim.NameGlob));
    }

    if (procNameLen > 1)
    {
        strlcpy(pException->Victim.ProcessGlob, pProcName, sizeof(pException->Victim.ProcessGlob));
    }

    if (UpdateException->SigCount > 0)
    {
        // We have calculated the size occupied by the exception, so it's safe to use memcpy for signatures
        void *pSigStart = pProcName + procNameLen;
        memcpy(pException->Signatures, pSigStart, UpdateException->SigCount * sizeof(EXCEPTION_SIGNATURE_ID));
    }

    InsertTailList(&gGuest.Exceptions->GlobUserExceptions, &pException->Link);

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntUpdateAddCbSignature(
    _In_ UPDATE_CB_SIGNATURE *UpdateSignature,
    _In_ UPDATE_ITEM_SIZE *Item
    )
///
/// @brief Creates a new code-blocks signature  and adds it to our internal list.
///
/// @param[in] UpdateSignature  The data from the binary file.
/// @param[in] Item             The information about the current entry size and the file size.
///
/// @retval #INT_STATUS_SUCCESS                 On success.
/// @retval #INT_STATUS_NOT_NEEDED_HINT         If the the flags don't match the operating system.
/// @retval #INT_STATUS_INSUFFICIENT_RESOURCES  If the HpAllocWithTag fails.
///
{
    DWORD extraSize = 0;
    DWORD size = 0;
    UPDATE_CB_HASH *pHashList;
    SIG_CODEBLOCKS *pSignature;
    SIG_CODEBLOCK_HASH *pSigHash;

    // Now see how many hashes we have in each signature
    if (!IntUpdateIsValidEntry(sizeof(*UpdateSignature) + sizeof(UPDATE_CB_HASH), Item, UPDATE_VALIDATE_FILE_SIZE))
    {
        return INT_STATUS_INVALID_DATA_STATE;
    }

    pHashList = (PUPDATE_CB_HASH)UpdateSignature->HashesList;
    for (DWORD i = 0; i < UpdateSignature->ListsCount; i++)
    {
        DWORD updateHashSize;
        DWORD hashSize;

        // Make sure that we can actually use pHashList
        if (!IntUpdateIsValidEntry(sizeof(*UpdateSignature) + size + sizeof(*pHashList),
                                   Item, UPDATE_VALIDATE_FILE_SIZE))
        {
            return INT_STATUS_INVALID_DATA_STATE;
        }

        // The sizes are not the same due to alignment
        updateHashSize = sizeof(UPDATE_CB_HASH) + pHashList->Count * sizeof(DWORD);
        hashSize = sizeof(SIG_CODEBLOCK_HASH) + pHashList->Count * sizeof(DWORD);

        extraSize += hashSize;
        size += updateHashSize;

        // This will check that the hashes up to this point (size) + the size of the signature structure don't spill
        // outside the file
        if (!IntUpdateIsValidEntry(sizeof(*UpdateSignature) + size, Item, UPDATE_VALIDATE_FILE_SIZE))
        {
            return INT_STATUS_INVALID_DATA_STATE;
        }

        // advance to the next hash list
        pHashList = (UPDATE_CB_HASH *)((BYTE *)pHashList + updateHashSize);
    }

    if (!IntUpdateIsValidEntry(sizeof(*UpdateSignature) + size, Item, UPDATE_VALIDATE_ALL))
    {
        return INT_STATUS_INVALID_DATA_STATE;
    }

    if ((gGuest.OSType == introGuestWindows && (UpdateSignature->Flags & SIGNATURE_FLG_LINUX)) ||
        (gGuest.OSType == introGuestLinux && !(UpdateSignature->Flags & SIGNATURE_FLG_LINUX)))
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    pSignature = HpAllocWithTag(sizeof(*pSignature) + extraSize, IC_TAG_ESIG);
    if (NULL == pSignature)
    {
        return INT_STATUS_INSUFFICIENT_RESOURCES;
    }

    pSignature->Id.Value = UpdateSignature->Id;
    pSignature->Flags = UpdateSignature->Flags;
    pSignature->Score = UpdateSignature->Score;
    pSignature->ListsCount = UpdateSignature->ListsCount;
    pSignature->AlertSignature = FALSE;

    // Now copy the hashes lists
    pHashList = (UPDATE_CB_HASH *)UpdateSignature->HashesList;
    pSigHash = (SIG_CODEBLOCK_HASH *)pSignature->Object;
    for (DWORD i = 0; i < UpdateSignature->ListsCount; i++)
    {
        // The sizes are not the same due to alignment
        DWORD updateHashSize = sizeof(*pHashList) + pHashList->Count * sizeof(DWORD);
        DWORD hashSize = sizeof(*pSigHash) + pHashList->Count * sizeof(DWORD);

        pSigHash->Count = pHashList->Count;
        for (DWORD j = 0; j < pHashList->Count; j++)
        {
            pSigHash->Hashes[j] = pHashList->Hashes[j];
        }

        // advance to the next hash list
        pHashList = (UPDATE_CB_HASH *)((BYTE *)pHashList + updateHashSize);
        pSigHash = (SIG_CODEBLOCK_HASH *)((BYTE *)pSigHash + hashSize);
    }

    InsertTailList(&gGuest.Exceptions->CbSignatures, &pSignature->Link);

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntUpdateAddValueSignature(
    _In_ UPDATE_VALUE_SIGNATURE *UpdateSignature,
    _In_ UPDATE_ITEM_SIZE *Item
    )
///
/// @brief Creates a new value signature and adds it to our internal list.
///
/// @param[in] UpdateSignature  The data from the binary file.
/// @param[in] Item             The information about the current entry size and the file size.
///
/// @retval #INT_STATUS_SUCCESS                 On success.
/// @retval #INT_STATUS_NOT_NEEDED_HINT         If the the flags don't match the operating system.
/// @retval #INT_STATUS_INSUFFICIENT_RESOURCES  If the HpAllocWithTag fails.
///
{
    DWORD size;
    DWORD extraSize;
    SIG_VALUE *pSignature;
    UPDATE_VALUE_HASH *pHashList;
    SIG_VALUE_HASH *pSigHash;

    if (!IntUpdateIsValidEntry(sizeof(*UpdateSignature), Item, UPDATE_VALIDATE_FILE_SIZE))
    {
        return INT_STATUS_INVALID_DATA_STATE;
    }

    size = UpdateSignature->ListsCount * sizeof(UPDATE_VALUE_HASH);
    if (!IntUpdateIsValidEntry(sizeof(*UpdateSignature) + size, Item, UPDATE_VALIDATE_ALL))
    {
        return INT_STATUS_INVALID_DATA_STATE;
    }

    if ((gGuest.OSType == introGuestWindows && (UpdateSignature->Flags & SIGNATURE_FLG_LINUX)) ||
        (gGuest.OSType == introGuestLinux && !(UpdateSignature->Flags & SIGNATURE_FLG_LINUX)))
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    extraSize = UpdateSignature->ListsCount * sizeof(SIG_VALUE_HASH);

    pSignature = HpAllocWithTag(sizeof(*pSignature) + extraSize, IC_TAG_ESIG);
    if (NULL == pSignature)
    {
        return INT_STATUS_INSUFFICIENT_RESOURCES;
    }

    pSignature->Id.Value = UpdateSignature->Id;
    pSignature->Flags = UpdateSignature->Flags;
    pSignature->Score = UpdateSignature->Score;
    pSignature->ListsCount = UpdateSignature->ListsCount;
    pSignature->AlertSignature = FALSE;

    // Now copy the hashes lists
    pHashList = (UPDATE_VALUE_HASH *)UpdateSignature->HashesList;
    pSigHash = (SIG_VALUE_HASH *)pSignature->Object;

    for (DWORD i = 0; i < UpdateSignature->ListsCount; i++)
    {
        pSigHash[i].Offset = pHashList[i].Offset;
        pSigHash[i].Size = pHashList[i].Size;
        pSigHash[i].Hash = pHashList[i].Hash;
    }

    InsertTailList(&gGuest.Exceptions->ValueSignatures, &pSignature->Link);

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntUpdateAddIdtSignature(
    _In_ UPDATE_IDT_SIGNATURE *UpdateSignature,
    _In_ UPDATE_ITEM_SIZE *Item
    )
///
/// @brief Creates a new IDT signature and adds it to our internal list.
///
/// @param[in] UpdateSignature  The data from the binary file.
/// @param[in] Item             The information about the current entry size and the file size.
///
/// @retval #INT_STATUS_SUCCESS                 On success.
/// @retval #INT_STATUS_NOT_NEEDED_HINT         If the the flags don't match the operation system.
/// @retval #INT_STATUS_INSUFFICIENT_RESOURCES  If not enough memory is available.
///
{
    SIG_IDT *pSignature;

    if (!IntUpdateIsValidEntry(sizeof(*UpdateSignature), Item, UPDATE_VALIDATE_ALL))
    {
        return INT_STATUS_INVALID_DATA_STATE;
    }

    if ((gGuest.OSType == introGuestWindows && (UpdateSignature->Flags & SIGNATURE_FLG_LINUX)) ||
        (gGuest.OSType == introGuestLinux && !(UpdateSignature->Flags & SIGNATURE_FLG_LINUX)))
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    pSignature = HpAllocWithTag(sizeof(*pSignature), IC_TAG_ESIG);
    if (NULL == pSignature)
    {
        return INT_STATUS_INSUFFICIENT_RESOURCES;
    }

    pSignature->Id.Value = UpdateSignature->Id;
    pSignature->Flags = UpdateSignature->Flags;
    pSignature->Entry = UpdateSignature->Entry;
    pSignature->AlertSignature = FALSE;

    InsertTailList(&gGuest.Exceptions->IdtSignatures, &pSignature->Link);

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntUpdateAddValueCodeSignature(
    _In_ UPDATE_VALUE_CODE_SIGNATURE *UpdateSignature,
    _In_ UPDATE_ITEM_SIZE *Item
    )
///
/// @brief Creates a new value-code signature and adds it to our internal list.
///
/// @param[in] UpdateSignature  The data from the binary file.
/// @param[in] Item             The information about the current entry size and the file size.
///
/// @retval #INT_STATUS_SUCCESS                 On success.
/// @retval #INT_STATUS_NOT_NEEDED_HINT         If the the flags don't match the operating system.
/// @retval #INT_STATUS_INSUFFICIENT_RESOURCES  If not enough memory is available.
///
{
    DWORD size;
    SIG_VALUE_CODE *pSignature;
    WORD *pUpdatePattern;
    WORD *pExceptionPattern;

    if (!IntUpdateIsValidEntry(sizeof(*UpdateSignature), Item, UPDATE_VALIDATE_FILE_SIZE))
    {
        return INT_STATUS_INVALID_DATA_STATE;
    }

    size = UpdateSignature->Length * sizeof(WORD);

    if (!IntUpdateIsValidEntry(sizeof(*UpdateSignature) + size, Item, UPDATE_VALIDATE_ALL))
    {
        return INT_STATUS_INVALID_DATA_STATE;
    }

    if ((gGuest.OSType == introGuestWindows && (UpdateSignature->Flags & SIGNATURE_FLG_LINUX)) ||
        (gGuest.OSType == introGuestLinux && !(UpdateSignature->Flags & SIGNATURE_FLG_LINUX)))
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    pSignature = HpAllocWithTag(sizeof(*pSignature) + size, IC_TAG_ESIG);
    if (NULL == pSignature)
    {
        return INT_STATUS_INSUFFICIENT_RESOURCES;
    }

    pSignature->Id.Value = UpdateSignature->Id;
    pSignature->Offset = UpdateSignature->Offset;
    pSignature->Flags = UpdateSignature->Flags;
    pSignature->Length = UpdateSignature->Length;
    pSignature->AlertSignature = FALSE;

    pUpdatePattern = &UpdateSignature->Pattern[0];
    pExceptionPattern = &pSignature->Object[0];

    // We have only one pattern for each signature
    for (DWORD i = 0; i < UpdateSignature->Length; i++)
    {
        pExceptionPattern[i] = pUpdatePattern[i];
    }

    InsertTailList(&gGuest.Exceptions->ValueCodeSignatures, &pSignature->Link);

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntUpdateAddVersionOsSignature(
    _In_ UPDATE_VERSION_OS_SIGNATURE *UpdateSignature,
    _In_ UPDATE_ITEM_SIZE *Item
    )
///
/// @brief Creates a new operating system version signature and adds it to our internal list.
///
/// @param[in] UpdateSignature  The data from the binary file.
/// @param[in] Item             The information about the current entry size and the file size.
///
/// @retval #INT_STATUS_SUCCESS                 On success.
/// @retval #INT_STATUS_NOT_NEEDED_HINT         If the the flags don't match the operating system.
/// @retval #INT_STATUS_INSUFFICIENT_RESOURCES  If not enough memory is available.
///
{
    if (!IntUpdateIsValidEntry(sizeof(*UpdateSignature), Item, UPDATE_VALIDATE_ALL))
    {
        return INT_STATUS_INVALID_DATA_STATE;
    }

    if ((gGuest.OSType == introGuestWindows && (UpdateSignature->Flags & SIGNATURE_FLG_LINUX)) ||
        (gGuest.OSType == introGuestLinux && !(UpdateSignature->Flags & SIGNATURE_FLG_LINUX)))
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    SIG_VERSION_OS *pSignature = HpAllocWithTag(sizeof(*pSignature), IC_TAG_ESIG);
    if (pSignature == NULL)
    {
        return INT_STATUS_INSUFFICIENT_RESOURCES;
    }

    pSignature->Id.Value = UpdateSignature->Id;
    pSignature->Flags = UpdateSignature->Flags;
    pSignature->AlertSignature = FALSE;
    pSignature->Minimum.Value = UpdateSignature->Minimum.Value;
    pSignature->Maximum.Value = UpdateSignature->Maximum.Value;

    InsertTailList(&gGuest.Exceptions->VersionOsSignatures, &pSignature->Link);

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntUpdateAddVersionIntroSignature(
    _In_ UPDATE_VERSION_INTRO_SIGNATURE *UpdateSignature,
    _In_ UPDATE_ITEM_SIZE *Item
    )
///
/// @brief Creates a new introspection version signature and adds it to our internal list.
///
/// @param[in] UpdateSignature  The data from the binary file.
/// @param[in] Item             The information about the current entry size and the file size.
///
/// @retval #INT_STATUS_SUCCESS                 On success.
/// @retval #INT_STATUS_NOT_NEEDED_HINT         If the the flags don't match the operating system.
/// @retval #INT_STATUS_INSUFFICIENT_RESOURCES  If not enough memory is available.
///
{
    if (!IntUpdateIsValidEntry(sizeof(*UpdateSignature), Item, UPDATE_VALIDATE_ALL))
    {
        return INT_STATUS_INVALID_DATA_STATE;
    }

    if ((gGuest.OSType == introGuestWindows && (UpdateSignature->Flags & SIGNATURE_FLG_LINUX)) ||
        (gGuest.OSType == introGuestLinux && !(UpdateSignature->Flags & SIGNATURE_FLG_LINUX)))
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    SIG_VERSION_INTRO *pSignature = HpAllocWithTag(sizeof(*pSignature), IC_TAG_ESIG);
    if (pSignature == NULL)
    {
        return INT_STATUS_INSUFFICIENT_RESOURCES;
    }

    pSignature->Id.Value = UpdateSignature->Id;
    pSignature->Flags = UpdateSignature->Flags;
    pSignature->AlertSignature = FALSE;
    pSignature->Minimum.Raw = UpdateSignature->Minimum.Raw;
    pSignature->Maximum.Raw = UpdateSignature->Maximum.Raw;

    InsertTailList(&gGuest.Exceptions->VersionIntroSignatures, &pSignature->Link);

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntUpdateAddExportSignature(
    _In_ UPDATE_EXPORT_SIGNATURE *UpdateSignature,
    _In_ UPDATE_ITEM_SIZE *Item
    )
///
/// @brief Creates a new export signature and adds it to our internal list.
///
/// @param[in] UpdateSignature  The data from the binary file.
/// @param[in] Item             The information about the current entry size and the file size.
///
/// @retval #INT_STATUS_SUCCESS                 On success.
/// @retval #INT_STATUS_NOT_NEEDED_HINT         If the the flags don't match the operating system.
/// @retval #INT_STATUS_INSUFFICIENT_RESOURCES  If not enough memory is available.
///
{
    if (!IntUpdateIsValidEntry(sizeof(*UpdateSignature), Item, UPDATE_VALIDATE_FILE_SIZE))
    {
        return INT_STATUS_INVALID_DATA_STATE;
    }

    DWORD size = UpdateSignature->ListsCount * sizeof(UPDATE_EXPORT_HASH);
    if (!IntUpdateIsValidEntry(sizeof(*UpdateSignature) + size, Item, UPDATE_VALIDATE_ALL))
    {
        return INT_STATUS_INVALID_DATA_STATE;
    }

    if ((gGuest.OSType == introGuestWindows && (UpdateSignature->Flags & SIGNATURE_FLG_LINUX)) ||
        (gGuest.OSType == introGuestLinux && !(UpdateSignature->Flags & SIGNATURE_FLG_LINUX)))
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    DWORD extraSize = UpdateSignature->ListsCount * sizeof(SIG_EXPORT_HASH);

    SIG_EXPORT *pSignature = HpAllocWithTag(sizeof(*pSignature) + extraSize, IC_TAG_ESIG);
    if (NULL == pSignature)
    {
        return INT_STATUS_INSUFFICIENT_RESOURCES;
    }

    pSignature->Id.Value = UpdateSignature->Id;
    pSignature->Flags = UpdateSignature->Flags;
    pSignature->LibraryNameHash = UpdateSignature->LibraryName;
    pSignature->ListsCount = UpdateSignature->ListsCount;
    pSignature->AlertSignature = FALSE;

    // Now copy the hashes lists
    UPDATE_EXPORT_HASH *pHashList = (UPDATE_EXPORT_HASH *)UpdateSignature->HashesList;
    SIG_EXPORT_HASH *pSigHash = (SIG_EXPORT_HASH *)pSignature->Object;

    for (DWORD i = 0; i < UpdateSignature->ListsCount; i++)
    {
        pSigHash[i].Hash = pHashList[i].Hash;
        pSigHash[i].Delta = pHashList[i].Delta;
    }

    InsertTailList(&gGuest.Exceptions->ExportSignatures, &pSignature->Link);

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntUpdateAddProcessCreationSignature(
    _In_ UPDATE_PROCESS_CREATION_SIGNATURE *UpdateSignature,
    _In_ UPDATE_ITEM_SIZE *Item
    )
///
/// @brief Creates a new process-creation signature and adds it to our internal list.
///
/// @param[in] UpdateSignature  The data from the binary file.
/// @param[in] Item             The information about the current entry size and the file size.
///
/// @retval #INT_STATUS_SUCCESS                 On success.
/// @retval #INT_STATUS_NOT_NEEDED_HINT         If the the flags don't match the operating system.
/// @retval #INT_STATUS_INSUFFICIENT_RESOURCES  If not enough memory is available.
///
{
    if (!IntUpdateIsValidEntry(sizeof(*UpdateSignature), Item, UPDATE_VALIDATE_ALL))
    {
        return INT_STATUS_INVALID_DATA_STATE;
    }

    if ((gGuest.OSType == introGuestWindows && (UpdateSignature->Flags & SIGNATURE_FLG_LINUX)) ||
        (gGuest.OSType == introGuestLinux && !(UpdateSignature->Flags & SIGNATURE_FLG_LINUX)))
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    SIG_PROCESS_CREATION *pSignature = HpAllocWithTag(sizeof(*pSignature), IC_TAG_ESIG);
    if (pSignature == NULL)
    {
        return INT_STATUS_INSUFFICIENT_RESOURCES;
    }

    pSignature->Id.Value = UpdateSignature->Id;
    pSignature->Flags = UpdateSignature->Flags;
    pSignature->AlertSignature = FALSE;
    pSignature->CreateMask = UpdateSignature->CreateMask;

    InsertTailList(&gGuest.Exceptions->ProcessCreationSignatures, &pSignature->Link);

    return INT_STATUS_SUCCESS;
}


static void
IntUpdateSetIdForException(
    _In_ EXCEPTION_SIGNATURE_ID *Signatures,
    _In_ DWORD Count
    )
///
/// @brief Generate a new ID for each signature.
///
/// This function is used when the new binary exceptions is loaded. The exceptions that were added from alert are not
/// removed when a new binary exceptions is loaded and we must reassign the IDs for these signatures.
///
/// @param[in] Signatures   The list of exceptions' signatures.
/// @param[in] Count        The number of the signatures.
///
{
    for (DWORD i = 0; i < Count; i++)
    {
        switch (Signatures[i].Field.Type)
        {
        case signatureTypeExport :
        {
            for_each_export_signature(gGuest.Exceptions->ExportSignatures, pSignature)
            {
                if (pSignature->AlertSignature && pSignature->Id.Value == Signatures[i].Value)
                {
                    pSignature->Id = IntUpdateGetUniqueSigId(pSignature->Id.Field.Type);
                    Signatures[i] = pSignature->Id;

                    break;
                }
            }

            break;
        }

        case signatureTypeCodeBlocks:
        {
            for_each_cb_signature(gGuest.Exceptions->CbSignatures, pSignature)
            {
                if (pSignature->AlertSignature && pSignature->Id.Value == Signatures[i].Value)
                {
                    pSignature->Id = IntUpdateGetUniqueSigId(pSignature->Id.Field.Type);
                    Signatures[i] = pSignature->Id;

                    break;
                }
            }

            break;
        }

        case signatureTypeIdt:
        {
            for_each_idt_signature(gGuest.Exceptions->IdtSignatures, pSignature)
            {
                if (pSignature->AlertSignature && pSignature->Id.Value == Signatures[i].Value)
                {
                    pSignature->Id = IntUpdateGetUniqueSigId(pSignature->Id.Field.Type);
                    Signatures[i] = pSignature->Id;

                    break;
                }
            }

            break;
        }

        default:
        {
            ERROR("[ERROR] Should not reach here. Type is '%d'n", Signatures[i].Field.Type);
            return;
        }
        }
    }
}


void
IntUpdateAssignAlertSignatureIds(
    void
    )
///
/// @brief Generates IDs for exceptions that were added from alert.
///
{
    for_each_um_exception(gGuest.Exceptions->UserAlertExceptions, pException)
    {
        IntUpdateSetIdForException(pException->Signatures, pException->SigCount);
    }

    for_each_km_exception(gGuest.Exceptions->KernelAlertExceptions, pException)
    {
        IntUpdateSetIdForException(pException->Signatures, pException->SigCount);
    }

    for_each_um_exception(gGuest.Exceptions->ProcessCreationAlertExceptions, pException)
    {
        IntUpdateSetIdForException(pException->Signatures, pException->SigCount);
    }
}


INTSTATUS
IntUpdateLoadExceptions(
    _In_ void *Buffer,
    _In_ DWORD Length,
    _In_ DWORD Flags
    )
///
/// @brief Handles the exceptions coming from the integrator.
///
/// This function removes the existing exceptions that were not added from alert, then it parse the entire provided
/// buffer and calls the appropriate function that adds a specific type of exception or signature.
///
/// @param[in] Buffer   The exceptions buffer.
/// @param[in] Length   The length of the exceptions buffer.
/// @param[in] Flags    Unused.
///
/// @retval #INT_STATUS_SUCCESS         On success.
/// @retval #INT_STATUS_NOT_SUPPORTED   If the exceptions buffer is corrupted or the version of the exceptions is not
///                                     supported.
///
{
    INTSTATUS status;
    BYTE *address;
    UPDATE_FILE_HEADER *fileHeader;

    UNREFERENCED_PARAMETER(Flags);

    if (NULL == Buffer)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (Length <= sizeof(UPDATE_FILE_HEADER))
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    address = Buffer;
    fileHeader = Buffer;

    LOG("[UPDATE] Requested to update the intro exceptions...\n");

    if (fileHeader->Magic != UPDATE_MAGIC_WORD)
    {
        ERROR("[ERROR] Exception file header doesn't have the right magic word (%c%c%c%c)\n",
              (fileHeader->Magic & 0xff000000) >> 24, (fileHeader->Magic & 0xff0000) >> 16,
              (fileHeader->Magic & 0xff00) >> 8, fileHeader->Magic & 0xff);

        return INT_STATUS_INVALID_OBJECT_TYPE;
    }

    if (fileHeader->Version.Major != UPDATE_EXCEPTIONS_MIN_VER_MAJOR)
    {
        ERROR("[ERROR] Update's file major (%d.%d) version is different form ours (%d.%d)\n",
              fileHeader->Version.Major, fileHeader->Version.Minor, UPDATE_EXCEPTIONS_MIN_VER_MAJOR,
              UPDATE_EXCEPTIONS_MIN_VER_MINOR);

        return INT_STATUS_NOT_SUPPORTED;
    }

    if (fileHeader->Version.Minor > UPDATE_EXCEPTIONS_MIN_VER_MINOR)
    {
        WARNING("[WARNING] Update's file minor (%d.%d) version is newer than ours (%d.%d). "
                "Not all features will be available!\n", fileHeader->Version.Major, fileHeader->Version.Minor,
                UPDATE_EXCEPTIONS_MIN_VER_MAJOR, UPDATE_EXCEPTIONS_MIN_VER_MINOR);
    }
    else if (fileHeader->Version.Minor < UPDATE_EXCEPTIONS_MIN_VER_MINOR)
    {
        ERROR("[ERROR] Update's file minor (%d.%d) version is older than ours (%d.%d). "
              "Will not update the exceptions.\n", fileHeader->Version.Major, fileHeader->Version.Minor,
              UPDATE_EXCEPTIONS_MIN_VER_MAJOR, UPDATE_EXCEPTIONS_MIN_VER_MINOR);

        return INT_STATUS_NOT_SUPPORTED;
    }

    if (fileHeader->KernelExceptionsCount == 0 &&
        fileHeader->UserExceptionsCount == 0 &&
        fileHeader->KernelUserExceptionsCount == 0 &&
        fileHeader->UserExceptionsGlobCount == 0)
    {
        WARNING("[WARNING] Requested update with 0 kernel exceptions and 0 user exceptions. We cannot do that...\n");

        return INT_STATUS_INVALID_OBJECT_TYPE;
    }

    if (NULL == gGuest.Exceptions)
    {
        return INT_STATUS_INVALID_INTERNAL_STATE;
    }

    status = IntExceptRemove();
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntExceptRemove failed: 0x%08x\n", status);
        return status;
    }

    // Reset the last signature ID (will be updated again when adding signatures)
    gCurrentSignatureId.Field.Value = BIT(22) / 2;

    // skip over the file header
    address += sizeof(UPDATE_FILE_HEADER);

    while (address < (PBYTE)(size_t)Buffer + Length)
    {
        if ((QWORD)(address + sizeof(UPDATE_HEADER)) > ((QWORD)Buffer + Length))
        {
            ERROR("[ERROR] The address of 'UPDATE_HEADER' structure exceeds the exception buffer "
                  "(0x%016llx/0x%016llx)\n", (QWORD)(address + sizeof(UPDATE_HEADER)), ((QWORD)Buffer + Length));
            return INT_STATUS_INVALID_DATA_SIZE;
        }

        UPDATE_HEADER *header = (UPDATE_HEADER *)address;
        PBYTE structure = address + sizeof(UPDATE_HEADER);
        UPDATE_ITEM_SIZE item = { 0 };

        item.EntrySize = header->Size;
        item.RemainingFileSize = (DWORD)((QWORD)((QWORD)(Buffer) + Length) - (QWORD)structure);

        address += sizeof(UPDATE_HEADER) + header->Size;

        switch (header->Type)
        {
        case UPDATE_TYPE_KM_EXCEPTION:
            status = IntUpdateAddKernelException((UPDATE_KM_EXCEPTION *)structure, &item);
            break;

        case UPDATE_TYPE_UM_EXCEPTION:
            status = IntUpdateAddUserException((UPDATE_UM_EXCEPTION *)structure, &item);
            break;

        case UPDATE_TYPE_UM_EXCEPTION_GLOB_MATCH:
            status = IntUpdateAddUserExceptionGlob((UPDATE_UM_EXCEPTION_GLOB *)structure, &item);
            break;

        case UPDATE_TYPE_CB_SIGNATURE:
            status = IntUpdateAddCbSignature((UPDATE_CB_SIGNATURE *)structure, &item);
            break;

        case UPDATE_TYPE_EXPORT_SIGNATURE:
            status = IntUpdateAddExportSignature((UPDATE_EXPORT_SIGNATURE *)structure, &item);
            break;

        case UPDATE_TYPE_VALUE_SIGNATURE:
            status = IntUpdateAddValueSignature((UPDATE_VALUE_SIGNATURE *)structure, &item);
            break;

        case UPDATE_TYPE_VALUE_CODE_SIGNATURE:
            status = IntUpdateAddValueCodeSignature((UPDATE_VALUE_CODE_SIGNATURE *)structure, &item);
            break;

        case UPDATE_TYPE_IDT_SIGNATURE:
            status = IntUpdateAddIdtSignature((UPDATE_IDT_SIGNATURE *)structure, &item);
            break;

        case UPDATE_TYPE_VERSION_OS_SIGNATURE:
            status = IntUpdateAddVersionOsSignature((UPDATE_VERSION_OS_SIGNATURE *)structure, &item);
            break;

        case UPDATE_TYPE_VERSION_INTRO_SIGNATURE:
            status = IntUpdateAddVersionIntroSignature((UPDATE_VERSION_INTRO_SIGNATURE *)structure, &item);
            break;

        case UPDATE_TYPE_APC_UM_EXCEPTION:
            status = IntUpdateAddUserException((UPDATE_UM_EXCEPTION *)structure, &item);
            break;

        case UPDATE_TYPE_PROCESS_CREATION_SIGNATURE:
            status = IntUpdateAddProcessCreationSignature((UPDATE_PROCESS_CREATION_SIGNATURE *)structure, &item);
            break;

        case UPDATE_TYPE_KUM_EXCEPTION:
            status = IntUpdateAddKernelUserException((UPDATE_KUM_EXCEPTION *)structure, &item);
            break;

        default:
            // For future versions: ignore unknown types
            WARNING("[WARNING] Unknown exception/signature type '%d'. Will ignore ...\n", header->Type);
            status = INT_STATUS_NOT_NEEDED_HINT;
            break;
        }

        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] Failed adding exception/signature. Will abort the update. Reason=0x%08x\n", status);
            return status;
        }
    }

    IntUpdateAssignAlertSignatureIds();

    gGuest.Exceptions->Version.Build = fileHeader->BuildNumber;
    gGuest.Exceptions->Version.Major = fileHeader->Version.Major;
    gGuest.Exceptions->Version.Minor = fileHeader->Version.Minor;

    gGuest.Exceptions->Loaded = TRUE;

    LOG("[UPDATE] Updated exceptions to version %d.%d.%d\n",
        fileHeader->Version.Major, fileHeader->Version.Minor, fileHeader->BuildNumber);

    return INT_STATUS_SUCCESS;
}


static void
IntUpdateAddUserExceptionInOrder(
    _In_ UM_EXCEPTION *Exception
    )
///
/// @brief Adds a user-mode exceptions from alert in the sorted list.
///
/// The exception is added to the list that contains process-creation alert-exceptions list if the object type is
/// #umObjProcessCreation, otherwise it is added to the user-mode alert-exceptions list.
///
/// @param[in] Exception    The user-mode exception structure.
///
{
    LIST_HEAD *head;

    TRACE("[UPDATE] Add exception %08x -> %08x, %08x, %d, %08x\n",
          Exception->OriginatorNameHash, Exception->Victim.ProcessHash, Exception->Victim.NameHash,
          Exception->Type, Exception->Flags);

    if (Exception->SigCount == 1)
    {
        TRACE("[UPDATE] sig: 0x%08x\n", Exception->Signatures[0].Value);
    }
    else if (Exception->SigCount > 0)
    {
        TRACE("[UPDATE] sig: %d signatures\n", Exception->SigCount);
    }

    if (Exception->Type == umObjProcessCreation)
    {
        head = &gGuest.Exceptions->ProcessCreationAlertExceptions;
    }
    else
    {
        head = &gGuest.Exceptions->UserAlertExceptions;
    }

    for_each_um_exception((*head), pEx)
    {
        // Every list is ordered, so break when we got to a hash bigger than ours
        if (pEx->OriginatorNameHash > Exception->OriginatorNameHash)
        {
            pEx = CONTAINING_RECORD(pEx->Link.Blink, UM_EXCEPTION, Link);

            InsertAfterList(&pEx->Link, &Exception->Link);

            return;
        }
    }

    // We didn't found an exception that has a hash bigger than ours. Insert at the end of the list!
    InsertTailList(head, &Exception->Link);
}


static void
IntUpdateAddKernelExceptionInOrder(
    _In_ KM_EXCEPTION *Exception
    )
///
/// @brief Adds a kernel-mode exceptions from alert in the sorted list.
///
/// The exception is added to the user-mode alert-exceptions list.
///
/// @param[in] Exception   The kernel-mode exception structure.
///
{
    TRACE("[UPDATE] Add exception %08x -> %08x, %d, %08x\n",
          Exception->OriginatorNameHash, Exception->VictimNameHash,
          Exception->Type, Exception->Flags);

    if (Exception->SigCount == 1)
    {
        TRACE("[UPDATE] sig: %d\n", Exception->Signatures[0].Value);
    }
    else if (Exception->SigCount > 0)
    {
        TRACE("[UPDATE] sig: %d signatures\n", Exception->SigCount);
    }

    for_each_km_exception(gGuest.Exceptions->KernelAlertExceptions, pEx)
    {
        // Every list is ordered, so break when we got to a hash bigger than ours
        if (pEx->OriginatorNameHash > Exception->OriginatorNameHash)
        {
            pEx = CONTAINING_RECORD(pEx->Link.Blink, KM_EXCEPTION, Link);

            InsertAfterList(&pEx->Link, &Exception->Link);

            return;
        }
    }

    // We didn't found an exception that has a hash bigger than ours. Insert at the end of the list!
    InsertTailList(&gGuest.Exceptions->KernelAlertExceptions, &Exception->Link);
}


static void
IntUpdateAddKernelUserExceptionInOrder(
    _In_ KUM_EXCEPTION *Exception
    )
///
/// @brief Adds a kernel-user mode exceptions from alert in the sorted list.
///
/// The exception is added to the user-mode alert-exceptions list.
///
/// @param[in] Exception   The kernel-mode exception structure.
///
{
    TRACE("[UPDATE] Add exception %08x -> %08x %08x, %d, %08x\n",
          Exception->Originator.NameHash, Exception->Victim.NameHash, Exception->Victim.ProcessHash,
          Exception->Type, Exception->Flags);

    TRACE("[UPDATE] Signatures = %d \n", Exception->SigCount);

    for_each_kum_exception(gGuest.Exceptions->KernelUserAlertExceptions, pEx)
    {
        // Every list is ordered, so break when we got to a hash bigger than ours
        if (pEx->Originator.NameHash > Exception->Originator.NameHash)
        {
            pEx = CONTAINING_RECORD(pEx->Link.Blink, KUM_EXCEPTION, Link);

            InsertAfterList(&pEx->Link, &Exception->Link);

            return;
        }
    }

    // We didn't found an exception that has a hash bigger than ours. Insert at the end of the list!
    InsertTailList(&gGuest.Exceptions->KernelUserAlertExceptions, &Exception->Link);
}


static INTSTATUS
IntUpdateCreateExportSignatureFromAlert(
    _In_ const ALERT_EXPORT_SIGNATURE *AlertSig,
    _Out_ SIG_EXPORT **Signature
    )
///
/// @brief Creates a new export signature from an #ALERT_EXPORT_SIGNATURE.
///
/// @param[in]  AlertSig    The signature created form an alert.
/// @param[out] Signature   The newly created signature.
///
/// @retval #INT_STATUS_SUCCESS                 On success.
/// @retval #INT_STATUS_UNSUPPORTED_DATA_VALUE  If the alert-signature's version is different than our internal version.
/// @retval #INT_STATUS_INSUFFICIENT_RESOURCES  If not enough memory is available.
///
{
    if (AlertSig->Header.Version != ALERT_EXPORT_SIGNATURE_VERSION)
    {
        ERROR("[ERROR] Unsupported export signature version: %d. We have %d\n",
              AlertSig->Header.Version, ALERT_EXPORT_SIGNATURE_VERSION);
        return INT_STATUS_UNSUPPORTED_DATA_VALUE;
    }

    SIG_EXPORT *pSig = HpAllocWithTag(sizeof(*pSig) + sizeof(SIG_EXPORT_HASH), IC_TAG_ESIG);
    if (NULL == pSig)
    {
        return INT_STATUS_INSUFFICIENT_RESOURCES;
    }

    pSig->Id = IntUpdateGetUniqueSigId(signatureTypeExport);
    pSig->LibraryNameHash = AlertSig->Library;
    pSig->Flags = AlertSig->Flags;
    pSig->ListsCount = 1;
    pSig->AlertSignature = TRUE;

    SIG_EXPORT_HASH *pSigHash = (SIG_EXPORT_HASH *)pSig->Object;

    pSigHash->Hash = AlertSig->Function;
    pSigHash->Delta = (WORD)(AlertSig->Delta + AlertSig->WriteSize);

    TRACE("[INFO] Add Export signature on 0x%08x (0x%08x) with delta %d\n",
          AlertSig->Function, AlertSig->Library, pSigHash->Delta);

    *Signature = pSig;

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntUpdateCreateIdtSignatureFromAlert(
    _In_ const ALERT_IDT_SIGNATURE *AlertSig,
    _Out_ SIG_IDT **Signature
    )
///
/// @brief Creates a new IDT signature from an /ref ALERT_IDT_SIGNATURE.
///
/// @param[in]  AlertSig    The signature created form an alert.
/// @param[out] Signature   The newly created signature.
///
/// @retval #INT_STATUS_SUCCESS                 On success.
/// @retval #INT_STATUS_UNSUPPORTED_DATA_VALUE  If the alert-signature's version is different than our internal version.
/// @retval #INT_STATUS_INSUFFICIENT_RESOURCES  If not enough memory is available.
///

{
    if (AlertSig->Header.Version != ALERT_IDT_SIGNATURE_VERSION)
    {
        ERROR("[ERROR] Unsupported idt signature version: %d. We have %d\n",
              AlertSig->Header.Version, ALERT_IDT_SIGNATURE_VERSION);
        return INT_STATUS_UNSUPPORTED_DATA_VALUE;
    }

    SIG_IDT *pSignature = HpAllocWithTag(sizeof(*pSignature), IC_TAG_ESIG);
    if (NULL == pSignature)
    {
        return INT_STATUS_INSUFFICIENT_RESOURCES;
    }

    pSignature->Id = IntUpdateGetUniqueSigId(signatureTypeIdt);
    pSignature->Entry = AlertSig->Entry;
    pSignature->Flags = AlertSig->Flags;
    pSignature->AlertSignature = TRUE;

    TRACE("[INFO] Add Idt Signature on %d entry.", pSignature->Entry);

    *Signature = pSignature;

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntUpdateCreateCbSignatureFromAlert(
    _In_ const ALERT_CB_SIGNATURE *AlertSig,
    _Out_ SIG_CODEBLOCKS **Signature
    )
///
/// @brief Creates a new code-blocks signature from an /ref ALERT_CB_SIGNATURE.
///
/// @param[in]  AlertSig    The signature created form an alert.
/// @param[out] Signature   The newly created signature.
///
/// @retval #INT_STATUS_SUCCESS                 On success.
/// @retval #INT_STATUS_UNSUPPORTED_DATA_VALUE  If the alert-signature's version is different than our internal version.
/// @retval #INT_STATUS_INSUFFICIENT_RESOURCES  If not enough memory is available.
///

{
    if (AlertSig->Header.Version != ALERT_CB_SIGNATURE_VERSION)
    {
        WARNING("[WARNING] Unsupported cb signature version: %d. We have %d\n",
                AlertSig->Header.Version, ALERT_CB_SIGNATURE_VERSION);
        return INT_STATUS_UNSUPPORTED_DATA_VALUE;
    }

    if (AlertSig->Count > ALERT_HASH_COUNT)
    {
        return INT_STATUS_INVALID_DATA_SIZE;
    }

    SIG_CODEBLOCKS *pSignature;
    SIG_CODEBLOCK_HASH *pSigHash;

    DWORD totalSize = sizeof(*pSignature) + sizeof(*pSigHash) + AlertSig->Count * sizeof(DWORD);

    pSignature = HpAllocWithTag(totalSize, IC_TAG_ESIG);
    if (NULL == pSignature)
    {
        return INT_STATUS_INSUFFICIENT_RESOURCES;
    }

    pSignature->Id = IntUpdateGetUniqueSigId(signatureTypeCodeBlocks);

    pSignature->Score = AlertSig->Score;
    pSignature->ListsCount = 1;
    pSignature->AlertSignature = TRUE;
    pSignature->Flags = AlertSig->Flags;

    pSigHash = (SIG_CODEBLOCK_HASH *)pSignature->Object;

    pSigHash->Count = AlertSig->Count;
    for (DWORD i = 0; i < pSigHash->Count; i++)
    {
        pSigHash->Hashes[i] = AlertSig->CodeBlocks[i];
    }

    // The code blocks are already sorted (see IntAlertCreateCbSignature), but considering that the exception buffer is
    // an external data, we should sort them again.
    UtilQuickSort(pSigHash->Hashes, pSigHash->Count, sizeof(pSigHash->Hashes[0]));

    *Signature = pSignature;

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntUpdateCreateProcessCreationSignatureFromAlert(
    _In_ const ALERT_PROCESS_CREATION_SIGNATURE *AlertSig,
    _Out_ SIG_PROCESS_CREATION **Signature
    )
///
/// @brief Creates a new process-creation signature from an /ref ALERT_PROCESS_CREATION_SIGNATURE.
///
/// @param[in]  AlertSig    The signature created form an alert.
/// @param[out] Signature   The newly created signature.
///
/// @retval #INT_STATUS_SUCCESS                 On success.
/// @retval #INT_STATUS_UNSUPPORTED_DATA_VALUE  If the alert-signature's version is different than our internal version.
/// @retval #INT_STATUS_INSUFFICIENT_RESOURCES  If not enough memory is available.
///
{
    if (AlertSig->Header.Version != ALERT_PROCESS_CREATION_SIGNATURE_VERSION)
    {
        ERROR("[ERROR] Unsupported process-creation signature version: %d. We have %d\n",
              AlertSig->Header.Version, ALERT_PROCESS_CREATION_SIGNATURE_VERSION);
        return INT_STATUS_UNSUPPORTED_DATA_VALUE;
    }

    SIG_PROCESS_CREATION *pSignature;

    pSignature = HpAllocWithTag(sizeof(SIG_PROCESS_CREATION), IC_TAG_ESIG);
    if (NULL == pSignature)
    {
        return INT_STATUS_INSUFFICIENT_RESOURCES;
    }

    pSignature->Id = IntUpdateGetUniqueSigId(signatureTypeProcessCreation);

    pSignature->AlertSignature = TRUE;
    pSignature->Flags = AlertSig->Flags;
    pSignature->CreateMask = AlertSig->CreateMask;

    *Signature = pSignature;

    return INT_STATUS_SUCCESS;
}


__nonnull() static BOOLEAN
IntUpdateIsDuplicateCbSignature(
    _In_ const ALERT_CB_SIGNATURE *Signature,
    _In_ const EXCEPTION_SIGNATURE_ID *SigIds,
    _In_ DWORD SigCount
    )
///
/// @brief Checks if the provided code-blocks alert-signature already exists in our list.
///
/// @param[in] Signature    The signature that must be verified if already exists.
/// @param[in] SigIds       An array of signature IDs.
/// @param[in] SigCount     The number of signatures.
///
/// @retval True if the signature already exists; otherwise false.
///
{
    if (!Signature->Valid)
    {
        return FALSE;
    }

    for_each_cb_signature(gGuest.Exceptions->CbSignatures, pSig)
    {
        DWORD sigSize = 0;

        for (DWORD i = 0; i < SigCount; i++)
        {
            if (pSig->Id.Value != SigIds[i].Value)
            {
                continue;
            }

            for (DWORD j = 0; j < pSig->ListsCount; j++)
            {
                const SIG_CODEBLOCK_HASH *pHash = (const SIG_CODEBLOCK_HASH *)(pSig->Object + sigSize);
                sigSize += pHash->Count * sizeof(DWORD) + sizeof(*pHash);

                if (pHash->Count != Signature->Count)
                {
                    continue;
                }

                if (0 == memcmp(pHash->Hashes, Signature->CodeBlocks, sizeof(DWORD) * pHash->Count))
                {
                    return TRUE;
                }
            }
        }
    }

    return FALSE;
}


static BOOLEAN
IntUpdateIsDuplicateIdtSignature(
    _In_ const ALERT_IDT_SIGNATURE *Signature,
    _In_ const EXCEPTION_SIGNATURE_ID *SigIds,
    _In_ DWORD SigCount
    )
///
/// @brief Checks if the provided IDT alert-signature already exists in our list.
///
/// @param[in] Signature    The signature that must be verified if already exists.
/// @param[in] SigIds       An array of signature IDs.
/// @param[in] SigCount     The number of signatures.
///
/// @retval True if the signature already exists; otherwise false.
///
{
    if (!Signature->Valid)
    {
        return FALSE;
    }

    for_each_idt_signature(gGuest.Exceptions->IdtSignatures, pSignature)
    {
        for (DWORD iSig = 0; iSig < SigCount; iSig++)
        {
            if (pSignature->Id.Value != SigIds[iSig].Value)
            {
                continue;
            }

            if (Signature->Entry == pSignature->Entry)
            {
                return TRUE;
            }
        }
    }

    return FALSE;
}


static BOOLEAN
IntUpdateIsDuplicateExportSignature(
    _In_ const ALERT_EXPORT_SIGNATURE *Signature,
    _In_ const EXCEPTION_SIGNATURE_ID *SigIds,
    _In_ DWORD SigCount
    )
///
/// @brief Checks if the provided export alert-signature already exists in our list.
///
/// @param[in] Signature    The signature that must be verified if already exists
/// @param[in] SigIds       An array of signature IDs.
/// @param[in] SigCount     The number of signatures.
///
/// @retval True if the signature already exists; otherwise false.
///
{
    if (!Signature->Valid)
    {
        return FALSE;
    }

    for (DWORD i = 0; i < SigCount; i++)
    {
        for_each_export_signature(gGuest.Exceptions->ExportSignatures, pSig)
        {
            SIG_EXPORT_HASH *pSigHash = (SIG_EXPORT_HASH *)pSig->Object;

            if (pSig->Id.Value != SigIds[i].Value)
            {
                continue;
            }

            if (pSig->LibraryNameHash != Signature->Library)
            {
                continue;
            }

            for (DWORD j = 0; j < pSig->ListsCount; j++)
            {
                if (pSigHash[j].Hash == Signature->Function && pSigHash[j].Delta >= Signature->Delta)
                {
                    return TRUE;
                }
            }
        }
    }

    return FALSE;
}


static BOOLEAN
IntUpdateIsDuplicateKernelException(
    _In_ const ALERT_KM_EXCEPTION *Exception
    )
///
/// @brief Checks if the provided kernel-mode exception already exists in out list.
///
/// This function also verify if there exists another exception with same signatures.
///
/// @param[in] Exception    The exception that must be verified if already exists.
///
/// @retval True if the exception already exists; otherwise false.
///
{
    for_each_km_exception(gGuest.Exceptions->KernelAlertExceptions, pEx)
    {
        if (Exception->Originator == pEx->OriginatorNameHash &&
            Exception->Victim == pEx->VictimNameHash &&
            Exception->Flags == pEx->Flags &&
            Exception->Type == pEx->Type)
        {
            if (pEx->SigCount != 0)
            {
                BOOLEAN isCbDuplicate = FALSE;
                BOOLEAN isIdtDuplicate = FALSE;

                if (IntUpdateIsDuplicateCbSignature(&Exception->CodeBlocks, pEx->Signatures, pEx->SigCount))
                {
                    isCbDuplicate = TRUE;
                }

                if (IntUpdateIsDuplicateIdtSignature(&Exception->Idt, pEx->Signatures, pEx->SigCount))
                {
                    isIdtDuplicate = TRUE;
                }

                if ((isIdtDuplicate && isCbDuplicate) ||
                    (isCbDuplicate && !Exception->Idt.Valid) ||
                    (isIdtDuplicate && !Exception->CodeBlocks.Valid))
                {
                    TRACE("[UPDATE] Ignoring duplicate exception with signature: %08x -> %08x, %d, %08x\n",
                          pEx->OriginatorNameHash, pEx->VictimNameHash, pEx->Type, pEx->Flags);

                    return TRUE;
                }
            }
            else if (!Exception->CodeBlocks.Valid && !Exception->Idt.Valid)
            {
                // We didn't give a signature, nor we have one in the current exception
                TRACE("[UPDATE] Ignoring duplicate exception: %08x -> %08x, %d, %08x\n",
                      pEx->OriginatorNameHash, pEx->VictimNameHash, pEx->Type, pEx->Flags);

                return TRUE;
            }
        }

        // Every list is ordered, so break when we got to a hash bigger than ours
        if (pEx->OriginatorNameHash > Exception->Originator)
        {
            break;
        }
    }

    return FALSE;
}

static BOOLEAN
IntUpdateIsDuplicateKernelUserException(
    _In_ const ALERT_KUM_EXCEPTION *Exception
    )
///
/// @brief Checks if the provided kernel-user mode exception already exists in out list.
///
/// This function also verify if there exists another exception with same signatures.
///
/// @param[in] Exception    The exception that must be verified if already exists.
///
/// @retval True if the exception already exists; otherwise false.
///
{
    for_each_kum_exception(gGuest.Exceptions->KernelUserAlertExceptions, pEx)
    {
        if (Exception->Originator == pEx->Originator.NameHash &&
            Exception->Victim == pEx->Victim.NameHash &&
            Exception->Process == pEx->Victim.ProcessHash &&
            Exception->Flags == pEx->Flags &&
            Exception->Type == pEx->Type)
        {
            if (pEx->SigCount != 0)
            {
                if (IntUpdateIsDuplicateCbSignature(&Exception->CodeBlocks, pEx->Signatures, pEx->SigCount))
                {
                    TRACE("[UPDATE] Ignoring duplicate exception with signature: %08x -> %08x - %08x, %d, %08x\n",
                          pEx->Originator.NameHash, pEx->Victim.NameHash, pEx->Victim.ProcessHash, pEx->Type, pEx->Flags);

                    return TRUE;
                }
            }
            else if (!Exception->CodeBlocks.Valid)
            {
                // We didn't give a signature, nor we have one in the current exception
                TRACE("[UPDATE] Ignoring duplicate exception: %08x -> %08x %08x, %d, %08x\n",
                      pEx->Originator.NameHash, pEx->Victim.NameHash, pEx->Victim.ProcessHash, pEx->Type, pEx->Flags);
                return TRUE;
            }
        }

        // Every list is ordered, so break when we got to a hash bigger than ours
        if (pEx->Originator.NameHash > Exception->Originator)
        {
            break;
        }
    }

    return FALSE;
}


static BOOLEAN
IntUpdateIsDuplicateUserException(
    _In_ const ALERT_UM_EXCEPTION *Exception
    )
///
/// @brief Checks if the provided user-mode exception already exists in out list.
///
/// This function also verify if exists another exception with same signatures.
///
/// @param[in] Exception    The exception that must be verified if already exists.
///
/// @retval True if the exception already exists; otherwise false.
///
{
    LIST_HEAD *head;

    if (Exception->Type == umObjProcessCreation)
    {
        head = &gGuest.Exceptions->ProcessCreationAlertExceptions;
    }
    else
    {
        head = &gGuest.Exceptions->UserAlertExceptions;
    }

    for_each_um_exception((*head), pEx)
    {
        if (Exception->Originator == pEx->OriginatorNameHash &&
            Exception->Victim == pEx->Victim.NameHash &&
            Exception->Process == pEx->Victim.ProcessHash &&
            Exception->Type == pEx->Type)
        {
            if (pEx->SigCount != 0)
            {
                BOOLEAN isCbDuplicate = FALSE;
                BOOLEAN isExportDuplicate = FALSE;

                if (IntUpdateIsDuplicateCbSignature(&Exception->CodeBlocks, pEx->Signatures, pEx->SigCount))
                {
                    isCbDuplicate = TRUE;
                }

                if (IntUpdateIsDuplicateExportSignature(&Exception->Export, pEx->Signatures, pEx->SigCount))
                {
                    isExportDuplicate = TRUE;
                }

                if ((isExportDuplicate && isCbDuplicate) ||
                    (isCbDuplicate && !Exception->Export.Valid) ||
                    (isExportDuplicate && !Exception->CodeBlocks.Valid))
                {
                    TRACE("[UPDATE] Ignoring duplicate exception with signature: %08x -> %08x, %08x, %d, %08x\n",
                          pEx->OriginatorNameHash, pEx->Victim.ProcessHash,
                          pEx->Victim.NameHash, pEx->Type, pEx->Flags);

                    return TRUE;
                }
            }
            else if (!Exception->CodeBlocks.Valid && !Exception->Export.Valid)
            {
                // We didn't give a signature, nor we have one in the current exception
                TRACE("[UPDATE] Ignoring duplicate exception: %08x -> %08x, %08x, %d, %08x\n",
                      pEx->OriginatorNameHash, pEx->Victim.ProcessHash, pEx->Victim.NameHash,
                      pEx->Type, pEx->Flags);

                return TRUE;
            }
        }

        // Every list is ordered, so break when we got to a hash bigger than ours
        if (pEx->OriginatorNameHash > Exception->Originator)
        {
            break;
        }
    }

    return FALSE;
}


static INTSTATUS
IntUpdateAddUmException(
    _In_ const ALERT_UM_EXCEPTION *Exception,
    _In_ QWORD Context
    )
///
/// @brief Creates a new user-mode exception from an alert-exception structure #ALERT_UM_EXCEPTION and adds it to our
/// internal list.
///
/// This function also creates code-blocks, export or process-creation signatures, if any, and adds them to the
/// corresponding list of alert exceptions/signatures.
///
/// @param[in] Exception    The structure of the alert-exception.
/// @param[in] Context      The context provided by integrator.
///
/// @retval #INT_STATUS_SUCCESS                 On success.
/// @retval #INT_STATUS_NOT_NEEDED_HINT         If the exception already exists.
/// @retval #INT_STATUS_UNSUPPORTED_DATA_VALUE  If the alert-signature's version is different than our internal version.
/// @retval #INT_STATUS_INSUFFICIENT_RESOURCES  If not enough memory is available.
///
{
    INTSTATUS status;
    DWORD sigCount = (Exception->CodeBlocks.Valid != 0) +
                     (Exception->Export.Valid != 0) + (Exception->ProcessCreation.Valid);
    SIG_EXPORT *pExpSignature = NULL;
    SIG_CODEBLOCKS *pCbSignature = NULL;
    SIG_PROCESS_CREATION *pProcessCreationSignature = NULL;

    if (Exception->Header.Version != ALERT_UM_EXCEPTION_VERSION)
    {
        ERROR("[ERROR] Unsupported um exception version: %d. We have %d\n",
              Exception->Header.Version, ALERT_UM_EXCEPTION_VERSION);
        return INT_STATUS_UNSUPPORTED_DATA_VALUE;
    }

    if (IntUpdateIsDuplicateUserException(Exception))
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    UM_EXCEPTION *pUmException = HpAllocWithTag(sizeof(*pUmException) + sigCount * sizeof(DWORD), IC_TAG_EXUM);
    if (NULL == pUmException)
    {
        return INT_STATUS_INSUFFICIENT_RESOURCES;
    }

    pUmException->Context = Context;

    pUmException->OriginatorNameHash = Exception->Originator;
    pUmException->Victim.NameHash = Exception->Victim;
    pUmException->Victim.ProcessHash = Exception->Process;
    pUmException->Flags = Exception->Flags;
    pUmException->Type = Exception->Type;

    if (Exception->CodeBlocks.Valid)
    {
        status = IntUpdateCreateCbSignatureFromAlert(&Exception->CodeBlocks, &pCbSignature);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntUpdateCreateCbSignatureFromAlert failed with status: 0x%08x\n", status);
            goto _exit;
        }
        else
        {
            pUmException->Signatures[pUmException->SigCount] = pCbSignature->Id;
            pUmException->SigCount++;

            InsertTailList(&gGuest.Exceptions->CbSignatures, &pCbSignature->Link);
        }
    }

    if (Exception->Export.Valid)
    {
        status = IntUpdateCreateExportSignatureFromAlert(&Exception->Export, &pExpSignature);
        if (!INT_SUCCESS(status))
        {
            WARNING("[WARNING] IntUpdateCreateExportSignatureFromAlert failed with status: 0x%08x.\n", status);
            goto _exit;
        }
        else
        {
            pUmException->Signatures[pUmException->SigCount] = pExpSignature->Id;
            pUmException->SigCount++;

            InsertTailList(&gGuest.Exceptions->ExportSignatures, &pExpSignature->Link);
        }
    }

    if (Exception->ProcessCreation.Valid)
    {
        status = IntUpdateCreateProcessCreationSignatureFromAlert(&Exception->ProcessCreation,
                                                                  &pProcessCreationSignature);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntUpdateCreateProcessCreationSignatureFromAlert failed with status: 0x%08x.\n", status);
            goto _exit;
        }
        else
        {
            pUmException->Signatures[pUmException->SigCount] = pProcessCreationSignature->Id;
            pUmException->SigCount++;

            InsertTailList(&gGuest.Exceptions->ProcessCreationSignatures, &pProcessCreationSignature->Link);
        }
    }

    IntUpdateAddUserExceptionInOrder(pUmException);

    return INT_STATUS_SUCCESS;

_exit:
    if (pCbSignature != NULL)
    {
        IntExceptErase(pCbSignature, IC_TAG_ESIG);
    }

    if (pProcessCreationSignature != NULL)
    {
        IntExceptErase(pProcessCreationSignature, IC_TAG_ESIG);
    }

    if (pExpSignature != NULL)
    {
        IntExceptErase(pExpSignature, IC_TAG_ESIG);
    }

    HpFreeAndNullWithTag(&pUmException, IC_TAG_EXUM);

    return status;
}


static INTSTATUS
IntUpdateAddKmException(
    _In_ const ALERT_KM_EXCEPTION *Exception,
    _In_ QWORD Context
    )
///
/// @brief Creates a new kernel-mode exception from an alert-exception structure #ALERT_UM_EXCEPTION and adds it to our
/// internal list.
///
/// This function also creates code-blocks, export or process-creation signatures, if any, and adds them to the
/// corresponding list of alert exceptions/signatures.
///
/// @param[in] Exception    The structure of the alert-exception.
/// @param[in] Context      The context provided by integrator.
///
/// @retval #INT_STATUS_SUCCESS                 On success.
/// @retval #INT_STATUS_NOT_NEEDED_HINT         If the exception already exists.
/// @retval #INT_STATUS_UNSUPPORTED_DATA_VALUE  If the alert-signature's version is different than our internal version.
/// @retval #INT_STATUS_INSUFFICIENT_RESOURCES  If not enough memory is available.
///
{
    INTSTATUS status;

    DWORD sigCount = (Exception->Idt.Valid != 0) + (Exception->CodeBlocks.Valid != 0);
    SIG_CODEBLOCKS *pCbSignature = NULL;
    SIG_IDT *pIdtSignature = NULL;

    if (Exception->Header.Version != ALERT_KM_EXCEPTION_VERSION)
    {
        ERROR("[ERROR] Unsupported km exception version: %d. We have %d\n",
              Exception->Header.Version, ALERT_KM_EXCEPTION_VERSION);
        return INT_STATUS_UNSUPPORTED_DATA_VALUE;
    }

    if (IntUpdateIsDuplicateKernelException(Exception))
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    KM_EXCEPTION *pKmException = HpAllocWithTag(sizeof(*pKmException) + sigCount * sizeof(DWORD), IC_TAG_EXKM);
    if (NULL == pKmException)
    {
        return INT_STATUS_INSUFFICIENT_RESOURCES;
    }

    pKmException->Context = Context;
    pKmException->OriginatorNameHash = Exception->Originator;
    pKmException->VictimNameHash = Exception->Victim;
    pKmException->Flags = Exception->Flags;
    pKmException->Type = Exception->Type;

    if (Exception->Idt.Valid)
    {
        status = IntUpdateCreateIdtSignatureFromAlert(&Exception->Idt, &pIdtSignature);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntUpdateCreateIdtSignatureFromAlert failed with status: 0x%08x.\n", status);
            goto _exit;
        }
        else
        {
            pKmException->Signatures[pKmException->SigCount] = pIdtSignature->Id;
            pKmException->SigCount++;

            InsertTailList(&gGuest.Exceptions->IdtSignatures, &pIdtSignature->Link);
        }
    }

    if (Exception->CodeBlocks.Valid)
    {
        status = IntUpdateCreateCbSignatureFromAlert(&Exception->CodeBlocks, &pCbSignature);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntUpdateCreateCbSignatureFromAlert failed with status: 0x%08x.\n", status);
            goto _exit;
        }
        else
        {
            pKmException->Signatures[pKmException->SigCount] = pCbSignature->Id;
            pKmException->SigCount++;

            InsertTailList(&gGuest.Exceptions->CbSignatures, &pCbSignature->Link);
        }
    }

    IntUpdateAddKernelExceptionInOrder(pKmException);

    return INT_STATUS_SUCCESS;

_exit:
    if (pCbSignature != NULL)
    {
        IntExceptErase(pCbSignature, IC_TAG_ESIG);
    }

    if (pIdtSignature != NULL)
    {
        IntExceptErase(pIdtSignature, IC_TAG_ESIG);
    }

    HpFreeAndNullWithTag(&pKmException, IC_TAG_EXKM);

    return status;
}


static INTSTATUS
IntUpdateAddKmUmException(
    _In_ const ALERT_KUM_EXCEPTION *Exception,
    _In_ QWORD Context
    )
///
/// @brief Creates a new kernel-user mode exception from an alert-exception structure #ALERT_KUM_EXCEPTION and adds it to our
/// internal list.
///
/// This function also creates code-blocks, export or process-creation signatures, if any, and adds them to the
/// corresponding list of alert exceptions/signatures.
///
/// @param[in] Exception    The structure of the alert-exception.
/// @param[in] Context      The context provided by integrator.
///
/// @retval #INT_STATUS_SUCCESS                 On success.
/// @retval #INT_STATUS_NOT_NEEDED_HINT         If the exception already exists.
/// @retval #INT_STATUS_UNSUPPORTED_DATA_VALUE  If the alert-signature's version is different than our internal version.
/// @retval #INT_STATUS_INSUFFICIENT_RESOURCES  If not enough memory is available.
///
{
    INTSTATUS status;
    DWORD sigCount = (Exception->CodeBlocks.Valid != 0);
    SIG_CODEBLOCKS *pCbSignature = NULL;

    if (Exception->Header.Version != ALERT_KM_EXCEPTION_VERSION)
    {
        ERROR("[ERROR] Unsupported km exception version: %d. We have %d\n",
              Exception->Header.Version, ALERT_KM_EXCEPTION_VERSION);
        return INT_STATUS_UNSUPPORTED_DATA_VALUE;
    }

    if (IntUpdateIsDuplicateKernelUserException(Exception))
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    KUM_EXCEPTION *pException = HpAllocWithTag(sizeof(*pException) + sigCount * sizeof(DWORD), IC_TAG_EXKU);
    if (NULL == pException)
    {
        return INT_STATUS_INSUFFICIENT_RESOURCES;
    }

    pException->Context = Context;
    pException->Originator.NameHash = Exception->Originator;
    pException->Victim.NameHash = Exception->Victim;
    pException->Victim.ProcessHash = Exception->Process;
    pException->Flags = Exception->Flags;
    pException->Type = Exception->Type;

    if (Exception->CodeBlocks.Valid)
    {
        status = IntUpdateCreateCbSignatureFromAlert(&Exception->CodeBlocks, &pCbSignature);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntUpdateCreateCbSignatureFromAlert failed with status: 0x%08x.\n", status);
            goto _exit;
        }
        else
        {
            pException->Signatures[pException->SigCount] = pCbSignature->Id;
            pException->SigCount++;

            InsertTailList(&gGuest.Exceptions->CbSignatures, &pCbSignature->Link);
        }
    }

    IntUpdateAddKernelUserExceptionInOrder(pException);

    return INT_STATUS_SUCCESS;

_exit:
    if (pCbSignature != NULL)
    {
        IntExceptErase(pCbSignature, IC_TAG_ESIG);
    }

    HpFreeAndNullWithTag(&pException, IC_TAG_EXKU);

    return status;
}


INTSTATUS
IntUpdateAddExceptionFromAlert(
    _In_ const void *Event,
    _In_ INTRO_EVENT_TYPE Type,
    _In_ BOOLEAN Exception,
    _In_ QWORD Context
    )
///
/// @brief Handles all types of supported exceptions that can be added from alerts.
///
/// If the alert-exception is already created (the Exception parameter is true), this function will dispatch the
/// alert-exception to the appropriate function that can create the exception with the provided type. If the Exception
/// parameter is false, this function calls the IntAlertCreateException to create the alert-exception structure and
/// will dispatch the newly created structure to the appropriate function that can create the exception with the
/// provided type.
///
///
/// @param[in] Event        The event structure that contains the required information to create an exception.
/// @param[in] Type         The type of the provided event.
/// @param[in] Exception    True if the alert-exceptions structure is already created, otherwise false.
/// @param[in] Context      The context provided by the integrator.
///
/// @retval #INT_STATUS_SUCCESS                 On success.
/// @retval #INT_STATUS_NOT_NEEDED_HINT         If the exception already exists.
/// @retval #INT_STATUS_UNSUPPORTED_DATA_VALUE  If the alert-signature's version is different than our internal version.
/// @retval #INT_STATUS_INSUFFICIENT_RESOURCES  If not enough memory is available.
///
{
    INTSTATUS status;
    const void *pException;
    QWORD violationFlags;
    BYTE pBuff[ALERT_EXCEPTION_SIZE] = { 0 };

    if (NULL == Event)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (!IntAlertIsEventTypeViolation(Type))
    {
        ERROR("[ERROR] Failed to add exception of type %d!\n", Type);
        return INT_STATUS_NOT_SUPPORTED;
    }

    if (Exception)
    {
        const INTRO_ALERT_EXCEPTION_HEADER *header = Event;

        pException = Event;
        violationFlags = header->ViolationFlags;

        if (!header->Valid)
        {
            ERROR("[ERROR] Exception of type %d is invalid!\n", Type);
            return INT_STATUS_INVALID_DATA_STATE;
        }
    }
    else
    {
        const INTRO_VIOLATION_HEADER *header = Event;

        violationFlags = header->Flags;

        status = IntAlertCreateException(Event, Type, TRUE, pBuff);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntAlertCreateException failed: %08x\n", status);
            return status;
        }

        pException = (const void *)pBuff;
    }

    if (NULL == gGuest.Exceptions)
    {
        status = IntExceptInit();
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntExceptInit failed: 0x%08x\n", status);
            return status;
        }
    }

    if (Type == introEventEptViolation)
    {
        if (violationFlags & ALERT_FLAG_KM_UM)
        {
            status = IntUpdateAddKmUmException(pException, Context);
        }
        else if (violationFlags & ALERT_FLAG_NOT_RING0)
        {
            status = IntUpdateAddUmException(pException, Context);
        }
        else
        {
            status = IntUpdateAddKmException(pException, Context);
        }
    }
    else if (introEventMsrViolation == Type ||
             introEventCrViolation == Type ||
             introEventDtrViolation == Type ||
             introEventIntegrityViolation == Type)
    {
        status = IntUpdateAddKmException(pException, Context);
    }
    else if (introEventInjectionViolation == Type ||
             introEventProcessCreationViolation == Type ||
             introEventModuleLoadViolation == Type)
    {
        status = IntUpdateAddUmException(pException, Context);
    }
    else
    {
        status = INT_STATUS_NOT_SUPPORTED;
    }

    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Failed to add exception of type %d: 0x%08x\n", Type, status);
    }

    return status;
}


static void
IntUpdateRemoveSignaturesForException(
    _In_ EXCEPTION_SIGNATURE_ID *Signatures,
    _In_ DWORD Count
    )
///
/// @brief This function removes and frees all signature from the provided array.
///
/// @param[in] Signatures   An array that contains the signature IDs.
/// @param[in] Count        The number of the signatures.
///
{
    for (DWORD i = 0; i < Count; i++)
    {
        switch (Signatures[i].Field.Type)
        {
        case signatureTypeExport :
        {
            for_each_export_signature(gGuest.Exceptions->ExportSignatures, pSignature)
            {
                if (pSignature->AlertSignature && pSignature->Id.Value == Signatures[i].Value)
                {
                    IntExceptErase(pSignature, IC_TAG_ESIG);
                    break;
                }
            }

            break;
        }

        case signatureTypeCodeBlocks :
        {
            for_each_cb_signature(gGuest.Exceptions->CbSignatures, pSignature)
            {
                if (pSignature->AlertSignature && pSignature->Id.Value == Signatures[i].Value)
                {
                    IntExceptErase(pSignature, IC_TAG_ESIG);
                    break;
                }
            }

            break;
        }

        case signatureTypeIdt :
        {
            for_each_idt_signature(gGuest.Exceptions->IdtSignatures, pSignature)
            {
                if (pSignature->AlertSignature && pSignature->Id.Value == Signatures[i].Value)
                {
                    IntExceptErase(pSignature, IC_TAG_ESIG);
                    break;
                }
            }

            break;
        }

        default:
        {
            ERROR("[ERROR] Should not reach here. Type is %d\n", Signatures[i].Field.Type);
            return;
        }
        }
    }
}


INTSTATUS
IntUpdateRemoveException(
    _In_opt_ QWORD Context
    )
///
/// @brief This function removes an exception for a given context.
///
/// This function iterates all alert-exception list to find a exception that match the given context.
///
/// @param[in] Context  The context given by the integrator.
///
/// @retval #INT_STATUS_SUCCESS          On success.
/// @retval #INT_STATUS_NOT_INITIALIZED  If the exceptions is not initialized.
/// @retval #INT_STATUS_NOT_FOUND        If no exception with the given context exists.
///
{
    if (NULL == gGuest.Exceptions)
    {
        return INT_STATUS_NOT_INITIALIZED;
    }

    for_each_um_exception(gGuest.Exceptions->UserAlertExceptions, pException)
    {
        if (pException->Context == Context)
        {
            IntUpdateRemoveSignaturesForException(pException->Signatures, pException->SigCount);
            IntExceptErase(pException, IC_TAG_EXUM);
            return INT_STATUS_SUCCESS;
        }
    }

    for_each_km_exception(gGuest.Exceptions->KernelAlertExceptions, pException)
    {
        if (pException->Context == Context)
        {
            IntUpdateRemoveSignaturesForException(pException->Signatures, pException->SigCount);
            IntExceptErase(pException, IC_TAG_EXUM);
            return INT_STATUS_SUCCESS;
        }
    }

    for_each_um_exception(gGuest.Exceptions->ProcessCreationAlertExceptions, pException)
    {
        if (pException->Context == Context)
        {
            IntUpdateRemoveSignaturesForException(pException->Signatures, pException->SigCount);
            IntExceptErase(pException, IC_TAG_EXUM);
            return INT_STATUS_SUCCESS;
        }
    }

    return INT_STATUS_NOT_FOUND;
}


INTSTATUS
IntUpdateFlushAlertExceptions(
    void
    )
///
/// @brief This function removes all exceptions that were added from alerts.
///
/// @retval #INT_STATUS_SUCCESS          On success.
/// @retval #INT_STATUS_NOT_INITIALIZED  If the exceptions is not initialized.
///
{
    INTSTATUS status;

    if (NULL == gGuest.Exceptions)
    {
        return INT_STATUS_NOT_INITIALIZED;
    }

    TRACE("[INFO] Requesting to flush alert exceptions!\n");

    status = IntExceptAlertRemove();
    if (!INT_SUCCESS(status))
    {
        return status;
    }

    return INT_STATUS_SUCCESS;
}


BOOLEAN
IntUpdateAreExceptionsLoaded(
    void
    )
///
/// @brief Checks if the exceptions are loaded.
///
/// @retval True if the exceptions are loaded, otherwise false.
///
{
    return gGuest.Exceptions && gGuest.Exceptions->Loaded;
}
