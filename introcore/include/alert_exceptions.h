/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
///
/// @file       alert_exceptions.h
/// @ingroup    group_exceptions
///

#ifndef _ALERT_EXCEPTIONS_H_
#define _ALERT_EXCEPTIONS_H_

#include "exceptions.h"

#pragma pack(push, 1)

#define ALERT_HASH_COUNT         6u

#define ALERT_CB_SIGNATURE_VERSION 1


typedef struct _ALERT_CB_SIGNATURE
{
    INTRO_ALERT_EXCEPTION_HEADER Header;    ///< The header used by alert-signature

    DWORD       Flags;                      ///< Contains any flags from \ref _SIGNATURE_FLG

    BOOLEAN     Valid;                      ///< True if the alert-signature is valid, otherwise false
    BYTE        Score;                      ///< The number of (minimum) hashes from a list that need to match
    BYTE        Count;                      ///< The number of the code-blocks
    BYTE        _Reserved;

    DWORD       CodeBlocks[ALERT_HASH_COUNT];///< An array that contains the code-blocks
} ALERT_CB_SIGNATURE;


#define ALERT_IDT_SIGNATURE_VERSION 1

///
/// @brief Describes an idt alert-signature
///
typedef struct _ALERT_IDT_SIGNATURE
{
    INTRO_ALERT_EXCEPTION_HEADER Header;    ///< The header used by alert-signature

    DWORD       Flags;                      ///< Contains any flags from \ref _SIGNATURE_FLG

    BOOLEAN     Valid;                      ///< True if the alert-signature is valid, otherwise false
    BYTE        Entry;                      ///< The number of the IDT entry
    BYTE        _Reserved[2];
} ALERT_IDT_SIGNATURE;


#define ALERT_EXPORT_SIGNATURE_VERSION 1

typedef struct _ALERT_EXPORT_SIGNATURE
{
    INTRO_ALERT_EXCEPTION_HEADER Header;    ///< The header used by alert-signature

    DWORD       Flags;                      ///< Contains any flags from \ref _SIGNATURE_FLG

    BOOLEAN     Valid;                      ///< True if the alert-signature is valid, otherwise false
    BYTE        _Reserved[3];

    DWORD       Library;                    ///< The name-hash of the modified library
    DWORD       Function;                   ///< The name-hash of the modified function
    WORD        Delta;                      ///< The number of modified bytes that will be excepted
    BYTE        WriteSize;                  ///< The number of bytes that are modified
    BYTE        _Reserved1;
} ALERT_EXPORT_SIGNATURE;


#define ALERT_PROCESS_CREATION_SIGNATURE_VERSION 1

///
/// @brief Describe a process-creation alert-signature
///
typedef struct _ALERT_PROCESS_CREATION_SIGNATURE
{
    INTRO_ALERT_EXCEPTION_HEADER Header;    ///< The header used by alert-signature

    DWORD       Flags;                      ///< Contains any flags from \ref _SIGNATURE_FLG

    BOOLEAN     Valid;                      ///< True if the alert-signature is valid, otherwise false

    DWORD       CreateMask;                 ///< The deep-process-inspection creation bit-mask
    DWORD       _Reserved[3];
} ALERT_PROCESS_CREATION_SIGNATURE;


#define ALERT_KM_EXCEPTION_VERSION 1

///
/// @brief Describes a kernel-mode alert-exception
///
typedef struct _ALERT_KM_EXCEPTION
{
    INTRO_ALERT_EXCEPTION_HEADER Header; ///< The header used by alert-exception

    DWORD       Originator;             ///< The name-hash of the originator
    DWORD       Victim;                 ///< The name-hash of the victim

    DWORD       Flags;                  ///< The flags of the exception; any flags from \ref _EXCEPTION_FLG

    KM_EXCEPTION_OBJECT Type;           ///< The type of the exception; any type from \ref _KM_EXCEPTION_OBJECT

    ALERT_CB_SIGNATURE  CodeBlocks;     ///< The code-blocks alert-signature, if any
    ALERT_IDT_SIGNATURE Idt;            ///< The idt alert-signature, if any
} ALERT_KM_EXCEPTION;


#define ALERT_KUM_EXCEPTION_VERSION 1

///
/// @brief Describes a kernel-mode alert-exception
///
typedef struct _ALERT_KUM_EXCEPTION
{
    INTRO_ALERT_EXCEPTION_HEADER Header; ///< The header used by alert-exception

    DWORD       Originator;             ///< The name-hash of the originator
    DWORD       Victim;                 ///< The name-hash of the victim
    DWORD       Process;                ///< The name-hash of the process.

    DWORD       Flags;                  ///< The flags of the exception; any flags from \ref _EXCEPTION_FLG

    KUM_EXCEPTION_OBJECT Type;          ///< The type of the exception; any type from \ref _KUM_EXCEPTION_OBJECT

    ALERT_CB_SIGNATURE      CodeBlocks; ///< The code-blocks alert-signature, if any
} ALERT_KUM_EXCEPTION;

STATIC_ASSERT(sizeof(ALERT_KM_EXCEPTION) <= ALERT_EXCEPTION_SIZE,
              "The ALERT_KM_EXCEPTION structure exceeds ALERT_EXCEPTION_SIZE, possible buffer overflow!");

#define ALERT_UM_EXCEPTION_VERSION 1

///
/// @brief Describes a user-mode alert-exception
///
typedef struct _ALERT_UM_EXCEPTION
{
    INTRO_ALERT_EXCEPTION_HEADER Header;        ///< The header used by alert-exception

    DWORD       Originator;                     ///< The name-hash of the originator
    DWORD       Victim;                         ///< The name-hash of the victim
    DWORD       Process;                        ///< The name-hash of the process in which the modification takes place

    DWORD       Flags;                          ///< The flags of the exception; any flags from \ref _EXCEPTION_FLG

    UM_EXCEPTION_OBJECT Type;                   ///< The type of the exception; any type from \ref _UM_EXCEPTION_OBJECT

    ALERT_CB_SIGNATURE               CodeBlocks;///< The code-blocks alert-signature, if any
    ALERT_EXPORT_SIGNATURE           Export;    ///< The export alert-signature, if any
    ALERT_PROCESS_CREATION_SIGNATURE ProcessCreation;   ///< The process-creation alert-signature, if any
} ALERT_UM_EXCEPTION;

STATIC_ASSERT(sizeof(ALERT_UM_EXCEPTION) <= ALERT_EXCEPTION_SIZE,
              "The ALERT_UM_EXCEPTION structure exceeds ALERT_EXCEPTION_SIZE, possible buffer overflow!");

#pragma pack(pop)


INTSTATUS
IntAlertCreateException(
    _In_ const void *Event,
    _In_ INTRO_EVENT_TYPE Type,
    _In_ BOOLEAN LogErrors,
    _Inout_ void *Exception
    );

INTSTATUS
IntAlertCreateExceptionInEvent(
    _Inout_ void *Event,
    _In_ INTRO_EVENT_TYPE Type
    );

__forceinline BOOLEAN
IntAlertIsEventTypeViolation(
    _In_ INTRO_EVENT_TYPE Type
    )
{
    // Whenever a new violation is created, one must add here the violation type
    // in order to check when adding an exception from alert.
    return !(introEventEptViolation != Type &&
             introEventMsrViolation != Type &&
             introEventCrViolation != Type &&
             introEventDtrViolation != Type &&
             introEventIntegrityViolation != Type &&
             introEventInjectionViolation != Type &&
             introEventProcessCreationViolation != Type &&
             introEventModuleLoadViolation != Type);
}

#endif // _ALERT_EXCEPTIONS_H_
