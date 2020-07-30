/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _INTRO_NET_H_
#define _INTRO_NET_H_

#include "lixprocess.h"
#include "winprocess.h"

/// @brief  The minimum buffer size needed for the textual representation of an IP address.
#define INTRONET_MIN_BUFFER_SIZE       (sizeof("[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]"))

///
/// @brief  An IP address.
typedef union _INTRONET_ADDRESS
{
    BYTE                Ipv6[16];   ///< IPv6 address.
    BYTE                Ipv4[4];    ///< IPv4 address.
} INTRONET_ADDRESS;

typedef WORD INTRONET_PORT;

///
/// @brief  An endpoint.
typedef struct _INTRONET_ENDPOINT
{
    /// @brief  Address family.
    INTRO_NET_AF            AddressFamily;

    /// @brief  Connection state.
    INTRO_NET_STATE         State;

    /// @brief  Local address.
    INTRONET_ADDRESS        LocalAddress;
    /// @brief  Local port.
    INTRONET_PORT           LocalPort;

    /// @brief  Remote address.
    ///
    /// Will always be 0 for #introNetStateListening states.
    INTRONET_ADDRESS        RemoteAddress;
    /// @brief  Remote port.
    ///
    /// Will always be 0 for #introNetStateListening states.
    INTRONET_PORT           RemotePort;

    union
    {
        /// @brief  Pointer to the task that owns the connection.
        ///
        /// Will always be NULL for #introNetStateTimeWait states. Valid only for Linux guests.
        LIX_TASK_OBJECT     *OwnerTask;
        /// @brief  Pointer to the process that owns the connection.
        ///
        /// Will always be NULL for #introNetStateTimeWait states. Valid only for Windows guests.
        WIN_PROCESS_OBJECT  *OwnerProcess;
    };

    /// @brief Guest virtual address of the endpoint/socket object.
    QWORD                   Endpoint;
} INTRONET_ENDPOINT;


//
// IntNetStateToString
//
__forceinline const char *
IntNetStateToString(
    _In_ INTRO_NET_STATE State
    )
///
/// @brief  Converts a connection state to a string.
///
{
    switch (State)
    {
    case introNetStateClosed:
        return "CLOSED";
    case introNetStateListening:
        return "LISTENING";
    case introNetStateSynSent:
        return "SYN-SENT";
    case introNetStateSynRecv:
        return "SYN-RECV";
    case introNetStateEstablished:
        return "ESTABLISHED";
    case introNetStateFinWait:
        return "FIN-WAIT";
    case introNetStateFinWait2:
        return "FIN-WAIT2";
    case introNetStateCloseWait:
        return "CLOSE-WAIT";
    case introNetStateClosing:
        return "CLOSING";
    case introNetStateLastAck:
        return "LAST-ACK";
    case introNetStateTimeWait:
        return "TIME-WAIT";
    case introNetStateDeleteTcb:
        return "DELETE-TCB";
    default:
        return "UNKNOWN";
    }
}

INTRO_NET_STATE
IntNetConvertState(
    _In_ const DWORD State
    );

_Success_(return > 0)
DWORD
IntNetAddrToStr(
    _In_ const INTRO_NET_AF Family,
    _In_ const INTRONET_ADDRESS *Address,
    _Out_writes_(INTRONET_MIN_BUFFER_SIZE) CHAR *String
    );

#endif // _INTRO_NET_H
