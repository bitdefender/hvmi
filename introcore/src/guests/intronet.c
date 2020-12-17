/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "intronet.h"
#include "guests.h"


_Success_(return > 0)
DWORD
IntNetAddrToStr(
    _In_ const INTRO_NET_AF Family,
    _In_ const INTRONET_ADDRESS *Address,
    _Out_writes_(INTRONET_MIN_BUFFER_SIZE) CHAR *String
    )
///
/// @brief  Converts an IP address to a string.
///
/// @param[in]  Family      The type of address.
/// @param[in]  Address     Pointer to an address.
/// @param[in]  String      Pointer to a buffer that, on success, will contain a NULL-terminated string that represents
///                         the provided address. Must be at least #INTRONET_MIN_BUFFER_SIZE long.
///
/// @returns    The number of characters written to the buffer, not including the NULL terminator; or 0 in case of
///             error.
///
{
    DWORD written = 0;
    int ret;
    int rem = INTRONET_MIN_BUFFER_SIZE;

    if (NULL == Address || NULL == String)
    {
        return 0;
    }

    if (introNetAfIpv4 == Family)
    {
        ret = snprintf(String, rem, "%d.%d.%d.%d",
                       Address->Ipv4[0], Address->Ipv4[1], Address->Ipv4[2], Address->Ipv4[3]);
        if (ret < 0 || ret >= rem)
        {
            ERROR("[ERROR] snprintf error: %d, size %d\n", ret, rem);
            return 0;
        }

        written += ret;
        rem -= ret;
    }
    else if (introNetAfIpv6 == Family)
    {
        CHAR *format = NULL;
        BOOLEAN first = TRUE;
        WORD toPrint = 0;

        ret = snprintf(String, rem, "[");
        if (ret < 0 || ret >= rem)
        {
            ERROR("[ERROR] snprintf error: %d, size %d\n", ret, rem);
            return ret;
        }

        written += ret;
        rem -= ret;

        // Iterate up to 14 since we don't want to print the last two BYTEs inside this loop.
        for (DWORD i = 0; i < 14; i += 2)
        {
            toPrint = Address->Ipv6[i] << 8 | Address->Ipv6[i + 1];

            if (0 != toPrint)
            {
                format = first ? "%04x" : ":%04x";

                ret = snprintf(String + written, rem, format, toPrint);
                if (ret < 0 || ret >= rem)
                {
                    ERROR("[ERROR] snprintf error: %d, size %d\n", ret, rem);
                    return 0;
                }

                written += ret;
                rem -= ret;
            }
            else if (first)
            {
                ret = snprintf(String + written, rem, ":");
                if (ret < 0 || ret >= rem)
                {
                    ERROR("[ERROR] snprintf error: %d, size %d\n", ret, rem);
                    return 0;
                }

                written += ret;
                rem -= ret;
            }

            first = FALSE;
        }

        format = ":%x]";
        toPrint = Address->Ipv6[14] << 8 | Address->Ipv6[15];

        ret = snprintf(String + written, rem, format, toPrint);
        if (ret < 0 || ret >= rem)
        {
            ERROR("[ERROR] snprintf error: %d, size %d\n", ret, rem);
            return 0;
        }

        written += ret;
        rem -= ret;
    }

    return written;
}


static __forceinline INTRO_NET_STATE
IntNetConvertStateLix(
    _In_ const LIX_SOCK_STATE State
    )
///
/// @brief  Converts a Linux specific connection state to an Introcore connection state.
///
/// @param[in]  State   Connection state to be converted.
///
/// @returns    The equivalent Introcore connection state; or #introNetStateUnknown if the Linux connection state
///             is not known.
///
{
    switch (State)
    {
    case LIX_TCP_ESTABLISHED:
        return introNetStateEstablished;
    case LIX_TCP_SYN_SENT:
        return introNetStateSynSent;
    case LIX_TCP_SYN_RECV:
        return introNetStateSynRecv;
    case LIX_TCP_FIN_WAIT1:
        return introNetStateFinWait;
    case LIX_TCP_FIN_WAIT2:
        return introNetStateFinWait2;
    case LIX_TCP_TIME_WAIT:
        return introNetStateTimeWait;
    case LIX_TCP_CLOSE:
        return introNetStateClosed;
    case LIX_TCP_CLOSE_WAIT:
        return introNetStateCloseWait;
    case LIX_TCP_LAST_ACK:
        return introNetStateLastAck;
    case LIX_TCP_LISTEN:
        return introNetStateListening;
    case LIX_TCP_CLOSING:
        return introNetStateClosing;
    case LIX_TCP_NEW_SYN_RECV:
        return introNetStateNewSynRecv;
    default:
        return introNetStateUnknown;
    }
}


static __forceinline INTRO_NET_STATE
IntNetConvertStateWin(
    _In_ const WIN_SOCK_STATE State
    )
///
/// @brief  Converts a Windows specific connection state to an Introcore connection state.
///
/// @param[in]  State   Connection state to be converted.
///
/// @returns    The equivalent Introcore connection state; or #introNetStateUnknown if the Windows connection state
///             is not known.
///
{
    switch (State)
    {
    case WIN_TCP_CLOSED:
        return introNetStateClosed;
    case WIN_TCP_LISTENING:
        return introNetStateListening;
    case WIN_TCP_SYN_SENT:
        return introNetStateSynSent;
    case WIN_TCP_SYN_RECV:
        return introNetStateSynRecv;
    case WIN_TCP_ESTABLISHED:
        return introNetStateEstablished;
    case WIN_TCP_FIN_WAIT:
        return introNetStateFinWait;
    case WIN_TCP_FIN_WAIT2:
        return introNetStateFinWait2;
    case WIN_TCP_CLOSE_WAIT:
        return introNetStateCloseWait;
    case WIN_TCP_CLOSING:
        return introNetStateClosing;
    case WIN_TCP_LAST_ACK:
        return introNetStateLastAck;
    case WIN_TCP_TIME_WAIT:
        return introNetStateTimeWait;
    case WIN_TCP_DELETE_TCB:
        return introNetStateDeleteTcb;
    default:
        return introNetStateUnknown;
    }
}


INTRO_NET_STATE
IntNetConvertState(
    _In_ const DWORD State
    )
///
/// @brief  Converts a guest connection state to an Introcore connection state.
///
/// @param[in]  State   Connection state to be converted.
///
/// @returns    The equivalent Introcore connection state; or #introNetStateUnknown if the guest connection state
///             is not known.
///
{
    switch (gGuest.OSType)
    {
    case introGuestLinux:
        return IntNetConvertStateLix(State);

    case introGuestWindows:
        return IntNetConvertStateWin(State);

    default:
        return introNetStateUnknown;
    }
}
