/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "lixnet.h"
#include "alerts.h"
#include "guests.h"
#include "intronet.h"
#include "introstatus.h"

#define LIX_FDTABLE_MAX_FDS_CAP     2048u        ///< The maximum number of file descriptors to be iterated.

///
/// @brief An internal structure used to cache the "struct proto" addresses of required connection types.
///
typedef struct _SOCK_PROTO
{
    QWORD   Gva;        ///< The GVA of the "struct proto" object.
    CHAR    Name[32];   ///< The protocol name as defined in Linux kernel.
} SOCK_PROTO;


static void
IntLixNetSendConnectionEvent(
    _In_ INTRONET_ENDPOINT *Connection
    )
///
/// @brief Sends a connection event to the integrator.
///
/// @param[in] Connection The TCP/IP connection.
///
{
    INTSTATUS status;
    PEVENT_CONNECTION_EVENT pConnectionEvent;

    pConnectionEvent = &gAlert.Connection;

    IntAlertFillConnection(Connection, pConnectionEvent);

    status = IntNotifyIntroEvent(introEventConnectionEvent, pConnectionEvent, sizeof(*pConnectionEvent));
    if (!INT_SUCCESS(status))
    {
        WARNING("[WARNING] IntNotifyIntroEvent failed: 0x%08x\n", status);
    }
}


_Success_(return == INT_STATUS_SUCCESS)
static INTSTATUS
IntLixNetGetConnectionFromSocket(
    _In_ QWORD SocketGva,
    _Out_ INTRONET_ENDPOINT *Connection
    )
///
/// @brief Fills an INTRONET_ENDPOINT structure from a TCP/IP socket GVA.
///
/// This function is able to retrieve the connection details starting from the address of a socket object.  If the
/// connection type is not either IPv4 or IPv6 it will be ignored.
///
/// * Known issue: For kernel versions < 3.16 (except the Centos/Redhat 3.10 which backported the patch) this function
/// is not able to retrieve IPv6 connections.
///
/// @param[in]  SocketGva The GVA of a socket object.
/// @param[out] Connection Upon successful return this structure will be filled with the connection details.
///
/// @return INT_STATUS_SUCCESS On success.
/// @return INT_STATUS_NOT_NEEDED_HINT If the SocketGva does not refer to a valid TCP/IP connection.
///
{
    INTSTATUS status;

    QWORD sock, proto;
    CHAR protoName[32];
    DWORD sockState = 0;

    DWORD iProto;

    static SOCK_PROTO protos[] =
    {
        {
            .Name = "TCP"
        },
        {
            .Name = "TCPv6"
        },
    };

    status = IntKernVirtMemFetchQword(SocketGva + LIX_FIELD(Socket, Sk), &sock);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemFetchQword failed for GVA 0x%016llx: 0x%08x\n",
              SocketGva + LIX_FIELD(Socket, Sk), status);
        return status;
    }

    status = IntKernVirtMemFetchQword(sock + LIX_FIELD(Sock, Proto), &proto);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemFetchQword failed for GVA 0x%016llx: 0x%08x\n",
              sock + LIX_FIELD(Sock, Proto), status);
        return status;
    }

    if (!IS_KERNEL_POINTER_LIX(proto))
    {
        WARNING("[WARNING] Sock 0x%016llx has NULL proto pointer.", sock);
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    for (iProto = 0; iProto < ARRAYSIZE(protos); iProto++)
    {
        if (proto == protos[iProto].Gva)
        {
            break;
        }
    }

    if (iProto == ARRAYSIZE(protos))
    {
        status = IntKernVirtMemRead(proto + LIX_FIELD(Ungrouped, ProtoName), sizeof(protoName), protoName, NULL);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntKernVirtMemRead failed for GVA 0x%016llx: 0x%08x\n",
                  proto + LIX_FIELD(Ungrouped, ProtoName), status);
            return INT_STATUS_SUCCESS;
        }

        for (iProto = 0; iProto < ARRAYSIZE(protos); iProto++)
        {
            if (!strcmp(protos[iProto].Name, protoName))
            {
                protos[iProto].Gva = proto;
                break;
            }
        }

        if (iProto == ARRAYSIZE(protos))
        {
            return INT_STATUS_NOT_NEEDED_HINT;
        }
    }

    status = IntKernVirtMemRead(sock + LIX_FIELD(Sock, State), 1,  &sockState, NULL);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemRead failed for GVA 0x%016llx: 0x%08x\n",
              sock + LIX_FIELD(Sock, State), status);
        return status;
    }

    Connection->State = IntNetConvertState(sockState);
    Connection->AddressFamily = (iProto == 0 ? introNetAfIpv4 : introNetAfIpv6);
    Connection->Endpoint = sock;

    memset(&Connection->LocalAddress, 0, sizeof(Connection->LocalAddress));
    memset(&Connection->RemoteAddress, 0, sizeof(Connection->RemoteAddress));

    if (introNetAfIpv6 == Connection->AddressFamily)
    {
        status = IntKernVirtMemRead(sock + LIX_FIELD(Sock, RcvSaddr), 16, &Connection->LocalAddress, NULL);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntKernVirtMemRead failed for GVA 0x%016llx: 0x%08x\n",
                  sock + LIX_FIELD(Sock, V6RcvSaddr), status);
            return status;
        }

        status = IntKernVirtMemRead(sock + LIX_FIELD(Sock, V6Daddr), 16, &Connection->RemoteAddress, NULL);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntKernVirtMemRead failed for GVA 0x%016llx: 0x%08x\n",
                  sock + LIX_FIELD(Sock, V6RcvSaddr), status);
            return status;
        }
    }
    else
    {
        status = IntKernVirtMemRead(sock + LIX_FIELD(Sock, RcvSaddr), 4, &Connection->LocalAddress, NULL);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntKernVirtMemRead failed for GVA 0x%016llx: 0x%08x\n",
                  sock + LIX_FIELD(Sock, RcvSaddr), status);
            return status;
        }

        status = IntKernVirtMemRead(sock + LIX_FIELD(Sock, Daddr), 4, &Connection->RemoteAddress, NULL);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntKernVirtMemRead failed for GVA 0x%016llx: 0x%08x\n",
                  sock + LIX_FIELD(Sock, RcvSaddr), status);
            return status;
        }
    }

    status = IntKernVirtMemRead(sock + LIX_FIELD(Sock, Num), 2, &Connection->LocalPort, NULL);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemRead failed for GVA 0x%016llx: 0x%08x\n",
              sock + LIX_FIELD(Sock, Num), status);
        return status;
    }

    status = IntKernVirtMemRead(sock + LIX_FIELD(Sock, Dport), 2, &Connection->RemotePort, NULL);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemRead failed for GVA 0x%016llx: 0x%08x\n",
              sock + LIX_FIELD(Sock, Dport), status);
        return status;
    }

    return INT_STATUS_SUCCESS;
}


static BOOLEAN
IntLixNetFileIsSocket(
    _In_ QWORD StructFileGva,
    _Out_ QWORD *SocketGva
    )
///
/// @brief Check if a give file object is a socked and return the socket GVA.
///
/// @param[in]  StructFileGva   The GVA of the file structure.
/// @param[out] SocketGva       Will contain the GVA of the socket structure corresponding to the given file structure
///                             when the returned value is TRUE
///
/// @return TRUE  If the file is indeed a socket.
/// @return FALSE If the file is not a socket.
///
{
    INTSTATUS status;
    QWORD dentry, inode;
    UINT16 imode;

    *SocketGva = 0;

    status = IntKernVirtMemFetchQword(StructFileGva + LIX_FIELD(Ungrouped, FileDentry), &dentry);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemFetchQword failed for GVA 0x%016llx: 0x%08x\n",
              StructFileGva + LIX_FIELD(Ungrouped, FileDentry), status);
        return FALSE;
    }

    status = IntKernVirtMemFetchQword(dentry + LIX_FIELD(Dentry, Inode), &inode);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemFetchQword failed for GVA 0x%016llx: 0x%08x\n",
              dentry + LIX_FIELD(Dentry, Inode), status);
        return FALSE;
    }

    status = IntKernVirtMemRead(inode + LIX_FIELD(Inode, Imode), sizeof(imode), &imode, NULL);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemRead failed for GVA 0x%016llx: 0x%08x\n",
              dentry + LIX_FIELD(Dentry, Inode), status);
        return FALSE;
    }

    if (!S_ISSOCK(imode))
    {
        return FALSE;
    }

    *SocketGva = inode - LIX_FIELD(Ungrouped, SocketAllocVfsInode);
    return TRUE;

}


INTSTATUS
IntLixNetIterateTaskConnections(
    _In_ LIX_TASK_OBJECT *Task,
    _In_ PFUNC_IterateConnectionsCallback Callback
    )
///
/// @brief Iterates all TCP/IP connections of a process and supplies them to callback.
///
/// This function will iterate all file descriptors for the given process and for those that refer to a
/// socket will attempt to extract the connection details if the protocol used is TCP IPv4 or IPv6.
///
/// @param[in] Task The Linux process.
/// @param[in] Callback The callback that will be called for each connection.
///
/// @return INT_STATUS_SUCCESS On success.
/// @return INT_STATUS_NOT_NEEDED_HINT If the connection events are not enabled.
/// @return INT_STATUS_INVALID_PARAMETER_1 If the Task parameter does not point to a valid LIX_TASK_OBJECT.
/// @return INT_STATUS_NOT_SUPPORTED If the current OS type is not Linux.
///
{
    INTSTATUS status;

    INTRONET_ENDPOINT conn;

    QWORD files, fdt, fd;
    DWORD maxFds;

    if (gGuest.OSType != introGuestLinux)
    {
        BUG_ON(TRUE);

        return INT_STATUS_NOT_SUPPORTED;
    }

    if (!(gGuest.CoreOptions.Current & INTRO_OPT_EVENT_CONNECTIONS))
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    if (NULL == Task)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (NULL == Callback)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    status = IntKernVirtMemFetchQword(Task->Gva + LIX_FIELD(TaskStruct, Files), &files);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemFetchQword failed for %llx: 0x%08x\n",
              Task->Gva + LIX_FIELD(TaskStruct, Files), status);
        return status;
    }

    status = IntKernVirtMemFetchQword(files + LIX_FIELD(Files, Fdt), &fdt);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemFetchQword failed for %llx: 0x%08x\n", files + LIX_FIELD(Files, Fdt), status);
        return status;
    }

    status = IntKernVirtMemFetchDword(fdt + LIX_FIELD(FdTable, MaxFds), &maxFds);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemFetchQword failed for %llx: 0x%08x\n", fdt + LIX_FIELD(FdTable, MaxFds), status);
        return status;
    }

    status = IntKernVirtMemFetchQword(fdt + LIX_FIELD(FdTable, Fd), &fd);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemFetchQword failed for %llx: 0x%08x\n", files + LIX_FIELD(FdTable, Fd), status);
        return status;
    }

    conn.OwnerTask = Task;

    maxFds = MIN(maxFds, LIX_FDTABLE_MAX_FDS_CAP);
    for (DWORD iFd = 0; iFd < maxFds; iFd++)
    {
        QWORD file;
        QWORD socketGva;

        status = IntKernVirtMemFetchQword(fd + iFd * sizeof(QWORD), &file);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntKernVirtMemFetchQword failed for %llx: 0x%08x\n", fd + iFd * 8ull, status);
            return status;
        }

        if ((!IS_KERNEL_POINTER_LIX(file)) || (!IntLixNetFileIsSocket(file, &socketGva)))
        {
            continue;
        }

        status = IntLixNetGetConnectionFromSocket(socketGva, &conn);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntLixSocketGetConnection failed for socket %llx : 0x%08x\n", socketGva, status);
            continue;
        }

        if (INT_STATUS_NOT_NEEDED_HINT == status)
        {
            continue;
        }

        Callback(&conn);
    }

    return INT_STATUS_SUCCESS;
}


static void
IntLixNetProcessConnection(
    INTRONET_ENDPOINT *Endpoint
    )
///
/// @brief Callback for IntLixNetIterateTaskConnections that processes each TCP/IP connection.
///
/// This function will log the connection details and send to the integrator an event.
///
/// @param[in] Endpoint The TCP/IP connection.
///
{
    CHAR ipString[INTRONET_MIN_BUFFER_SIZE];

    IntLixNetSendConnectionEvent(Endpoint);

    IntNetAddrToStr(Endpoint->AddressFamily, &Endpoint->RemoteAddress, ipString);
    TRACE("[CONNECTION] Owner %s | Family: %u | State %s | LocalPort: %hu | RemoteAddress: %s | Endpoint %016llx\n",
          Endpoint->OwnerTask->Comm, Endpoint->AddressFamily, IntNetStateToString(Endpoint->State),
          Endpoint->LocalPort, ipString, Endpoint->Endpoint);
}


INTSTATUS
IntLixNetSendTaskConnections(
    _In_ LIX_TASK_OBJECT *Task
    )
///
/// @brief Logs and sends to the integrator all connections opened by a Linux proces..
///
/// @param[in] Task The Linux process.
///
/// @returns INT_STATUS_SUCCESS On success.
/// @returns INT_STATUS_INVALID_PARAMETER_1 If an invalid process is supplied
///
{
    if (NULL == Task)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    return IntLixNetIterateTaskConnections(Task, IntLixNetProcessConnection);
}


INTSTATUS
IntLixNetSendGuestConnections(
    void
    )
///
/// @brief Sends all active in-guest TCP/IP connections as events to the integrator.
///
/// This function will iterate all processes running inside the guest and send all their active TCP/IP connections.
///
/// @return INT_STATUS_SUCCESS On success.
/// @return INT_STATUS_NOT_NEEDED_HINT If connection events are not enabled.
///
{
    INTSTATUS status;

    if (gGuest.OSType != introGuestLinux)
    {
        BUG_ON(TRUE);

        return INT_STATUS_NOT_SUPPORTED;
    }

    if (!(gGuest.CoreOptions.Current & INTRO_OPT_EVENT_CONNECTIONS))
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    status = IntLixTaskIterateTasks(IntLixNetSendTaskConnections);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntLixTaskIterateTasks failed: 0x%08x\n", status);
    }

    return status;
}
