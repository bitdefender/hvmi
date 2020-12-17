/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "introcore.h"
#include "guests.h"
#include "intronet.h"
#include "winnet.h"
#include "winprocesshp.h"
#include "winpe.h"
#include "drivers.h"
#include "alerts.h"
#include "bitmask.h"
#include "structs.h"

/// @brief Maximum allowed count for the tcpip!PartitionCount value.
///
/// For newer Windows versions, this value is the maximum that can be returned from
/// tcpip!TcpNumPartitionsForProcessorCount.
///
/// For older Windows versions, this value is obtained using the maximum returned value
/// from tcpip!TcpMaxPartitionShift. In this case, the count is calulated as (1 << shift).
///
/// However, for all of these, the maximum count remains the same.
///
#define TCPIP_MAX_PARTITION_CNT 0x40

/// @brief Switch a WORD from network endianness to little endina.
#define NET_BYTE_ORDER(Word)    (((Word) >> 8) | ((Word) << 8))

/// @brief Check if a port is valid. Not the best check, but a valid check.
#define VALID_PORT(Port)        (0 != (Port) && 49151 != (Port))

/// @brief Upper limit for iterating through guest linked lists.
#define WINNET_LIST_ITERS_CAP 64
///
/// @brief Structure that describe the kernel objects needed by introcore
/// to extract connections.
///
struct _WINNET_STATE
{
    /// @brief Describe information about the TCP partition containing endpoints.
    struct _PARTITION
    {
        QWORD   Table;          ///< Will hold the address of the TCP partition table.
        DWORD   Count;          ///< Will hold the number of elements inside the partition table.
        DWORD   Size;           ///< Will hold the size of a partition element.

        BOOLEAN Found;          ///< TRUE if we managed to find the elements above.
    } Partition;

    /// @brief Describe information about the TCP port pool containing listeners.
    struct _BITMAP
    {
        QWORD   PortAssignment; ///< Will hold the address of the array of inet port assignment arrays in the port pool.
        QWORD   Buffer;         ///< Will hold the address of the bitmap buffer in the port pool.

        BOOLEAN Found;          ///< TRUE if we managed to find the elements above.
    } Bitmap;
} gWinNet;


static inline INTRO_NET_AF
IntWinNetConvertAf(
    _In_ WORD Af
    )
///
/// @brief         Convert a windows address family value to an introcore one.
///
/// @param[in]     Af  The windows address family value.
///
/// @returns       A propper #INTRO_NET_AF value.
///
{
    switch (Af)
    {
    case AF_INET:
        return introNetAfIpv4;
    case AF_INET6:
        return introNetAfIpv6;
    }

    return introNetAfUnknown;
}


static INTSTATUS
IntWinNetGetAddrFam(
    _In_reads_bytes_(Size) const BYTE *Buffer,
    _In_ size_t Size,
    _Inout_ size_t *Offset,
    _Inout_ void *Context
    )
///
/// @brief         Callback to get the address family from a guest buffer.
///
/// Will check if the Buffer contains a guest pointer to an address family.
/// The address family is simply a WORD with values 2 (v4) or 17 (v6).
///
/// @param[in]     Buffer   Buffer in which the search is performed.
/// @param[in]     Size     The size of the buffer.
/// @param[in,out] Offset   Offset in the buffer where the current search is being performed.
///                         Will increment this offset accordingly.
/// @param[in,out] Context  A caller allocated #INTRONET_ENDPOINT structure to be filled.
///
/// @returns  #INT_STATUS_SUCCESS if successful, or an appropriate #INTSTATUS error value.
///
{
#define ADDR_FAM_OFFSET (gGuest.Guest64 ? (gGuest.OSVersion >= 9200 ? 0x18 : 0x14) : 0xC)

    POOL_HEADER ph;
    INTRONET_ENDPOINT *net = (INTRONET_ENDPOINT *)Context;
    size_t off;
    QWORD addr;
    INTSTATUS status;
    DWORD tag;
    WORD fam;

    *Offset = ROUND_UP(*Offset, gGuest.WordSize);

    off = *Offset;
    *Offset += gGuest.WordSize;

    if (off + gGuest.WordSize > Size)
    {
        return INT_STATUS_BUFFER_OVERFLOW;
    }

    addr = gGuest.Guest64 ? *(const QWORD *)(Buffer + off) : *(const DWORD *)(Buffer + off);

    if (ROUND_DOWN(addr, WIN_POOL_HEADER_SIZE) != addr)
    {
        return INT_STATUS_ALIGNMENT_INCONSISTENCY;
    }

    status = IntKernVirtMemRead(addr - WIN_POOL_HEADER_SIZE, WIN_POOL_HEADER_SIZE, &ph, NULL);
    if (!INT_SUCCESS(status))
    {
        return status;
    }

    tag = gGuest.Guest64 ? ph.Header64.PoolTag : ph.Header32.PoolTag;

    if (tag != POOL_TAG_INNL)
    {
        return INT_STATUS_INVALID_OBJECT_TYPE;
    }
    
    status = IntKernVirtMemRead(addr + ADDR_FAM_OFFSET, sizeof(fam), &fam, NULL);
    if (!INT_SUCCESS(status))
    {
        return status;
    }

    net->AddressFamily = IntWinNetConvertAf(fam);
    if (net->AddressFamily == introNetAfUnknown)
    {
        return INT_STATUS_INVALID_OBJECT_TYPE;
    }

    return INT_STATUS_SUCCESS;

#undef ADDR_FAM_OFFSET
}


static INTSTATUS
IntWinNetGetLocalAddr(
    _In_ QWORD Gva,
    _Out_ INTRONET_ENDPOINT *Endpoint
    )
///
/// @brief         Get the local address of a connection from a given address.
///
/// The Gva should point to a memory location containing a LOCAL_ADDRESS structure.
/// From that structure, the InAddr field points to a pointer to the local address.
///
/// @param[in]     Gva        Gva from where to extract the address.
/// @param[out]    Endpoint   A caller allocated #INTRONET_ENDPOINT structure to be filled.
///
/// @returns  #INT_STATUS_SUCCESS if successful, or an appropriate #INTSTATUS error value.
///should trigger 
{
    INTSTATUS status;
    QWORD addr;
    LOCAL_ADDRESS la;

    addr = FIX_GUEST_POINTER(gGuest.Guest64, Gva);
    status = IntKernVirtMemRead(addr, gGuest.Guest64 ? sizeof(la.Addr64) : sizeof(la.Addr32), &la, NULL);
    if (!INT_SUCCESS(status))
    {
        return status;
    }

    addr = gGuest.Guest64 ? la.Addr64.InAddr : la.Addr32.InAddr;
    status = IntKernVirtMemFetchWordSize(addr, &addr);
    if (!INT_SUCCESS(status))
    {
        return status;
    }

    addr = FIX_GUEST_POINTER(gGuest.Guest64, addr);
    return IntKernVirtMemRead(addr, sizeof(Endpoint->LocalAddress), &Endpoint->LocalAddress, NULL);
}


static INTSTATUS
IntWinNetGetAddrInfo(
    _In_reads_bytes_(Size) const BYTE *Buffer,
    _In_ size_t Size,
    _Inout_ size_t *Offset,
    _Inout_ void *Context
    )
///
/// @brief         Callback to get the address information from a guest buffer.
///
/// Will get the local and remote addresses of an active tcp endpoint.
///
/// Will check if the Buffer contains a guest pointer to an ADDR_INFO struct.
/// From that struct, read a guest pointer to the remote address, and extract it from there.
/// Next, from the same struct read a guest pointer to a LOCAL_ADDRESS from which we'll extract
/// the local address using #IntWinNetGetLocalAddr.
///
/// @param[in]     Buffer   Buffer in which the search is performed.
/// @param[in]     Size     The size of the buffer.
/// @param[in,out] Offset   Offset in the buffer where the current search is being performed.
///                         Will increment this offset accordingly.
/// @param[in,out] Context  A caller allocated #INTRONET_ENDPOINT structure to be filled.
///
/// @returns  #INT_STATUS_SUCCESS if successful, or an appropriate #INTSTATUS error value.
///
{
    QWORD addr, local, remote;
    ADDRINFO ai = { 0 };
    DWORD sz;
    INTRONET_ENDPOINT *net = (INTRONET_ENDPOINT *)Context;
    size_t off;
    INTSTATUS status;

    *Offset = ROUND_UP(*Offset, gGuest.WordSize);

    if (gGuest.Guest64)
    {
        sz = sizeof(ai.Addr64);
    }
    else
    {
        sz = gGuest.OSVersion >= 9200 ? sizeof(ai.Addr32.Win8AndAbove) : sizeof(ai.Addr32.Win7);
    }

    off = *Offset;
    *Offset += gGuest.WordSize;

    if (off + gGuest.WordSize > Size)
    {
        return INT_STATUS_BUFFER_OVERFLOW;
    }
    
    addr = gGuest.Guest64 ? *(const QWORD *)(Buffer + off) : *(const DWORD *)(Buffer + off);
    status = IntKernVirtMemRead(addr, sz, &ai, NULL);
    if (!INT_SUCCESS(status))
    {
        return status;
    }

    if (gGuest.Guest64)
    {
        remote = ai.Addr64.Remote;
        local = ai.Addr64.Local;
    }
    else
    {
        remote = gGuest.OSVersion >= 9200 ? ai.Addr32.Win8AndAbove.Remote : ai.Addr32.Win7.Remote;
        local = gGuest.OSVersion >= 9200 ? ai.Addr32.Win8AndAbove.Local : ai.Addr32.Win7.Local;
    }

    status = IntKernVirtMemRead(remote, sizeof(net->RemoteAddress), &net->RemoteAddress, NULL);
    if (!INT_SUCCESS(status))
    {
        return status;
    }

    return IntWinNetGetLocalAddr(local, net);
}


static INTSTATUS
IntWinNetGetPortsAndState(
    _In_reads_bytes_(Size) const BYTE *Buffer,
    _In_ size_t Size,
    _Inout_ size_t *Offset,
    _Inout_ void *Context
    )
///
/// @brief         Callback to get the ports and state from a guest buffer.
///
/// Read the local & remote ports and the guest state from the buffer.
/// Those are a DWORD ( state), and two WORDs (ports) in this order.
///
/// On their own, they have realy weak invariants: the list of valid ports is any port
/// that's not 0 or 49151, and the list of valid states is any DWORD that's less than 14.
///
/// However, by searching for them together, ( since they're always going to be one after
/// the other) their invariants become stronger.
///
/// @param[in]     Buffer   Buffer in which the search is performed.
/// @param[in]     Size     The size of the buffer.
/// @param[in,out] Offset   Offset in the buffer where the current search is being performed.
///                         Will increment this offset accordingly.
/// @param[in,out] Context  A caller allocated #INTRONET_ENDPOINT structure to be filled.
///
/// @returns  #INT_STATUS_SUCCESS if successful, or an appropriate #INTSTATUS error value.
///
{
    INTSTATUS status;
    size_t off, skip;
    INTRONET_ENDPOINT *net = (INTRONET_ENDPOINT *)Context;

    *Offset = ROUND_UP(*Offset, sizeof(DWORD));

    skip = 4;
    off = *Offset;

    // Make sure we can fit both ports and the state.
    if (off + 2 * sizeof(WORD) + sizeof(DWORD) > Size)
    {
        status = INT_STATUS_BUFFER_OVERFLOW;
        goto _exit;
    }

    if (gGuest.Guest64 && IS_KERNEL_POINTER_WIN(TRUE, *(const QWORD *)(Buffer + off)))
    {
        skip = 8;
        status = INT_STATUS_INVALID_DATA_TYPE;
        goto _exit;
    }

    net->State = IntNetConvertState(*(const DWORD *)(Buffer + off));
    if (net->State == introNetStateUnknown ||
        net->State == introNetStateListening ||
        net->State == introNetStateClosed)
    {
        status = INT_STATUS_INVALID_OBJECT_TYPE;
        goto _exit;
    }

    net->LocalPort = NET_BYTE_ORDER(*(const WORD *)(Buffer + off + 4));
    net->RemotePort = NET_BYTE_ORDER(*(const WORD *)(Buffer + off + 6));

    if (!VALID_PORT(net->LocalPort) || !VALID_PORT(net->RemotePort))
    {
        status = INT_STATUS_INVALID_OBJECT_TYPE;
        goto _exit;
    }

    skip += 4;
    status = INT_STATUS_SUCCESS;

_exit:
    *Offset += skip;

    return status;
}


static INTSTATUS
IntWinNetGetOwner(
    _In_reads_bytes_(Size) const BYTE *Buffer,
    _In_ size_t Size,
    _Inout_ size_t *Offset,
    _Inout_ void *Context
    )
///
/// @brief         Callback to get the owner process from a guest buffer.
///
/// Will simply read a guest pointer and try to find a matching process object.
///
/// @param[in]     Buffer   Buffer in which the search is performed.
/// @param[in]     Size     The size of the buffer.
/// @param[in,out] Offset   Offset in the buffer where the current search is being performed.
///                         Will increment this offset accordingly.
/// @param[in,out] Context  A caller allocated #INTRONET_ENDPOINT structure to be filled.
///
/// @returns  #INT_STATUS_SUCCESS if successful, or an appropriate #INTSTATUS error value.
///
{
    INTRONET_ENDPOINT *net = (INTRONET_ENDPOINT *)Context;
    QWORD addr;
    size_t off;

    *Offset = ROUND_UP(*Offset, gGuest.WordSize);

    off = *Offset;
    *Offset += gGuest.WordSize;

    if (off + gGuest.WordSize > Size)
    {
        return INT_STATUS_BUFFER_OVERFLOW;
    }

    addr = gGuest.Guest64 ? *(const QWORD *)(Buffer + off) : *(const DWORD *)(Buffer + off);

    net->OwnerProcess = IntWinProcFindObjectByEprocess(addr);
    if (NULL == net->OwnerProcess)
    {
        return INT_STATUS_INVALID_OBJECT_TYPE;
    }

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntWinNetGetListenerAddressInfo(
    _In_reads_bytes_(Size) const BYTE *Buffer,
    _In_ size_t Size,
    _Inout_ size_t *Offset,
    _Inout_ void *Context
    )
///
/// @brief         Callback to get the address family and local address from a guest buffer.
///
/// The listener structure contains, in this order, the address family, local address and
/// the local port.
/// The local port is the same as the entry in the tcpip!TcpPortPool bitmap, so we'll use that
/// as a very strong check.
/// The local port field in the #INTRONET_ENDPOINT must be set to the entry in the bitfield in
/// order for this to be successful.
///
/// @param[in]     Buffer   Buffer in which the search is performed.
/// @param[in]     Size     The size of the buffer.
/// @param[in,out] Offset   Offset in the buffer where the current search is being performed.
///                         Will increment this offset accordingly.
/// @param[in,out] Context  A caller allocated #INTRONET_ENDPOINT structure to be filled.
///
/// @returns  #INT_STATUS_SUCCESS if successful, or an appropriate #INTSTATUS error value.
///
{
    INTRONET_ENDPOINT *net = (INTRONET_ENDPOINT *)Context;
    QWORD addrinfo;
    size_t off;
    INTSTATUS status;
    WORD port;

    *Offset = ROUND_UP(*Offset, gGuest.WordSize);

    off = *Offset;
    *Offset += gGuest.WordSize;

    // Make sure we can fit the both the address and address family pointers
    // and the local port, which is at an offset of 2 bytes from those pointers.
    if (off + 2ull * gGuest.WordSize + 2 + sizeof(WORD) > Size)
    {
        return INT_STATUS_BUFFER_OVERFLOW;
    }

    addrinfo = gGuest.Guest64 ? *(const QWORD *)(Buffer + off) : *(const DWORD *)(Buffer + off);
    if (0 == addrinfo)
    {
        // Handle dual stack sockets.
        if (introNetAfIpv4 == net->AddressFamily)
        {
            net->LocalAddress.Ipv4[0] = 127;
            net->LocalAddress.Ipv4[3] = 1;
        }
        else
        {
            net->LocalAddress.Ipv6[15] = 1;
        }
    }
    else
    {
        status = IntWinNetGetLocalAddr(addrinfo, net);
        if (!INT_SUCCESS(status))
        {
            return status;
        }
    }

    // Get to the next pointer.
    off += gGuest.WordSize;

    // Note that this will increase the offset.
    status = IntWinNetGetAddrFam(Buffer, Size, &off, Context);
    if (!INT_SUCCESS(status))
    {
        return status;
    }

    port = NET_BYTE_ORDER(*(const WORD *)(Buffer + off + 2));
    if (port != net->LocalPort)
    {
        return INT_STATUS_INVALID_DATA_TYPE;
    }

    net->State = introNetStateListening;

    *Offset += 2ull * gGuest.WordSize;

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntWinNetFillTcpStruct(
    _In_ const QWORD Gva,
    _Inout_updates_(Count) INT_STRUCT_INVARIANT *Invariants,
    _In_ size_t Count,
    _In_ DWORD PoolTag,
    _In_ BOOLEAN LogErrors,
    _Inout_ INTRONET_ENDPOINT *Endpoint
    )
///
/// @brief          Wrapper over #IntStructFill to map a guest page and perform the search
///                 there.
///
/// @param[in]      Gva         Gva from where to start searching.
/// @param[in,out]  Invariants  Invariants to be applied in order to search/fill the structure.
/// @param[in]      Count       Number of invariants to apply.
/// @param[in]      PoolTag     Pool tag of the allocation in where we'll search for the structure.
/// @param[in]      LogErrors   Set to TRUE if the function shoud log the errors it encounters.   
/// @param[in,out]  Endpoint    Pointer to a caller allocated (and initialized) structure to be filled.
///
/// @returns  #INT_STATUS_SUCCESS if successful, or an appropriate #INTSTATUS error value.
///
{
    QWORD alignedAddr;
    const POOL_HEADER *ph;
    BYTE *map;
    size_t sz, originalOffset;
    ssize_t offset;
    INTSTATUS status;

    if (!IS_KERNEL_POINTER_WIN(gGuest.Guest64, Gva))
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (NULL == Invariants)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    if (0 == Count || Count > INT_STRUCT_MAX_INVARIANT_CNT)
    {
        return INT_STATUS_INVALID_PARAMETER_3;
    }

    if (NULL == Endpoint)
    {
        return INT_STATUS_INVALID_PARAMETER_5;
    }

    alignedAddr = Gva & PAGE_MASK;
    originalOffset = ROUND_DOWN(Gva & PAGE_OFFSET, WIN_POOL_HEADER_SIZE);

    status = IntVirtMemMap(alignedAddr, PAGE_SIZE, gGuest.Mm.SystemCr3, 0, &map);
    if (!INT_SUCCESS(status))
    {
        return status;
    }

    ph = NULL;
    sz = 0;
    offset = originalOffset;
    while (offset >= 0)
    {
        DWORD tag, type;

        ph = (const POOL_HEADER *)((size_t)map + offset);

        tag = gGuest.Guest64 ? ph->Header64.PoolTag : ph->Header32.PoolTag;
        type = gGuest.Guest64 ? ph->Header64.PoolType : ph->Header32.PoolType;

        sz = gGuest.Guest64 ? ph->Header64.BlockSize : ph->Header32.BlockSize;
        sz *= WIN_POOL_BLOCK_SIZE;

        if (tag == PoolTag && offset + sz <= PAGE_SIZE && type == NonPagedPoolMustSucceed)
        {
            break;
        }

        offset -= WIN_POOL_HEADER_SIZE;
        ph = NULL;
    }

    if (NULL == ph)
    {
        status = INT_STATUS_NOT_FOUND;
        goto _exit;
    }

    if (offset + sz < originalOffset)
    {
        status = INT_STATUS_INVALID_OBJECT_TYPE;
        goto _exit;
    }
    
    status = IntStructFill(map + offset, sz, Invariants, Count, LogErrors, Endpoint);
    if (!INT_SUCCESS(status))
    {
        if (LogErrors)
        {
            IntDumpBuffer(map, alignedAddr, PAGE_SIZE, 16, 1, TRUE, TRUE);
        }
    }

_exit:

    IntVirtMemUnmap(&map);

    return status;
}


static INTSTATUS
IntWinNetGetTcpEndpoint(
    _In_ QWORD Gva,
    _Inout_ INTRONET_ENDPOINT *Endpoint
    )
///
/// @brief         Search for a TCP endpoint structure from a given address.
///
/// @param[in]      Gva         Address from where to begin searching.
/// @param[in, out] Endpoint    Pointer to a caller allocated structure to be filled.
///
/// @returns       #INT_STATUS_SUCCESS if successful, or an appropriate #INTSTATUS error value.
///
{
    INTSTATUS status;

    static BOOLEAN found = FALSE;
    static INT_STRUCT_INVARIANT invs[] =
    {
        {
            .Offset = INT_OFFSET_NOT_INITIALIZED,
            .Getter = IntWinNetGetAddrFam,
        },
        {
            .Offset = INT_OFFSET_NOT_INITIALIZED,
            .Getter = IntWinNetGetAddrInfo,
        },
        {
            .Offset = INT_OFFSET_NOT_INITIALIZED,
            .Getter = IntWinNetGetPortsAndState,
        },
        {
            .Offset = INT_OFFSET_NOT_INITIALIZED,
            .Getter = IntWinNetGetOwner,
        },
    };

    status = IntWinNetFillTcpStruct(Gva, invs, ARRAYSIZE(invs), POOL_TAG_TCPE, found, Endpoint);
    if (!INT_SUCCESS(status))
    {
        WARNING("[WARNING] Failed to fill endpoint from 0x%016llx: 0x%08x\n", Gva, status);
        if (!found)
        {
            for (size_t i = 0; i < ARRAYSIZE(invs); i++)
            {
                invs[i].Offset = INT_OFFSET_NOT_INITIALIZED;
            }
        }
    }
    else
    {
        found = TRUE;
    }

    return status;
}


static INTSTATUS
IntWinNetGetTcpListener(
    _In_ QWORD Gva,
    _Inout_ INTRONET_ENDPOINT *Endpoint
    )
///
/// @brief         Search for a tcp endpoint structure from a given address.
///
/// @param[in]     Gva         Address from where to begin searching.
/// @param[out]    Endpoint    Pointer to a caller allocate structure to be filled.
///
/// @returns       #INT_STATUS_SUCCESS if successful, or an appropriate #INTSTATUS error value.
///
{
    INTSTATUS status;

    static BOOLEAN found = FALSE;
    static INT_STRUCT_INVARIANT invs[] =
    {
        {
            .Offset = INT_OFFSET_NOT_INITIALIZED,
            .Getter = IntWinNetGetOwner,
        },

        {
            .Offset = INT_OFFSET_NOT_INITIALIZED,
            .Getter = IntWinNetGetListenerAddressInfo,
        },
    };

    status = IntWinNetFillTcpStruct(Gva, invs, ARRAYSIZE(invs), POOL_TAG_TCPL, found, Endpoint);
    if (!INT_SUCCESS(status))
    {
        WARNING("[WARNING] Failed to fill listener from 0x%016llx: 0x%08x\n", Gva, status);

        if (!found)
        {
            for (size_t i = 0; i < ARRAYSIZE(invs); i++)
            {
                invs[i].Offset = INT_OFFSET_NOT_INITIALIZED;
            }
        }
    }
    else
    {
        found = TRUE;
    }

    return status;
}


static INTSTATUS
IntWinNetIterateLinkedList(
    _In_ QWORD Gva,
    _In_ PFUNC_IntWinNetCallback Callback,
    _Inout_opt_ void *Context
    )
///
/// @brief         Iterate through a doubly linked list of tcpip!_TCP_ENDPOINT structures and invoke
///                the callback on each valid connection.
///
/// @param[in]     Gva       Address of the list head.
/// @param[in]     Callback  Function to be invoked on each valid connection.
/// @param[in,out] Context   Optional context for the callback, can be anything.
///
/// @returns       #INT_STATUS_SUCCESS on success, or an appropriate #INTSTATUS error value.
///
{

    INTSTATUS status;
    QWORD flink = 0;
    QWORD head = FIX_GUEST_POINTER(gGuest.Guest64, Gva);
    size_t iters = 0;

    status = IntKernVirtMemFetchWordSize(head, &flink);
    if (!INT_SUCCESS(status))
    {
        return status;
    }

    while (flink != head && iters++ < WINNET_LIST_ITERS_CAP)
    {
        QWORD old = flink;
        INTRONET_ENDPOINT net = { 0 };

        status = IntWinNetGetTcpEndpoint(flink, &net);
        if (!INT_SUCCESS(status))
        {
            WARNING("[WARNING] Failed to extract tcp endpoint from 0x%016llx: 0x%08x\n", flink, status);
            return status;
        }

        Callback(&net, Context);

        status = IntKernVirtMemFetchWordSize(old, &flink);
        if (!INT_SUCCESS(status))
        {
            WARNING("[WARNING] IntKernVirtMemFetchWordSize failed for 0x%016llx: 0x%08x\n", old, status);
            return status;
        }

        flink = FIX_GUEST_POINTER(gGuest.Guest64, flink);

        // don't trust the guest, this may be a moment when this endpoint is to
        // be removed from the linked list, so it's list entry will point to itself,
        // causing an infinite loop here.
        if (old == flink)
        {
            ERROR("[ERROR] Entry @ 0x%016llx points to itself\n", old);
            return INT_STATUS_SUCCESS;
        }
    }

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntWinNetParseTcpPartition(
    _In_ PFUNC_IntWinNetCallback Callback,
    _Inout_opt_ void *Context
    )
///
/// @brief         Iterate through the tcpip!PartitionTable and invoke the callback
///                on each found connection.
///
/// Will iterate through each tcpip!_PARTITION from the tcpip!PartitionTable.
///
/// Each entry has, as the first 3 elements, pointers to nt!_RTL_DYNAMIC_HASH_TABLE
/// structures. 
///
/// The first hash table contains tcpip!_TCP_ENDPOINT elements that we'll use
/// to extract active connections.
///
/// The second hasn table contains tcpip!_TCP_TIME_WAIT_ENDPOINT elements that we
/// ignore for now.
///
/// The Directory field in the hash table points to an array of 0x80 nt!_LIST_HEAD
/// elements so we'll simply iterate each non-empty list from there.
///
/// @param[in]     Callback  Function to be invoked on each valid connection.
/// @param[in,out] Context   Optional context for the callback, can be anything.
///
/// @returns       #INT_STATUS_SUCCESS on success, or an appropriate #INTSTATUS error value.
///
{
#define TCP_DIRECTORY_ENTRY_CNT     0x80
#define TCP_DIRECTORY_ENTRY_SIZE    (2ull * (gGuest.WordSize))
#define TCP_DIRECTORY_SIZE          (TCP_DIRECTORY_ENTRY_CNT * TCP_DIRECTORY_ENTRY_SIZE)

    for (DWORD i = 0; i < gWinNet.Partition.Count; i++)
    {
        QWORD ht, dir, addr;
        DWORD cnt, sz;
        INTSTATUS status;

        union
        {
            RTL_DYNAMIC_HASH_TABLE64 Ht64;
            RTL_DYNAMIC_HASH_TABLE32 Ht32;
        } tbl;

        addr = gWinNet.Partition.Table + (QWORD)i * gWinNet.Partition.Size + gGuest.WordSize;

        ht = 0;
        status = IntKernVirtMemFetchWordSize(addr, &ht);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntKernVirtMemFetchWordSize failed for 0x%016llx: 0x%08x\n",
                  addr, status);
            return status;
        }

        sz = gGuest.Guest64 ? sizeof(tbl.Ht64) : sizeof(tbl.Ht32);
        status = IntKernVirtMemRead(ht, sz, &tbl, NULL);
        if (!INT_SUCCESS(status))
        {
            continue;
        }

        dir = gGuest.Guest64 ? tbl.Ht64.Directory : tbl.Ht32.Directory;
        cnt = gGuest.Guest64 ? tbl.Ht64.NonEmptyBuckets : tbl.Ht32.NonEmptyBuckets;

        // don't iterate a directory with empty buckets.
        if (cnt == 0)
        {
            continue;
        }

        for (size_t j = 0; j < TCP_DIRECTORY_ENTRY_CNT; j++)
        {
            QWORD list = FIX_GUEST_POINTER(gGuest.Guest64, dir + j * TCP_DIRECTORY_ENTRY_SIZE);

            status = IntWinNetIterateLinkedList(list, Callback, Context);
            if (!INT_SUCCESS(status))
            {
                WARNING("[WARNING] IntWinNetIterateLinkedList failed: 0x%08x\n", status);
            }
        }

    }
#undef TCP_DIRECTORY_SIZE
#undef TCP_DIRECTORY_ENTRY_SIZE
#undef TCP_DIRECTORY_ENTRY_CNT

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntWinNetIterateSlinkedList(
    _In_ INTRONET_PORT Port,
    _In_ QWORD Gva,
    _In_ PFUNC_IntWinNetCallback Callback,
    _Inout_opt_ void *Context
    )
///
/// @brief         Iterate through a single linked list of tcpip endpoint structures and invoke
///                the callback on each valid connection.
///
/// @param[in]     Port     The port for which this function is called.
/// @param[in]     Gva      Address of the list head.
/// @param[in]     Callback Function to be invoked on each valid connection.
/// @param[in,out] Context  Optional context for the callback, can be anything.
///
/// @returns       #INT_STATUS_SUCCESS on success, or an appropriate #INTSTATUS error value.
///
{
// Pointers inside the InetPortAssignmentArray are not properly aligned. There may be some refcount bits
// or something. This is the mask Windows applies as well.
#define WINNET_CLEAN_PTR_MASK   ((QWORD)0xFFFFFFFFFFFFFFFCull)

    INTSTATUS status = INT_STATUS_SUCCESS;
    QWORD slist = Gva & WINNET_CLEAN_PTR_MASK;
    QWORD slistOld = 0;
    size_t iters = 0;

    while (IS_KERNEL_POINTER_WIN(gGuest.Guest64, slist) && slist != slistOld && iters++ < WINNET_LIST_ITERS_CAP)
    {
        INTRONET_ENDPOINT net = { .LocalPort = Port };

        status = IntWinNetGetTcpListener(slist, &net);
        if (INT_SUCCESS(status))
        {
            // We ignore errors here because we might have "dummy" endpoints active on this port.
            // We might want to look into those because we might not actually need to iterate the
            // TCP Partition if we can get to the "real" endpoints from here.

            Callback(&net, Context);
        }

        slistOld = slist;
        status = IntKernVirtMemFetchWordSize(slistOld, &slist);
        if (!INT_SUCCESS(status))
        {
            return status;
        }

        slist &= WINNET_CLEAN_PTR_MASK;
    }

    return status;

#undef WINNET_CLEAN_PTR_MASK
}


static INTSTATUS
IntWinNetParseTcpBitmap(
    _In_ PFUNC_IntWinNetCallback Callback,
    _Inout_opt_ void *Context
    )
///
/// @brief         Will iterate through the guest port bitmap and invoke the callback on each
///                valid connection.
///
/// Will iterate through the bitmap and consider each set bit's index a connection in listening
/// state whose local port is the index.
///
/// The port assignment array is an array of pointers to undocumented _INET_PORT_ASSIGNMENT_ARRAY
/// structures. These are indexed by the higher byte of the bit index word.
///
/// Each element of the type above contains an array of undocumented _INET_PORT_ASSIGNMENT structures.
/// This array is indexed via the lower byte of the bit index word.
///
/// The structure describe above containts a SLIST_HEAD whose entries are the listeners on this port.
///
/// @param[in]     Callback  Function to be invoked on each valid connection.
/// @param[in,out] Context   Optional context for the callback, can be anything.
///
/// @returns       #INT_STATUS_SUCCESS on success, or an appropriate #INTSTATUS error value.
///
{
    INTSTATUS status;
    DWORD sz = 0x10000;
    BITMASK *bts;
    size_t pasz, offListener, offPa;

    offListener = gGuest.WordSize;

    if (gGuest.OSVersion >= 19041)
    {
        pasz = gGuest.Guest64 ? 4ull * sizeof(QWORD) : 6ull * sizeof(DWORD);
        offPa = gGuest.Guest64 ? 3 * sizeof(QWORD) : 4 * sizeof(DWORD);
        offListener = 2 * sizeof(QWORD);
    }
    else if (gGuest.OSVersion >= 9600)
    {
        pasz = 3ull * gGuest.WordSize;
        offPa = gGuest.Guest64 ? 3 * sizeof(QWORD) : 4 * sizeof(DWORD);
    }
    else
    {
        pasz = 2ull * gGuest.WordSize;
        offPa = gGuest.Guest64 ? 4 * sizeof(QWORD) : 5 * sizeof(DWORD);
    }

    bts = BitMaskAlloc(sz);
    if (NULL == bts)
    {
        ERROR("[ERROR] BitMaskAlloc failed\n");
        return INT_STATUS_INSUFFICIENT_RESOURCES;
    }


    status = IntKernVirtMemRead(gWinNet.Bitmap.Buffer, sz / 8, bts->Bits, NULL);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemRead failed to read 0x%x bytes from 0x%016llx: 0x%08x\n",
              sz / 8, gWinNet.Bitmap.Buffer, status);
        goto _exit;
    }

    for (DWORD i = 1; i < sz; i++)
    {
#define TCP_PORT_ASSIGNMENT_ARRAY_INDEX(i)      (((i) >> 8) & 0xFF)
#define TCP_PORT_ASSIGNMENT_INDEX(i)            ((i) & 0xFF)

        QWORD addr = 0;
        QWORD arr = 0;
        QWORD pa = 0;
        QWORD listener = 0;

        if (!BitMaskTest(bts, i))
        {
            continue;
        }

        addr = gWinNet.Bitmap.PortAssignment + (QWORD)gGuest.WordSize * TCP_PORT_ASSIGNMENT_ARRAY_INDEX(i);
        status = IntKernVirtMemFetchWordSize(addr, &arr);
        if (!INT_SUCCESS(status))
        {
            continue;
        }

        arr += offPa;
        status = IntKernVirtMemFetchWordSize(arr, &pa);
        if (!INT_SUCCESS(status))
        {
            continue;
        }

        pa += pasz * TCP_PORT_ASSIGNMENT_INDEX(i) + offListener;
        status = IntKernVirtMemFetchWordSize(pa, &listener);
        if (!INT_SUCCESS(status))
        {
            continue;
        }

        status = IntWinNetIterateSlinkedList((INTRONET_PORT)i, listener, Callback, Context);
        if (!INT_SUCCESS(status))
        {
            WARNING("[WARNING] IntWinNetIterateSlinkedList failed: 0x%08x\n", status);
        }

#undef TCP_PORT_ASSIGNMENT_INDEX
#undef TCP_PORT_ASSIGNMENT_ARRAY_INDEX
    }

_exit:
    BitMaskFree(&bts);

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntWinNetCheckPartition(
    _In_reads_bytes_(Size) const BYTE *Buffer,
    _In_ size_t Size
    )
///
/// @brief         Check wether a buffer contains a valid undocumented 
///                tcpip!_PARTITION object.
///
/// Will check if the buffer contains 3 pointers, each to pointing in the
/// same page to nt!_RTL_DYNAMIC_HASH_TABLE structures. Will check for the
/// hash table structs simply by verifying that their allocation tag is
/// `THcT`.
///
/// @param[in]     Buffer   The buffer to be checked.
/// @param[in]     Size     Size in bytes of the buffer.
///
/// @returns       #INT_STATUS_SUCCESS on success, or an appropiate #INTSTATUS error value
///
{
    QWORD page;
    size_t sz;
    INTSTATUS status;

    // Describe the fist 3 elements of a tcpip!_PARTITION undocumented structure.
    // Each of those should pe pointers to some nt!_RTL_DYNAMIC_HASH_TABLE that
    // reside in the same page, with the THcT pool tag.
    const union _PARTITION
    {
        DWORD Part32[3];
        QWORD Part64[3];
    } *part = (const union _PARTITION *)Buffer;

    sz = gGuest.Guest64 ? sizeof(part->Part64) : sizeof(part->Part32);

    if (sz > Size)
    {
        return INT_STATUS_INVALID_DATA_SIZE;
    }

    page = (gGuest.Guest64 ? part->Part64[0] : part->Part32[0]) & PAGE_MASK;
    if (!IS_KERNEL_POINTER_WIN(gGuest.Guest64, page))
    {
        return INT_STATUS_INVALID_DATA_TYPE;
    }

    for (size_t i = 0; i < ARRAYSIZE(part->Part64); i++)
    {
        QWORD p = gGuest.Guest64 ? part->Part64[i] : part->Part32[i];
        DWORD ptag;

        if (i == 0)
        {
            if ((p - WIN_POOL_HEADER_SIZE) < page)
            {
                return INT_STATUS_INVALID_DATA_TYPE;
            }

            status = IntKernVirtMemFetchDword(p - WIN_POOL_HEADER_SIZE + 4, &ptag);
            if (!INT_SUCCESS(status))
            {
                return status;
            }

            if (ptag != POOL_TAG_TCHT)
            {
                return INT_STATUS_INVALID_OBJECT_TYPE;
            }
        }
        else
        {
            if ((p & PAGE_MASK) != page)
            {
                return INT_STATUS_INVALID_DATA_TYPE;
            }
        }

    }

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntWinNetFindTcpPartition(
    _In_ QWORD PartitionAddress,
    _In_ QWORD PartitionPointer
    )
///
/// @brief         Get tcpip!PartitionTable information from the guest and initialize
///                #gWinNet.
///
/// Will check if a given gva points to a valid undocumented tcpip!_PARTITION
/// using #IntWinNetCheckPartition.
///
/// From there, will iterate the page in search for a second one in order to
/// determine the size of the structure. The second entry in the partition table
/// will always be in the same page as the first one because there are 2 posiblities:
///     - the partition table is a small pool allocation, meaning that the whole
///       table resides in the same page.
///     - the partition table is a big pool allocation, meaning that it's page aligned
///       and, knowing that the size of a partition is smaller than page size, the second
///       entry is sure to be in the same page.
///
/// Next, find the valud inside tcpip!Partition count. This is a guest word just before
/// tcpip!PartitionTable on windows 8+, or the second WORD after the tcpip!PartitionTable
/// on older versions. It's size is also dependant on version, it may be a guest word or
/// a WORD.
///
/// @param[in]     PartitionAddress Gva of the possible partition table.
/// @param[in]     PartitionPointer Gva of the place in the `.data` of `tcpip.sys` from where
///                                 the first parameter was read.
///
/// @returns       #INT_STATUS_SUCCESS on success, or an appropiate #INTSTATUS error value.
///
{
    BYTE *map;
    QWORD addr;
    QWORD cnt;
    DWORD sz;
    DWORD off;
    INTSTATUS status;

    if (gWinNet.Partition.Found)
    {
        return INT_STATUS_ALREADY_INITIALIZED;
    }

    if (!IS_KERNEL_POINTER_WIN(gGuest.Guest64, PartitionAddress))
    {
        return INT_STATUS_INVALID_DATA_TYPE;
    }

    off = PartitionAddress & PAGE_OFFSET;
    if (ROUND_DOWN(off, gGuest.WordSize) != off)
    {
        return INT_STATUS_ALIGNMENT_INCONSISTENCY;
    }

    status = IntVirtMemMap(PartitionAddress & PAGE_MASK, PAGE_SIZE, gGuest.Mm.SystemCr3, 0, &map);
    if (!INT_SUCCESS(status))
    {
        return status;
    }

    // Check for a valid tcpip!_PARTITION.
    status = IntWinNetCheckPartition(map + off, PAGE_SIZE - off);
    if (!INT_SUCCESS(status))
    {
        goto _exit;
    }

    // Read the tcpip!PartitionCount value.
    addr = PartitionPointer;

    if (gGuest.OSVersion >= 19041)
    {
        sz = gGuest.WordSize;
        addr -= gGuest.WordSize;
    }
    else if (gGuest.OSVersion >= 9600)
    {
        sz = sizeof(DWORD);
        addr -= sizeof(DWORD);
    }
    else if (gGuest.OSVersion >= 9200)
    {
        sz = gGuest.WordSize;
        addr -= gGuest.WordSize;
    }
    else
    {
        sz = 2;
        addr += gGuest.WordSize + 2ull;
    }

    cnt = 0;
    status = IntKernVirtMemRead(addr, sz, &cnt, NULL);
    if (!INT_SUCCESS(status))
    {
        goto _exit;
    }

    if (cnt > TCPIP_MAX_PARTITION_CNT)
    {
        goto _exit;
    }

    if (cnt > 1)
    {
        // Search for the next partition to determine the size.
        status = INT_STATUS_NOT_FOUND;
        for (DWORD cur = off + 8 * gGuest.WordSize; cur < PAGE_SIZE; cur += gGuest.WordSize)
        {
            status = IntWinNetCheckPartition(map + cur, PAGE_SIZE - cur);
            if (INT_SUCCESS(status))
            {
                sz = cur - off;
                break;
            }
        }

        if (!INT_SUCCESS(status))
        {
            goto _exit;
        }
    }
    else
    {
        // We don't realy care for it's size if there's only one of them but set it just in case.
        sz = PAGE_SIZE - off;
    }

    IntDumpGvaEx(PartitionPointer - 8, 0x20, gGuest.Mm.SystemCr3, 16, 1, FALSE, TRUE);

    gWinNet.Partition.Table = PartitionAddress;
    gWinNet.Partition.Size = sz;
    gWinNet.Partition.Count = (DWORD)cnt;

    TRACE("[WINNET] Found tcpip!ParitionTable @ 0x%016llx pointing to"
          " 0x%016llx with %u elements of size 0x%x from 0x%016llx\n",
          PartitionAddress, gWinNet.Partition.Table, gWinNet.Partition.Count,
          gWinNet.Partition.Size, PartitionPointer);

    gWinNet.Partition.Found = TRUE;
    
    status = INT_STATUS_SUCCESS;

_exit:
    IntVirtMemUnmap(&map);

    return status;
}


static INTSTATUS
IntWinNetSearchForAlloc(
    _In_ QWORD Gva,
    _In_ DWORD Tag,
    _Out_ QWORD *Alloc
    )
///
/// @brief         Search for an allocation with given tag.
///
/// Will map the whole page containing the address and iterate through it,
/// treating it as an array of pointers, checking if any of those is pointing
/// to a small pool allocation with given tag.
/// Will only search starting from the given address untill the end of the
/// page.
///
/// @param[in]     Gva   Address from where to begin searching.
/// @param[in]     Tag   Pool tag of the allocation to be searched.
/// @param[out]    Alloc Will contain the address of the allocation.
///
{
    BYTE *map;
    QWORD aligned;
    DWORD off;
    INTSTATUS status;

    aligned = Gva & PAGE_MASK;
    off = ROUND_UP(Gva & PAGE_OFFSET, gGuest.WordSize);

    status = IntVirtMemMap(aligned, PAGE_SIZE, gGuest.Mm.SystemCr3, 0, &map);
    if (!INT_SUCCESS(status))
    {
        return status;
    }

    while (off < PAGE_SIZE)
    {
        QWORD addr = gGuest.Guest64 ? *(QWORD *)((size_t)map + off) :
                                      *(DWORD *)((size_t)map + off);
        DWORD tag;

        status = IntKernVirtMemFetchDword(addr - WIN_POOL_HEADER_SIZE + 4, &tag);
        if (INT_SUCCESS(status) && tag == Tag)
        {
            *Alloc = addr;
            goto _exit;
        }

        off += gGuest.WordSize;
    }

    status = INT_STATUS_NOT_FOUND;

_exit:
    IntVirtMemUnmap(&map);

    return status;
}


static INTSTATUS
IntWinNetGetTcpPortPoolFromCompartment(
    _In_ QWORD Gva,
    _Out_ QWORD *PortPool
    )
///
/// @brief         Get the address of a tcp port pool for windows RS1 and newer.
///
/// The tcp port pool is a big pool allocation, meaning that it will always
/// be page aligned.
///
/// Starting with RS1, we start from tcpip!TcpCompartmentSet, which is a small
/// pool allocation with tag InCS (InetCompartmentSet).
///
/// Next, search for an InetCompartment, which should be a small pool allocaiton
/// with tag InCo.
///
/// From there, search for a TcpCompartment, which is yet another small pool
/// allocation with tag TcCo.
///
/// The first pointer inside the TcpCompartment is the port pool.
///
/// @param[in]     Gva      Address from where to start searching.
/// @param[out]    PortPool Will contain the address of the tcp port pool.
///
/// @returns       #INT_STATUS_SUCCESS on success, or an appropriate #INTSTATUS error value.
///
{
    QWORD inetCmp, tcpCmp, pool;
    DWORD tag;
    INTSTATUS status;

    if (ROUND_DOWN(Gva, WIN_POOL_HEADER_SIZE) != Gva)
    {
        return INT_STATUS_ALIGNMENT_INCONSISTENCY;
    }

    status = IntKernVirtMemFetchDword(Gva - WIN_POOL_HEADER_SIZE + 4, &tag);
    if (!INT_SUCCESS(status) || POOL_TAG_INCS != tag)
    {
        return INT_STATUS_INVALID_OBJECT_TYPE;
    }

    status = IntWinNetSearchForAlloc(Gva, POOL_TAG_INCO, &inetCmp);
    if (!INT_SUCCESS(status))
    {
        return status;
    }

    status = IntWinNetSearchForAlloc(inetCmp, POOL_TAG_TCCO, &tcpCmp);
    if (!INT_SUCCESS(status))
    {
        return status;
    }

    pool = 0;
    status = IntKernVirtMemFetchWordSize(tcpCmp, &pool);
    if (!INT_SUCCESS(status))
    {
        return status;
    }

    if ((pool & PAGE_OFFSET) != 0)
    {
        return INT_STATUS_ALIGNMENT_INCONSISTENCY;
    }

    *PortPool = pool;

    return INT_STATUS_SUCCESS;
}



static INTSTATUS
IntWinNetGetTcpPortPool(
    _In_ QWORD Gva,
    _Out_ QWORD *PortPool
    )
///
/// @brief         Get the address of a tcp port pool for windows versions before
///                RS1.
///
/// The tcp port pool is a big pool allocation, meaning that it will always
/// be page aligned.
///
/// For windows versions before RS1, tcpip!PortPool is a global variable so
/// we check the Gva.
///
/// Now, the first port pool that we find might be the udp port pool, but we check
/// for that as follows:
///     - the tcp port pools first element is a pointer to the udp port pool.
///     - the udp port pools second element is a pointer to the tcp port pool.
///
/// @param[in]     Gva      Address from where to start searching.
/// @param[out]    PortPool Will contain the address of the tcp port pool.
///
/// @returns       #INT_STATUS_SUCCESS on success, or an appropriate #INTSTATUS error value.
///
{
    QWORD addr;
    INTSTATUS status;

    union
    {
        DWORD Ptr32[2];
        QWORD Ptr64[2];
    } ptrs;

    if ((Gva & PAGE_OFFSET) != 0)
    {
        return INT_STATUS_ALIGNMENT_INCONSISTENCY;
    }

    status = IntKernVirtMemRead(Gva, 2 * gGuest.WordSize, &ptrs, NULL);
    if (!INT_SUCCESS(status))
    {
        return status;
    }

    addr = gGuest.Guest64 ? ptrs.Ptr64[0] : ptrs.Ptr32[0];
    if (IS_KERNEL_POINTER_WIN(gGuest.Guest64, addr) && 
        (addr & PAGE_OFFSET) == 0)
    {
        *PortPool = Gva;
        return INT_STATUS_SUCCESS;
    }

    addr = gGuest.Guest64 ? ptrs.Ptr64[1] : ptrs.Ptr32[1];
    if (IS_KERNEL_POINTER_WIN(gGuest.Guest64, addr) &&
        (addr & PAGE_OFFSET) == 0)
    {
        *PortPool = addr;
        return INT_STATUS_SUCCESS;
    }

    return INT_STATUS_INVALID_OBJECT_TYPE;
}


static INTSTATUS
IntWinNetFindTcpBitmap(
    _In_ QWORD Gva,
    _In_ QWORD Addr
    )
///
/// @brief         Get tcpip!TcpPortPool information form the guest and
///                initialize #gWinNet.
///
/// Will check if any given Gva points to a port pool ( before RS1),
/// or an object that points to the port pool.
/// Will use #IntWinNetGetTcpPortPool or #IntWinNetGetTcpPortPoolFromCompartment
/// to get the propper address of the possible port pool.
/// Furthermore, will search for 3 specific fields inside the port pool,
/// namely the bitmap size, the bitmap, and a pointer to an array.
///
/// The size of the bitmap is always 0x10000, this is a size in bits, each
/// one describing a used port.
/// A pointer to the bitmap buffer is immediatley after, and the buffer is
/// in the same page as the port pool.
/// Next is an array of tcpip!_INET_PORT_ASSIGNMENT_ARRAY pointers. Each of
/// those are small pool allocations with tag InPA.
///
/// @param[in]     Gva    Gva of the possible partition table.
/// @param[in]     Addr   Gva of the place in the `.data` of `tcpip.sys` from where
///                       the first parameter was read.
/// 
/// @returns       #INT_STATUS_SUCCESS on success, or an appropriate #INTSTATUS error value.
///
{
    void *map;
    QWORD pool, sz, buf, pa;
    size_t i;
    DWORD tag;
    INTSTATUS status;

    if (gWinNet.Bitmap.Found)
    {
        return INT_STATUS_ALREADY_INITIALIZED;
    }

    if (gGuest.OSVersion > 10586)
    {
        status = IntWinNetGetTcpPortPoolFromCompartment(Gva, &pool);
    }
    else
    {
        status = IntWinNetGetTcpPortPool(Gva, &pool);
    }
    if (!INT_SUCCESS(status))
    {
        return status;
    }

    status = IntVirtMemMap(pool, PAGE_SIZE, gGuest.Mm.SystemCr3, 0, &map);
    if (!INT_SUCCESS(status))
    {
        return status;
    }

    buf = pa = 0;
    status = INT_STATUS_NOT_FOUND;
    for (i = 0; i < PAGE_SIZE - 2ull * gGuest.WordSize; i += gGuest.WordSize)
    {
        size_t p = (size_t)map + i;
        sz = gGuest.Guest64 ? ((QWORD *)p)[0] : ((DWORD *)p)[0];
        buf = gGuest.Guest64 ? ((QWORD *)p)[1] : ((DWORD *)p)[1];
        pa = gGuest.Guest64 ? ((QWORD *)p)[2] : ((DWORD *)p)[2];

        sz &= 0xFFFFFFFF;
        
        if (0x10000 == sz && IS_KERNEL_POINTER_WIN(gGuest.Guest64, buf) &&
            ((buf & PAGE_MASK) == (pool & PAGE_MASK)))
        {
            status = INT_STATUS_SUCCESS;
            break;
        }
    }

    if (!INT_SUCCESS(status))
    {
        goto _exit;
    }

    status = IntKernVirtMemFetchDword(pa - WIN_POOL_HEADER_SIZE + 4, &tag);
    if (!INT_SUCCESS(status) || POOL_TAG_INPA != tag)
    {
        status = INT_STATUS_INVALID_OBJECT_TYPE;
        goto _exit;
    }

    gWinNet.Bitmap.PortAssignment = pool + i + 2ull * gGuest.WordSize;
    gWinNet.Bitmap.Buffer = buf;

    TRACE("[WINNET] Found tcpip!TcpPortPool @ 0x%016llx, BitmapBuffer @ 0x%016llx, "
          "and port assignment array @ 0x%016llx from 0x%016llx:0x%016llx\n", pool,
          gWinNet.Bitmap.Buffer, gWinNet.Bitmap.PortAssignment, Gva, Addr);

    gWinNet.Bitmap.Found = TRUE;

    status = INT_STATUS_SUCCESS;

_exit:
    IntVirtMemUnmap(&map);

    return status;
}


static INTSTATUS
IntWinNetFindTcpObjects(
    void
    )
///
/// @brief         Iterate through the .data section of tcpip.sys and attempt to find the objects
///                that we need to initialize #gWinNet.
///
/// Will search for the bitmap in tcpip!TcpPortPool using #IntWinNetFindTcpBitmap in order
/// to extract listeners, and for tcpip!PartitionTable using #IntWinNetFindTcpPartition
/// for active connections.
///
/// @returns       #INT_STATUS_SUCCESS on success, or an appropriate #INTSTATUS error value.
///
{
    IMAGE_SECTION_HEADER sec;
    PKERNEL_DRIVER drv;
    DWORD objs;
    INTSTATUS status;

    if (gWinNet.Bitmap.Found && gWinNet.Partition.Found)
    {
        return INT_STATUS_ALREADY_INITIALIZED_HINT;
    }

    drv = IntDriverFindByName(u"tcpip.sys");
    if (NULL == drv)
    {
        ERROR("[ERROR] Failed to find `tcpip.sys`\n");
        return INT_STATUS_NOT_FOUND;
    }

    TRACE("[WINNET] tcpip.sys @ 0x%016llx\n", drv->BaseVa);

    status = IntPeGetSectionHeaderByName(drv->BaseVa, NULL, ".data", gGuest.Mm.SystemCr3, &sec);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Failed to find `.data` section in `tcpip.sys`: 0x%08x\n", status);
        return status;
    }

    objs = 0;
    for (size_t page = 0; page < ROUND_UP((size_t)sec.Misc.VirtualSize, PAGE_SIZE); page += PAGE_SIZE)
    {
        QWORD gva = drv->BaseVa + sec.VirtualAddress + page;
        void *map;

        status = IntVirtMemMap(gva, PAGE_SIZE, gGuest.Mm.SystemCr3, 0, &map);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntVirtMemMap failed for 0x%016llx: 0x%08x\n", gva, status);
            return status;
        }

        for (size_t i = 0; objs < 2 && i < PAGE_SIZE / gGuest.WordSize; i++)
        {
            QWORD ptr = gGuest.Guest64 ? ((QWORD *)map)[i] : ((DWORD *)map)[i];

            status = IntWinNetFindTcpPartition(ptr, gva + i * gGuest.WordSize);
            if (INT_SUCCESS(status))
            {
                objs++;
                continue;
            }

            status = IntWinNetFindTcpBitmap(ptr, gva + i * gGuest.WordSize);
            if (INT_SUCCESS(status))
            {
                objs++;
                continue;
            }
        }

        IntVirtMemUnmap(&map);

        if (objs == 2)
        {
            status = INT_STATUS_SUCCESS;
            break;
        }
    }

    return status;
}


static INTSTATUS
IntWinNetIterateConnections(
    _In_ PFUNC_IntWinNetCallback Callback,
    _Inout_opt_ void *Context
    )
///
/// @brief         Iterate through guest connections and invoke the callback on each one.
///
/// @param[in]     Callback Function to be invoked on each valid connection.
/// @param[in,out] Context  Optional context for the callback, can be anything.
///
/// @returns       #INT_STATUS_SUCCESS on success, or an appropriate #INTSTATUS error value.
///
{
    INTSTATUS status;

    status = IntWinNetFindTcpObjects();
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntWinNetFindTcpObjects failed ( 0x%016llx, 0x%016llx): 0x%08x\n", 
              gWinNet.Partition.Table, gWinNet.Bitmap.Buffer, status);
        return status;
    }

    status = IntWinNetParseTcpPartition(Callback, Context);
    if (!INT_SUCCESS(status))
    {
        WARNING("[WARNING] IntWinNetParseTcpPartition failed: 0x%08x\n", status);
    }

    status = IntWinNetParseTcpBitmap(Callback, Context);
    if (!INT_SUCCESS(status))
    {
        WARNING("[WARNING] IntWinNetParseTcpBitmap failed: 0x%08x\n", status);
    }

    return status;
}


_Function_class_(PFUNC_IntWinNetCallback) static INTSTATUS
IntWinNetSendConnectionEvent(
    _In_ const INTRONET_ENDPOINT *Endpoint,
    _Inout_opt_ void *Context
    )
///
/// @brief         Send a connection event.
///
/// Will only send connections whose owner is the process described by the context.
///
/// @param[in]     Endpoint Connection to send.
/// @param[in,out] Context  Will be a pointer to a #WIN_PROCESS_OBJECT.
///
/// @returns       #INT_STATUS_SUCCESS on success, or an appropriate #INTSTATUS error value.
///
{
    INTSTATUS status;
    EVENT_CONNECTION_EVENT *evt = &gAlert.Connection;
    const WIN_PROCESS_OBJECT *proc = (WIN_PROCESS_OBJECT *)Context;

    if (proc != Endpoint->OwnerProcess)
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    IntAlertFillConnection(Endpoint, evt);

    status = IntNotifyIntroEvent(introEventConnectionEvent, evt, sizeof(*evt));
    if (!INT_SUCCESS(status))
    {
        WARNING("[WARNING] IntNotifyIntroEvent failed: 0x%08x\n", status);
    }

    return status;
}


INTSTATUS
IntWinNetSendProcessConnections(
    _In_ WIN_PROCESS_OBJECT *Process
    )
///
/// @brief         Send connection events for all active connections whose owner is
///                the given process.
///
/// @param[in]     Process  The process whose connections to send.
///
/// @returns #INT_STATUS_SUCCESS on success, or an appropriate #INTSTATUS error value.
///
{
    if (!(gGuest.CoreOptions.Current & INTRO_OPT_EVENT_CONNECTIONS))
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    return IntWinNetIterateConnections(IntWinNetSendConnectionEvent, Process);
}


_Function_class_(PFUNC_IntWinNetCallback) static INTSTATUS
IntWinNetDumpConnection(
    _In_ const INTRONET_ENDPOINT *Endpoint,
    _Inout_opt_ void *Context
    )
///
/// @brief         Log a connection.
///
/// @param[in]     Endpoint Connection to log.
/// @param[in,out] Context  Not used.
///
/// @retval        #INT_STATUS_SUCCESS      On success.
///
{
    char local[INTRONET_MIN_BUFFER_SIZE] = { 0 };
    char remote[INTRONET_MIN_BUFFER_SIZE] = { 0 };

    UNREFERENCED_PARAMETER(Context);

    IntNetAddrToStr(Endpoint->AddressFamily, &Endpoint->LocalAddress, local);
    IntNetAddrToStr(Endpoint->AddressFamily, &Endpoint->RemoteAddress, remote);

    LOG("[WINNET] Endpoint @ 0x%016llx Local %s:%d Remote %s:%d State %s Owner 0x%016llx (%s:%u)\n",
        Endpoint->Endpoint, local, Endpoint->LocalPort, remote, Endpoint->RemotePort,
        IntNetStateToString(Endpoint->State), Endpoint->Endpoint,
        Endpoint->OwnerProcess->Name, Endpoint->OwnerProcess->Pid);

    return INT_STATUS_SUCCESS;
}


//
// IntWinNetDumpConnections
//
INTSTATUS
IntWinNetDumpConnections(
    void
    )
///
/// @brief         Dump all active guest connections.
///
/// @returns       #INT_STATUS_SUCCESS on success, or an appropriate #INTSTATUS error value.
///
{
    return IntWinNetIterateConnections(IntWinNetDumpConnection, NULL);
}

