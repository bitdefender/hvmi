#include <ntifs.h>
#include "introbootdrv_types.h"
#include "hypercall.h"
#include "loader.h"
#include "unexported.h"

// 64 KB of buffer
#define DEPLOY_BUFER_SIZE       (1024 * 64)

#pragma section("ENTRYP", read, execute, nopage)
#pragma section("BUFFER", read, write, nopage)

/// Important note: for some reason, the compiler will generate 16 nulls before the ENTRYP section code... I don't know
/// why for now, and I don't know how to disable that. For know, intro will just pass control to ENTRYP+16.
NTSTATUS
RealEntryPoint(
    void *Arg1,
    void *Arg2
    );

#pragma alloc_text("ENTRYP", RealEntryPoint)

#include "stubs.h"

#define MAX_PATH_LEN        128
#define MIN_PAYLOAD_SPACE   (AGENT_MAX_AGENT_NAME_LENGTH + 2 + AGENT_MAX_AGENT_NAME_LENGTH + AGENT_MAX_COMMAND_LINE_LENGTH)

WCHAR gAgentPath[MAX_PATH_LEN] = L"\\SystemRoot\\System32\\";

AGENT_COMMAND gAgentCmd;

__declspec(allocate("BUFFER"))
BYTE *gBuffer, gBackupBuffer[8192];


//
// IremDrvStoreNameInPath
//
BOOLEAN
IremDrvStoreNameInPath(
    void
    )
{
    SIZE_T wlen = wcslen(gAgentPath);
    SIZE_T slen = strlen(gAgentCmd.Name);

    // Store the name inside the path.
    for (SIZE_T i = 0; i < slen; i++)
    {
        if (wlen >= MAX_PATH_LEN)
        {
            return FALSE;
        }

        gAgentPath[wlen++] = (WCHAR)gAgentCmd.Name[i];
    }

    return TRUE;
}


//
// IremDrvInjectFile
//
NTSTATUS
IremDrvInjectFile(
    _In_ PUNICODE_STRING Path
    )
{
    HANDLE handle;
    OBJECT_ATTRIBUTES objAttr;
    NTSTATUS status;
    IO_STATUS_BLOCK ioStatusBlock;
    DWORD bufferSize;
    SIZE_T result;

    if (NULL == Path)
    {
        return STATUS_INVALID_PARAMETER_1;
    }

    DbgPrint("Creating file %wZ...\n", Path);

    InitializeObjectAttributes(&objAttr, Path, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    status = ZwCreateFile(&handle,
                          GENERIC_WRITE,
                          &objAttr,
                          &ioStatusBlock,
                          NULL,
                          FILE_ATTRIBUTE_NORMAL,
                          0,
                          FILE_SUPERSEDE,
                          FILE_SYNCHRONOUS_IO_NONALERT,
                          NULL,
                          0);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("ZwCreateFile failed: 0x%08x\n", status);
        goto cleanup_and_exit;
    }

    gBuffer = ExAllocatePoolWithTag(NonPagedPool, DEPLOY_BUFER_SIZE, IREM_TAG_DEPL_BUFFER);
    if (NULL == gBuffer)
    {
        DbgPrint("ExAllocatePoolWithTag failed, will use the backup buffer\n");

        bufferSize = sizeof(gBackupBuffer);

        gBuffer = gBackupBuffer;
    }
    else
    {
        bufferSize = DEPLOY_BUFER_SIZE;
    }
    
    DbgPrint("Writing content, file handle %018p\n", handle);

    while ((result = Hypercall(bufferSize, gBuffer, AGENT_HCALL_FETCH_CHUNK)) != 0)
    {
        if (HYPERCALL_EXCEPTION == result)
        {
            status = STATUS_UNHANDLED_EXCEPTION;
            DbgPrint("Error occurred during hypercall\n");
            goto cleanup_and_exit;
        }

        status = ZwWriteFile(handle,
                             NULL,
                             NULL,
                             NULL,
                             &ioStatusBlock,
                             gBuffer,
                             (DWORD)result,
                             0,
                             NULL);
        if (!NT_SUCCESS(status))
        {
            DbgPrint("ZwWriteFile failed: 0x%08x, handle %018p\n", status, handle);
            goto cleanup_and_exit;
        }
    }

cleanup_and_exit:
    if ((NULL != gBuffer) && (gBuffer != gBackupBuffer))
    {
        ExFreePoolWithTag(gBuffer, IREM_TAG_DEPL_BUFFER);

        gBuffer = NULL;
    }

    if (NULL != handle)
    {
        ZwClose(handle);
    }

    return status;
}

//
// IremDrvHandleFile
//
NTSTATUS
IremDrvHandleFile(
    void
    )
{
    NTSTATUS status;
    UNICODE_STRING filePath = { 0 };

    if (!IremDrvStoreNameInPath())
    {
        DbgPrint("IremDrvStoreNameInPath failed\n");
        return STATUS_NOT_SUPPORTED;
    }

    DbgPrint("Injecting agent file '%s' to '%S'...\n", gAgentCmd.Name, gAgentPath);

    RtlInitUnicodeString(&filePath, gAgentPath);

    status = IremDrvInjectFile(&filePath);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("IremDrvInjectFile failed: 0x%08x\n", status);
        goto cleanup_and_exit;
    }

    DbgPrint("Successfully injected file %Z\n", &filePath);
    // All good!
    status = STATUS_SUCCESS;

cleanup_and_exit:

    return status;
}


//
// IremDrvCreateProcess
//
NTSTATUS
IremDrvCreateProcess(
    _In_ void *ParentPid
    )
{
    OBJECT_ATTRIBUTES obj;
    HANDLE proc = NULL;
    HANDLE thread = NULL;
    CLIENT_ID cid = { 0 };
    void *buf = NULL;
    NTSTATUS status;
    SIZE_T size = USER_MODE_PROC_CODE_SIZE;
    ULONG old;

    InitializeObjectAttributes(&obj, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

    cid.UniqueProcess = (HANDLE)ParentPid;
    cid.UniqueThread = NULL;

    DbgPrint("Opening process %d\n", ParentPid);
    status = ZwOpenProcess(&proc, PROCESS_ALL_ACCESS, &obj, &cid);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("ZwOpenProcess failed: 0x%08x\n", status);
        goto cleanup_and_exit;
    }

    status = ZwAllocateVirtualMemory(proc, &buf, 0, &size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("ZwAllocateVirtualMemory failed: 0x%08x\n", status);
        goto cleanup_and_exit;
    }

#ifndef AMD64
    *(DWORD *)(gUserModeProcCode + RELOC_OFFSET) = ((DWORD)buf);
#endif

    status = ZwWriteVirtualMemory(proc, buf, gUserModeProcCode, (ULONG)size, NULL);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("ZwWriteVirtualMemory failed: 0x%08x\n", status);
        goto cleanup_and_exit;
    }

    status = ZwProtectVirtualMemory(proc, &buf, (PULONG)&size, PAGE_EXECUTE_READ, &old);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("ZwProtectVirtualMemory failed: 0x%08x\n", status);
        goto cleanup_and_exit;
    }

    InitializeObjectAttributes(&obj, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

    DbgPrint("Creating remote thread\n");
    status = ZwCreateThreadEx(&thread, THREAD_ALL_ACCESS, &obj, proc, buf, NULL, 0, 0, 0, 0, NULL);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("ZwCreateThreadEx failed: 0x%08x\n", status);
        goto cleanup_and_exit;
    }

cleanup_and_exit:
    if (NULL != thread)
    {
        ZwClose(thread);
    }

    if (NULL != proc)
    {
        if (NULL != buf && !NT_SUCCESS(status))
        {
            ZwFreeVirtualMemory(proc, &buf, &size, MEM_RELEASE);
        }

        ZwClose(proc);
    }

    return status;
}



//
// IremDrvHandleProcess
//
NTSTATUS
IremDrvHandleProcess(
    void
    )
{
    UNICODE_STRING filePath = { 0 };
    SIZE_T argsOffset;
    NTSTATUS status;

    if (!IremDrvStoreNameInPath())
    {
        DbgPrint("IremDrvStoreNameInPath failed\n");
        return STATUS_NOT_SUPPORTED;
    }

    DbgPrint("Injecting agent file '%s' with id %d to '%S'\n", gAgentCmd.Name, gAgentCmd.Agid, gAgentPath);

    RtlInitUnicodeString(&filePath, gAgentPath);

    // Zero-out the padding used to hold the agent name & arguments.
    memset(&gUserModeProcCode[NAME_OFFSET], 0, USER_MODE_PROC_CODE_SIZE - NAME_OFFSET);

    // This is safe. Note that we save our file in %windir%\system32. An application can't write that directory unless
    // it is privileged. According to MSDN, the CreateProcess function searches first in the directory where the parent
    // process resides (the directory from which the application loaded.). That directory is %windir%\system32,
    // because we inject our thread inside a winlogon.exe session. Therefore, privilege escalation is not possible.
    memcpy(&gUserModeProcCode[NAME_OFFSET], gAgentCmd.Name, strlen(gAgentCmd.Name));

    argsOffset = NAME_OFFSET + (DWORD)strlen(gAgentCmd.Name) + 1;

    // Now copy the name again and prepare the command line.
    memcpy(&gUserModeProcCode[argsOffset], gAgentCmd.Name, strlen(gAgentCmd.Name));

    argsOffset += strlen(gAgentCmd.Name);

    // Put a space.
    gUserModeProcCode[argsOffset++] = 0x20;

    memcpy(&gUserModeProcCode[argsOffset], gAgentCmd.Args, sizeof(gAgentCmd.Args));

    *((DWORD*)(&gUserModeProcCode[AGID_OFFSET])) = gAgentCmd.Agid;

    status = IremDrvInjectFile(&filePath);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("IremDrvInjectFile failed: 0x%08x\n", status);
        goto _exit;
    }

    DbgPrint("Successfully injected file %Z\n", &filePath);

    status = IremDrvCreateProcess((void *)(SIZE_T)gAgentCmd.Pid);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("IremDrvCreateProcess failed: 0x%08x\n", status);
        goto _exit;
    }

    DbgPrint("Successfully started agent!\n");

    // All good!
    status = STATUS_SUCCESS;
_exit:

    return status;
}


//
// IremDrvHandleDriverLoader
//
NTSTATUS
IremDrvHandleDriverLoader(
    _In_ ULONG DriverPoolTag,
    _In_ DWORD DriverHypercall
    )
{
    DWORD size = gAgentCmd.Size;
    PBYTE drv;

    // Allocate space for the driver image.
    drv = ExAllocatePoolWithTag(NonPagedPoolExecute, size, DriverPoolTag);
    if (NULL == drv)
    {
        DbgPrint("ExAllocatePoolWithTag failed for %d bytes!\n", size);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Fetch the content.
    Hypercall(size, drv, DriverHypercall);

    return STATUS_SUCCESS;
}


//
// IremDrvHandleDriverUnloader
//
NTSTATUS
IremDrvHandleDriverUnloader(
    _In_ ULONG DriverPoolTag,
    _In_ DWORD DriverHypercall
    )
{
    PBYTE drv;

    drv = (PBYTE)(SIZE_T)gAgentCmd.Pointer;
    if (NULL == drv)
    {
        return STATUS_INVALID_DEVICE_STATE;
    }

    while (0 != Hypercall(0, drv, DriverHypercall));

    if (NULL != drv)
    {
        ExFreePoolWithTag(drv, DriverPoolTag);
    }

    return STATUS_SUCCESS;
}


//
// DriverEntry
//
NTSTATUS __stdcall
DriverEntry(
    void *Unused1,
    void *Unused2
    )
{
    NTSTATUS status;
    SIZE_T result;

    UNREFERENCED_PARAMETER(Unused1);
    UNREFERENCED_PARAMETER(Unused2);

    status = STATUS_SUCCESS;

    // Sanity check.
#if (USER_MODE_PROC_CODE_SIZE - NAME_OFFSET < MIN_PAYLOAD_SPACE)
#error "Payload slack space is too small!\n"
#endif

    // Fetch the injection parameters.
    memset(&gAgentCmd, 0, sizeof(gAgentCmd));

    gAgentCmd.Version = AGENT_COMMAND_VERSION;

    result = Hypercall((DWORD)sizeof(gAgentCmd), (PBYTE)&gAgentCmd, AGENT_HCALL_FETCH_CMD);
    if (0 != result)
    {
        status = STATUS_NOT_SUPPORTED;
        DbgPrint("Failed fetching the agent command!\n");
        goto _exit;
    }

    if (AGENT_TYPE_FILE == gAgentCmd.Type)
    {
        status = IremDrvHandleFile();
    }
    else if (AGENT_TYPE_PROCESS == gAgentCmd.Type)
    {
        status = IremDrvHandleProcess();
    }
    else if (AGENT_TYPE_VE_LOADER == gAgentCmd.Type)
    {
        status = IremDrvHandleDriverLoader(IREM_TAG_VE_AGENT, AGENT_HCALL_VE);
    }
    else if (AGENT_TYPE_VE_UNLOADER == gAgentCmd.Type)
    {
        status = IremDrvHandleDriverUnloader(IREM_TAG_VE_AGENT, AGENT_HCALL_VE);
    }
    else if (AGENT_TYPE_PT_LOADER == gAgentCmd.Type)
    {
        status = IremDrvHandleDriverLoader(IREM_TAG_PT_AGENT, AGENT_HCALL_PT);
    }
    else if (AGENT_TYPE_PT_UNLOADER == gAgentCmd.Type)
    {
        status = IremDrvHandleDriverUnloader(IREM_TAG_PT_AGENT, AGENT_HCALL_PT);
    }
    else
    {
        status = STATUS_NOT_SUPPORTED;
    }

_exit:
    // Report the error code.
    Hypercall(status, 0, AGENT_HCALL_ERROR);

    return status;
}


//
// RealEntryPoint
//
NTSTATUS __stdcall
RealEntryPoint(
    void *Arg1,
    void *Arg2
    )
{
    // Fix my imports. BIG NOTE: This must be the first function called!!!
    if (!LdrFixMyImports())
    {
        return STATUS_FAILED_DRIVER_ENTRY;
    }

    // Find all kernel syscall linkage addresses that we need.
    if (!NT_SUCCESS(UexFindFunctions()))
    {
        return STATUS_FAILED_DRIVER_ENTRY;
    }

    return DriverEntry(Arg1, Arg2);
}
