/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include <windows.h>
#include <stdio.h>


#ifndef QWORD
#define QWORD unsigned long long
#endif

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status)                  (((NTSTATUS)(Status)) >= 0)
#endif

#include "intro_types.h"

#ifndef MIN
#define MIN(a, b)                   ((a) < (b) ? (a) : (b))
#endif // !MIN


#define ONE_SECOND_IN_MS                1000


BOOLEAN
Taskkill(
    _In_ PWCHAR ImageName,
    _In_ DWORD Pid,
    _In_ BOOLEAN Force
    )
{
    WCHAR cmdLine[MAX_PATH] = { 0 };
    STARTUPINFO info = { 0 };
    PROCESS_INFORMATION procInfo = { 0 };
    BOOLEAN result = TRUE;

    if (!Force)
    {
        _snwprintf_s(cmdLine, sizeof(cmdLine),
            L"taskkill.exe /FI \"IMAGENAME eq %s\" /FI \"PID eq %d\" /T",
            ImageName, Pid);
    }
    else
    {
        _snwprintf_s(cmdLine, sizeof(cmdLine),
            L"taskkill.exe /FI \"IMAGENAME eq %s\" /FI \"PID eq %d\" /T /F",
            ImageName, Pid);
    }

    if (!CreateProcess(NULL, cmdLine, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &info, &procInfo))
    {
        printf("[ERROR] CreateProcess failed: 0x%08x\n", GetLastError());
        result = FALSE;
    }
    else
    {
        DWORD exitCode = 0;

        WaitForSingleObject(procInfo.hProcess, ONE_SECOND_IN_MS);
        if (!GetExitCodeProcess(procInfo.hProcess, &exitCode))
        {
            printf("[ERROR] GetExitCodeProcess failed: 0x%08x\n", GetLastError());
            result = FALSE;
        }
        else if (0 != exitCode)
        {
            printf("[INFO] `taskkill` exited with: %d\n", exitCode);
            result = FALSE;
        }

        CloseHandle(procInfo.hProcess);
        CloseHandle(procInfo.hThread);
    }

    return result;
}


#ifdef NDEBUG
int CALLBACK WinMain(
    _In_ HINSTANCE hInstance,
    _In_ HINSTANCE hPrevInstance,
    _In_ LPSTR     lpCmdLine,
    _In_ int       nCmdShow
    )
#else
int wmain(
    int argc,
    WCHAR **argv
    )
#endif // NDEBUG
{
    PWCHAR *pArgvW;
    INT32 err = 0;

#ifdef NDEBUG
    INT32 argc = 0;

    UNREFERENCED_PARAMETER(hInstance);
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(nCmdShow);
    UNREFERENCED_PARAMETER(lpCmdLine);

    pArgvW = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (NULL == pArgvW)
    {
        goto cleanup_and_exit;
    }
#else
    pArgvW = (PWCHAR *)argv;
#endif

    if (argc <= 1)
    {
        goto cleanup_and_exit;
    }

    if (argc % 2 == 0)
    {
        printf("[ERROR] Invalid number of arguments!\n");
        err = -1;
        goto cleanup_and_exit;
    }

    // parse the <name, pid> pairs
    for (INT32 i = 1; i < argc; i += 2)
    {
        PWCHAR pTargetName = pArgvW[i];
        DWORD pid = wcstoul(pArgvW[i + 1], NULL, 0);
        HANDLE hProc = OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (NULL == hProc)
        {
            printf("[ERROR] OpenProcess failed for `%S` (%d): 0x%08x\n", pTargetName, pid, GetLastError());
            continue;
        }

        WCHAR name[MAX_PATH] = { 0 };
        DWORD nameSize = sizeof(name);

        if (!QueryFullProcessImageName(hProc, 0, name, &nameSize))
        {
            printf("[ERROR] QueryFullProcessImageName failed: 0x%08x\n", GetLastError());
            CloseHandle(hProc);
            continue;
        }

        INT32 j = (INT32)wcslen(name) - 1;
        for (; j >= 0; j--)
        {
            if (name[j] == L'\\')
            {
                j++;
                break;
            }
        }

        if (!_wcsnicmp(&name[j], pTargetName, MIN(wcslen(&name[j]), MIN(15, wcslen(pTargetName)))))
        {
            BOOLEAN bForce = FALSE;

            if (!Taskkill(pTargetName, pid, FALSE))
            {
                printf("[ERROR] taskkill failed for `%S` (%d), will do a forced taskkill...\n",
                    pTargetName, pid);

                if (!Taskkill(pTargetName, pid, TRUE))
                {
                    printf("[ERROR] forced taskkill failed for `%S` (%d), will do a `TerminateProcess`...\n",
                        pTargetName, pid);

                    bForce = TRUE;
                }
            }

            if (bForce)
            {
                if (!TerminateProcess(hProc, (UINT)-1))
                {
                    printf("[ERROR] TerminateProcess failed: 0x%08x\n", GetLastError());
                }
                else
                {
                    printf("[INFO] Process `%S` (%d) was terminated!\n", pTargetName, pid);
                    WaitForSingleObject(hProc, 3 * ONE_SECOND_IN_MS);
                }
            }
        }
        else
        {
            printf("[INFO] Skipping process %d. Expecting `%S`, but got `%S`\n", pid, pTargetName, &name[j]);
        }

        CloseHandle(hProc);
    }

    SetLastError(ERROR_SUCCESS);

cleanup_and_exit:
#ifndef NDEBUG
    getchar();
#endif // !NDEBUG

    return err;
}
