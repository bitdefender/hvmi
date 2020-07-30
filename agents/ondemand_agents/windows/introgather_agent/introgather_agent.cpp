/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */

#include "stdafx.h"
#include <windows.h>
#include <UserEnv.h>

#pragma comment(lib, "Userenv.lib")


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

extern "C" {
#ifdef AMD64
    void
        IntroCall64(
        __in PAGENT_LGT_EVENT Message,
        __in DWORD Hcall
        );
#else
    void __cdecl
        IntroCall32(
        __in PAGENT_LGT_EVENT Message,
        __in DWORD Hcall
        );
#endif // AMD64
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
    HANDLE hFile, hFind;
    WIN32_FIND_DATA fData;
    PWCHAR *pArgvW;
    WCHAR tmpPath[MAX_PATH], dirPath[MAX_PATH], *fname;
    PAGENT_LGT_EVENT pData;
    DWORD fSize, dwRead;
    size_t i;
    int ret;
    bool deleteFiles = false;

    hFile = NULL;
    hFind = NULL;
    pData = NULL;
    pArgvW = NULL;
    fSize = 0;
    dwRead = 0;
    ret = -1;
    memset(&fData, 0, sizeof(fData));

    // Allocate the structure.
    pData = (PAGENT_LGT_EVENT)VirtualAlloc(NULL, sizeof(AGENT_LGT_EVENT), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (NULL == pData)
    {
        printf("[ERROR] Could not alloc memory: 0x%08x\n", GetLastError());
        goto cleanup_and_exit;
    }

    if (!VirtualLock(pData, sizeof(AGENT_LGT_EVENT)))
    {
        printf("[ERROR] Could not lock memory: 0x%08x\n", GetLastError());
        goto cleanup_and_exit;
    }

    pData->Header.Version = LGT_EVENT_VERSION;
    pData->Header.Size = LGT_EVENT_SIZE;

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

    if (argc != 2 && argc != 3)
    {
        goto cleanup_and_exit;
    }

    fname = NULL;

    for (INT32 j = 1; j < argc; j++)
    {
        if (wcslen(pArgvW[j]) == 7
            && !wcscmp(pArgvW[j], L"-rmlogs"))
        {
            deleteFiles = true;
        }
        else
        {
            // Make sure the provided argument does not exceed the MAX_PATH.
            if (wcslen(pArgvW[j]) >= MAX_PATH)
            {
                printf("[ERROR] Cannot accept a path longer than MAX_PATH!\n");
                goto cleanup_and_exit;
            }

            wcscpy_s(tmpPath, MAX_PATH, pArgvW[j]);

            i = wcslen(tmpPath);
            while (i > 0 && tmpPath[i] != L'\\' && tmpPath[i] != L'/')
            {
                i--;
            }

            if (i != 0)
            {
                tmpPath[i + 1] = 0;
                fname = &pArgvW[j][i + 1];
            }
            else
            {
                fname = pArgvW[j];
            }
        }
    }

    if (NULL == fname)
    {
        printf("[ERROR] No path provided!\n");
        goto cleanup_and_exit;
    }

    if (!ExpandEnvironmentStringsForUser(NULL, tmpPath, dirPath, MAX_PATH))
    {
        printf("[ERROR] ExpandEnvironmentStringsForUser failed: 0x%08x\n", GetLastError());
        goto cleanup_and_exit;
    }

    if (!SetCurrentDirectory(dirPath))
    {
        printf("[ERROR] SetCurrentDirectory failed: 0x%08x\n", GetLastError());
        goto cleanup_and_exit;
    }

    hFind = FindFirstFileW(fname, &fData);
    if (INVALID_HANDLE_VALUE == hFind)
    {
        printf("[ERROR] No files matching the pattern found: 0x%08x\n", GetLastError());
        goto cleanup_and_exit;
    }

    pData->Header.EventType = lgtEventData;

    do
    {
        DWORD fileAttr = GetFileAttributesW(fData.cFileName);
        if (INVALID_FILE_ATTRIBUTES == fileAttr)
        {
            printf("[ERROR] Could not open file: 0x%08x\n", GetLastError());
            goto cleanup_and_exit;
        }

        if (fileAttr & FILE_ATTRIBUTE_DIRECTORY)
        {
            continue;
        }

        memset(&pData->DataEvent, 0, sizeof(pData->DataEvent));

        hFile = CreateFileW(fData.cFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (INVALID_HANDLE_VALUE == hFile)
        {
            printf("[ERROR] Could not open file: 0x%08x\n", GetLastError());
            goto cleanup_and_exit;
        }

        memcpy(pData->DataEvent.FileName, fData.cFileName, MIN(sizeof(pData->DataEvent.FileName), sizeof(fData.cFileName)));

        fSize = GetFileSize(hFile, NULL);
        while (fSize)
        {
            pData->DataEvent.DataSize = MIN(LGT_MAX_DATA_SIZE, fSize);

            if (!ReadFile(hFile, pData->DataEvent.Data, pData->DataEvent.DataSize, &dwRead, NULL))
            {
                printf("[ERROR] Could not read file: 0x%08x\n", GetLastError());
                goto cleanup_and_exit;
            }

            fSize -= pData->DataEvent.DataSize;

        #ifdef AMD64
            IntroCall64(pData, AGENT_HCALL_GATHER_TOOL);
        #else
            IntroCall32(pData, AGENT_HCALL_GATHER_TOOL);
        #endif
        }

        CloseHandle(hFile);

        if (deleteFiles)
        {
            if (fileAttr & FILE_ATTRIBUTE_READONLY)
            {
                if (!SetFileAttributesW(fData.cFileName, fileAttr & (~FILE_ATTRIBUTE_READONLY)))
                {
                    printf("[ERROR] Could not remove RO attribute: 0x%08x\n", GetLastError());
                    continue;
                }
            }

            if (!DeleteFileW(fData.cFileName))
            {
                printf("[ERROR] Could not delete file: 0x%08x\n", GetLastError());
                continue;
            }
        }
    } while (FindNextFile(hFind, &fData));

    ret = 0;

    SetLastError(ERROR_SUCCESS);

cleanup_and_exit:
    if (NULL != pData)
    {
        pData->Header.EventType = lgtEventError;
        pData->ErrorEvent.ErrorCode = GetLastError();

    #ifdef AMD64
        IntroCall64(pData, AGENT_HCALL_GATHER_TOOL);
    #else
        IntroCall32(pData, AGENT_HCALL_GATHER_TOOL);
    #endif

        VirtualFree(pData, 0, MEM_RELEASE);
    }

    if ((hFind != NULL) && (hFind != INVALID_HANDLE_VALUE))
    {
        FindClose(hFind);
    }

    if ((hFile != NULL) && (hFile != INVALID_HANDLE_VALUE))
    {
        CloseHandle(hFile);
    }

#ifndef NDEBUG
    getchar();
#endif

    return ret;
}
