#include "loader.h"
#include "hypercall.h"
#include <ntimage.h>


//
// LdrFindModuleByName
//
void *
LdrFindModuleByName(
    _In_z_ const CHAR *ModuleName
    )
//
// Will query the Introspection engine for the base of the indicated module.
// If ModuleName is NULL, the base of the current agent module is returned.
//
// Return value: the virtual address of the identified module. NULL if the
// module couldn't be found.
//
{
    SIZE_T result;
    // Use the introspection engine to retrieve the module base of the imported modules and
    // our own module base. It is far more safer & easier this way.
    if (NULL == ModuleName)
    {
        // Hypercall with EDX == 3 -> get my module base.
        result = Hypercall(0, 0, AGENT_HCALL_OWN_BASE);
    }
    else
    {
        // Hypercall with EDX == 2 -> get the module base of the module pointed by ECX/RCX.
        result = Hypercall((DWORD)strlen(ModuleName), (PBYTE)ModuleName, AGENT_HCALL_MOD_BASE);
    }

    if (HYPERCALL_EXCEPTION == result)
    {
        return NULL;
    }
    else
    {
        return (void *)result;
    }
}


//
// _LdrGetNtHeaders
//
static PIMAGE_NT_HEADERS
_LdrGetNtHeaders(
    _In_ void *ImageBase
    )
{
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)ImageBase;
    PIMAGE_NT_HEADERS pNt;

    // Check DOS signature.
    if (IMAGE_DOS_SIGNATURE != pDos->e_magic)
    {
        return NULL;
    }

    // Make sure this is not a scrambled PE.
    if ((QWORD)pDos->e_lfanew + sizeof(IMAGE_NT_HEADERS) > 0x1000)
    {
        return NULL;
    }

    // Validate NT headers.
    pNt = (PIMAGE_NT_HEADERS)((ULONG_PTR)ImageBase + pDos->e_lfanew);
    if (IMAGE_NT_SIGNATURE != pNt->Signature)
    {
        return NULL;
    }

    return pNt;
}


//
// LdrFindExportByName
//
void *
LdrFindExportByName(
    _In_ PBYTE ModuleBase,
    _In_z_ const CHAR *ExportName
    )
//
// Will search for the ExportName inside the ModuleBase module. If it is found,
// the virtual address (not RVA) si returned. Otherwise, NULL is returned.
//
{
    PIMAGE_NT_HEADERS pNth;
    PIMAGE_EXPORT_DIRECTORY pExp;
    DWORD imageSize, *names, *pointers, rva, eatAddress, eatSize;
    WORD *ordinals;
    size_t len;
    int left, right, mid, res;

    if (NULL == ModuleBase)
    {
        return NULL;
    }

    if (NULL == ExportName)
    {
        return NULL;
    }

    pNth = _LdrGetNtHeaders(ModuleBase);
    if (NULL == pNth)
    {
        return NULL;
    }

    imageSize = pNth->OptionalHeader.SizeOfImage;
    eatAddress = pNth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    eatSize = pNth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

    // Make sure we do have exports.
    if ((0 == eatAddress) || (0 == eatSize))
    {
        return NULL;
    }

    // Validate export-directory
    if (eatAddress >= imageSize || eatAddress + eatSize >= imageSize ||
        eatAddress + sizeof(IMAGE_EXPORT_DIRECTORY) >= imageSize)
    {
        return NULL;
    }

    // Go to the export directory.
    pExp = (PIMAGE_EXPORT_DIRECTORY)(ModuleBase + eatAddress);
    names = (DWORD*)(ModuleBase + pExp->AddressOfNames);
    ordinals = (WORD*)(ModuleBase + pExp->AddressOfNameOrdinals);
    pointers = (DWORD*)(ModuleBase + pExp->AddressOfFunctions);

    left = 0;
    right = pExp->NumberOfNames;

    len = strlen(ExportName) + 1;

    // Binary-search the exported function.
    while (left < right)
    {
        mid = (left +right) / 2;

        // Make sure the current export is inside the module.
        if (&names[mid] >= (DWORD *)(ModuleBase + imageSize))
        {
            break;
        }

        if (&ordinals[mid] + 1 >= (WORD *)(ModuleBase + imageSize))
        {
            break;
        }

        res = memcmp(ExportName, ModuleBase + names[mid], len);

        if (0 == res)
        {
            WORD fnordinal;

            fnordinal = ordinals[mid];
            if (&pointers[fnordinal] + 1 >= (DWORD *)(ModuleBase + imageSize))
            {
                break;
            }

            rva = pointers[fnordinal];

            if (rva >= imageSize)
            {
                break;
            }

            // Bingo! We got it!
            return ModuleBase + rva;
        }
        else if (res < 0)
        {
            right = mid;
        }
        else
        {
            left = mid + 1;
        }
    }

    return NULL;
}


//
// LdrFixMyImports
//
BOOLEAN
LdrFixMyImports(
    void
    )
//
// This function will parse & fix the imports of the current module.
//
{
    PIMAGE_NT_HEADERS pNth;
    PIMAGE_IMPORT_DESCRIPTOR pImp;
    DWORD imageSize, i, importsSize, importsRva;
    PBYTE pSelf;

    // Use the introspection engine to find our own address, as it is safer and easier.
    pSelf = LdrFindModuleByName(NULL);
    if (NULL == pSelf)
    {
        return FALSE;
    }

    pNth = _LdrGetNtHeaders(pSelf);
    if (NULL == pNth)
    {
        return FALSE;
    }

    imageSize = pNth->OptionalHeader.SizeOfImage;
    importsSize = pNth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
    importsRva = pNth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

    // Make sure we do have imports.
    if ((0 == importsRva) || (0 == importsSize))
    {
        return FALSE;
    }

    // Validate the import descriptors
    if (importsRva >= imageSize || importsRva + importsSize >= imageSize)
    {
        return FALSE;
    }

    pImp = (PIMAGE_IMPORT_DESCRIPTOR)(pSelf +
                                      pNth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    i = 0;
    while ((i < importsSize / sizeof(IMAGE_IMPORT_DESCRIPTOR)) &&
           ((pImp->FirstThunk != 0 ) && (pImp->OriginalFirstThunk != 0)))
    {
        PBYTE module;
        size_t *names;
        void **iat;
        void *functionPointer;

        // Is the current import exceeding the image?
        if ((PBYTE)(pImp + 1) > pSelf + imageSize)
        {
            return FALSE;
        }

        // Is the import name exceeding the image?
        if (pImp->Name >= imageSize)
        {
            return FALSE;
        }

        // Find the module
        module = LdrFindModuleByName((PCHAR)(pSelf + pImp->Name));
        if (NULL == module)
        {
            return FALSE;
        }

        // Fix each function
        iat = (void **)(pSelf + pImp->FirstThunk);
        names = (size_t*)(pSelf + pImp->OriginalFirstThunk);

        while (*names)
        {
            PIMAGE_IMPORT_BY_NAME pImpName;

            if ((PBYTE)names + sizeof(size_t) > pSelf + imageSize)
            {
                return FALSE;
            }

            if ((PBYTE)iat + sizeof(size_t) > pSelf + imageSize)
            {
                return FALSE;
            }

#ifdef AMD64
            if (0 != (*names & 0x8000000000000000))
#else
            if (0 != (*names & 0x80000000))
#endif
            {
                /// TODO: Imports by ordinal not yet handled.
                functionPointer = NULL;
                return FALSE;
            }
            else
            {
                DWORD j = 0;
                PBYTE imageEnd = pSelf + imageSize;

                pImpName = (PIMAGE_IMPORT_BY_NAME)(pSelf + *names);

                if (*names + sizeof(IMAGE_IMPORT_BY_NAME) > imageSize)
                {
                    return FALSE;
                }

                while (((PBYTE)pImpName + 2 + j < imageEnd) && (pImpName->Name[j] != 0))
                {
                    j++;
                }

                if ((PBYTE)pImpName + 2 + j >= imageEnd)
                {
                    return FALSE;
                }

                functionPointer = LdrFindExportByName(module, (PCHAR)pImpName->Name);
            }

            *iat = functionPointer;

            names++;

            iat++;
        }

        i++;

        pImp++;
    }

    return TRUE;
}

