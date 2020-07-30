/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "loader.h"
#include "drivers.h"
#include "winpe.h"


INTSTATUS
IntLdrGetImageSizeAndEntryPoint(
    _In_ PBYTE RawPe,
    _In_ DWORD RawSize,
    _Out_ DWORD *VirtualSize,
    _Out_ DWORD *EntryPoint
    )
///
/// @brief Returns the entry point and the virtual size for the provided module.
///
/// This module will get the entry point and the virtual size of the module. If a special section named
/// ENTRYP is found, the beginning of that section is considered to be the entry point. The returned
/// entry point is a RVA inside the module.
/// NOTE: this function assumes that the PE contained at RawPe is fully read into memory.
///
/// @param[in]  RawPe       The PE file contents.
/// @param[in]  RawSize     The PE raw size.
/// @param[out] VirtualSize The virtual PE size (SizeOfImage).
/// @param[out] EntryPoint  A RVA to the PE entry point.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
///
{
    PIMAGE_SECTION_HEADER pSec;
    DWORD i;
    INTSTATUS status;
    INTRO_PE_INFO peInfo = { 0 };

    if (NULL == RawPe)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (NULL == VirtualSize)
    {
        return INT_STATUS_INVALID_PARAMETER_3;
    }

    if (NULL == EntryPoint)
    {
        return INT_STATUS_INVALID_PARAMETER_4;
    }

    status = IntPeValidateHeader(0, RawPe, RawSize, &peInfo, 0);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntPeValidateHeader failed: 0x%08x\n", status);
        return status;
    }

    *VirtualSize = peInfo.SizeOfImage;
    *EntryPoint = peInfo.EntryPoint;

    // By default, use the PE entry point, but if we have the ENTRYP section, use that entry point.
    pSec = (IMAGE_SECTION_HEADER *)(RawPe + peInfo.SectionOffset);
    for (i = 0; i < peInfo.NumberOfSections; i++, pSec++)
    {
        if (0 == memcmp(pSec->Name, "ENTRYP", sizeof("ENTRYP")))
        {
            TRACE("[INFO] Found 'ENTRYP' section at 0x%08x, will use it as an EP!\n", pSec->VirtualAddress);
            *EntryPoint = pSec->VirtualAddress;
            break;
        }
    }

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntLdrPreLoadImage(
    _In_ PBYTE RawImage,
    _In_ DWORD RawImageSize,
    _In_ PBYTE VirtualImage,
    _In_ DWORD VirtualImageSize,
    _In_ DWORD NumberOfSections,
    _In_ PIMAGE_SECTION_HEADER Sections
    )
///
/// @brief Pre-load the given raw PE image at the indicated virtual address.
///
/// This function will pre-load the image inside the new, virtual, final space. What it does is:
/// - Initialize the entire virtual range with zeros;
/// - Copy the headers (everything from the raw image, up until the first section) inside the loaded image;
/// - Copy the sections from their raw location, to their virtual location inside the loaded image.
/// Basically, this function acts like the loader, in that it creates the image version of the PE file. It does not,
/// however, apply relocations and it does not fix imports.
/// Upon successful return, the VirtualImage address will contain the memory image of the provided PE file, as if
/// it was loaded for execution.
///
/// @param[in]  RawImage            The raw PE file contents (disk image).
/// @param[in]  RawImageSize        The raw PE file size (disk size).
/// @param[in]  VirtualImage        A preallocated region of memory where the memory image of the PE will be stored.
/// @param[in]  VirtualImageSize    The size of the memory image (SizeOfImage).
/// @param[in]  NumberOfSections    The number of PE sections.
/// @param[in]  Sections            A pointer to the first PE section.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
/// @retval #INT_STATUS_INVALID_OBJECT_TYPE If the MZ/PE image is malformed in any way.
///
{
    DWORD i, minSection;

    if (NULL == RawImage)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (NULL == VirtualImage)
    {
        return INT_STATUS_INVALID_PARAMETER_3;
    }

    if (NULL == Sections)
    {
        return INT_STATUS_INVALID_PARAMETER_6;
    }

    // Initialize the virtual image with nulls.
    memset(VirtualImage, 0, VirtualImageSize);

    // Copy the headers - we copy everything from the raw image, inside the virtual image, up until the first section.
    minSection = 0xFFFFFFFF;

    // Note for the readers: the order in which the sections lie inside the file doesn't need to reflect the order in
    /// which they appear inside the section headers.
    for (i = 0; i < NumberOfSections; i++)
    {
        if (Sections[i].PointerToRawData < minSection &&
            !(Sections[i].Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA))
        {
            minSection = Sections[i].PointerToRawData;
        }
    }

    if (RawImageSize < minSection)
    {
        ERROR("[ERROR] The headers span outside the image: 0x%08x\n", minSection);
        return INT_STATUS_INVALID_OBJECT_TYPE;
    }

    if (VirtualImageSize < minSection)
    {
        ERROR("[ERROR] The first section starts beyond the end of the image!: 0x%08x\n", minSection);
        return INT_STATUS_INVALID_OBJECT_TYPE;
    }

    memcpy(VirtualImage, RawImage, minSection);

    // Copy the sections - one by one - from the raw address, to their virtual address
    for (i = 0; i < NumberOfSections; i++)
    {
        // Make sure that the boundaries of this raw section are within the raw image
        if ((RawImageSize < Sections[i].PointerToRawData + Sections[i].SizeOfRawData) ||
            (RawImageSize < Sections[i].SizeOfRawData) ||
            (RawImageSize <= Sections[i].PointerToRawData))
        {
            ERROR("[ERROR] Section %d at 0x%08x:0x%08x overflows the raw image!\n",
                  i, Sections[i].PointerToRawData, Sections[i].SizeOfRawData);
            return INT_STATUS_INVALID_OBJECT_TYPE;
        }

        // Make sure the virtual boundaries of the section lie within the virtual, loaded image
        if ((VirtualImageSize < Sections[i].VirtualAddress + Sections[i].Misc.VirtualSize) ||
            (VirtualImageSize < Sections[i].Misc.VirtualSize) ||
            (VirtualImageSize <= Sections[i].VirtualAddress))
        {
            ERROR("[ERROR] Section %d at 0x%08x:0x%08x overflows the virtual image!\n",
                  i, Sections[i].VirtualAddress, Sections[i].Misc.VirtualSize);
            return INT_STATUS_INVALID_OBJECT_TYPE;
        }

        if (VirtualImage + Sections[i].VirtualAddress + Sections[i].SizeOfRawData > VirtualImage + VirtualImageSize)
        {
            ERROR("[ERROR] Section %d does not fit inside the virtual image [%p, %p): "
                  "va = 0x%08x raw data size = 0x%08x\n", i, VirtualImage, VirtualImage + VirtualImageSize,
                  Sections[i].VirtualAddress, Sections[i].SizeOfRawData);
            return INT_STATUS_INVALID_OBJECT_TYPE;
        }

        if (RawImage + Sections[i].PointerToRawData + Sections[i].SizeOfRawData > RawImage + RawImageSize)
        {
            ERROR("[ERROR] Section %d does not fit inside the raw image [%p, %p): "
                  "pointer to raw data = 0x%08x raw data size = 0x%08x\n", i, RawImage, RawImage + RawImageSize,
                  Sections[i].PointerToRawData, Sections[i].SizeOfRawData);
            return INT_STATUS_INVALID_OBJECT_TYPE;
        }

        // Copy the section to its new location
        memcpy(VirtualImage + Sections[i].VirtualAddress,
               RawImage + Sections[i].PointerToRawData,
               Sections[i].SizeOfRawData);
    }

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntLdrFixRelocations(
    _In_ PBYTE VirtualImage,
    _In_ DWORD VirtualImageSize,
    _In_ QWORD Delta,
    _In_ PIMAGE_DATA_DIRECTORY BaseRelocations
    )
///
/// @brief This function will parse the relocations of the PE and apply them where needed.
///
/// @param[in]  VirtualImage        The pre-loaded memory image of the PE file.
/// @param[in]  VirtualImageSize    The size of the memory image.
/// @param[in]  Delta               The delta value to be applied to each relocated address.
/// @param[in]  BaseRelocations     The base relocations data directory.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
/// @retval #INT_STATUS_INVALID_OBJECT_TYPE If the MZ/PE image is malformed in any way.
///
{
    DWORD i;
    IMAGE_BASE_RELOCATION reloc;
    QWORD relocRva, relocSize;

    if (NULL == VirtualImage)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (NULL == BaseRelocations)
    {
        return INT_STATUS_INVALID_PARAMETER_4;
    }

    i = 0;

    // Fetch the relocation directory.
    relocRva  = BaseRelocations->VirtualAddress;
    relocSize = BaseRelocations->Size;

    // Make sure we have relocs before moving on.
    if ((0 == relocRva ) || (0 == relocSize))
    {
        // If there are no relocations, we can safely leave. Nonexistent relocations doesn't mean that the driver is
        // invalid or can't run.
        return INT_STATUS_SUCCESS;
    }

    // Make sure the relocs are valid before moving on.
    if ((VirtualImageSize <= relocRva) || (VirtualImageSize < relocSize) || (VirtualImageSize < relocRva + relocSize))
    {
        // This is a problem... we have relocs, but they point out of the image...
        return INT_STATUS_INVALID_OBJECT_TYPE;
    }

    // By now, the VirtualImageBase contains the pre-loaded image: all the sections are in their correct, virtual,
    // locations.
    while (i + sizeof(IMAGE_BASE_RELOCATION) <= relocSize)
    {
        DWORD j;

        // Fetch the next relocation entry.
        reloc = *(PIMAGE_BASE_RELOCATION)(VirtualImage + relocRva + i);

        // Make sure the virtual address is page aligned. If it is not, we're probably dealing with a bad PE.
        if (0 != (reloc.VirtualAddress & 0xFFF))
        {
            // Bad RVA - not page aligned.
            return INT_STATUS_INVALID_OBJECT_TYPE;
        }

        // Make sure this relocation doesn't overflow the virtual image!
        if ((VirtualImageSize < reloc.VirtualAddress) ||
            (VirtualImageSize < reloc.VirtualAddress + 0x1000))
        {
            // This page lies outside the image; probably bad PE.
            return INT_STATUS_INVALID_OBJECT_TYPE;
        }

        // Make sure the relocation entries are all inside the image.
        if (VirtualImageSize < relocRva + i + reloc.SizeOfBlock)
        {
            // The relocation entries overflow the image. Bad PE. Bad.
            return INT_STATUS_INVALID_OBJECT_TYPE;
        }

        // Make sure the relocation entries are inside the relocation directory.
        if (relocSize < (QWORD)i + reloc.SizeOfBlock)
        {
            // The entry lies outside the relocation directory...
            return INT_STATUS_INVALID_OBJECT_TYPE;
        }

        if (reloc.SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION))
        {
            WARNING("Invalid relocation for RVA 0x%016llxx: SizeOfBlock is: 0x%08x\n", relocRva, reloc.SizeOfBlock);
            return INT_STATUS_INVALID_OBJECT_TYPE;
        }

        TRACE("[LOADER] Applying relocations for RVA page 0x%08x\n", reloc.VirtualAddress);

        // pReloc->BlockSize - sizeof(IMAGE_BASE_RELOCATION) bytes follow, which contain the page offsets
        // inside the VA page pReloc->VirtualAddress for which the relocation must be applied.
        j = 0;
        while (j < reloc.SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION))
        {
            // Each entry inside the block is a word. The high 4 bit indicate the reloc type, the low 12 bit indicate
            // the offset inside the pReloc->VirtualAddress page where the relocation should be applied.
            WORD desc, type, offset;

            desc = *((WORD *)(VirtualImage + relocRva + i + sizeof(IMAGE_BASE_RELOCATION) + j));

            type = (desc >> 12) & 0xF;

            offset = desc & 0xFFF;

            TRACE("[LOADER] -> Relocationg offset 0x%08x of type %d...\n", offset, type);

            // Apply this relocation.
            switch (type)
            {
            case IMAGE_REL_BASED_HIGHLOW:
                // Basic x86 relocation.
                *((DWORD *)(VirtualImage + reloc.VirtualAddress + offset)) += (DWORD)Delta;
                break;
            case IMAGE_REL_BASED_DIR64:
                // x64 relocation.
                *((QWORD *)(VirtualImage + reloc.VirtualAddress + offset)) += Delta;
                break;
            case IMAGE_REL_BASED_ABSOLUTE:
                // This relocation type is just for padding.
                break;
            default:
                break;
            }

            j += sizeof(WORD);
        }

        // Skip to the next relocation entry.
        i += reloc.SizeOfBlock;
    }

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntLdrFixImports(
    _In_ PBYTE VirtualImage,
    _In_ DWORD VirtualImageSize,
    _In_ BOOLEAN Is64,
    _In_ PIMAGE_DATA_DIRECTORY ImportTable
    )
///
/// @brief Fix the imports of the provided PE image.
///
/// This function will lookup, in guest memory, each module that is imported by the loaded PE image, it will
/// locate each imported function, and it will fix the IAT of this loaded image by storing the actual function
/// pointers for each imported function.
/// NOTE: The export directories of the kernel modules are usually paged, so this may fail if required info
/// is not present in physical memory!
///
/// @param[in]  VirtualImage        The pre-loaded memory image of the PE file.
/// @param[in]  VirtualImageSize    The size of the memory image.
/// @param[in]  Is64                True if the image is 64 bit.
/// @param[in]  ImportTable         The imports data directory.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
/// @retval #INT_STATUS_INVALID_OBJECT_TYPE If the MZ/PE image is malformed in any way.
/// @retval #INT_STATUS_INSUFFICIENT_RESOURCES If a memory alloc fails.
///
{
    INTSTATUS status;
    PIMAGE_IMPORT_DESCRIPTOR pImpDesc;
    QWORD importsRva, importsSize, i;

    if (NULL == VirtualImage)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (NULL == ImportTable)
    {
        return INT_STATUS_INVALID_PARAMETER_4;
    }

    i = 0;

    // Parse the import descriptors.
    importsRva = ImportTable->VirtualAddress;
    importsSize = ImportTable->Size;

    // Validate the imports. If RVA or Size is zero, then we don't have any imports
    if ((0 == importsRva) || (0 == importsSize))
    {
        return INT_STATUS_SUCCESS;
    }

    // Make sure the import directory is inside the virtual image.
    if ((VirtualImageSize < importsRva) || (VirtualImageSize < importsRva + importsSize))
    {
        return INT_STATUS_INVALID_OBJECT_TYPE;
    }

    pImpDesc = (PIMAGE_IMPORT_DESCRIPTOR)(VirtualImage + importsRva);

    while ((i < importsSize / sizeof(IMAGE_IMPORT_DESCRIPTOR)) &&
           ((pImpDesc->FirstThunk != 0 ) && (pImpDesc->u.Characteristics != 0)))
    {
        char *modName;
        DWORD *names32;
        QWORD *names64;
        DWORD *iat32;
        QWORD *iat64;
        DWORD rva;
        SIZE_T len, j;
        QWORD modBase, namesBase, iatBase, count;
        WCHAR *wModuleName;

        count = 0;
        wModuleName = NULL;

        if (pImpDesc->Name >= VirtualImageSize)
        {
            ERROR("[ERROR] Import name outside the image: 0x%08x\n", pImpDesc->Name);
            return INT_STATUS_INVALID_OBJECT_TYPE;
        }

        // Get the current DLL name. That is actually a RVA that points to the actual name.
        modName = (char *)(VirtualImage + pImpDesc->Name);

        len = strnlen(modName, VirtualImageSize - pImpDesc->Name);

        // Name too lung, or overflowing the image - bail out.
        if (len >= 512 || len >= VirtualImageSize - pImpDesc->Name)
        {
            return INT_STATUS_INVALID_OBJECT_TYPE;
        }

        // len + 2 OK: len is not longer than 512.
        wModuleName = HpAllocWithTag((len + 1ull) * 2ull, IC_TAG_DRNU);
        if (NULL == wModuleName)
        {
            return INT_STATUS_INSUFFICIENT_RESOURCES;
        }

        j = 0;

        while (j < len + 1)
        {
            wModuleName[j] = modName[j];

            j++;
        }

        TRACE("[LOADER] Fixing imports for imported library %s...\n", modName);

        if (0 == strcmp(modName, "ntoskrnl.exe"))
        {
            KERNEL_DRIVER *pDriver = IntDriverFindByLoadOrder(0);
            if (NULL == pDriver)
            {
                ERROR("[ERROR] IntWinDriverFindByLoadOrder failed for %s\n", modName);
                HpFreeAndNullWithTag(&wModuleName, IC_TAG_DRNU);
                goto _continue;
            }

            modBase = pDriver->BaseVa;
        }
        else if (0 == strcmp(modName, "hal.dll"))
        {
            KERNEL_DRIVER *pDriver = IntDriverFindByLoadOrder(1);
            if (NULL == pDriver)
            {
                ERROR("[ERROR] IntWinDriverFindByLoadOrder failed for %s\n", modName);
                HpFreeAndNullWithTag(&wModuleName, IC_TAG_DRNU);
                goto _continue;
            }

            modBase = pDriver->BaseVa;
        }
        else
        {
            KERNEL_DRIVER *pDriver = IntDriverFindByName(wModuleName);
            if (NULL == pDriver)
            {
                ERROR("[ERROR] IntWinDriverFindByName failed for %s\n", modName);
                HpFreeAndNullWithTag(&wModuleName, IC_TAG_DRNU);
                goto _continue;
            }

            modBase = pDriver->BaseVa;
        }

        HpFreeAndNullWithTag(&wModuleName, IC_TAG_DRNU);

        // Make sure this import is valid: each function must reside within the image.
        if (pImpDesc->u.Characteristics >= VirtualImageSize)
        {
            return INT_STATUS_INVALID_OBJECT_TYPE;
        }

        // Parse every imported function.
        names32 = (DWORD *)(VirtualImage + pImpDesc->u.Characteristics);
        names64 = (QWORD *)(VirtualImage + pImpDesc->u.Characteristics);
        namesBase = pImpDesc->u.Characteristics;

        // We'll use only one, depending on the module architecture.
        iat32 = (DWORD *)(VirtualImage + pImpDesc->FirstThunk);
        iat64 = (QWORD *)(VirtualImage + pImpDesc->FirstThunk);
        iatBase = pImpDesc->FirstThunk;

        // Now parse & map the exports of the imported module. We do this inline, rather than creating a different
        // function, because of performance problems - if we'd map the exports separately for each imported function,
        // we'd kill performance.

        if (!Is64)
        {
            // Parse each imported symbol...
            while ((namesBase + count * 4 + 4 <= VirtualImageSize) && (iatBase + count * 4 + 4 <= VirtualImageSize) &&
                   (0 != *names32))
            {
                PIMAGE_IMPORT_BY_NAME pImpName;
                DWORD impAddr;

                count++;

                // Make sure the current name is inside the image.
                if ((VirtualImageSize < *names32) && (0 == (*names32 & 0x80000000)))
                {
                    return INT_STATUS_INVALID_OBJECT_TYPE;
                }

                // Check if this is an import by ordinal.
                if (0 != (*names32 & 0x80000000))
                {
                    // This is an import by ordinal. These are not supported.
                    impAddr = 0;
                }
                else
                {
                    DWORD l;

                    l = 0;

                    // Import by name.
                    pImpName = (PIMAGE_IMPORT_BY_NAME)(VirtualImage + *names32);

                    if (*names32 + sizeof(IMAGE_IMPORT_BY_NAME) > VirtualImageSize)
                    {
                        return INT_STATUS_INVALID_OBJECT_TYPE;
                    }

                    // Make sure the entire name is within the image.
                    while ((*names32 + 2 + l < VirtualImageSize) && (pImpName->Name[l] != 0))
                    {
                        l++;
                    }

                    if (*names32 + 2 + l >= VirtualImageSize)
                    {
                        return INT_STATUS_INVALID_OBJECT_TYPE;
                    }

                    status = IntPeFindExportByName(modBase, NULL, (char *)pImpName->Name, &rva);
                    if (!INT_SUCCESS(status))
                    {
                        ERROR("[ERROR] IntPeFindExportByName failed: 0x%08x\n", status);
                    }

                    impAddr = (DWORD)modBase + rva;
                }

                *iat32 = impAddr;

                // Skip to the next entry, both in IDT and IAT.
                names32++;

                iat32++;
            }
        }
        else
        {
            // Parse each imported symbol...
            while ((namesBase + count * 8 + 8 <= VirtualImageSize) && (iatBase + count * 8 + 8 <= VirtualImageSize) &&
                   (0 != *names64))
            {
                PIMAGE_IMPORT_BY_NAME pImpName;
                QWORD impAddr;

                count++;

                // Make sure the current name is inside the image.
                if ((VirtualImageSize < *names64) && (0 == (*names64 & 0x8000000000000000ULL)))
                {
                    return INT_STATUS_INVALID_OBJECT_TYPE;
                }

                // Check if this is an import by ordinal.
                if (0 != (*names64 & 0x8000000000000000ULL))
                {
                    // This is an import by ordinal. These are not supported.
                    impAddr = 0;
                }
                else
                {
                    DWORD k;

                    k = 0;

                    // Import by name.
                    pImpName = (PIMAGE_IMPORT_BY_NAME)(VirtualImage + *names64);

                    if (*names64 + sizeof(IMAGE_IMPORT_BY_NAME) > VirtualImageSize)
                    {
                        return INT_STATUS_INVALID_OBJECT_TYPE;
                    }

                    while ((*names64 + 2 + k < VirtualImageSize) && (pImpName->Name[k] != 0))
                    {
                        k++;
                    }

                    if (*names64 + 2 + k >= VirtualImageSize)
                    {
                        return INT_STATUS_INVALID_OBJECT_TYPE;
                    }

                    status = IntPeFindExportByName(modBase, NULL, (char *)pImpName->Name, &rva);
                    if (!INT_SUCCESS(status))
                    {
                        ERROR("[ERROR] IntPeFindExportByName failed: 0x%08x\n", status);
                    }

                    impAddr = modBase + rva;
                }

                *iat64 = impAddr;

                // Skip to the next entry, both in IDT and IAT.
                names64++;

                iat64++;
            }
        }

_continue:
        // Skip to the next entry.
        pImpDesc++;

        i++;
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntLdrLoadPEImage(
    _In_ PBYTE RawPe,
    _In_ DWORD RawPeSize,
    _In_ QWORD GuestVirtualAddress,
    _Inout_ PBYTE LoadedPe,
    _In_ DWORD VirtualPeSize,
    _In_ DWORD Flags
    )
///
/// @brief Load the provided PE image at the provided guest virtual address, and return it in LoadedPe.
///
/// This function will act as a PE loader which is capable of loading a PE file from the Introcore memory address space
/// to the guest memory address space.
/// NOTE: For now, we only support parsing relocations & imports (basic in order to get the PE ready for running);
/// We don't take into consideration forwarded exports, delayed imports or bounded imports.
///
/// @param[in]  RawPe               A buffer that contains the raw PE image that must be "loaded" (disk image).
/// @param[in]  RawPeSize           Raw size of the PE to be loaded (disk size).
/// @param[in]  GuestVirtualAddress Guest virtual address where the module will be loaded.
/// @param[in]  LoadedPe            Will contain, upon exit, the fixed image.
/// @param[in]  VirtualPeSize       The size of the loaded image.
/// @param[in]  Flags               Indicates what fixups are required. Supported fixups are:
///                                 LDR_FLAG_FIX_RELOCATIONS and LDR_FLAG_FIX_IMPORTS.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
/// @retval #INT_STATUS_INVALID_OBJECT_TYPE If the MZ/PE is malformed in any way.
/// @retval #INT_STATUS_NOT_SUPPORTED If the PE does not match the guest OS architecture.
///
{
    INTSTATUS status;
    PIMAGE_SECTION_HEADER pSections;
    IMAGE_DATA_DIRECTORY dir;
    QWORD delta;
    INTRO_PE_INFO peInfo = { 0 };

    if (NULL == RawPe)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (NULL == LoadedPe)
    {
        return INT_STATUS_INVALID_PARAMETER_4;
    }

    status = IntPeValidateHeader(0, RawPe, RawPeSize, &peInfo, 0);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntPeValidateHeader failed: 0x%08x\n", status);
        return INT_STATUS_INVALID_OBJECT_TYPE;
    }

    TRACE("[LOADER] Preparing image for execution...\n");

    // Get the image type and invoke the PE parser, in order to load the PE in memory and prepare it for execution
    if (peInfo.Machine == IMAGE_FILE_MACHINE_AMD64)
    {
        // x64 PE (PE64)

        // Make sure the image is native.
        if (peInfo.Subsystem != IMAGE_SUBSYSTEM_NATIVE)
        {
            WARNING("[WARNING] The image is not native: %d\n", peInfo.Subsystem);
        }

        pSections = (PIMAGE_SECTION_HEADER)(RawPe + peInfo.SectionOffset);

        // Preload the PE.
        status = IntLdrPreLoadImage(RawPe, RawPeSize, LoadedPe, VirtualPeSize,
                                    (DWORD)peInfo.NumberOfSections, pSections);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntLdrPreLoadImage failed: 0x%08x\n", status);
            return status;
        }


        if (0 != (Flags & LDR_FLAG_FIX_RELOCATIONS))
        {
            // Apply relocations.
            delta = GuestVirtualAddress - peInfo.ImageBase;

            status = IntPeGetDirectory(0, RawPe, IMAGE_DIRECTORY_ENTRY_BASERELOC, &dir);
            if (!INT_SUCCESS(status) && status != INT_STATUS_NOT_FOUND)
            {
                ERROR("[ERROR] IntPeGetDirectory failed: 0x%08x\n", status);
            }

            status = IntLdrFixRelocations(LoadedPe, VirtualPeSize, delta, &dir);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntLdrFixRelocations failed: 0x%08x\n", status);
            }
        }


        if (0 != (Flags & LDR_FLAG_FIX_IMPORTS))
        {
            // Resolve imports.
            status = IntPeGetDirectory(0, RawPe, IMAGE_DIRECTORY_ENTRY_IMPORT, &dir);
            if (!INT_SUCCESS(status) && status != INT_STATUS_NOT_FOUND)
            {
                ERROR("[ERROR] IntPeGetDirectory failed: 0x%08x\n", status);
            }

            status = IntLdrFixImports(LoadedPe, VirtualPeSize, TRUE, &dir);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntLdrFixImports failed: 0x%08x\n", status);
            }
        }
    }
    else if (peInfo.Machine == IMAGE_FILE_MACHINE_I386)
    {
        // i386 PE (32 bit PE)

        // Make sure the image is native.
        if (peInfo.Subsystem != IMAGE_SUBSYSTEM_NATIVE)
        {
            WARNING("[WARNING] The image is not native: %d\n", peInfo.Subsystem);
        }

        pSections = (PIMAGE_SECTION_HEADER)(RawPe + peInfo.SectionOffset);

        // Preload the PE.
        status = IntLdrPreLoadImage(RawPe, RawPeSize, LoadedPe, VirtualPeSize,
                                    (DWORD)peInfo.NumberOfSections, pSections);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntLdrPreLoadImage failed: 0x%08x\n", status);
            return status;
        }


        if (0 != (Flags & LDR_FLAG_FIX_RELOCATIONS))
        {
            // Apply relocations.
            delta = GuestVirtualAddress - peInfo.ImageBase;

            status = IntPeGetDirectory(0, RawPe, IMAGE_DIRECTORY_ENTRY_BASERELOC, &dir);
            if (!INT_SUCCESS(status) && status != INT_STATUS_NOT_FOUND)
            {
                ERROR("[ERROR] IntPeGetDirectory failed: 0x%08x\n", status);
            }

            status = IntLdrFixRelocations(LoadedPe, VirtualPeSize, delta, &dir);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntLdrFixRelocations failed: 0x%08x\n", status);
            }
        }


        if (0 != (Flags & LDR_FLAG_FIX_IMPORTS))
        {
            // Resolve the imports.
            status = IntPeGetDirectory(0, RawPe, IMAGE_DIRECTORY_ENTRY_IMPORT, &dir);
            if (!INT_SUCCESS(status) && status != INT_STATUS_NOT_FOUND)
            {
                ERROR("[ERROR] IntPeGetDirectory failed: 0x%08x\n", status);
            }

            status = IntLdrFixImports(LoadedPe, VirtualPeSize, FALSE, &dir);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntLdrFixImports failed: 0x%08x\n", status);
            }
        }
    }
    else
    {
        ERROR("[ERROR] Unsupported machine type: %d\n", peInfo.Machine);

        return INT_STATUS_NOT_SUPPORTED;
    }

    TRACE("[LOADER] The image should be loaded & prepared for execution!\n");

    return INT_STATUS_SUCCESS;
}
