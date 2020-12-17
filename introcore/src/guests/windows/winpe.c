/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "winpe.h"
#include "decoder.h"
#include "introcpu.h"
#include "guests.h"


/// We won't consider a valid image if it has more than MAX_NUMBER_OF_EXPORT_NAMES names
#define MAX_NUMBER_OF_EXPORT_NAMES  65535ul

/// The maximum number of iterations done while parsing unwind data.
#define MAX_UNWIND_INFO_TRIES       512

/// The maximum value for the SizeOfImage field from a MZPE header.
///
/// See https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#optional-header-image-only
#define MAX_SIZE_OF_IMAGE           (2 * ONE_GIGABYTE)

/// Maximum number of unwind codes to check.
#define MAX_UNWIND_CODES            50

///
/// @brief Structure describing relevant fields extracted from the optional header.
///
typedef struct _OPTIONAL_HEADER_INFO
{
    DWORD   SizeOfImage;    ///< The size of the image.
    DWORD   EntryPoint;     ///< Rva to the entry point of the image.
    QWORD   ImageBase;      ///< The base of the image.
    WORD    Subsystem;      ///< The subsystem which the image belongs to.
    DWORD   SectionAlign;   ///< The number of bytes sections are aligned by at runtime.
    DWORD   FileAlign;      ///< The number of bytes sections are aligned by on the disk.
    BOOLEAN Image64;        ///< True if the image is considered 64 bits, False otherwise.
} OPTIONAL_HEADER_INFO, *POPTIONAL_HEADER_INFO;


static INTSTATUS
IntPeValidateOptionalHeader(
    _In_ void *OptionalHeader,
    _In_ DWORD SizeOfOptionalHeader,
    _Out_ OPTIONAL_HEADER_INFO *Info
    )
///
/// @brief Validates and extracts info about the optional header
///
/// This function will parse the optional header and get relevant information,
/// described in the #OPTIONAL_HEADER_INFO structure. Note that the optional header
/// is parsed with respect to the magic, even if the process is considered 64 bits,
/// if we encounter a IMAGE_OPTIONAL_HEADER_PE32 signature, we'll consider the optional
/// header, as well as the whole image, to be 32 bits.
///
/// @param[in] OptionalHeader   A pointer to the optional header field of the nt headers.
/// @param[in] SizeOfOptionalHeader The number of bytes in the optional header, as extracted
///                                 from the file header.
/// @param[out] Info            An #OPTIONAL_HEADER_INFO structure containing the retrieved
///                             relevant information.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INVALID_OBJECT_TYPE If the optional header is corrupted or has an invalid
///                                         magic.
///
{
    WORD magic = ((WORD *)OptionalHeader)[0];

    if (magic == IMAGE_OPTIONAL_HEADER_PE32)
    {
        IMAGE_OPTIONAL_HEADER32 *pOptional = (IMAGE_OPTIONAL_HEADER32 *)OptionalHeader;
        DWORD actualSizeOfOptionalHeader = 0;

        // Size of OptionalHeader without the data directories
        actualSizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER32) - sizeof(IMAGE_DATA_DIRECTORY) *
                                     IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
        // Add the size of the actual data directories to the size of the optional header
        actualSizeOfOptionalHeader += sizeof(IMAGE_DATA_DIRECTORY) * pOptional->NumberOfRvaAndSizes;

        if (actualSizeOfOptionalHeader != SizeOfOptionalHeader)
        {
            WARNING("[WARNING] SizeOfOptionalHeader (0x%08x) different from actual size (0x%08x).\n",
                    SizeOfOptionalHeader, actualSizeOfOptionalHeader);
            return INT_STATUS_INVALID_OBJECT_TYPE;
        }

        Info->SizeOfImage = pOptional->SizeOfImage;
        Info->EntryPoint = pOptional->AddressOfEntryPoint;
        Info->ImageBase = pOptional->ImageBase;
        Info->Subsystem = pOptional->Subsystem;
        Info->SectionAlign = pOptional->SectionAlignment;
        Info->FileAlign = pOptional->FileAlignment;
        Info->Image64 = FALSE;
    }
    else if (magic == IMAGE_OPTIONAL_HEADER_PE64)
    {
        IMAGE_OPTIONAL_HEADER64 *pOptional = (IMAGE_OPTIONAL_HEADER64 *)OptionalHeader;
        DWORD actualSizeOfOptionalHeader = 0;

        // Size of OptionalHeader without the data directories
        actualSizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64) - sizeof(IMAGE_DATA_DIRECTORY) *
                                     IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
        // Add the size of the actual data directories to the size of the optional header
        actualSizeOfOptionalHeader += sizeof(IMAGE_DATA_DIRECTORY) * pOptional->NumberOfRvaAndSizes;

        if (actualSizeOfOptionalHeader != SizeOfOptionalHeader)
        {
            WARNING("[WARNING] SizeOfOptionalHeader (0x%08x) different from actual size (0x%08x).\n",
                    SizeOfOptionalHeader, actualSizeOfOptionalHeader);
            return INT_STATUS_INVALID_OBJECT_TYPE;
        }

        Info->SizeOfImage = pOptional->SizeOfImage;
        Info->EntryPoint = pOptional->AddressOfEntryPoint;
        Info->ImageBase = pOptional->ImageBase;
        Info->Subsystem = pOptional->Subsystem;
        Info->SectionAlign = pOptional->SectionAlignment;
        Info->FileAlign = pOptional->FileAlignment;
        Info->Image64 = TRUE;
    }
    else
    {
        ERROR("[ERROR] Optional header has an invalid magic: 0x%04x!\n", magic);
        return INT_STATUS_INVALID_OBJECT_TYPE;
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntPeValidateHeader(
    _In_ QWORD ImageBase,
    _In_opt_ BYTE *ImageBaseBuffer,
    _In_opt_ DWORD ImageBaseBufferSize,
    _Out_opt_ INTRO_PE_INFO *PeInfo,
    _In_opt_ QWORD Cr3
    )
///
/// @brief Validates a PE header.
///
/// This function will perform several checks on the given PE header:
/// 1. MZ and PE signatures;
/// 2. Optional header size;
/// 3. Sections (offset, size);
/// 4. Entry point;
/// 5. File & section alignment;
/// If all the checks pass (the PE does not look malformed/corrupted), it will return the information in the PeInfo
/// structure. In order to work, at least a page of memory (containing the MZ/PE) headers must be mapped. If the
/// caller provides ImageBaseBuffer, it must make sure that at least one page is available.
///
/// @param[in]  ImageBase           Guest virtual address of the beginning of the module (headers) to be validated.
/// @param[in]  ImageBaseBuffer     Address where the ImageBase is already mapped in Introcore space, if present.
/// @param[in]  ImageBaseBufferSize If ImageBaseBuffer is valid, this indicates its size.
/// @param[out] PeInfo              Will contain upon successful validation relevant PE information.
/// @param[in]  Cr3                 Optional virtual address space the image lies in.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_NOT_SUPPORTED If the base of the PE file is not aligned to 4K.
/// @retval #INT_STATUS_INVALID_OBJECT_TYPE If the PE file is malformed or corrupted in any way.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;
    DWORD size = 0;
    BOOLEAN image64 = TRUE;
    BYTE *pBase;
    IMAGE_NT_HEADERS64 *pNth64;
    IMAGE_NT_HEADERS32 *pNth32;
    IMAGE_DOS_HEADER *pDosHeader;
    IMAGE_SECTION_HEADER *pSec;
    WORD subsystem = 0, machine = 0;
    DWORD timeDateStamp = 0, sizeOfImage = 0;
    DWORD entryPoint = 0, numberOfSections = 0;
    DWORD actualSectionSize = 0;
    DWORD sectionAlign = 0, fileAlign = 0;
    QWORD imageBase = 0;
    OPTIONAL_HEADER_INFO opthdrInfo = { 0 };
    QWORD e_lfanew, secOff = 0;

    if ((ImageBase & PAGE_OFFSET) != 0)
    {
        ERROR("[ERROR] Image at 0x%016llx is not page-aligned\n", ImageBase);
        return INT_STATUS_NOT_SUPPORTED;
    }

    if (NULL != ImageBaseBuffer)
    {
        pBase = ImageBaseBuffer;
        size = ImageBaseBufferSize;
    }
    else
    {
        if (ImageBase < ONE_KILOBYTE * 4)
        {
            ERROR("[ERROR] Can not map MZPE image at GVA 0x%016llx!\n", ImageBase);
            return INT_STATUS_NOT_SUPPORTED;
        }

        status = IntVirtMemMap(ImageBase, PAGE_SIZE, Cr3, 0, &pBase);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] Failed mapping VA 0x%016llx to host: 0x%08x\n", ImageBase, status);
            return status;
        }

        size = PAGE_SIZE;
    }

    if (size < PAGE_SIZE)
    {
        status = INT_STATUS_INVALID_OBJECT_TYPE;
        goto leave;
    }

    pDosHeader = (IMAGE_DOS_HEADER *)pBase;

    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        status = INT_STATUS_INVALID_OBJECT_TYPE;
        goto leave;
    }

    e_lfanew = (DWORD)pDosHeader->e_lfanew;
    if (e_lfanew >= size)
    {
        status = INT_STATUS_INVALID_OBJECT_TYPE;
        goto leave;
    }

    if (e_lfanew + sizeof(IMAGE_NT_HEADERS64) >= size)
    {
        status = INT_STATUS_INVALID_OBJECT_TYPE;
        goto leave;
    }

    pNth32 = (IMAGE_NT_HEADERS32 *)(pBase + e_lfanew);
    pNth64 = (IMAGE_NT_HEADERS64 *)(pBase + e_lfanew);

    // Validate the PE signature. Doesn't matter what we use here since only the OptionalHeader is different
    if (pNth64->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64)
    {
        if (pNth64->Signature != IMAGE_NT_SIGNATURE)
        {
            status = INT_STATUS_INVALID_OBJECT_TYPE;
            goto leave;
        }

        // Safe cast, we know that e_lfanew is a valid RVA
        secOff = e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) + pNth64->FileHeader.SizeOfOptionalHeader;
        timeDateStamp = pNth64->FileHeader.TimeDateStamp;
        numberOfSections = pNth64->FileHeader.NumberOfSections;
        machine = pNth64->FileHeader.Machine;

        status = IntPeValidateOptionalHeader(&pNth64->OptionalHeader, pNth64->FileHeader.SizeOfOptionalHeader,
                                             &opthdrInfo);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] Image at 0x%016llx has an invalid optional header!\n", ImageBase);
            goto leave;
        }

        if (!opthdrInfo.Image64)
        {
            WARNING("[WARNING] Image 0x%016llx is AMD64 but has a PE32 optional header! Will consider it 32 bits\n",
                    ImageBase);
        }
    }
    else if (pNth32->FileHeader.Machine == IMAGE_FILE_MACHINE_I386)
    {
        if (pNth32->Signature != IMAGE_NT_SIGNATURE)
        {
            status = INT_STATUS_INVALID_OBJECT_TYPE;
            goto leave;
        }

        // Safe cast, we know that e_lfanew is a valid RVA
        secOff = e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) + pNth32->FileHeader.SizeOfOptionalHeader;
        timeDateStamp = pNth32->FileHeader.TimeDateStamp;
        numberOfSections = pNth32->FileHeader.NumberOfSections;
        machine = pNth32->FileHeader.Machine;

        status = IntPeValidateOptionalHeader(&pNth32->OptionalHeader, pNth32->FileHeader.SizeOfOptionalHeader,
                                             &opthdrInfo);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] Image at 0x%016llx has an invalid optional header!\n", ImageBase);
            goto leave;
        }

        if (opthdrInfo.Image64)
        {
            WARNING("[WARNING] Image 0x%016llx is I386 but has a PE64 optional header! Will consider it 64 bits\n",
                    ImageBase);
        }
    }
    else
    {
        status = INT_STATUS_INVALID_OBJECT_TYPE;
        goto leave;
    }

    image64 = opthdrInfo.Image64;
    sizeOfImage = opthdrInfo.SizeOfImage;
    entryPoint = opthdrInfo.EntryPoint;
    imageBase = opthdrInfo.ImageBase;
    subsystem = opthdrInfo.Subsystem;
    sectionAlign = opthdrInfo.SectionAlign;
    fileAlign = opthdrInfo.FileAlign;

    if (sizeOfImage > MAX_SIZE_OF_IMAGE)
    {
        ERROR("[ERROR] Image at 0x%016llx has SizeOfImage (0x%08x) larger than the maximum allowed (0x%016llx)\n",
              ImageBase, sizeOfImage, MAX_SIZE_OF_IMAGE);
        status = INT_STATUS_INVALID_OBJECT_TYPE;
        goto leave;
    }

    if (sectionAlign == 0)
    {
        ERROR("[ERROR] Section alignment is 0 for image at 0x%016llx\n", ImageBase);
        status = INT_STATUS_INVALID_OBJECT_TYPE;
        goto leave;
    }

    if ((sectionAlign < fileAlign) || (fileAlign < MIN_FILE_ALIGNMENT || fileAlign > MAX_FILE_ALIGNMENT))
    {
        WARNING("[WARNING] Image alignments invalid. FileAlignment: 0x%08x, SectionAlignment: 0x%08x. "
                "The image at 0x%016llx may have been tampered with\n",
                fileAlign, sectionAlign, ImageBase);
    }

    if (secOff + sizeof(IMAGE_SECTION_HEADER) * numberOfSections > size)
    {
        ERROR("[ERROR] Sections headers point out of the mapping. SectionOffset: 0x%08llx; NrOfSections: %d; "
              "MaxSize: 0x%08llx; MappingSize: 0x%08x. Image base: 0x%016llx\n",
              secOff, numberOfSections, secOff + sizeof(IMAGE_SECTION_HEADER) * numberOfSections, size, ImageBase);
        status = INT_STATUS_INVALID_OBJECT_TYPE;
        goto leave;
    }

    if (entryPoint >= sizeOfImage)
    {
        ERROR("[ERROR] EntryPoint points out of the file. EntryPoint: 0x%08x; SizeOfImage: 0x%08x; "
              "ImageBase: 0x%016llx\n",
              entryPoint, sizeOfImage, ImageBase);
        status = INT_STATUS_INVALID_OBJECT_TYPE;
        goto leave;
    }

    // Make a final validation (so we know that the NT headers weren't moved outside the image)
    if (e_lfanew >= sizeOfImage)
    {
        WARNING("[WARNING] e_lfanew 0x%llx points outside of image 0x%08x. Module 0x%016llx\n",
                e_lfanew, sizeOfImage, ImageBase);
        status = INT_STATUS_INVALID_OBJECT_TYPE;
        goto leave;
    }

    // Validate section headers
    pSec = (IMAGE_SECTION_HEADER *)(pBase + secOff);
    for (DWORD i = 0; i < numberOfSections; i++, pSec++)
    {
        UINT32 secVirtSize = pSec->Misc.VirtualSize;
        UINT32 secSizeOfRawData = pSec->SizeOfRawData;

        actualSectionSize = ROUND_UP(secVirtSize ? secVirtSize : secSizeOfRawData, sectionAlign);

        if (0 == actualSectionSize)
        {
            CHAR name[9];
            memcpy(name, pSec->Name, sizeof(pSec->Name));
            name[8] = 0;

            ERROR("[ERROR] Section %d (%s) for image at 0x%016llx has actual size 0. VirtualSize = 0x%08x "
                  "SizeOfRawData = 0x%08x Align = 0x%08x\n",
                  i, name, ImageBase, secVirtSize, secSizeOfRawData, sectionAlign);
            status = INT_STATUS_INVALID_OBJECT_TYPE;
            goto leave;
        }

        if (0 == pSec->VirtualAddress)
        {
            CHAR name[9];
            memcpy(name, pSec->Name, sizeof(pSec->Name));
            name[8] = 0;

            ERROR("[ERROR] Section starting at 0. Section name: %s\n", name);
            status = INT_STATUS_INVALID_OBJECT_TYPE;
            goto leave;
        }

        if (0 == secVirtSize && (0 == secSizeOfRawData || secSizeOfRawData > PAGE_SIZE))
        {
            CHAR name[9];
            memcpy(name, pSec->Name, sizeof(pSec->Name));
            name[8] = 0;

            ERROR("[ERROR] Section %d (%s) size is invalid for image at 0x%016llx. "
                  "VirtualSize: 0x%08x. SizeOfRawData: 0x%08x\n",
                  i, name, ImageBase, pSec->Misc.VirtualSize, pSec->SizeOfRawData);
            status = INT_STATUS_INVALID_OBJECT_TYPE;
            goto leave;
        }

        // Make sure the section fits within sizeOfImage
        if ((pSec->VirtualAddress >= sizeOfImage) ||
            (actualSectionSize > sizeOfImage) ||
            (pSec->VirtualAddress + actualSectionSize > sizeOfImage))
        {
            CHAR name[9];
            memcpy(name, pSec->Name, sizeof(pSec->Name));
            name[8] = 0;

            ERROR("[ERROR] Section %d (%s) for image at 0x%016llx seems corrupted: "
                  "sizeOfImage = 0x%x, secStart = 0x%x, secSize = 0x%x, actualSecSize = 0x%08x\n",
                  i, name, ImageBase, sizeOfImage, pSec->VirtualAddress, pSec->Misc.VirtualSize, actualSectionSize);
            status = INT_STATUS_INVALID_OBJECT_TYPE;
            goto leave;
        }
    }

    if (NULL != PeInfo)
    {
        PeInfo->Image64Bit = image64;
        PeInfo->SectionOffset = secOff;
        PeInfo->SizeOfImage = sizeOfImage;
        PeInfo->TimeDateStamp = timeDateStamp;
        PeInfo->EntryPoint = entryPoint;
        PeInfo->NumberOfSections = numberOfSections;
        PeInfo->Subsystem = subsystem;
        PeInfo->ImageBase = imageBase;
        PeInfo->SectionAlignment = sectionAlign;
        PeInfo->Machine = machine;
    }

    status = INT_STATUS_SUCCESS;

leave:
    if (NULL == ImageBaseBuffer)
    {
        IntVirtMemUnmap(&pBase);
    }

    return status;
}


INTSTATUS
IntPeListSectionsHeaders(
    _In_ QWORD ImageBase,
    _In_opt_ BYTE *ImageBuffer,
    _In_opt_ DWORD ImageBufferSize,
    _Out_ DWORD *FirstSectionOffset,
    _Out_ DWORD *SectionCount
    )
///
/// @brief Will get the offset to the first section header and the number of sections from the given module.
///
/// @param[in]  ImageBase           Guest virtual address of the beginning of the module (headers).
/// @param[in]  ImageBuffer         Address where the ImageBase is already mapped in Introcore space, if present.
/// @param[in]  ImageBufferSize     If ImageBaseBuffer is valid, this indicates its size.
/// @param[out] FirstSectionOffset  Offset to the first section header.
/// @param[out] SectionCount        Number of sections.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
/// @retval #INT_STATUS_INVALID_OBJECT_TYPE If the MZ/PE is malformed or corrupted in any way.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;
    BYTE *pBase;
    DWORD size = 0;
    INTRO_PE_INFO peInfo = {0};

    if (NULL == FirstSectionOffset)
    {
        return INT_STATUS_INVALID_PARAMETER_4;
    }

    if (NULL == SectionCount)
    {
        return INT_STATUS_INVALID_PARAMETER_5;
    }

    if (NULL != ImageBuffer)
    {
        pBase = ImageBuffer;
        size = ImageBufferSize;
    }
    else
    {
        status = IntVirtMemMap(ImageBase, PAGE_SIZE, gGuest.Mm.SystemCr3, 0, &pBase);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntVirtMemMap failed: 0x%08x\n", status);
            return status;
        }

        size = PAGE_SIZE;
    }

    status = IntPeValidateHeader(ImageBase, pBase, size, &peInfo, 0);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntPeValidateHeader failed: 0x%08x\n", status);
        goto cleanup_and_exit;
    }

    *FirstSectionOffset = (DWORD)peInfo.SectionOffset;
    *SectionCount = (DWORD)peInfo.NumberOfSections;

cleanup_and_exit:
    if (NULL == ImageBuffer)
    {
        // Don't override the status from IntPeValidateHeader
        INTSTATUS status2 = IntVirtMemUnmap(&pBase);
        if (!INT_SUCCESS(status2))
        {
            ERROR("[ERROR] IntVirtMemUnmap failed: 0x%08x\n", status2);
        }
    }

    return status;
}


INTSTATUS
IntPeGetDirectory(
    _In_ QWORD ImageBase,
    _In_opt_ BYTE *ImageBaseBuffer,
    _In_ DWORD DirectoryEntry,
    _Out_ IMAGE_DATA_DIRECTORY *Directory
    )
///
/// @brief Validate & return the indicated image data directory.
///
/// @param[in]  ImageBase           Guest virtual address of the beginning of the module (headers).
/// @param[in]  ImageBaseBuffer     Address where the ImageBase is already mapped in Introcore space, if present.
/// @param[in]  DirectoryEntry      Data directory entry to be fetched.
/// @param[out] Directory           Will contain, upon successful return, the requested data directory.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
/// @retval #INT_STATUS_INVALID_OBJECT_TYPE If the MZ/PE is malformed or corrupted in any way.
/// @retval #INT_STATUS_NOT_FOUND If the indicated data directory is not present.
///

{
    INTSTATUS status;
    BOOLEAN unmapNtHeaders;
    BYTE *map;
    IMAGE_DOS_HEADER *pDosHeader;
    IMAGE_NT_HEADERS64 *pNth64;
    IMAGE_NT_HEADERS32 *pNth32;
    INTRO_PE_INFO peInfo = {0};

    if (DirectoryEntry > IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR)
    {
        return INT_STATUS_INVALID_PARAMETER_3;
    }

    if (NULL == Directory)
    {
        return INT_STATUS_INVALID_PARAMETER_4;
    }

    unmapNtHeaders = FALSE;

    if (NULL != ImageBaseBuffer)
    {
        map = ImageBaseBuffer;
    }
    else
    {
        status = IntVirtMemMap(ImageBase, PAGE_SIZE, 0, 0, &map);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] Failed mapping VA 0x%016llx to host: 0x%08x\n", ImageBase, status);
            return status;
        }
    }

    // First thing, validate the buffer
    status = IntPeValidateHeader(ImageBase, map, PAGE_SIZE, &peInfo, 0);
    if (!INT_SUCCESS(status))
    {
        goto leave;
    }

    pDosHeader = (IMAGE_DOS_HEADER *)map;

    if (peInfo.Image64Bit)
    {
        QWORD e_lfanew = (DWORD)pDosHeader->e_lfanew;

        if (e_lfanew + sizeof(IMAGE_NT_HEADERS64) <= PAGE_SIZE)
        {
            pNth64 = (IMAGE_NT_HEADERS64 *)(map + e_lfanew);
        }
        else
        {
            status = IntVirtMemMap(ImageBase + e_lfanew, sizeof(*pNth64), 0, 0, &pNth64);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] Failed mapping VA 0x%016llx to host: 0x%08x\n", ImageBase + e_lfanew, status);
                goto leave;
            }

            unmapNtHeaders = TRUE;
        }

        Directory->Size = pNth64->OptionalHeader.DataDirectory[DirectoryEntry].Size;
        Directory->VirtualAddress = pNth64->OptionalHeader.DataDirectory[DirectoryEntry].VirtualAddress;
    }
    else
    {
        QWORD e_lfanew = (DWORD)pDosHeader->e_lfanew;

        if (e_lfanew + sizeof(IMAGE_NT_HEADERS32) <= PAGE_SIZE)
        {
            pNth32 = (IMAGE_NT_HEADERS32 *)(map + e_lfanew);
        }
        else
        {
            status = IntVirtMemMap(ImageBase + e_lfanew, sizeof(*pNth32), 0, 0, &pNth32);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] Failed mapping VA 0x%016llx to host: 0x%08x\n", ImageBase + e_lfanew, status);
                goto leave;
            }

            unmapNtHeaders = TRUE;
        }

        Directory->Size = pNth32->OptionalHeader.DataDirectory[DirectoryEntry].Size;
        Directory->VirtualAddress = pNth32->OptionalHeader.DataDirectory[DirectoryEntry].VirtualAddress;
    }

    if (Directory->VirtualAddress == 0 || Directory->Size == 0)
    {
        status = INT_STATUS_NOT_FOUND;
        goto leave;
    }

    // Validate the entry and return appropriate status when it's invalid
    if ((QWORD)Directory->Size + Directory->VirtualAddress > peInfo.SizeOfImage)
    {
        status = INT_STATUS_INVALID_OBJECT_TYPE;
        goto leave;
    }

    status = INT_STATUS_SUCCESS;

leave:
    if (unmapNtHeaders)
    {
        if (peInfo.Image64Bit)
        {
            IntVirtMemUnmap(&pNth64);
        }
        else
        {
            IntVirtMemUnmap(&pNth32);
        }
    }

    if (NULL == ImageBaseBuffer)
    {
        IntVirtMemUnmap(&map);
    }

    if (!INT_SUCCESS(status))
    {
        Directory->VirtualAddress = 0;
        Directory->Size = 0;
    }

    return status;
}


INTSTATUS
IntPeGetSectionHeaderByRva(
    _In_ QWORD ImageBase,
    _In_opt_ BYTE *ImageBaseBuffer,
    _In_ DWORD GuestRva,
    _Out_ IMAGE_SECTION_HEADER *SectionHeader
    )
///
/// @brief Given a relative virtual address, return the section header which describes the section the RVA lies in.
///
/// @param[in]  ImageBase           Guest virtual address of the beginning of the module (headers).
/// @param[in]  ImageBaseBuffer     Address where the ImageBase is already mapped in Introcore space, if present.
/// @param[in]  GuestRva            The RVA to be found.
/// @param[out] SectionHeader       Will contain, upon successful return, the section header describing the section
///                                 that contains the indicated RVA.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
/// @retval #INT_STATUS_INVALID_OBJECT_TYPE If the MZ/PE is malformed or corrupted in any way.
/// @retval #INT_STATUS_NOT_FOUND If a section containing the RVA is not found.
///
{
    INTSTATUS status;
    BOOLEAN unmapSecHeaders;
    DWORD i;
    IMAGE_SECTION_HEADER *pSecHeader;
    BYTE *map;
    INTRO_PE_INFO peInfo = {0};

    if (NULL == SectionHeader)
    {
        return INT_STATUS_INVALID_PARAMETER_4;
    }

    if (NULL != ImageBaseBuffer)
    {
        map = ImageBaseBuffer;
    }
    else
    {
        status = IntVirtMemMap(ImageBase, PAGE_SIZE, 0, 0, &map);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] Failed mapping VA 0x%016llx to host: 0x%08x\n", ImageBase, status);
            return status;
        }
    }

    unmapSecHeaders = FALSE;
    pSecHeader = NULL;

    // First thing, validate the buffer
    status = IntPeValidateHeader(ImageBase, map, PAGE_SIZE, &peInfo, 0);
    if (!INT_SUCCESS(status))
    {
        goto leave;
    }

    if (peInfo.SectionOffset + (peInfo.NumberOfSections * sizeof(IMAGE_SECTION_HEADER)) <= PAGE_SIZE)
    {
        // We are in the same page, so it's safe to use this
        pSecHeader = (IMAGE_SECTION_HEADER *)((BYTE *)map + peInfo.SectionOffset);
    }

    // See that the sections aren't outside of the image
    if (peInfo.SectionOffset + peInfo.NumberOfSections * sizeof(IMAGE_SECTION_HEADER) > peInfo.SizeOfImage)
    {
        status = INT_STATUS_INVALID_OBJECT_TYPE;
        goto leave;
    }
    else if (peInfo.NumberOfSections > ((PAGE_SIZE * 2) / sizeof(IMAGE_SECTION_HEADER))) // ~227 sections
    {
        // Let's assume that the secCount == 65536, that will make us map 537 pages,
        // which on XEN means allocating 537 pages + memcpy, and Napoca will
        // probably just return INT_STATUS_INSUFFICIENT_RESOURCES. So, if secCount is bigger
        // than two pages, then search the given RVA only in two pages.
        WARNING("[WARNING] Image has %lld sections, which is a bit too much!\n", peInfo.NumberOfSections);
        peInfo.NumberOfSections = (PAGE_SIZE * 2) / sizeof(IMAGE_SECTION_HEADER);
    }

    // If the pSecHeader is NULL, then the sections doesn't end in the first page
    if (NULL == pSecHeader)
    {
        status = IntVirtMemMap(ImageBase + peInfo.SectionOffset,
                               (DWORD)(peInfo.NumberOfSections * sizeof(*pSecHeader)), 0, 0, &pSecHeader);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] Failed mapping VA 0x%016llx to host with size %llu: 0x%08x\n",
                  ImageBase + peInfo.SectionOffset, peInfo.NumberOfSections * sizeof(IMAGE_SECTION_HEADER), status);
            goto leave;
        }

        unmapSecHeaders = TRUE;
    }

    for (i = 0; i < peInfo.NumberOfSections; i++)
    {
        DWORD secEnd = pSecHeader[i].VirtualAddress +
                       ALIGN_UP((QWORD)pSecHeader[i].Misc.VirtualSize, peInfo.SectionAlignment);

        if (GuestRva >= pSecHeader[i].VirtualAddress &&
            GuestRva < secEnd)
        {
            memcpy(SectionHeader, &pSecHeader[i], sizeof(IMAGE_SECTION_HEADER));
            status = INT_STATUS_SUCCESS;
            goto leave;
        }
    }

    status = INT_STATUS_NOT_FOUND;

leave:
    if (unmapSecHeaders)
    {
        IntVirtMemUnmap(&pSecHeader);
    }

    if (NULL == ImageBaseBuffer)
    {
        IntVirtMemUnmap(&map);
    }

    if (!INT_SUCCESS(status))
    {
        memzero(SectionHeader, sizeof(*SectionHeader));
    }

    return status;
}


INTSTATUS
IntPeGetSectionHeaderByIndex(
    _In_ QWORD ImageBase,
    _In_opt_ BYTE *ImageBaseBuffer,
    _In_ DWORD Index,
    _Out_ IMAGE_SECTION_HEADER *SectionHeader
    )
///
/// @brief Return the section header located on position Index (0 based).
///
/// @param[in]  ImageBase           Guest virtual address of the beginning of the module (headers).
/// @param[in]  ImageBaseBuffer     Address where the ImageBase is already mapped in Introcore space, if present.
/// @param[in]  Index               Index of the section header to be returned (0 based).
/// @param[out] SectionHeader       Will contain, upon successful return, the section header located at Index.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
/// @retval #INT_STATUS_INVALID_OBJECT_TYPE If the MZ/PE is malformed or corrupted in any way.
/// @retval #INT_STATUS_NOT_FOUND If the section Index is not found.
///
{
    INTSTATUS status;
    IMAGE_SECTION_HEADER *pSecHeader;
    BYTE *map;
    INTRO_PE_INFO peInfo = {0};

    if (NULL == SectionHeader)
    {
        return INT_STATUS_INVALID_PARAMETER_4;
    }

    if (NULL != ImageBaseBuffer)
    {
        map = ImageBaseBuffer;
    }
    else
    {
        status = IntVirtMemMap(ImageBase, PAGE_SIZE, 0, 0, &map);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] Failed mapping VA 0x%016llx to host: 0x%08x\n", ImageBase, status);
            return status;
        }
    }

    pSecHeader = NULL;

    // First thing, validate the buffer
    status = IntPeValidateHeader(ImageBase, map, PAGE_SIZE, &peInfo, 0);
    if (!INT_SUCCESS(status))
    {
        goto leave;
    }

    if (peInfo.SectionOffset + (Index * sizeof(IMAGE_SECTION_HEADER)) <= PAGE_SIZE)
    {
        // We are in the same page, so it's safe to use this
        pSecHeader = (IMAGE_SECTION_HEADER *)((BYTE *)map + peInfo.SectionOffset);
    }

    // See that the sections aren't outside of the image
    if (peInfo.SectionOffset + peInfo.NumberOfSections * sizeof(IMAGE_SECTION_HEADER) > peInfo.SizeOfImage)
    {
        status = INT_STATUS_INVALID_OBJECT_TYPE;
        goto leave;
    }

    if (Index >= peInfo.NumberOfSections)
    {
        status = INT_STATUS_NOT_FOUND;
        goto leave;
    }

    // If the pSecHeader is NULL, then the section we are searching is not in the first page
    if (NULL == pSecHeader)
    {
        status = IntKernVirtMemRead(ImageBase + peInfo.SectionOffset + Index * sizeof(IMAGE_SECTION_HEADER),
                                    sizeof(IMAGE_SECTION_HEADER),
                                    SectionHeader,
                                    NULL);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] Failed reading section header from GVA 0x%016llx: 0x%08x\n",
                  ImageBase + peInfo.SectionOffset + Index * sizeof(IMAGE_SECTION_HEADER), status);
            goto leave;
        }
    }
    else
    {
        memcpy(SectionHeader, &pSecHeader[Index], sizeof(IMAGE_SECTION_HEADER));
    }

    status = INT_STATUS_SUCCESS;

leave:
    if (NULL == ImageBaseBuffer)
    {
        IntVirtMemUnmap(&map);
    }

    return status;
}


INTSTATUS
IntPeGetSectionHeadersByName(
    _In_ QWORD ImageBase,
    _In_opt_ BYTE *ImageBaseBuffer,
    _In_reads_or_z_(8) PCHAR Name,
    _In_ DWORD NumberOfSectionHeadersAllocated,
    _In_ QWORD Cr3,
    _Out_ IMAGE_SECTION_HEADER *SectionHeaders,
    _Out_opt_ DWORD *NumberOfSectionHeadersFilled
    )
///
/// @brief Return all the section headers matching the indicated Name.
///
/// @param[in]  ImageBase           Guest virtual address of the beginning of the module (headers).
/// @param[in]  ImageBaseBuffer     Address where the ImageBase is already mapped in Introcore space, if present.
/// @param[in]  Name                The name of the searched sections.
/// @param[in]  NumberOfSectionHeadersAllocated Number of section headers allocated for the results.
/// @param[in]  Cr3                 The Cr3 used for mapping the headers in case ImageBaseBuffer is not provided.
/// @param[out] SectionHeaders      Buffer containing NumberOfSectionHeadersAllocated slots.
/// @param[out] NumberOfSectionHeadersFilled    Number of slots filled in the SectionHeaders = number of sections found
///                                             to have the indicated Name.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
/// @retval #INT_STATUS_INVALID_OBJECT_TYPE If the MZ/PE is malformed or corrupted in any way.
/// @retval #INT_STATUS_NOT_FOUND If no section with the given name is found.
///
{
    INTSTATUS status;
    BOOLEAN unmapSecHeaders;
    DWORD numberSectionsFound;
    BYTE *map;
    IMAGE_SECTION_HEADER *pSecHeader;
    INTRO_PE_INFO peInfo = {0};
    SIZE_T cmpSize;

    if (0 == NumberOfSectionHeadersAllocated)
    {
        return INT_STATUS_INVALID_PARAMETER_4;
    }

    if (NULL == SectionHeaders)
    {
        return INT_STATUS_INVALID_PARAMETER_5;
    }

    if (NULL != ImageBaseBuffer)
    {
        map = ImageBaseBuffer;
    }
    else
    {
        status = IntVirtMemMap(ImageBase, PAGE_SIZE, Cr3, 0, &map);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] Failed mapping VA 0x%016llx to host: 0x%08x\n", ImageBase, status);
            return status;
        }
    }

    unmapSecHeaders = FALSE;
    pSecHeader = NULL;
    numberSectionsFound = 0;

    // First thing, validate the buffer
    status = IntPeValidateHeader(ImageBase, map, PAGE_SIZE, &peInfo, 0);
    if (!INT_SUCCESS(status))
    {
        goto leave;
    }

    if (peInfo.SectionOffset + (peInfo.NumberOfSections * sizeof(IMAGE_SECTION_HEADER)) <= PAGE_SIZE)
    {
        // We are in the same page, so it's safe to use this
        pSecHeader = (IMAGE_SECTION_HEADER *)((BYTE *)map + peInfo.SectionOffset);
    }

    // See that the sections aren't outside of the image
    if (peInfo.SectionOffset + peInfo.NumberOfSections * sizeof(IMAGE_SECTION_HEADER) > peInfo.SizeOfImage)
    {
        status = INT_STATUS_INVALID_OBJECT_TYPE;
        goto leave;
    }
    else if (peInfo.NumberOfSections > ((PAGE_SIZE * 2) / sizeof(IMAGE_SECTION_HEADER))) // ~227 sections
    {
        // Let's assume that the secCount == 65536, that will make us map 537 pages,
        // which on XEN means allocating 537 pages + memcpy, and Napoca will
        // probably just return INT_STATUS_INSUFFICIENT_RESOURCES. So, if secCount is bigger
        // than two pages, then search the given RVA only in two pages.
        WARNING("[WARNING] Image has %lld sections, which is a bit too much!\n", peInfo.NumberOfSections);
        peInfo.NumberOfSections = (PAGE_SIZE * 2) / sizeof(IMAGE_SECTION_HEADER);
    }

    // If the pSecHeader is NULL, then the sections doesn't end in the first page
    if (NULL == pSecHeader)
    {
        status = IntVirtMemMap(ImageBase + peInfo.SectionOffset,
                               (DWORD)(peInfo.NumberOfSections * sizeof(IMAGE_SECTION_HEADER)), 0, 0, &pSecHeader);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] Failed mapping VA 0x%016llx to host with size 0x%016llx: 0x%08x\n",
                  ImageBase + peInfo.SectionOffset, peInfo.NumberOfSections * sizeof(IMAGE_SECTION_HEADER), status);
            goto leave;
        }

        unmapSecHeaders = TRUE;
    }

    // We use memcmp, so add 1 to also compare the NULL terminator
    cmpSize = strlen(Name) + 1;
    // Section names are not guaranteed to be NULL terminated, so if we go past that, limit the compare size to 8
    cmpSize = MIN(cmpSize, IMAGE_SIZEOF_SHORT_NAME);
    for (size_t i = 0; i < peInfo.NumberOfSections; i++)
    {
        if (memcmp(Name, pSecHeader[i].Name, cmpSize) == 0)
        {
            memcpy(&SectionHeaders[numberSectionsFound], &pSecHeader[i], sizeof(IMAGE_SECTION_HEADER));

            numberSectionsFound++;

            if (numberSectionsFound == NumberOfSectionHeadersAllocated)
            {
                break;
            }
        }
    }

    if (0 == numberSectionsFound)
    {
        status = INT_STATUS_NOT_FOUND;
    }
    else
    {
        status = INT_STATUS_SUCCESS;
    }

    if (NULL != NumberOfSectionHeadersFilled)
    {
        *NumberOfSectionHeadersFilled = numberSectionsFound;
    }

leave:
    if (unmapSecHeaders)
    {
        IntVirtMemUnmap(&pSecHeader);
    }

    if (NULL == ImageBaseBuffer)
    {
        IntVirtMemUnmap(&map);
    }

    if (!INT_SUCCESS(status))
    {
        memzero(SectionHeaders, sizeof(*SectionHeaders) * NumberOfSectionHeadersAllocated);
    }

    return status;
}


INTSTATUS
IntPeFindExportByRva(
    _In_ QWORD ImageBase,
    _In_opt_ BYTE *ImageBaseBuffer,
    _In_ DWORD Rva
    )
///
/// @brief Check if a RVA lies inside an exported function.
///
/// Will return success if the given RVA is inside an exported function. Does not return the name since that would be
/// slow. For getting the name use the IntPeGetExportNameByRva.
///
/// @param[in]  ImageBase       Guest virtual address of the beginning of the module (headers).
/// @param[in]  ImageBaseBuffer Address where the ImageBase is already mapped in Introcore space, if present.
/// @param[in]  Rva             The Rva to be checked.
///
/// @retval #INT_STATUS_SUCCESS If the indicated Rva lies within an export.
/// @retval #INT_STATUS_NOT_FOUND if the RVA isn't inside an exported function
/// @retval #INT_STATUS_INVALID_OBJECT_TYPE if the ImageBase isn't a valid PE/PE+ object
///
{
    INTSTATUS status;
    DWORD beginRva, i, size;
    QWORD address;
    IMAGE_DATA_DIRECTORY dir;
    IMAGE_EXPORT_DIRECTORY exportDir;
    BOOLEAN found;
    BYTE *functions;
    BYTE *map;

    found = FALSE;

    if (NULL != ImageBaseBuffer)
    {
        map = ImageBaseBuffer;
    }
    else
    {
        status = IntVirtMemMap(ImageBase, PAGE_SIZE, 0, 0, &map);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] Failed mapping VA 0x%016llx to host: 0x%08x\n", ImageBase, status);
            return status;
        }
    }

    // Get the export directory, if present
    status = IntPeGetDirectory(ImageBase, map, IMAGE_DIRECTORY_ENTRY_EXPORT, &dir);
    if (!INT_SUCCESS(status))
    {
        goto leave;
    }

    // Find the start of the function
    status = IntPeFindFunctionStart(ImageBase, map, Rva, &beginRva);
    if (!INT_SUCCESS(status))
    {
        goto leave;
    }

    // Read the export directory
    status = IntKernVirtMemRead(ImageBase + dir.VirtualAddress, sizeof(IMAGE_EXPORT_DIRECTORY), &exportDir, NULL);
    if (!INT_SUCCESS(status))
    {
        goto leave;
    }

    // Parse the export directory and find the function corresponding to this (if any)
    // Cap the number of searched symbols to MAX_NUMBER_OF_EXPORT_NAMES
    size = MIN(exportDir.NumberOfFunctions, MAX_NUMBER_OF_EXPORT_NAMES) * 4;
    address = ImageBase + exportDir.AddressOfFunctions;

    for (i = 0; i < size; i += PAGE_SIZE)
    {
        DWORD parsed = 0;
        DWORD mappingSize = (i < (size & PAGE_MASK)) ? PAGE_SIZE : (address & PAGE_OFFSET);

        status = IntVirtMemMap(address & PAGE_MASK, PAGE_SIZE, 0, 0, &functions);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] Failed mapping AddressOfFunctions 0x%016llx (0x%016llx + 0x%08x): 0x%08x\n",
                  address & PAGE_MASK, ImageBase, exportDir.AddressOfFunctions, status);
            goto leave;
        }

        // has meaning only on the first map, on the rest it's already aligned
        functions += address & PAGE_OFFSET;

        while (parsed + mappingSize < PAGE_SIZE)
        {
            // We don't care about forwarded addresses (they still are exported)
            if (*(DWORD *)(functions + parsed) == beginRva)
            {
                found = TRUE;
                break;
            }
            parsed += 4;
        }

        functions -= address & PAGE_OFFSET;
        address += mappingSize; // this will align the address

        IntVirtMemUnmap(&functions);
    }

    if (!found)
    {
        status = INT_STATUS_NOT_FOUND;
    }

leave:
    if (NULL == ImageBaseBuffer)
    {
        IntVirtMemUnmap(&map);
    }

    return status;
}


INTSTATUS
IntPeFindExportByRvaInBuffer(
    _In_ QWORD ImageBase,
    _In_ BYTE *Buffer,
    _In_ DWORD BufferSize,
    _In_ DWORD Rva
    )
///
/// @brief Check if the indicated Rva belongs to an exported function.
///
/// Will return success if the given RVA is inside an exported function. Does not return the name since that would be
/// slow. For getting the name use the IntPeGetExportNameByRva.
///
/// @param[in]  ImageBase       Guest virtual address of the beginning of the module (headers).
/// @param[in]  Buffer          Buffer containing the module.
/// @param[in]  BufferSize      The size of the buffer containing the module.
/// @param[in]  Rva             The Rva to be found.
///
/// @retval #INT_STATUS_SUCCESS If an export is found to contain the given Rva.
/// @retval #INT_STATUS_NOT_FOUND if the RVA isn't inside an exported function
/// @retval STATUS_INVALID_OBJECT_TYPE if the ImageBase isn't a valid PE/PE+ object
///
{
    INTSTATUS status;
    DWORD beginRva;
    QWORD size;
    IMAGE_EXPORT_DIRECTORY exportDir;
    IMAGE_DATA_DIRECTORY dir;

    // Firstly, validate that headers are valid before going through EAT
    status = IntPeValidateHeader(ImageBase, Buffer, BufferSize, NULL, 0);
    if (!INT_SUCCESS(status))
    {
        return status;
    }

    // Find the start of the function
    status = IntPeFindFunctionStart(ImageBase, Buffer, Rva, &beginRva);
    if (!INT_SUCCESS(status))
    {
        return status;
    }

    status = IntPeGetDirectory(ImageBase, Buffer, IMAGE_DIRECTORY_ENTRY_EXPORT, &dir);
    if (!INT_SUCCESS(status))
    {
        return status;
    }

    if ((QWORD)dir.VirtualAddress + dir.Size > BufferSize)
    {
        return INT_STATUS_INVALID_DATA_SIZE;
    }

    // We want to make sure that we don't overflow the buffer even for some special crafted size
    // (e.g. dir.VirtualAddress = BufferSize - 1, dir.Size = 1, but dir.VirtualAddress + sizeof(IMAGE_EXPORT_DIRECTORY)
    // is > BufferSize)
    if ((QWORD)dir.VirtualAddress + sizeof(IMAGE_EXPORT_DIRECTORY) > BufferSize)
    {
        return INT_STATUS_INVALID_DATA_SIZE;
    }

    exportDir = *(IMAGE_EXPORT_DIRECTORY *)(Buffer + dir.VirtualAddress);

    size = (QWORD)MIN(exportDir.NumberOfFunctions, MAX_NUMBER_OF_EXPORT_NAMES) * 4;

    if (size > BufferSize)
    {
        return INT_STATUS_INVALID_DATA_TYPE;
    }

    for (DWORD i = 0; i < size; i += 4)
    {
        if ((QWORD)exportDir.AddressOfFunctions + i + sizeof(DWORD) > BufferSize)
        {
            continue;
        }

        // We don't care about forwarded addresses (they still are exported)
        if (*(DWORD *)(Buffer + exportDir.AddressOfFunctions + i) == beginRva)
        {
            return INT_STATUS_SUCCESS;
        }
    }

    return INT_STATUS_NOT_FOUND;
}


INTSTATUS
IntPeGetExportNameByRva(
    _In_ QWORD ImageBase,
    _In_opt_ BYTE *ImageBaseBuffer,
    _In_ DWORD Rva,
    _In_ DWORD ExportNameSize,
    _Out_writes_z_(ExportNameSize) CHAR *ExportName
    )
///
/// @brief Find the export name a Rva lies in.
///
/// @param[in]  ImageBase       Guest virtual address of the beginning of the module (headers).
/// @param[in]  ImageBaseBuffer Address where the ImageBase is already mapped in Introcore space, if present.
/// @param[in]  Rva             The Rva for which we wish to find the export name.
/// @param[in]  ExportNameSize  Maximum length of the ExportName buffer, which will contain the export name, including
///                             the NULL-terminator.
/// @param[out] ExportName      Will contain upon successful return the name of the export Rva belongs to.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_NOT_FOUND If no export containing the Rva is found.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
/// @retval #INT_STATUS_INVALID_OBJECT_TYPE If the MZ/PE file is malformed or corrupted in any way.
///
{
    INTSTATUS status;
    DWORD i;
    BOOLEAN found;
    IMAGE_EXPORT_DIRECTORY exportDir;
    IMAGE_DATA_DIRECTORY dir;
    BYTE *map;

    if (0 == ExportNameSize)
    {
        return INT_STATUS_INVALID_PARAMETER_4;
    }

    if (NULL == ExportName)
    {
        return INT_STATUS_INVALID_PARAMETER_5;
    }

    if (NULL != ImageBaseBuffer)
    {
        map = ImageBaseBuffer;
    }
    else
    {
        status = IntVirtMemMap(ImageBase, PAGE_SIZE, 0, 0, &map);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] Failed mapping VA 0x%016llx to host: 0x%08x\n", ImageBase, status);
            return status;
        }
    }

    // Get the export directory, if present
    status = IntPeGetDirectory(ImageBase, map, IMAGE_DIRECTORY_ENTRY_EXPORT, &dir);
    if (!INT_SUCCESS(status))
    {
        goto _cleanup_and_leave;
    }

    status = IntKernVirtMemRead(ImageBase + dir.VirtualAddress, sizeof(IMAGE_EXPORT_DIRECTORY), &exportDir, NULL);
    if (!INT_SUCCESS(status))
    {
        if (status != INT_STATUS_PAGE_NOT_PRESENT)
        {
            // Export directory is pageable so it CAN happen to not be present, so don't spam
            WARNING("[WARNING] Failed to read the export directory of 0x%016llx located at 0x%016llx: 0x%08x\n",
                    ImageBase, ImageBase + dir.VirtualAddress, status);
        }
        goto _cleanup_and_leave;
    }

    found = FALSE;

    if (exportDir.NumberOfNames > MAX_NUMBER_OF_EXPORT_NAMES)
    {
        ERROR("[ERROR] Number of names %d exceeds %lu!\n", exportDir.NumberOfNames, MAX_NUMBER_OF_EXPORT_NAMES);
        status = INT_STATUS_INVALID_DATA_TYPE;
        goto _cleanup_and_leave;
    }

    for (i = 0; i < exportDir.NumberOfNames; i++)
    {
        DWORD exportOrdinal, exportRva, namePointer, retLen;

        // Get this name's ordinal; note that ordinals are 2 bytes in size
        status = IntKernVirtMemFetchDword(ImageBase + exportDir.AddressOfNameOrdinals + i * 2ull, &exportOrdinal);
        if (!INT_SUCCESS(status))
        {
            continue;
        }
        exportOrdinal &= 0xFFFF;

        // Read the export RVA
        status = IntKernVirtMemFetchDword(ImageBase + exportDir.AddressOfFunctions + exportOrdinal * 4ull, &exportRva);
        if (!INT_SUCCESS(status))
        {
            continue;
        }

        if (exportRva != Rva)
        {
            continue;
        }

        // Get the name pointer (RVA)
        status = IntKernVirtMemFetchDword(ImageBase + exportDir.AddressOfNames + i * 4ull, &namePointer);
        if (!INT_SUCCESS(status))
        {
            goto _cleanup_and_leave;
        }

        // Read the name
        status = IntKernVirtMemRead(ImageBase + namePointer, ExportNameSize, ExportName, &retLen);
        if (!INT_SUCCESS(status))
        {
            goto _cleanup_and_leave;
        }

        // retLen will always have the same value as ExportNameSize in this case
        ExportName[retLen - 1] = 0;

        found = TRUE;
        status = INT_STATUS_SUCCESS;
        break;
    }

    if (!found)
    {
        status = INT_STATUS_NOT_FOUND;
        goto _cleanup_and_leave;
    }

_cleanup_and_leave:
    if (ImageBaseBuffer == NULL)
    {
        IntVirtMemUnmap(&map);
    }

    return status;
}


INTSTATUS
IntPeGetExportNameByRvaInBuffer(
    _In_ QWORD ImageBase,
    _In_ BYTE *Buffer,
    _In_ DWORD BufferSize,
    _In_ DWORD Rva,
    _In_ DWORD ExportNameSize,
    _Out_writes_z_(ExportNameSize) CHAR *ExportName
    )
///
/// @brief Find the export name a Rva lies in.
///
/// @param[in]  ImageBase       Guest virtual address of the beginning of the module (headers).
/// @param[in]  Buffer          Buffer containing the MZ/PE image.
/// @param[in]  BufferSize      Size of the Buffer containing the MZ/PE image.
/// @param[in]  Rva             The Rva for which we wish to find the export name.
/// @param[in]  ExportNameSize  Maximum length of the ExportName buffer, which will contain the export name.
/// @param[out] ExportName      Will contain upon successful return the name of the export Rva belongs to.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_NOT_FOUND If no export containing the Rva is found.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
/// @retval #INT_STATUS_INVALID_OBJECT_TYPE If the MZ/PE file is malformed or corrupted in any way.
///
{
    INTSTATUS status;
    DWORD i;
    IMAGE_EXPORT_DIRECTORY exportDir;
    IMAGE_DATA_DIRECTORY dir;

    if (NULL == Buffer)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    if (0 == BufferSize)
    {
        return INT_STATUS_INVALID_PARAMETER_3;
    }

    if (0 == ExportNameSize)
    {
        return INT_STATUS_INVALID_PARAMETER_5;
    }

    if (NULL == ExportName)
    {
        return INT_STATUS_INVALID_PARAMETER_6;
    }

    // Firstly, validate that headers are valid before going through EAT
    status = IntPeValidateHeader(ImageBase, Buffer, BufferSize, NULL, 0);
    if (!INT_SUCCESS(status))
    {
        return status;
    }

    // Get the export directory, if present
    status = IntPeGetDirectory(ImageBase, Buffer, IMAGE_DIRECTORY_ENTRY_EXPORT, &dir);
    if (!INT_SUCCESS(status))
    {
        return status;
    }

    if ((QWORD)dir.VirtualAddress + dir.Size > BufferSize)
    {
        return INT_STATUS_INVALID_DATA_TYPE;
    }

    // We want to make sure that we don't overflow the buffer even for some special crafted size
    // (e.g. dir.VirtualAddress = BufferSize - 1, dir.Size = 1, but dir.VirtualAddress +
    // sizeof(IMAGE_EXPORT_DIRECTORY) is > BufferSize)
    if ((QWORD)dir.VirtualAddress + sizeof(IMAGE_EXPORT_DIRECTORY) > BufferSize)
    {
        return INT_STATUS_INVALID_DATA_TYPE;
    }

    // Read the export directory
    exportDir = *(IMAGE_EXPORT_DIRECTORY *)(Buffer + dir.VirtualAddress);
    if (exportDir.NumberOfNames > MAX_NUMBER_OF_EXPORT_NAMES)
    {
        ERROR("[ERROR] Number of names %d exceeds %lu!\n", exportDir.NumberOfNames, MAX_NUMBER_OF_EXPORT_NAMES);
        return INT_STATUS_INVALID_DATA_TYPE;
    }

    for (i = 0; i < exportDir.NumberOfNames; i++)
    {
        DWORD exportOrdinal, exportRva, namePointer;

        // Get this name's ordinal; note that ordinals are 2 bytes in size
        if ((QWORD)exportDir.AddressOfNameOrdinals + i * 2ull + sizeof(DWORD) > BufferSize)
        {
            continue;
        }

        exportOrdinal = (*(DWORD *)(Buffer + exportDir.AddressOfNameOrdinals + i * 2ull)) & 0xFFFF;
        if ((QWORD)exportDir.AddressOfFunctions + exportOrdinal * 4ull + sizeof(DWORD) > BufferSize)
        {
            continue;
        }

        exportRva = *(DWORD *)(Buffer + exportDir.AddressOfFunctions + exportOrdinal * 4ull);
        if (exportRva != Rva)
        {
            continue;
        }

        if ((QWORD)exportDir.AddressOfNames + i * 4ull + sizeof(DWORD) > BufferSize)
        {
            return INT_STATUS_INVALID_DATA_TYPE;
        }

        // Get the name pointer (RVA)
        namePointer = *(DWORD *)(Buffer + exportDir.AddressOfNames + i * 4ull);
        if ((QWORD)namePointer + ExportNameSize > BufferSize)
        {
            return INT_STATUS_INVALID_DATA_TYPE;
        }

        // Read the name
        strlcpy(ExportName, (char *)Buffer + namePointer, ExportNameSize);

        return INT_STATUS_SUCCESS;
    }

    return INT_STATUS_NOT_FOUND;
}


INTSTATUS
IntPeFindExportByNameInBuffer(
    _In_ QWORD ImageBase,
    _In_bytecount_(BufferSize) BYTE *Buffer,
    _In_ DWORD BufferSize,
    _In_z_ const char *Name,
    _Out_ DWORD *ExportRva
    )
///
/// @brief Find the export name a Rva lies in.
///
/// @param[in]  ImageBase       Guest virtual address of the beginning of the module (headers).
/// @param[in]  Buffer          Buffer containing the MZ/PE image.
/// @param[in]  BufferSize      Size of the Buffer containing the MZ/PE image.
/// @param[in]  Name            Export name to be found.
/// @param[out] ExportRva       Rva the indicated export is found at.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_NOT_FOUND If no export containing the Rva is found.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
/// @retval #INT_STATUS_INVALID_OBJECT_TYPE If the MZ/PE file is malformed or corrupted in any way.
///
{
    INTSTATUS status;
    IMAGE_DATA_DIRECTORY dir;
    size_t exportNameLen;
    int left, right;
    IMAGE_EXPORT_DIRECTORY *pExpDir;

    if (NULL == Buffer)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    if (NULL == Name)
    {
        return INT_STATUS_INVALID_PARAMETER_4;
    }

    if (NULL == ExportRva)
    {
        return INT_STATUS_INVALID_PARAMETER_5;
    }

    exportNameLen = strlen(Name);
    *ExportRva = 0;

    if (exportNameLen >= 512)
    {
        return INT_STATUS_INVALID_PARAMETER_4;
    }

    // Firstly, validate that headers are valid before going through EAT
    status = IntPeValidateHeader(ImageBase, Buffer, BufferSize, NULL, 0);
    if (!INT_SUCCESS(status))
    {
        return status;
    }

    status = IntPeGetDirectory(ImageBase, Buffer, IMAGE_DIRECTORY_ENTRY_EXPORT, &dir);
    if (!INT_SUCCESS(status))
    {
        return status;
    }

    if ((QWORD)dir.VirtualAddress + dir.Size > BufferSize)
    {
        return INT_STATUS_INVALID_DATA_SIZE;
    }

    // We want to make sure that we don't overflow the buffer even for some special crafted size
    // (e.g. dir.VirtualAddress = BufferSize - 1, dir.Size = 1, but dir.VirtualAddress + sizeof(IMAGE_EXPORT_DIRECTORY)
    // is > BufferSize)
    if ((QWORD)dir.VirtualAddress + sizeof(IMAGE_EXPORT_DIRECTORY) > BufferSize)
    {
        return INT_STATUS_INVALID_DATA_TYPE;
    }

    // There is a validation done by IntPeGetDirectory with peinfo.SizeOfImage,
    // but we should also validate against BufferSize
    pExpDir = (IMAGE_EXPORT_DIRECTORY *)(Buffer + dir.VirtualAddress);

    left = 0;
    right = pExpDir->NumberOfNames;

    while (left < right)
    {
        DWORD namePointer;
        size_t offset;
        size_t cmpSize = exportNameLen + 1;
        int mid, res;

        mid = (left + right) / 2;

        offset = pExpDir->AddressOfNames + mid * 4ull;
        if (offset + sizeof(namePointer) > BufferSize)
        {
            WARNING("[WARNING] Corrupted export name pointer: 0x%lx is outside of image size of 0x%x\n",
                    offset + sizeof(namePointer), BufferSize);
            return INT_STATUS_INVALID_DATA_TYPE;
        }

        namePointer = *(DWORD *)(Buffer + offset);

        if (namePointer >= BufferSize)
        {
            WARNING("[WARNING] Corrupted export name. Name pointer 0x%08x is outside of image size: 0x%08x\n",
                    namePointer, BufferSize);
            return INT_STATUS_INVALID_DATA_TYPE;
        }

        if (namePointer + cmpSize > BufferSize)
        {
            // Don't leave with an error, we still need to do the comparison, maybe the export directory is at
            // the end of the image, and what we search for it's really big
            cmpSize = BufferSize - namePointer;
        }

        // Compares the null-terminator too so we can avoid cases like: ExAllocatePool equals ExAllocatePoolWithTag
        res = memcmp(Name, Buffer + namePointer, cmpSize);

        if (0 == res)
        {
            WORD ord;

            offset = pExpDir->AddressOfNameOrdinals + mid * 2ull;
            if (offset + sizeof(ord) > BufferSize)
            {
                WARNING("[WARNING] Corrupted export ordinal: 0x%lx is outside of image size of 0x%x\n",
                        offset + sizeof(ord), BufferSize);
                return INT_STATUS_INVALID_DATA_TYPE;
            }

            ord = *(WORD *)(Buffer + offset);

            offset = pExpDir->AddressOfFunctions + ord * 4ull;
            if (offset + sizeof(*ExportRva) > BufferSize)
            {
                WARNING("[WARNING] Corrupted export address: 0x%lx is outside of image size of 0x%x\n",
                        offset + sizeof(*ExportRva), BufferSize);
                return INT_STATUS_INVALID_DATA_TYPE;
            }

            *ExportRva = *(DWORD *)(Buffer + offset);

            // It's the callers duty to see if this is forwarded
            return INT_STATUS_SUCCESS;
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

    return INT_STATUS_NOT_FOUND;
}


INTSTATUS
IntPeFindKernelExport(
    _In_z_ const char *Name,
    _Out_ QWORD *ExportGva
    )
///
/// @brief Find an export inside the NT kernel image.
///
/// @param[in]  Name        Export to be found.
/// @param[out] ExportGva   Guest virtual address (NOT RVA!) of the identified export.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    INTSTATUS status;
    DWORD rva;

    *ExportGva = 0;

    status = IntPeFindExportByNameInBuffer(gGuest.KernelVa,
                                           gWinGuest->KernelBuffer,
                                           gWinGuest->KernelBufferSize,
                                           Name,
                                           &rva);
    if (!INT_SUCCESS(status))
    {
        return status;
    }

    *ExportGva = gGuest.KernelVa + rva;

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntPeFindExportByName(
    _In_ QWORD ImageBase,
    _In_opt_ BYTE *ImageBaseBuffer,
    _In_z_ CHAR *Name,
    _Out_ DWORD *ExportRva
    )
///
/// @brief Find the export name a Rva lies in.
///
/// @param[in]  ImageBase       Guest virtual address of the beginning of the module (headers).
/// @param[in]  ImageBaseBuffer Buffer containing the MZ/PE image.
/// @param[in]  Name            Export name to be found.
/// @param[out] ExportRva       Rva the indicated export is found at.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_NOT_FOUND If no export containing the Rva is found.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
/// @retval #INT_STATUS_INVALID_OBJECT_TYPE If the MZ/PE file is malformed or corrupted in any way.
/// @retval #INT_STATUS_INSUFFICIENT_RESOURCES If a memory alloc fails.
///
{
    SIZE_T exportNameLen;
    BOOLEAN found;
    INTSTATUS status;
    IMAGE_DATA_DIRECTORY dir;
    BYTE *map;
    BYTE *exportNameBuffer;
    IMAGE_EXPORT_DIRECTORY exportDir;
    int left, right;

    if (NULL == Name)
    {
        return INT_STATUS_INVALID_PARAMETER_3;
    }

    if (NULL == ExportRva)
    {
        return INT_STATUS_INVALID_PARAMETER_4;
    }

    exportNameBuffer = NULL;
    found = FALSE;
    exportNameLen = strlen(Name);

    if (exportNameLen >= 512)
    {
        return INT_STATUS_INVALID_PARAMETER_4;
    }

    if (NULL != ImageBaseBuffer)
    {
        map = ImageBaseBuffer;
    }
    else
    {
        status = IntVirtMemMap(ImageBase, PAGE_SIZE, 0, 0, &map);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] Failed mapping VA 0x%016llx to host: 0x%08x\n", ImageBase, status);
            return status;
        }
    }

    // Get the export directory, if present
    status = IntPeGetDirectory(ImageBase, map, IMAGE_DIRECTORY_ENTRY_EXPORT, &dir);
    if (!INT_SUCCESS(status))
    {
        goto leave;
    }

    // Read the export directory
    status = IntKernVirtMemRead(ImageBase + dir.VirtualAddress, sizeof(IMAGE_EXPORT_DIRECTORY), &exportDir, NULL);
    if (!INT_SUCCESS(status))
    {
        // Export directory is pageable so it CAN happen to not be present, so don't spam
        if (status != INT_STATUS_PAGE_NOT_PRESENT)
        {
            WARNING("[ERROR] Failed to read the export directory of 0x%016llx located at 0x%016llx: 0x%08x\n",
                    ImageBase, ImageBase + dir.VirtualAddress, status);
        }
        goto leave;
    }

    // exportNameLen + 1 OK: exportNameLen is not longer than 512.
    exportNameBuffer = HpAllocWithTag(exportNameLen + 1ull, IC_TAG_EXPN);
    if (NULL == exportNameBuffer)
    {
        status = INT_STATUS_INSUFFICIENT_RESOURCES;
        goto leave;
    }

    left = 0;
    right = MIN(exportDir.NumberOfNames, 10000ul); // Cap the number of exported names to 10K.

    // The export names are sorted, therefore, we can do a binary search.
    while (left < right)
    {
        DWORD namePointer;
        int mid, res;

        mid = (left + right) / 2;

        status = IntKernVirtMemFetchDword(ImageBase + exportDir.AddressOfNames + mid * 4ull, &namePointer);
        if (!INT_SUCCESS(status))
        {
            goto leave;
        }

        status = IntKernVirtMemRead(ImageBase + namePointer, (DWORD)exportNameLen + 1, exportNameBuffer, NULL);
        if (!INT_SUCCESS(status))
        {
            goto leave;
        }

        // compare the null-terminator too so we can avoid cases like: ExAllocatePool equals ExAllocatePoolWithTag
        res = memcmp(Name, exportNameBuffer, exportNameLen + 1ull);

        if (0 == res)
        {
            DWORD exportOrdinal;

            // Get the export ordinal
            status = IntKernVirtMemFetchDword(ImageBase + exportDir.AddressOfNameOrdinals + mid * 2ull,
                                              &exportOrdinal);
            if (!INT_SUCCESS(status))
            {
                goto leave;
            }
            exportOrdinal &= 0xFFFF;

            // Read the export RVA
            status = IntKernVirtMemFetchDword(ImageBase + exportDir.AddressOfFunctions + exportOrdinal * 4ull,
                                              ExportRva);
            if (!INT_SUCCESS(status))
            {
                goto leave;
            }

            // It's the callers duty to see if this is forwarded
            found = TRUE;
            break;
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

leave:
    if (NULL != exportNameBuffer)
    {
        HpFreeAndNullWithTag(&exportNameBuffer, IC_TAG_EXPN);
    }

    if (ImageBaseBuffer == NULL)
    {
        IntVirtMemUnmap(&map);
    }

    // return the error if any...
    if (!INT_SUCCESS(status))
    {
        return status;
    }
    else if (!found)
    {
        return INT_STATUS_NOT_FOUND;
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntPeFindExportByOrdinal(
    _In_ QWORD ImageBase,
    _In_opt_ BYTE *ImageBaseBuffer,
    _In_ DWORD Ordinal,
    _Out_ DWORD *ExportRva
    )
///
/// @brief Find an exported function using its ordinal.
///
/// @param[in]  ImageBase       Guest virtual address of the beginning of the module (headers).
/// @param[in]  ImageBaseBuffer Buffer containing the MZ/PE image.
/// @param[in]  Ordinal         Ordinal used to find the export.
/// @param[out] ExportRva       Rva the indicated export is found at.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_NOT_FOUND If no export containing the Rva is found.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
/// @retval #INT_STATUS_INVALID_OBJECT_TYPE If the MZ/PE file is malformed or corrupted in any way.
///
{
    BOOLEAN found;
    INTSTATUS status;
    IMAGE_DATA_DIRECTORY dir = {0};
    BYTE *map;
    IMAGE_EXPORT_DIRECTORY exportDir;

    if (NULL == ExportRva)
    {
        return INT_STATUS_INVALID_PARAMETER_4;
    }

    found = FALSE;

    if (NULL != ImageBaseBuffer)
    {
        map = ImageBaseBuffer;
    }
    else
    {
        status = IntVirtMemMap(ImageBase, PAGE_SIZE, 0, 0, &map);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] Failed mapping VA 0x%016llx to host: 0x%08x\n", ImageBase, status);
            return status;
        }
    }

    // get the export directory, if present
    status = IntPeGetDirectory(ImageBase, map, IMAGE_DIRECTORY_ENTRY_EXPORT, &dir);
    if (!INT_SUCCESS(status))
    {
        goto leave;
    }

    // Read the export directory
    status = IntKernVirtMemRead(ImageBase + dir.VirtualAddress, sizeof(IMAGE_EXPORT_DIRECTORY), &exportDir, NULL);
    if (!INT_SUCCESS(status))
    {
        // Export directory is pageable so it CAN happen to not be present, so don't spam
        if (status != INT_STATUS_PAGE_NOT_PRESENT)
        {
            WARNING("[ERROR] Failed to read the export directory of 0x%016llx located at 0x%016llx: 0x%08x\n",
                    ImageBase, ImageBase + dir.VirtualAddress, status);
        }
        goto leave;
    }

    if (Ordinal > exportDir.NumberOfFunctions)
    {
        status = INT_STATUS_INVALID_PARAMETER_2;
        goto leave;
    }

    // Read the export RVA
    status = IntKernVirtMemFetchDword(ImageBase + exportDir.AddressOfFunctions + Ordinal * 4ull, ExportRva);
    if (!INT_SUCCESS(status))
    {
        goto leave;
    }

leave:
    if (ImageBaseBuffer == NULL)
    {
        IntVirtMemUnmap(&map);
    }

    // return the error if any...
    if (!INT_SUCCESS(status))
    {
        return status;
    }
    else if (!found)
    {
        return INT_STATUS_NOT_FOUND;
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntPeGetRuntimeFunction(
    _In_ QWORD ImageBase,
    _In_opt_ BYTE *ImageBaseBuffer,
    _In_ DWORD Rva,
    _Out_ RUNTIME_FUNCTION *RuntimeFunction
    )
///
/// @brief Parses the exception directory and gets the runtime function corresponding to the Rva.
///
/// @param[in]  ImageBase       Guest virtual address of the beginning of the module (headers).
/// @param[in]  ImageBaseBuffer Buffer containing the MZ/PE image.
/// @param[in]  Rva             The Rva whose runtime function is to be found.
/// @param[out] RuntimeFunction The identified runtime function for the indicated Rva.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INVALID_OBJECT_TYPE If the MZ/PE file is malformed or corrupted in any way.
/// @retval #INT_STATUS_NOT_SUPPORTED If the indicated MZ/PE file is not 64 bit.
/// @retval #INT_STATUS_NOT_FOUND If no function is found at that RVA
///
{
    IMAGE_DATA_DIRECTORY dir;
    INTSTATUS status;
    DWORD i;
    PRUNTIME_FUNCTION pRuntimeFunction;
    QWORD currentAddress;
    BYTE *map;
    BOOLEAN found;
    INTRO_PE_INFO peInfo = {0};

    if (NULL == RuntimeFunction)
    {
        return INT_STATUS_INVALID_PARAMETER_4;
    }

    found = FALSE;
    pRuntimeFunction = NULL;

    if (NULL != ImageBaseBuffer)
    {
        map = ImageBaseBuffer;
    }
    else
    {
        status = IntVirtMemMap(ImageBase, PAGE_SIZE, 0, 0, &map);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] Failed mapping VA 0x%016llx to host: 0x%08x\n", ImageBase, status);
            return status;
        }
    }

    status = IntPeValidateHeader(ImageBase, map, PAGE_SIZE, &peInfo, 0);
    if (!INT_SUCCESS(status))
    {
        goto leave;
    }

    // this only works on x64 systems
    if (!peInfo.Image64Bit)
    {
        status = INT_STATUS_NOT_SUPPORTED;
        goto leave;
    }

    status = IntPeGetDirectory(ImageBase, map, IMAGE_DIRECTORY_ENTRY_EXCEPTION, &dir);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] No exception directory for ImageBase 0x%016llx: 0x%08x\n", ImageBase, status);
        goto leave;
    }

    // The structures are ordered in memory by BeginAddress field so search till we find one
    // bigger than ours or we reach the last page
    currentAddress = ImageBase + dir.VirtualAddress;

    while (currentAddress < ImageBase + dir.VirtualAddress + dir.Size)
    {
        DWORD lastTableInPage = currentAddress & PAGE_OFFSET;
        DWORD beginRva;

        // if we get in the next page, this is the last one
        while (lastTableInPage + sizeof(RUNTIME_FUNCTION) < PAGE_SIZE)
        {
            lastTableInPage += sizeof(RUNTIME_FUNCTION);
        }

        // If we got out of the exception directory then check the last entry!
        if ((currentAddress & PAGE_MASK) + lastTableInPage > ImageBase + dir.VirtualAddress + dir.Size)
        {
            lastTableInPage = ((QWORD)dir.VirtualAddress + dir.Size - sizeof(RUNTIME_FUNCTION)) & PAGE_OFFSET;
        }

        status = IntKernVirtMemFetchDword((currentAddress & PAGE_MASK) + lastTableInPage, &beginRva);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntKernVirtMemFetchDword failed for GVA 0x%016llx (dir->RVA 0x%08x, dir->Size 0x%08x, "
                  "ImageBase 0x%016llx: 0x%08x\n", currentAddress + lastTableInPage, dir.VirtualAddress,
                  dir.Size, ImageBase, status);
            goto leave;
        }
        else if (beginRva == Rva)
        {
            status = IntKernVirtMemRead((currentAddress & PAGE_MASK) + lastTableInPage,
                                        sizeof(RUNTIME_FUNCTION), RuntimeFunction, NULL);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] Failed reading runtime function from address 0x%016llx: 0x%08x\n",
                      currentAddress + lastTableInPage, status);
            }

            goto leave;
        }
        else if (beginRva > Rva)
        {
            found = TRUE;
            break;
        }

        // the first structure in the next page
        currentAddress = (currentAddress & PAGE_MASK) + lastTableInPage + sizeof(RUNTIME_FUNCTION);
    }

    if (!found)
    {
        status = INT_STATUS_NOT_FOUND;
        goto leave;
    }

    status = IntVirtMemMap(currentAddress, PAGE_REMAINING(currentAddress), 0, 0, &pRuntimeFunction);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Failed mapping VA 0x%016llx to host: 0x%08x\n", currentAddress, status);
        goto leave;
    }

    // It can't be the last one on the page, we already covered that in the while
    found = FALSE;
    for (i = 0; i < PAGE_REMAINING(currentAddress) / sizeof(RUNTIME_FUNCTION); i++)
    {
        if (pRuntimeFunction[i].BeginAddress <= Rva && pRuntimeFunction[i].EndAddress > Rva)
        {
            found = TRUE;
            break;
        }
    }

    if (found)
    {
        // This may be a pointer to the next unwind info structure
        if (pRuntimeFunction[i].UnwindData % sizeof(DWORD) != 0)
        {
            DWORD newUnwindInfoAddr = ALIGN_DOWN(pRuntimeFunction[i].UnwindData, sizeof(DWORD));

            if (newUnwindInfoAddr >= dir.VirtualAddress &&
                newUnwindInfoAddr < dir.VirtualAddress + dir.Size)
            {
                IntVirtMemUnmap(&pRuntimeFunction);

                status = IntVirtMemMap(ImageBase + newUnwindInfoAddr,
                                       sizeof(RUNTIME_FUNCTION), 0, 0, &pRuntimeFunction);
                if (!INT_SUCCESS(status))
                {
                    ERROR("[ERROR] Failed mapping next unwind data for runtime function at "
                          "0x%016llx in driver 0x%016llx",
                          currentAddress + i * sizeof(RUNTIME_FUNCTION), ImageBase);
                    goto leave;
                }

                memcpy(RuntimeFunction, pRuntimeFunction, sizeof(RUNTIME_FUNCTION));
                goto _done_saving;
            }
            else
            {
                TRACE("[INFO] We have a function at 0x%016llx but it's not inside the exception dir (0x%016llx, %x)\n",
                      ImageBase + pRuntimeFunction->UnwindData, ImageBase + dir.VirtualAddress, dir.Size);

                status = INT_STATUS_NOT_FOUND;
                goto _cleanup_and_leave;
            }
        }

        memcpy(RuntimeFunction, &pRuntimeFunction[i], sizeof(RUNTIME_FUNCTION));

_done_saving:
        status = INT_STATUS_SUCCESS;
    }
    else
    {
        status = INT_STATUS_NOT_FOUND;
    }

_cleanup_and_leave:
    IntVirtMemUnmap(&pRuntimeFunction);

leave:
    if (NULL == ImageBaseBuffer)
    {
        IntVirtMemUnmap(&map);
    }

    return status;
}


INTSTATUS
IntPeGetRuntimeFunctionInBuffer(
    _In_ QWORD ImageBase,
    _In_ BYTE *Buffer,
    _In_ DWORD BufferSize,
    _In_ DWORD Rva,
    _Out_ RUNTIME_FUNCTION *RuntimeFunction
    )
///
/// @brief Parses the exception directory and gets the runtime function corresponding to the Rva.
///
/// @param[in]  ImageBase       Guest virtual address of the beginning of the module (headers).
/// @param[in]  Buffer          Buffer containing the MZ/PE image.
/// @param[in]  BufferSize      The size of the Buffer containing the MZ/PE image.
/// @param[in]  Rva             The Rva whose runtime function is to be found.
/// @param[out] RuntimeFunction The identified runtime function for the indicated Rva.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
/// @retval #INT_STATUS_INVALID_OBJECT_TYPE If the MZ/PE file is malformed or corrupted in any way.
/// @retval #INT_STATUS_NOT_SUPPORTED If the indicated MZ/PE file is not 64 bit.
/// @retval #INT_STATUS_NOT_FOUND If no function is found at that RVA
///
{
    IMAGE_DATA_DIRECTORY dir;
    INTSTATUS status;
    RUNTIME_FUNCTION *pRuntimeFunction = NULL;
    BOOLEAN found = FALSE;
    INTRO_PE_INFO peInfo = {0};
    size_t left, right;

    if (NULL == Buffer)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    if (0 == BufferSize)
    {
        return INT_STATUS_INVALID_PARAMETER_3;
    }

    if (NULL == RuntimeFunction)
    {
        return INT_STATUS_INVALID_PARAMETER_5;
    }

    status = IntPeValidateHeader(ImageBase, Buffer, PAGE_SIZE, &peInfo, 0);
    if (!INT_SUCCESS(status))
    {
        return status;
    }

    // this only works on x64 systems
    if (!peInfo.Image64Bit)
    {
        return INT_STATUS_NOT_SUPPORTED;
    }

    status = IntPeGetDirectory(ImageBase, Buffer, IMAGE_DIRECTORY_ENTRY_EXCEPTION, &dir);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] No exception directory for ImageBase 0x%016llx: 0x%08x\n", ImageBase, status);
        return status;
    }

    // IntPeGetDirectory already did checks for SizeOfImage, but not for BufferSize
    if ((QWORD)dir.VirtualAddress + dir.Size > BufferSize)
    {
        return INT_STATUS_INVALID_DATA_TYPE;
    }

    left = 0;
    right = (dir.Size / sizeof(RUNTIME_FUNCTION));

    while (left < right)
    {
        size_t midd = (left + right) / 2;

        pRuntimeFunction = (RUNTIME_FUNCTION *)(Buffer + dir.VirtualAddress + midd * sizeof(*pRuntimeFunction));

        if (pRuntimeFunction->BeginAddress <= Rva && pRuntimeFunction->EndAddress > Rva)
        {
            found = TRUE;
            break;
        }
        else if (pRuntimeFunction->BeginAddress < Rva)
        {
            left = midd + 1;
        }
        else
        {
            right = midd;
        }
    }

    if (!found)
    {
        return INT_STATUS_NOT_FOUND;
    }

    // This may be a pointer to the next unwind info structure
    if (pRuntimeFunction->UnwindData % sizeof(DWORD) != 0)
    {
        DWORD newUnwindInfoAddr = ALIGN_DOWN(pRuntimeFunction->UnwindData, sizeof(DWORD));

        if (IN_RANGE_LEN(newUnwindInfoAddr, dir.VirtualAddress, dir.Size))
        {
            pRuntimeFunction = (RUNTIME_FUNCTION *)(Buffer + newUnwindInfoAddr);

            memcpy(RuntimeFunction, pRuntimeFunction, sizeof(RUNTIME_FUNCTION));

            return INT_STATUS_SUCCESS;
        }
        else
        {
            TRACE("[INFO] We have a function at 0x%016llx but it's not inside the exception dir (0x%016llx, %x)\n",
                  ImageBase + pRuntimeFunction->UnwindData, ImageBase + dir.VirtualAddress, dir.Size);

            return INT_STATUS_NOT_FOUND;
        }
    }

    memcpy(RuntimeFunction, pRuntimeFunction, sizeof(RUNTIME_FUNCTION));

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntPeParseUnwindData(
    _In_ QWORD ImageBase,
    _In_opt_ BYTE *ImageBaseBuffer,
    _In_ RUNTIME_FUNCTION *RuntimeFunction,
    _In_opt_ DWORD RipOffset,
    _Out_opt_ DWORD *ReservedStack,
    _Out_opt_ DWORD *BeginAddress,
    _Out_opt_ BOOLEAN *InterruptFunction,
    _Out_opt_ BOOLEAN *ExceptionFunction,
    _Out_opt_ BOOLEAN *HasFramePointer
    )
///
/// @brief Parse the unwind data for the indicated function and return the prologue size.
///
/// Parses the UNWIND_INFO structure(s) of the RuntimeFunction and returns the total space occupied by the function
/// prologue (it can be 0!).
///
/// @param[in]  ImageBase           Guest virtual address of the beginning of the module (headers).
/// @param[in]  ImageBaseBuffer     Buffer containing the MZ/PE image.
/// @param[in]  RuntimeFunction     The runtime function to be parsed.
/// @param[in]  RipOffset           The offset inside the function where the RIP is.
/// @param[out] ReservedStack       Size reserved on the stack for that function.
/// @param[out] BeginAddress        The actual beginning of the function (after parsing chained info).
/// @param[out] InterruptFunction   True if it's an interrupt handler function.
/// @param[out] ExceptionFunction   True if it's an exception handler function.
/// @param[out] HasFramePointer     True if the function uses a frame pointer.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
///
{
    QWORD unwindInfoAddress;
    DWORD unwindInfoSize, i, extraSpace;
    INTRO_UNWIND_INFO *pUnwindInfoMap;
    BOOLEAN hasChainedUnwind;
    BOOLEAN interrupt, exception;
    BYTE *map;
    INTSTATUS status;
    DWORD itCount = 0;

    if (NULL == RuntimeFunction)
    {
        return INT_STATUS_INVALID_PARAMETER_3;
    }

    if (RipOffset > RuntimeFunction->EndAddress - RuntimeFunction->BeginAddress)
    {
        ERROR("[ERROR] RipOffset %x, End %x, Begin %x, Total %x\n", RipOffset, RuntimeFunction->EndAddress,
              RuntimeFunction->BeginAddress, RuntimeFunction->EndAddress - RuntimeFunction->BeginAddress);
        return INT_STATUS_INVALID_PARAMETER_5;
    }

    if (NULL != ImageBaseBuffer)
    {
        map = ImageBaseBuffer;
    }
    else
    {
        status = IntVirtMemMap(ImageBase, PAGE_SIZE, 0, 0, &map);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] Failed mapping VA 0x%016llx to host: 0x%08x\n", ImageBase, status);
            return status;
        }
    }

    hasChainedUnwind = FALSE;
    interrupt = exception = FALSE;
    pUnwindInfoMap = NULL;
    extraSpace = 0;

    if (NULL != BeginAddress)
    {
        *BeginAddress = 0;
    }

    if (NULL != HasFramePointer)
    {
        *HasFramePointer = FALSE;
    }

    // Align to DWORD (there are some weird cases in kernel when the address is not aligned...
    // I assume it's because the UNWIND_INFO structure is shared by multiple structures, and the
    // first byte is a flag, at least that's what happened in those cases)
    unwindInfoAddress = ALIGN_DOWN(ImageBase + RuntimeFunction->UnwindData, sizeof(DWORD));
    unwindInfoSize = MAX_UNWIND_CODES * 2 + 12 + sizeof(DWORD);

    if (NULL != InterruptFunction)
    {
        *InterruptFunction = FALSE;
    }

    if (NULL != ExceptionFunction)
    {
        *ExceptionFunction = FALSE;
    }

    do
    {
        BOOLEAN saveExtraSpace;
        DWORD countOfCodes;

        if (pUnwindInfoMap != NULL)
        {
            IntVirtMemUnmap(&pUnwindInfoMap);
        }

        itCount++;
        if (itCount > MAX_UNWIND_INFO_TRIES)
        {
            ERROR("[ERROR] Reached MAX_UNWIND_INFO_TRIES for image at 0x%016llx\n", ImageBase);
            status = INT_STATUS_NOT_SUPPORTED;
            goto leave;
        }

        status = IntVirtMemMap(unwindInfoAddress, unwindInfoSize, 0, 0, &pUnwindInfoMap);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntVirtMemMap failed for GVA 0x%016llx (chained: %s, RIP: 0x%016llx): 0x%08x\n",
                  unwindInfoAddress, hasChainedUnwind ? "TRUE" : "FALSE", ImageBase + RuntimeFunction->BeginAddress,
                  status);
            goto leave;
        }

        countOfCodes = pUnwindInfoMap->CountOfCodes;

        // Make sure we mapped enough
        if (countOfCodes > MAX_UNWIND_CODES)
        {
            WARNING("[WARNING] Function with %d codes at RVA %08x in driver 0x%016llx with unwind info %llx\n",
                    countOfCodes, RuntimeFunction->BeginAddress, ImageBase, unwindInfoAddress);
            status = INT_STATUS_NOT_SUPPORTED;
            goto leave;
        }

        if (ReservedStack == NULL)
        {
            goto _get_chained_info;
        }

        // If the FrameRegister is not NULL then another register is used as a stack frame with a FrameOffset
        // But this doesn't change anything for what we want to do since the return address is still on RSP.
        i = 0; // Sometimes we need to skip the next codes (they're passed as info to this code)
        while (i < countOfCodes)
        {
            BYTE unwindOp = pUnwindInfoMap->UnwindCode[i].UnwindOp;

            // We check for version (1 on Win7, 2 on Win8) in case we somehow don't skip enough codes
            if (pUnwindInfoMap->Version != 1 && pUnwindInfoMap->Version != 2)
            {
                i++;
                continue;
            }

            // We only save if the instruction was executed. We use less-or-equal because CodeOffset field doesn't point
            // to the beginning of the instruction, but to the end. But if we are inside a chained entry, then this
            // we save automatically, because it's code that was executed before
            if (!hasChainedUnwind)
            {
                saveExtraSpace = RipOffset >= pUnwindInfoMap->UnwindCode[i].CodeOffset;
            }
            else
            {
                saveExtraSpace = TRUE;
            }

            // see http://msdn.microsoft.com/en-US/library/ck9asaa9%28v=vs.80%29.aspx for details
            switch (unwindOp)
            {
            case 0: // UWOP_PUSH_NONVOL (1)
                if (saveExtraSpace)
                {
                    extraSpace += 8;
                }

                i++;
                break;

            case 1: // UWOP_ALLOC_LARGE (2 or 3)
                if (pUnwindInfoMap->UnwindCode[i].OpInfo == 0)
                {
                    if (saveExtraSpace)
                    {
                        extraSpace += *((WORD *)&pUnwindInfoMap->UnwindCode[i + 1]) * 8;
                    }

                    i += 2;
                }
                else
                {
                    if (saveExtraSpace)
                    {
                        extraSpace += *((DWORD *)&pUnwindInfoMap->UnwindCode[i + 2]) * 8;
                    }

                    i += 3;
                }

                break;
            case 2: // UWOP_ALLOC_SMALL (1)
                if (saveExtraSpace)
                {
                    extraSpace += pUnwindInfoMap->UnwindCode[i].OpInfo * 8 + 8;
                }

                i++;
                break;

            case 3: // UWOP_SET_FPREG(1)
                if (HasFramePointer != NULL)
                {
                    *HasFramePointer = TRUE;
                }

                i++;
                break;

            case 4: // UWOP_SAVE_NONVOL(1)
                i += 2;
                break;

            case 5: // UWOP_SAVE_NONVOL_FAR
                i += 3;
                break;

            case 6: // UWOP_EPILOG
                // For what I see so far it just says where the exit points are in a function
                // (if there are multiple exit points)
                i += 1;
                break;

            case 7: // UWOP_SPARE_CODE
                i += 2;
                break;

            case 8: // UWOP_SAVE_XMM128
                i += 2;
                break;

            case 9: // UWOP_SAVE_XMM128_FAR
                i += 3;
                break;

            case 10: // UWOP_PUSH_MACHFRAME
                if (pUnwindInfoMap->UnwindCode[i].OpInfo == 0)
                {
                    // We are inside an exception. This is done automatically, so no need to verify rip offset
                    // Actually here, we will do a trick. We only subtract enough to get to the RIP

                    exception = TRUE;
                }
                else if (pUnwindInfoMap->UnwindCode[i].OpInfo == 1)
                {
                    // We are inside an hardware interrupt. This is done automatically, so no need to verify rip offset
                    // Actually here we will do a trick. We only subtract enough to get to the RIP

                    interrupt = TRUE;
                }
                else
                {
                    WARNING("[WARNING] Unknown info for UWOP_PUSH_MACHFRAME: %d\n",
                            pUnwindInfoMap->UnwindCode[i].OpInfo);
                }

                i++;
                break;

            default:
                WARNING("[WARNING] UWOP value not known: %d\n", pUnwindInfoMap->UnwindCode[i].UnwindOp);

                i++;
                break;
            }
        }

_get_chained_info:
        // Get the new unwind info address so we can map the new one if we need to. Formula:
        // CountOfCode * sizeof(UNWIND_CODE) + 4 (first BYTES in UNWIND_INFO) => RUNTIME_FUNCTION.
        // Add 8 (OFFSET_OF(RUNTIME_FUNCTION, UnwindData)) to get the new unwind info address.
        hasChainedUnwind = (pUnwindInfoMap->Flags == UNW_FLAG_CHAININFO);

        unwindInfoAddress =
            ALIGN_DOWN(ImageBase + * (DWORD *)((PBYTE)pUnwindInfoMap + (countOfCodes * 2ull) + 12),
                       sizeof(DWORD));

        // Get the actual function start if we have a chain
        if (hasChainedUnwind && BeginAddress != NULL)
        {
            *BeginAddress = *(DWORD *)((PBYTE)pUnwindInfoMap + (countOfCodes * 2ull) + 4);
        }
    } while (hasChainedUnwind);

    if (NULL != ReservedStack)
    {
        *ReservedStack = extraSpace;
    }

    if (exception && interrupt)
    {
        WARNING("[WARNING] Why do we have both exception and interrupt context ? RIP 0x%016llx, Module 0x%016llx\n",
                ImageBase + RuntimeFunction->BeginAddress + RipOffset, ImageBase);
    }

    if (NULL != ExceptionFunction)
    {
        *ExceptionFunction = exception;
    }

    if (NULL != InterruptFunction)
    {
        *InterruptFunction = interrupt;
    }

    status = INT_STATUS_SUCCESS;

leave:
    if (pUnwindInfoMap != NULL)
    {
        IntVirtMemUnmap(&pUnwindInfoMap);
    }

    if (NULL == ImageBaseBuffer)
    {
        IntVirtMemUnmap(&map);
    }

    return status;
}


INTSTATUS
IntPeParseUnwindDataInBuffer(
    _In_ QWORD ImageBase,
    _In_ BYTE *Buffer,
    _In_ DWORD BufferSize,
    _In_ RUNTIME_FUNCTION *RuntimeFunction,
    _In_opt_ DWORD RipOffset,
    _Out_opt_ DWORD *ReservedStack,
    _Out_opt_ DWORD *BeginAddress,
    _Out_opt_ BOOLEAN *InterruptFunction,
    _Out_opt_ BOOLEAN *ExceptionFunction,
    _Out_opt_ BOOLEAN *HasFramePointer
    )
///
/// @brief Parse the unwind data for the indicated function and return the prologue size.
///
/// Parses the UNWIND_INFO structure(s) of the RuntimeFunction and returns the total space occupied by the function
/// prologue (it can be 0!).
///
/// @param[in]  ImageBase           Guest virtual address of the beginning of the module (headers).
/// @param[in]  Buffer              Buffer containing the MZ/PE image.
/// @param[in]  BufferSize          The size of the Buffer containing the MZ/PE image.
/// @param[in]  RuntimeFunction     The runtime function to be parsed.
/// @param[in]  RipOffset           The offset inside the function where the RIP is.
/// @param[out] ReservedStack       Size reserved on the stack for that function.
/// @param[out] BeginAddress        The actual beginning of the function (after parsing chained info).
/// @param[out] InterruptFunction   True if it's an interrupt handler function.
/// @param[out] ExceptionFunction   True if it's an exception handler function.
/// @param[out] HasFramePointer     True if the function uses a frame pointer.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
///
{
    DWORD unwindInfoRva;
    DWORD i, extraSpace;
    INTRO_UNWIND_INFO *pUnwindInfo;
    BOOLEAN hasChainedUnwind;
    BOOLEAN interrupt, exception;
    DWORD itCount = 0;
    const DWORD unwindInfoSize = MAX_UNWIND_CODES * 2 + 12 + sizeof(DWORD);

    if (NULL == Buffer)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    if (0 == BufferSize)
    {
        return INT_STATUS_INVALID_PARAMETER_3;
    }

    if (NULL == RuntimeFunction)
    {
        return INT_STATUS_INVALID_PARAMETER_4;
    }

    if (RipOffset > RuntimeFunction->EndAddress - RuntimeFunction->BeginAddress)
    {
        ERROR("[ERROR] RipOffset %x, End %x, Begin %x, Total %x\n", RipOffset, RuntimeFunction->EndAddress,
              RuntimeFunction->BeginAddress, RuntimeFunction->EndAddress - RuntimeFunction->BeginAddress);
        return INT_STATUS_INVALID_PARAMETER_5;
    }

    hasChainedUnwind = FALSE;
    interrupt = exception = FALSE;
    extraSpace = 0;

    if (BeginAddress != NULL)
    {
        *BeginAddress = 0;
    }

    if (HasFramePointer != NULL)
    {
        *HasFramePointer = FALSE;
    }

    // Align to DWORD (there are some weird cases in kernel when the address is not aligned...
    // I assume it's because the UNWIND_INFO structure is shared by multiple structures, and the
    // first byte is a flag, at least that's what happened in those cases)
    unwindInfoRva = ALIGN_DOWN(RuntimeFunction->UnwindData, sizeof(DWORD));

    if ((QWORD)unwindInfoRva + sizeof(*pUnwindInfo) + unwindInfoSize >= BufferSize)
    {
        ERROR("[ERROR] Invalid unwind info at 0x%04x, we have only 0x%04x\n", unwindInfoRva, BufferSize);
        return INT_STATUS_INVALID_DATA_TYPE;
    }

    if (NULL != InterruptFunction)
    {
        *InterruptFunction = FALSE;
    }

    if (NULL != ExceptionFunction)
    {
        *ExceptionFunction = FALSE;
    }

    do
    {
        DWORD countOfCodes;

        // Although we checked before with unwindInfoSize, better safe than sorry.
        if ((QWORD)unwindInfoRva + sizeof(*pUnwindInfo) > BufferSize)
        {
            return INT_STATUS_INVALID_DATA_TYPE;
        }

        itCount++;
        if (itCount > MAX_UNWIND_INFO_TRIES)
        {
            ERROR("[ERROR] Reached MAX_UNWIND_INFO_TRIES for image at 0x%016llx\n", ImageBase);
            return INT_STATUS_NOT_SUPPORTED;
        }

        pUnwindInfo = (INTRO_UNWIND_INFO *)(Buffer + unwindInfoRva);

        countOfCodes = pUnwindInfo->CountOfCodes;

        // Make sure we mapped enough
        if (countOfCodes > MAX_UNWIND_CODES)
        {
            WARNING("[WARNING] Function with %d codes at RVA %08x in driver 0x%016llx with unwind info 0x%04x\n",
                    countOfCodes, RuntimeFunction->BeginAddress, ImageBase, unwindInfoRva);
            return INT_STATUS_NOT_SUPPORTED;
        }

        if (ReservedStack == NULL)
        {
            goto _get_chained_info;
        }

        // If the FrameRegister is not NULL then another register is used as a stack frame with a FrameOffset
        // But this doesn't change anything for what we want to do since the return address is still on RSP.
        i = 0; // Sometimes we need to skip the next codes (they're passed as info to this code)
        while (i < countOfCodes)
        {
            BOOLEAN saveExtraSpace;
            BYTE unwindOp = pUnwindInfo->UnwindCode[i].UnwindOp;

            // We check for version (1 on Win7, 2 on Win8) in case we somehow don't skip enough codes
            if (pUnwindInfo->Version != 1 && pUnwindInfo->Version != 2)
            {
                i++;
                continue;
            }

            // We only save if the instruction was executed. We use less-or-equal because CodeOffset field doesn't point
            // to the beginning of the instruction, but to the end. But if we are inside a chained entry, then this
            // we save automatically, because it's code that was executed before
            if (!hasChainedUnwind)
            {
                saveExtraSpace = RipOffset >= pUnwindInfo->UnwindCode[i].CodeOffset;
            }
            else
            {
                saveExtraSpace = TRUE;
            }

            // see http://msdn.microsoft.com/en-US/library/ck9asaa9%28v=vs.80%29.aspx for details
            switch (unwindOp)
            {
            case 0: // UWOP_PUSH_NONVOL (1)
                if (saveExtraSpace)
                {
                    extraSpace += 8;
                }

                i++;
                break;

            case 1: // UWOP_ALLOC_LARGE (2 or 3)
                if (pUnwindInfo->UnwindCode[i].OpInfo == 0)
                {
                    if (saveExtraSpace)
                    {
                        extraSpace += *((WORD *)&pUnwindInfo->UnwindCode[i + 1]) * 8;
                    }

                    i += 2;
                }
                else
                {
                    if (saveExtraSpace)
                    {
                        extraSpace += *((DWORD *)&pUnwindInfo->UnwindCode[i + 2]) * 8;
                    }

                    i += 3;
                }

                break;
            case 2: // UWOP_ALLOC_SMALL (1)
                if (saveExtraSpace)
                {
                    extraSpace += pUnwindInfo->UnwindCode[i].OpInfo * 8 + 8;
                }

                i++;
                break;

            case 3: // UWOP_SET_FPREG(1)
                if (HasFramePointer != NULL)
                {
                    *HasFramePointer = TRUE;
                }

                i++;
                break;

            case 4: // UWOP_SAVE_NONVOL(1)
                i += 2;
                break;

            case 5: // UWOP_SAVE_NONVOL_FAR
                i += 3;
                break;

            case 6: // UWOP_EPILOG
                // For what I see so far it just says where the exit points are in a function
                // (if there are multiple exit points)
                i += 1;
                break;

            case 7: // UWOP_SPARE_CODE
                i += 2;
                break;

            case 8: // UWOP_SAVE_XMM128
                i += 2;
                break;

            case 9: // UWOP_SAVE_XMM128_FAR
                i += 3;
                break;

            case 10: // UWOP_PUSH_MACHFRAME
                if (pUnwindInfo->UnwindCode[i].OpInfo == 0)
                {
                    // We are inside an exception. This is done automatically, so no need to verify rip offset
                    // Actually here, we will do a trick. We only subtract enough to get to the RIP

                    exception = TRUE;
                }
                else if (pUnwindInfo->UnwindCode[i].OpInfo == 1)
                {
                    // We are inside an hardware interrupt. This is done automatically, so no need to verify rip offset
                    // Actually here we will do a trick. We only subtract enough to get to the RIP

                    interrupt = TRUE;
                }
                else
                {
                    WARNING("[WARNING] Unknown info for UWOP_PUSH_MACHFRAME: %d\n",
                            pUnwindInfo->UnwindCode[i].OpInfo);
                }

                i++;
                break;

            default:
                WARNING("[WARNING] UWOP value not known: %d\n", pUnwindInfo->UnwindCode[i].UnwindOp);

                i++;
                break;
            }
        }

_get_chained_info:
        // Get the new unwind info address so we can map the new one if we need to. Formula:
        // CountOfCode * sizeof(UNWIND_CODE) + 4 (first BYTES in UNWIND_INFO) => RUNTIME_FUNCTION.
        // Add 8 (FIELD_OFFSET(RUNTIME_FUNCTION, UnwindData)) to get the new unwind info address.
        hasChainedUnwind = (pUnwindInfo->Flags == UNW_FLAG_CHAININFO);

        unwindInfoRva =
            ALIGN_DOWN(*(DWORD *)((BYTE *)pUnwindInfo + (countOfCodes * 2ull) + 12), sizeof(DWORD));

        // We want to verify only if it has chained unwind, as the next RVA will most probably be invalid and we
        // shouldn't bother as we don't get anything from the buffer anymore.
        if (hasChainedUnwind && (QWORD)unwindInfoRva + sizeof(*pUnwindInfo) + unwindInfoSize >= BufferSize)
        {
            ERROR("[ERROR] Invalid unwind info at 0x%04x, we have only 0x%04x\n", unwindInfoRva, BufferSize);
            return INT_STATUS_INVALID_DATA_TYPE;
        }

        // Get the actual function start if we have a chain
        if (hasChainedUnwind && BeginAddress != NULL)
        {
            *BeginAddress = *(DWORD *)((BYTE *)pUnwindInfo + (countOfCodes * 2ull) + 4);
        }
    } while (hasChainedUnwind);

    if (NULL != ReservedStack)
    {
        *ReservedStack = extraSpace;
    }

    if (exception && interrupt)
    {
        WARNING("[WARNING] Why do we have both exception and interrupt context ? RIP 0x%016llx, Module 0x%016llx\n",
                ImageBase + RuntimeFunction->BeginAddress + RipOffset, ImageBase);
    }

    if (NULL != ExceptionFunction)
    {
        *ExceptionFunction = exception;
    }

    if (NULL != InterruptFunction)
    {
        *InterruptFunction = interrupt;
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntPeFindFunctionByPatternInBuffer(
    _In_bytecount_(BufferSize) BYTE *Buffer,
    _In_ DWORD BufferSize,
    _In_ WIN_UNEXPORTED_FUNCTION_PATTERN *Pattern,
    _In_ BOOLEAN IgnoreSectionHint,
    _Out_ DWORD *Rva
    )
///
/// @brief Find a function using a pattern.
///
/// Searches the indicated buffer for a function matching the provided pattern.
///
/// @param[in]  Buffer              The buffer to search.
/// @param[in]  BufferSize          The size of the Buffer to be searched.
/// @param[in]  Pattern             The searched pattern.
/// @param[in]  IgnoreSectionHint   If true, the pattern section hint will be ignored.
/// @param[out] Rva                 The Rva the indicated pattern is found at.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_DATA_BUFFER_TOO_SMALL If a section exceeds the size of the provided buffer.
/// @retval #INT_STATUS_NOT_FOUND If not function matching that pattern is found.
///
{
    IMAGE_DOS_HEADER *pDos;
    IMAGE_FILE_HEADER *pFileHeader;
    IMAGE_SECTION_HEADER *pSec;
    DWORD secheadersRva;
    BYTE *p;
    INTSTATUS status;

    // Validate the header before actually going through sections
    status = IntPeValidateHeader(0, Buffer, BufferSize, NULL, 0);
    if (!INT_SUCCESS(status))
    {
        return status;
    }

    pDos = (IMAGE_DOS_HEADER *)Buffer;

    // Read the signature + file header
    pFileHeader = (IMAGE_FILE_HEADER *)(Buffer + pDos->e_lfanew + 4);

    secheadersRva = pDos->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) + pFileHeader->SizeOfOptionalHeader;

    for (DWORD i = 0; i < pFileHeader->NumberOfSections; i++)
    {
        pSec = (IMAGE_SECTION_HEADER *)(Buffer + secheadersRva + sizeof(IMAGE_SECTION_HEADER) * i);

        // ERRATA has a size of 3...
        if (pSec->Misc.VirtualSize < Pattern->Signature.Length)
        {
            continue;
        }

        if (Pattern->SectionHint[0] && !IgnoreSectionHint && 0 != memcmp(pSec->Name, Pattern->SectionHint, 8))
        {
            continue;
        }

        if ((QWORD)pSec->VirtualAddress + pSec->Misc.VirtualSize > BufferSize)
        {
            CHAR name[9];
            memcpy(name, pSec->Name, sizeof(pSec->Name));
            name[8] = 0;

            ERROR("[ERROR] Section %s %08x with size %08x outside of image size %08x...\n",
                  name, pSec->VirtualAddress, pSec->Misc.VirtualSize, BufferSize);
            return INT_STATUS_DATA_BUFFER_TOO_SMALL;
        }

        p = Buffer + pSec->VirtualAddress;

        // Try to find the pattern inside this section.
        for (DWORD j = 0; j < pSec->Misc.VirtualSize - Pattern->Signature.Length; j++)
        {
            BOOLEAN bFound = TRUE;

            for (DWORD k = 0; k < Pattern->Signature.Length; k++)
            {
                if (__likely(Pattern->Signature.Pattern[k] != 0x100 &&
                             Pattern->Signature.Pattern[k] != p[j + k]))
                {
                    bFound = FALSE;
                    break;
                }
            }

            if (bFound)
            {
                *Rva = pSec->VirtualAddress + j;
                if (IgnoreSectionHint)
                {
                    TRACE("[DEBUG] Found function inside section %d:%s, was supposed to find in %s\n",
                          i, pSec->Name, Pattern->SectionHint);
                }

                return INT_STATUS_SUCCESS;
            }
        }
    }

    return INT_STATUS_NOT_FOUND;
}


INTSTATUS
IntPeFindFunctionByPattern(
    _In_ QWORD ImageBase,
    _In_ WIN_UNEXPORTED_FUNCTION_PATTERN *Pattern,
    _In_ BOOLEAN IgnoreSectionHint,
    _Out_ DWORD *Rva
    )
///
/// @brief Find a function using a pattern.
///
/// Searches the indicated guest module for a function matching the provided pattern.
/// This function uses #IntPeValidateHeader to validate the MZPE headers before using them.
///
/// @param[in]  ImageBase           Guest virtual address of the beginning of the module (headers) to be validated.
/// @param[in]  Pattern             The searched pattern.
/// @param[in]  IgnoreSectionHint   If true, the pattern section hint will be ignored.
/// @param[out] Rva                 The Rva the indicated pattern is found at.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_DATA_BUFFER_TOO_SMALL If a section exceeds the size of the provided buffer.
/// @retval #INT_STATUS_NOT_FOUND If not function matching that pattern is found.
///
{
    INTSTATUS status;
    QWORD secheadersRva;
    QWORD cr3 = gGuest.Mm.SystemCr3;
    INTRO_PE_INFO peInfo = { 0 };

    status = IntPeValidateHeader(ImageBase, NULL, 0, &peInfo, cr3);
    if (!INT_SUCCESS(status))
    {
        ERROR("IntPeValidateHeader failed for image at 0x%016llx: 0x%08x\n", ImageBase, status);
        return status;
    }

    secheadersRva = peInfo.SectionOffset;

    for (QWORD i = 0; i < peInfo.NumberOfSections; i++)
    {
        PBYTE pPage1, pPage2;
        DWORD rva, k, j, origStart;
        BOOLEAN bFound;
        IMAGE_SECTION_HEADER hSec;

        bFound = FALSE;

        // Read the designated section header.
        status = IntKernVirtMemRead(ImageBase + secheadersRva + (sizeof(IMAGE_SECTION_HEADER) * i),
                                    sizeof(IMAGE_SECTION_HEADER), &hSec, NULL);
        if (!INT_SUCCESS(status))
        {
            return status;
        }

        if (!IgnoreSectionHint && 0 != memcmp(hSec.Name, Pattern->SectionHint, 8))
        {
            continue;
        }

        // Try to find the pattern inside this section.
        for (rva = hSec.VirtualAddress; rva < hSec.VirtualAddress + hSec.Misc.VirtualSize; rva += 0x1000)
        {
            if (rva >= peInfo.SizeOfImage)
            {
                break;
            }

            status = IntVirtMemMap(ImageBase + rva, PAGE_SIZE, cr3, 0, &pPage1);
            if (!INT_SUCCESS(status))
            {
                continue;
            }

            // Try to match the sig in this current page.
            origStart = j = k = 0;
            while (k < PAGE_SIZE)
            {
                origStart = k;

                j = 0;

                while ((k < PAGE_SIZE) && (j < Pattern->Signature.Length) &&
                       ((pPage1[k] == Pattern->Signature.Pattern[j]) ||
                        (0x100 == Pattern->Signature.Pattern[j])))
                {
                    k++;
                    j++;
                }

                // Handle page boundary access
                if (k == PAGE_SIZE)
                {
                    DWORD l;

                    // We must map the next page
                    status = IntVirtMemMap(ImageBase + rva + PAGE_SIZE, PAGE_SIZE, cr3, 0, &pPage2);
                    if (!INT_SUCCESS(status))
                    {
                        break;
                    }

                    l = 0;

                    while ((l < PAGE_SIZE) && (j < Pattern->Signature.Length) &&
                           ((pPage2[l] == Pattern->Signature.Pattern[j]) ||
                            (0x100 == Pattern->Signature.Pattern[j])))
                    {
                        l++;
                        j++;
                    }

                    IntVirtMemUnmap(&pPage2);
                }

                if (j != Pattern->Signature.Length)
                {
                    k = origStart;
                }
                else
                {
                    bFound = TRUE;
                    break;
                }

                k++;
            }

            IntVirtMemUnmap(&pPage1);

            if (bFound)
            {
                *Rva = rva + origStart;
                if (IgnoreSectionHint)
                {
                    TRACE("[DEBUG] Found function inside section %lld:%s, was supposed to find in %s\n",
                          i, hSec.Name, Pattern->SectionHint);
                }

                return INT_STATUS_SUCCESS;
            }
        }
    }

    return INT_STATUS_NOT_FOUND;
}


INTSTATUS
IntPeFindFunctionStart(
    _In_ QWORD ImageBase,
    _In_opt_ BYTE *ImageBaseBuffer,
    _In_ DWORD Rva,
    _Out_ DWORD *BeginAddress
    )
///
/// @brief Find the start address of a function, given a Rva pointing inside of it.
///
/// Given a Rva, parse code backwards until we find what looks like the start of the function. This function uses
/// either the exception directory for 64 bit executables or the standard prologue for 32 bit executables to locate
/// the beginning of the function.
///
/// @param[in]  ImageBase           Guest virtual address of the beginning of the module (headers) to be validated.
/// @param[in]  ImageBaseBuffer     Address where the ImageBase is already mapped in Introcore space, if present.
/// @param[in]  Rva                 The Rva we will search the function start for.
/// @param[out] BeginAddress        The Rva of the identified function start.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
/// @retval #INT_STATUS_NOT_SUPPORTED If the Rva lies in a non-executable section.
/// @retval #INT_STATUS_NOT_FOUND If the function start could not be identified.
///
{
    INTRO_PE_INFO peInfo = {0};
    BYTE *map;
    BOOLEAN found;
    INTSTATUS status;
    IMAGE_SECTION_HEADER sectionHeader = {0};
    QWORD cr3;

    if (NULL == BeginAddress)
    {
        return INT_STATUS_INVALID_PARAMETER_3;
    }

    *BeginAddress = 0;
    found = FALSE;

    if (NULL != ImageBaseBuffer)
    {
        map = ImageBaseBuffer;
    }
    else
    {
        status = IntVirtMemMap(ImageBase, PAGE_SIZE, 0, 0, &map);
        if (!INT_SUCCESS(status))
        {
            return status;
        }
    }

    // Validate that this is a good module, and get the architecture
    status = IntPeValidateHeader(ImageBase, map, PAGE_SIZE, &peInfo, 0);
    if (!INT_SUCCESS(status))
    {
        goto leave;
    }

    // we ignore the errors, because maybe we want to search outside the driver
    status = IntPeGetSectionHeaderByRva(ImageBase, map, Rva, &sectionHeader);
    if (INT_SUCCESS(status))
    {
        if (0 == ((sectionHeader.Characteristics & IMAGE_SCN_CNT_CODE)) ||
            0 == ((sectionHeader.Characteristics & IMAGE_SCN_MEM_EXECUTE)))
        {
            status = INT_STATUS_NOT_SUPPORTED;
            goto leave;
        }
    }

    status = IntCr3Read(IG_CURRENT_VCPU, &cr3);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntCr3Read failed: 0x%08x\n", status);
        goto leave;
    }

    // Tested on the whole kernel memory space on Windows 7 (both 64 and 32 bit) and not a single fail
    if (peInfo.Image64Bit)
    {
        RUNTIME_FUNCTION runtimeFunction;

        status = IntPeGetRuntimeFunction(ImageBase, map, Rva, &runtimeFunction);
        if (!INT_SUCCESS(status))
        {
            goto leave;
        }

        *BeginAddress = runtimeFunction.BeginAddress;

        // Parse all the unwind info structures and get to the actual beginning of the function
        status = IntPeParseUnwindData(ImageBase, map, &runtimeFunction, 0, NULL, BeginAddress, NULL, NULL, NULL);
        if (!INT_SUCCESS(status))
        {
            WARNING("[WARNING] IntPeParseUnwindData failed for 0x%08x: 0x%08x\n", *BeginAddress, status);
        }

        status = INT_STATUS_SUCCESS;
    }
    else
    {
        PBYTE pageMap, code;
        QWORD currentAddress, functionStart;
        DWORD bytesToScan;
        BOOLEAN physicalUnmap;

        currentAddress = ImageBase + Rva;

        status = IntVirtMemMap(currentAddress & PAGE_MASK, PAGE_SIZE, cr3, 0, &pageMap);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] Failed mapping VA 0x%016llx to host: 0x%08x\n", currentAddress, status);
            goto leave;
        }

        // go where the RIP is
        code = pageMap + (currentAddress & PAGE_OFFSET);

        // see that we aren't going in the previous section. If we do, scan only from the section start
        if (sectionHeader.VirtualAddress != 0 &&
            (Rva - MAX_FUNC_LENGTH < sectionHeader.VirtualAddress))
        {
            bytesToScan = Rva - sectionHeader.VirtualAddress;
        }
        else
        {
            bytesToScan = MAX_FUNC_LENGTH;
        }

        functionStart = 0;
        physicalUnmap = FALSE;

        while (bytesToScan > 0)
        {
            NDSTATUS ndstatus;
            INSTRUX instruction;
            BYTE sepByte;

            // before the function there must be a series of NOP or INT3
            if (*code != 0xCC && *code != 0x90)
            {
                goto _next_bytes;
            }

            // Save a pointer to the function start (at current address is a NOP or a INT3)
            functionStart = currentAddress + 1;

            // This byte must repeat itself between the function
            sepByte = *code;

            // Get where the separating bytes will end
            while (*code == sepByte && bytesToScan > 1)
            {
                --code;
                --bytesToScan;
                --currentAddress;

                // We reached the end of the page. See if we can map further.
                // Since code starts as pageMap it should never go lower than pageMap
                if (code < pageMap)
                {
                    QWORD prevPage;

                    status = IntTranslateVirtualAddress(currentAddress & PAGE_MASK, cr3, &prevPage);
                    if (!INT_SUCCESS(status))
                    {
                        // We must assume this is the beginning, since the previous page is not present. Also the
                        // current page won't be unmapped
                        break;
                    }

                    IntVirtMemUnmap(&pageMap);

                    status = IntPhysMemMap(prevPage, PAGE_SIZE, 0, &pageMap);
                    if (!INT_SUCCESS(status))
                    {
                        // This shouldn't fail since we checked that the previous page is present. So exit the
                        // function if this happens and signal the error
                        ERROR("[ERROR] Failed mapping VA 0x%016llx with GPA 0x%016llx to host: 0x%08x\n",
                              currentAddress & PAGE_MASK, prevPage, status);
                        goto leave;
                    }

                    physicalUnmap = TRUE;
                    code = pageMap + (currentAddress & PAGE_OFFSET);
                }
            }

            // There must be more than 3 bytes separating
            if (functionStart - currentAddress < 3)
            {
                // The current one is still different from NOP and INT3 so decrement it again
                goto _next_bytes;
            }

            // If the previous instruction is a RET, don't check anymore
            if ((*code == 0xc3 || *code == 0xCB) || ((((QWORD)code & PAGE_OFFSET) >= 0x2) && (*(code - 2) == 0xc2)) ||
                // RET / imm16
                ((((QWORD)code & PAGE_OFFSET) >= 0x4) && (*(code - 4) == 0xe9 || *(code - 4) == 0xe8))) // CALL or JMP
            {
                found = TRUE;
                break;
            }

            // The end of the previous function and the start of the one we search are in different pages.
            // Or if the function start is at an offset too big (> 0xff0) that when we will try to decode will spill
            // in the next page
            if ((functionStart & PAGE_MASK) != (currentAddress & PAGE_MASK) || (functionStart & PAGE_OFFSET) >= 0xff0)
            {
                // If we get here, the next page should be present (CODE sections are not swappable!)
                status = IntDecDecodeInstruction(IG_CS_TYPE_32B, functionStart, &instruction);
                if (!INT_SUCCESS(status))
                {
                    goto _next_bytes;
                }
            }
            else
            {
                // We are in the same page
                const QWORD pageMapOffset = functionStart & PAGE_OFFSET;
                ndstatus = NdDecodeEx(&instruction, pageMap + pageMapOffset, PAGE_SIZE - pageMapOffset,
                                      ND_CODE_32, ND_DATA_32);
                if (!ND_SUCCESS(ndstatus))
                {
                    goto _next_bytes;
                }
            }


            // a lot of functions start with a movzx
            if ((instruction.Instruction == ND_INS_MOV || instruction.Instruction == ND_INS_MOVZX ||
                 instruction.Instruction == ND_INS_MOVS || instruction.Instruction == ND_INS_MOVSXD ||
                 instruction.Instruction == ND_INS_MOVNTI) &&
                instruction.HasModRm)
            {
                if (instruction.Operands[0].Size != 4) // Must operate on a whole register, not just a part.
                {
                    goto _next_bytes;
                }

                if ((instruction.ModRm.reg == 5 && instruction.ModRm.rm == 4) ||    // mov ebp, esp
                    (instruction.ModRm.reg == 7 && instruction.ModRm.rm == 7))      // mod edi, edi
                {
                    found = TRUE;
                    break;
                }

                goto _next_bytes;
            }

            if ((ND_CAT_PUSH == instruction.Category) || (ND_INS_XOR == instruction.Instruction))
            {
                found = TRUE;
                break;
            }

_next_bytes:
            --currentAddress;
            --code;
            --bytesToScan;

            // We reached the end of the page. See if we can map further.
            // Since code starts as pageMap it should never go lower than pageMap
            if (code < pageMap)
            {
                QWORD prevPage;

                status = IntTranslateVirtualAddress(currentAddress & PAGE_MASK, cr3, &prevPage);
                if (!INT_SUCCESS(status))
                {
                    // The function will exit with INT_STATUS_NOT_FOUND since the start wasn't found and we cannot scan
                    // further
                    break;
                }

                IntVirtMemUnmap(&pageMap);

                status = IntPhysMemMap(prevPage, PAGE_SIZE, 0, &pageMap);
                if (!INT_SUCCESS(status))
                {
                    // This shouldn't fail since we checked that the previous page is present. So exit the
                    // function if this happens and signal the error
                    ERROR("[ERROR] Failed mapping VA 0x%016llx with GPA 0x%016llx to host: 0x%08x\n",
                          currentAddress & PAGE_MASK, prevPage, status);
                    goto leave;
                }

                physicalUnmap = TRUE;
                code = pageMap + (currentAddress & PAGE_OFFSET);
            }
        }

        // Clean the memory
        if (pageMap != NULL && physicalUnmap)
        {
            IntPhysMemUnmap(&pageMap);
        }
        else if (pageMap != NULL)
        {
            IntVirtMemUnmap(&pageMap);
        }

        if (!found)
        {
            status = INT_STATUS_NOT_FOUND;
            goto leave;
        }
        else
        {
            status = INT_STATUS_SUCCESS;
        }

        *BeginAddress = 0xffffffff & (functionStart - ImageBase);
    }

leave:
    if (NULL == ImageBaseBuffer)
    {
        IntVirtMemUnmap(&map);
    }

    return status;
}


INTSTATUS
IntPeFindFunctionStartInBuffer(
    _In_ QWORD ImageBase,
    _In_ BYTE *Buffer,
    _In_ DWORD BufferSize,
    _In_ DWORD Rva,
    _Out_ DWORD *BeginAddress
    )
///
/// @brief Find the start address of a function, given a Rva pointing inside of it.
///
/// Given a Rva, parse code backwards until we find what looks like the start of the function. This function uses
/// either the exception directory for 64 bit executables or the standard prologue for 32 bit executables to locate
/// the beginning of the function. For 64-bit MZPEs #IntPeParseUnwindDataInBuffer should be used instead.
///
/// @param[in]  ImageBase           Guest virtual address of the beginning of the module (headers) to be validated.
/// @param[in]  Buffer              The buffer containing the MZ/PE image.
/// @param[in]  BufferSize          The size of the Buffer containing the MZ/PE image.
/// @param[in]  Rva                 The Rva we will search the function start for.
/// @param[out] BeginAddress        The Rva of the identified function start.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
/// @retval #INT_STATUS_NOT_SUPPORTED If the Rva lies in a non-executable section.
/// @retval #INT_STATUS_NOT_FOUND If the function start could not be identified.
///
{
    INTRO_PE_INFO peInfo = { 0 };
    BOOLEAN found;
    INTSTATUS status;
    IMAGE_SECTION_HEADER sectionHeader = { 0 };

    if (NULL == Buffer)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    if (0 == BufferSize)
    {
        return INT_STATUS_INVALID_PARAMETER_3;
    }

    if (NULL == BeginAddress)
    {
        return INT_STATUS_INVALID_PARAMETER_5;
    }

    if (Rva >= BufferSize)
    {
        return INT_STATUS_DATA_BUFFER_TOO_SMALL;
    }

    *BeginAddress = 0;
    found = FALSE;

    // Validate that this is a good module, and get the architecture
    status = IntPeValidateHeader(ImageBase, Buffer, PAGE_SIZE, &peInfo, 0);
    if (!INT_SUCCESS(status))
    {
        return status;
    }

    // we ignore the errors, because maybe we want to search outside the driver
    status = IntPeGetSectionHeaderByRva(ImageBase, Buffer, Rva, &sectionHeader);
    if (INT_SUCCESS(status))
    {
        if (0 == (sectionHeader.Characteristics & IMAGE_SCN_MEM_EXECUTE))
        {
            return INT_STATUS_NOT_SUPPORTED;
        }
    }

    // Tested on the whole kernel memory space on Windows 7 (both 64 and 32 bit) and not a single fail
    if (peInfo.Image64Bit)
    {
        RUNTIME_FUNCTION runtimeFunction;

        status = IntPeGetRuntimeFunctionInBuffer(ImageBase, Buffer, BufferSize, Rva, &runtimeFunction);
        if (!INT_SUCCESS(status))
        {
            return status;
        }

        *BeginAddress = runtimeFunction.BeginAddress;

        // Parse all the unwind info structures and get to the actual beginning of the function
        status = IntPeParseUnwindDataInBuffer(ImageBase, Buffer, BufferSize,
                                              &runtimeFunction, 0, NULL, BeginAddress, NULL, NULL, NULL);
        if (!INT_SUCCESS(status))
        {
            WARNING("[WARNING] IntPeParseUnwindDataInBuffer failed for 0x%08x: 0x%08x\n", *BeginAddress, status);
        }

        return INT_STATUS_SUCCESS;
    }

    {
        BYTE *code = Buffer + Rva;
        QWORD functionStartRva = 0;
        DWORD bytesToScan;
        QWORD currentRva = Rva;

        // see that we aren't going in the previous section. If we do, scan only from the section start
        if (sectionHeader.VirtualAddress != 0 &&
            (Rva - MAX_FUNC_LENGTH < sectionHeader.VirtualAddress))
        {
            bytesToScan = Rva - sectionHeader.VirtualAddress;
        }
        else
        {
            bytesToScan = MAX_FUNC_LENGTH;
        }

        while (bytesToScan > 0)
        {
            NDSTATUS ndstatus;
            INSTRUX instruction;
            BYTE sepByte;

            if (code < Buffer)
            {
                break;
            }

            // before the function there must be a series of NOP or INT3
            if (*code != 0xCC && *code != 0x90)
            {
                goto _next_bytes;
            }

            // Save a pointer to the function start (at current address is a NOP or a INT3)
            functionStartRva = currentRva + 1;

            if (functionStartRva >= BufferSize)
            {
                break;
            }

            // This byte must repeat itself between the function
            sepByte = *code;

            // Get where the separating bytes will end
            while (code >= Buffer && *code == sepByte && bytesToScan)
            {
                --code;
                --bytesToScan;
                --currentRva;
            }

            if (code < Buffer)
            {
                break;
            }

            // There must be more than 3 bytes separating
            if (functionStartRva - currentRva < 3)
            {
                // The current one is still different from NOP and INT3 so decrement it again
                goto _next_bytes;
            }

            // If the previous instruction is a RET, don't check anymore
            if ((*code == 0xc3 || *code == 0xCB) ||
                ((((QWORD)code & PAGE_OFFSET) >= 0x2) && (*(code - 2) == 0xc2)) ||                      // RET / imm16
                ((((QWORD)code & PAGE_OFFSET) >= 0x4) && (*(code - 4) == 0xe9 || *(code - 4) == 0xe8))) // CALL or JMP
            {
                found = TRUE;
                break;
            }

            ndstatus = NdDecodeEx(&instruction, Buffer + functionStartRva, BufferSize - functionStartRva,
                                  ND_CODE_32, ND_DATA_32);
            if (!ND_SUCCESS(ndstatus))
            {
                goto _next_bytes;
            }


            // a lot of functions start with a movzx
            if ((instruction.Instruction == ND_INS_MOV || instruction.Instruction == ND_INS_MOVZX ||
                 instruction.Instruction == ND_INS_MOVS || instruction.Instruction == ND_INS_MOVSXD ||
                 instruction.Instruction == ND_INS_MOVNTI) &&
                instruction.HasModRm)
            {
                if (instruction.Operands[0].Size != 4) // Must operate on a whole register, not just a part.
                {
                    goto _next_bytes;
                }

                if ((instruction.ModRm.reg == 5 && instruction.ModRm.rm == 4) ||        // mov ebp, esp
                    (instruction.ModRm.reg == 7 && instruction.ModRm.rm == 7))          // mod edi, edi
                {
                    found = TRUE;
                    break;
                }

                goto _next_bytes;
            }

            if ((ND_CAT_PUSH == instruction.Category) || (ND_INS_XOR == instruction.Instruction))
            {
                found = TRUE;
                break;
            }

_next_bytes:
            --currentRva;
            --code;
            --bytesToScan;
        }

        if (!found)
        {
            return INT_STATUS_NOT_FOUND;
        }

        *BeginAddress = functionStartRva & 0xFFFFFFFF;
    }

    return INT_STATUS_SUCCESS;
}
