/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
///
/// @file windrv_protected.c
///
/// @brief This file contains Windows Kernel Driver and Driver Object related
/// protection options.
///

#include "drivers.h"
#include "windrvobj.h"
#include "guests.h"
#include "winguest.h"
#include "windrv_protected.h"

/// Describe protection information for the NT Kernel.
static const PROTECTED_MODULE_INFO gNtModule = 
{
    .Type = winModCore,
    .Name = u"ntoskrnl.exe",
    .Path = u"\\SystemRoot\\System32\\ntoskrnl.exe",
    .RequiredFlags = INTRO_OPT_PROT_KM_NT,
};

/// Describe protection information for HAL.
static const PROTECTED_MODULE_INFO gHalModule = 
{
    .Type = winModCore,
    .Name = u"hal.dll",
    .Path = u"\\SystemRoot\\System32\\hal.dll",
    .RequiredFlags = INTRO_OPT_PROT_KM_HAL,
};

/// Describe protection information for the core Kernel modules.
static const PROTECTED_MODULE_INFO gCoreModules[] = 
{
    {
        .Type = winModCore,
        .Name = u"iastor.sys",
        .Path = u"\\SystemRoot\\System32\\drivers\\iastor.sys",
        .DriverObject = u"\\driver\\iastor",
        .RequiredFlags = INTRO_OPT_PROT_KM_NT_DRIVERS,
    },

    {
        .Type = winModCore,
        .Name = u"ndis.sys",
        .Path = u"\\SystemRoot\\System32\\drivers\\ndis.sys",
        .DriverObject = u"\\driver\\ndis",
        .RequiredFlags = INTRO_OPT_PROT_KM_NT_DRIVERS,
    },

    {
        .Type = winModCore,
        .Name = u"netio.sys",
        .Path = u"\\SystemRoot\\System32\\drivers\\netio.sys",
        .DriverObject = NULL,
        .RequiredFlags = INTRO_OPT_PROT_KM_NT_DRIVERS,
    },

    {
        .Type = winModCore,
        .Name = u"iastorV.sys",
        .Path = u"\\SystemRoot\\System32\\drivers\\iastorV.sys",
        .DriverObject = u"\\driver\\iastorv",
        .RequiredFlags = INTRO_OPT_PROT_KM_NT_DRIVERS,
    },

    {
        .Type = winModCore,
        .Name = u"iastorAV.sys",
        .Path = u"\\SystemRoot\\System32\\drivers\\iastorAV.sys",
        .DriverObject = u"\\driver\\iastorav",
        .RequiredFlags = INTRO_OPT_PROT_KM_NT_DRIVERS,
    },

    {
        .Type = winModCore,
        .Name = u"disk.sys",
        .Path = u"\\SystemRoot\\System32\\drivers\\disk.sys",
        .DriverObject = u"\\driver\\disk",
        .RequiredFlags = INTRO_OPT_PROT_KM_NT_DRIVERS,
    },

    {
        .Type = winModCore,
        .Name = u"atapi.sys",
        .Path = u"\\SystemRoot\\System32\\drivers\\atapi.sys",
        .DriverObject = u"\\driver\\atapi",
        .RequiredFlags = INTRO_OPT_PROT_KM_NT_DRIVERS,
    },

    {
        .Type = winModCore,
        .Name = u"storahci.sys",
        .Path = u"\\SystemRoot\\System32\\drivers\\storahci.sys",
        .DriverObject = u"\\driver\\storahci",
        .RequiredFlags = INTRO_OPT_PROT_KM_NT_DRIVERS,
    },

    {
        .Type = winModCore,
        .Name = u"ataport.sys",
        .Path = u"\\SystemRoot\\System32\\drivers\\ataport.sys",
        .DriverObject = NULL,
        .RequiredFlags = INTRO_OPT_PROT_KM_NT_DRIVERS,
    },

    {
        .Type = winModCore,
        .Name = u"ntfs.sys",
        .Path = u"\\SystemRoot\\System32\\drivers\\ntfs.sys",
        .DriverObject = u"\\filesystem\\ntfs",
        .RequiredFlags = INTRO_OPT_PROT_KM_NT_DRIVERS,
    },

    {
        .Type = winModCore,
        .Name = u"refs.sys",
        .Path = u"\\SystemRoot\\System32\\drivers\\refs.sys",
        .DriverObject = u"\\filesystem\\refs",
        .RequiredFlags = INTRO_OPT_PROT_KM_NT_DRIVERS,
    },

    {
        .Type = winModCore,
        .Name = u"tcpip.sys",
        .Path = u"\\SystemRoot\\System32\\drivers\\tcpip.sys",
        .DriverObject = u"\\driver\\tcpip",
        .RequiredFlags = INTRO_OPT_PROT_KM_NT_DRIVERS,
    },

    {
        .Type = winModCore,
        .Name = u"srv.sys",
        .Path = u"\\SystemRoot\\System32\\drivers\\srv.sys",
        .DriverObject = NULL,   // \\filesystem\\srv
        .RequiredFlags = INTRO_OPT_PROT_KM_NT_DRIVERS,
    },

    {
        .Type = winModCore,
        .Name = u"srv2.sys",
        .Path = u"\\SystemRoot\\System32\\drivers\\srv2.sys",
        .DriverObject = NULL,   // \\filesystem\\srv2
        .RequiredFlags = INTRO_OPT_PROT_KM_NT_DRIVERS,
    },

    {
        .Type = winModCore,
        .Name = u"srvnet.sys",
        .Path = u"\\SystemRoot\\System32\\drivers\\srvnet.sys",
        .DriverObject = NULL,   // \\filesystem\\srvnet
        .RequiredFlags = INTRO_OPT_PROT_KM_NT_DRIVERS,
    },

    {
        .Type = winModCore,
        .Name = u"lxss.sys",
        .Path = u"\\SystemRoot\\system32\\drivers\\lxss.sys",
        .DriverObject = u"\\Driver\\lxss",
        .RequiredFlags = INTRO_OPT_PROT_KM_NT_DRIVERS,
    },

    {
        .Type = winModCore,
        .Name = u"lxcore.sys",
        .Path = u"\\SystemRoot\\system32\\drivers\\LXCORE.SYS",
        .DriverObject = NULL,
        .RequiredFlags = INTRO_OPT_PROT_KM_NT_DRIVERS,
    },
};

/// Describe protection information for antivirus Kernel modules.
static const PROTECTED_MODULE_INFO gAvModules[] = 
{
    {
        .Type = winModAntivirus,
        .Name = u"avc3.sys",
        .Path = u"\\systemroot\\system32\\drivers\\avc3.sys",
        .DriverObject = u"\\filesystem\\avc3",
        .RequiredFlags = INTRO_OPT_PROT_KM_AV_DRIVERS,
    },

    {
        .Type = winModAntivirus,
        .Name = u"avckf.sys",
        .Path = u"\\systemroot\\system32\\drivers\\avckf.sys",
        .DriverObject = u"\\filesystem\\avckf",
        .RequiredFlags = INTRO_OPT_PROT_KM_AV_DRIVERS,
    },

    {
        .Type = winModAntivirus,
        .Name = u"winguest.sys",
        .Path = u"\\systemroot\\system32\\drivers\\winguest.sys",
        .DriverObject = u"\\driver\\winguest",
        .RequiredFlags = INTRO_OPT_PROT_KM_AV_DRIVERS,
    },

    {
        .Type = winModAntivirus,
        .Name = u"trufos.sys",
        .Path = u"\\systemroot\\system32\\drivers\\trufos.sys",
        .DriverObject = u"\\filesystem\\trufos",
        .RequiredFlags = INTRO_OPT_PROT_KM_AV_DRIVERS,
    },

    {
        .Type = winModAntivirus,
        .Name = u"trufosalt.sys",
        .Path = u"\\systemroot\\system32\\drivers\\trufosalt.sys",
        .DriverObject = u"\\filesystem\\trufosalt",
        .RequiredFlags = INTRO_OPT_PROT_KM_AV_DRIVERS,
    },

    {
        .Type = winModAntivirus,
        .Name = u"gzflt.sys",
        .Path = u"\\systemroot\\system32\\drivers\\gzflt.sys",
        .DriverObject = u"\\filesystem\\gzflt",
        .RequiredFlags = INTRO_OPT_PROT_KM_AV_DRIVERS,
    },

    {
        .Type = winModAntivirus,
        .Name = u"bdvedisk.sys",
        .Path = u"\\systemroot\\system32\\drivers\\bdvedisk.sys",
        .DriverObject = u"\\driver\\bdvedisk",
        .RequiredFlags = INTRO_OPT_PROT_KM_AV_DRIVERS,
    },

    {
        .Type = winModAntivirus,
        .Name = u"bdsandbox.sys",
        .Path = u"\\systemroot\\system32\\drivers\\bdsandbox.sys",
        .DriverObject = u"\\filesystem\\BDSandBox",
        .RequiredFlags = INTRO_OPT_PROT_KM_AV_DRIVERS,
    },

    {
        .Type = winModAntivirus,
        .Name = u"bdfndisf6.sys",
        .Path = u"\\systemroot\\system32\\drivers\\bdfndisf6.sys",
        .DriverObject = u"\\driver\\BdfNdisf",
        .RequiredFlags = INTRO_OPT_PROT_KM_AV_DRIVERS,
    },

    {
        .Type = winModAntivirus,
        .Name = u"bdfwfpf.sys",
        .Path = u"\\systemroot\\system32\\drivers\\bdfwfpf.sys",
        .DriverObject = u"\\driver\\bdfwfpf",
        .RequiredFlags = INTRO_OPT_PROT_KM_AV_DRIVERS,
    },

    {
        .Type = winModAntivirus,
        .Name = u"bdelam.sys",
        .Path = u"\\systemroot\\system32\\drivers\\bdelam.sys",
        .DriverObject = u"\\driver\\bdelam",
        .RequiredFlags = INTRO_OPT_PROT_KM_AV_DRIVERS,
    },

    {
        .Type = winModAntivirus,
        .Name = u"bddci.sys",
        .Path = u"\\systemroot\\system32\\drivers\\bddci.sys",
        .DriverObject = u"\\driver\\bddci",
        .RequiredFlags = INTRO_OPT_PROT_KM_AV_DRIVERS,
    },

    {
        .Type = winModAntivirus,
        .Name = u"edrsensor.sys",
        .Path = u"\\systemroot\\system32\\drivers\\edrsensor.sys",
        .DriverObject = u"\\filesystem\\edrsensor",
        .RequiredFlags = INTRO_OPT_PROT_KM_AV_DRIVERS,
    },

    {
        .Type = winModAntivirus,
        .Name = u"ignis.sys",
        .Path = u"\\systemroot\\system32\\drivers\\ignis.sys",
        .DriverObject = u"\\driver\\ignis",
        .RequiredFlags = INTRO_OPT_PROT_KM_AV_DRIVERS,
    },

    {
        .Type = winModAntivirus,
        .Name = u"atc.sys",
        .Path = u"\\systemroot\\system32\\drivers\\atc.sys",
        .DriverObject = u"\\filesystem\\atc",
        .RequiredFlags = INTRO_OPT_PROT_KM_AV_DRIVERS,
    },

    {
        .Type = winModAntivirus,
        .Name = u"gemma.sys",
        .Path = u"\\systemroot\\system32\\drivers\\gemma.sys",
        .DriverObject = u"\\filesystem\\gemma",
        .RequiredFlags = INTRO_OPT_PROT_KM_AV_DRIVERS,
    },
};

/// Describe protection information for XEN Kernel modules.
static const PROTECTED_MODULE_INFO gXenModules[] = 
{
    {
        .Type = winModCitrix,
        .Name = u"picadm.sys",
        .Path = u"\\SystemRoot\\System32\\drivers\\picadm.sys",
        .DriverObject = u"\\FileSystem\\picadm",
        .RequiredFlags = INTRO_OPT_PROT_KM_XEN_DRIVERS,
    },

    {
        .Type = winModCitrix,
        .Name = u"ctxad.sys",
        .Path = u"\\SystemRoot\\System32\\drivers\\ctxad.sys",
        .DriverObject = u"\\Driver\\ctxad",
        .RequiredFlags = INTRO_OPT_PROT_KM_XEN_DRIVERS,
    },

    {
        .Type = winModCitrix,
        .Name = u"ctxusbb.sys",
        .Path = u"\\SystemRoot\\System32\\drivers\\ctxusbb.sys",
        .DriverObject = u"\\Driver\\ctxusbb",
        .RequiredFlags = INTRO_OPT_PROT_KM_XEN_DRIVERS,
    },

    {
        .Type = winModCitrix,
        .Name = u"ctxsmcdrv.sys",
        .Path = u"\\SystemRoot\\System32\\drivers\\ctxsmcdrv.sys",
        .DriverObject = u"\\Driver\\ctxsmcdrv",
        .RequiredFlags = INTRO_OPT_PROT_KM_XEN_DRIVERS,
    },

    ////////////////////////////////////////////
    // bad bad bad // bad bad bad // bad bad bad
    {
        .Type = winModCitrix,
        .Name = u"picapar.sys",
        .Path = u"\\SystemRoot\\System32\\drivers\\picapar.sys",
        .DriverObject = u"\\FileSystem\\picapar",
        .RequiredFlags = INTRO_OPT_PROT_KM_XEN_DRIVERS,
    },
    ////////////////////////////////////////////

    {
        .Type = winModCitrix,
        .Name = u"picaser.sys",
        .Path = u"\\SystemRoot\\System32\\drivers\\picaser.sys",
        .DriverObject = u"\\FileSystem\\picaser",
        .RequiredFlags = INTRO_OPT_PROT_KM_XEN_DRIVERS,
    },

    {
        .Type = winModCitrix,
        .Name = u"picakbm.sys",
        .Path = u"\\SystemRoot\\System32\\drivers\\picakbm.sys",
        .DriverObject = u"\\Driver\\picakbm",
        .RequiredFlags = INTRO_OPT_PROT_KM_XEN_DRIVERS,
    },

    {
        .Type = winModCitrix,
        .Name = u"picakbf.sys",
        .Path = u"\\SystemRoot\\System32\\drivers\\picakbf.sys",
        .DriverObject = u"\\Driver\\picakbf",
        .RequiredFlags = INTRO_OPT_PROT_KM_XEN_DRIVERS,
    },

    {
        .Type = winModCitrix,
        .Name = u"picamouf.sys",
        .Path = u"\\SystemRoot\\System32\\drivers\\picamouf.sys",
        .DriverObject = u"\\Driver\\picamouf",
        .RequiredFlags = INTRO_OPT_PROT_KM_XEN_DRIVERS,
    },

    {
        .Type = winModCitrix,
        .Name = u"picaTwComms.sys",
        .Path = u"\\SystemRoot\\System32\\drivers\\picaTwComms.sys",
        .DriverObject = NULL,
        .RequiredFlags = INTRO_OPT_PROT_KM_XEN_DRIVERS,
    },

    {
        .Type = winModCitrix,
        .Name = u"picavc.sys",
        .Path = u"\\SystemRoot\\System32\\drivers\\picavc.sys",
        .DriverObject = NULL,
        .RequiredFlags = INTRO_OPT_PROT_KM_XEN_DRIVERS,
    },

    {
        .Type = winModCitrix,
        .Name = u"picacdd2.sys",
        .Path = u"\\SystemRoot\\System32\\drivers\\picacdd2.sys",
        .DriverObject = NULL,
        .RequiredFlags = INTRO_OPT_PROT_KM_XEN_DRIVERS,
    },

    {
        .Type = winModCitrix,
        .Name = u"picadd.sys",
        .Path = u"\\SystemRoot\\System32\\drivers\\picadd.sys",
        .DriverObject = NULL,
        .RequiredFlags = INTRO_OPT_PROT_KM_XEN_DRIVERS,
    },
};

_Success_(return != NULL)
static __forceinline const PROTECTED_MODULE_INFO *
IntWinDrvGetProtInfoByName(
    _In_reads_(InfoSize) const PROTECTED_MODULE_INFO *Info,
    _In_ size_t InfoSize,
    _In_ const WCHAR *Name
    )
///
/// @brief Perform a search for a driver by name in an array of protected kernel modules.
///
/// @param[in] Info     The array of protected modules to search into.
/// @param[in] InfoSize The number of elements in the array.
/// @param[in] Name     The name of the driver to search for.
///
/// @returns The desired protection information or NULL if not found.
///
{
    for (size_t i = 0; i < InfoSize; i++)
    {
        if (!wstrcasecmp(Info[i].Name, Name))
        {
            return &Info[i];
        }
    }

    return NULL;
}


_Success_(return != NULL)
static __forceinline const PROTECTED_MODULE_INFO *
IntWinDrvObjGetProtInfoByName(
    _In_reads_(InfoSize) const PROTECTED_MODULE_INFO *Info,
    _In_ size_t InfoSize,
    _In_ const WCHAR *Name
    )
///
/// @brief Perform a search for a driver object by name in an array of protected kernel modules.
///
/// @param[in] Info     The array of protected modules to search into.
/// @param[in] InfoSize The number of elements in the array.
/// @param[in] Name     The name of the driver object to search for.
///
/// @returns The desired protection information or NULL if not found.
///
{
    if (NULL == Name)
    {
        return NULL;
    }

    for (size_t i = 0; i < InfoSize; i++)
    {
        if (NULL != Info[i].DriverObject && !wstrcasecmp(Info[i].DriverObject, Name))
        {
            return &Info[i];
        }
    }

    return NULL;
}


_Success_(return != NULL)
const PROTECTED_MODULE_INFO *
IntWinDrvIsProtected(
    _In_ const KERNEL_DRIVER *Driver
    )
///
/// @brief Get the protected module information for a kernel driver.
///
/// @param[in] Driver   Pointer to a kernel driver for which to search a protection information.
///
/// @returns The desired protection information or NULL if not found.
///
{
    static const struct
    {
        const PROTECTED_MODULE_INFO *Info;
        size_t Size;
        QWORD RequiredProtection;
    } pms[] = 
    {
        { .Info = &gNtModule,   .Size = 1,                      .RequiredProtection = INTRO_OPT_PROT_KM_NT },
        { .Info = &gHalModule,  .Size = 1,                      .RequiredProtection = INTRO_OPT_PROT_KM_HAL },
        { .Info = gCoreModules, .Size = ARRAYSIZE(gCoreModules),.RequiredProtection = INTRO_OPT_PROT_KM_NT_DRIVERS },
        { .Info = gAvModules,   .Size = ARRAYSIZE(gAvModules),  .RequiredProtection = INTRO_OPT_PROT_KM_AV_DRIVERS },
        { .Info = gXenModules,  .Size = ARRAYSIZE(gXenModules), .RequiredProtection = INTRO_OPT_PROT_KM_XEN_DRIVERS },
    };
    
    if (NULL == Driver)
    {
        return NULL;
    }

    for (size_t i = 0; i < ARRAYSIZE(pms); i++)
    {
        const PROTECTED_MODULE_INFO *pm;

        if (0 == (gGuest.CoreOptions.Current & pms[i].RequiredProtection))
        {
            continue;
        }

        pm = IntWinDrvGetProtInfoByName(pms[i].Info, pms[i].Size, Driver->Name);
        if (NULL != pm)
        {
            return pm;
        }
    }

    return NULL;
}


_Success_(return != NULL)
const PROTECTED_MODULE_INFO *
IntWinDrvObjIsProtected(
    _In_ const WIN_DRIVER_OBJECT *Driver
    )
///
/// @brief Get the protected module information for a kernel driver object.
///
/// @param[in] Driver   Pointer to a driver object for which to search a protection information.
///
/// @returns The desired protection information or NULL if not found.
///
{
    static const struct
    {
        const PROTECTED_MODULE_INFO *Info;
        size_t Size;
    } pms[] = 
    {
        { .Info = gCoreModules, .Size = ARRAYSIZE(gCoreModules) },
        { .Info = gAvModules,   .Size = ARRAYSIZE(gAvModules) },
        { .Info = gXenModules,  .Size = ARRAYSIZE(gXenModules) }
    };

    if (NULL == Driver || 0 == (gGuest.CoreOptions.Current & INTRO_OPT_PROT_KM_DRVOBJ))
    {
        return NULL;
    }

    for (size_t i = 0; i < ARRAYSIZE(pms); i++)
    {
        const PROTECTED_MODULE_INFO *pm = IntWinDrvObjGetProtInfoByName(pms[i].Info, pms[i].Size, Driver->Name);
        if (NULL != pm)
        {
            return pm;
        }
    }

    return NULL;
}


BOOLEAN
IntWinDrvHasDriverObject(
    _In_ const KERNEL_DRIVER *Driver
    )
///
/// @brief Check wether a kernel driver has a driver object that we care to protect.
///
/// @param[in] Driver Pointer to a kernel driver to be checked.
///
/// @returns TRUE if the driver has a driver object, FALSE otherwise.
///
{
    const PROTECTED_MODULE_INFO *pm = IntWinDrvIsProtected(Driver);

    return NULL != pm && NULL != pm->DriverObject;
}


BOOLEAN
IntWinDrvIsProtectedAv(
    _In_ const WCHAR *Driver
    )
///
/// @brief Check wether a kernel driver is a known and protected antivirus.
///
/// @param[in] Driver Pointer to a WCHAR string describing the drivers name.
///
/// @returns TRUE if the driver is a known and protected antivirus, FALSE otherwise.
///
{
    return NULL != Driver && NULL != IntWinDrvGetProtInfoByName(gAvModules, ARRAYSIZE(gAvModules), Driver);
}


BOOLEAN
IntWinDrvObjIsProtectedAv(
    _In_ const WCHAR *DrvObj
    )
///
/// @brief Checks if a driver object belongs to a known and protected antivirus.
///
/// @param[in] DrvObj   Pointer to a WCHAR string describing the driver objects name.
///
/// @returns TRUE if the driver object belongs to a known and protected antivirus, FALSE otherwise.
///
{
    return NULL != DrvObj && NULL != IntWinDrvObjGetProtInfoByName(gAvModules, ARRAYSIZE(gAvModules), DrvObj);
}

