/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _MEMTAGS_H_
#define _MEMTAGS_H_

//
// tags for memory allocations
//
#define IC_TAG_DRNU             'UND:'          ///< Guest loaded module name buffer (Unicode)
#define IC_TAG_EXPN             'PXE:'          ///< Export name buffer
#define IC_TAG_DOBJ             'BOD:'          ///< Driver Object List Entry
#define IC_TAG_POBJ             'BOP:'          ///< Process Object List Entry
#define IC_TAG_MODU             'DOM:'          ///< Loaded module
#define IC_TAG_DETG             'SGTD'          ///< Guest detour state.
#define IC_TAG_GVCA             'CVG:'          ///< The GVA cache.
#define IC_TAG_GPCA             'CPG:'          ///< The GPA cache.
#define IC_TAG_GPCV             'VPG:'          ///< GPA cache victim.
#define IC_TAG_ITGR             'TGI:'          ///< Integrity region
#define IC_TAG_WPFN             'NFP:'          ///< Windows PFN locked page.
#define IC_TAG_EXCP             'CXE:'          ///< Exception structure
#define IC_TAG_EXKM             'KXE:'          ///< Kernel exceptions structures
#define IC_TAG_EXKU             'UKXE'          ///< Kernel-User mode exceptions structures
#define IC_TAG_EXUM             'UXE:'          ///< User exceptions structures
#define IC_TAG_ESIG             'GSE:'          ///< Exception signatures structures
#define IC_TAG_DEBUG            'GBD:'          ///< Debugger stuff
#define IC_TAG_ALLOC            'CLA:'          ///< Memory allocation.
#define IC_TAG_INSC             'SNI:'          ///< Instruction cache.
#define IC_TAG_IINV             'VNII'          ///< Instruction cache invalidation entry.
#define IC_TAG_CDBK             'KBDC'          ///< Code blocks
#define IC_TAG_MSRHK            'EDH:'          ///< MSR Hook descriptor
#define IC_TAG_HKOBJ            'DJOB'          ///< Hook-object descriptor
#define IC_TAG_GPAH             'HAPG'          ///< GPA hook
#define IC_TAG_GVAH             'HAVG'          ///< GVA hook object
#define IC_TAG_EPTE             'EPTE'          ///< EPT hook entry
#define IC_TAG_REGD             'DGER'          ///< Object region descriptor
#define IC_TAG_HKAR             'RAKH'          ///< Hooks array in object region descriptor
#define IC_TAG_UNPG             'GPNU'          ///< Protected unpacker-page.
#define IC_TAG_SWCX             'XCS:'          ///< Swapmem context.
#define IC_TAG_SWPP             'PPS:'          ///< Swapmem pages data area.
#define IC_TAG_SWPG             'GPWS'          ///< Swapmem page
#define IC_TAG_SWPN             'NPWS'          ///< Swap pending
#define IC_TAG_UPDT             'TDU:'          ///< Update structure, holding a chunk
#define IC_TAG_EPTV             'EPTV'          ///< EPT violations cache.
#define IC_TAG_RGCH             'HCGR'          ///< Register cache.
#define IC_TAG_AGNE             'ENGA'          ///< Agent entry.
#define IC_TAG_LAGE             'EGAL'          ///< Linux agent entry.
#define IC_TAG_AGND             'DNGA'          ///< Agent data.
#define IC_TAG_AGNN             'NNGA'          ///< Agent name.
#define IC_TAG_IMGE             'IMGE'          ///< PE image buffer.
#define IC_TAG_HDRS             'SRDH'          ///< Module headers as cached inside a KERNEL_MODULE structure.
#define IC_TAG_PTHP             'PHTP'          ///< Object path (cached)
#define IC_TAG_UMPT             'TPMU'          ///< UM object path (cached)
#define IC_TAG_PATH             'HTAP'          ///< Object path
#define IC_TAG_NAME             'EMAN'          ///< Object name
#define IC_TAG_MCRG             'GRCM'          ///< MemCloak region
#define IC_TAG_MCBF             'FBCM'          ///< MemCloak original buffer
#define IC_TAG_VASR             'RSVA'          ///< VAS Root Object
#define IC_TAG_VAST             'TSAV'          ///< VAS Monitor Table
#define IC_TAG_VASE             'ESAV'          ///< VAS Monitor Table Entries array
#define IC_TAG_VASP             'PSAV'          ///< VAS Monitor Table Pointers array
#define IC_TAG_PTPT             'TPTP'          ///< PTS Page Table hook.
#define IC_TAG_PTPS             'SPTP'          ///< PTS Page Hook Context.
#define IC_TAG_SUBS             'SUBS'          ///< Process subsystem structure.
#define IC_TAG_CPUS             'SUPC'          ///< CPU state.
#define IC_TAG_XCRH             'HRCX'          ///< XCR hook
#define IC_TAG_XCRS             'SRCX'          ///< XCR hook state
#define IC_TAG_MSRS             'SRSM'          ///< MSR hook state
#define IC_TAG_CRH              'KHRC'          ///< CR hook
#define IC_TAG_CRS              'TSRC'          ///< CR hook state
#define IC_TAG_DTRH             'HRTD'          ///< IDTR & GDTR hook
#define IC_TAG_DTRS             'SRTD'          ///< IDTR & GDTR hook state
#define IC_TAG_HOOKS            'AHTS'          ///< Global hook state
#define IC_TAG_SLKE             'EKLS'          ///< Slack space entry
#define IC_TAG_PPAG             'GAPP'          ///< Process VAD page
#define IC_TAG_VADP             'PDAV'          ///< VAD pages hash table
#define IC_TAG_PCMD             'LDMC'          ///< Process command line
#define IC_TAG_FSTM             'PMSF'          ///< Linux fast map
#define IC_TAG_MLMP             'PMLM'          ///< Multi-page mappings
#define IC_TAG_PPIF             'FIPP'          ///< Protected process info
#define IC_TAG_MDHS             'SHDM'          ///< Module hashes
#define IC_TAG_INVC             'CVNI'          ///< Invocation context
#define IC_TAG_NSPX             'XPSN'          ///< NsProxy object
#define IC_TAG_UDCX             'XCDU'          ///< UD pending context

#define IC_TAG_PTPM             'MPTP'          ///< Page Table Hook Manager entry.
#define IC_TAG_PTPP             'PPTP'          ///< Page Table Hook Manager page.
#define IC_TAG_PTPA             'APTP'          ///< Page Table Hook Manager array.

#define IC_TAG_KRNB             'BNRK'          ///< Kernel Buffer, cached by the introspection
#define IC_TAG_HALB             'BLAH'          ///< Hal Buffer, cached by the introspection


#define IC_TAG_VAD              ':daV'          ///< Virtual Address Descriptor for user mode address ranges
#define IC_TAG_VAD_PGARR        'PGAR'          ///< Virtual page array with the pages contained by a VAD
#define IC_TAG_VAD_PAGE         'PGEN'          ///< Virtual page from a VAD page array

#define IC_TAG_HAL_HEAP         'GPHH'          ///< Page in Hal Heap

#define IC_TAG_KSYM             'MYSK'          ///< Kallsym cache
#define IC_TAG_EPTE             'EPTE'
#define IC_TAG_IATB             'BTAI'          ///< IAT entries bitmap
#define IC_TAG_VEVE             'EVEV'          ///< \#VE state

#define IC_TAG_EXPCH            'HCXE'          ///< Windows UM exports cache
#define IC_TAG_MODCH            'HCDM'          ///< Windows UM module cache

#define IC_TAG_WINOBJ_SWAP      'JBOS'          ///< Winobj swap handle
#define IC_TAG_WSWP             'PWSW'          ///< Win init swap handle
#define IC_TAG_POKE             'EKOP'          ///< Linux text poke kprobes

#define IC_TAG_MTBL             'LBTM'          ///< Mem Table
#define IC_TAG_PTI_DRV          'ITPD'          ///< PTI driver image
#define IC_TAG_XSAVE            'EVSX'          ///< XSAVE area

#define IC_TAG_VEPG             'GPEV'          ///< \#VE agent pages
#define IC_TAG_SPPE             'EPPS'          ///< SPP entry.

#define IC_TAG_WINMOD_BLOCK     'LBOM'          ///< Win um module load-blocking objects
#define IC_TAG_WINMOD_CB_LIST   'LBCM'          ///< Win um module call back list for a reason (in DllMain)
#define IC_TAG_WINMOD_CB_OBJ    'OBCM'          ///< Win um module call back object for reason (in DllMain)

#define IC_TAG_CAMI             'IMAC'          ///< Live update allocations.

#define IC_TAG_SGDG             'GDGS'          ///< SWAPGS gadget.
#define IC_TAG_SGDH             'HDGS'          ///< SWAPGS handler.

#define IC_TAG_CRED             'DERC'          ///< Linux cred struct

#define IC_TAG_CMD_LINE         'DMC:'          ///< Windows command line
#define IC_TAG_ENGINE_NOT       'GNE:'          ///< Used for asynchronous engine notifications

#define IC_TAG_VMA              'AMV:'          ///< Used for Linux VMA structs
#define IC_TAG_GUEST            'TSG:'          ///< Used for Linux/Windows guest structure

#define IC_TAG_SUD_BUFFER       'BDUS'          ///< Used for keeping the SharedUserData buffer internally

#define IC_TAG_IOBD             'DBOI'          ///< Used for interrupt object protection descriptors.

#endif // _MEMTAGS_H_
