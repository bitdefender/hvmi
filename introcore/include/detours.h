/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _DETOURS_H_
#define _DETOURS_H_

///
/// @defgroup   group_detours Guest API detours
/// @ingroup    group_internal
/// @brief      Guest functions hooked by introcore
///
/// In order to intercept certain guest operations, VMEXIT events may not be enough. For example, if we want to
/// know when a new process is inserted inside the guest process list. For these cases, introcore is able to hook
/// guest functions. This is done in a pretty standard way: the first few instructions in a hooked function are replaced
/// with a jump to a memory zone that contains code controlled by us (the in-guest detour handler). The in-guest
/// handler can notify introcore about the event by issuing a hypercall.
/// The in-guest handler can also do pre-processing on the event or can change the behavior of the guest without
/// notifying introcore about it.
///

///
/// @file       detours.h
/// @ingroup    group_detours
/// @brief      The guest detour API
///

#include "thread_safeness.h"
#include "handlers.h"

typedef struct _LIX_FN_DETOUR LIX_FN_DETOUR;

/// @brief      Checks if the argument should be taken from the guest general purpose registers.
///
/// @param[in]  Arg     The argument encoding as taken from a #DETOUR_ARGS structure.
///
/// @returns    True if the argument is present in the guest GPRs; False if it is not. If the argument is present
///             in the guest GPRs, Arg will be the register index.
#define DET_ARG_REGS(Arg)         (gGuest.Guest64 ? ((DWORD)(Arg) < 16) : ((DWORD)(Arg) < 8))

/// @brief      Creates an encoding for a parameter passed on the guest stack.
///
/// In order to distinguish stack arguments from arguments passed through registers, the lower word of the argument
/// is set to 0xFFFF, while the upper word is the stack index.
///
/// @param[in]  Index   The parameter index on the stack (parameter 1 has index 1, parameter 2 has index 2, etc).
///
/// @returns    An encoding for the given parameter index.
#define DET_ARG_STACK(Index)      (((DWORD)(Index) << 16) | 0xFFFF)

/// @brief      Checks if the argument should be taken from the guest stack.
///
/// @param[in]  Arg     The argument encoding as taken from a #DETOUR_ARGS structure.
///
/// @returns    True if the argument is present on the guest stack; False if it is not. If the argument is present
///             on the stack, #DET_ARG_STACK_OFFSET should be used to obtain its stack offset.
#define DET_ARG_ON_STACK(Arg)     (((Arg) & 0xFFFF) == 0xFFFF)

/// @brief      Gets the stack offset at which a stack argument is found.
///
/// #DET_ARG_ON_STACK must be used in order to check that the argument is present on the stack before using this macro.
///
/// @param[in]  Arg     The argument encoding as taken from a #DETOUR_ARGS structure.
///
/// @returns    The offset, relative to the current guest RSP, at which the argument is found.
#define DET_ARG_STACK_OFFSET(Arg) (((Arg) >> 16) * gGuest.WordSize)

/// @brief      The maximum number of arguments passed from the guest to introcore.
#define DET_ARGS_MAX              8

/// @brief      Default argument passing convention for Linux guests.
#define DET_ARGS_DEFAULT_LIX      {.Argc = DET_ARGS_MAX, .Argv = {NDR_RDI, NDR_RSI, NDR_RDX, NDR_RCX, \
                                    NDR_R8, NDR_R9, DET_ARG_STACK(1), DET_ARG_STACK(2)}}

/// @brief      Default argument passing convention for 64-bit Windows guests.
///
/// This follows the default calling convention used on 64-bit Windows and takes into consideration the stack shadow
/// space, so indexes 1, 2, 3, and 4 point to the shadow space.
/// See https://docs.microsoft.com/en-us/cpp/build/x64-calling-convention?view=vs-2019
#define DET_ARGS_DEFAULT_WIN64    {.Argc = DET_ARGS_MAX, .Argv = {NDR_RCX, NDR_RDX, NDR_R8, NDR_R9, \
                                    DET_ARG_STACK(5), DET_ARG_STACK(6), DET_ARG_STACK(7), DET_ARG_STACK(8)}}

/// @brief      Default argument passing convention for 32-bit Windows guests.
///
/// This follows cdecl calling convention. See https://docs.microsoft.com/en-us/cpp/cpp/cdecl?view=vs-2019
#define DET_ARGS_DEFAULT_WIN86    {.Argc = DET_ARGS_MAX, \
                                    .Argv = {DET_ARG_STACK(1), DET_ARG_STACK(2), DET_ARG_STACK(3), DET_ARG_STACK(4),\
                                    DET_ARG_STACK(5), DET_ARG_STACK(6), DET_ARG_STACK(7), DET_ARG_STACK(8)}}

///
/// @brief      Describes the arguments passed by a in-guest detour handler to introcore.
///
/// These definitions help describe argument passing between the handler injected by introcore inside the guest
/// and the detour handler invoked inside introcore. These can match the way the guest passes the arguments, but the
/// handler inside the guest can change this order and can also obtain additional information, so these do not
/// describe any in-guest calling convention.
/// Arguments can be passed either in the guest general purpose registers, or on the stack. The argument is always
/// encoded in a 32-bit integer.
/// In the case in which arguments are passed through the guest GPRs, the argument is encoded as the index of the
/// register which holds it. The index respects the order defined by Intel docs and can be seen in the #IG_ARCH_REGS
/// structure.
/// For arguments passed on the stack, the lower word of the index is set to 0xFFFF and the upper word is the index
/// on the stack. In other words, the first parameter is encoded as 0x1FFFF, the second parameter is encoded as
/// 0x2FFFF and so on. This closely follows the way parameters are passed on the stack, stack[0] being the return
/// address, stack[1] the first parameter and so on.
/// We pass only integers or guest pointers.
///
typedef struct _DETOUR_ARGS
{
    DWORD Argc;                 ///< The number of valid entries inside the Argv array.
    DWORD Argv[DET_ARGS_MAX];   ///< Argument encoding. See #DET_ARG_REGS and #DET_ARG_ON_STACK.
} DETOUR_ARGS;

///
/// @brief  Unique tag used to identify a detour.
///
/// See #gLixHookHandlersx64, #gHookableApisX86, or #gHookableApisX64.
///
typedef enum
{
    detTagUnknown = 0,
    detTagPoolAlloc,
    detTagPoolFree,
    detTagModuleLoad,
    detTagModuleUnload,
    detTagProcCreate,
    detTagProcTerminate,
    detTagProcInject,
    detTagProcPtrace,
    detTagProcPtraceCompat,
    detTagProcVmRw,
    detTagEarlyProt,
    detTagBugcheck,
    detTagBugcheck2,
    detTagSyscallHook,
    detTagProcCopy,
    detTagException,
    detTagVadInsert,
    detTagVadInsertPriv,
    detTagVadInsertMap,
    detTagVmProtect,
    detTagVaDelete,
    detTagFinishVadDeletion,
    detTagVadDelete,
    detTagVadDeletePartial,
    detTagUnmapSection,
    detTagVadAdjust,
    detTagVadExpandDown,
    detTagPowerState,
    detTagProcThrHijack,
    detTagProcThrHijackWow64,
    detTagTextPoke,
    detTagTextPoke2,
    detTagProcQueueApc,
    detTagCommitCreds,
    detTagProbeKernelWrite,
    detTagSwapgs,
    detTagAccessRemoteVm,
    detTagSetProcInformation,

    detTagRtlVirtualUnwind1,
    detTagRtlVirtualUnwind2,
    detTagRtlVirtualUnwind3,
    detTagRtlVirtualUnwind4,
    detTagRtlVirtualUnwind5,
    detTagRtlVirtualUnwind6,
    detTagRtlVirtualUnwind7,
    detTagRtlVirtualUnwind8,
    detTagRtlVirtualUnwindMax,

    detTagCleanupMemDump,
    detTagVadCommit,
    detTagKernelRead,

    detTagProcSwapIn,
    detTagProcSwapOut,

    detTagMax   ///< Must always be the last one.
} DETOUR_TAG;

///
/// @brief      The type of the hypercall used by a detour.
///
typedef enum
{
    /// @brief  No hypercall. This detour does not generate events.
    hypercallTypeNone = 0,
    /// @brief  The detour will use a INT3 instruction in order to notify introcore about an event.
    hypercallTypeInt3,
    /// @brief  The detour will use a VMCALL instruction in order to notify introcore about an event.
    hypercallTypeVmcall
} HYPERCALL_TYPE;

#define DETOUR_MAX_HANDLER_SIZE     512 ///< The maximum size of a in-guest detour handler.
#define DETOUR_MAX_HANDLERS         8   ///< The maximum number of handlers a detour can have.

///
/// @brief      The type of a detour callback.
///
/// This is the type of the function that will be invoked when a detour handler issues a hypercall.
///
/// @param[in]  Detour  The detour handle. This is an opaque value for the handler; it can be used by other detour APIs.
///
/// @retval     #INT_STATUS_DISABLE_DETOUR_ON_RET if the detour should be disabled after the callback returns.
/// @retval     #INT_STATUS_REMOVE_DETOUR_AND_SET_RIP if the detour should be removed from the guest. This will set
///             the guest RIP back to the start of the hooked code region in order to let the guest properly execute
///             the code. This does not work if the hypercall type is not #hypercallTypeInt3.
/// @retval     #INT_STATUS_SUCCESS in case of success. While all status values beside #INT_STATUS_DISABLE_DETOUR_ON_RET
///             and #INT_STATUS_REMOVE_DETOUR_AND_SET_RIP are ignored, it is good practice to actually return a
///             success status value in no error was encountered.
///
typedef INTSTATUS (*PFUNC_DetourCallback)(
    _In_ void *Detour
    );

///
/// @brief  The type of a callback invoked before setting a detour.
///
/// This is an optional callback. If one exists, it will be invoked before any modifications are done to the guest
/// code.
///
/// @param[in]  FunctionAddress     The guest virtual address of the hooked function.
/// @param[in]  Handler             Optional pointer to a #API_HOOK_HANDLER structure.
/// @param[in]  Descriptor          Pointer to a structure that describes the hook and the detour handler.
///
/// @retval     #INT_STATUS_SUCCESS in case of success
/// @retval     #INT_STATUS_NOT_NEEDED_HINT if the detour should not be set anymore. This will make the detour
///             mechanism skip the hook and free any resources acquired so far for this detour. Returning an error
///             status has the same effect, but should be avoided if no actual error was encountered, as the error
///             will fail introcore initialization if the detour is marked as being critical.
///
typedef INTSTATUS (*PFUNC_PreDetourCallback)(
    _In_ QWORD FunctionAddress,
    _In_ void *Handler,
    _In_ void *Descriptor
    );

///
/// @brief  The type of a callback invoked after a detour is set.
///
/// This is an optional callback. If one exists, it will be invoked as the last step of the detour setting process,
/// after everything has been written inside the guest memory.
///
/// @param[in]  Handler     Pointer to a #API_HOOK_HANDLER structure.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value; if an error is returned,
///             it will be logged but no special action will be taken. More importantly, the detour will not be
///             disabled or removed if an error is returned.
///
typedef INTSTATUS (*PFUNC_PostDetourCallback)(
    _In_ void *Handler
    );

/// The maximum size of the PublicDataName field inside the #API_HOOK_PUBLIC_DATA structure.
#define PUBLIC_DATA_MAX_NAME_SIZE       16
/// The maximum number of entries in the PublicDataOffsets array inside the #API_HOOK_HANDLER structure.
#define PUBLIC_DATA_MAX_DESCRIPTORS     5

///
/// @brief  Public data which allows for external modification to a in-guest hook handler.
///
/// This allows for changes to be made only to certain parts of the detour handler, delimited by the PublicDataOffset
/// and PublicDataSize fields.
typedef struct _API_HOOK_PUBLIC_DATA
{
    /// Name used to identify the data.
    CHAR PublicDataName[PUBLIC_DATA_MAX_NAME_SIZE];
    /// The offset at which the data is available inside the detour handler.
    BYTE PublicDataOffset;
    /// The size of the data.
    BYTE PublicDataSize;
} API_HOOK_PUBLIC_DATA, *PAPI_HOOK_PUBLIC_DATA;

// Handler code. If the NtBuildNumber is zero, the handler can be used for Windows guests with any NtBuildNumber.
// If the NtBuildNumber is NOT zero, the handler can be used only for Windows guests that have the exact same
// NtBuildNumber. For this reason, the generic handler must be placed the last one: we could have a special handler
// for Windows with NtBuildNumber 10000 for example, and a generic handler that works for all other Windows
// guests.

///
/// @brief  Described a detour handler.
///
typedef struct _API_HOOK_HANDLER
{
    /// @brief  The minimum version of the OS for which this handler works.
    ///
    /// If the OS is older than this, the handler is ignored.
    DWORD                   MinVersion;
    /// @brief  The maximum version of the OS for which this handler works.
    ///
    /// If the OS is newer than this, the handler is ignored.
    DWORD                   MaxVersion;
    /// @brief  The size of the handler. Must not be larger than #DETOUR_MAX_HANDLER_SIZE.
    DWORD                   CodeLength;
    /// @brief  The type of hypercall used.
    HYPERCALL_TYPE          HypercallType;
    /// @brief  The code of the detour handler. Only #CodeLength bytes are valid.
    BYTE                    Code[DETOUR_MAX_HANDLER_SIZE];
    /// @brief  The offset inside the handler at which the hypercall instruction is placed.
    ///
    /// A detour can have only one hypercall. This is used to identify the detour and to invoke to proper introcore
    /// handler when a hypercall is issued.
    BYTE                    HypercallOffset;
    /// @brief  The offset inside the handler at which the original instructions were relocated.
    BYTE                    RelocatedCodeOffset;
    /// @brief  Optional public data used to allow external changes to the detour handler.
    API_HOOK_PUBLIC_DATA    PublicDataOffsets[PUBLIC_DATA_MAX_DESCRIPTORS];
    /// @brief  The number of valid entries inside the PublicDataOffsets array.
    BYTE                    NrPublicDataOffsets;
} API_HOOK_HANDLER, *PAPI_HOOK_HANDLER;

/// @brief  Specifies that the first OS version for which a detour handler is available is the first OS version
/// supported by introcore.
#define DETOUR_MIN_VERSION_ANY          0
/// @brief  Specifies that the first OS version for which a detour handler is available is the latest OS version
/// supported by introcore.
#define DETOUR_MAX_VERSION_ANY          0xFFFFFFFF

/// @brief  Used to specify that no hypercall is present in the detour handler so the HypercallOffset field inside
/// the #API_HOOK_HANDLER is not valid.
#define DETOUR_INVALID_HYPERCALL        0xFF

typedef struct _WIN_UNEXPORTED_FUNCTION WIN_UNEXPORTED_FUNCTION;

///
/// @brief  Describes a function to be hooked.
///
/// This is used by #IntDetSetHook and #IntDetSetLixHook to know what to hook and how to find the hooked region.
typedef struct _API_HOOK_DESCRIPTOR
{
    /// @brief  NULL-terminated string of the kernel module in which the function is found.
    PWCHAR                      ModuleName;
    /// @brief  NULL-terminated string of the function name.
    ///
    /// This is used to match against function information inside a CAMI file. If Exported is True, the name is
    /// also used to find the function inside the kernel module that owns it.
    PCHAR                       FunctionName;
    /// @brief  The minimum OS version for which this hook should be applied.
    ///
    /// #DETOUR_MIN_VERSION_ANY can be used if there is no lower limit.
    DWORD                       MinVersion;
    /// @brief  The maximum OS version for which this hook should be applied.
    ///
    /// #DETOUR_MAX_VERSION_ANY can be used if there is no lower limit.
    DWORD                       MaxVersion;
    /// @brief  Callback to be invoked when the detour issues a hypercall. May be NULL.
    PFUNC_DetourCallback        Callback;
    /// @brief  Callback to be invoked before the detour is written inside the guest. May be NULL.
    PFUNC_PreDetourCallback     PreCallback;
    /// @brief  Callback to be invoked after the detour has been set. May be NULL.
    PFUNC_PostDetourCallback    PostCallback;

    /// @brief  Detour tag.
    DETOUR_TAG                  Tag;
    /// @brief  True if this function is exported by the module that owns it.
    ///
    /// If False, the function address is found by using a code pattern.
    BOOLEAN                     Exported;
    /// @brief  If True, this hook is not critical.
    ///
    /// Failure to set a critical hook is treated as a fatal initialization error and stops introcore.
    BOOLEAN                     NotCritical;
    /// @brief  Core activation and protection flags that will cause introcore to skip this hook.
    ///
    /// These are checked against the current options from #gGuest. If options are changed and the new options
    /// contain any of these bits, the hook is disabled.
    QWORD                       DisableFlags;
    /// @brief  Core activation and protection flags that must be set in order to set and activate this hook.
    ///
    /// These are checked against the current options from #gGuest. At least one must be set.
    /// If options are changed and the new options do not contain any of these bits, the hook is disabled.
    /// #DETOUR_ENABLE_ALWAYS can be used to always enable this hook.
    QWORD                       EnableFlags;
    /// @brief  Array of code patterns used to find this function.
    ///
    /// If Exported is True this field is ignored. If Exported is False this field must be valid.
    WIN_UNEXPORTED_FUNCTION     *Patterns;
    /// @brief  Encoding of the arguments needed by introcore from the hooked function.
    DETOUR_ARGS                 Arguments;
    /// @brief  The number of valid entries inside the Handlers array.
    DWORD                       HandlersCount;
    /// @brief  Handlers that can be set for this function.
    ///
    /// The first entry in the array that matches the restrictions for this hook is used. Because of this, the order
    /// in which handlers should be set in this array is from the most to least restrictive. For example, if a function
    /// has to handlers: one available for Windows 9200 only, and another one available for all the other versions,
    /// the one for 9200 must be the first in the array.
    API_HOOK_HANDLER            Handlers[DETOUR_MAX_HANDLERS];
} API_HOOK_DESCRIPTOR, *PAPI_HOOK_DESCRIPTOR;


///
/// @brief      The type of a linux-detour callback.
///
/// This is the type of the function that will be invoked when a detour handler issues a hypercall.
///
/// @param[in]  Detour  The detour handle. This is an opaque value for the handler; it can be used by other detour APIs.
///
/// @retval     #INT_STATUS_DISABLE_DETOUR_ON_RET if the detour should be disabled after the callback returns.
/// @retval     #INT_STATUS_REMOVE_DETOUR_AND_SET_RIP if the detour should be removed from the guest. This will set
///             the guest RIP back to the start of the hooked code region in order to let the guest properly execute
///             the code. This does not work if the hypercall type is not #hypercallTypeInt3.
/// @retval     #INT_STATUS_SUCCESS in case of success. While all status values beside #INT_STATUS_DISABLE_DETOUR_ON_RET
///             and #INT_STATUS_REMOVE_DETOUR_AND_SET_RIP are ignored, it is good practice to actually return a
///             success status value in no error was encountered.
///
typedef INTSTATUS
(*PFUNC_LixDetourCallback)(
    _In_ void *Detour
    );


///
/// @brief  Describes a Linux-function to be hooked.
///
typedef struct _LIX_FN_DETOUR
{
    DETOUR_ID                   Id;                     ///< The #DETOUR_ID of the linux detour descriptor.
    char                        *FunctionName;          ///< The name of the function to be hooked.
    /// @brief  The name of the function from the FunctionName to be hooked.
    char                        *HijackFunctionName;
    PFUNC_LixDetourCallback     Callback;               ///< Callback to be invoked when the detour issues a hypercall.
    QWORD                       EnableFlags;            ///< These are checked against the current options from #gGuest.
} LIX_FN_DETOUR;



/// @brief  Can be used as the #API_HOOK_DESCRIPTOR.EnableFlags to always enable the detour.
#define DETOUR_ENABLE_ALWAYS    0xFFFFFFFFFFFFFFFF

///
/// @brief  Describes a detour set inside the guest memory.
///
/// This is created by #IntDetSetHook and #IntDetSetLixHook in order to hold information about a detour that has
/// been set. Part of the information in this structure comes from the #API_HOOK_DESCRIPTOR used for this hook.
typedef struct _DETOUR
{
    /// @brief  The link inside the #DETOURS_STATE.DetoursList list.
    LIST_ENTRY              Link;
    /// @brief  Callback to be invoked when the detour issues a hypercall. May be NULL.
    PFUNC_DetourCallback    Callback;

    /// @brief  Detour tag.
    DETOUR_TAG              Tag;

    /// @brief  The guest virtual address at which the hypercall is placed.
    ///
    /// This is used to find the proper #DETOUR structure when a hypercall is issued.
    QWORD                   HypercallAddress;
    /// @brief  The guest virtual address of the hooked function.
    QWORD                   FunctionAddress;

    /// @brief  The guest virtual address of the detour handler.
    QWORD                   HandlerAddress;
    /// @brief  The size of the detour handler.
    ///
    /// Note that this is not the same as the #API_HOOK_HANDLER.CodeLength, as that represents only the code
    /// injected for the handler itself, but this also takes into account the size of the reallocated guest
    /// instructions.
    DWORD                   HandlerSize;

    /// @brief The address of the linux-detour header
    QWORD                   LixGuestDetour;

    /// @brief  The type of the hypercall that this detour uses.
    HYPERCALL_TYPE          HypercallType;

    /// @brief  Offset, relative to HandlerAddress, where the jump that returns control to the hooked function is
    /// found.
    BYTE                    JumpBackOffset;
    /// @brief  Offset, relative to HandlerAddress, where the hypercall instruction is found.
    BYTE                    HypercallOffset;
    /// @brief  Offset, relative to HandlerAddress, where the prologue that has been replaced by our jump at the
    /// beginning of the function has been relocated.
    BYTE                    RelocatedCodeOffset;
    /// @brief  The size of the relocated code.
    BYTE                    RelocatedCodeLength;

    /// @brief  The number of valid entries inside the PublicDataOffsets array.
    BYTE                    NrPublicDataOffsets;
    /// @brief  Public data that can be used to modify the detour handler.
    API_HOOK_PUBLIC_DATA    PublicDataOffsets[PUBLIC_DATA_MAX_DESCRIPTORS];

    /// @brief  True if this detour has been disabled.
    ///
    /// Disabled detours are still present inside the guest, but they no longer issue hypercalls.
    ///
    /// The hypercall instruction is replaced with NOPs, but the rest of the detour code is untouched.
    BOOLEAN                 Disabled;
    /// @brief  The guest virtual address of the base of the kernel module that owns the hooked function.
    QWORD                   ModuleBase;

    /// @brief  The memory cloak handle used to hide the modified function start. See @ref group_memclk.
    void                    *FunctionCloakHandle;
    /// @brief  The memory cloak handle used to hide the detour handler. See @ref group_memclk.
    void                    *HandlerCloakHandle;
    /// @brief  The number of times this detour issued a hypercall.
    QWORD                   HitCount;

    /// @brief  The hook descriptor for which this hook was set.
    PAPI_HOOK_DESCRIPTOR    Descriptor;
    const LIX_FN_DETOUR     *LixFnDetour;
} DETOUR, *PDETOUR;


INTSTATUS
IntDetSetHook(
    _In_ QWORD FunctionAddress,
    _In_ QWORD ModuleBase,
    _Inout_ API_HOOK_DESCRIPTOR *Descriptor,
    _Inout_ API_HOOK_HANDLER *Handler
    );

INTSTATUS
IntDetSetLixHook(
    _In_ QWORD FunctionAddress,
    _In_ const LIX_FN_DETOUR *FnDetour,
    _Out_ BOOLEAN *MultipleInstructions
    );

INTSTATUS
IntDetSetReturnValue(
    _In_ DETOUR const *Detour,
    _Inout_opt_ IG_ARCH_REGS *Registers,
    _In_ QWORD ReturnValue
    );

INTSTATUS
IntDetCallCallback(
    void
    );

INTSTATUS
IntDetEnableDetour(
    _In_ DETOUR_TAG Tag
    );

INTSTATUS
IntDetDisableDetour(
    _In_ DETOUR_TAG Tag
    );

void
IntDetDisableAllHooks(
    void
    );

void
IntDetUninit(
    void
    );

void
IntDetDumpDetours(
    void
    );

BOOLEAN
IntDetIsPtrInHandler(
    _In_ QWORD Ptr,
    _In_ THS_PTR_TYPE Type,
    _Out_opt_ DETOUR_TAG *Tag
    );

BOOLEAN
IntDetIsPtrInRelocatedCode(
    _In_ QWORD Ptr,
    _Out_opt_ DETOUR_TAG *Tag
    );

QWORD
IntDetRelocatePtrIfNeeded(
    _In_ QWORD Ptr
    );

INTSTATUS
IntDetGetAddrAndTag(
    _In_ QWORD Ptr,
    _Out_ QWORD *Address,
    _Out_ DWORD *Size,
    _Out_ DETOUR_TAG *Tag
    );

INTSTATUS
IntDetGetByTag(
    _In_ DETOUR_TAG Tag,
    _Out_ QWORD *Address,
    _Out_opt_ DWORD *Size
    );

INTSTATUS
IntDetGetArgument(
    _In_ void const *Detour,
    _In_ DWORD Index,
    _In_opt_ BYTE const *StackBuffer,
    _In_ DWORD StackBufferSize,
    _Out_ QWORD *Value
    );

INTSTATUS
IntDetGetArguments(
    _In_ void const *Detour,
    _In_ DWORD Argc,
    _Out_writes_(Argc) QWORD *Argv
    );

INTSTATUS
IntDetPatchArgument(
    _In_ void const *Detour,
    _In_ DWORD Index,
    _In_ QWORD Value
    );

INTSTATUS
IntDetModifyPublicData(
    _In_ DETOUR_TAG Tag,
    _In_ void const *Data,
    _In_ DWORD DataSize,
    _In_ char const *PublicDataName
    );

INTSTATUS
IntDetGetFunctionAddressByTag(
    _In_ DETOUR_TAG Tag,
    _Out_ QWORD *FunctionAddress
    );

#endif // _DETOURS_H_
