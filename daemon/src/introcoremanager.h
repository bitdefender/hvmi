/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef __INTROCOREMANAGER_H_INCLUDED__
#define __INTROCOREMANAGER_H_INCLUDED__

#include <algorithm>
#include <atomic>
#include "hvmisettings.h"
#include "hvmitooltask.h"
#include <bdvmi/driver.h>
#include <condition_variable>
#include <fstream>
#include <future>
#include <introcore.h>
#include <unordered_map>
#include <memory>
#include <mutex>
#include <set>
#include <stdint.h>
#include <thread>
#include "threadhelper.h"
#include <time.h>
#include <utility>

#define UUID_LENGTH 36

namespace bdvmi {

// Forward declarations
struct Registers;
class EventManager;
}

class HvmiSettings;

class IntrocoreManager {

	struct EventInfo {

		INTRO_EVENT_TYPE eventType;
		PrimaryAction    actionTaken;
		std::string      processUUID;
		std::string      eventUUID{ "00000000-0000-0000-0000-000000000000" };

		union {
			EVENT_EPT_VIOLATION               eptViolation;
			EVENT_MSR_VIOLATION               msrViolation;
			EVENT_CR_VIOLATION                crViolation;
			EVENT_XCR_VIOLATION               xcrViolation;
			EVENT_MEMCOPY_VIOLATION           memCopyViolation;
			EVENT_TRANSLATION_VIOLATION       translationViolation;
			EVENT_INTEGRITY_VIOLATION         integrityViolation;
			EVENT_DTR_VIOLATION               dtrViolation;
			EVENT_INTROSPECTION_MESSAGE       introspectionMessage;
			EVENT_PROCESS_EVENT               processEvent;
			EVENT_AGENT_EVENT                 agentAction;
			EVENT_PROCESS_CREATION_VIOLATION  processCreationViolation;
			EVENT_MODULE_LOAD_VIOLATION       moduleLoadViolation;
			EVENT_ENGINES_DETECTION_VIOLATION enginesDetectionViolation;
		} event;
	};

public:
	enum PostEventAction {
		POST_EVENT_ACTION_NONE,
		POST_EVENT_ACTION_SET_PROTECTED_PROCESSES,
		POST_EVENT_ACTION_INJECT_AGENT_KILLER,
	};

public:
	IntrocoreManager( bdvmi::Driver &driver, bdvmi::EventManager &eventManager, const std::string &domainName,
	                  HvmiSettings &settings );

	~IntrocoreManager();

	IntrocoreManager( const IntrocoreManager & ) = delete;
	IntrocoreManager &operator=( const IntrocoreManager & ) = delete;

public:
	bool newGuestNotification();

	unsigned short currentInstructionLength( unsigned short vcpu );

	void notifySessionOver( bdvmi::GuestState guestState );

	bool isLastEventInUserspace() const
	{
		return isLastEventInUserspace_;
	}

	uint64_t lastEventProcessId() const
	{
		return lastEventProcessId_;
	}

	bool isGuestWindows() const
	{
		return guestType_ == introGuestWindows;
	}

	PostEventAction postEventAction();

	const std::string &remToolParams() const
	{
		return remToolParams_;
	}

	INTSTATUS updateExceptions();

	void updateUserExclusions();

	INTSTATUS updateProtections();

	INTSTATUS updateLiveUpdate();

	INTSTATUS updateIntrocoreOptions( const HvmiSettings &settings );

	INTSTATUS CRWrite( DWORD CpuNumber, DWORD Cr, QWORD OldValue, QWORD NewValue, const bdvmi::Registers &regs,
	                   INTRO_ACTION *Action );

	INTSTATUS EPTViolation( QWORD PhysicalAddress, QWORD VirtualAddress, DWORD CpuNumber, INTRO_ACTION *Action,
	                        BYTE Type, const bdvmi::Registers &regs, bdvmi::EmulatorContext &emulatorCtx );

	INTSTATUS MSRViolation( DWORD Msr, IG_MSR_HOOK_TYPE Flags, INTRO_ACTION *Action, QWORD OriginalValue,
	                        QWORD *NewValue, DWORD CpuNumber );

	INTSTATUS VMCALL( DWORD CpuNumber, const bdvmi::Registers &regs );

	INTSTATUS XSETBV( DWORD CpuNumber, INTRO_ACTION *Action );

	INTSTATUS breakpoint( DWORD CpuNumber, const bdvmi::Registers &regs, QWORD Gpa );

	INTSTATUS injection( DWORD Vector, QWORD ErrorCode, QWORD Cr2, DWORD CpuNumber, const bdvmi::Registers &regs );

	INTSTATUS descriptorAccess( DWORD CpuNumber, const bdvmi::Registers &regs, DWORD Flags, INTRO_ACTION *Action );

	void generateSessionId();

	bool injectAgent( const Tool &agent );

	bool injectLogCollector( const Tool &tool, bool getStdout = false );

	void setAbortStatus( bool enable );

	bool agentMatchesOS( const Tool &agent );

	void waitForAgent( int timeout = 0 );

	bool violationAgentsPending() const
	{
		return violationAgentsPending_;
	}

	void violationAgentsPending( bool state )
	{
		violationAgentsPending_ = state;
	}

	bool remediationToolPending() const
	{
		return remediationToolPending_;
	}

	void remediationToolPending( bool state )
	{
		remediationToolPending_ = state;
	}

	void signalAgentFinished();

	std::string sessionId() const
	{
		return sessionId_;
	}

	void setTaskAgent( const Tool &t );
	void resetTaskAgent();

	long toolError() const
	{
		return toolError_;
	}

	std::string logsDirTimestamp() const;

	bool availableLogDiskSpace() const
	{
		return availableLogDiskSpace_;
	}

	bool OSDetected() const
	{
		return guestOSDetected_;
	}

	bool injectAgentKiller();

	void getStartupTime();

	void sendGuestHookEvent();

private: // GLUE_IFACE callbacks
	static INTSTATUS IntOpenGuest( PCHAR GuestName, DWORD Flags, void *OpenParam, void **GuestHandle );

	static INTSTATUS IntCloseGuestHandle( void **GuestHandle );

	static INTSTATUS IntQueryGuestInfo( void *GuestHandle, DWORD InfoClass, void *InfoParam, void *Buffer,
	                                    DWORD BufferLength );

	static INTSTATUS IntGpaToHpa( void *GuestHandle, QWORD Gpa, QWORD *Hpa );

	static INTSTATUS IntPhysMemMapToHost( void *GuestHandle, QWORD PhysAddress, DWORD Length, DWORD Flags,
	                                      void **HostPtr );

	static INTSTATUS IntPhysMemUnmap( void *GuestHandle, void **HostPtr );

	static INTSTATUS IntGetPhysicalPageTypeFromMtrrs( void *GuestHandle, QWORD Gpa, IG_MEMTYPE *MemType );

	static INTSTATUS IntRegisterCrWriteHandler( void *GuestHandle, PFUNC_IntCrWriteCallback Callback );

	static INTSTATUS IntUnregisterCrWriteHandler( void *GuestHandle );

	static INTSTATUS IntRegisterBreakpointHandler( void *GuestHandle, PFUNC_IntBreakpointCallback Callback );

	static INTSTATUS IntUnregisterBreakpointHandler( void *GuestHandle );

	static INTSTATUS IntEnableCrWriteExit( void *GuestHandle, DWORD Cr );

	static INTSTATUS IntDisableCrWriteExit( void *GuestHandle, DWORD Cr );

	static INTSTATUS IntGetEPTPageProtection( void *GuestHandle, DWORD EptIndex, QWORD Address, BYTE *Read,
	                                          BYTE *Write, BYTE *Execute );

	static INTSTATUS IntSetEPTPageProtection( void *GuestHandle, DWORD EptIndex, QWORD Address, BYTE Read,
	                                          BYTE Write, BYTE Execute );

	static INTSTATUS IntRegisterEPTHandler( void *GuestHandle, PFUNC_IntEPTViolationCallback Callback );

	static INTSTATUS IntUnregisterEPTHandler( void *GuestHandle );

	// #VE callbacks
	static INTSTATUS IntSetVeInfoPage( void *GuestHandle, DWORD CpuNumber, QWORD VeInfoGpa );

	static INTSTATUS IntCreateEPT( void *GuestHandle, DWORD *EptIndex );

	static INTSTATUS IntDestroyEPT( void *GuestHandle, DWORD EptIndex );

	static INTSTATUS IntSwitchEPT( void *GuestHandle, DWORD NewEptIndex );

	static INTSTATUS IntGetEPTPageConvertible( void *GuestHandle, DWORD EptIndex, QWORD Address,
	                                           BOOLEAN *Convertible );

	static INTSTATUS IntSetEPTPageConvertible( void *GuestHandle, DWORD EptIndex, QWORD Address,
	                                           BOOLEAN Convertible );

	static INTSTATUS IntEnableMsrExit( void *GuestHandle, DWORD Msr, BOOLEAN *OldValue );

	static INTSTATUS IntDisableMsrExit( void *GuestHandle, DWORD Msr, BOOLEAN *OldValue );

	static INTSTATUS IntRegisterMSRHandler( void *GuestHandle, PFUNC_IntMSRViolationCallback Callback );

	static INTSTATUS IntUnregisterMSRHandler( void *GuestHandle );

	static INTSTATUS SpinLockInit( void **SpinLock, PCHAR Name );

	static INTSTATUS SpinLockUnInit( void **SpinLock );

	static INTSTATUS SpinLockAcquire( void *SpinLock );

	static INTSTATUS SpinLockRelease( void *SpinLock );

	static INTSTATUS RwSpinLockInit( void **SpinLock, PCHAR Name );

	static INTSTATUS RwSpinLockUnInit( void **SpinLock );

	static INTSTATUS RwSpinLockAcquireShared( void *SpinLock );

	static INTSTATUS RwSpinLockAcquireExclusive( void *SpinLock );

	static INTSTATUS RwSpinLockReleaseShared( void *SpinLock );

	static INTSTATUS RwSpinLockReleaseExclusive( void *SpinLock );

	static INTSTATUS IntRegisterIntroCallHandler( void *GuestHandle, PFUNC_IntIntroCallCallback Callback );

	static INTSTATUS IntUnregisterIntroCallHandler( void *GuestHandle );

	static INTSTATUS IntRegisterVmxTimerHandler( void *GuestHandle, PFUNC_IntIntroTimerCallback Callback );

	static INTSTATUS IntUnregisterVmxTimerHandler( void *GuestHandle );

	static INTSTATUS IntRegisterXcrWriteHandler( void *GuestHandle, PFUNC_IntXcrWriteCallback Callback );

	static INTSTATUS IntUnregisterXcrWriteHandler( void *GuestHandle );

	static void BugCheck();

	static INTSTATUS ReserveVaSpaceWithPt( void *GuestHandle, void **FirstPageBase, DWORD *PagesCount,
	                                       void **PtBase );

	static void IntEnterDebugger();

	static INTSTATUS InjectTrap( void *GuestHandle, DWORD CpuNumber, BYTE TrapNumber, DWORD ErrorCode, QWORD Cr2 );

	static INTSTATUS NotifyIntrospectionActivated( void *GuestHandle );

	static INTSTATUS NotifyIntrospectionDetectedOs( void *GuestHandle, PGUEST_INFO GuestInfo );

	static INTSTATUS RequestVcpusPause( void *GuestHandle );

	static INTSTATUS RequestVcpusResume( void *GuestHandle );

	static INTSTATUS RegisterDescriptorTableHandler( void *                                GuestHandle,
	                                                 PFUNC_IntIntroDescriptorTableCallback Callback );

	static INTSTATUS UnregisterDescriptorTableHandler( void *GuestHandle );

	static INTSTATUS SetIntroEmulatorContext( void *GuestHandle, DWORD CpuNumber, QWORD VirtualAddress,
	                                          DWORD BufferSize, PBYTE Buffer );

	static INTSTATUS GetAgentContent( void *GuestHandle, DWORD AgentTag, BOOLEAN Is64, DWORD *Size,
	                                  PBYTE *Content );

	static INTSTATUS ToggleRepOptimization( void *GuestHandle, BOOLEAN Enable );

	static INTSTATUS NotifyIntrospectionDeactivated( void *GuestHandle );

	static INTSTATUS RegisterEventInjectionHandler( void *GuestHandle, PFUNC_IntEventInjectionCallback Callback );

	static INTSTATUS UnregisterEventInjectionHandler( void *GuestHandle );

	static INTSTATUS NotifyIntrospectionErrorState( void *GuestHandle, INTRO_ERROR_STATE Error,
	                                                PINTRO_ERROR_CONTEXT Context );

	static INTSTATUS ReleaseBuffer( void *GuestHandle, void *AgentContent, DWORD AgentSize );

	static INTSTATUS NotifyScanEngines( void *GuestHandle, void *Parameters );

	static INTSTATUS RegisterEnginesResultCallback( void *                              GuestHandle,
	                                                PFUNC_IntEventEnginesResultCallback Callback );
	static INTSTATUS UnregisterEnginesResultCalback( void *GuestHandle );

private: // UPPER_IFACE callbacks
	static INTSTATUS IntIntroEventNotify( void *GuestHandle, DWORD EventClass, void *Parameters, SIZE_T EventSize );

	static INTSTATUS IntIntroRequestAction( void *GuestHandle, DWORD ActionClass, void *Parameters );

	static INTSTATUS IntTracePrint( const CHAR *File, DWORD Line, const CHAR *Format, ... );

	static INTSTATUS MemAllocWithTagAndInfo( void **Address, size_t Size, DWORD Tag );

	static INTSTATUS MemFreeWithTagAndInfo( void **Address, DWORD Tag );

	static INTSTATUS QueryHeapSize( SIZE_T *TotalHeapSize, SIZE_T *FreeHeapSize );

private:
	bool disableIntrocore();

	void introTimerCallback();

	bool startTimer();

	void runIntroCommand( const std::string &command );

	void saveLastEvent( INTRO_EVENT_TYPE eventType, void *event, const std::string &eventUUID );

	void collectEvents();

	INTSTATUS addRemProtectedProcessByOS( const std::string &process, DWORD ProtectionMask, BOOLEAN Add, QWORD id );

	std::string generateAgentName() const;

	std::string launcherNameByOS() const;

	std::string generateEventUUID( INTRO_EVENT_TYPE eventType ) const;

	void processLogAgentEvent( const PEVENT_AGENT_EVENT info );

	void processAgentKillerEvent( const PEVENT_AGENT_EVENT info );

	void processCustomAgentEvent( const PEVENT_AGENT_EVENT info );

	bool mapLiveUpdateFile( const std::string &filename, PBYTE &bytes, DWORD &size );

	bool mapFile( const std::string &filename, PBYTE &bytes, DWORD &size ) const;

	std::string stdoutFile() const;

	void processVerdict( const void *info, HvmiEventHandler::Action &action, PrimaryAction &actionTaken );

	bool taskAgent( Tool &agent );

	void reportOnTask( unsigned status, long errorCode = 0 );

	void toolError( long error )
	{
		if ( error )
			toolError_ = error;
	}

	bool generateToolLogDir( const Tool &tool );

	bool loadExceptions( const std::string &file );

	void debugCommandsCallback();

	bool injectAgent( const std::string &exeFile, const std::string &exeName, DWORD agentTag,
	                  const std::string &args, const std::string &archiveFile = "",
	                  const std::string &archiveName = "" );

	// Does _NOT_ take a lock!
	void cacheRegs( unsigned short vcpu, const bdvmi::Registers &regs );

	// Does _NOT_ take a lock!
	bool regsCached( unsigned short vcpu ) const
	{
		return vcpuRegsCache_.size() > vcpu && vcpuRegsCache_[vcpu].first;
	}

	// Does _NOT_ take a lock!
	void clearRegsCache( unsigned short vcpu )
	{
		if ( vcpuRegsCache_.size() > vcpu )
			vcpuRegsCache_[vcpu].first = false;
	}

	// This is used by a scan engine to indicate that a scan request has completed
	static void engineScanComplete( void *ctx, void *param, const char *detection, const char *enginesVersion );

private:
	GLUE_IFACE           iface_{};
	UPPER_IFACE          uface_{};
	std::string          domainName_;
	std::string          domainUuid_;
	bdvmi::Driver &      driver_;
	bdvmi::EventManager &eventManager_;

	std::atomic<PFUNC_IntCrWriteCallback>              crWriteCallback_{ nullptr };
	std::atomic<PFUNC_IntMSRViolationCallback>         msrViolationCallback_{ nullptr };
	std::atomic<PFUNC_IntEPTViolationCallback>         eptViolationCallback_{ nullptr };
	std::atomic<PFUNC_IntIntroCallCallback>            introCallCallback_{ nullptr };
	std::atomic<PFUNC_IntIntroTimerCallback>           timerCallback_{ nullptr };
	std::atomic<PFUNC_IntXcrWriteCallback>             xcrWriteCallback_{ nullptr };
	std::atomic<PFUNC_IntBreakpointCallback>           breakpointCallback_{ nullptr };
	std::atomic<PFUNC_IntEventInjectionCallback>       injectionCallback_{ nullptr };
	std::atomic<PFUNC_IntIntroDescriptorTableCallback> descriptorCallback_{ nullptr };
	std::atomic<PFUNC_IntEventEnginesResultCallback>   enginesResultCallback_{ nullptr };

	std::atomic_ushort                             currentCpu_{ 0 };
	std::atomic_uint                               cachedCpuCount_{ 0 };
	std::vector<std::pair<bool, bdvmi::Registers>> vcpuRegsCache_;
	bool                                           setEip_{ true };
	std::thread                                    timerThread_;
	std::mutex                                     cacheMutex_;
	bdvmi::EmulatorContext                         emulatorCtx_;
	HvmiSettings &                                 settings_;
	char                                           sessionId_[UUID_LENGTH + 1];
	bool                                           isLastEventInUserspace_{ false };
	uint64_t                                       lastEventProcessId_;
	INTRO_GUEST_TYPE                               guestType_{ introGuestWindows };
	DWORD                                          guestVersion_{ 0 };
	QWORD                                          guestBuildNumber_{ 0 };
	bool                                           guest64_{ false };
	QWORD                                          guestStartupTime_{ IG_INVALID_TIME };
	EventInfo                                      lastEvent_;
	bool                                           isAgentRunning_{ false };
	std::atomic_bool                               stopTimer_{ false };
	PostEventAction                                postEventAction_{ POST_EVENT_ACTION_NONE };
	std::string                                    remToolParams_;
	bool                                           introEnabled_{ false };
	time_t                                         lastStateUpdate_{ 0 };
	size_t                                         exceptionsHash_{ 0 };
	size_t                                         liveUpdateHash_{ 0 };
	std::atomic_bool                               guestOSDetected_{ false };
	bool                                           vmUninitStatusSet_{ false };
	std::atomic_bool                               violationAgentsPending_{ false };
	std::atomic_bool                               remediationToolPending_{ false };
	std::condition_variable                        cv_;
	std::mutex                                     cvMutex_;
	mutable std::mutex                             activeAgentMutex_;
	Tool                                           taskAgent_;
	bool                                           isTaskAgentActive_{ false };
	std::atomic_long                               toolError_{ 0 };
	std::string                                    logsDir_;
	std::string                                    logsDirTimestamp_;
	std::atomic_bool                               availableLogDiskSpace_{ true };
	std::string                                    agentName_;
	bool                                           killerInjected_{ false };
	bool                                           killerInitialized_{ false };
	bool                                           killerStarted_{ false };
	WORD                                           exceptionsVerMajor_{ 0 };
	WORD                                           exceptionsVerMinor_{ 0 };
	DWORD                                          exceptionsBuildNo_{ 0 };
	bool                                           disableIntroInProgress_{ false };
	std::atomic_bool                               guestNotRunning_{ false };
	uint64_t                                       introspectionOptions_{ 0 };
	ThreadHelper                                   debugCommandsThread_;
	bool                                           stopDebugCommandsThread_{ false };
	bool                                           cancellingLogExtraction_{ false };
	std::future<void>                              memoryDumpFuture_;
	std::ofstream                                  memoryDumpFile_;
	std::string                                    memoryDumpFilename_;
	std::string                                    memoryDumpDir_;
	bool                                           introActivated_{ false };
	std::string                                    introErrorState_;
	std::atomic_bool                               guestHookEventPending_{ false };

#ifdef _DEBUG
	static std::unique_ptr<std::ofstream> debugOut_;
#endif
};

#endif // __INTROCOREMANAGER_H_INCLUDED__
