/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "introcoremanager.h"
#include <algorithm>
#include "hvmitooltask.h"
#include <bdvmi/eventmanager.h>
#include <bdvmi/logger.h>
#include <bdvmi/statscollector.h>
#include <regex>
#include <chrono>
#include <codecvt>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <experimental/filesystem>
#include <fcntl.h>
#include <fstream>
#include <functional>
#include <iomanip>
#include <locale>
#include <mutex>
#include <poll.h>
#include <pthread.h>
#include <sstream>
#include <stdexcept>
#include <string>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <sys/types.h>
#include <unistd.h>
#include <vector>

#ifdef FUZZ_INTROCORE
// Should fail roughly 50% of the time
bool g_startFailing = false;
#define START_FAILING_IF_FUZZING()                                                                                     \
	{                                                                                                              \
		g_startFailing = true;                                                                                 \
	}
#define FAIL_IF_FUZZING()                                                                                              \
	{                                                                                                              \
		if ( g_startFailing && ( rand() % 2 ) )                                                                \
			return INT_STATUS_UNSUCCESSFUL;                                                                \
	}
#else
#define START_FAILING_IF_FUZZING()
#define FAIL_IF_FUZZING()
#endif

extern sig_atomic_t g_stop;
extern sig_atomic_t g_introInit;
IntrocoreManager *  g_guestHandle; // For BugCheck(), IntTracePrint(), and close signal handler

namespace {

constexpr char UNKNOWN[] = "*";

#define DOMAIN_UUID ( g_guestHandle ? g_guestHandle->domainUuid_.c_str() : UNKNOWN )

#define WORKING_CPU( x ) ( x == IG_CURRENT_VCPU ? pim->currentCpu_ : x )

/* Taken from the Google Chromium project */
#define COUNT_OF( __x )                                                                                                \
	( ( sizeof( __x ) / sizeof( 0 [__x] ) ) / ( ( size_t )( !( sizeof( __x ) % sizeof( 0 [__x] ) ) ) ) )

using cfreeFunc = void ( * )( void * );

std::string utf16ToUtf8( const WCHAR *s )
{
	static std::mutex                                                        mtx;
	static std::wstring_convert<std::codecvt_utf8_utf16<char16_t>, char16_t> conversion;
	std::string                                                              ret;

	try {
		std::lock_guard<std::mutex> lock( mtx );
		ret = conversion.to_bytes( reinterpret_cast<const char16_t *>( s ) );
	} catch ( ... ) {
	}

	return ret;
}

std::u16string utf8ToUtf16( const char *s )
{
	static std::mutex                                                        mtx;
	static std::wstring_convert<std::codecvt_utf8_utf16<char16_t>, char16_t> conversion;
	std::u16string                                                           ret;

	try {
		std::lock_guard<std::mutex> lock( mtx );
		ret = conversion.from_bytes( s );
	} catch ( ... ) {
	}

	return ret;
}

static void trim( std::string &str )
{
	constexpr char ignored[] = "\n\r\t ";

	str.erase( 0, str.find_first_not_of( ignored ) );
	str.erase( str.find_last_not_of( ignored ) + 1 );
}

class ScopeTimer { // exception-safe

public:
	explicit ScopeTimer( const std::string &message )
	    : message_{ message }
	    , start_{ std::chrono::system_clock::now() }
	{
	}

	~ScopeTimer()
	{
		std::chrono::duration<double> elapsedSeconds = std::chrono::system_clock::now() - start_;

		bdvmi::logger << bdvmi::DEBUG << message_ << " timed at " << std::dec << elapsedSeconds.count()
		              << " seconds" << std::flush;
	}

private:
	std::string                                                 message_;
	std::chrono::time_point<std::chrono::high_resolution_clock> start_;
};

std::string computeEventUUID( const INTRO_PROCESS & /* process */ )
{
	return "00000000-0000-0000-0000-000000000000";
}

std::string computeEventUUID( const INTRO_MODULE & /* module */ )
{
	return "00000000-0000-0000-0000-000000000000";
}

std::string newUUID()
{
	return "00000000-0000-0000-0000-000000000000";
}

std::string introOptionsToString( uint64_t options )
{
	std::string ret;

	if ( options & INTRO_OPT_PROT_KM_NT )
		ret += "km_nt ";

	if ( options & INTRO_OPT_PROT_KM_HAL )
		ret += "km_hal ";

	if ( options & INTRO_OPT_PROT_KM_HAL_HEAP_EXEC )
		ret += "km_hal_heap_exec ";

	if ( options & INTRO_OPT_PROT_KM_HAL_INT_CTRL )
		ret += "km_hal_int_ctrl ";

	if ( options & INTRO_OPT_PROT_KM_SSDT )
		ret += "km_ssdt ";

	if ( options & INTRO_OPT_PROT_KM_IDT )
		ret += "km_idt ";

	if ( options & INTRO_OPT_PROT_KM_HAL_DISP_TABLE )
		ret += "km_hdt ";

	if ( options & INTRO_OPT_PROT_KM_SYSTEM_CR3 )
		ret += "km_sys_cr3 ";

	if ( options & INTRO_OPT_PROT_KM_TOKEN_PTR )
		ret += "km_token ";

	if ( options & INTRO_OPT_PROT_KM_NT_DRIVERS )
		ret += "km_nt_drivers ";

	if ( options & INTRO_OPT_PROT_KM_AV_DRIVERS )
		ret += "km_av_drivers ";

	if ( options & INTRO_OPT_PROT_KM_XEN_DRIVERS )
		ret += "km_xen_drivers ";

	if ( options & INTRO_OPT_PROT_KM_DRVOBJ )
		ret += "km_drvobj ";

	if ( options & INTRO_OPT_PROT_KM_CR4 )
		ret += "km_cr4 ";

	if ( options & INTRO_OPT_PROT_KM_MSR_SYSCALL )
		ret += "km_msr_syscall ";

	if ( options & INTRO_OPT_PROT_KM_IDTR )
		ret += "km_idtr ";

	if ( options & INTRO_OPT_PROT_KM_SELF_MAP_ENTRY )
		ret += "km_self_map_entry ";

	if ( options & INTRO_OPT_PROT_KM_GDTR )
		ret += "km_gdtr ";

	if ( options & INTRO_OPT_PROT_KM_LOGGER_CONTEXT )
		ret += "kvm_logger_ctx ";

	if ( options & INTRO_OPT_PROT_KM_NT_EAT_READS )
		ret += "km_nt_eat_reads ";

	if ( options & INTRO_OPT_PROT_UM_MISC_PROCS )
		ret += "um_misc_procs ";

	if ( options & INTRO_OPT_PROT_UM_SYS_PROCS )
		ret += "um_sys_procs ";

	if ( options & INTRO_OPT_EVENT_PROCESSES )
		ret += "evt_process ";

	if ( options & INTRO_OPT_EVENT_MODULES )
		ret += "evt_module ";

	if ( options & INTRO_OPT_EVENT_OS_CRASH )
		ret += "evt_os_crash ";

	if ( options & INTRO_OPT_EVENT_PROCESS_CRASH )
		ret += "evt_process_crash ";

	if ( options & INTRO_OPT_AGENT_INJECTION )
		ret += "agent_injection ";

	if ( options & INTRO_OPT_FULL_PATH )
		ret += "full_path_protection ";

	if ( options & INTRO_OPT_KM_BETA_DETECTIONS )
		ret += "beta_detections ";

	if ( options & INTRO_OPT_BUGCHECK_CLEANUP )
		ret += "bugcheck_cleanup ";

	if ( options & INTRO_OPT_IN_GUEST_PT_FILTER )
		ret += "in_guest_pt_filter ";

	if ( options & INTRO_OPT_EVENT_CONNECTIONS )
		ret += "connection_events ";

	if ( options & INTRO_OPT_NOTIFY_ENGINES )
		ret += "notify_engines ";

	return ret;
}

std::string ipv4AddrToString( DWORD addr )
{
	return std::to_string( addr & 0xff ) + "." + std::to_string( ( addr >> 8 ) & 0xff ) + "." +
	    std::to_string( ( addr >> 16 ) & 0xff ) + "." + std::to_string( ( addr >> 24 ) & 0xff );
}

std::string ipv6AddrToString( const BYTE addr[16] )
{
	std::stringstream ss;

	ss << std::hex;

	for ( int i = 0; i < 16; ++i ) {
		ss << static_cast<int>( addr[i] );
		if ( i && i != 15 && ( i % 2 ) )
			ss << ":";
	}

	return ss.str();
}

void extractAddresses( const EVENT_CONNECTION_EVENT &connection, std::string &localAddress, std::string &remoteAddress )
{
	switch ( connection.Family ) {
		case introNetAfIpv4:
			localAddress  = ipv4AddrToString( connection.LocalAddress.Ipv4 );
			remoteAddress = ipv4AddrToString( connection.RemoteAddress.Ipv4 );
			break;
		case introNetAfIpv6:
			localAddress  = ipv6AddrToString( connection.LocalAddress.Ipv6 );
			remoteAddress = ipv6AddrToString( connection.RemoteAddress.Ipv6 );
			break;
		case introNetAfUnknown:
		default:
			break;
	}
}

#define __case( x )                                                                                                    \
	case x:                                                                                                        \
		return #x;                                                                                             \
		break

const char *introActionToString( INTRO_ACTION action )
{
	switch ( action ) {
		__case( introGuestAllowed );
		__case( introGuestAllowedVirtual );
		__case( introGuestAllowedPatched );
		__case( introGuestNotAllowed );
		__case( introGuestIgnore );
		__case( introGuestRetry );
		default:
			return "unknown";
	}
}

const char *agentEventToString( AGENT_EVENT_TYPE state )
{
	switch ( state ) {
		__case( agentInjected );
		__case( agentInitialized );
		__case( agentStarted );
		__case( agentTerminated );
		__case( agentMessage );
		__case( agentError );
		__case( agentInvalid );
		default:
			return "unknown";
	}
}

std::string violationToString( BYTE violation )
{
	std::string ret;

	ret += ( ( violation & IG_EPT_HOOK_READ ) ? "r" : "-" );
	ret += ( ( violation & IG_EPT_HOOK_WRITE ) ? "w" : "-" );
	ret += ( ( violation & IG_EPT_HOOK_EXECUTE ) ? "x" : "-" );

	return ret;
}

const char *typeToString( INTRO_OBJECT_TYPE state )
{
	switch ( state ) {
		__case( introObjectTypeRaw );
		__case( introObjectTypeInternal );
		__case( introObjectTypeSsdt );
		__case( introObjectTypeFastIoDispatch );
		__case( introObjectTypeDriverObject );
		__case( introObjectTypeKmModule );
		__case( introObjectTypeIdt );
		__case( introObjectTypeGdt );
		__case( introObjectTypeKmUnpack );
		__case( introObjectTypeProcess );
		__case( introObjectTypeUmInternal );
		__case( introObjectTypeUmUnpack );
		__case( introObjectTypeUmHeap );
		__case( introObjectTypeUmStack );
		__case( introObjectTypeUmGenericNxZone );
		__case( introObjectTypeUmModule );
		__case( introObjectTypeDetourRead );
		__case( introObjectTypeTokenPtr );
		__case( introObjectTypeHalDispatchTable );
		__case( introObjectTypeHalIntController );
		__case( introObjectTypeSelfMapEntry );
		__case( introObjectTypeHalHeap );
		__case( introObjectTypeVdso );
		__case( introObjectTypeVsyscall );
		__case( introObjectTypeExTable );
		__case( introObjectTypeVeAgent );
		__case( introObjectTypeIdtr );
		__case( introObjectTypeGdtr );
		__case( introObjectTypeTest );
		__case( introObjectTypeTokenPrivs );
		__case( introObjectTypeSharedUserData );
		default:
			return "unknown";
	}
}

const char *afFamilyToString( INTRO_NET_AF family )
{
	switch ( family ) {
		__case( introNetAfIpv4 );
		__case( introNetAfIpv6 );
		__case( introNetAfUnknown );
		default:
			return "unknown";
	}
}

const char *netStateToString( INTRO_NET_STATE state )
{
	switch ( state ) {
		__case( introNetStateEstablished );
		__case( introNetStateSynSent );
		__case( introNetStateSynRecv );
		__case( introNetStateFinWait );
		__case( introNetStateFinWait2 );
		__case( introNetStateTimeWait );
		__case( introNetStateClosed );
		__case( introNetStateCloseWait );
		__case( introNetStateLastAck );
		__case( introNetStateListening );
		__case( introNetStateClosing );
		__case( introNetStateNewSynRecv );
		__case( introNetStateDeleteTcb );
		__case( introNetStateUnknown );
		default:
			return "unknown";
	}
}

const char *reasonToString( INTRO_ACTION_REASON reason )
{
	switch ( reason ) {
		__case( introReasonAllowed );
		__case( introReasonAllowedFeedback );
		__case( introReasonSignatureNotMatched );
		__case( introReasonNoException );
		__case( introReasonExtraChecksFailed );
		__case( introReasonExceptionsNotLoaded );
		__case( introReasonInternalError );
		__case( introReasonValueCodeNotMatched );
		__case( introReasonValueNotMatched );
		__case( introReasonExportNotMatched );
		__case( introReasonUnknown );
		default:
			return "unknown";
	}
}

const char *errorStateToString( INTRO_ERROR_STATE errorState )
{
	switch ( errorState ) {
		__case( intErrGuestNotIdentified );
		__case( intErrGuestNotSupported );
		__case( intErrGuestKernelNotFound );
		__case( intErrGuestApiNotFound );
		__case( intErrGuestExportNotFound );
		__case( intErrGuestStructureNotFound );
		__case( intErrUpdateFileNotSupported );
		__case( intErrProcNotProtectedNoMemory );
		__case( intErrProcNotProtectedInternalError );
		default:
			return "unknown";
	}
}

#undef __case

bool hasExecutableExtension( const std::string &filename )
{
	size_t pos = filename.rfind( '.' );

	if ( pos == std::string::npos || pos == 0 /* UNIX hidden */ )
		return false;

	std::string extension = filename.substr( pos + 1 );

	return ( extension.compare( "exe" ) == 0 ) || ( extension.compare( "com" ) == 0 );
}

bool disableQueryHeap = false;

} // end of anonymous namespace

#ifdef _DEBUG
std::unique_ptr<std::ofstream> IntrocoreManager::debugOut_;
#endif

extern "C" {

void IntPreinit();

INTSTATUS IntInit( PGLUE_IFACE GlueInterfaceBuffer, PUPPER_IFACE UpperInterface );

INTSTATUS IntUninit();
}

IntrocoreManager::IntrocoreManager( bdvmi::Driver &driver, bdvmi::EventManager &eventManager,
                                    const std::string &domainName, HvmiSettings &settings )
    : domainName_{ domainName }
    , driver_{ driver }
    , eventManager_{ eventManager }
    , settings_{ settings }
{
	domainUuid_ = driver_.uuid();

	generateSessionId();

	IntPreinit();

	iface_.Version = GLUE_IFACE_VERSION_LATEST;
	iface_.Size    = sizeof( iface_ );

	iface_.QueryGuestInfo = IntQueryGuestInfo;

	iface_.GpaToHpa         = IntGpaToHpa;
	iface_.PhysMemMapToHost = IntPhysMemMapToHost;
	iface_.PhysMemUnmap     = IntPhysMemUnmap;

	iface_.PhysMemGetTypeFromMtrrs = IntGetPhysicalPageTypeFromMtrrs;

	iface_.RegisterCrWriteHandler   = IntRegisterCrWriteHandler;
	iface_.UnregisterCrWriteHandler = IntUnregisterCrWriteHandler;
	iface_.EnableCrWriteExit        = IntEnableCrWriteExit;
	iface_.DisableCrWriteExit       = IntDisableCrWriteExit;

	iface_.GetEPTPageProtection = IntGetEPTPageProtection;
	iface_.SetEPTPageProtection = IntSetEPTPageProtection;
	iface_.RegisterEPTHandler   = IntRegisterEPTHandler;
	iface_.UnregisterEPTHandler = IntUnregisterEPTHandler;

	// #VE
	iface_.SetVeInfoPage         = IntSetVeInfoPage;
	iface_.CreateEPT             = IntCreateEPT;
	iface_.DestroyEPT            = IntDestroyEPT;
	iface_.SwitchEPT             = IntSwitchEPT;
	iface_.GetEPTPageConvertible = IntGetEPTPageConvertible;
	iface_.SetEPTPageConvertible = IntSetEPTPageConvertible;

	iface_.EnableMSRExit        = IntEnableMsrExit;
	iface_.DisableMSRExit       = IntDisableMsrExit;
	iface_.RegisterMSRHandler   = IntRegisterMSRHandler;
	iface_.UnregisterMSRHandler = IntUnregisterMSRHandler;

	iface_.RegisterIntroCallHandler    = IntRegisterIntroCallHandler;
	iface_.UnregisterIntroCallHandler  = IntUnregisterIntroCallHandler;
	iface_.RegisterIntroTimerHandler   = IntRegisterVmxTimerHandler;
	iface_.UnregisterIntroTimerHandler = IntUnregisterVmxTimerHandler;

	iface_.RegisterXcrWriteHandler   = IntRegisterXcrWriteHandler;
	iface_.UnregisterXcrWriteHandler = IntUnregisterXcrWriteHandler;

	iface_.RegisterBreakpointHandler   = IntRegisterBreakpointHandler;
	iface_.UnregisterBreakpointHandler = IntUnregisterBreakpointHandler;

	iface_.ReserveVaSpaceWithPt = ReserveVaSpaceWithPt;

	iface_.InjectTrap                     = InjectTrap;
	iface_.NotifyIntrospectionActivated   = NotifyIntrospectionActivated;
	iface_.NotifyIntrospectionDeactivated = NotifyIntrospectionDeactivated;
	iface_.NotifyIntrospectionDetectedOs  = NotifyIntrospectionDetectedOs;

	iface_.PauseVcpus              = RequestVcpusPause;
	iface_.ResumeVcpus             = RequestVcpusResume;
	iface_.RegisterDtrHandler      = RegisterDescriptorTableHandler;
	iface_.UnregisterDtrHandler    = UnregisterDescriptorTableHandler;
	iface_.SetIntroEmulatorContext = SetIntroEmulatorContext;
	iface_.GetAgentContent         = GetAgentContent;
	iface_.ReleaseBuffer           = ReleaseBuffer;
	iface_.NotifyScanEngines       = NotifyScanEngines;

	iface_.NotifyIntrospectionAlert = IntIntroEventNotify;
	iface_.ToggleRepOptimization    = ToggleRepOptimization;

	iface_.RegisterEventInjectionHandler   = RegisterEventInjectionHandler;
	iface_.UnregisterEventInjectionHandler = UnregisterEventInjectionHandler;
	iface_.NotifyIntrospectionErrorState   = NotifyIntrospectionErrorState;

	iface_.RegisterEnginesResultCallback  = RegisterEnginesResultCallback;
	iface_.UnregisterEnginesResultCalback = UnregisterEnginesResultCalback;

	uface_.Version                = UPPER_IFACE_VERSION_LATEST;
	uface_.Size                   = sizeof( uface_ );
	uface_.TracePrint             = IntTracePrint;
	uface_.MemAllocWithTagAndInfo = MemAllocWithTagAndInfo;
	uface_.MemFreeWithTagAndInfo  = MemFreeWithTagAndInfo;
	uface_.QueryHeapSize          = QueryHeapSize;

	uface_.SpinLockInit    = SpinLockInit;
	uface_.SpinLockUnInit  = SpinLockUnInit;
	uface_.SpinLockAcquire = SpinLockAcquire;
	uface_.SpinLockRelease = SpinLockRelease;

	uface_.RwSpinLockInit             = RwSpinLockInit;
	uface_.RwSpinLockUnInit           = RwSpinLockUnInit;
	uface_.RwSpinLockAcquireShared    = RwSpinLockAcquireShared;
	uface_.RwSpinLockAcquireExclusive = RwSpinLockAcquireExclusive;
	uface_.RwSpinLockReleaseShared    = RwSpinLockReleaseShared;
	uface_.RwSpinLockReleaseExclusive = RwSpinLockReleaseExclusive;

	uface_.BugCheck      = BugCheck;
	uface_.EnterDebugger = IntEnterDebugger;

	g_guestHandle = this;

	INTSTATUS ret = IntInit( &iface_, &uface_ );

	g_introInit = 1;

	if ( !INT_SUCCESS( ret ) ) {
		std::stringstream ss;

		ss << "[" << domainUuid_ << "] IntInit() failed (error: 0x" << std::hex << ret << ")";

		bdvmi::logger << bdvmi::DEBUG << "Domain status: unhooked" << std::flush;

		throw std::runtime_error( ss.str() );
	}

	bdvmi::logger << bdvmi::INFO << "Introcore init complete" << std::flush;

	srand( time( nullptr ) );

	if ( settings_.debugPipes_ )
		debugCommandsThread_.start( &IntrocoreManager::debugCommandsCallback, this );

	disableQueryHeap = settings_.disableQueryHeap_;

	// Driver::maxGPFN() computes and caches the MAXGPFN value which is important
	// given the way it operates (maps and unmaps a range of guest pages). We call
	// it here because later the process spawns a number of threads including
	// IntrocoreManager::introTimerCallback() which can access the pages probed
	// by Driver::maxGPFN(), leading to a crash.
	unsigned long long val = 0;
	if ( !driver_.maxGPFN( val ) )
		throw std::runtime_error( "failed to compute MAXGPFN for the guest" );
}

IntrocoreManager::~IntrocoreManager()
{
	if ( debugCommandsThread_.isRunning() )
		debugCommandsThread_.stop( [&] { stopDebugCommandsThread_ = true; } );

	// Calling this because it needs to shut down the timer thread gracefully
	// regardless of whether full cleanup is possible or not. Otherwise we end
	// up with an unjoined joinable thread and the C++ runtime terminate()s.
	disableIntrocore();

	g_introInit = 0;

	if ( !guestNotRunning_ )
		IntUninit();

	g_guestHandle = nullptr;

	if ( !vmUninitStatusSet_ )
		bdvmi::logger << bdvmi::DEBUG << "Domain status: unhooked" << std::flush;

	bdvmi::logger << bdvmi::INFO << "Introcore shutdown complete" << std::flush;
}

void IntrocoreManager::collectEvents()
{
	try {
		while ( introEnabled_ )
			eventManager_.waitForEvents();
	} catch ( const std::exception &e ) {
		bdvmi::logger << bdvmi::ERROR << "Error while collecting events: " << e.what() << std::flush;
	} catch ( ... ) {
		bdvmi::logger << bdvmi::ERROR << "Error while collecting events" << std::flush;
	}
}

INTSTATUS IntrocoreManager::addRemProtectedProcessByOS( const std::string &process, DWORD ProtectionMask, BOOLEAN Add,
                                                        QWORD id )
{
	INTSTATUS ret = INT_STATUS_SUCCESS;

	if ( isGuestWindows() ) {
		std::u16string u16 = utf8ToUtf16( process.c_str() );

		ret = iface_.AddRemoveProtectedProcessUtf16( this, ( PWCHAR )u16.c_str(), ProtectionMask, Add, id );

		if ( !hasExecutableExtension( process ) ) {
			const std::string exe    = process + ".exe";
			const std::string com    = process + ".com";
			std::u16string    u16exe = utf8ToUtf16( exe.c_str() );
			std::u16string    u16com = utf8ToUtf16( com.c_str() );

			iface_.AddRemoveProtectedProcessUtf16( this, ( PWCHAR )u16exe.c_str(), ProtectionMask, Add,
			                                       id );
			iface_.AddRemoveProtectedProcessUtf16( this, ( PWCHAR )u16com.c_str(), ProtectionMask, Add,
			                                       id );
		}
	} else
		ret = iface_.AddRemoveProtectedProcessUtf8( this, process.c_str(), ProtectionMask, Add, id );

	return ret;
}

std::string IntrocoreManager::generateAgentName() const
{
	static constexpr char alphanum[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
	std::string           result     = "bd";

	// ATTENTION: the name should _never_ exceed 14 characters (nul included).
	// Going beyond that will break introcore's agent tagging mechanism inside the guest.
	for ( int i = 0; i < 6; ++i )
		result += alphanum[rand() % ( sizeof( alphanum ) - 1 )];

	if ( isGuestWindows() )
		result += ".exe";

	return result;
}

std::string IntrocoreManager::launcherNameByOS() const
{
	std::string ret;

	switch ( guestType_ ) {
		case introGuestWindows:
			ret = ( guest64_ ? "launcher-64bit.exe" : "launcher-32bit.exe" );
			break;
		case introGuestLinux:
			ret = "launcher-64bit.linux";
			break;
		default:
			break;
	}

	return ret;
}

void IntrocoreManager::setAbortStatus( bool enable )
{
	iface_.SetIntroAbortStatus( this, enable ? TRUE : FALSE );
}

bool IntrocoreManager::disableIntrocore()
{
	bool ret = false;

	postEventAction_ = POST_EVENT_ACTION_NONE;

	stopTimer_ = true;
	if ( timerThread_.joinable() )
		timerThread_.join();

	if ( !introEnabled_ || guestNotRunning_ )
		return true; // already disabled or pointless to try to disable it

	eventManager_.stop();
	std::thread collector( &IntrocoreManager::collectEvents, this );

	if ( injectAgentKiller() )
		waitForAgent( 30 );

	int introDisableRetries = 300;

	while ( introDisableRetries-- > 0 ) {
		if ( guestNotRunning_ /* pointless to continue */ ||
		     iface_.DisableIntro( this, 0U ) != INT_STATUS_CANNOT_UNLOAD ) {
			ret = true;
			break;
		}

		if ( introDisableRetries > 0 )
			usleep( 100000 ); // 100 miliseconds
	}

	introEnabled_ = false; // introEnabled_ == false stops the thread loop
	collector.join();

	disableIntroInProgress_ = !ret;
	introEnabled_           = !ret;

	return ret;
}

bool IntrocoreManager::mapLiveUpdateFile( const std::string &filename, PBYTE &bytes, DWORD &size )
{
	if ( filename.empty() ) {
		bdvmi::logger << bdvmi::ERROR << "No live update file specified" << std::flush;
		return false;
	}

	size_t liveUpdateHash = 0xBD;

	if ( !liveUpdateHash )
		bdvmi::logger << bdvmi::ERROR << "Failed to compute the hash of '" << filename << "'" << std::flush;
	else if ( liveUpdateHash != liveUpdateHash_ ) {
		bdvmi::logger << bdvmi::INFO << "Loading live update file " << filename << std::flush;

		if ( mapFile( filename, bytes, size ) ) {
			liveUpdateHash_ = liveUpdateHash;
			return true;
		} else
			bdvmi::logger << bdvmi::ERROR << "Could not load live update file " << filename << std::flush;
	}

	return false;
}

bool IntrocoreManager::newGuestNotification()
{
	uint64_t    introspectionOptions;
	std::string liveUpdateFile;

	{
		std::lock_guard<std::mutex> guard( settings_.mutex_ );
		introspectionOptions = settings_.introspectionOptions_;
		liveUpdateFile       = settings_.liveUpdateFile_;
		settings_.oldProtectedProcesses_.clear();
	}

	exceptionsHash_ = 0;

	bdvmi::logger << bdvmi::DEBUG << "Introcore about to be initialized with options " << std::hex << std::showbase
	              << introspectionOptions << ": " << introOptionsToString( introspectionOptions ) << std::flush;

	ScopeTimer sTimer( "Introcore hook" );

	currentCpu_ = 0;

	PBYTE liveUpdateBuf  = nullptr;
	DWORD liveUpdateSize = 0;

	mapLiveUpdateFile( liveUpdateFile, liveUpdateBuf, liveUpdateSize );

	// If liveUpdateBuf remains nullptr, NewGuestNotification() will fail, so we don't need to do
	// anything special.
	INTSTATUS ret = iface_.NewGuestNotification( this, introspectionOptions, liveUpdateBuf, liveUpdateSize );

	if ( !INT_SUCCESS( ret ) ) {

		if ( guestOSDetected_ && !g_stop ) { // otherwise unsupported
			bdvmi::logger << bdvmi::DEBUG << "Domain status: needs reboot" << std::flush;
			vmUninitStatusSet_ = true;
		}

		bdvmi::logger << bdvmi::ERROR << "NewGuestNotification() failed (error: " << std::hex << std::showbase
		              << ret << ")" << std::flush;
		return false;
	}

	introEnabled_ = true;

	bdvmi::logger << bdvmi::DEBUG << "Domain status: new" << std::flush;

	updateExceptions();

	return true;
}

INTSTATUS
IntrocoreManager::CRWrite( DWORD CpuNumber, DWORD Cr, QWORD OldValue, QWORD NewValue, const bdvmi::Registers &regs,
                           INTRO_ACTION *Action )
{
	INTSTATUS                ret      = INT_STATUS_UNSUCCESSFUL;
	PFUNC_IntCrWriteCallback callback = crWriteCallback_;

	if ( !callback )
		return INT_STATUS_UNSUCCESSFUL;

	{
		std::lock_guard<std::mutex> lock( cacheMutex_ );
		cacheRegs( CpuNumber, regs );
	} // lock scope

	ret = callback( this, Cr, CpuNumber, OldValue, NewValue, Action );

	std::lock_guard<std::mutex> lock( cacheMutex_ );
	clearRegsCache( CpuNumber );

	return ret;
}

INTSTATUS
IntrocoreManager::EPTViolation( QWORD PhysicalAddress, QWORD VirtualAddress, DWORD CpuNumber, INTRO_ACTION *Action,
                                BYTE Type, const bdvmi::Registers &regs, bdvmi::EmulatorContext &emulatorCtx )
{
	INTSTATUS                     ret      = INT_STATUS_UNSUCCESSFUL;
	PFUNC_IntEPTViolationCallback callback = eptViolationCallback_;

	if ( !callback )
		return INT_STATUS_UNSUCCESSFUL;

	{
		std::lock_guard<std::mutex> lock( cacheMutex_ );
		cacheRegs( CpuNumber, regs );
	} // lock scope

	emulatorCtx_.reset();

	ret = callback( this, PhysicalAddress, 0, VirtualAddress, CpuNumber, Action, Type );

	emulatorCtx = emulatorCtx_;

	std::lock_guard<std::mutex> lock( cacheMutex_ );
	clearRegsCache( CpuNumber );

	return ret;
}

INTSTATUS
IntrocoreManager::MSRViolation( DWORD Msr, IG_MSR_HOOK_TYPE Flags, INTRO_ACTION *Action, QWORD OriginalValue,
                                QWORD *NewValue, DWORD CpuNumber )
{
	PFUNC_IntMSRViolationCallback callback = msrViolationCallback_;

	if ( !callback )
		return INT_STATUS_UNSUCCESSFUL;

	currentCpu_ = CpuNumber;

	return callback( this, Msr, Flags, Action, OriginalValue, NewValue, CpuNumber );
}

INTSTATUS
IntrocoreManager::VMCALL( DWORD CpuNumber, const bdvmi::Registers &regs )
{
	INTSTATUS                  ret      = INT_STATUS_UNSUCCESSFUL;
	PFUNC_IntIntroCallCallback callback = introCallCallback_;

	if ( callback ) {

		{
			std::lock_guard<std::mutex> lock( cacheMutex_ );
			cacheRegs( CpuNumber, regs );
		} // useful lock scope

		setEip_ = false;

		ret = callback( this, regs.rip, CpuNumber );

		std::lock_guard<std::mutex> lock( cacheMutex_ );
		clearRegsCache( CpuNumber );
		setEip_ = true;
	}

	return ret;
}

INTSTATUS IntrocoreManager::XSETBV( DWORD CpuNumber, INTRO_ACTION *Action )
{
	PFUNC_IntXcrWriteCallback callback = xcrWriteCallback_;

	if ( !callback )
		return INT_STATUS_UNSUCCESSFUL;

	currentCpu_ = CpuNumber;

	return callback( this, CpuNumber, Action );
}

INTSTATUS IntrocoreManager::breakpoint( DWORD CpuNumber, const bdvmi::Registers &regs, QWORD Gpa )
{
	PFUNC_IntBreakpointCallback callback = breakpointCallback_;

	if ( !callback )
		return INT_STATUS_NOT_INITIALIZED;

	{
		std::lock_guard<std::mutex> lock( cacheMutex_ );
		cacheRegs( CpuNumber, regs );
	} // lock scope

	INTSTATUS ret = callback( this, Gpa, CpuNumber );

	std::lock_guard<std::mutex> lock( cacheMutex_ );
	clearRegsCache( CpuNumber );

	return ret;
}

INTSTATUS IntrocoreManager::injection( DWORD Vector, QWORD ErrorCode, QWORD Cr2, DWORD CpuNumber,
                                       const bdvmi::Registers &regs )
{
	PFUNC_IntEventInjectionCallback callback = injectionCallback_;

	if ( !callback )
		return INT_STATUS_UNSUCCESSFUL;

	{
		std::lock_guard<std::mutex> lock( cacheMutex_ );
		cacheRegs( CpuNumber, regs );
	} // lock scope

	INTSTATUS ret = callback( this, Vector, ErrorCode, Cr2, CpuNumber );

	std::lock_guard<std::mutex> lock( cacheMutex_ );
	clearRegsCache( CpuNumber );

	return ret;
}

INTSTATUS IntrocoreManager::descriptorAccess( DWORD CpuNumber, const bdvmi::Registers &regs, DWORD Flags,
                                              INTRO_ACTION *Action )
{
	PFUNC_IntIntroDescriptorTableCallback callback = descriptorCallback_;

	if ( !callback )
		return INT_STATUS_UNSUCCESSFUL;

	{
		std::lock_guard<std::mutex> lock( cacheMutex_ );
		cacheRegs( CpuNumber, regs );
	} // lock scope

	INTSTATUS ret = callback( this, Flags, CpuNumber, Action );

	std::lock_guard<std::mutex> lock( cacheMutex_ );
	clearRegsCache( CpuNumber );

	return ret;
}

void IntrocoreManager::generateSessionId()
{
	uint32_t startTime = driver_.startTime();

	if ( startTime == ( uint32_t )-1 ) {
		bdvmi::logger << bdvmi::ERROR << "Could not retrieve guest start time!" << std::flush;
		return;
	}

	bdvmi::logger << bdvmi::INFO << "Guest start time: " << std::dec << startTime << std::flush;

	// sessionId_ = ??
}

bool IntrocoreManager::injectAgent( const Tool & /* agent */ )
{
	bdvmi::logger << bdvmi::ERROR << "Agent injection is not supported yet!" << std::flush;

	return false;
}

bool IntrocoreManager::injectLogCollector( const Tool &tool, bool getStdout )
{
	if ( disableIntroInProgress_ )
		return false;

	std::string file = getStdout ? stdoutFile() : tool.logs_.logFile_;
	std::string args = tool.logs_.deleteLogFiles_ ? "-rmlogs " : "";

	args += file;

	availableLogDiskSpace_ = true;

	if ( file.empty() ) {
		bdvmi::logger << bdvmi::WARNING << "No log file specified for tool " << tool.toolId_ << std::flush;
		return false;
	}

	agentName_ = generateAgentName();

	bdvmi::logger << bdvmi::DEBUG << "Log gatherer arguments for tool " << tool.toolId_ << ": " << args
	              << std::flush;

	INTSTATUS ret = iface_.InjectProcessAgent( this, IG_AGENT_TAG_LOG_GATHER_TOOL, nullptr, 0, agentName_.c_str(),
	                                           args.c_str() );

	if ( ret == INT_STATUS_SUCCESS ) {
		isAgentRunning_ = true;
		return true;
	}

	return false;
}

bool IntrocoreManager::injectAgentKiller()
{
	if ( guestNotRunning_ || disableIntroInProgress_ )
		return false;

	agentName_ = generateAgentName();

	killerInjected_ = killerInitialized_ = killerStarted_ = false;

	INTSTATUS ret =
	    iface_.InjectProcessAgent( this, IG_AGENT_TAG_AGENT_KILLER_TOOL, nullptr, 0, agentName_.c_str(), nullptr );

	if ( ret == INT_STATUS_SUCCESS ) {
		isAgentRunning_ = true;
		return true;
	}

	return false;
}

bool IntrocoreManager::injectAgent( const std::string &exeFile, const std::string &exeName, DWORD agentTag,
                                    const std::string &args, const std::string &archiveFile,
                                    const std::string &archiveName )
{
	if ( guestNotRunning_ || disableIntroInProgress_ )
		return false;

	PBYTE archBytes, exeBytes;
	DWORD archSize, exeSize;

	if ( !mapFile( exeFile, exeBytes, exeSize ) )
		return false;

	if ( !archiveFile.empty() ) {

		if ( !mapFile( archiveFile, archBytes, archSize ) ) {
			munmap( exeBytes, exeSize );
			return false;
		}

		INTSTATUS ret = iface_.InjectFileAgent( this, archBytes, archSize, archiveName.c_str() );
		if ( !INT_SUCCESS( ret ) ) {
			bdvmi::logger << bdvmi::ERROR << "Could not inject agent file!" << std::flush;
			munmap( archBytes, archSize );
			munmap( exeBytes, exeSize );
			return false;
		}
	}

	INTSTATUS ret = iface_.InjectProcessAgent( this, agentTag, exeBytes, exeSize, exeName.c_str(), args.c_str() );

	if ( ret == INT_STATUS_SUCCESS ) {
		isAgentRunning_ = true;
		return true;
	}

	// InjectProcessAgent() failed. If it wouldn't had, we wouldn't have needed to call munmap()
	// here - introcore has a dedicated unmap callback for successful agent injection.
	munmap( exeBytes, exeSize );

	return false;
}

INTSTATUS IntrocoreManager::IntQueryGuestInfo( void *GuestHandle, DWORD InfoClass, void *InfoParam, void *Buffer,
                                               DWORD BufferLength )
{
	IntrocoreManager *pim  = static_cast<IntrocoreManager *>( GuestHandle );
	INTSTATUS         ret  = INT_STATUS_SUCCESS;
	unsigned long     vcpu = reinterpret_cast<unsigned long>( InfoParam );

	FAIL_IF_FUZZING();

	if ( vcpu == IG_CURRENT_VCPU )
		vcpu = pim->currentCpu_;

	switch ( InfoClass ) {

		case IG_QUERY_INFO_CLASS_READ_MSR: {
			PIG_QUERY_MSR __msr = static_cast<PIG_QUERY_MSR>( Buffer );

			if ( sizeof( *__msr ) != BufferLength ) {
				bdvmi::logger << bdvmi::ERROR << "MSR BufferLength is not correct! (" << std::dec
				              << sizeof( *__msr ) << ", " << BufferLength << ")" << std::flush;

				ret = INT_STATUS_UNSUCCESSFUL;
				break;
			}

			bdvmi::Registers            regs;
			std::lock_guard<std::mutex> lock( pim->cacheMutex_ );

			if ( pim->driver_.isMsrCached( __msr->MsrId ) && pim->regsCached( vcpu ) )
				regs = pim->vcpuRegsCache_[vcpu].second;
			else if ( !pim->driver_.registers( vcpu, regs ) )
				return INT_STATUS_UNSUCCESSFUL;

			switch ( __msr->MsrId ) {
				case IG_IA32_SYSENTER_CS:
					__msr->Value = regs.sysenter_cs;
					break;
				case IG_IA32_SYSENTER_ESP:
					__msr->Value = regs.sysenter_esp;
					break;
				case IG_IA32_SYSENTER_EIP:
					__msr->Value = regs.sysenter_eip;
					break;
				case IG_IA32_EFER:
					__msr->Value = regs.msr_efer;
					break;
				case IG_IA32_LSTAR:
					__msr->Value = regs.msr_lstar;
					break;
				case IG_IA32_FS_BASE:
					__msr->Value = regs.fs_base;
					break;
				case IG_IA32_GS_BASE:
					__msr->Value = regs.gs_base;
					break;
				case IG_IA32_STAR:
					__msr->Value = regs.msr_star;
					break;
				case IG_IA32_PAT:
					__msr->Value = regs.msr_pat;
					break;
				case IG_IA32_KERNEL_GS_BASE:
					__msr->Value = regs.shadow_gs;
					break;
				case IG_IA32_MISC_ENABLE:
				case IG_IA32_MC0_CTL:
				default:
					return INT_STATUS_UNSUCCESSFUL;
			}

			break;
		}

		case IG_QUERY_INFO_CLASS_IDT: {
			uint64_t *       idt_base = static_cast<uint64_t *>( Buffer );
			bdvmi::Registers regs;

			if ( !pim->driver_.registers( vcpu, regs ) )
				return INT_STATUS_UNSUCCESSFUL;

			if ( sizeof( *idt_base ) != BufferLength ) {
				bdvmi::logger << bdvmi::ERROR << "IDT BufferLength is not correct! (" << std::dec
				              << sizeof( *idt_base ) << ", " << BufferLength << ")" << std::flush;

				ret = INT_STATUS_UNSUCCESSFUL;
				break;
			}

			*idt_base = regs.idtr_base;

			break;
		}

		case IG_QUERY_INFO_CLASS_CS_TYPE: {
			uint32_t *                  cs_type = static_cast<uint32_t *>( Buffer );
			bdvmi::Registers            regs;
			std::lock_guard<std::mutex> lock( pim->cacheMutex_ );

			if ( pim->regsCached( vcpu ) )
				regs = pim->vcpuRegsCache_[vcpu].second;
			else if ( !pim->driver_.registers( vcpu, regs ) )
				return INT_STATUS_UNSUCCESSFUL;

			if ( sizeof( *cs_type ) != BufferLength ) {
				bdvmi::logger << bdvmi::ERROR << "CS_TYPE BufferLength is not correct! (" << std::dec
				              << sizeof( *cs_type ) << ", " << BufferLength << ")" << std::flush;

				ret = INT_STATUS_UNSUCCESSFUL;
				break;
			}

			switch ( regs.guest_x86_mode ) {
				case bdvmi::Registers::CS_TYPE_16:
					*cs_type = IG_CS_TYPE_16B;
					break;

				case bdvmi::Registers::CS_TYPE_32:
					*cs_type = IG_CS_TYPE_32B;
					break;

				case bdvmi::Registers::CS_TYPE_64:
					*cs_type = IG_CS_TYPE_64B;
					break;

				case bdvmi::Registers::ERROR:
				default:
					ret = INT_STATUS_UNSUCCESSFUL;
					break;
			}

			break;
		}

		case IG_QUERY_INFO_CLASS_REGISTER_STATE:
		case IG_QUERY_INFO_CLASS_REGISTER_STATE_GPRS: {
			PIG_ARCH_REGS               introArch = static_cast<PIG_ARCH_REGS>( Buffer );
			bdvmi::Registers            regs;
			std::lock_guard<std::mutex> lock( pim->cacheMutex_ );

			if ( InfoClass == IG_QUERY_INFO_CLASS_REGISTER_STATE_GPRS && pim->regsCached( vcpu ) )
				regs = pim->vcpuRegsCache_[vcpu].second;
			else if ( !pim->driver_.registers( vcpu, regs ) )
				return INT_STATUS_UNSUCCESSFUL;

			introArch->Rax      = regs.rax;
			introArch->Rcx      = regs.rcx;
			introArch->Rdx      = regs.rdx;
			introArch->Rbx      = regs.rbx;
			introArch->Rsp      = regs.rsp;
			introArch->Rbp      = regs.rbp;
			introArch->Rsi      = regs.rsi;
			introArch->Rdi      = regs.rdi;
			introArch->R8       = regs.r8;
			introArch->R9       = regs.r9;
			introArch->R10      = regs.r10;
			introArch->R11      = regs.r11;
			introArch->R12      = regs.r12;
			introArch->R13      = regs.r13;
			introArch->R14      = regs.r14;
			introArch->R15      = regs.r15;
			introArch->Flags    = regs.rflags;
			introArch->Rip      = regs.rip;
			introArch->IdtLimit = regs.idtr_limit;
			introArch->IdtBase  = regs.idtr_base;
			introArch->GdtLimit = regs.gdtr_limit;
			introArch->GdtBase  = regs.gdtr_base;
			introArch->Cr0      = regs.cr0;
			introArch->Cr2      = regs.cr2;
			introArch->Cr3      = regs.cr3;
			introArch->Cr4      = regs.cr4;

			break;
		}

		case IG_QUERY_INFO_CLASS_SET_REGISTERS: {
			PIG_ARCH_REGS               introArch = static_cast<PIG_ARCH_REGS>( Buffer );
			bdvmi::Registers            regs;
			std::lock_guard<std::mutex> lock( pim->cacheMutex_ );

			if ( pim->regsCached( vcpu ) )
				regs = pim->vcpuRegsCache_[vcpu].second;

			regs.rax    = introArch->Rax;
			regs.rcx    = introArch->Rcx;
			regs.rdx    = introArch->Rdx;
			regs.rbx    = introArch->Rbx;
			regs.rsp    = introArch->Rsp;
			regs.rbp    = introArch->Rbp;
			regs.rsi    = introArch->Rsi;
			regs.rdi    = introArch->Rdi;
			regs.r8     = introArch->R8;
			regs.r9     = introArch->R9;
			regs.r10    = introArch->R10;
			regs.r11    = introArch->R11;
			regs.r12    = introArch->R12;
			regs.r13    = introArch->R13;
			regs.r14    = introArch->R14;
			regs.r15    = introArch->R15;
			regs.rip    = introArch->Rip;
			regs.rflags = introArch->Flags;

			if ( !pim->driver_.setRegisters( vcpu, regs, pim->setEip_, true ) )
				return INT_STATUS_UNSUCCESSFUL;

			if ( pim->regsCached( vcpu ) )
				pim->vcpuRegsCache_[vcpu].second = regs;

			break;
		}

		case IG_QUERY_INFO_CLASS_CPU_COUNT: {
			DWORD *pCpuCount = static_cast<DWORD *>( Buffer );

			if ( pim->cachedCpuCount_ == 0 ) {
				unsigned int count = 0;

				if ( !pim->driver_.cpuCount( count ) )
					return INT_STATUS_UNSUCCESSFUL;

				pim->cachedCpuCount_ = count;
			}

			*pCpuCount = pim->cachedCpuCount_;

			break;
		}

		case IG_QUERY_INFO_CLASS_TSC_SPEED: {
			QWORD *pTscSpeed = static_cast<QWORD *>( Buffer );

			unsigned long long speed;
			if ( !pim->driver_.tscSpeed( speed ) )
				return INT_STATUS_UNSUCCESSFUL;

			*pTscSpeed = speed;

			break;
		}

		case IG_QUERY_INFO_CLASS_CURRENT_TID:
			*static_cast<DWORD *>( Buffer ) = pim->currentCpu_;
			break;

		case IG_QUERY_INFO_CLASS_CS_RING: {
			DWORD *          csRing = static_cast<DWORD *>( Buffer );
			bdvmi::Registers regs;

			if ( pim->regsCached( vcpu ) )
				regs = pim->vcpuRegsCache_[vcpu].second;
			else if ( !pim->driver_.registers( vcpu, regs ) )
				return INT_STATUS_UNSUCCESSFUL;

			*csRing = ( regs.cs_arbytes >> 5 ) & 3;

			break;
		}

		case IG_QUERY_INFO_CLASS_SEG_REGISTERS: {
			PIG_SEG_REGS     isr = static_cast<PIG_SEG_REGS>( Buffer );
			bdvmi::Registers regs;

			/*
			    This should be infrequent, so don't
			    cache it. Caching it would further increase the size of a
			    mem_event (by sizeof(INTRO_SEG_REGS)), requiring _much_
			    more space in the ring buffer.
			*/
			if ( !pim->driver_.registers( vcpu, regs ) )
				return INT_STATUS_UNSUCCESSFUL;

			isr->CsBase     = regs.cs_base;
			isr->CsLimit    = regs.cs_limit;
			isr->CsSelector = regs.cs_sel;
			isr->CsAr       = regs.cs_arbytes;
			isr->SsBase     = regs.ss_base;
			isr->SsLimit    = regs.ss_limit;
			isr->SsSelector = regs.ss_sel;
			isr->SsAr       = regs.ss_arbytes;
			isr->DsBase     = regs.ds_base;
			isr->DsLimit    = regs.ds_limit;
			isr->DsSelector = regs.ds_sel;
			isr->DsAr       = regs.ds_arbytes;
			isr->EsBase     = regs.es_base;
			isr->EsLimit    = regs.es_limit;
			isr->EsSelector = regs.es_sel;
			isr->EsAr       = regs.es_arbytes;
			isr->FsBase     = regs.fs_base;
			isr->FsLimit    = regs.fs_limit;
			isr->FsSelector = regs.fs_sel;
			isr->FsAr       = regs.fs_arbytes;
			isr->GsBase     = regs.gs_base;
			isr->GsLimit    = regs.gs_limit;
			isr->GsSelector = regs.gs_sel;
			isr->GsAr       = regs.gs_arbytes;

			break;
		}

		case IG_QUERY_INFO_CLASS_XSAVE_SIZE: {
			DWORD *xsave_size = static_cast<DWORD *>( Buffer );
			size_t size       = 0;

			if ( !pim->driver_.getXSAVESize( vcpu, size ) )
				return INT_STATUS_UNSUCCESSFUL;

			*xsave_size = size;

			break;
		}

		case IG_QUERY_INFO_CLASS_XSAVE_AREA: {
			PIG_XSAVE_AREA xsave_area = static_cast<PIG_XSAVE_AREA>( Buffer );

			memset( xsave_area, 0, BufferLength );

			if ( !pim->driver_.getXSAVEArea( vcpu, xsave_area, BufferLength ) )
				return INT_STATUS_UNSUCCESSFUL;

			break;
		}

		case IG_QUERY_INFO_CLASS_MAX_GPFN: {
			QWORD *            pMaxGPFN = static_cast<QWORD *>( Buffer );
			unsigned long long maxGPFN;

			if ( !pim->driver_.maxGPFN( maxGPFN ) )
				return INT_STATUS_UNSUCCESSFUL;

			*pMaxGPFN = maxGPFN;

			break;
		}

		case IG_QUERY_INFO_CLASS_EPTP_INDEX: {
			DWORD *eptpIndex = static_cast<DWORD *>( Buffer );

			*eptpIndex = pim->driver_.eptpIndex( vcpu );

			break;
		}

		case IG_QUERY_INFO_CLASS_VE_SUPPORT: {
			BOOLEAN *state = static_cast<BOOLEAN *>( Buffer );

			*state = pim->driver_.veSupported();

			if ( *state )
				bdvmi::logger << bdvmi::INFO << "We can use #VE with this guest" << std::flush;
			else
				bdvmi::logger << bdvmi::WARNING << "No #VE support!" << std::flush;

			break;
		}

		case IG_QUERY_INFO_CLASS_VMFUNC_SUPPORT: {
			BOOLEAN *state = static_cast<BOOLEAN *>( Buffer );

			*state = pim->driver_.vmfuncSupported();

			if ( *state )
				bdvmi::logger << bdvmi::INFO << "We can use VMFUNC with this guest" << std::flush;
			else
				bdvmi::logger << bdvmi::WARNING << "No VMFUNC support!" << std::flush;

			break;
		}

		case IG_QUERY_INFO_CLASS_DTR_SUPPORT: {
			BOOLEAN *state = static_cast<BOOLEAN *>( Buffer );

			*state = pim->driver_.dtrEventsSupported();

			if ( *state )
				bdvmi::logger << bdvmi::INFO << "DTR events supported" << std::flush;
			else
				bdvmi::logger << bdvmi::WARNING << "DTR events not supported" << std::flush;

			break;
		}

		case IG_QUERY_INFO_CLASS_SPP_SUPPORT: {
			BOOLEAN *state = static_cast<BOOLEAN *>( Buffer );

			*state = pim->driver_.sppSupported();

			break;
		}

		case IG_QUERY_INFO_CLASS_GET_XCR0: {
			QWORD *  xcr0 = static_cast<QWORD *>( Buffer );
			uint64_t val  = 0;

			if ( !pim->driver_.getXCR0( vcpu, val ) ) {
				bdvmi::logger << bdvmi::WARNING << "Failed to retrieve XCR0" << std::flush;
				return INT_STATUS_UNSUCCESSFUL;
			}

			*xcr0 = val;

			break;
		}

		case IG_QUERY_INFO_CLASS_GDT:
		default:
			// Unsupported
			ret = INT_STATUS_UNSUCCESSFUL;
			break;
	}

	return ret;
}

INTSTATUS IntrocoreManager::IntGpaToHpa( void * /* GuestHandle */, QWORD /* Gpa */, QWORD * /* Hpa */ )
{
	// Implemented.
	return INT_STATUS_UNSUCCESSFUL;
}

INTSTATUS IntrocoreManager::IntPhysMemMapToHost( void *GuestHandle, QWORD PhysAddress, DWORD Length, DWORD Flags,
                                                 void **HostPtr )
{
	IntrocoreManager *pim = static_cast<IntrocoreManager *>( GuestHandle );

	FAIL_IF_FUZZING();

	if ( !pim )
		return INT_STATUS_UNSUCCESSFUL;

	bdvmi::MapReturnCode mrc = pim->driver_.mapPhysMemToHost( PhysAddress, Length, Flags, *HostPtr );

	switch ( mrc ) {
		case bdvmi::MAP_SUCCESS:
			return INT_STATUS_SUCCESS;

		case bdvmi::MAP_PAGE_NOT_PRESENT:
			return INT_STATUS_PAGE_NOT_PRESENT;

		case bdvmi::MAP_INVALID_PARAMETER:
		case bdvmi::MAP_FAILED_GENERIC:
		default:
			return INT_STATUS_UNSUCCESSFUL;
	}
}

INTSTATUS IntrocoreManager::IntPhysMemUnmap( void *GuestHandle, void **HostPtr )
{
	IntrocoreManager *pim = static_cast<IntrocoreManager *>( GuestHandle );

	if ( !pim )
		return INT_STATUS_UNSUCCESSFUL;

	if ( !pim->driver_.unmapPhysMem( *HostPtr ) )
		return INT_STATUS_UNSUCCESSFUL;

	*HostPtr = nullptr;
	return INT_STATUS_SUCCESS;
}

INTSTATUS IntrocoreManager::IntGetPhysicalPageTypeFromMtrrs( void *GuestHandle, QWORD Gpa, IG_MEMTYPE *MemType )
{
	IntrocoreManager *pim = static_cast<IntrocoreManager *>( GuestHandle );

	if ( !pim )
		return INT_STATUS_UNSUCCESSFUL;

	uint8_t type = 0;
	if ( !pim->driver_.mtrrType( Gpa, type ) )
		return INT_STATUS_UNSUCCESSFUL;

	*MemType = static_cast<IG_MEMTYPE>( type );

	return INT_STATUS_SUCCESS;
}

INTSTATUS IntrocoreManager::IntRegisterCrWriteHandler( void *GuestHandle, PFUNC_IntCrWriteCallback Callback )
{
	IntrocoreManager *pim = static_cast<IntrocoreManager *>( GuestHandle );

	if ( !pim )
		return INT_STATUS_UNSUCCESSFUL;

	pim->crWriteCallback_ = Callback;

	return INT_STATUS_SUCCESS;
}

INTSTATUS IntrocoreManager::IntUnregisterCrWriteHandler( void *GuestHandle )
{
	IntrocoreManager *pim = static_cast<IntrocoreManager *>( GuestHandle );

	if ( !pim )
		return INT_STATUS_UNSUCCESSFUL;

	pim->crWriteCallback_ = nullptr;

	return INT_STATUS_SUCCESS;
}

INTSTATUS IntrocoreManager::IntRegisterBreakpointHandler( void *GuestHandle, PFUNC_IntBreakpointCallback Callback )
{
	IntrocoreManager *pim = static_cast<IntrocoreManager *>( GuestHandle );

	if ( !pim )
		return INT_STATUS_UNSUCCESSFUL;

	if ( !pim->eventManager_.enableBreakpointEvents() )
		return INT_STATUS_UNSUCCESSFUL;

	pim->breakpointCallback_ = Callback;

	return INT_STATUS_SUCCESS;
}

INTSTATUS IntrocoreManager::IntUnregisterBreakpointHandler( void *GuestHandle )
{
	IntrocoreManager *pim = static_cast<IntrocoreManager *>( GuestHandle );

	if ( !pim )
		return INT_STATUS_UNSUCCESSFUL;

	if ( !pim->eventManager_.disableBreakpointEvents() )
		return INT_STATUS_UNSUCCESSFUL;

	pim->breakpointCallback_ = nullptr;

	return INT_STATUS_SUCCESS;
}

INTSTATUS IntrocoreManager::IntEnableCrWriteExit( void *GuestHandle, DWORD Cr )
{
	IntrocoreManager *pim = static_cast<IntrocoreManager *>( GuestHandle );

	if ( !pim )
		return INT_STATUS_UNSUCCESSFUL;

	return ( pim->eventManager_.enableCrEvents( Cr ) ? INT_STATUS_SUCCESS : INT_STATUS_UNSUCCESSFUL );
}

INTSTATUS IntrocoreManager::IntDisableCrWriteExit( void *GuestHandle, DWORD Cr )
{
	IntrocoreManager *pim = static_cast<IntrocoreManager *>( GuestHandle );

	if ( !pim )
		return INT_STATUS_UNSUCCESSFUL;

	return ( pim->eventManager_.disableCrEvents( Cr ) ? INT_STATUS_SUCCESS : INT_STATUS_UNSUCCESSFUL );
}

INTSTATUS IntrocoreManager::IntGetEPTPageProtection( void *GuestHandle, DWORD EptIndex, QWORD Address, BYTE *Read,
                                                     BYTE *Write, BYTE *Execute )
{
	IntrocoreManager *pim = static_cast<IntrocoreManager *>( GuestHandle );

	if ( !pim )
		return INT_STATUS_UNSUCCESSFUL;

	bool r = false, w = false, x = false;
	if ( !pim->driver_.getPageProtection( static_cast<unsigned long>( Address ), r, w, x, EptIndex ) )
		return INT_STATUS_UNSUCCESSFUL;

	*Read    = ( r ? 1 : 0 );
	*Write   = ( w ? 1 : 0 );
	*Execute = ( x ? 1 : 0 );

	return INT_STATUS_SUCCESS;
}

INTSTATUS IntrocoreManager::IntSetEPTPageProtection( void *GuestHandle, DWORD EptIndex, QWORD Address, BYTE Read,
                                                     BYTE Write, BYTE Execute )
{
	IntrocoreManager *pim = static_cast<IntrocoreManager *>( GuestHandle );

	if ( !pim )
		return INT_STATUS_UNSUCCESSFUL;

	bool r = Read, w = Write, x = Execute;
	if ( !pim->driver_.setPageProtection( static_cast<unsigned long>( Address ), r, w, x, EptIndex ) )
		return INT_STATUS_UNSUCCESSFUL;

	return INT_STATUS_SUCCESS;
}

INTSTATUS IntrocoreManager::IntSetVeInfoPage( void *GuestHandle, DWORD CpuNumber, QWORD VeInfoGpa )
{
	IntrocoreManager *pim = static_cast<IntrocoreManager *>( GuestHandle );

	if ( !pim )
		return INT_STATUS_UNSUCCESSFUL;

	if ( VeInfoGpa != ~0UL ) { // INVALID_GFN
		if ( !pim->driver_.setVEInfoPage( CpuNumber, VeInfoGpa ) )
			return INT_STATUS_UNSUCCESSFUL;
	} else if ( !pim->driver_.disableVE( CpuNumber ) )
		return INT_STATUS_UNSUCCESSFUL;

	return INT_STATUS_SUCCESS;
}

INTSTATUS IntrocoreManager::IntCreateEPT( void *GuestHandle, DWORD *EptIndex )
{
	IntrocoreManager *pim = static_cast<IntrocoreManager *>( GuestHandle );

	unsigned short index = 0;

	if ( !pim || !pim->driver_.createEPT( index ) )
		return INT_STATUS_UNSUCCESSFUL;

	*EptIndex = index;

	return INT_STATUS_SUCCESS;
}

INTSTATUS IntrocoreManager::IntDestroyEPT( void *GuestHandle, DWORD EptIndex )
{
	IntrocoreManager *pim = static_cast<IntrocoreManager *>( GuestHandle );

	if ( !pim || !pim->driver_.destroyEPT( EptIndex ) )
		return INT_STATUS_UNSUCCESSFUL;

	return INT_STATUS_SUCCESS;
}

INTSTATUS IntrocoreManager::IntSwitchEPT( void *GuestHandle, DWORD NewEptIndex )
{
	IntrocoreManager *pim = static_cast<IntrocoreManager *>( GuestHandle );

	if ( !pim || !pim->driver_.switchEPT( NewEptIndex ) )
		return INT_STATUS_UNSUCCESSFUL;

	return INT_STATUS_SUCCESS;
}

INTSTATUS IntrocoreManager::IntGetEPTPageConvertible( void *GuestHandle, DWORD EptIndex, QWORD Address,
                                                      BOOLEAN *Convertible )
{
	IntrocoreManager *pim = static_cast<IntrocoreManager *>( GuestHandle );

	bool conv;

	if ( !pim || !pim->driver_.getEPTPageConvertible( EptIndex, Address, conv ) )
		return INT_STATUS_UNSUCCESSFUL;

	*Convertible = !conv;

	return INT_STATUS_SUCCESS;
}

INTSTATUS IntrocoreManager::IntSetEPTPageConvertible( void *GuestHandle, DWORD EptIndex, QWORD Address,
                                                      BOOLEAN Convertible )
{
	IntrocoreManager *pim = static_cast<IntrocoreManager *>( GuestHandle );

	if ( !pim || !pim->driver_.setEPTPageConvertible( EptIndex, Address, !Convertible ) )
		return INT_STATUS_UNSUCCESSFUL;

	return INT_STATUS_SUCCESS;
}

INTSTATUS IntrocoreManager::IntRegisterEPTHandler( void *GuestHandle, PFUNC_IntEPTViolationCallback Callback )
{
	IntrocoreManager *pim = static_cast<IntrocoreManager *>( GuestHandle );

	if ( !pim )
		return INT_STATUS_UNSUCCESSFUL;

	pim->eptViolationCallback_ = Callback;

	return INT_STATUS_SUCCESS;
}

INTSTATUS IntrocoreManager::IntUnregisterEPTHandler( void *GuestHandle )
{
	IntrocoreManager *pim = static_cast<IntrocoreManager *>( GuestHandle );

	if ( !pim )
		return INT_STATUS_UNSUCCESSFUL;

	pim->eptViolationCallback_ = nullptr;

	return INT_STATUS_SUCCESS;
}

INTSTATUS IntrocoreManager::IntEnableMsrExit( void *GuestHandle, DWORD Msr, BOOLEAN *OldValue )
{
	IntrocoreManager *pim = static_cast<IntrocoreManager *>( GuestHandle );
	bool              old = false;

	if ( !pim )
		return INT_STATUS_UNSUCCESSFUL;

	bool ret = pim->eventManager_.enableMsrEvents( Msr, old );

	*OldValue = ( old ? 1 : 0 );

	return ( ret ? INT_STATUS_SUCCESS : INT_STATUS_UNSUCCESSFUL );
}

INTSTATUS IntrocoreManager::IntDisableMsrExit( void *GuestHandle, DWORD Msr, BOOLEAN *OldValue )
{
	IntrocoreManager *pim = static_cast<IntrocoreManager *>( GuestHandle );
	bool              old = false;

	if ( !pim )
		return INT_STATUS_UNSUCCESSFUL;

	bool ret = pim->eventManager_.disableMsrEvents( Msr, old );

	*OldValue = ( old ? 1 : 0 );

	return ( ret ? INT_STATUS_SUCCESS : INT_STATUS_UNSUCCESSFUL );
}

INTSTATUS IntrocoreManager::IntRegisterMSRHandler( void *GuestHandle, PFUNC_IntMSRViolationCallback Callback )
{
	IntrocoreManager *pim = static_cast<IntrocoreManager *>( GuestHandle );

	if ( !pim )
		return INT_STATUS_UNSUCCESSFUL;

	pim->msrViolationCallback_ = Callback;

	return INT_STATUS_SUCCESS;
}

INTSTATUS IntrocoreManager::IntUnregisterMSRHandler( void *GuestHandle )
{
	IntrocoreManager *pim = static_cast<IntrocoreManager *>( GuestHandle );

	if ( !pim )
		return INT_STATUS_UNSUCCESSFUL;

	pim->msrViolationCallback_ = nullptr;

	return INT_STATUS_SUCCESS;
}

INTSTATUS IntrocoreManager::SpinLockInit( void **SpinLock, PCHAR /* Name */ )
{
	pthread_mutex_t *pmtx = static_cast<pthread_mutex_t *>( malloc( sizeof( pthread_mutex_t ) ) );

	if ( !pmtx ) {
		bdvmi::logger << bdvmi::ERROR << "Could not allocate memory for spin lock" << std::flush;
		return INT_STATUS_UNSUCCESSFUL;
	}

	*pmtx     = PTHREAD_MUTEX_INITIALIZER;
	*SpinLock = pmtx;

	return INT_STATUS_SUCCESS;
}

INTSTATUS IntrocoreManager::SpinLockUnInit( void **SpinLock )
{
	pthread_mutex_destroy( static_cast<pthread_mutex_t *>( *SpinLock ) );
	free( *SpinLock );
	*SpinLock = nullptr;

	return INT_STATUS_SUCCESS;
}

INTSTATUS IntrocoreManager::SpinLockAcquire( void *SpinLock )
{
	int ret = pthread_mutex_lock( static_cast<pthread_mutex_t *>( SpinLock ) );

	if ( ret ) {
		bdvmi::logger << bdvmi::ERROR << "Error locking spin lock: " << strerror( ret ) << std::flush;
		return INT_STATUS_UNSUCCESSFUL;
	}

	return INT_STATUS_SUCCESS;
}

INTSTATUS IntrocoreManager::SpinLockRelease( void *SpinLock )
{
	int ret = pthread_mutex_unlock( static_cast<pthread_mutex_t *>( SpinLock ) );

	if ( ret ) {
		bdvmi::logger << bdvmi::ERROR << "Error unlocking spin lock: " << strerror( ret ) << std::flush;
		return INT_STATUS_UNSUCCESSFUL;
	}

	return INT_STATUS_SUCCESS;
}

INTSTATUS IntrocoreManager::RwSpinLockInit( void **SpinLock, PCHAR /* Name */ )
{
	pthread_rwlock_t *prwl = static_cast<pthread_rwlock_t *>( malloc( sizeof( pthread_rwlock_t ) ) );

	if ( !prwl ) {
		bdvmi::logger << bdvmi::ERROR << "Could not allocate memory for r/w spin lock" << std::flush;
		return INT_STATUS_UNSUCCESSFUL;
	}

	*prwl     = PTHREAD_RWLOCK_INITIALIZER;
	*SpinLock = prwl;

	return INT_STATUS_SUCCESS;
}

INTSTATUS IntrocoreManager::RwSpinLockUnInit( void **SpinLock )
{
	pthread_rwlock_destroy( static_cast<pthread_rwlock_t *>( *SpinLock ) );
	free( *SpinLock );
	*SpinLock = nullptr;

	return INT_STATUS_SUCCESS;
}

INTSTATUS IntrocoreManager::RwSpinLockAcquireShared( void *SpinLock )
{
	int ret = pthread_rwlock_rdlock( static_cast<pthread_rwlock_t *>( SpinLock ) );

	if ( ret ) {
		bdvmi::logger << bdvmi::ERROR << "Error read locking spin lock: " << strerror( ret ) << std::flush;
		return INT_STATUS_UNSUCCESSFUL;
	}

	return INT_STATUS_SUCCESS;
}

INTSTATUS IntrocoreManager::RwSpinLockAcquireExclusive( void *SpinLock )
{
	int ret = pthread_rwlock_wrlock( static_cast<pthread_rwlock_t *>( SpinLock ) );

	if ( ret ) {
		bdvmi::logger << bdvmi::ERROR << "Error write locking spin lock: " << strerror( ret ) << std::flush;
		return INT_STATUS_UNSUCCESSFUL;
	}

	return INT_STATUS_SUCCESS;
}

INTSTATUS IntrocoreManager::RwSpinLockReleaseShared( void *SpinLock )
{
	return RwSpinLockReleaseExclusive( SpinLock );
}

INTSTATUS IntrocoreManager::RwSpinLockReleaseExclusive( void *SpinLock )
{
	int ret = pthread_rwlock_unlock( static_cast<pthread_rwlock_t *>( SpinLock ) );

	if ( ret ) {
		bdvmi::logger << bdvmi::ERROR << "Error unlocking r/w spin lock: " << strerror( ret ) << std::flush;
		return INT_STATUS_UNSUCCESSFUL;
	}

	return INT_STATUS_SUCCESS;
}

INTSTATUS IntrocoreManager::IntRegisterIntroCallHandler( void *GuestHandle, PFUNC_IntIntroCallCallback Callback )
{
	IntrocoreManager *pim = static_cast<IntrocoreManager *>( GuestHandle );

	if ( !pim )
		return INT_STATUS_UNSUCCESSFUL;

	if ( !pim->eventManager_.enableVMCALLEvents() )
		return INT_STATUS_UNSUCCESSFUL;

	pim->introCallCallback_ = Callback;

	return INT_STATUS_SUCCESS;
}

INTSTATUS IntrocoreManager::IntUnregisterIntroCallHandler( void *GuestHandle )
{
	IntrocoreManager *pim = static_cast<IntrocoreManager *>( GuestHandle );

	if ( !pim )
		return INT_STATUS_UNSUCCESSFUL;

	if ( !pim->eventManager_.disableVMCALLEvents() )
		return INT_STATUS_UNSUCCESSFUL;

	pim->introCallCallback_ = nullptr;

	return INT_STATUS_SUCCESS;
}

INTSTATUS IntrocoreManager::IntRegisterVmxTimerHandler( void *GuestHandle, PFUNC_IntIntroTimerCallback Callback )
{
	IntrocoreManager *pim = static_cast<IntrocoreManager *>( GuestHandle );

	if ( !pim )
		return INT_STATUS_UNSUCCESSFUL;

	pim->timerCallback_ = Callback;
	pim->startTimer();

	return INT_STATUS_SUCCESS;
}

INTSTATUS IntrocoreManager::IntUnregisterVmxTimerHandler( void *GuestHandle )
{
	IntrocoreManager *pim = static_cast<IntrocoreManager *>( GuestHandle );

	if ( !pim )
		return INT_STATUS_UNSUCCESSFUL;

	pim->timerCallback_ = nullptr;

	return INT_STATUS_SUCCESS;
}

INTSTATUS IntrocoreManager::IntRegisterXcrWriteHandler( void *GuestHandle, PFUNC_IntXcrWriteCallback Callback )
{
	IntrocoreManager *pim = static_cast<IntrocoreManager *>( GuestHandle );

	if ( !pim )
		return INT_STATUS_UNSUCCESSFUL;

	if ( !pim->eventManager_.enableXSETBVEvents() )
		return INT_STATUS_UNSUCCESSFUL;

	pim->xcrWriteCallback_ = Callback;

	return INT_STATUS_SUCCESS;
}

INTSTATUS IntrocoreManager::IntUnregisterXcrWriteHandler( void *GuestHandle )
{
	IntrocoreManager *pim = static_cast<IntrocoreManager *>( GuestHandle );

	if ( !pim )
		return INT_STATUS_UNSUCCESSFUL;

	if ( !pim->eventManager_.disableXSETBVEvents() )
		return INT_STATUS_UNSUCCESSFUL;

	pim->xcrWriteCallback_ = nullptr;

	return INT_STATUS_SUCCESS;
}

void IntrocoreManager::runIntroCommand( const std::string &command )
{
	std::regex rgx( "[\\r\\t\\n ]+" );

	std::sregex_token_iterator iter( command.begin(), command.end(), rgx, -1 ), end;

	std::vector<std::string> tokens( iter, end );

	if ( tokens.empty() ) // empty line?
		return;

	std::vector<char *> cStyleStrArray( tokens.size() );

	for ( size_t i = 0; i < tokens.size(); ++i )
		cStyleStrArray[i] = strdup( tokens[i].c_str() );

	bdvmi::logger << bdvmi::DEBUG << "Sending introcore command: " << command << std::flush;

	iface_.DebugProcessCommand( this, 0, tokens.size(), &cStyleStrArray[0] );

	for ( size_t i = 0; i < tokens.size(); ++i )
		free( cStyleStrArray[i] );
}

void IntrocoreManager::BugCheck()
{
#ifdef _DEBUG
	using namespace std;

	string fname   = string( "/tmp/bugcheck" ) + to_string( getpid() );
	string inPipe  = fname + ".fifo.in";
	string outPipe = fname + ".fifo.out";

	if ( mkfifo( inPipe.c_str(), S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP ) ) {
		bdvmi::logger << bdvmi::ERROR << "Could not create bugcheck input pipe! Aborting" << std::flush;
		abort();
	}

	string line;

	for ( ;; ) {
		ifstream in( inPipe.c_str() );

		if ( !in )
			break;

		while ( getline( in, line ) ) {
			if ( line == "!go" ) {
				bdvmi::logger << bdvmi::DEBUG << "Exiting BugCheck()" << std::flush;
				remove( inPipe.c_str() );
				abort(); // we're done
			}

			struct stat sb;

			if ( stat( outPipe.c_str(), &sb ) == -1 )
				bdvmi::logger << bdvmi::ERROR
				              << "Can't find bugcheck output pipe! Output will be log-only."
				              << std::flush;
			else {
				if ( ( sb.st_mode & S_IFMT ) == S_IFIFO )
					debugOut_ = make_unique<ofstream>( outPipe.c_str() );
				else
					bdvmi::logger << bdvmi::ERROR
					              << "Can't use bugcheck output pipe! Output will be log-only."
					              << std::flush;
			}

			g_guestHandle->runIntroCommand( line );

			debugOut_.reset();
		}
	}

	remove( inPipe.c_str() );
#endif // _DEBUG

	abort();
}

INTSTATUS IntrocoreManager::ReserveVaSpaceWithPt( void * /* GuestHandle */, void **FirstPageBase, DWORD *PagesCount,
                                                  void **PtBase )
{
	/* Tell the introengine we can't give it access to the page tables */
	*FirstPageBase = nullptr;
	*PagesCount    = 0;
	*PtBase        = nullptr;

	return INT_STATUS_SUCCESS;
}

INTSTATUS IntrocoreManager::IntIntroEventNotify( void *GuestHandle, DWORD EventClass, void *Parameters,
                                                 SIZE_T /* EventSize */ )
{
	IntrocoreManager *pim = static_cast<IntrocoreManager *>( GuestHandle );

	if ( !pim )
		return INT_STATUS_UNSUCCESSFUL;

	HvmiEventHandler::Action action      = HvmiEventHandler::ACT_ALLOW;
	PrimaryAction            actionTaken = PA_LOG;
	std::string              eventUUID   = pim->generateEventUUID( static_cast<INTRO_EVENT_TYPE>( EventClass ) );
	PEVENT_EPT_VIOLATION     dummy       = static_cast<PEVENT_EPT_VIOLATION>( Parameters );
	bool                     beta        = dummy->Header.Flags & ALERT_FLAG_BETA;
	bool                     feedback    = dummy->Header.Flags & ALERT_FLAG_FEEDBACK_ONLY;
	HvmiSettings             localSettings;

	{
		std::lock_guard<std::mutex> guard( pim->settings_.mutex_ );
		localSettings = pim->settings_;
	}

	pim->saveLastEvent( static_cast<INTRO_EVENT_TYPE>( EventClass ), Parameters, eventUUID );

	switch ( EventClass ) {

		case introEventEptViolation: {
			PEVENT_EPT_VIOLATION Info = static_cast<PEVENT_EPT_VIOLATION>( Parameters );

			std::string processPath = utf16ToUtf8( Info->Header.CurrentProcess.Path );

			pim->lastEventProcessId_ = Info->Header.CurrentProcess.Context;

			std::string name;

			switch ( Info->Victim.Type ) {
				case introObjectTypeDriverObject:
				case introObjectTypeFastIoDispatch:
					name = utf16ToUtf8( Info->Victim.DriverObject.Name );
					break;
				default:
					if ( Info->Victim.Module.Valid )
						name = utf16ToUtf8( Info->Victim.Module.Name );
					break;
			}

			std::string originatorName = utf16ToUtf8( Info->Originator.Module.Name );
			std::string returnName     = utf16ToUtf8( Info->Originator.ReturnModule.Name );

			pim->processVerdict( Info, action, actionTaken );

			INTRO_PROCESS *process =
			    ( ( Info->Header.Flags & ALERT_FLAG_NOT_RING0 ) ? &Info->Header.CurrentProcess : nullptr );

			char *buf = nullptr;

			int err = asprintf(
			    &buf,
			    "BDINT [EPT violation]: violation = %s, action = %s,"
			    " reason = %s, type = %s, virt = 0x%llx, phys = 0x%llx,"
			    " page = 0x%llx, off = %u, cpu = %u, flags = %llu, name = '%s',"
			    " originatorName = '%s', returnName = '%s', imageName = '%s',"
			    " actionTaken = %s, pid = %u, cr3 = 0x%llx, event_uuid = %s, beta = %u,"
			    " feedback_only = %u, current_process_cmdline = '%s', MITRE ID = T%u",
			    violationToString( Info->Violation ).c_str(), introActionToString( Info->Header.Action ),
			    reasonToString( Info->Header.Reason ), typeToString( Info->Victim.Type ),
			    Info->HookStartVirtual, Info->HookStartPhysical, Info->VirtualPage, Info->Offset,
			    Info->Header.CpuContext.Cpu, Info->Header.Flags, name.c_str(), originatorName.c_str(),
			    returnName.c_str(), Info->Header.CurrentProcess.ImageName, actionToString( actionTaken ),
			    Info->Header.CurrentProcess.Pid, Info->Header.CurrentProcess.Cr3, eventUUID.c_str(), beta,
			    feedback, process ? process->CmdLine : "N/A", Info->Header.MitreID );

			if ( err > 0 && buf ) {
				std::unique_ptr<char, cfreeFunc> pb( buf, std::free );

				bdvmi::logger << bdvmi::WARNING << buf << std::flush;
			}

			break;
		}

		case introEventInjectionViolation: {
			PEVENT_MEMCOPY_VIOLATION Info = ( PEVENT_MEMCOPY_VIOLATION )Parameters;

			pim->lastEventProcessId_ = Info->Victim.Process.Context;

			pim->processVerdict( Info, action, actionTaken );

			char *buf = nullptr;

			int err = asprintf(
			    &buf,
			    "BDINT [injection violation]: action = %s, actionTaken = %s, reason = %s"
			    " virt src = 0x%llx, virt dst = 0x%llx, proc src = %llu, proc dst = %llu,"
			    " size = %u, cpu = %u, flags = %llu, src name = %s, dst name = %s,"
			    " src pid = %u, dst pid = %u, event_uuid = %s, beta = %u, feedback_only = %u,"
			    " originator_process_cmdline = '%s', victim_process_cmdline = '%s', MITRE ID = T%u",
			    introActionToString( Info->Header.Action ), actionToString( actionTaken ),
			    reasonToString( Info->Header.Reason ), Info->SourceVirtualAddress,
			    Info->DestinationVirtualAddress, Info->Originator.Process.Cr3, Info->Victim.Process.Cr3,
			    Info->CopySize, Info->Header.CpuContext.Cpu, Info->Header.Flags,
			    Info->Originator.Process.ImageName, Info->Victim.Process.ImageName,
			    Info->Originator.Process.Pid, Info->Victim.Process.Pid, eventUUID.c_str(), beta, feedback,
			    Info->Originator.Process.CmdLine, Info->Victim.Process.CmdLine, Info->Header.MitreID );

			if ( err > 0 && buf ) {
				std::unique_ptr<char, cfreeFunc> pb( buf, std::free );

				bdvmi::logger << bdvmi::WARNING << buf << std::flush;
			}

			break;
		}

		case introEventTranslationViolation: {
			PEVENT_TRANSLATION_VIOLATION Info = ( PEVENT_TRANSLATION_VIOLATION )Parameters;

			std::string originatorName = utf16ToUtf8( Info->Originator.Module.Name );
			std::string returnName     = utf16ToUtf8( Info->Originator.ReturnModule.Name );

			pim->processVerdict( Info, action, actionTaken );

			char *buf = nullptr;

			int err = asprintf(
			    &buf,
			    "BDINT [translation violation]: action = %s, actionTaken = %s, reason = %s,"
			    " virt = 0x%llx, old phys = 0x%llx, new phys = 0x%llx, flags = %llu, originatorName = "
			    "'%s', returnName = '%s', imageName = '%s', pid = %u, eventUUID = %s, beta = %u,"
			    " feedback_only = %u, current_process_cmdline = '%s', MITRE ID = T%u",
			    introActionToString( Info->Header.Action ), actionToString( actionTaken ),
			    reasonToString( Info->Header.Reason ), Info->Victim.VirtualAddress,
			    Info->WriteInfo.OldValue[0], Info->WriteInfo.NewValue[0], Info->Header.Flags,
			    originatorName.c_str(), returnName.c_str(), Info->Header.CurrentProcess.ImageName,
			    Info->Header.CurrentProcess.Pid, eventUUID.c_str(), beta, feedback,
			    Info->Header.CurrentProcess.CmdLine, Info->Header.MitreID );

			if ( err > 0 && buf ) {
				std::unique_ptr<char, cfreeFunc> pb( buf, std::free );

				bdvmi::logger << bdvmi::WARNING << buf << std::flush;
			}

			break;
		}

		case introEventMsrViolation: {
			PEVENT_MSR_VIOLATION Info = ( PEVENT_MSR_VIOLATION )Parameters;

			std::string originatorName = utf16ToUtf8( Info->Originator.Module.Name );
			std::string returnName     = utf16ToUtf8( Info->Originator.ReturnModule.Name );

			pim->processVerdict( Info, action, actionTaken );

			INTRO_PROCESS *process =
			    ( ( Info->Header.Flags & ALERT_FLAG_NOT_RING0 ) ? &Info->Header.CurrentProcess : nullptr );

			char *buf = nullptr;

			int err = asprintf(
			    &buf,
			    "BDINT [MSR violation]: action = %s, msr = %x, old = 0x%llx, new = 0x%llx,"
			    " rip = 0x%llx, cpu = %u, flags = %llu, originatorName = '%s', returnName = '%s',"
			    " imageName = '%s', pid = %u, eventUUID = %s, actionTaken = %s, reason = %s,"
			    " beta = %u, feedback_only = %u, current_process_cmdline = '%s', MITRE ID = T%u",
			    introActionToString( Info->Header.Action ), Info->Victim.Msr, Info->WriteInfo.OldValue[0],
			    Info->WriteInfo.NewValue[0], Info->Header.CpuContext.Rip, Info->Header.CpuContext.Cpu,
			    Info->Header.Flags, originatorName.c_str(), returnName.c_str(),
			    Info->Header.CurrentProcess.ImageName, Info->Header.CurrentProcess.Pid, eventUUID.c_str(),
			    actionToString( actionTaken ), reasonToString( Info->Header.Reason ), beta, feedback,
			    process ? process->CmdLine : "N/A", Info->Header.MitreID );

			if ( err > 0 && buf ) {
				std::unique_ptr<char, cfreeFunc> pb( buf, std::free );

				bdvmi::logger << bdvmi::WARNING << buf << std::flush;
			}

			pim->lastEvent_.actionTaken = actionTaken;
			break;
		}

		case introEventIntegrityViolation: {
			PEVENT_INTEGRITY_VIOLATION Info = ( PEVENT_INTEGRITY_VIOLATION )Parameters;

			std::string name;
			std::string originatorName = utf16ToUtf8( Info->Originator.Module.Name );

			switch ( Info->Victim.Type ) {
				case introObjectTypeDriverObject:
				case introObjectTypeFastIoDispatch:
					name = utf16ToUtf8( Info->Victim.DriverObject.Name );
					break;
				default:
					name = utf16ToUtf8( Info->Victim.Name );
					break;
			}

			pim->processVerdict( Info, action, actionTaken );

			char *buf = nullptr;

			int err =
			    asprintf( &buf,
			              "BDINT [integrity violation]: action = %s, type = %s, cpu = %u,"
			              " virt = 0x%llx, size = %u, flags = %llu, name = '%s', pid = %u,"
			              " eventUUID = %s, actionTaken = %s, reason = %s, originatorName = '%s',"
			              " imageName = '%s', beta = %u, feedback_only = %u,"
			              " current_process_cmdline = '%s', MITRE ID = T%u",
			              introActionToString( Info->Header.Action ), typeToString( Info->Victim.Type ),
			              Info->Header.CpuContext.Cpu, Info->VirtualAddress, Info->Size, Info->Header.Flags,
			              name.c_str(), Info->Header.CurrentProcess.Pid, eventUUID.c_str(),
			              actionToString( actionTaken ), reasonToString( Info->Header.Reason ),
			              originatorName.c_str(), Info->Header.CurrentProcess.ImageName, beta, feedback,
			              Info->Header.CurrentProcess.CmdLine, Info->Header.MitreID );

			if ( err > 0 && buf ) {
				std::unique_ptr<char, cfreeFunc> pb( buf, std::free );

				bdvmi::logger << bdvmi::WARNING << buf << std::flush;
			}

			break;
		}

		case introEventCrViolation: {
			PEVENT_CR_VIOLATION Info = ( PEVENT_CR_VIOLATION )Parameters;

			std::string originatorName = utf16ToUtf8( Info->Originator.Module.Name );
			std::string returnName     = utf16ToUtf8( Info->Originator.ReturnModule.Name );

			pim->processVerdict( Info, action, actionTaken );

			INTRO_PROCESS *process =
			    ( ( Info->Header.Flags & ALERT_FLAG_NOT_RING0 ) ? &Info->Header.CurrentProcess : nullptr );

			char *buf = nullptr;

			int err = asprintf(
			    &buf,
			    "BDINT [CR violation]: action = %s, actionTaken = %s, reason = %s, cr = %u,"
			    " old = 0x%llx, new = 0x%llx, rip = 0x%llx, cpu = %u, flags = %llu,"
			    " originatorName = '%s', returnName = '%s', imageName = '%s', pid = %u,"
			    " event_uuid = %s, beta = %u, feedback_only = %u, current_process_cmdline = '%s',"
			    " MITRE ID = T%u",
			    introActionToString( Info->Header.Action ), actionToString( actionTaken ),
			    reasonToString( Info->Header.Reason ), Info->Victim.Cr, Info->WriteInfo.OldValue[0],
			    Info->WriteInfo.NewValue[0], Info->Header.CpuContext.Rip, Info->Header.CpuContext.Cpu,
			    Info->Header.Flags, originatorName.c_str(), returnName.c_str(),
			    Info->Header.CurrentProcess.ImageName, Info->Header.CurrentProcess.Pid, eventUUID.c_str(),
			    beta, feedback, process ? process->CmdLine : "N/A", Info->Header.MitreID );

			if ( err > 0 && buf ) {
				std::unique_ptr<char, cfreeFunc> pb( buf, std::free );

				bdvmi::logger << bdvmi::WARNING << buf << std::flush;
			}

			pim->lastEvent_.actionTaken = actionTaken;
			break;
		}

		case introEventXcrViolation: {
			PEVENT_XCR_VIOLATION Info = ( PEVENT_XCR_VIOLATION )Parameters;

			std::string originatorName = utf16ToUtf8( Info->Originator.Module.Name );
			std::string returnName     = utf16ToUtf8( Info->Originator.ReturnModule.Name );

			pim->processVerdict( Info, action, actionTaken );

			INTRO_PROCESS *process =
			    ( ( Info->Header.Flags & ALERT_FLAG_NOT_RING0 ) ? &Info->Header.CurrentProcess : nullptr );

			char *buf = nullptr;

			int err = asprintf(
			    &buf,
			    "BDINT [XCR violation]: action = %s, actionTaken = %s, reason = %s, xcr = %u,"
			    " old = 0x%llx, new = 0x%llx, rip = 0x%llx, cpu = %u, flags = %llu,"
			    " originatorName = '%s', returnName = '%s', imageName = '%s', pid = %u,"
			    " eventUUID = %s, beta =%u, feedback_only = %u, current_process_cmdline = '%s',"
			    " MITRE ID = T%u",
			    introActionToString( Info->Header.Action ), actionToString( actionTaken ),
			    reasonToString( Info->Header.Reason ), Info->Victim.Xcr, Info->WriteInfo.OldValue[0],
			    Info->WriteInfo.NewValue[0], Info->Header.CpuContext.Rip, Info->Header.CpuContext.Cpu,
			    Info->Header.Flags, originatorName.c_str(), returnName.c_str(),
			    Info->Header.CurrentProcess.ImageName, Info->Header.CurrentProcess.Pid, eventUUID.c_str(),
			    beta, feedback, process ? process->CmdLine : "N/A", Info->Header.MitreID );

			if ( err > 0 && buf ) {
				std::unique_ptr<char, cfreeFunc> pb( buf, std::free );

				bdvmi::logger << bdvmi::WARNING << buf << std::flush;
			}

			pim->lastEvent_.actionTaken = actionTaken;
			break;
		}

		case introEventDtrViolation: {
			PEVENT_DTR_VIOLATION Info = ( PEVENT_DTR_VIOLATION )Parameters;

			pim->processVerdict( Info, action, actionTaken );

			std::string originatorName = utf16ToUtf8( Info->Originator.Module.Name );
			std::string returnName     = utf16ToUtf8( Info->Originator.ReturnModule.Name );

			char *buf = nullptr;

			int err = asprintf( &buf,
			                    "BDINT [DTR violation]: action = %s, actionTaken = %s, reason = %s,"
			                    " type = %s, imageName = '%s', originatorName = '%s', returnName = '%s',"
			                    " beta = %u, feedback_only = %u, MITRE ID = T%u",
			                    introActionToString( Info->Header.Action ), actionToString( actionTaken ),
			                    reasonToString( Info->Header.Reason ), typeToString( Info->Victim.Type ),
			                    Info->Header.CurrentProcess.ImageName, originatorName.c_str(),
			                    returnName.c_str(), beta, feedback, Info->Header.MitreID );

			if ( err > 0 && buf ) {
				std::unique_ptr<char, cfreeFunc> pb( buf, std::free );

				bdvmi::logger << bdvmi::WARNING << buf << std::flush;
			}

			pim->lastEvent_.actionTaken = actionTaken;
			break;
		}

		case introEventProcessCreationViolation: {
			PEVENT_PROCESS_CREATION_VIOLATION Info       = ( PEVENT_PROCESS_CREATION_VIOLATION )Parameters;
			std::string                       originUUID = computeEventUUID( Info->Originator );

			pim->lastEventProcessId_ = Info->Victim.Context;

			pim->processVerdict( Info, action, actionTaken );

			char *buf = nullptr;

			int err =
			    asprintf( &buf,
			              "BDINT [process creation violation]: action = %s, actionTaken = %s,"
			              " reason = %s, imageName = '%s', originatorName = '%s',"
			              " beta = %u, feedback_only = %u, MITRE ID = T%u",
			              introActionToString( Info->Header.Action ), actionToString( actionTaken ),
			              reasonToString( Info->Header.Reason ), Info->Header.CurrentProcess.ImageName,
			              Info->Originator.ImageName, beta, feedback, Info->Header.MitreID );

			if ( err > 0 && buf ) {
				std::unique_ptr<char, cfreeFunc> pb( buf, std::free );

				bdvmi::logger << bdvmi::WARNING << buf << std::flush;
			}

			pim->lastEvent_.actionTaken = actionTaken;
			break;
		}

		case introEventProcessEvent: {
			PEVENT_PROCESS_EVENT Info = ( PEVENT_PROCESS_EVENT )Parameters;

			std::string procUUID   = computeEventUUID( Info->Child );
			std::string parentUUID = computeEventUUID( Info->Parent );

			if ( localSettings.logUnprotectedProcesses_ || Info->Protected ) {
				char *buf = nullptr;

				int err = asprintf(
				    &buf,
				    "BDINT [process event]: created = %u, protected = %u, crashed = %u,"
				    " image name = %s, parent image name = %s, pid = %u, parent pid = %u, cr3 ="
				    " 0x%llx, parent cr3 = 0x%llx, uuid = %s, origin_uuid = %s, cmdline = '%s'",
				    Info->Created, Info->Protected, Info->Crashed, Info->Child.ImageName,
				    Info->Parent.ImageName, Info->Child.Pid, Info->Parent.Pid, Info->Child.Cr3,
				    Info->Parent.Cr3, procUUID.c_str(), parentUUID.c_str(), Info->Child.CmdLine );

				if ( err > 0 && buf ) {
					std::unique_ptr<char, cfreeFunc> pb( buf, std::free );

					bdvmi::logger << bdvmi::WARNING << buf << std::flush;
				}
			}
			break;
		}

		case introEventAgentEvent: {
			PEVENT_AGENT_EVENT Info = ( PEVENT_AGENT_EVENT )Parameters;

			switch ( Info->AgentTag ) {
				case IG_AGENT_TAG_REMEDIATION_TOOL:
				case IG_AGENT_TAG_REMEDIATION_TOOL_LINUX:
					break;
				case IG_AGENT_TAG_LOG_GATHER_TOOL:
					pim->processLogAgentEvent( Info );
					break;
				case IG_AGENT_TAG_CUSTOM_TOOL:
					pim->processCustomAgentEvent( Info );
					break;
				case IG_AGENT_TAG_AGENT_KILLER_TOOL:
					pim->processAgentKillerEvent( Info );
					break;
				default:
					// log an error?
					break;
			}

			break;
		}

		case introEventModuleEvent: {
			PEVENT_MODULE_EVENT Info = ( PEVENT_MODULE_EVENT )Parameters;

			std::string moduleName = utf16ToUtf8( Info->Module.Name );
			std::string originUUID = computeEventUUID( Info->CurrentProcess );
			std::string moduleUUID = computeEventUUID( Info->Module );

			if ( Info->Loaded && !pim->violationAgentsPending_ && Info->Protected )
				pim->lastEvent_.processUUID = moduleUUID;

			char *buf = nullptr;

			int err = asprintf(
			    &buf,
			    "BDINT [module event]: loaded = %u, protected = %u, module name = %s,"
			    " base = 0x%llx, size = %u, timestamp = %u, image name = %s, pid = %u, cr3 = 0x%llx,"
			    " uuid = %s, origin_uuid = %s",
			    Info->Loaded, Info->Protected, moduleName.c_str(), Info->Module.Base, Info->Module.Size,
			    Info->Module.TimeDateStamp, Info->CurrentProcess.ImageName, Info->CurrentProcess.Pid,
			    Info->CurrentProcess.Cr3, moduleUUID.c_str(), originUUID.c_str() );

			if ( err > 0 && buf ) {
				std::unique_ptr<char, cfreeFunc> pb( buf, std::free );

				bdvmi::logger << bdvmi::WARNING << buf << std::flush;
			}
			break;
		}

		case introEventCrashEvent: {
			PEVENT_CRASH_EVENT Info = ( PEVENT_CRASH_EVENT )Parameters;
			char *             buf  = nullptr;

			int err = asprintf( &buf,
			                    "BDINT [OS crash]: reason = %llu, param1 = %llu,"
			                    " param2 = %llu, param3 = %llu, param4 = %llu,"
			                    " image name = %s, pid = %u, cr3 = 0x%llx,"
			                    " current_process_cmdline = '%s'",
			                    Info->Reason, Info->Param1, Info->Param2, Info->Param3, Info->Param4,
			                    Info->CurrentProcess.ImageName, Info->CurrentProcess.Pid,
			                    Info->CurrentProcess.Cr3, Info->CurrentProcess.CmdLine );

			if ( err > 0 && buf ) {
				std::unique_ptr<char, cfreeFunc> pb( buf, std::free );

				bdvmi::logger << bdvmi::WARNING << buf << std::flush;
			}
			break;
		}

		case introEventExceptionEvent: {
			PEVENT_EXCEPTION_EVENT Info = ( PEVENT_EXCEPTION_EVENT )Parameters;
			char *                 buf  = nullptr;

			int err = asprintf( &buf,
			                    "BDINT [process exception]: exception code = 0x%llx,"
			                    " rip = 0x%llx, continuable = %u, process name = %s, pid = %u,"
			                    " cr3 = 0x%llx, cmdline = '%s'",
			                    Info->ExceptionCode, Info->Rip, Info->Continuable,
			                    Info->CurrentProcess.ImageName, Info->CurrentProcess.Pid,
			                    Info->CurrentProcess.Cr3, Info->CurrentProcess.CmdLine );

			if ( err > 0 && buf ) {
				std::unique_ptr<char, cfreeFunc> pb( buf, std::free );

				bdvmi::logger << bdvmi::WARNING << buf << std::flush;
			}
			break;
		}

		case introEventConnectionEvent: {
			PEVENT_CONNECTION_EVENT Info = ( PEVENT_CONNECTION_EVENT )Parameters;
			std::string             localAddress, remoteAddress;
			std::string             processPath = "N/A";

			if ( Info->Owner.Valid )
				processPath = utf16ToUtf8( Info->Owner.Path );

			extractAddresses( *Info, localAddress, remoteAddress );

			char *buf = nullptr;

			int err = asprintf( &buf,
			                    "BDINT [connection]: family = %s, state = %s,"
			                    " local_address = %s, remote_address = %s,"
			                    " local_port = %u, remote_port = %u, process = %s, pid = %u",
			                    afFamilyToString( Info->Family ), netStateToString( Info->State ),
			                    localAddress.c_str(), remoteAddress.c_str(), Info->LocalPort,
			                    Info->RemotePort, processPath.c_str(), Info->Owner.Pid );

			if ( err > 0 && buf ) {
				std::unique_ptr<char, cfreeFunc> pb( buf, std::free );

				bdvmi::logger << bdvmi::WARNING << buf << std::flush;
			}
			break;
		}

		case introEventModuleLoadViolation: {
			PEVENT_MODULE_LOAD_VIOLATION Info       = ( PEVENT_MODULE_LOAD_VIOLATION )Parameters;
			std::string                  originUUID = computeEventUUID( Info->Header.CurrentProcess );

			pim->lastEventProcessId_ = Info->Victim.Context;

			pim->processVerdict( Info, action, actionTaken );

			std::string originatorName = utf16ToUtf8( Info->Originator.Module.Name );

			char *buf = nullptr;

			int err =
			    asprintf( &buf,
			              "BDINT [module load violation]: action = %s, actionTaken = %s,"
			              " reason = %s, imageName = '%s', originatorName = '%s', beta = %u,"
			              " feedback_only = %u, MITRE ID = T%u",
			              introActionToString( Info->Header.Action ), actionToString( actionTaken ),
			              reasonToString( Info->Header.Reason ), Info->Header.CurrentProcess.ImageName,
			              originatorName.c_str(), beta, feedback, Info->Header.MitreID );

			if ( err > 0 && buf ) {
				std::unique_ptr<char, cfreeFunc> pb( buf, std::free );

				bdvmi::logger << bdvmi::WARNING << buf << std::flush;
			}

			pim->lastEvent_.actionTaken = actionTaken;
			break;
		}

		case introEventEnginesDetectionViolation: {
			PEVENT_ENGINES_DETECTION_VIOLATION Info = ( PEVENT_ENGINES_DETECTION_VIOLATION )Parameters;

			const char *type = nullptr;

			if ( Info->Type == introEngineNotificationCodeExecution ) {
				type                     = "code execution violation";
				pim->lastEventProcessId_ = Info->ExecViolation.Process.Context;
			} else if ( Info->Type == introEngineNotificationCmdLine ) {
				type                     = "command line violation";
				pim->lastEventProcessId_ = Info->CmdLineViolation.Victim.Context;
			} else {
				bdvmi::logger << bdvmi::ERROR << "unsupported engines detection violation event"
				              << std::flush;
				break;
			}

			std::string originUUID = computeEventUUID( Info->Header.CurrentProcess );

			actionTaken = PA_LOG;

			char *buf = nullptr;

			int err = asprintf( &buf,
			                    "BDINT [%s]: action = %s, actionTaken = %s,"
			                    " reason = %s, imageName = '%s', originatorName = '%s', beta = %u,"
			                    " feedback_only = %u, detectionName = '%s', MITRE ID = T%u",
			                    ( type ? type : "unknown" ), introActionToString( Info->Header.Action ),
			                    actionToString( actionTaken ), reasonToString( Info->Header.Reason ),
			                    Info->Header.CurrentProcess.ImageName,
			                    Info->CmdLineViolation.Originator.ImageName, beta, feedback,
			                    Info->DetectionName, Info->Header.MitreID );

			if ( err > 0 && buf ) {
				std::unique_ptr<char, cfreeFunc> pb( buf, std::free );

				bdvmi::logger << bdvmi::WARNING << buf << std::flush;
			}

			pim->lastEvent_.actionTaken = actionTaken;
			break;
		}

		case introEventMessage: // No longer used
		default:
			bdvmi::logger
			    << bdvmi::WARNING
			    << "An unsupported event class has been received from the memory introspection engine ("
			    << std::hex << std::showbase << EventClass << ")" << std::flush;
			break;
	}

	return INT_STATUS_SUCCESS;
}

INTSTATUS IntrocoreManager::IntTracePrint( const CHAR *File, DWORD Line, const CHAR *Format, ... )
{
	char    buf[1024] = {};
	va_list ap;

	va_start( ap, Format );
	vsnprintf( buf, sizeof( buf ), Format, ap );
	va_end( ap );

	long l = strlen( buf ) - 1;

	while ( l >= 0 && isspace( buf[l] ) ) {
		buf[l] = 0;
		--l;
	}

	if ( buf[0] )
		bdvmi::logger << bdvmi::DEBUG << ( File ? File : "(null)" ) << " : " << std::dec << Line << " " << buf
		              << std::flush;

#ifdef _DEBUG
	if ( buf[0] && debugOut_ )
		*debugOut_ << ( File ? File : "(null)" ) << " : " << Line << " " << buf << std::endl;
#endif

	return INT_STATUS_SUCCESS;
}

INTSTATUS IntrocoreManager::MemAllocWithTagAndInfo( void **Address, size_t Size, DWORD /* Tag */ )
{
	*Address = calloc( 1, Size );

	if ( *Address == nullptr )
		return INT_STATUS_UNSUCCESSFUL;

	return INT_STATUS_SUCCESS;
}

INTSTATUS IntrocoreManager::MemFreeWithTagAndInfo( void **Address, DWORD /* Tag */ )
{
	if ( Address ) {
		free( *Address );
		*Address = nullptr;
	}

	return INT_STATUS_SUCCESS;
}

//
// According to Andrei Luțaș, this callback is meant to help introcore avoid
// using too much RAM and thus being a target of the OOM killer. The logic
// behind it is tuned for the Xen SVA which implements guest mappings in an
// nifty way: they add up to the total RAM size instead of consuming it. It's
// actually transparent to the kernel (the stats in /proc/meminfo are not
// affected).
//
// On KVM, however, the guest mappings are actual anonymous mappings that add
// up to the total hvmi RSS, which in turn trips the memory usage employed by
// introcore. The option `disableQueryHeap` is meant to allow disabling the
// said logic and instead (coupled with the OOM killer being disabled for hvmi)
// rely on the kernel to free up as much as possible RAM by pushing all idle
// pages to swap.
//
INTSTATUS IntrocoreManager::QueryHeapSize( SIZE_T *TotalHeapSize, SIZE_T *FreeHeapSize )
{
	if ( !TotalHeapSize || !FreeHeapSize )
		return INT_STATUS_UNSUCCESSFUL;

	*TotalHeapSize = *FreeHeapSize = 0;

	std::ifstream in( "/proc/self/statm" );

	if ( !in )
		return INT_STATUS_UNSUCCESSFUL;

	SIZE_T vmsize = 0, rss, shared, text, lib, data = 0;

	in >> vmsize >> rss >> shared >> text >> lib >> data;

	if ( !vmsize )
		return INT_STATUS_UNSUCCESSFUL;

	data *= static_cast<size_t>( sysconf( _SC_PAGESIZE ) );

	struct rlimit limit;

	if ( getrlimit( RLIMIT_DATA, &limit ) )
		return INT_STATUS_UNSUCCESSFUL;

	if ( limit.rlim_cur != RLIM_INFINITY ) {
		*TotalHeapSize = limit.rlim_cur;

		if ( disableQueryHeap )
			*FreeHeapSize = *TotalHeapSize;
		else
			*FreeHeapSize = *TotalHeapSize - data;

		return INT_STATUS_SUCCESS;
	}

	std::ifstream minfo( "/proc/meminfo" );

	if ( !minfo )
		return INT_STATUS_UNSUCCESSFUL;

	std::string              line;
	static const std::string availStr = "MemAvailable:";
	static const std::string totalStr = "MemTotal:";

	while ( std::getline( minfo, line ) ) {
		if ( line.compare( 0, availStr.length(), availStr ) == 0 ) {
			std::stringstream ss( line.substr( availStr.length() ) );
			ss >> *FreeHeapSize;
			*FreeHeapSize *= 1024; // They give it in kb.
		} else if ( line.compare( 0, totalStr.length(), totalStr ) == 0 ) {
			std::stringstream ss( line.substr( totalStr.length() ) );
			ss >> *TotalHeapSize;
			*TotalHeapSize *= 1024; // They give it in kb.
		}

		// Short-circuit all the string parsing.
		if ( *TotalHeapSize != 0 && *FreeHeapSize != 0 ) {
			if ( disableQueryHeap )
				*FreeHeapSize = *TotalHeapSize;
			return INT_STATUS_SUCCESS;
		}
	}

	if ( *TotalHeapSize == 0 || *FreeHeapSize == 0 )
		return INT_STATUS_UNSUCCESSFUL;

	if ( disableQueryHeap )
		*FreeHeapSize = *TotalHeapSize;

	return INT_STATUS_SUCCESS;
}

void IntrocoreManager::IntEnterDebugger()
{
	bdvmi::logger << bdvmi::ERROR << "Introspection engine fatal error, shutting down" << std::flush;
	g_stop = 1;
}

INTSTATUS IntrocoreManager::InjectTrap( void *GuestHandle, DWORD CpuNumber, BYTE TrapNumber, DWORD ErrorCode,
                                        QWORD Cr2 )
{
	IntrocoreManager *pim = static_cast<IntrocoreManager *>( GuestHandle );

	if ( !pim )
		return INT_STATUS_UNSUCCESSFUL;

#ifndef NDEBUG
	bdvmi::logger << bdvmi::DEBUG << "Injecting trap " << std::hex << std::showbase << TrapNumber
	              << ", error code = " << ErrorCode << ", cr2 = " << Cr2 << std::flush;
#endif

	if ( CpuNumber == IG_CURRENT_VCPU )
		CpuNumber = pim->currentCpu_;

	if ( !pim->driver_.injectTrap( CpuNumber, TrapNumber, ErrorCode, Cr2 ) )
		return INT_STATUS_UNSUCCESSFUL;

	return INT_STATUS_SUCCESS;
}

bool IntrocoreManager::loadExceptions( const std::string &file )
{
	if ( file.empty() )
		return false;

	std::ifstream in( file.c_str(), std::ios::in | std::ios::binary );

	if ( !in ) {
		bdvmi::logger << bdvmi::ERROR << "Can't open exceptions file: " << file << std::flush;
		return false;
	}

	in.seekg( 0, in.end );
	int length = in.tellg();
	in.seekg( 0, in.beg );

	std::vector<char> buffer( length );

	in.read( &buffer[0], length );

	if ( !in ) {
		bdvmi::logger << bdvmi::ERROR << "Error reading exceptions file: " << file << std::flush;
		return false;
	}

	in.close();

	// It's either this conversion or manual specialization for vector<char>
	std::string            strBuffer( &buffer[0], buffer.size() );
	std::hash<std::string> hashFn;

	size_t newHash = hashFn( strBuffer );

	if ( newHash == exceptionsHash_ )
		return true;

	INTSTATUS ret = iface_.UpdateExceptions( this, reinterpret_cast<PBYTE>( &buffer[0] ), length, 0 );
	if ( !INT_SUCCESS( ret ) ) {
		bdvmi::logger << bdvmi::ERROR << "Couldn't set exceptions (format?) from file: " << file << std::flush;
		return false;
	}

	iface_.GetExceptionsVersion( this, &exceptionsVerMajor_, &exceptionsVerMinor_, &exceptionsBuildNo_ );

	bdvmi::logger << bdvmi::INFO << "Successfully loaded exceptions file: " << file << ", version: " << std::dec
	              << exceptionsVerMajor_ << "." << exceptionsVerMinor_ << "." << exceptionsBuildNo_ << std::flush;

	exceptionsHash_ = newHash;

	{
		std::lock_guard<std::mutex> guard( settings_.mutex_ );
		settings_.pendingViolations_ = true;
	}

	updateUserExclusions();

	return true;
}

INTSTATUS
IntrocoreManager::updateExceptions()
{
	if ( !introEnabled_ )
		return INT_STATUS_UNSUCCESSFUL;

	bool loaded = false;

	try {

		loaded = this->loadExceptions( settings_.exceptionsFile_ );

	} catch ( ... ) {
		return INT_STATUS_UNSUCCESSFUL;
	}

	if ( !loaded ) {
		bdvmi::logger << bdvmi::ERROR << "No exceptions file could be loaded, THIS WILL LEAD TO FALSE POSITIVES"
		              << std::flush;

		return INT_STATUS_UNSUCCESSFUL;
	}

	return INT_STATUS_SUCCESS;
}

void IntrocoreManager::updateUserExclusions()
{
	HvmiSettings localSettings;

	{
		std::lock_guard<std::mutex> guard( settings_.mutex_ );
		localSettings = settings_;
	}

	if ( !localSettings.pendingViolations_ )
		return;

	iface_.FlushAlertExceptions( this );

	for ( auto &&item : localSettings.violations_ ) {
		static unsigned long context = 0;

		static_assert( sizeof( item.violation ) >= ALERT_EXCEPTION_SIZE, "alert exception size mismatch" );
		INTSTATUS ret =
		    iface_.AddExceptionFromAlert( this, &item.violation, item.type, !!item.version, context++ );

		if ( !INT_SUCCESS( ret ) )
			bdvmi::logger << bdvmi::ERROR << "Failed to add exception from alert: " << std::hex
			              << std::showbase << ret << std::flush;
	}

	if ( !localSettings.violations_.empty() )
		bdvmi::logger << bdvmi::INFO << "Loaded user exceptions" << std::flush;

	std::lock_guard<std::mutex> guard( settings_.mutex_ );
	settings_.pendingViolations_ = false;
}

INTSTATUS IntrocoreManager::updateProtections()
{
	INTSTATUS ret = INT_STATUS_SUCCESS;

	if ( !introEnabled_ || !guestOSDetected_ || g_stop )
		return INT_STATUS_UNSUCCESSFUL;

	try {
		HvmiSettings localSettings;

		{
			std::lock_guard<std::mutex> guard( settings_.mutex_ );
			localSettings = settings_;
		}

		if ( !localSettings.umEnabled_ )
			return INT_STATUS_SUCCESS;

		for ( auto &&pps : localSettings.oldProtectedProcesses_ ) {
			// Remove old processes no longer protected
			if ( localSettings.protectedProcesses_.find( pps.first ) ==
			     localSettings.protectedProcesses_.end() ) {
				addRemProtectedProcessByOS( pps.first, 0, FALSE, 0 );
				bdvmi::logger << bdvmi::INFO << "Removing protection for process: " << pps.first
				              << std::flush;
			}
		}

		for ( auto &&pps : localSettings.protectedProcesses_ ) {

			auto i = localSettings.oldProtectedProcesses_.find( pps.first );

			if ( i != localSettings.oldProtectedProcesses_.end() )
				// Process already protected with the same flags
				if ( pps.second == i->second )
					continue;

			bdvmi::logger << bdvmi::INFO << ( pps.second.unprotect_ ? "Removing" : "Adding" )
			              << " protection for process: " << pps.first << " with flags: " << std::hex
			              << std::showbase << pps.second.flags_ << std::flush;

			ret = addRemProtectedProcessByOS( pps.first, ( DWORD )pps.second.flags_,
			                                  pps.second.unprotect_ ? FALSE : TRUE, pps.second.id_ );

			if ( !INT_SUCCESS( ret ) )
				bdvmi::logger << bdvmi::ERROR << "AddRemoveProtectedProcess() has failed: " << std::hex
				              << std::showbase << ret << std::flush;
		}

		std::lock_guard<std::mutex> guard( settings_.mutex_ );
		settings_.oldProtectedProcesses_ = settings_.protectedProcesses_;
	} catch ( ... ) {
		ret = INT_STATUS_UNSUCCESSFUL;
	}

	return ret;
}

INTSTATUS IntrocoreManager::updateLiveUpdate()
{
	INTSTATUS ret = INT_STATUS_UNSUCCESSFUL;

	try {
		std::string liveUpdateFile;

		{
			std::lock_guard<std::mutex> guard( settings_.mutex_ );
			liveUpdateFile = settings_.liveUpdateFile_;
		}

		PBYTE liveUpdateBuf  = nullptr;
		DWORD liveUpdateSize = 0;

		if ( mapLiveUpdateFile( liveUpdateFile, liveUpdateBuf, liveUpdateSize ) )
			return iface_.UpdateSupport( this, liveUpdateBuf, liveUpdateSize );
	} catch ( ... ) {
		ret = INT_STATUS_UNSUCCESSFUL;
	}

	return ret;
}

IntrocoreManager::PostEventAction IntrocoreManager::postEventAction()
{
	PostEventAction ret = postEventAction_;

	switch ( ret ) {
		case POST_EVENT_ACTION_INJECT_AGENT_KILLER:
		case POST_EVENT_ACTION_SET_PROTECTED_PROCESSES:
			postEventAction_ = POST_EVENT_ACTION_NONE;
			break;
		default:
			break;
	}

	return ret;
}

INTSTATUS
IntrocoreManager::updateIntrocoreOptions( const HvmiSettings &settings )
{
	if ( settings.introspectionOptions_ == introspectionOptions_ )
		return INT_STATUS_SUCCESS;

	INTSTATUS ret = iface_.ModifyDynamicOptions( this, settings.introspectionOptions_ );

	if ( INT_SUCCESS( ret ) )
		introspectionOptions_ = settings.introspectionOptions_;

	return ret;
}

INTSTATUS IntrocoreManager::NotifyIntrospectionActivated( void *GuestHandle )
{
	START_FAILING_IF_FUZZING();

	IntrocoreManager *pim = static_cast<IntrocoreManager *>( GuestHandle );

	pim->introActivated_        = true;
	pim->guestHookEventPending_ = true;

	return INT_STATUS_SUCCESS;
}

INTSTATUS IntrocoreManager::NotifyIntrospectionDetectedOs( void *GuestHandle, PGUEST_INFO GuestInfo )
{
	IntrocoreManager *pim = static_cast<IntrocoreManager *>( GuestHandle );

	if ( !pim || !GuestInfo )
		return INT_STATUS_UNSUCCESSFUL;

	pim->guestType_        = GuestInfo->Type;
	pim->guestVersion_     = GuestInfo->OsVersion;
	pim->guest64_          = !!GuestInfo->Guest64;
	pim->guestBuildNumber_ = GuestInfo->BuildNumber;
	pim->guestOSDetected_  = true;
	// GuestInfo->StartupTime is not yet available here.

	pim->postEventAction_ = POST_EVENT_ACTION_SET_PROTECTED_PROCESSES;

	return INT_STATUS_SUCCESS;
}

INTSTATUS IntrocoreManager::RequestVcpusPause( void *GuestHandle )
{
	IntrocoreManager *pim = static_cast<IntrocoreManager *>( GuestHandle );

	if ( !pim )
		return INT_STATUS_UNSUCCESSFUL;

	if ( !pim->driver_.pause() )
		return INT_STATUS_UNSUCCESSFUL;

	return INT_STATUS_SUCCESS;
}

INTSTATUS IntrocoreManager::RequestVcpusResume( void *GuestHandle )
{
	IntrocoreManager *pim = static_cast<IntrocoreManager *>( GuestHandle );

	if ( !pim )
		return INT_STATUS_UNSUCCESSFUL;

	if ( !pim->driver_.unpause() )
		return INT_STATUS_UNSUCCESSFUL;

	return INT_STATUS_SUCCESS;
}

INTSTATUS IntrocoreManager::RegisterDescriptorTableHandler( void *                                GuestHandle,
                                                            PFUNC_IntIntroDescriptorTableCallback Callback )
{
	IntrocoreManager *pim = static_cast<IntrocoreManager *>( GuestHandle );

	if ( !pim )
		return INT_STATUS_UNSUCCESSFUL;

	if ( !pim->eventManager_.enableDescriptorEvents() )
		return INT_STATUS_UNSUCCESSFUL;

	pim->descriptorCallback_ = Callback;

	return INT_STATUS_SUCCESS;
}

INTSTATUS IntrocoreManager::UnregisterDescriptorTableHandler( void *GuestHandle )
{
	IntrocoreManager *pim = static_cast<IntrocoreManager *>( GuestHandle );

	if ( !pim )
		return INT_STATUS_UNSUCCESSFUL;

	if ( !pim->eventManager_.disableDescriptorEvents() )
		return INT_STATUS_UNSUCCESSFUL;

	pim->descriptorCallback_ = nullptr;

	return INT_STATUS_SUCCESS;
}

INTSTATUS IntrocoreManager::SetIntroEmulatorContext( void *GuestHandle, DWORD /* CpuNumber */, QWORD VirtualAddress,
                                                     DWORD BufferSize, PBYTE Buffer )
{
	IntrocoreManager *pim = static_cast<IntrocoreManager *>( GuestHandle );

	if ( !pim )
		return INT_STATUS_UNSUCCESSFUL;

	uint32_t size = sizeof( pim->emulatorCtx_.data_ );

	if ( BufferSize < size )
		size = BufferSize;

	pim->emulatorCtx_.address_ = VirtualAddress;
	pim->emulatorCtx_.size_    = size;
	memcpy( pim->emulatorCtx_.data_, Buffer, size );

	return INT_STATUS_SUCCESS;
}

INTSTATUS IntrocoreManager::GetAgentContent( void * /* GuestHandle */, DWORD /* AgentTag */, BOOLEAN /* Is64 */,
                                             DWORD * /* Size */, PBYTE * /* Content */ )
{
	return INT_STATUS_UNSUCCESSFUL;
}

INTSTATUS IntrocoreManager::ToggleRepOptimization( void *GuestHandle, BOOLEAN Enable )
{
	IntrocoreManager *pim = static_cast<IntrocoreManager *>( GuestHandle );

	if ( !pim )
		return INT_STATUS_UNSUCCESSFUL;

	if ( pim->driver_.setRepOptimizations( !!Enable ) )
		return INT_STATUS_SUCCESS;

	return INT_STATUS_UNSUCCESSFUL;
}

INTSTATUS IntrocoreManager::NotifyIntrospectionDeactivated( void * /* GuestHandle */ )
{
	g_stop = 1;

	return INT_STATUS_SUCCESS;
}

INTSTATUS IntrocoreManager::RegisterEventInjectionHandler( void *GuestHandle, PFUNC_IntEventInjectionCallback Callback )
{
	IntrocoreManager *pim = static_cast<IntrocoreManager *>( GuestHandle );

	if ( !pim )
		return INT_STATUS_UNSUCCESSFUL;

	pim->injectionCallback_ = Callback;

	return INT_STATUS_SUCCESS;
}

INTSTATUS IntrocoreManager::NotifyIntrospectionErrorState( void *GuestHandle, INTRO_ERROR_STATE Error,
                                                           PINTRO_ERROR_CONTEXT Context )
{
	IntrocoreManager *pim = static_cast<IntrocoreManager *>( GuestHandle );

	if ( !pim )
		return INT_STATUS_UNSUCCESSFUL;

	switch ( Error ) {
		case intErrProcNotProtectedNoMemory:
			bdvmi::logger << bdvmi::WARNING << "Out of memory: can't protect process "
			              << Context->ProcessProtection.Process.ImageName << " (pid " << std::dec
			              << Context->ProcessProtection.Process.Pid << ")" << std::flush;
			break;
		case intErrProcNotProtectedInternalError:
			bdvmi::logger << bdvmi::WARNING << "Internal error: can't protect process "
			              << Context->ProcessProtection.Process.ImageName << " (pid " << std::dec
			              << Context->ProcessProtection.Process.Pid << ")" << std::flush;
			break;
		default:
			break;
	}

	pim->introActivated_        = false;
	pim->introErrorState_       = errorStateToString( Error );
	pim->guestHookEventPending_ = true;

	return INT_STATUS_SUCCESS;
}

INTSTATUS IntrocoreManager::UnregisterEventInjectionHandler( void *GuestHandle )
{
	IntrocoreManager *pim = static_cast<IntrocoreManager *>( GuestHandle );

	if ( !pim )
		return INT_STATUS_UNSUCCESSFUL;

	pim->injectionCallback_ = nullptr;

	return INT_STATUS_SUCCESS;
}

INTSTATUS IntrocoreManager::ReleaseBuffer( void *GuestHandle, void *AgentContent, DWORD AgentSize )
{
	if ( !GuestHandle || !AgentContent || !AgentSize )
		return INT_STATUS_UNSUCCESSFUL;

	munmap( AgentContent, AgentSize );

	return INT_STATUS_SUCCESS;
}

INTSTATUS IntrocoreManager::NotifyScanEngines( void * /* GuestHandle */, void * /* Parameters */ )
{
	return INT_STATUS_NOT_SUPPORTED;
	;
}

bool IntrocoreManager::startTimer()
{
	if ( timerThread_.joinable() ) // already running
		return false;

	stopTimer_ = false;

	// Move-construct the thread
	timerThread_ = std::thread( &IntrocoreManager::introTimerCallback, this );

	return true;
}

void IntrocoreManager::notifySessionOver( bdvmi::GuestState guestState )
{
	guestNotRunning_ = ( guestState == bdvmi::POST_SHUTDOWN );

	if ( guestState == bdvmi::RUNNING )
		return;

	IG_GUEST_POWER_STATE powerState = intGuestPowerStateShutDown;

	if ( guestState == bdvmi::SHUTDOWN_IN_PROGRESS )
		powerState = intGuestPowerStateTerminating;

	// Tell introcore to not bother to uninit - the guest has already vanished.
	iface_.NotifyGuestPowerStateChange( this, powerState );
}

void IntrocoreManager::introTimerCallback()
{
	while ( !stopTimer_ ) {
		PFUNC_IntIntroTimerCallback callback = timerCallback_;

		if ( callback )
			callback( this );

		time_t now = time( nullptr );

		if ( now > lastStateUpdate_ + 120 ) {
			driver_.update();
			lastStateUpdate_ = now;
		}

		sleep( 1 ); // YAYEY!
	}
}

unsigned short IntrocoreManager::currentInstructionLength( unsigned short vcpu )
{
	BYTE insnLen = 0;

	INTSTATUS ret = iface_.GetCurrentInstructionLength( this, vcpu, &insnLen );

	if ( INT_SUCCESS( ret ) )
		return insnLen;

	if ( ret == INT_STATUS_PAGE_NOT_PRESENT || ret == INT_STATUS_NO_MAPPING_STRUCTURES )
		return 0;
	else
		return 1;
}

void IntrocoreManager::saveLastEvent( INTRO_EVENT_TYPE eventType, void *event, const std::string &eventUUID )
{
	// Flags it at the same offset for all violation events, just using the EPT one for convenience
	EVENT_EPT_VIOLATION *dummy = ( EVENT_EPT_VIOLATION * )event;

	switch ( eventType ) {
		case introEventEptViolation:
		case introEventInjectionViolation:
		case introEventTranslationViolation:
		case introEventMsrViolation:
		case introEventIntegrityViolation:
		case introEventCrViolation:
		case introEventXcrViolation:
		case introEventDtrViolation:
		case introEventProcessCreationViolation:
		case introEventModuleLoadViolation:
			isLastEventInUserspace_ = ( ( dummy->Header.Flags & ALERT_FLAG_NOT_RING0 ) != 0 );
			break;
		default:
			break;
	}

	if ( violationAgentsPending_ )
		return; // A violation event triggered on-violation agents injection.

	lastEvent_.actionTaken = PA_LOG;
	lastEvent_.eventUUID   = eventUUID;

	switch ( eventType ) {
		case introEventEptViolation:
			lastEvent_.event.eptViolation = *( PEVENT_EPT_VIOLATION )event;
			break;
		case introEventInjectionViolation:
			lastEvent_.event.memCopyViolation = *( PEVENT_MEMCOPY_VIOLATION )event;
			break;
		case introEventTranslationViolation:
			lastEvent_.event.translationViolation = *( PEVENT_TRANSLATION_VIOLATION )event;
			break;
		case introEventMsrViolation:
			lastEvent_.event.msrViolation = *( PEVENT_MSR_VIOLATION )event;
			break;
		case introEventIntegrityViolation:
			lastEvent_.event.integrityViolation = *( PEVENT_INTEGRITY_VIOLATION )event;
			break;
		case introEventCrViolation:
			lastEvent_.event.crViolation = *( PEVENT_CR_VIOLATION )event;
			break;
		case introEventXcrViolation:
			lastEvent_.event.xcrViolation = *( PEVENT_XCR_VIOLATION )event;
			break;
		case introEventDtrViolation:
			lastEvent_.event.dtrViolation = *( PEVENT_DTR_VIOLATION )event;
			break;
		case introEventProcessCreationViolation:
			lastEvent_.event.processCreationViolation = *( PEVENT_PROCESS_CREATION_VIOLATION )event;
			break;
		case introEventModuleLoadViolation:
			lastEvent_.event.moduleLoadViolation = *( PEVENT_MODULE_LOAD_VIOLATION )event;
			break;
		case introEventEnginesDetectionViolation:
			lastEvent_.event.enginesDetectionViolation = *( PEVENT_ENGINES_DETECTION_VIOLATION )event;
			break;
		case introEventMessage:
		// Not saving these, as what we're saving serves as context for
		// introspection agent events, and messages can't trigger agent
		// injection. Fall-through.
		case introEventProcessEvent:
		// Not saving these, as what we're saving serves as context for
		// introspection agent events, and process events can't trigger
		// agent injection. Fall-through.
		case introEventAgentEvent:
		// Not saving these, as what we're saving serves as context for
		// introspection agent events, and here it would be pointless.
		case introEventModuleEvent:
		case introEventCrashEvent:
		case introEventExceptionEvent:
		case introEventConnectionEvent:
			return;
	}

	lastEvent_.eventType = eventType;
}

std::string IntrocoreManager::generateEventUUID( INTRO_EVENT_TYPE eventType ) const
{
	switch ( eventType ) {
		case introEventEptViolation:
		case introEventInjectionViolation:
		case introEventTranslationViolation:
		case introEventMsrViolation:
		case introEventIntegrityViolation:
		case introEventCrViolation:
		case introEventXcrViolation:
		case introEventDtrViolation:
		case introEventConnectionEvent:
		case introEventModuleLoadViolation:
		case introEventProcessCreationViolation:
		case introEventEnginesDetectionViolation:
			return newUUID();
		default:
			break;
	}

	return "";
}

void IntrocoreManager::getStartupTime()
{
	if ( guestStartupTime_ != IG_INVALID_TIME || !isGuestWindows() )
		return;

	GUEST_INFO guestInfo;

	INTSTATUS ret = iface_.GetGuestInfo( this, &guestInfo );
	if ( INT_SUCCESS( ret ) )
		guestStartupTime_ = guestInfo.StartupTime;
}

void IntrocoreManager::processLogAgentEvent( const PEVENT_AGENT_EVENT info )
{
	namespace fs = std::experimental::filesystem;

	static constexpr int WIN_ERROR_FILE_NOT_FOUND = 0x2;
	static constexpr int WIN_ERROR_PATH_NOT_FOUND = 0x3;

	// TODO: this might be spammy - will log an event for every log file chunk sent from the guest.
	if ( availableLogDiskSpace_ || info->Event != agentMessage )
		bdvmi::logger << bdvmi::DEBUG << "BDINT [log tool]: state = " << agentEventToString( info->Event )
		              << ", error code: " << std::dec << static_cast<int>( info->ErrorCode ) << std::flush;

	switch ( info->Event ) {
		case agentTerminated:
		case agentError:
			cancellingLogExtraction_ = false;
			signalAgentFinished();
			return;
		case agentStarted:
			return;
		case agentMessage:
			break; // Handled below.
		case agentInjected:
		case agentInitialized:
		case agentInvalid:
		default:
			return; // We only care about agentMessage going forward.
	}

	switch ( info->LogGatherEvent.Header.EventType ) {
		case lgtEventData:
			break;
		case lgtEventError:
			if ( isGuestWindows() ) {
				switch ( info->LogGatherEvent.ErrorEvent.ErrorCode ) {
					case WIN_ERROR_FILE_NOT_FOUND:
					case WIN_ERROR_PATH_NOT_FOUND:
					default:
						break;
				}
			} else {
				switch ( info->LogGatherEvent.ErrorEvent.ErrorCode ) {
					case ENOENT:
					default:
						break;
				}
			}
			return;
		default:
			return;
	}

	std::string fileName = logsDir_ + "/" + utf16ToUtf8( info->LogGatherEvent.DataEvent.FileName );

	if ( availableLogDiskSpace_ ) {
		fs::space_info si = fs::space( logsDir_ );

		if ( si.available < 512 * 1024 * 1204 ) { // Less than 512MB.
			bdvmi::logger << bdvmi::WARNING
			              << "BDINT [log tool]: not enough disk space, cancelling log collection for file "
			              << fileName << std::flush;
			availableLogDiskSpace_   = false;
			cancellingLogExtraction_ = true;
			postEventAction_         = POST_EVENT_ACTION_INJECT_AGENT_KILLER;
		}
	}

	if ( !availableLogDiskSpace_ )
		return;

	std::ofstream out( fileName.c_str(), std::ios_base::out | std::ios_base::binary | std::ios_base::app );

	bdvmi::logger << bdvmi::DEBUG << "BDINT [log tool]: opening file " << fileName << " "
	              << ( !out ? "failed" : "succeeded" ) << ", about to write " << std::dec
	              << info->LogGatherEvent.DataEvent.DataSize << " bytes" << std::flush;
	if ( !out )
		return;

	out.write( reinterpret_cast<const char *>( info->LogGatherEvent.DataEvent.Data ),
	           info->LogGatherEvent.DataEvent.DataSize );
}

void IntrocoreManager::processAgentKillerEvent( const PEVENT_AGENT_EVENT info )
{
	long errorCode = ( isGuestWindows() ? static_cast<unsigned int>( info->ErrorCode ) : info->ErrorCode );

	bdvmi::logger << bdvmi::DEBUG << "BDINT [agent killer]: state = " << agentEventToString( info->Event )
	              << ", error code: " << std::dec << errorCode << std::flush;

	switch ( info->Event ) {
		case agentStarted:
			killerStarted_ = true;
			break;
		case agentInjected:
			killerInjected_ = true;
			break;
		case agentInitialized:
			killerInitialized_ = true;
			break;
		case agentTerminated:
		case agentError:
		case agentMessage:
		case agentInvalid:
		default:
			break;
	}

	if ( !cancellingLogExtraction_ && killerInjected_ && killerInitialized_ && killerStarted_ )
		signalAgentFinished();
}

void IntrocoreManager::processCustomAgentEvent( const PEVENT_AGENT_EVENT info )
{
	long errorCode = ( isGuestWindows() ? static_cast<unsigned int>( info->ErrorCode ) : info->ErrorCode );

	bdvmi::logger << bdvmi::DEBUG << "BDINT [custom tool]: state = " << agentEventToString( info->Event )
	              << ", error code: " << std::dec << errorCode << std::flush;

	switch ( info->Event ) {
		case agentTerminated:
		case agentError:
			signalAgentFinished();
			break;
		case agentStarted:
			break;
		case agentInjected:
		case agentInitialized:
		case agentMessage:
		case agentInvalid:
		default:
			break;
	}
}

bool IntrocoreManager::mapFile( const std::string &filename, PBYTE &bytes, DWORD &size ) const
{
	struct stat st;

	if ( stat( filename.c_str(), &st ) != 0 ) {
		bdvmi::logger << bdvmi::WARNING << "Error getting file size for " << filename << " ("
		              << strerror( errno ) << ")" << std::flush;
		return false;
	}

	size = st.st_size;

	int fd = open( filename.c_str(), O_RDONLY );

	if ( fd == -1 ) {
		bdvmi::logger << bdvmi::WARNING << "Error opening file " << filename << " (" << strerror( errno ) << ")"
		              << std::flush;
		return false;
	}

	void *mapping = mmap( nullptr, st.st_size, PROT_READ, MAP_SHARED, fd, 0 );

	close( fd );

	if ( mapping == MAP_FAILED ) {
		bdvmi::logger << bdvmi::WARNING << "Error mapping file " << filename << " (" << strerror( errno ) << ")"
		              << std::flush;
		return false;
	}

	bytes = static_cast<PBYTE>( mapping );

	return true;
}

std::string IntrocoreManager::stdoutFile() const
{
	if ( isGuestWindows() )
		return "%TEMP%\\output.log";

	return "/tmp/output.log";
}

void IntrocoreManager::waitForAgent( int timeout )
{
	std::unique_lock<std::mutex> lock( cvMutex_ );

	if ( timeout == 0 )
		cv_.wait( lock, [this] { return !isAgentRunning_; } );
	else
		cv_.wait_for( lock, std::chrono::seconds( timeout ), [this] { return !isAgentRunning_; } );
}

void IntrocoreManager::signalAgentFinished()
{
	{ // lock scope
		std::unique_lock<std::mutex> lock( cvMutex_ );
		isAgentRunning_ = false;
	}

	cv_.notify_one();
}

void IntrocoreManager::processVerdict( const void *info, HvmiEventHandler::Action &action, PrimaryAction &actionTaken )
{
	const PEVENT_EPT_VIOLATION dummy = ( PEVENT_EPT_VIOLATION )info;

	if ( dummy->Header.Action != introGuestNotAllowed )
		return;

	// System processes are earmarked by introcore. It makes no sense to search in our list
	// of "regular" protected processes.
	if ( dummy->Header.Flags & ALERT_FLAG_SYSPROC ) {
		if ( dummy->Header.Flags & ( ALERT_FLAG_FEEDBACK_ONLY | ALERT_FLAG_BETA ) ) {
			action      = HvmiEventHandler::ACT_ALLOW;
			actionTaken = PA_LOG;
		} else {
			// Introcore has already killed the process / taken action.
			// Might as well tell log that that's the case (event if that's post-factum).
			action      = HvmiEventHandler::ACT_SKIP;
			actionTaken = PA_DENY;
		}
	} else
		settings_.getAction( isLastEventInUserspace(), lastEventProcessId(), action, actionTaken );

	lastEvent_.actionTaken = actionTaken;

	if ( action == HvmiEventHandler::ACT_SHUTDOWN && ( dummy->Header.Flags & ALERT_FLAG_BETA ) == 0 ) {
		bdvmi::logger << bdvmi::INFO << "Shutting the domain down" << std::flush;
		driver_.shutdown();
	}
}

void IntrocoreManager::setTaskAgent( const Tool &agent )
{
	std::lock_guard<std::mutex> lock( activeAgentMutex_ );

	generateToolLogDir( agent );

	isTaskAgentActive_ = true;
	taskAgent_         = agent;
}

bool IntrocoreManager::taskAgent( Tool &agent )
{
	std::lock_guard<std::mutex> lock( activeAgentMutex_ );

	if ( !isTaskAgentActive_ )
		return false;

	agent = taskAgent_;

	return true;
}

void IntrocoreManager::resetTaskAgent()
{
	std::lock_guard<std::mutex> lock( activeAgentMutex_ );

	isTaskAgentActive_ = false;
}

std::string IntrocoreManager::logsDirTimestamp() const
{
	std::lock_guard<std::mutex> lock( activeAgentMutex_ );

	return logsDirTimestamp_;
}

void IntrocoreManager::reportOnTask( unsigned status, long errorCode )
{
	Tool t;

	if ( !taskAgent( t ) )
		return;

	toolError( errorCode );

	ToolStatusHelper tsh( DOMAIN_UUID, sessionId_, t, settings_.internalFeedback_, false );
	tsh.errorCode( errorCode );
	tsh.reportStatus( status );
}

bool IntrocoreManager::generateToolLogDir( const Tool &tool )
{
	namespace fs = std::experimental::filesystem;

	logsDirTimestamp_ = std::string( "not yet son" );

	logsDir_ = "./logs/" + domainUuid_ + "_" + domainName_ + "/" + tool.toolName_ + "_" +
	    tool.toolId_; // TODO: Add timestamp.

	std::error_code ec;

	if ( !fs::exists( logsDir_, ec ) ) {
		fs::create_directories( logsDir_, ec );

		if ( ec ) {
			bdvmi::logger << bdvmi::WARNING << "Error creating logs directory " << logsDir_ << " for tool "
			              << tool.toolId_ << ": " << ec.message() << std::flush;
			return false;
		}
	}

	bdvmi::logger << bdvmi::DEBUG << "Created log directory at: " << logsDir_ << std::flush;

	return true;
}

void IntrocoreManager::debugCommandsCallback()
{
	using namespace std;

	string inPipe = "/tmp/" + domainUuid_ + ".fifo.in";

	remove( inPipe.c_str() );

	if ( mkfifo( inPipe.c_str(), S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP ) ) {
		bdvmi::logger << bdvmi::ERROR << "Could not create debug input pipe! Aborting" << std::flush;
		return;
	}

	struct pollfd fd           = {};
	constexpr int timeoutMsecs = 500;

	fd.fd     = open( inPipe.c_str(), O_RDONLY | O_NONBLOCK );
	fd.events = POLLIN | POLLERR;

	if ( fd.fd < 0 ) {
		bdvmi::logger << bdvmi::WARNING << "Failed to open debug pipe: " << strerror( errno ) << std::flush;
		remove( inPipe.c_str() );
		return;
	}

	string content;

	while ( !stopDebugCommandsThread_ && !g_stop ) {
		int ret = poll( &fd, 1, timeoutMsecs );

		if ( ret < 0 ) {
			bdvmi::logger << bdvmi::WARNING << "Debug pipe poll() fail: " << strerror( errno )
			              << std::flush;
			break;
		}

		if ( ret > 0 && fd.revents & POLLIN ) {
			char buffer[256];

			do {
				ret = read( fd.fd, buffer, sizeof( buffer ) );

			} while ( ret < 0 && errno == EINTR && !stopDebugCommandsThread_ && !g_stop );

			if ( ret < 0 ) {
				bdvmi::logger << bdvmi::WARNING << "Debug pipe read() fail: " << strerror( errno )
				              << std::flush;
				break;
			}

			if ( ret ) {
				content.append( buffer, static_cast<size_t>( ret ) );

				size_t pos;

				while ( ( pos = content.find( '\n' ) ) != string::npos ) {
					std::string command = content.substr( 0, pos );
					content             = content.substr( pos + 1 );

					trim( command );

					if ( command.empty() ) // Just whitespace between newlines
						continue;

					if ( command == "trace" )
						bdvmi::logger.trace( true );
					else if ( command == "notrace" )
						bdvmi::logger.trace( false );
					else if ( command == "stats" )
						bdvmi::StatsCollector::instance().enable( true );
					else if ( command == "nostats" )
						bdvmi::StatsCollector::instance().enable( false );
					else if ( command == "dumpstats" )
						bdvmi::StatsCollector::instance().dump();
					else if ( command[0] == '!' )
						runIntroCommand( command );
					else
						bdvmi::logger << bdvmi::WARNING
						              << "Unsupported debug command received: " << command
						              << std::flush;
				}
			}
		}
	}

	close( fd.fd );
	remove( inPipe.c_str() );
}

void IntrocoreManager::cacheRegs( unsigned short vcpu, const bdvmi::Registers &regs )
{
	if ( vcpuRegsCache_.size() <= vcpu )
		vcpuRegsCache_.resize( vcpu + 1 );

	currentCpu_          = vcpu;
	vcpuRegsCache_[vcpu] = std::make_pair( true, regs );
}

void IntrocoreManager::engineScanComplete( void *ctx, void *param, const char *detection, const char *enginesVersion )
{
	IntrocoreManager *pim = static_cast<IntrocoreManager *>( ctx );
	HvmiSettings      localSettings;

	{
		std::lock_guard<std::mutex> guard( pim->settings_.mutex_ );
		localSettings = pim->settings_;
	}

	PENG_NOTIFICATION_HEADER header    = static_cast<PENG_NOTIFICATION_HEADER>( param );
	std::string              eventUUID = pim->generateEventUUID( introEventEnginesDetectionViolation );

	if ( header->Type == introEngineNotificationCodeExecution || header->Type == introEngineNotificationCmdLine ) {
		if ( detection ) {
			snprintf( header->DetectionName, sizeof( header->DetectionName ), "%s", detection );
			snprintf( header->EnginesVersion, sizeof( header->EnginesVersion ), "%s", enginesVersion );
			header->RequestedAction = introGuestNotAllowed;
		} else {
			std::memset( header->DetectionName, 0, sizeof( header->DetectionName ) );
			std::memset( header->EnginesVersion, 0, sizeof( header->EnginesVersion ) );
			header->RequestedAction = introGuestAllowed;
		}

		INTSTATUS                           ret      = INT_STATUS_SUCCESS;
		PFUNC_IntEventEnginesResultCallback callback = pim->enginesResultCallback_;

		if ( callback )
			ret = callback( pim, header );

		if ( !INT_SUCCESS( ret ) )
			bdvmi::logger << bdvmi::WARNING << "the engines result callback has failed: " << std::hex
			              << std::showbase << ret << std::flush;
	}
}

INTSTATUS IntrocoreManager::RegisterEnginesResultCallback( void *                              GuestHandle,
                                                           PFUNC_IntEventEnginesResultCallback Callback )
{
	IntrocoreManager *pim = static_cast<IntrocoreManager *>( GuestHandle );

	if ( !pim )
		return INT_STATUS_UNSUCCESSFUL;

	pim->enginesResultCallback_ = Callback;

	return INT_STATUS_SUCCESS;
}

INTSTATUS IntrocoreManager::UnregisterEnginesResultCalback( void *GuestHandle )
{
	IntrocoreManager *pim = static_cast<IntrocoreManager *>( GuestHandle );

	if ( !pim )
		return INT_STATUS_UNSUCCESSFUL;

	pim->enginesResultCallback_ = nullptr;

	return INT_STATUS_SUCCESS;
}

void IntrocoreManager::sendGuestHookEvent()
{
	if ( !guestHookEventPending_ || !iface_.GetVersionString )
		return;

	guestHookEventPending_ = false;

	char fullString[256]{};
	char versionString[128]{};

	INTSTATUS ret =
	    iface_.GetVersionString( sizeof( fullString ), sizeof( versionString ), fullString, versionString );
	if ( !INT_SUCCESS( ret ) )
		return;

	DWORD cpuCount = 0;
	ret            = IntQueryGuestInfo( this, IG_QUERY_INFO_CLASS_CPU_COUNT, ( void * )IG_CURRENT_VCPU, &cpuCount,
                                 sizeof( cpuCount ) );
	if ( !INT_SUCCESS( ret ) )
		return;

	QWORD maxGpfn = 0;
	ret           = IntQueryGuestInfo( this, IG_QUERY_INFO_CLASS_MAX_GPFN, ( void * )IG_CURRENT_VCPU, &maxGpfn,
                                 sizeof( maxGpfn ) );
	if ( !INT_SUCCESS( ret ) )
		return;
}
