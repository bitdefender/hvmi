/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include <algorithm>
#include "hvmidomainhandler.h"
#include "hvmidaemon.h"
#include "hvmieventhandler.h"
#include "hvmisettings.h"
#include "hvmitooltask.h"
#include <experimental/filesystem>
#include "introcoremanager.h"
#include <bdvmi/backendfactory.h>
#include <bdvmi/domainwatcher.h>
#include <bdvmi/eventmanager.h>
#include <bdvmi/logger.h>
#include <fstream>
#include <libgen.h>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <stdio.h>
#include <strings.h>
#include <sys/sendfile.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* Did we receive a HUP? */
sig_atomic_t             g_reload    = 0;
sig_atomic_t             g_introInit = 0;
extern sig_atomic_t      g_stop;
extern IntrocoreManager *g_guestHandle;

namespace {

struct sigaction aoact, soact;

const unsigned int HARDWARE_CONCURRENCY = std::max( std::thread::hardware_concurrency(), 2U );

void close_handler( int sig )
{
	g_stop = sig;

	if ( !g_introInit )
		return;

	// Cache it so it doesn't become nullptr behind our backs
	IntrocoreManager *im = g_guestHandle;

	if ( im )
		// introcore only sets a variable here, so safe in signal handler
		im->setAbortStatus( true );
}

void reload_handler( int sig )
{
	g_reload = ( sig_atomic_t )sig;
}

void dummy_handler( int, siginfo_t *, void * )
{
	// nothing
}

void intro_init_crash_handler( int )
{
	// Restore previous (breakpad) handler.
	sigaction( SIGSEGV, &soact, nullptr );
	sigaction( SIGABRT, &aoact, nullptr );

	abort();
}

class RAIIDirRemover {

public:
	explicit RAIIDirRemover( const std::string &dir )
	    : dir_{ dir }
	{
	}

	~RAIIDirRemover()
	{
		namespace fs = std::experimental::filesystem;

		std::error_code ec;
		fs::remove_all( dir_, ec );
	}

	RAIIDirRemover( const RAIIDirRemover & ) = delete;
	RAIIDirRemover &operator=( const RAIIDirRemover & ) = delete;

private:
	std::string dir_;
};

} // end of anonymous namespace

HvmiDomainHandler::HvmiDomainHandler( HvmiSettings &settings, bdvmi::DomainWatcher *dw )
    : settings_{ settings }
    , dw_{ dw }
{
	bdvmi::logger << bdvmi::INFO << "Hardware concurrency: " << std::dec << HARDWARE_CONCURRENCY << std::flush;

	startSignalThread();
	processDomainsThread_.start( &HvmiDomainHandler::processDomainsCallback, this );
}

HvmiDomainHandler::~HvmiDomainHandler()
{
	// Make sure threads are join()ed, otherwise the thread destructor will throw.
	processDomainsThread_.stop( [&] {
		g_stop = 1;
		pendingDomainsCV_.notify_one();
	} );

	if ( exitTimeoutThread_.joinable() ) {
		stopStuckChildrenThread_ = true;
		stuckChildrenCV_.notify_one();
		exitTimeoutThread_.join();
	}

	collectChildProcesses();
}

void HvmiDomainHandler::startExitTimeoutThread( int seconds )
{
	exitTimeoutThread_ = std::thread( &HvmiDomainHandler::killChildrenCallback, this, seconds );
}

void HvmiDomainHandler::collectChildProcesses( bool stopThread )
{
	if ( stopThread && !signalThread_.stop( [&] { g_stop = 1; } ) )
		return;

	int   status;
	pid_t pid;
	int   options = ( stopThread ? 0 : WNOHANG );

	// collect child status
	while ( ( pid = waitpid( static_cast<pid_t>( -1 ), &status, options ) ) > 0 ) {
		std::string uuid;
		bool        foundUUID = getUuid( pid, uuid );

		if ( !WIFEXITED( status ) ) {
			bdvmi::logger << bdvmi::ERROR << "process " << std::dec << pid << " crashed" << std::flush;

			if ( foundUUID )
				bdvmi::logger << bdvmi::DEBUG << "Domain status: introspection crashed" << std::flush;
		}

		if ( dw_ )
			dw_->diedHandler( uuid );

		removePid( pid );
	}
}

void HvmiDomainHandler::handleDomainFound( const std::string &uuid, const std::string &name )
{
	addPendingDomain( uuid, name, nullptr );
}

void HvmiDomainHandler::handleDomainFinished( const std::string &uuid )
{
	removePendingDomain( uuid );

	std::lock_guard<std::mutex> guard( allDomainsMutex_ );

	bdvmi::logger << bdvmi::INFO << "[" << uuid << "] Domain finished" << std::flush;
	allDomains_.erase( uuid );
}

void HvmiDomainHandler::cleanup( bool /* suspendIntrospectorDomain */ )
{
	bdvmi::logger << bdvmi::INFO << "Done waiting for domains" << std::flush;

	// if ( suspendIntrospectorDomain && xreg_set_string( "/Temp/MIDaemon/Suspending", "on" ) != XREGERR_OK )
	// 	bdvmi::logger << bdvmi::ERROR << "The /Suspending key has not been set" << std::flush;
}

bool HvmiDomainHandler::loadPolicy( const std::string &uuid, HvmiSettings &settings, bool log,
                                    bool /* sendApplied */ ) const
{
	bool ret;

	ret = settings.loadVmPolicy( uuid );

	if ( !ret && log )
		bdvmi::logger << bdvmi::WARNING << "[" << uuid << "] No policy available for domain" << std::flush;

	if ( settings_.policyOnly_ && !ret ) {
		if ( log )
			bdvmi::logger << bdvmi::WARNING << "[" << uuid << "] Won't hook unlicensed domain"
			              << std::flush;

		return false;
	}

	if ( ret && !settings.enabled_ && log )
		bdvmi::logger << bdvmi::WARNING << "[" << uuid
		              << "] The domain policy disables introspection, won't hook it" << std::flush;
	return true;
}

void HvmiDomainHandler::handleDomain( const std::string &uuid, const std::string &name, const HvmiSettings *settings )
{
	HvmiSettings domainSpecificSettings( settings_ );

	try {
		bdvmi::logger << bdvmi::INFO << "[" << uuid << "] Found domain: '" << name << "'" << std::flush;

		if ( shouldIgnore( name ) ) {
			bdvmi::logger << bdvmi::INFO << "[" << uuid << "] Domain '" << name
			              << "' is in the ignore list, won't hook it" << std::flush;
			return;
		}

		if ( !settings ) {
			bool license  = licensed( uuid );
			bool goodToGo = false;

			if ( !license )
				bdvmi::logger << bdvmi::WARNING << "[" << uuid << "] Domain '" << uuid
				              << "' is unlicensed, won't hook it" << std::flush;
			else
				goodToGo = ( loadPolicy( uuid, domainSpecificSettings, true ) &&
				             domainSpecificSettings.enabled_ );

			std::lock_guard<std::mutex> guard( allDomainsMutex_ );

			DomainInfo info( goodToGo, domainSpecificSettings, name );
			allDomains_[uuid] = info;

			if ( !goodToGo )
				return;
		} else
			domainSpecificSettings = *settings;
	} catch ( const std::exception &e ) {
		bdvmi::logger << bdvmi::ERROR << "[" << uuid
		              << "] Could not retrieve domain-specific settings: " << e.what() << std::flush;
	} catch ( ... ) {
		bdvmi::logger << bdvmi::ERROR << "[" << uuid << "] Could not retrieve domain-specific settings"
		              << std::flush;
	}

	if ( dw_ )
		dw_->forkingHandler( uuid );

#ifndef DISABLE_FORK_CHILDREN

	pid_t pid = fork();

	if ( pid == -1 ) {
		bdvmi::logger << bdvmi::ERROR << "[" << uuid << "] fork() failed: " << strerror( errno ) << std::flush;
		bdvmi::logger << bdvmi::ERROR << "[" << uuid << "] Can't start watching the domain" << std::flush;

		return;
	}

	if ( pid ) { // parent
		if ( dw_ )
			dw_->forkedHandler( uuid );

		addPid( pid, uuid );

		return;
	}

	if ( dw_ )
		dw_->forkedHandler( uuid, false );
#endif

	// child process
	g_stop = 0;

#ifndef DISABLE_FORK_CHILDREN
	// set signal handler
	struct sigaction act {
	};

	act.sa_handler = close_handler;
	sigemptyset( &act.sa_mask );

	sigaction( SIGTERM, &act, nullptr );
	sigaction( SIGINT, &act, nullptr );
	sigaction( SIGALRM, &act, nullptr );

	act.sa_handler = reload_handler;
	sigaction( SIGHUP, &act, nullptr );

	act.sa_handler = SIG_IGN;
	act.sa_flags   = SA_NOCLDWAIT;
	sigaction( SIGCHLD, &act, nullptr );
#endif

	if ( setpriority( PRIO_PROCESS, 0, -10 ) )
		bdvmi::logger << bdvmi::WARNING << "[" << uuid
		              << "] could not set process priority: " << strerror( errno ) << std::flush;

	int status = 0;

	try {
		settings_ = domainSpecificSettings;

		if ( !hookDomain( uuid, name ) )
			bdvmi::logger << bdvmi::ERROR << "[" << uuid
			              << "] NewGuestNotification() failed: could not hook domain" << std::flush;
	} catch ( const std::exception &e ) {
		bdvmi::logger << bdvmi::ERROR << e.what() << std::flush;
		status = -1;
	} catch ( ... ) {
		bdvmi::logger << bdvmi::ERROR << "[" << uuid << "] Caught unknown exception, exiting." << std::flush;
		status = -1;
	}

	// exit() doesn't call local objects' destructors, so call it explicitly for semPoster.

#ifndef DISABLE_FORK_CHILDREN
	exit( status );
#endif
}

bool HvmiDomainHandler::licensed( const std::string & /* uuid */ ) const
{
	return true;
}

bool HvmiDomainHandler::hookDomain( const std::string &uuid, const std::string &name )
{
	struct sigaction act {
	};

	act.sa_handler = intro_init_crash_handler;
	act.sa_flags   = SA_RESETHAND;
	sigemptyset( &act.sa_mask );

	sigaction( SIGSEGV, &act, &soact );
	sigaction( SIGABRT, &act, &aoact );

	bdvmi::logger.prefix( "[" + uuid + "] " );

	bdvmi::BackendFactory bf( settings_.backend_ );
	auto                  pd = bf.driver( uuid, settings_.useAltp2m_ );

	currentDomain_ = name;
	currentUuid_   = uuid;

	logsDir_ = "./logs/" + currentUuid_ + "_" + currentDomain_;

	if ( settings_.pageCacheLimit_ != 0 ) {
		bdvmi::logger << bdvmi::WARNING << "Setting page cache limit to " << std::dec
		              << settings_.pageCacheLimit_ << " mappings" << std::flush;

		size_t actualLimit = pd->setPageCacheLimit( settings_.pageCacheLimit_ );

		bdvmi::logger << bdvmi::WARNING << "The hypervisor backend has chosen a page cache limit of "
		              << std::dec << actualLimit << " mappings" << std::flush;
	}

	HvmiEventHandler teh( *pd, settings_ );
	auto             pem = bf.eventManager( *pd, g_stop );

#ifndef DISABLE_MEM_EVENT
	IntrocoreManager im( *pd, *pem, name, settings_ );

	teh.setIntrocoreManager( &im );

	if ( !im.newGuestNotification() )
		return false;

	sigaction( SIGSEGV, &soact, nullptr );
	sigaction( SIGABRT, &aoact, nullptr );

	pem->handler( &teh );
	pd->handler( &teh );
#endif

	pim_ = &im;

	stopAgentsThread_ = false;
	agentsThread_.start( &HvmiDomainHandler::agentsCallback, this );

	bdvmi::logger << bdvmi::INFO << "Domain name: '" << name << "'" << std::flush;
	bdvmi::logger << bdvmi::INFO << "Waiting for events" << std::flush;

	pem->waitForEvents();

	pd->handler( nullptr );

	agentsThread_.stop( [&] {
		stopAgentsThread_ = true;
		if ( pim_ )
			pim_->signalAgentFinished();
	} );

	pim_ = nullptr;

	currentDomain_ = currentUuid_ = "";

	return true;
}

void HvmiDomainHandler::ignoreDomains( const std::set<std::string> &domains )
{
	if ( domains.empty() )
		return;

	for ( auto &&d : domains )
		bdvmi::logger << bdvmi::INFO << "Ignoring domain: " << d << std::flush;

	ignoredDomains_ = domains;
}

bool HvmiDomainHandler::shouldIgnore( const std::string &name ) const
{
	return ignoredDomains_.find( name ) != ignoredDomains_.end();
}

void HvmiDomainHandler::removePid( pid_t pid )
{
	std::lock_guard<std::mutex> guard( pidUuidMutex_ );

	pidUuids_.erase( pid );
}

void HvmiDomainHandler::addPid( pid_t pid, const std::string &uuid )
{
	std::lock_guard<std::mutex> guard( pidUuidMutex_ );

	pidUuids_[pid] = uuid;
}

bool HvmiDomainHandler::getUuid( pid_t pid, std::string &uuid ) const
{
	std::lock_guard<std::mutex> guard( pidUuidMutex_ );

	auto i = pidUuids_.find( pid );

	if ( i == pidUuids_.end() )
		return false;

	uuid = i->second;

	return true;
}

bool HvmiDomainHandler::stillHooked( const std::string &uuid ) const
{
	std::lock_guard<std::mutex> guard( pidUuidMutex_ );

	return std::any_of( pidUuids_.begin(), pidUuids_.end(), [uuid]( auto &&item ) { return item.second == uuid; } );
}

void HvmiDomainHandler::addPendingDomain( const std::string &uuid, const std::string &name,
                                          const HvmiSettings *settings )
{
	{
		std::lock_guard<std::mutex> lock( pendingDomainsMutex_ );

		PendingDomainInfo pdi( uuid, name, settings );
		pendingDomains_.insert( pdi );

		processDomains_ = true;
	}

	pendingDomainsCV_.notify_one();
}

void HvmiDomainHandler::removePendingDomain( const std::string &uuid )
{
	std::lock_guard<std::mutex> lock( pendingDomainsMutex_ );

	PendingDomainInfo pdi( uuid, "", nullptr );
	pendingDomains_.erase( pdi );
}

bool HvmiDomainHandler::startSignalThread()
{
	if ( signalThread_.isRunning() )
		return false;

	struct sigaction action {
	};

	// Comment shamelessly ripped off from a QNX example at qnx.com:
	// "By default, SIGCHLD is set to be ignored so unless we happen
	// to be blocked on sigwaitinfo() at the time that SIGCHLD
	// is set on us we will not get it.  To fix this, we simply
	// register a signal handler.  Since we've masked the signal
	// above, it will not affect us.  At the same time we will make
	// it a queued signal so that if more than one are set on us,
	// sigwaitinfo() will get them all."
	action.sa_sigaction = dummy_handler;
	sigemptyset( &action.sa_mask );
	action.sa_flags = SA_SIGINFO | SA_NOCLDSTOP; // make it a queued signal
	sigaction( SIGCHLD, &action, nullptr );

	return signalThread_.start( &HvmiDomainHandler::signalThreadCallback, this );
}

void HvmiDomainHandler::signalThreadCallback()
{
	sigset_t        mask;
	siginfo_t       info;
	struct timespec timeout;

	sigemptyset( &mask );
	sigaddset( &mask, SIGCHLD );

	timeout.tv_sec  = 0;
	timeout.tv_nsec = 500000000; // half a second

	while ( !g_stop ) {
		if ( sigtimedwait( &mask, &info, &timeout ) == -1 ) {
			if ( errno != EAGAIN ) // just a timeout
				bdvmi::logger << bdvmi::WARNING << "sigwaitinfo() failed: " << strerror( errno )
				              << std::flush;
			continue;
		}

		switch ( info.si_signo ) {
			case SIGCHLD:
				collectChildProcesses( false );
				break;

			default:
				bdvmi::logger << bdvmi::ERROR << "received unexpected signal" << std::flush;
				break;
		}
	}
}

void HvmiDomainHandler::agentsCallback()
{
	try {
		// Original:
		// 		if ( timeoutOrCondition( std::chrono::seconds(5), SLEEP_DIVISIONS, stopAgentsThread_ ) )
		// 			return;
		//

		while ( pim_ && !pim_->OSDetected() ) {
			sleep( 1 );

			if ( stopAgentsThread_ )
				return;
		}

		while ( !stopAgentsThread_ ) {
			Task onDemandTask;
			bool firstTask = true;

			while ( pollForGuestTasks( onDemandTask, firstTask, false ) && !stopAgentsThread_ ) {
				firstTask = false;
				runTask( onDemandTask );
			}

			if ( stopAgentsThread_ )
				return; // "Cancellation point."

			// if ( timeoutOrCondition( std::chrono::seconds(5), SLEEP_DIVISIONS, stopAgentsThread_) )
			// 		break;

			sleep( 5 );

			if ( stopAgentsThread_ )
				break;
		}
	} catch ( const std::exception &e ) {
		bdvmi::logger << bdvmi::ERROR << "Exception caught in tasks thread: " << e.what() << std::flush;
	} catch ( ... ) {
		bdvmi::logger << bdvmi::ERROR << "Exception caught in tasks thread" << std::flush;
	}
}

void HvmiDomainHandler::processDomainsCallback()
{
	for ( ;; ) {
		std::unique_lock<std::mutex> lock( pendingDomainsMutex_ );
		pendingDomainsCV_.wait( lock, [&] { return g_stop || processDomains_; } );

		if ( g_stop )
			return;

		if ( pendingDomains_.empty() ) {
			processDomains_ = false;
			continue;
		}

		// We need to check again here, pendingDomains_ might have emptied-out while we were waiting on the
		// semaphore.
		if ( pendingDomains_.empty() ) {
			processDomains_ = false;
			continue;
		}

		auto        pdi      = pendingDomains_.begin();
		auto        settings = pdi->settings_;
		std::string uuid = pdi->uuid_, name = pdi->name_;

		if ( stillHooked( uuid ) ) { // Can't hook a domain twice, so don't even try.
			continue;
		}

		pendingDomains_.erase( pdi );

		lock.unlock();

		if ( settings )
			bdvmi::logger << bdvmi::INFO << "Hooking domain with policy '" << settings->name_ << "'"
			              << std::flush;

		handleDomain( uuid, name, settings.get() );
	}
}

void HvmiDomainHandler::killChildrenCallback( int seconds )
{
	std::unique_lock<std::mutex> lock( stuckChildrenMutex_ );

	// Interrupted before timeout. This means all children have already been collected normally.
	// No need to kill anything.
	if ( stuckChildrenCV_.wait_for( lock, std::chrono::seconds( seconds ),
	                                [&] { return stopStuckChildrenThread_ == true; } ) )
		return;

	std::lock_guard<std::mutex> guard( pidUuidMutex_ );

	for ( auto &&item : pidUuids_ ) {
		bdvmi::logger << bdvmi::WARNING << "[TIMEOUT] Forcefully killing PID " << std::dec << item.first
		              << " (UUID: " << item.second << ")" << std::flush;
		kill( item.first, SIGKILL );
	}

	pidUuids_.clear();
}

void HvmiDomainHandler::runTask( const Task & /* task */ ) const
{
}

bool HvmiDomainHandler::runLogCollector( TaskStatusHelper & /* taskHelper */, ToolStatusHelper & /* toolHelper */,
                                         const Tool & /* tool */, bool /* isStdout */ ) const
{
	return false;
}

bool HvmiDomainHandler::pollForGuestTasks( Task & /* task */, bool /* firstTask */, bool /* onViolation */ )
{
	return true;
}
