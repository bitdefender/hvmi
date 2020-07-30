/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef __HVMIDOMAINHANDLER_H_INCLUDED__
#define __HVMIDOMAINHANDLER_H_INCLUDED__

#include <bdvmi/domainhandler.h>
#include "hvmieventhandler.h"
#include "hvmisettings.h"
#include "threadhelper.h"
#include <condition_variable>
#include <unordered_map>
#include <memory>
#include <mutex>
#include <set>
#include <signal.h>
#include <string>
#include <thread>
#include <time.h>

namespace bdvmi {
class DomainWatcher;
}

class IntrocoreManager;
struct Task;
class TaskStatusHelper;
struct Tool;
class ToolStatusHelper;

class HvmiDomainHandler : public bdvmi::DomainHandler {

	struct DomainInfo {
		DomainInfo() = default;

		DomainInfo( bool enabled, const HvmiSettings &settings, const std::string &name )
		    : settings_{ settings }
		    , enabled_{ enabled }
		    , name_{ name }
		{
		}

		HvmiSettings settings_;
		bool         enabled_{ true };
		std::string  name_;
	};

	struct PendingDomainInfo {
		PendingDomainInfo() = default;

		PendingDomainInfo( const std::string &uuid, const std::string &name,
		                   const HvmiSettings *settings = nullptr )
		    : uuid_{ uuid }
		    , name_{ name }
		    , settings_{ settings ? std::make_shared<HvmiSettings>( *settings ) : nullptr }
		{
		}

		// Sort these by UUID in set<>s, map<>s, etc.
		bool operator<( const PendingDomainInfo &other ) const
		{
			return uuid_ < other.uuid_;
		}

		std::string                   uuid_;
		std::string                   name_;
		std::shared_ptr<HvmiSettings> settings_;
	};

public:
	HvmiDomainHandler( HvmiSettings &settings, bdvmi::DomainWatcher *dw = nullptr );

	~HvmiDomainHandler();

public:
	void handleDomainFound( const std::string &uuid, const std::string &name ) override;

	void handleDomainFinished( const std::string &uuid ) override;

	void cleanup( bool suspendIntrospectorDomain ) override;

	void ignoreDomains( const std::set<std::string> &domains );

	bool shouldIgnore( const std::string &name ) const;

	void startExitTimeoutThread( int seconds );

	void collectChildProcesses( bool stopThread = true );

private:
	void handleDomain( const std::string &uuid, const std::string &name, const HvmiSettings *settings );

	bool hookDomain( const std::string &uuid, const std::string &name );

	bool loadPolicy( const std::string &uuid, HvmiSettings &settings, bool log = true,
	                 bool sendApplied = true ) const;

	bool licensed( const std::string &uuid ) const;

	bool startSignalThread();

	void signalThreadCallback();

	void agentsCallback();

	void processDomainsCallback();

	void killChildrenCallback( int seconds );

	bool pollForGuestTasks( Task &task, bool firstTask, bool onViolation );

	void removePid( pid_t pid );

	void addPid( pid_t pid, const std::string &uuid );

	bool getUuid( pid_t pid, std::string &uuid ) const;

	bool stillHooked( const std::string &uuid ) const;

	void addPendingDomain( const std::string &uuid, const std::string &name, const HvmiSettings *settings );

	void removePendingDomain( const std::string &uuid );

	void runTask( const Task &task ) const;

	bool runLogCollector( TaskStatusHelper &taskHelper, ToolStatusHelper &toolHelper, const Tool &tool,
	                      bool isStdout ) const;

private:
	std::set<std::string>                       ignoredDomains_;
	HvmiSettings &                              settings_;
	std::string                                 currentDomain_;
	std::string                                 currentUuid_;
	IntrocoreManager *                          pim_{ nullptr };
	std::unordered_map<std::string, DomainInfo> allDomains_;
	std::set<PendingDomainInfo>                 pendingDomains_;
	std::unordered_map<pid_t, std::string>      pidUuids_;
	std::mutex                                  allDomainsMutex_;
	mutable std::mutex                          pidUuidMutex_;
	ThreadHelper                                signalThread_;
	ThreadHelper                                agentsThread_;
	ThreadHelper                                processDomainsThread_;
	std::thread                                 exitTimeoutThread_;
	std::condition_variable                     pendingDomainsCV_;
	std::mutex                                  pendingDomainsMutex_;
	std::condition_variable                     stuckChildrenCV_;
	std::mutex                                  stuckChildrenMutex_;
	std::atomic_bool                            stopStuckChildrenThread_{ false };
	std::atomic_bool                            stopAgentsThread_{ false };
	bool                                        processDomains_{ false };
	std::string                                 logsDir_;
	bdvmi::DomainWatcher *                      dw_;
};

#endif // __HVMIDOMAINHANDLER_H_INCLUDED__
