/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef __HVMISETTINGS_H_INCLUDED__
#define __HVMISETTINGS_H_INCLUDED__

#include <bdvmi/backendfactory.h>
#include "hvmieventhandler.h"
#include <introcore.h>
#include <json/json.h>
#include <atomic>
#include <cstring>
#include <list>
#include <unordered_map>
#include <mutex>
#include <set>
#include <string>
#include <strings.h>
#include <vector>

#define DEFAULT_OPTIONS                                                                                                \
	( ( INTRO_OPT_DEFAULT_XEN_OPTIONS | INTRO_OPT_ENABLE_DTR_PROTECTION | INTRO_OPT_VE |                           \
	    INTRO_OPT_BUGCHECK_CLEANUP ) &                                                                             \
	  ~INTRO_OPT_EVENT_PROCESS_CRASH )

enum PrimaryAction { PA_LOG = 1, PA_DENY = 2, PA_KILL_TASK = 3, PA_SHUTDOWN = 4 };

const char *actionToString( PrimaryAction action );

struct ProtectedProcessSettings {

public:
	ProtectedProcessSettings() = default;

	ProtectedProcessSettings( unsigned int flags, HvmiEventHandler::Action action, PrimaryAction actionTaken,
	                          uint64_t id, bool unprotect = false )
	    : flags_{ flags }
	    , unprotect_{ unprotect }
	    , primaryAction_{ action }
	    , actionTaken_{ actionTaken }
	    , id_{ id }
	{
	}

public:
	bool operator==( const ProtectedProcessSettings &rhs ) const
	{
		return ( ( flags_ == rhs.flags_ ) && ( unprotect_ == rhs.unprotect_ ) );
	}

	bool operator!=( const ProtectedProcessSettings &rhs ) const
	{
		return !( *this == rhs );
	}

public:
	unsigned int             flags_{ 0 };
	bool                     unprotect_{ false };
	HvmiEventHandler::Action primaryAction_{ HvmiEventHandler::ACT_ALLOW };
	PrimaryAction            actionTaken_{ PA_LOG };
	uint64_t                 id_{ 0 };
};

class HvmiSettings {

public:
	struct ViolationEvent {
		INTRO_EVENT_TYPE type;
		unsigned int     version{};

		union {
			EVENT_EPT_VIOLATION               ept;
			EVENT_MSR_VIOLATION               msr;
			EVENT_CR_VIOLATION                cr;
			EVENT_XCR_VIOLATION               xcr;
			EVENT_MEMCOPY_VIOLATION           memcopy;
			EVENT_TRANSLATION_VIOLATION       translation;
			EVENT_INTEGRITY_VIOLATION         integrity;
			EVENT_DTR_VIOLATION               dtr;
			EVENT_PROCESS_CREATION_VIOLATION  processCreation;
			EVENT_MODULE_LOAD_VIOLATION       moduleLoad;
			EVENT_ENGINES_DETECTION_VIOLATION enginesDetection;
		} violation;

		bool operator==( const ViolationEvent &other ) const
		{
			return ( memcmp( this, &other, sizeof( ViolationEvent ) ) == 0 );
		}
	};

public:
	HvmiSettings() = default;

public:
	HvmiSettings( const HvmiSettings &other );
	HvmiSettings &operator=( const HvmiSettings &other );

public:
	void reset();

	bool loadDaemonSettings( void );

	bool loadVmPolicy( const std::string &vmid );

	bool actionFromString( const std::string &strAction, HvmiEventHandler::Action &action ) const;

	bool getAction( bool usermode, uint64_t id, HvmiEventHandler::Action &action,
	                PrimaryAction &actionTaken ) const;

	std::string toJson() const;

private:
	bool parseSettingsJson( const std::string &contents );

	bool parsePolicyJson( const std::string &contents );

	void copyFrom( const HvmiSettings &other );

	bool settingsForProcess( uint64_t id, ProtectedProcessSettings &result ) const;

	bool fetchJson( const std::string &filename, std::string &jsonStr );

	bool getDefaultJsonString( std::string &jsonStr );

	bool getVmJsonString( const std::string &vmid, std::string &jsonStr );

	bool loadDefaultPolicy( void );

	std::string hashString( const std::string &jsonString ) const;

public:
	bool                                                      enabled_{ true };
	HvmiEventHandler::Action                                  primaryAction_{ HvmiEventHandler::ACT_ALLOW };
	PrimaryAction                                             actionTaken_{ PA_LOG };
	size_t                                                    pageCacheLimit_{ 0 };
	std::string                                               defaultPolicyFile_;
	std::string                                               settingsFile_;
	std::string                                               policiesDir_;
	std::string                                               exceptionsFile_;
	std::string                                               liveUpdateFile_;
	std::set<std::string>                                     ignoredDomains_;
	std::unordered_map<std::string, ProtectedProcessSettings> protectedProcesses_;
	std::unordered_map<std::string, ProtectedProcessSettings> oldProtectedProcesses_;
	uint64_t                                                  introspectionOptions_{ DEFAULT_OPTIONS };
	mutable std::mutex                                        mutex_;
	std::string                                               polid_;
	std::string                                               name_;
	bool                                                      policyOnly_{ true };
	bool                                                      kmEnabled_{ true };
	bool                                                      umEnabled_{ true };
	bdvmi::BackendFactory::BackendType                        backend_{ bdvmi::BackendFactory::BACKEND_XEN };
	std::vector<ViolationEvent>                               violations_;
	bool                                                      pendingViolations_{ false };
	bool                                                      logUnprotectedProcesses_{ false };
	bool                                                      throttle_{ false };
	bool                                                      useScanEngines_{ false };
	bool                                                      debugPipes_{ false };
	bool                                                      internalFeedback_{ false };
	bool                                                      useAltp2m_{ true };
	bool                                                      disableQueryHeap_{ false };

private:
	size_t      hash_{ 0 };
	bool        hashInitialized_{ false };
	bool        policyApplied_{ false };
	std::string vmid_;
	size_t      protectionsHash_{ 0 };
	uint64_t    polTime_{ 0 };
};

#endif // __HVMISETTINGS_H_INCLUDED__
