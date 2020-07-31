/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "hvmisettings.h"
#include "hvmidaemon.h"
#include "bdvmi/backendfactory.h"
#include "config.h"
#include <introcore.h>
#include <fstream>
#include <functional>
#include <introcore.h>
#include <json/reader.h>
#include <sstream>
#include <bdvmi/logger.h>

namespace {

constexpr HvmiEventHandler::Action DENY_VMI_ACTION = HvmiEventHandler::ACT_SKIP;

} // end of anonymous namespace

#define __case( x )                                                                                                    \
	case x:                                                                                                        \
		return #x;                                                                                             \
		break

// yes, this is meant to not be anonymous (local to the compilation unit)
const char *actionToString( PrimaryAction action )
{
	switch ( action ) {
		__case( PA_LOG );
		__case( PA_DENY );
		__case( PA_KILL_TASK );
		__case( PA_SHUTDOWN );
		default:
			return "unknown";
			break;
	}
}

#undef __case

HvmiSettings::HvmiSettings( const HvmiSettings &other )
{
	copyFrom( other );
}

HvmiSettings &HvmiSettings::operator=( const HvmiSettings &other )
{
	if ( &other == this )
		return *this;

	copyFrom( other );

	return *this;
}

// Copy everything but the mutex.
void HvmiSettings::copyFrom( const HvmiSettings &other )
{
	enabled_                 = other.enabled_;
	settingsFile_            = other.settingsFile_;
	defaultPolicyFile_       = other.defaultPolicyFile_;
	policiesDir_             = other.policiesDir_;
	primaryAction_           = other.primaryAction_;
	actionTaken_             = other.actionTaken_;
	pageCacheLimit_          = other.pageCacheLimit_;
	exceptionsFile_          = other.exceptionsFile_;
	liveUpdateFile_          = other.liveUpdateFile_;
	ignoredDomains_          = other.ignoredDomains_;
	protectedProcesses_      = other.protectedProcesses_;
	oldProtectedProcesses_   = other.oldProtectedProcesses_;
	hash_                    = other.hash_;
	hashInitialized_         = other.hashInitialized_;
	introspectionOptions_    = other.introspectionOptions_;
	name_                    = other.name_;
	polid_                   = other.polid_;
	policyOnly_              = other.policyOnly_;
	kmEnabled_               = other.kmEnabled_;
	umEnabled_               = other.umEnabled_;
	policyApplied_           = other.policyApplied_;
	protectionsHash_         = other.protectionsHash_;
	violations_              = other.violations_;
	pendingViolations_       = other.pendingViolations_;
	logUnprotectedProcesses_ = other.logUnprotectedProcesses_;
	throttle_                = other.throttle_;
	useScanEngines_          = other.useScanEngines_;
	debugPipes_              = other.debugPipes_;
	internalFeedback_        = other.internalFeedback_;
	useAltp2m_               = other.useAltp2m_;
	disableQueryHeap_        = other.disableQueryHeap_;
}

void HvmiSettings::reset()
{
	enabled_         = true;
	primaryAction_   = HvmiEventHandler::ACT_ALLOW;
	actionTaken_     = PA_LOG;
	pageCacheLimit_  = 0;
	hash_            = 0;
	hashInitialized_ = false;
	exceptionsFile_.clear();
	liveUpdateFile_.clear();
	ignoredDomains_.clear();
	protectedProcesses_.clear();
	polid_.clear();
	name_.clear();
	policyOnly_      = true;
	kmEnabled_       = true;
	policyApplied_   = false;
	protectionsHash_ = 0;
	violations_.clear();
	pendingViolations_       = false;
	logUnprotectedProcesses_ = false;
	throttle_                = false;
	useScanEngines_          = false;
	debugPipes_              = false;
	internalFeedback_        = false;
	useAltp2m_               = true;
	disableQueryHeap_        = false;
}

bool HvmiSettings::loadDaemonSettings( void )
{
	std::string jsonStr;

	reset();

	settingsFile_      = std::string( INSTALL_PREFIX ) + "/etc/" + HVMID_DAEMON_NAME + "/settings.json";
	defaultPolicyFile_ = std::string( INSTALL_PREFIX ) + "/etc/" + HVMID_DAEMON_NAME + "/policies/default.json";

	if ( !fetchJson( settingsFile_, jsonStr ) ) {
		bdvmi::logger << bdvmi::ERROR << "Failed to load settings json" << std::flush;

		return false;
	}

	enabled_ = parseSettingsJson( jsonStr );

	if ( !enabled_ )
		bdvmi::logger << bdvmi::ERROR << "Failed to load settings. Introspection will not be activated!"
		              << std::flush;

	return enabled_;
}

bool HvmiSettings::parseSettingsJson( const std::string &contents )
{
	Json::Value settings;
	std::string errs;
	bool        ret;

	Json::CharReaderBuilder builder;
	Json::CharReader *      reader = builder.newCharReader();

	ret = reader->parse( contents.c_str(), contents.c_str() + contents.size(), &settings,
	                     &errs /* discard comments */ );

	delete reader;

	if ( !ret ) {
		bdvmi::logger << bdvmi::ERROR << "Failed to parse JSON " << contents << " " << errs << std::flush;

		return false;
	}

	policiesDir_    = settings["policiesDir"].asString();
	exceptionsFile_ = settings["exceptionsFile"].asString();
	liveUpdateFile_ = settings["liveUpdateFile"].asString();

	pageCacheLimit_ = settings["pageCacheLimit"].asUInt();
	useAltp2m_      = settings["useAltp2m"].asBool();

	disableQueryHeap_ = settings["disableQueryHeap"].asBool();

	policyOnly_ = settings["policyOnly"].asBool();

	logUnprotectedProcesses_ = settings["loadUnprotectedProcesses"].asBool();

	if ( !!settings["kvmBackend"] && settings["kvmBackend"].asBool() )
		backend_ = bdvmi::BackendFactory::BACKEND_KVM;

	if ( !!settings["enablePTFilter"] && settings["enablePTFilter"].asBool() )
		introspectionOptions_ |= INTRO_OPT_IN_GUEST_PT_FILTER;
	else
		introspectionOptions_ &= ~INTRO_OPT_IN_GUEST_PT_FILTER;

	if ( !!settings["enableBugcheckCleanup"] && settings["enableBugcheckCleanup"].asBool() )
		introspectionOptions_ |= INTRO_OPT_BUGCHECK_CLEANUP;
	else
		introspectionOptions_ &= ~INTRO_OPT_BUGCHECK_CLEANUP;

	if ( !!settings["enableBetaMode"] && settings["enableBetaMode"].asBool() ) {
		actionTaken_ = PA_LOG;
		introspectionOptions_ |= INTRO_OPT_ENABLE_KM_BETA_DETECTIONS | INTRO_OPT_SYSPROC_BETA_DETECTIONS;
	}

	for ( int i = 0; i < static_cast<int>( settings["ignoredDomains"].size() ); i++ )
		ignoredDomains_.insert( settings["ignoredDomains"][i].asString() );

	return loadDefaultPolicy();
}

bool HvmiSettings::fetchJson( const std::string &filename, std::string &jsonStr )
{
	std::ifstream in( filename.c_str() );

	if ( !in )
		return false;

	std::stringstream ss;

	ss << in.rdbuf();

	jsonStr = ss.str();

	return true;
}

bool HvmiSettings::getDefaultJsonString( std::string &jsonStr )
{
	std::string policyFile;

	policyFile = policiesDir_ + "/" + "default.json";

	bdvmi::logger << bdvmi::INFO << "Loading default policy file " << policyFile << std::flush;

	return fetchJson( policyFile, jsonStr );
}

bool HvmiSettings::getVmJsonString( const std::string &vmid, std::string &jsonStr )
{
	std::string policyFile;

	policyFile = policiesDir_ + "/" + vmid + ".json";

	bdvmi::logger << bdvmi::INFO << "Loading policy file " << policyFile << std::flush;

	return fetchJson( policyFile, jsonStr );
}

bool HvmiSettings::loadDefaultPolicy( void )
{
	std::string jsonStr;

	if ( !getDefaultJsonString( jsonStr ) ) {
		bdvmi::logger << bdvmi::ERROR << "Failed to load default policy!" << std::flush;

		return false;
	}

	return parsePolicyJson( jsonStr );
}

bool HvmiSettings::loadVmPolicy( const std::string &vmid )
{
	// No reset() here. Use previous settings if something's missing from the JSON, etc.

	std::string jsonStr;

	policyApplied_ = false;
	vmid_          = vmid;

	if ( !getVmJsonString( vmid, jsonStr ) )
		return false;

	bool ret = parsePolicyJson( jsonStr );

	policyApplied_ = ret;

	return ret;
}

bool HvmiSettings::parsePolicyJson( const std::string &contents )
{
	Json::Value introSettings;
	std::string errs;

	Json::CharReaderBuilder builder;
	Json::CharReader *      reader = builder.newCharReader();

	if ( !reader->parse( contents.c_str(), contents.c_str() + contents.size(), &introSettings,
	                     &errs /* discard comments */ ) )
		return false;

	delete reader;

	Json::Value kmSettings = introSettings["kernelSpaceMemoryIntrospection"];
	Json::Value umSettings = introSettings["userSpaceMemoryIntrospection"];
	Json::Value exclusions = introSettings["exceptions"];

	enabled_   = false;
	kmEnabled_ = false;
	umEnabled_ = false;

	if ( !!kmSettings ) {

		if ( !!kmSettings["enabled"] ) {
			if ( kmSettings["enabled"].asBool() ) {
				enabled_   = true;
				kmEnabled_ = true;
				introspectionOptions_ |= INTRO_OPT_ENABLE_KM_PROTECTION | INTRO_OPT_PROT_UM_SYS_PROCS |
				    INTRO_OPT_ENABLE_FULL_PATH;
			} else {

				introspectionOptions_ &=
				    ~( INTRO_OPT_ENABLE_KM_PROTECTION | INTRO_OPT_ENABLE_CR_PROTECTION |
				       INTRO_OPT_ENABLE_MSR_PROTECTION | INTRO_OPT_ENABLE_DTR_PROTECTION |
				       INTRO_OPT_ENABLE_AV_PROTECTION | INTRO_OPT_ENABLE_XEN_PROTECTION |
				       INTRO_OPT_ENABLE_INTEGRITY_CHECKS | INTRO_OPT_PROT_UM_SYS_PROCS );
			}
		}

		Json::Value monOpt = kmSettings["monitoringOptions"];

		if ( !!monOpt && kmEnabled_ ) {
			if ( !!monOpt["controlRegisters"] ) {
				if ( monOpt["controlRegisters"].asBool() )
					introspectionOptions_ |= INTRO_OPT_ENABLE_CR_PROTECTION;
				else
					introspectionOptions_ &= ~INTRO_OPT_ENABLE_CR_PROTECTION;
			}

			if ( !!monOpt["modelSpecificRegisters"] ) {
				if ( monOpt["modelSpecificRegisters"].asBool() )
					introspectionOptions_ |= INTRO_OPT_ENABLE_MSR_PROTECTION;
				else
					introspectionOptions_ &= ~INTRO_OPT_ENABLE_MSR_PROTECTION;
			}

			if ( !!monOpt["idtOrGdtIntegrity"] ) {
				if ( monOpt["idtOrGdtIntegrity"].asBool() )
					introspectionOptions_ |=
					    ( INTRO_OPT_ENABLE_DTR_PROTECTION | INTRO_OPT_ENABLE_INTEGRITY_CHECKS );
				else
					introspectionOptions_ &=
					    ~( INTRO_OPT_ENABLE_DTR_PROTECTION | INTRO_OPT_ENABLE_INTEGRITY_CHECKS );
			}

			if ( !!monOpt["antimalwareDrivers"] ) {
				if ( monOpt["antimalwareDrivers"].asBool() )
					introspectionOptions_ |= INTRO_OPT_ENABLE_AV_PROTECTION;
				else
					introspectionOptions_ &= ~INTRO_OPT_ENABLE_AV_PROTECTION;
			}

			if ( !!monOpt["xenDrivers"] ) {
				if ( monOpt["xenDrivers"].asBool() )
					introspectionOptions_ |= INTRO_OPT_ENABLE_XEN_PROTECTION;
				else
					introspectionOptions_ &= ~INTRO_OPT_ENABLE_XEN_PROTECTION;
			}

			if ( !!monOpt["osFailures"] ) {
				if ( monOpt["osFailures"].asBool() )
					introspectionOptions_ |= INTRO_OPT_EVENT_OS_CRASH;
				else
					introspectionOptions_ &= ~INTRO_OPT_EVENT_OS_CRASH;
			}

			if ( !!monOpt["driverEvents"] ) {
				if ( monOpt["driverEvents"].asBool() )
					introspectionOptions_ |= INTRO_OPT_EVENT_MODULES;
				else
					introspectionOptions_ &= ~INTRO_OPT_EVENT_MODULES;
			}
		}

		Json::Value actions   = kmSettings["actions"];
		std::string strAction = "log";

		if ( !!actions ) {
			if ( !!actions["primaryAction"] ) {
				introspectionOptions_ &=
				    ~( INTRO_OPT_ENABLE_KM_BETA_DETECTIONS | INTRO_OPT_SYSPROC_BETA_DETECTIONS );

				switch ( actions["primaryAction"].asInt() ) {
					case PA_LOG:
						primaryAction_ = HvmiEventHandler::ACT_ALLOW;
						actionTaken_   = PA_LOG;
						introspectionOptions_ |= INTRO_OPT_ENABLE_KM_BETA_DETECTIONS |
						    INTRO_OPT_SYSPROC_BETA_DETECTIONS;
						break;
					case PA_DENY:
						primaryAction_ = DENY_VMI_ACTION;
						actionTaken_   = PA_DENY;
						strAction      = "deny";
						break;
					case PA_SHUTDOWN:
						primaryAction_ = HvmiEventHandler::ACT_SHUTDOWN;
						actionTaken_   = PA_SHUTDOWN;
						strAction      = "shutdown";
						break;
				}
			}
		}
	}

	if ( !!umSettings ) {

		if ( !!umSettings["enabled"] ) {
			if ( umSettings["enabled"].asBool() ) {
				enabled_   = true;
				umEnabled_ = true;
				introspectionOptions_ |= INTRO_OPT_PROT_UM_MISC_PROCS | INTRO_OPT_ENABLE_FULL_PATH;
			} else {
				introspectionOptions_ &= ~INTRO_OPT_PROT_UM_MISC_PROCS;
			}
		}

		if ( !!umSettings["applicationCrashes"] ) {
			if ( umSettings["applicationCrashes"].asBool() )
				introspectionOptions_ |= INTRO_OPT_EVENT_PROCESS_CRASH;
			else
				introspectionOptions_ &= ~INTRO_OPT_EVENT_PROCESS_CRASH;
		}

		if ( !!umSettings["connectionEvents"] ) {
			if ( umSettings["connectionEvents"].asBool() )
				introspectionOptions_ |= INTRO_OPT_EVENT_CONNECTIONS;
			else
				introspectionOptions_ &= ~INTRO_OPT_EVENT_CONNECTIONS;
		}

		Json::Value rules = umSettings["rules"];

		if ( !!rules ) {
			protectedProcesses_.clear();

			for ( int i = 0; i < static_cast<int>( rules.size() ); ++i ) {
				std::string name = "<unspecified name>";

				if ( !!rules[i]["ruleName"] )
					name = rules[i]["ruleName"].asString();

				Json::Value monOpt = rules[i]["monitoringOptions"];

				unsigned flags = PROC_OPT_KILL_ON_EXPLOIT;

				bool doubleAgentPrevention = true;

				if ( !!monOpt ) {
					if ( !!monOpt["dllHooks"] && monOpt["dllHooks"].asBool() )
						flags |= PROC_OPT_PROT_CORE_HOOKS;

					// This is intended: there's been a mixup and we need to support this spelling.
					if ( !!monOpt["exeUnpackAttemtps"] && monOpt["exeUnpackAttemtps"].asBool() )
						flags |= PROC_OPT_PROT_UNPACK;

					if ( !!monOpt["exeUnpackAttempts"] && monOpt["exeUnpackAttempts"].asBool() )
						flags |= PROC_OPT_PROT_UNPACK;

					if ( !!monOpt["processRemoteWrites"] && monOpt["processRemoteWrites"].asBool() )
						flags |= PROC_OPT_PROT_INJECTION;

					if ( !!monOpt["exploits"] && monOpt["exploits"].asBool() )
						flags |= PROC_OPT_PROT_EXPLOIT;

					if ( !!monOpt["winSockHooking"] && monOpt["winSockHooking"].asBool() )
						flags |= PROC_OPT_PROT_WSOCK_HOOKS;

					if ( !!monOpt["preventChildCreation"] &&
					     monOpt["preventChildCreation"].asBool() )
						flags |= PROC_OPT_PROT_PREVENT_CHILD_CREATION;

					if ( !!monOpt["doubleAgentPrevention"] )
						doubleAgentPrevention = monOpt["doubleAgentPrevention"].asBool();
				}

				if ( doubleAgentPrevention )
					flags |= PROC_OPT_PROT_DOUBLE_AGENT;
				else
					// This can also be enabled via WINPROC_PROT_MASK_INJECTION, thus
					// we must explicitly clear it
					flags &= ~PROC_OPT_PROT_DOUBLE_AGENT;

				Json::Value actions   = rules[i]["actions"];
				std::string strAction = "log";

				HvmiEventHandler::Action processAction = DENY_VMI_ACTION;
				PrimaryAction            actionTaken   = PA_LOG;

				if ( !!actions ) {
					if ( !!actions["primaryAction"] ) {
						switch ( actions["primaryAction"].asInt() ) {
							case PA_LOG:
								processAction = HvmiEventHandler::ACT_ALLOW;
								actionTaken   = PA_LOG;
								flags |= PROC_OPT_BETA;
								break;
							case PA_KILL_TASK: // KILL_TASK and DENY are synonymous
								processAction = DENY_VMI_ACTION;
								actionTaken   = PA_KILL_TASK;
								strAction     = "kill";
								break;
							case PA_DENY:
								processAction = DENY_VMI_ACTION;
								actionTaken   = PA_DENY;
								strAction     = "deny";
								break;
							case PA_SHUTDOWN:
								processAction = HvmiEventHandler::ACT_SHUTDOWN;
								actionTaken   = PA_SHUTDOWN;
								strAction     = "shutdown";
								break;
						}
					}
				}

				Json::Value processes = rules[i]["processes"];

				if ( !!processes ) {
					for ( int j = 0; j < static_cast<int>( processes.size() ); ++j ) {

						std::string processName = processes[j].asString();

						auto s = protectedProcesses_.find( processName );

						if ( s != protectedProcesses_.end() ) {
							continue;
						}

						ProtectedProcessSettings pps( flags, processAction, actionTaken,
						                              std::hash<std::string>{}( processName ) );
						protectedProcesses_[processName] = pps;
					}
				}
			}
		}
	}

	if ( enabled_ )
		introspectionOptions_ |= INTRO_OPT_ENABLE_MANUAL_AGENT_INJ;

	return true;
}

bool HvmiSettings::settingsForProcess( uint64_t id, ProtectedProcessSettings &result ) const
{
	for ( auto &&pp : protectedProcesses_ ) {
		if ( pp.second.id_ == id ) {
			result = pp.second;
			return true;
		}
	}

	return false;
}

bool HvmiSettings::getAction( bool usermode, uint64_t id, HvmiEventHandler::Action &action,
                              PrimaryAction &actionTaken ) const
{
	std::lock_guard<std::mutex> guard( mutex_ );

	if ( !usermode ) {
		action      = primaryAction_;
		actionTaken = actionTaken_;
		return true;
	}

	ProtectedProcessSettings pps;

	if ( !settingsForProcess( id, pps ) )
		return false;

	action      = pps.primaryAction_;
	actionTaken = pps.actionTaken_;

	return true;
}

bool HvmiSettings::actionFromString( const std::string &strAction, HvmiEventHandler::Action &action ) const
{
	if ( !strAction.compare( "allow" ) )
		action = HvmiEventHandler::ACT_ALLOW;

	else if ( !strAction.compare( "ignore" ) )
		action = HvmiEventHandler::ACT_ALLOW; // ignore is a synonym for allow

	else if ( !strAction.compare( "nowrite" ) )
		action = HvmiEventHandler::ACT_ALLOW_NOWRITE;

	else if ( !strAction.compare( "deny" ) )
		action = DENY_VMI_ACTION;

	else if ( !strAction.compare( "shutdown" ) )
		action = HvmiEventHandler::ACT_SHUTDOWN;

	else if ( !strAction.compare( "skip" ) )
		action = HvmiEventHandler::ACT_SKIP;

	else
		return false;

	return true;
}

std::string HvmiSettings::toJson() const
{
	Json::Value root;

	root["name"]  = name_;
	root["polid"] = polid_;

	Json::Value hviGeneralSettings;
	hviGeneralSettings["@name"] = "SetGeneralHVISettings";

	root["settings"]["Product.AdvancedSettings"].append( hviGeneralSettings );

	Json::Value introSettings;
	introSettings["kernelSpaceMemoryIntrospection"]["enabled"] = kmEnabled_;

	introSettings["kernelSpaceMemoryIntrospection"]["monitoringOptions"]["controlRegisters"] =
	    !!( introspectionOptions_ & INTRO_OPT_ENABLE_CR_PROTECTION );
	introSettings["kernelSpaceMemoryIntrospection"]["monitoringOptions"]["modelSpecificRegisters"] =
	    !!( introspectionOptions_ & INTRO_OPT_ENABLE_MSR_PROTECTION );
	introSettings["kernelSpaceMemoryIntrospection"]["monitoringOptions"]["idtOrGdtIntegrity"] =
	    !!( introspectionOptions_ & INTRO_OPT_ENABLE_DTR_PROTECTION );
	introSettings["kernelSpaceMemoryIntrospection"]["monitoringOptions"]["antimalwareDrivers"] =
	    !!( introspectionOptions_ & INTRO_OPT_ENABLE_AV_PROTECTION );
	introSettings["kernelSpaceMemoryIntrospection"]["monitoringOptions"]["xenDrivers"] =
	    !!( introspectionOptions_ & INTRO_OPT_ENABLE_XEN_PROTECTION );
	introSettings["kernelSpaceMemoryIntrospection"]["monitoringOptions"]["osFailures"] =
	    !!( introspectionOptions_ & INTRO_OPT_EVENT_OS_CRASH );
	introSettings["kernelSpaceMemoryIntrospection"]["monitoringOptions"]["driverEvents"] =
	    !!( introspectionOptions_ & INTRO_OPT_EVENT_MODULES );

	introSettings["kernelSpaceMemoryIntrospection"]["actions"]["primaryAction"] = actionTaken_;

	introSettings["userSpaceMemoryIntrospection"]["enabled"] = umEnabled_;
	introSettings["userSpaceMemoryIntrospection"]["applicationCrashes"] =
	    !!( introspectionOptions_ & INTRO_OPT_EVENT_PROCESS_CRASH );
	introSettings["userSpaceMemoryIntrospection"]["connectionEvents"] =
	    !!( introspectionOptions_ & INTRO_OPT_EVENT_CONNECTIONS );

	static const unsigned protMaskInjection = PROC_OPT_PROT_INJECTION & ~PROC_OPT_PROT_DOUBLE_AGENT;

	for ( auto &&item : protectedProcesses_ ) {
		Json::Value process;

		process["name"]                                   = item.first;
		process["monitoringOptions"]["dllHooks"]          = !!( item.second.flags_ & PROC_OPT_PROT_CORE_HOOKS );
		process["monitoringOptions"]["exeUnpackAttemtps"] = !!( item.second.flags_ & PROC_OPT_PROT_UNPACK );
		process["monitoringOptions"]["processRemoteWrites"] =
		    ( item.second.flags_ & protMaskInjection ) == protMaskInjection;
		process["monitoringOptions"]["exploits"]       = !!( item.second.flags_ & PROC_OPT_PROT_EXPLOIT );
		process["monitoringOptions"]["winSockHooking"] = !!( item.second.flags_ & PROC_OPT_PROT_WSOCK_HOOKS );
		process["monitoringOptions"]["preventChildCreation"] =
		    !!( item.second.flags_ & PROC_OPT_PROT_PREVENT_CHILD_CREATION );
		process["monitoringOptions"]["doubleAgentPrevention"] =
		    !!( item.second.flags_ & PROC_OPT_PROT_DOUBLE_AGENT );
		process["actions"]["primaryAction"] = item.second.actionTaken_;

		introSettings["userSpaceMemoryIntrospection"]["processes"].append( process );
	}

	Json::Value hviSettings;
	hviSettings["@name"] = "SetHVISettings";
	hviSettings["input"] = introSettings;

	root["settings"]["svamp"].append( hviSettings );

	return root.toStyledString();
}
