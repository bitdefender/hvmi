/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "hvmieventhandler.h"
#include "hvmisettings.h"
#include "introcoremanager.h"
#include <algorithm>
#include <bdvmi/driver.h>
#include <bdvmi/logger.h>
#include <signal.h>
#include <stdlib.h>
#include <time.h>

#ifndef SUPRESS_INTRO_ACTION_LOG
#define intro_output( x, y ) bdvmi::logger << x << y << std::flush
#else
#define intro_output( x, y )
#endif

extern sig_atomic_t g_reload;
extern sig_atomic_t g_stop;

HvmiEventHandler::HvmiEventHandler( bdvmi::Driver &driver, HvmiSettings &settings )
    : driver_{ driver }
    , domainUuid_{ driver.uuid() }
    , settings_{ settings }
{
}

void HvmiEventHandler::handleCR( unsigned short vcpu, unsigned short crNumber, const bdvmi::Registers &regs,
                                 uint64_t oldValue, uint64_t newValue, bdvmi::HVAction &hvAction )
{
	INTRO_ACTION introAction = introGuestAllowed;

	if ( !pim_ )
		return;

	INTSTATUS status = pim_->CRWrite( vcpu, crNumber, oldValue, newValue, regs, &introAction );

	if ( !INT_SUCCESS( status ) && status != INT_STATUS_NOT_FOUND ) {
		if ( status == INT_STATUS_FATAL_ERROR )
			g_stop = 1;

		bdvmi::logger << bdvmi::WARNING << "Introcore CR callback returned code " << std::hex << std::showbase
		              << status << std::flush;
		return;
	}

	handleIntrocoreAction( introAction, hvAction, true, false );
}

void HvmiEventHandler::handleMSR( unsigned short vcpu, uint32_t msr, uint64_t oldValue, uint64_t newValue,
                                  bdvmi::HVAction &hvAction )
{
	INTRO_ACTION introAction = introGuestAllowed;
	QWORD        newVal      = newValue;

	if ( !pim_ )
		return;

	INTSTATUS status = pim_->MSRViolation( msr, IG_MSR_HOOK_WRITE, &introAction, oldValue, &newVal, vcpu );

	if ( !INT_SUCCESS( status ) && status != INT_STATUS_NOT_FOUND ) {
		if ( status == INT_STATUS_FATAL_ERROR )
			g_stop = 1;

		bdvmi::logger << bdvmi::WARNING << "Introcore MSR callback returned code " << std::hex << std::showbase
		              << status << std::flush;
		return;
	}

	handleIntrocoreAction( introAction, hvAction, true, false );
}

void HvmiEventHandler::handlePageFault( unsigned short vcpu, const bdvmi::Registers &regs, uint64_t physAddress,
                                        uint64_t virtAddress, bool read, bool write, bool execute, bool /* inGpt */,
                                        bdvmi::HVAction &hvAction, bdvmi::EmulatorContext &emulatorCtx,
                                        unsigned short &instructionLength )
{
	INTRO_ACTION introAction = introGuestAllowed;
	hvAction                 = bdvmi::NONE;
	INTSTATUS   status       = INT_STATUS_SUCCESS;
	std::string type = std::string( ( read ? "r" : "-" ) ) + ( write ? "w" : "-" ) + ( execute ? "x" : "-" );
	BYTE        violation =
	    ( write ? IG_EPT_HOOK_WRITE : 0 ) | ( read ? IG_EPT_HOOK_READ : 0 ) | ( execute ? IG_EPT_HOOK_EXECUTE : 0 );

	if ( !pim_ )
		return;

	status = pim_->EPTViolation( physAddress, virtAddress, vcpu, &introAction, violation, regs, emulatorCtx );

	instructionLength = 0;

	if ( ( INT_SUCCESS( status ) || status == INT_STATUS_FORCE_ACTION_ON_BETA ) &&
	     introAction == introGuestNotAllowed )
		instructionLength = pim_->currentInstructionLength( vcpu );

	if ( status == INT_STATUS_FORCE_ACTION_ON_BETA ) {
		hvAction = bdvmi::SKIP_INSTRUCTION;
		return;
	}

	if ( !INT_SUCCESS( status ) ) {
		if ( status == INT_STATUS_FATAL_ERROR )
			g_stop = 1;

		if ( status != INT_STATUS_NOT_FOUND )
			bdvmi::logger << bdvmi::WARNING << "Introcore EPT callback returned code " << std::hex
			              << std::showbase << status << ", violation: " << type << std::flush;
		return;
	}

	handleIntrocoreAction( introAction, hvAction, false, execute );
}

void HvmiEventHandler::handleVMCALL( unsigned short vcpu, const bdvmi::Registers &regs )
{
	if ( !pim_ )
		return;

	INTSTATUS status = pim_->VMCALL( vcpu, regs );

	if ( !INT_SUCCESS( status ) && status != INT_STATUS_NOT_FOUND ) {
		if ( status == INT_STATUS_FATAL_ERROR )
			g_stop = 1;

		bdvmi::logger << bdvmi::WARNING << "Introcore VMCALL callback returned code " << std::hex
		              << std::showbase << status << std::flush;
	}
}

void HvmiEventHandler::handleXSETBV( unsigned short vcpu )
{
	INTRO_ACTION action = introGuestAllowed;

	if ( !pim_ )
		return;

	INTSTATUS status = pim_->XSETBV( vcpu, &action );

	if ( !INT_SUCCESS( status ) && status != INT_STATUS_NOT_FOUND ) {
		if ( status == INT_STATUS_FATAL_ERROR )
			g_stop = 1;

		bdvmi::logger << bdvmi::WARNING << "Introcore XSETBV callback returned code " << std::hex
		              << std::showbase << status << std::flush;
	}
}

bool HvmiEventHandler::handleBreakpoint( unsigned short vcpu, const bdvmi::Registers &regs, uint64_t gpa )
{
	if ( !pim_ )
		return false;

	INTSTATUS status = pim_->breakpoint( vcpu, regs, gpa );

	if ( !INT_SUCCESS( status ) && status != INT_STATUS_NOT_FOUND ) {
		if ( status == INT_STATUS_FATAL_ERROR || status == INT_STATUS_UNINIT_BUGCHECK )
			g_stop = 1;

		if ( status != INT_STATUS_NOT_INITIALIZED )
			bdvmi::logger << bdvmi::WARNING << "Introcore breakpoint callback returned code " << std::hex
			              << std::showbase << status << std::flush;
	}

	return ( status == INT_STATUS_UNINIT_BUGCHECK || INT_SUCCESS( status ) );
}

void HvmiEventHandler::handleInterrupt( unsigned short vcpu, const bdvmi::Registers &regs, uint32_t vector,
                                        uint64_t errorCode, uint64_t cr2 )
{
	if ( !pim_ )
		return;

	INTSTATUS status = pim_->injection( vector, errorCode, cr2, vcpu, regs );

	if ( !INT_SUCCESS( status ) && status != INT_STATUS_NOT_FOUND ) {
		if ( status == INT_STATUS_FATAL_ERROR )
			g_stop = 1;

		bdvmi::logger << bdvmi::WARNING << "Introcore injection callback returned code " << std::hex
		              << std::showbase << status << std::flush;
	}
}

void HvmiEventHandler::handleDescriptorAccess( unsigned short vcpu, const bdvmi::Registers &regs, unsigned int flags,
                                               unsigned short &instructionLength, bdvmi::HVAction &hvAction )
{
	if ( !pim_ )
		return;

	INTRO_ACTION introAction = introGuestAllowed;

	INTSTATUS status = pim_->descriptorAccess( vcpu, regs, flags, &introAction );

	if ( !INT_SUCCESS( status ) && status != INT_STATUS_NOT_FOUND ) {
		if ( status == INT_STATUS_FATAL_ERROR )
			g_stop = 1;

		bdvmi::logger << bdvmi::WARNING << "Introcore descriptor callback returned code " << std::hex
		              << std::showbase << status << std::flush;
		return;
	}

	instructionLength = 0;

	if ( INT_SUCCESS( status ) && introAction == introGuestNotAllowed )
		instructionLength = pim_->currentInstructionLength( vcpu );

	handleIntrocoreAction( introAction, hvAction, false, false );
}

void HvmiEventHandler::handleSessionOver( bdvmi::GuestState guestState )
{
	if ( !pim_ )
		return;

	pim_->notifySessionOver( guestState );
}

void HvmiEventHandler::handleFatalError()
{
	bdvmi::logger << bdvmi::ERROR << "Fatal error trying to access domain (most likely forced shutdown), exiting!"
	              << std::flush;

	bdvmi::logger << bdvmi::DEBUG << "Domain status: unhooked" << std::flush;

	g_stop = 1;
}

void HvmiEventHandler::runPreEvent()
{
	if ( g_reload ) {
		bdvmi::logger << bdvmi::INFO << "RELOAD REQUEST" << std::flush;
		g_reload = 0;

		if ( pim_ ) {
			uint64_t introspectionOptions = settings_.introspectionOptions_;

			if ( settings_.loadVmPolicy( domainUuid_ ) &&
			     introspectionOptions != settings_.introspectionOptions_ ) {
				bdvmi::logger << bdvmi::DEBUG << "Introspection options changed from " << std::hex
				              << std::showbase << introspectionOptions << " to "
				              << settings_.introspectionOptions_ << std::flush;
				pim_->updateIntrocoreOptions( settings_ );
			}

			pim_->updateLiveUpdate();
			pim_->updateExceptions();
			pim_->updateUserExclusions();
			pim_->updateProtections();
		}
	}
}

void HvmiEventHandler::runPostEvent()
{
	if ( !pim_ )
		return;

	IntrocoreManager::PostEventAction pea = pim_->postEventAction();

	switch ( pea ) {
		case IntrocoreManager::POST_EVENT_ACTION_SET_PROTECTED_PROCESSES:
			pim_->updateProtections();
			break;
		case IntrocoreManager::POST_EVENT_ACTION_INJECT_AGENT_KILLER:
			pim_->injectAgentKiller();
			break;
		default:
			break;
	}

	pim_->getStartupTime();

	pim_->sendGuestHookEvent();
}

void HvmiEventHandler::handleIntrocoreAction( INTRO_ACTION introAction, bdvmi::HVAction &hvAction, bool crOrMsr,
                                              bool /* execute */ ) const
{
	if ( !pim_ )
		return;

	switch ( introAction ) {

		case introGuestNotAllowed: {
			Action        action      = HvmiEventHandler::ACT_ALLOW;
			PrimaryAction actionTaken = PA_LOG;

			intro_output( bdvmi::INFO, "Introcore requested action: GuestNotAllowed" );

			settings_.getAction( pim_->isLastEventInUserspace(), pim_->lastEventProcessId(), action,
			                     actionTaken );

			switch ( action ) {

				case HvmiEventHandler::ACT_ALLOW_NOWRITE:
					if ( crOrMsr ) {
						intro_output( bdvmi::INFO, "Skipping CR/MSR write" );
						hvAction = bdvmi::SKIP_INSTRUCTION;
					} else {
						intro_output( bdvmi::INFO,
						              "Emulating next instruction without the write" );
						hvAction = bdvmi::EMULATE_NOWRITE;
					}
					break;

				case HvmiEventHandler::ACT_SKIP:
					if ( crOrMsr ) {
						intro_output( bdvmi::INFO, "Skipping CR/MSR write" );
					} else {
						intro_output( bdvmi::INFO, "Skipping next instruction" );
					}
					hvAction = bdvmi::SKIP_INSTRUCTION;
					break;

				case HvmiEventHandler::ACT_SHUTDOWN:
					intro_output( bdvmi::INFO, "Shutting the domain down" );
					driver_.shutdown();
					break;

				case HvmiEventHandler::ACT_ALLOW:
				default:
					intro_output( bdvmi::INFO, "Ignoring violation event" );
					break;
			}

			break;
		}

		case introGuestRetry:
			intro_output( bdvmi::INFO, "Introcore requested action: GuestRetry" );
			hvAction = bdvmi::ALLOW_VIRTUAL;
			break;

		case introGuestAllowedVirtual:
			hvAction = bdvmi::ALLOW_VIRTUAL;
			break;

		case introGuestAllowedPatched:
			intro_output( bdvmi::INFO, "Introcore requested action: GuestAllowedPatched" );
			hvAction = bdvmi::EMULATE_SET_CTXT;
			break;

		default:
			break;
	}
}
