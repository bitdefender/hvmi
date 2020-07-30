/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef __HVMIEVENTHANDLER_H_INCLUDED__
#define __HVMIEVENTHANDLER_H_INCLUDED__

#include <bdvmi/eventhandler.h>
#include <string>
#include <introcore.h>

// Forward declaration
class IntrocoreManager;

namespace bdvmi {

// Forward declarations
class Driver;
struct Registers;
struct EmulatorContext;
}

class HvmiSettings;

class HvmiEventHandler : public bdvmi::EventHandler {

public:
	enum Action { ACT_ALLOW, ACT_ALLOW_NOWRITE, ACT_SHUTDOWN, ACT_SKIP };

public:
	HvmiEventHandler( bdvmi::Driver &driver, HvmiSettings &settings );

public:
	// Callback for CR3 write events
	void handleCR( unsigned short vcpu, unsigned short crNumber, const bdvmi::Registers &regs, uint64_t oldValue,
	               uint64_t newValue, bdvmi::HVAction &hvAction ) override;

	// Callback for writes in MSR addresses
	void handleMSR( unsigned short vcpu, uint32_t msr, uint64_t oldValue, uint64_t newValue,
	                bdvmi::HVAction &hvAction ) override;

	// Callback for page faults
	void handlePageFault( unsigned short vcpu, const bdvmi::Registers &regs, uint64_t physAddress,
	                      uint64_t virtAddress, bool read, bool write, bool execute, bool inGpt,
	                      bdvmi::HVAction &action, bdvmi::EmulatorContext &emulatorCtx,
	                      unsigned short &instructionLength ) override;

	void handleVMCALL( unsigned short vcpu, const bdvmi::Registers &regs ) override;

	void handleXSETBV( unsigned short vcpu ) override;

	bool handleBreakpoint( unsigned short vcpu, const bdvmi::Registers &regs, uint64_t gpa ) override;

	void handleInterrupt( unsigned short vcpu, const bdvmi::Registers &regs, uint32_t vector, uint64_t errorCode,
	                      uint64_t cr2 ) override;

	void handleDescriptorAccess( unsigned short vcpu, const bdvmi::Registers &regs, unsigned int flags,
	                             unsigned short &instructionLength, bdvmi::HVAction &hvAction ) override;

	void handleSessionOver( bdvmi::GuestState guestState ) override;

	void handleFatalError() override;

	void setIntrocoreManager( IntrocoreManager *pim )
	{
		pim_ = pim;
	}

private:
	void runPreEvent() override;

	void runPostEvent() override;

	void handleIntrocoreAction( INTRO_ACTION introAction, bdvmi::HVAction &hvAction, bool crOrMsr,
	                            bool execute ) const;

private:
	IntrocoreManager *pim_{ nullptr };
	bdvmi::Driver &   driver_;
	std::string       domainUuid_;
	HvmiSettings &    settings_;
};

#endif // __HVMIEVENTHANDLER_H_INCLUDED__
