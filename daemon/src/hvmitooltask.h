/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef __HVMITOOLTASK_H_INCLUDED__
#define __HVMITOOLTASK_H_INCLUDED__

#include <deque>
#include <mutex>
#include <string>

class IntrocoreManager;

struct Tool {

	enum Type { BD_INTERNAL = 0, CUSTOM = 1 };

	enum OSType {
		OS_LINUX        = 1,
		OS_WINDOWS_32   = 2,
		OS_WINDOWS_64   = 4,
		OS_WINDOWS_BOTH = 6 // OS_WINDOWS_32 | OS_WINDOWS_64
	};

	struct ToolHash {
		std::string md5_;
	};

	struct Logs {
		struct Share {
			std::string path_;
			std::string username_;
			std::string password_;
		};

		bool        logStdout_{ false };
		bool        getLogFile_{ true };
		bool        deleteLogFiles_{ false };
		std::string logFile_;
		Share       share_;
	};

	// Needed so Tool is usable as a std::set<> item.
	bool operator<( const Tool &other ) const
	{
		return ( toolId_ + cmdLineParams_ ) < ( other.toolId_ + cmdLineParams_ );
	}

public:
	std::string policyId_;
	std::string toolId_;
	int         toolType_{ CUSTOM };
	int         autoTermination_{ -1 };
	std::string toolName_;
	std::string toolURL_;
	std::string toolPath_;
	ToolHash    toolHash_;
	int         os_{ -1 };
	std::string cmdLineParams_;
	bool        injectOnViolation_{ false };
	Logs        logs_;
	bool        scheduled_{ false };
	std::string taskId_; // Repeat this information here for convenience.
	bool        downloadFailed_{ false };
};

struct Task {

	std::string      policyId_;
	std::string      taskId_;
	std::deque<Tool> tools_;
	bool             scheduled_{ false };

private:
	size_t hash_{ 0 };
};

class ToolStatusHelper {

public:
	ToolStatusHelper( const std::string &uuid, const std::string &sessionId, const std::string &policyId,
	                  const std::string &taskId, const std::string &toolId, unsigned int triggerType,
	                  bool internalFeedback, bool reportOnDestruction );

	ToolStatusHelper( const std::string &uuid, const std::string &sessionId, const Tool &tool,
	                  bool internalFeedback, bool reportOnDestruction );

	~ToolStatusHelper();

public:
	void errorCode( long error )
	{
		error_ = error;
	}

	void reportStatus( unsigned int state, const std::string &logsLocation = "" ) const;

	void reportStatus( unsigned int state, long error, const std::string &logsLocation = "" )
	{
		errorCode( error );
		reportStatus( state, logsLocation );
	}

private:
	std::string uuid_;
	std::string sessionId_;
	std::string policyId_;
	std::string taskId_;
	std::string toolId_;
	long        error_{ 0 };
	bool        internalFeedback_;
	bool        reportOnDestruction_;
};

class TaskStatusHelper {

public:
	TaskStatusHelper( const std::string &uuid, const Task &task );
	~TaskStatusHelper();

public:
	void reportStatus() const;

private:
	std::string uuid_;
	std::string policyId_;
	std::string taskId_;
};

// RAII tricks.
class ActiveAgentManager {

public:
	ActiveAgentManager( IntrocoreManager *pim, const Tool &agent );
	~ActiveAgentManager();

	ActiveAgentManager( const ActiveAgentManager & ) = delete;
	ActiveAgentManager &operator=( const ActiveAgentManager & ) = delete;

private:
	IntrocoreManager *pim_;
	Tool              agent_;
};

#endif // __HVMITOOLTASK_H_INCLUDED__
