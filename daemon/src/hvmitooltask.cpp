/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include <algorithm>
#include "hvmitooltask.h"
#include "introcoremanager.h"
#include <json/json.h>
#include <bdvmi/logger.h>
#include <stdexcept>

ToolStatusHelper::ToolStatusHelper( const std::string &uuid, const std::string &sessionId, const std::string &policyId,
                                    const std::string &taskId, const std::string &toolId,
                                    unsigned int /* triggerType */, bool internalFeedback, bool reportOnDestruction )
    : uuid_{ uuid }
    , sessionId_{ sessionId }
    , policyId_{ policyId }
    , taskId_{ taskId }
    , toolId_{ toolId }
    , internalFeedback_{ internalFeedback }
    , reportOnDestruction_{ reportOnDestruction }
{
}

ToolStatusHelper::ToolStatusHelper( const std::string &uuid, const std::string &sessionId, const Tool &tool,
                                    bool internalFeedback, bool reportOnDestruction )
    : uuid_{ uuid }
    , sessionId_{ sessionId }
    , policyId_{ tool.policyId_ }
    , taskId_{ tool.taskId_ }
    , toolId_{ tool.toolId_ }
    , internalFeedback_{ internalFeedback }
    , reportOnDestruction_{ reportOnDestruction }
{
}

ToolStatusHelper::~ToolStatusHelper()
{
}

void ToolStatusHelper::reportStatus( unsigned int /* state */, const std::string & /* logsLocation */ ) const
{
}

TaskStatusHelper::TaskStatusHelper( const std::string &uuid, const Task &task )
    : uuid_{ uuid }
    , policyId_{ task.policyId_ }
    , taskId_{ task.taskId_ }
{
}

TaskStatusHelper::~TaskStatusHelper()
{
	reportStatus();
}

void TaskStatusHelper::reportStatus() const
{
}

ActiveAgentManager::ActiveAgentManager( IntrocoreManager *pim, const Tool &agent )
    : pim_{ pim }
    , agent_{ agent }
{
	if ( pim_ )
		pim_->setTaskAgent( agent_ );
}

ActiveAgentManager::~ActiveAgentManager()
{
	if ( pim_ )
		pim_->resetTaskAgent();
}
