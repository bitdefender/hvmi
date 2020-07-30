#!/bin/bash
##
## Copyright (c) 2020 Bitdefender
## SPDX-License-Identifier: Apache-2.0
##

agent_gather_obj=../../../../agents/ondemand_agents/linux/gather_agent/gather_agent
agent_killer_obj=../../../../agents/ondemand_agents/linux/killer_agent/killer_agent

src_file=../../../src/guests/linux/lixagent_ondemand.c
header_file=../../../include/lixagent_ondemand.h

agent_gather_array=gLixGatherAgentx64
agent_killer_array=gLixKillerAgentx64

python3 generator_source.py $header_file $src_file "$agent_gather_obj $agent_gather_array" "$agent_killer_obj $agent_killer_array"
