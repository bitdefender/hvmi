/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef __HVMID_H__
#define __HVMID_H__

#include "config.h"

#define HVMID_NAME        PROJECT_DESCRIPTION
#define HVMID_DAEMON_NAME PROJECT_NAME

#define HVMID_PIDFILE     PROJECT_RUNSTATEDIR "/" HVMID_DAEMON_NAME ".pid"

constexpr int HVMID_EXIT_TIMEOUT        = 3 * 60; // 3 whole minutes
constexpr int HVMID_PARENT_EXIT_TIMEOUT = HVMID_EXIT_TIMEOUT + 5;

#endif /* __HVMID_H__ */
