/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef LINUX_AGENT_TYPES_H_
#define LINUX_AGENT_TYPES_H_

#include <stdint.h>

#define AGENT_HCALL_GATHER_TOOL 500

#define REN_MAX_OBJECT_PATH_LEN 512
#define LGT_MAX_DATA_SIZE 4096
#define LGT_EVENT_VERSION 0x10000

/*
 * XXX: Keep these structs synched with the ones from
 * `include/public/intro_types.h':
 *      - AGENT_LGT_EVENT_TYPE -> enum agent_lgt_event_type
 *      - AGENT_LGT_EVENT_HEADER -> struct agent_lgt_event_header
 *      - AGENT_LGT_EVENT -> struct agent_lgt_event
 */

enum agent_lgt_event_type
{
    LGT_EVENT_NONE = 0,
    LGT_EVENT_ERROR,
    LGT_EVENT_DATA
};

struct agent_lgt_event_header
{
    uint32_t version;
    uint32_t size;
    uint32_t reserved1;
    uint32_t event_type;
};

/*
 * Describes the event sent by the log gathering tool.
 */
struct agent_lgt_event
{
    struct agent_lgt_event_header header;

    union {
        struct {
            uint16_t filename[REN_MAX_OBJECT_PATH_LEN];
            uint32_t size;
            uint8_t data[LGT_MAX_DATA_SIZE];
        } file;

        struct {
            uint32_t error_code;
        } err;
    } content;
};

#define LGT_EVENT_SIZE sizeof(struct agent_lgt_event)

#endif
