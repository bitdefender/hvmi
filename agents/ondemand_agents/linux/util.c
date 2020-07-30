/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdint.h>
#include <sys/mman.h>
#include <stdio.h>
#include "util.h"
#include "vmcall.h"
#include "types.h"

/*
 * Notify intro that an error occured
 */
void
notify_error(
    int error_code
    )
{
    struct agent_lgt_event *data = calloc(1, sizeof(*data));
    if (data == NULL)
    {
        perror("calloc");
        return;
    }

    if (mlock(data, sizeof(*data)))
    {
        perror("mlock");
        return;
    }

    data->header.version = LGT_EVENT_VERSION;
    data->header.size = LGT_EVENT_SIZE;
    data->header.event_type = LGT_EVENT_ERROR;

    data->content.err.error_code = error_code;

    intro_call(data, AGENT_HCALL_GATHER_TOOL);

    if (munlock(data, sizeof(*data)))
    {
        perror("munlock");
    }

    free(data);
}

/*
 * Naively convert a normal string to a wide char string.
 *
 * TODO: Find a way to use something standard such as mbstowcs instead of
 *       deploying this crude version.
 */
void
stow(
    void *dst,
    const void *src,
    size_t n
    )
{
    uint8_t *d = dst;
    const uint8_t *s = src;

    while (n-- > 0)
    {
        *d++ = *s++;
        *d++ = '\0';
    }
}
