/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

// Needed for basename
#define _GNU_SOURCE
#include <string.h>

#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <glob.h>
#include <errno.h>
#include <libgen.h>
#include "gather_agent.h"
#include "../util.h"
#include "../vmcall.h"
#include "../types.h"

/*
 * Send the contents of a file to the SVA using vmcall.
 */
static
int
send_file(
    const char *filename
    )
{
    struct agent_lgt_event *data = NULL;
    int fd;
    ssize_t bytes_read;
    int ret = -1;
    char *base;

    fd = open(filename, O_RDONLY);
    if (fd == -1)
    {
        fprintf(stderr, "open %s: %s\n", filename, strerror(errno));
        goto cleanup_and_exit;
    }

    /* Allocate & lock struct in memory. */
    data = calloc(1, sizeof(struct agent_lgt_event));
    if (data == NULL)
    {
        perror("calloc");
        goto cleanup_and_exit;
    }

    if (mlock(data, sizeof(struct agent_lgt_event)))
    {
        perror("mlock");
        goto cleanup_and_exit;
    }

    base = basename((char *)filename);
    if (NULL == base || 0 == strlen(base))
    {
        perror("basename");
        goto cleanup_and_exit;
    }

    /* Fill data. */
    data->header.version = LGT_EVENT_VERSION;
    data->header.size = LGT_EVENT_SIZE;
    data->header.event_type = LGT_EVENT_DATA;
    stow(data->content.file.filename, base, strlen(base));

    /* Read and send chunks. */
    do
    {
        bytes_read = read(fd, data->content.file.data, LGT_MAX_DATA_SIZE);
        if (bytes_read == -1)
        {
            fprintf(stderr, "read %s: %s\n", filename, strerror(errno));
            goto cleanup_and_exit;
        }

        data->content.file.size = bytes_read;

        if (bytes_read > 0)
        {
            intro_call(data, AGENT_HCALL_GATHER_TOOL);
        }

    }
    while (bytes_read);

    ret = 0;

cleanup_and_exit:
    /* Cleanup. */
    if (data)
    {
        /* Send the error number if any. */
        if (errno)
        {
            data->header.event_type = LGT_EVENT_ERROR;
            data->content.err.error_code = errno;
            intro_call(data, AGENT_HCALL_GATHER_TOOL);
        }

        if (munlock(data, sizeof(struct agent_lgt_event)))
        {
            perror("munlock");
        }

        free(data);
    }

    if (fd != -1 && close(fd) == -1)
    {
        fprintf(stderr, "close %s: %s\n", filename, strerror(errno));
    }

    return ret;
}

/*
 * Send the contents of all regular files that glob has expanded.
 */
void
send_files(
    const glob_t *globbuf,
    int delete_after_send
    )
{
    size_t i;
    const char *path;
    struct stat sb;
    int total_sent = 0;

    for (i = 0; i < globbuf->gl_pathc; i++)
    {
        path = globbuf->gl_pathv[i];

        /* Check if we have a regular file. */
        if (stat(path, &sb) == -1)
        {
            fprintf(stderr, "stat %s: %s\n", path, strerror(errno));
            continue;
        }

        if (!S_ISREG(sb.st_mode))
        {
            fprintf(stderr, "%s is not a regular file! Ignoring.\n", path);
            continue;
        }

        if (send_file(path) == -1)
        {
            fprintf(stderr, "send_file %s: Failed to send\n", path);

            // Don't delete this file if we didn't manage to send it
            continue;
        }

        if (delete_after_send && -1 == unlink(path))
        {
            fprintf(stderr, "unlink %s\n", path);
        }

        total_sent++;
    }

    if (0 == total_sent)
    {
        notify_error(ENOENT);
    }
}

/*
 * Use glob(3) to expand paths.
 */
void
expand_paths(
    glob_t *globbuf,
    const char *path
    )
{
    static int first_time = 1;
    int flags = GLOB_NOSORT;

    if (!first_time)
    {
        flags |= GLOB_APPEND;
    }

    /* TODO: If path is a directory, add all its files here. */

    if (glob(path, flags, NULL, globbuf) != 0)
    {
        fprintf(stderr, "glob: %s: Failed\n", path);
    }

    first_time = 0;
}
