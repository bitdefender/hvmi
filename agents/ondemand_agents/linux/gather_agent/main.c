/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "gather_agent.h"

static
void print_usage(
    const char *progname
    );

int
main(
    int argc,
    char **argv
    )
{
    glob_t globbuf;
    int i, rmfiles, have_files;

    if (argc < 2)
    {
        goto _err_exit;
    }

    rmfiles = 0;
    have_files = 0;

    for (i = 1; i < argc; i++)
    {
        if (argv[i][0] == '-')
        {
            if (0 == strcmp(argv[i], "-rmlogs"))
            {
                rmfiles = 1;
                continue;
            }
        }

        have_files = 1;
        expand_paths(&globbuf, argv[i]);
    }

    if (!have_files)
    {
        goto _err_exit;
    }

    send_files(&globbuf, rmfiles);

    globfree(&globbuf);

    return 0;

_err_exit:
    print_usage(argv[0]);

    notify_error(EINVAL);
    exit(EXIT_FAILURE);
}

static
void
print_usage(
    const char *progname
    )
{
    fprintf(stderr, "Usage: %s [-rmlogs] filename [filename...]\n\n"
            "Uses glob to expand filenames, but directories aren't read.\n"
            "Instead of `/var/log' use `/var/log/*'.\n",
            progname);
}
