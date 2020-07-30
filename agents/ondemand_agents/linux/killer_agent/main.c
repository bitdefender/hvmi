/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <libgen.h>

#define __USE_POSIX
#include <signal.h>

#include "../util.h"

static
void print_usage(
    const char *progname
    );

static int
get_proc_path(
    int pid,
    char *proc_path,
    size_t proc_path_len
    )
{
    char proc_file[32] = {0};
    FILE *f;

    memset(proc_path, 0, proc_path_len);

    sprintf(proc_file, "/proc/%u/cmdline", pid);

    f = fopen(proc_file, "rb");
    if (NULL == f)
    {
        if (errno)
        {
            return errno;
        }

        return ENOENT;
    }

    fread(proc_path, proc_path_len - 1, 1, f);

    fclose(f);

    return 0;
}

static int
kill_process(
    int pid,
    int signal,
    int whole_tree,
    int timeout
    )
//
// If pid > 0 and whole_tree is true, then will use `pid = -pid` to send the signal.
// If pid < 0, then it will ignore whole_tree argument.
// See `man 3 kill` for documentation
//
// If timeout is negative, will wait forever (or until it wraps to 0) for the process end.
//
// /ret EAGIAN if the process couldn't be killed in the given timeout
// /ret EINVAL if kill failed without setting errno (shouldn't happne!)
// /ret errno set from kill (see `man 3 kill`)
//
{
    struct stat buf;
    char proc_file[32] = {0};

    if (whole_tree && pid > 0)
    {
        // pid = -1 * pid;
        // For now ignore the whole_tree
    }

    sprintf(proc_file, "/proc/%u", pid);

    if (0 != kill(pid, signal))
    {
        perror("kill failed");

        if (errno)
        {
            return errno;
        }

        return EINVAL;
    }

    while (timeout && stat(proc_file, &buf))
    {
        --timeout;
        sleep(1);
    }

    if (stat(proc_file, &buf))
    {
        return EAGAIN;
    }

    return 0;
}

#define DEFAULT_TIMEOUT 3

int
main(
    int argc,
    char **argv
    )
{
    int only_safe = 0;
    int timeout = DEFAULT_TIMEOUT;
    int start_proc = 1;
    int whole_tree = 1;

    if (argc < 2)
    {
        goto _usage_err;
    }

    for (int i = 1; i < argc; i++)
    {
        if (argv[i][0] == '-')
        {
            if (strcmp(argv[i], "-safe") == 0)
            {
                only_safe = 1;

                start_proc = i + 1;
            }
            else if (strcmp(argv[i], "-timeout") == 0)
            {
                ++i;

                if (i >= argc)
                {
                    goto _usage_err;
                }

                timeout = atoi(argv[i]);

                start_proc = i + 1;
            }
            else if (strcmp(argv[i], "-no-children") == 0)
            {
                whole_tree = 0;
            }
        }
        else
        {
            break;
        }
    }

    for (int i = start_proc; i < argc; i += 2)
    {
        char *proc_name = argv[i];
        char read_proc_path[1024] = {0}, *read_proc_name;
        pid_t pid;

        if (argv[i][0] == '-')
        {
            continue;
        }

        if (i + 1 >= argc)
        {
            goto _usage_err;
        }

        pid = atoi(argv[i + 1]);
        if (0 == pid)
        {
            fprintf(stderr, "Invalid pid: %s\n", argv[i + 1]);
            continue;
        }

        if (0 != get_proc_path(pid, read_proc_path, sizeof(read_proc_path)))
        {
            fprintf(stderr, "Can't get process name for %s:%d\n", proc_name, pid);
            continue;
        }

        read_proc_name = basename(read_proc_path);

        if (strncmp(proc_name, read_proc_name, strlen(proc_name)) != 0)
        {
            fprintf(stderr, "PID %d is OK, but process name not: %s != %s\n", pid, proc_name, read_proc_name);
            return ESRCH;
        }

        if (kill_process(pid, SIGTERM, whole_tree, timeout))
        {
            if (only_safe)
            {
                continue;
            }

            // no point in checking this, there's nothing we can do
            kill_process(pid, SIGKILL, whole_tree, timeout);
        }
    }

    return 0;

_usage_err:
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
    fprintf(stderr, "Usage: %s [-safe] [-timeout seconds] [[process_name pid] [process_name pid] ...]\n\n", progname);
}
