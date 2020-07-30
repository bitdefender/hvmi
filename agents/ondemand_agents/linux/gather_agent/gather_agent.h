/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include <glob.h>

#ifndef GATHER_AGENT_H
#define GATHER_AGENT_H

/* Use glob(3) to expand paths. */
extern
void
expand_paths(
    glob_t *globbuf,
    const char *path
    );

/* Send the contents of all regular files that glob has expanded. */
extern
void
send_files(
    const glob_t *globbuf,
    int delete_after_send
    );

/* Notify intro that an error occured */
extern
void
notify_error(
    int error_code
    );

#endif /* GATHER_AGENT_H */
