/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _UTIL_H
#define _UTIL_H

#include <stdlib.h>

/* Notify intro that an error occured */
extern void
notify_error(
    int error_code
    );

/*
 * Naively convert a normal string to a wide char string.
 */
extern void
stow(
    void *dst,
    const void *src,
    size_t n
    );

#endif /* _UTIL_H */
