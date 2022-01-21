/*-
 * SPDX-License-Identifier: MIT
 *
 * Copyright (c) Microsoft Corporation. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE
 */

/**
 * This file contains the integration point between snmalloc and FreeBSD libc.
 * The real implementations are all in snmalloc's override/malloc.cc in
 * contrib.  These are built with double-underscore prefixes, this file exposes
 * them as non-prefixed versions with weak linkage allowing them to be
 * replaced.
 */

#include <sys/cdefs.h>

#include "override/jemalloc_compat.cc"
#include "override/malloc.cc"

#define EXPOSE_WEAK_ALIAS(x) __weak_reference(__##x, x)

/*
 * The strong definitions of these are all provided by snmalloc's
 * override/malloc.cc, with the double-underscore prefix.  We provide the
 * non-prefixed versions with weak linkage here.
 */
EXPOSE_WEAK_ALIAS(malloc);
EXPOSE_WEAK_ALIAS(calloc);
EXPOSE_WEAK_ALIAS(realloc);
EXPOSE_WEAK_ALIAS(free);
EXPOSE_WEAK_ALIAS(posix_memalign);
EXPOSE_WEAK_ALIAS(malloc_usable_size);
EXPOSE_WEAK_ALIAS(aligned_alloc);
EXPOSE_WEAK_ALIAS(mallctl);
EXPOSE_WEAK_ALIAS(mallctlnametomib);
EXPOSE_WEAK_ALIAS(mallctlbymib);
EXPOSE_WEAK_ALIAS(mallocx);
EXPOSE_WEAK_ALIAS(rallocx);
EXPOSE_WEAK_ALIAS(xallocx);
EXPOSE_WEAK_ALIAS(sallocx);
EXPOSE_WEAK_ALIAS(dallocx);
EXPOSE_WEAK_ALIAS(nallocx);
EXPOSE_WEAK_ALIAS(allocm);
EXPOSE_WEAK_ALIAS(rallocm);
EXPOSE_WEAK_ALIAS(sallocm);
EXPOSE_WEAK_ALIAS(dallocm);
EXPOSE_WEAK_ALIAS(nallocm);
EXPOSE_WEAK_ALIAS(sdallocx);

/*
 * These are not provided by snmalloc and so are defined here as stubs.
 */
extern "C" {
void (*malloc_message)(void *cbopaque, const char *s);
const char *_malloc_options;
const char *_malloc_conf;
void
__malloc_stats_print(void (*)(void *, const char *), void *, const char *)
{
}
}
EXPOSE_WEAK_ALIAS(malloc_stats_print);
