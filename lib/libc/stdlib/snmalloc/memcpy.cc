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

#include <global/memcpy.h>

#include "bounds.hh"

namespace {
/**
 * ifunc resolver for memcpy.  Selects the implementation based on the bounds
 * checks environment variable.
 */
extern "C" decltype(&memcpy)
memcpy_resolver()
{
	return __libc_private::functionVariant<snmalloc::memcpy<true, true>,
	    snmalloc::memcpy<true, false>, snmalloc::memcpy<false, false>>();
}
}

/**
 * memcpy declaration, implementation is provided by the ifunc resolver.
 */
void *memcpy(void *dest, const void *src, size_t n)
    __attribute__((ifunc("memcpy_resolver")));
