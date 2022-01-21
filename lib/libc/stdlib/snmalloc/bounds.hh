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

#include <atomic>
#include <type_traits>
extern "C" char **environ;

/**
 * This file contains helpers to define ifuncs that enable heap bounds checking
 * on all pointer arguments, no pointer arguments, or only output arguments.
 */
namespace __libc_private {

/**
 * Which bounds checks are enabled?
 */
enum class BoundsChecks {
	/**
	 * `environ` has not yet been parsed, unknown.
	 */
	Unknown = 0,
	/**
	 * No bounds checks.
	 */
	None,
	/**
	 * Only stores are bounds checked
	 */
	WriteOnly,
	/**
	 * Read and write bounds checks.
	 */
	ReadWrite,
};

/**
 * Environment variable to check to see if bounds checks are enabled.
 */
constexpr char envVarName[] = "LIBC_BOUNDS_CHECKS=";

/**
 * Check the bounds checks mode.  The first call to this will parse the
 * environment variable, subsequent calls will read a cached value.
 */
__noinline inline BoundsChecks
boundsChecksMode()
{
	static std::atomic<BoundsChecks> mode;
	BoundsChecks m = mode.load(std::memory_order_relaxed);

	if (mode.load(std::memory_order_relaxed) == BoundsChecks::Unknown) {
		// Default to write-only checking
		m = BoundsChecks::WriteOnly;
		// The getenv function calls functions that may trigger the
		// resolver, so use `environ` directly.
		for (char **env = environ; *env; ++env) {
			// It should not be possible for the first call to this
			// function to happen after we've started a second
			// thread - starting a thread without calling `memcpy`
			// is technically possible, but not practical.
			char *e = *env;
			bool found = true;
			int i = 0;
			for (; i < (sizeof(envVarName) - 1); i++) {
				if (e[i] != envVarName[i]) {
					found = false;
					e += i;
					break;
				}
			}
			if (found) {
				switch (e[i]) {
				case '0':
					m = BoundsChecks::None;
					break;
				default:
				case '1':
					m = BoundsChecks::WriteOnly;
					break;
				case '2':
					m = BoundsChecks::ReadWrite;
					break;
				}
				mode.store(m, std::memory_order_relaxed);
			}
		}
	}
	return m;
};

/**
 * Returns the correct version of the function for the given bounds-checking
 * mode.
 */
template <auto ReadWriteChecks, auto WriteOnlyChecks, auto NoChecks>
__always_inline std::remove_reference_t<decltype(NoChecks)>
functionVariant()
{
	switch (boundsChecksMode()) {
	case BoundsChecks::ReadWrite:
		return ReadWriteChecks;
	case BoundsChecks::WriteOnly:
		return WriteOnlyChecks;
	case BoundsChecks::None:
		return NoChecks;
	case BoundsChecks::Unknown:
	default:
		__builtin_trap();
	}
}
}
