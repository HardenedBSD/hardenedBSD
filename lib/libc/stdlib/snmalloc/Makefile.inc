.PATH: ${LIBC_SRCTOP}/stdlib/snmalloc

MISRCS+=	malloc.cc memcpy.cc

SYM_MAPS+=	${LIBC_SRCTOP}/stdlib/snmalloc/Symbol.map

# Specify the locations in contrib for headers.
CXXFLAGS+=	-I${SRCTOP}/contrib/snmalloc/src/snmalloc

# C++ dialect options.  -mcx16 is needed to avoid calls to libatomic.
CXXFLAGS+=	-std=c++20 -mcx16 -fno-exceptions -fno-rtti

# Require an explicit call from libthr to clean up thread-local state
CXXFLAGS+=	-DSNMALLOC_USE_THREAD_CLEANUP
# Export the __je_bootstrap_* functions for TLS allocation.
CXXFLAGS+=	-DSNMALLOC_BOOTSTRAP_ALLOCATOR
# Export compatibility implementations of the jemalloc non-standard and
# experimental APIs that are now part of the ABI contract for libc.
CXXFLAGS+=	-DSNMALLOC_JEMALLOC3_EXPERIMENTAL
CXXFLAGS+=	-DSNMALLOC_JEMALLOC_NONSTANDARD
# Use getentropy for random numbers.
CXXFLAGS+=	-DSNMALLOC_PLATFORM_HAS_GETENTROPY
# Prefix all of these functions with double underscore:
CXXFLAGS+=	-DSNMALLOC_STATIC_LIBRARY_PREFIX=__

# libc is not dlopened, use initial-exec allow fast access to the thread-local
# allocator (fast path for malloc and free)
CXXFLAGS+=	-ftls-model=initial-exec

.if ${MK_MALLOC_PRODUCTION} != "yes" || !defined(MALLOC_PRODUCTION)
CXXFLAGS+=	-DSNMALLOC_CHECK_CLIENT
CXXFLAGS+=	-DSNMALLOC_FAIL_FAST=false
.endif

# Don't emit frame pointers, the fast path for malloc is sufficiently small
# that this adds measurable overhead.
SHARED_CXXFLAGS+=	-fomit-frame-pointer
STATIC_CXXFLAGS+=	-fomit-frame-pointer
PO_CXXFLAGS+=	-fno-omit-frame-pointer

# Disable asserts.  There are enough of these that it hurts performance a lot
# and doesn't help if you're debugging anything other than malloc.
CXXFLAGS+=	-DNDEBUG

# snmalloc relies a lot on inlining.  If a new version breaks, uncomment these
# lines to make it easy to debug.
#CXXFLAGS+=	-O0 -fno-inline

