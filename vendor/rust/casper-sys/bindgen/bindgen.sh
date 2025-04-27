#! /bin/sh

# Must be run on FreeBSD 13 or lower.  FreeBSD 14's libnv has a higher .so
# version, and uses different symbol names.  The symbol names are aliased to
# the old ones with macros for backwards compatibility, but bindgen doesn't
# understand macros.  Once generated, the bindgen bindings will work on either
# FreeBSD 13 or 14+.

CRATEDIR=`dirname $0`/..

bindgen --generate functions,types \
	--allowlist-function 'cap_.*' \
	--allowlist-function 'service_register' \
	--blocklist-type 'nvlist' \
	${CRATEDIR}/bindgen/wrapper.h > ${CRATEDIR}/src/ffi.rs
