PACKAGE=	hardenedbsd

SHLIB=		lattzfs
SHLIB_MAJOR=	0

.PATH:		${SRCTOP}/contrib/hardenedbsd/liblattzfs/src
.PATH:		${SRCTOP}/contrib/hardenedbsd/liblattzfs/include

SRCS+=		liblattzfs.c

INCS+=		liblattzfs.h

CFLAGS+=	-I${SRCTOP}/contrib/hardenedbsd/liblattzfs/include
CFLAGS+=	-DIN_BASE -DHAVE_RPC_TYPES
CFLAGS+= 	-I${SRCTOP}/sys/contrib/openzfs/include
CFLAGS+= 	-I${SRCTOP}/sys/contrib/openzfs/include/os/freebsd
CFLAGS+= 	-I${SRCTOP}/sys/contrib/openzfs/lib/libspl/include
CFLAGS+= 	-I${SRCTOP}/sys/contrib/openzfs/lib/libspl/include/os/freebsd
CFLAGS+= 	-I${SRCTOP}/sys
CFLAGS+= 	-I${SRCTOP}/cddl/compat/opensolaris/include
CFLAGS+= 	-include ${SRCTOP}/sys/contrib/openzfs/include/os/freebsd/spl/sys/ccompile.h
CFLAGS+= 	-DHAVE_ISSETUGID -DHAVE_STRLCAT -DHAVE_STRLCPY

LIBADD+=		zfs nvpair spl

FORTIFY_SOURCE=	0

.include <bsd.lib.mk>
