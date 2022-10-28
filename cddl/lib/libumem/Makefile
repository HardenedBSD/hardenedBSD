# $FreeBSD$

.PATH: ${SRCTOP}/cddl/compat/opensolaris/lib/libumem

PACKAGE=	zfs
LIB=	umem
SRCS=	umem.c
WARNS?=	3
CFLAGS+= -I${SRCTOP}/cddl/compat/opensolaris/lib/libumem

CFI_OVERRIDE=	-fno-sanitize=cfi-icall

.include <bsd.lib.mk>
