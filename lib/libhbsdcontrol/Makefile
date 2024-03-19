.include <bsd.own.mk>

PACKAGE=lib${LIB}
SHLIBDIR?= /lib

LIB=		hbsdcontrol
SHLIB_MAJOR=	0

CFLAGS+=	-I${.CURDIR}

SRCS=		aslr.c
SRCS+=		libhbsdcontrol.c
INCS=		libhbsdcontrol.h
MAN=

LIBADD+=	pthread
LIBADD+=	util

.include <bsd.lib.mk>
