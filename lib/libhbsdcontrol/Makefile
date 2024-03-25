.include <bsd.own.mk>

PACKAGE=lib${LIB}
SHLIBDIR?= /lib

LIB=		hbsdcontrol
SHLIB_MAJOR=	0

CFLAGS+=	-I${.CURDIR}

SRCS=		libhbsdcontrol.c
INCS=		libhbsdcontrol.h

# Features
SRCS+=		aslr.c
SRCS+=		mprotect.c
SRCS+=		pageexec.c
SRCS+=		segvguard.c
SRCS+=		shlibrandom.c

MAN=

LIBADD+=	pthread
LIBADD+=	util

.include <bsd.lib.mk>
