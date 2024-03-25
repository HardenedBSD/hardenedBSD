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
SRCS+=		disallow_map32bit.c
SRCS+=		harden_shm.c
SRCS+=		insecure_kmod.c
SRCS+=		mprotect.c
SRCS+=		pageexec.c
SRCS+=		segvguard.c
SRCS+=		shlibrandom.c

MAN=

LIBADD+=	pthread
LIBADD+=	util

.include <bsd.lib.mk>
