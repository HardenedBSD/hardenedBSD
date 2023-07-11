# $FreeBSD$

.include <bsd.init.mk>

.PATH: ${.CURDIR:H}/common

CFLAGS+=	-I${.CURDIR}
CFLAGS+=	-DCRT_IRELOC_REL

<<<<<<< HEAD
MK_CROSS_DSO_CFI=	no

CRT1OBJS+=	crt1_s.o
=======
CRT1SRC=	crt1_s.S
CRT1OBJ=	crt1_c.o
>>>>>>> internal/hardened/current/master

.include <bsd.lib.mk>
