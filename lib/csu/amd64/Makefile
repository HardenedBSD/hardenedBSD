
.include <src.opts.mk>

.PATH: ${.CURDIR:H}/common

CFLAGS+=	-I${.CURDIR}
CFLAGS+=	-fno-omit-frame-pointer

CRT1SRC=	crt1_s.S
CRT1OBJ=	crt1_c.o

MK_LTOLIB=	no
MK_RELRO=	no
MK_BIND_NOW=	no

NOCFI=			yes
MK_CFI=			no
MK_CROSS_DSO_CFI=	no

.include <bsd.lib.mk>
