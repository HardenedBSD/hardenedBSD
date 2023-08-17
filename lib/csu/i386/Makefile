
.PATH: ${.CURDIR:H}/common

CFLAGS+=	-I${.CURDIR}
CFLAGS+=	-DCRT_IRELOC_REL

MK_CROSS_DSO_CFI=	no

CRT1SRC=	crt1_s.S
CRT1OBJ=	crt1_c.o

.include <bsd.lib.mk>
