
.include <src.opts.mk>

.PATH: ${.CURDIR:H}/common

CFLAGS+=	-I${.CURDIR}
CFLAGS+=	-fno-omit-frame-pointer -DCRT_IRELOC_RELA

NOCFI=			yes
MK_CFI=			no
MK_CROSS_DSO_CFI=	no

.include <bsd.lib.mk>
