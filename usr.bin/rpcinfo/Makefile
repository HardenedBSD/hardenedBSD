PROG=	rpcinfo
SRCS=	rpcinfo.c
MAN=	rpcinfo.8

CFLAGS+= -DPORTMAP

CFI_OVERRIDE=	-fno-sanitize=cfi-icall

.include <bsd.prog.mk>
