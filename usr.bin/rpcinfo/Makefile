
PROG=	rpcinfo
SRCS=	rpcinfo.c
MAN=	rpcinfo.8

CFLAGS+= -DPORTMAP

WARNS?=	2

CFI_OVERRIDE=	-fno-sanitize=cfi-icall

.include <bsd.prog.mk>
