
PACKAGE=	nfs

PROG =	rpc.rquotad
SRCS =	rquotad.c
MAN  =	rpc.rquotad.8

LIBADD=	rpcsvc util

CFI_OVERRIDE=	-fno-sanitize=cfi-icall

.include <bsd.prog.mk>
