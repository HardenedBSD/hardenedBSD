
PROG =	rpc.rstatd
SRCS =	rstatd.c rstat_proc.c
MAN =	rpc.rstatd.8

LIBADD=	rpcsvc devstat

WARNS?=	1

CFI_OVERRIDE=	-fno-sanitize=cfi-icall

.include <bsd.prog.mk>
