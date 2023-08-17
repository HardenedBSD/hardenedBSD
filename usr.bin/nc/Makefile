
.include <src.opts.mk>

.PATH: ${SRCTOP}/contrib/netcat

PROG=	nc
SRCS=	netcat.c atomicio.c socks.c

CFLAGS+=-DIPSEC
LIBADD=	ipsec

CFI_OVERRIDE=-fno-sanitize=cfi-icall

.if ${MK_STATS} != "no" && !defined(RESCUE)
LIBADD+=	sbuf stats
CFLAGS+=	-DWITH_STATS
.endif

WARNS?=	2

.include <bsd.prog.mk>
