# Vendor sources and generated files
LDNSDIR=	${SRCTOP}/contrib/ldns
UNBOUNDDIR=	${SRCTOP}/contrib/unbound
LIBUNBOUNDDIR=	${SRCTOP}/lib/libunbound

.PATH:	${UNBOUNDDIR}
.PATH:	${UNBOUNDDIR}/smallapp
.PATH:	${UNBOUNDDIR}/doc

PROG=		unbound-host
SRCS=		unbound-host.c
MAN=		unbound-host.1

CFLAGS+=	-I${LIBUNBOUNDDIR}
CFLAGS+=	-I${UNBOUNDDIR}
CFLAGS+=	-I${LDNSDIR} 
CFLAGS+=	-I${SRCTOP}/usr.sbin/unbound

LIBADD=		unbound crypto ssl pthread

.include <bsd.prog.mk>
