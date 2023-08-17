
PACKAGE=	pkg-bootstrap

PROG=	pkg
SRCS=	pkg.c dns_utils.c config.c hash.c
MAN=	pkg.7

CONFS=		HardenedBSD.conf HardenedBSD.tor.conf
PKGCONF?=	HardenedBSD.conf
CONFSDIR=	/etc/pkg
CONFSMODE=	644

CFLAGS+=-I${SRCTOP}/contrib/libucl/include
.PATH:	${SRCTOP}/contrib/libucl/include
LIBADD=	archive fetch ucl crypto ssl util md

.include <bsd.prog.mk>
