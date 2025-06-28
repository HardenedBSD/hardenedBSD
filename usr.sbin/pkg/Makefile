
PACKAGE=	pkg-bootstrap

PROG=	pkg
SRCS=	pkg.c rsa.c dns_utils.c config.c ecc.c hash.c
MAN=	pkg.7

CONFS=		HardenedBSD.conf HardenedBSD.pkgbase.conf HardenedBSD.tor.conf
PKGCONF?=	HardenedBSD.conf
CONFSDIR=	/etc/pkg
CONFSMODE=	644

CFLAGS+=-I${SRCTOP}/contrib/libucl/include
.PATH:	${SRCTOP}/contrib/libucl/include
LIBADD=	archive der fetch pkgecc ucl crypto ssl util md

CFLAGS+=-I${SRCTOP}/contrib/libder/libder
CFLAGS+=-I${SRCTOP}/crypto/libecc/include

.include <bsd.prog.mk>
