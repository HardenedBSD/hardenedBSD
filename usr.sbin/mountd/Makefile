PACKAGE= nfs
PROG=	mountd
MAN=	exports.5 netgroup.5 mountd.8
CFI_OVERRIDE=	-fno-sanitize=cfi-icall

WARNS?= 2

LIBADD=	util

.include <bsd.prog.mk>
