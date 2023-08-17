
PACKAGE=	kerberos

PROG=	kdestroy
CFLAGS+=-I${KRB5DIR}/lib/roken
LIBADD=	kafs5 krb5 roken vers
MAN=	kdestroy.1

CFI_OVERRIDE=	-fno-sanitize=cfi-icall

.include <bsd.prog.mk>

.PATH: ${KRB5DIR}/kuser
