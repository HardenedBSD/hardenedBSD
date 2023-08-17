
PACKAGE=	kerberos

PROG=	kinit
CFLAGS+=-I${KRB5DIR}/lib/roken
LIBADD=	kafs5 krb5 heimntlm roken crypto vers

CFI_OVERRIDE=	-fno-sanitize=cfi-icall

.include <bsd.prog.mk>

.PATH: ${KRB5DIR}/kuser
