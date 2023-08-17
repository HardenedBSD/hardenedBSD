
PACKAGE=	kerberos

PROG=	kpasswd
CFLAGS+=-I${KRB5DIR}/lib/roken
LIBADD=	hdb krb5 roken vers crypto
LDFLAGS=${LDAPLDFLAGS}

CFI_OVERRIDE=	-fno-sanitize=cfi-icall

.include <bsd.prog.mk>

.PATH: ${KRB5DIR}/kpasswd
