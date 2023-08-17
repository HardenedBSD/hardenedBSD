
PACKAGE=	kerberos

PROG=	kgetcred
CFLAGS+=	-I${KRB5DIR}/lib/asn1 \
		-I${KRB5DIR}/lib/roken
LIBADD=	krb5 roken asn1 vers

CFI_OVERRIDE=	-fno-sanitize=cfi-icall

.include <bsd.prog.mk>

.PATH: ${KRB5DIR}/kuser
