
PACKAGE=	kerberos

PROG=	kf
MAN=	kf.1
CFLAGS+=	-I${KRB5DIR}/lib/asn1 \
		-I${KRB5DIR}/lib/roken
LIBADD=	krb5 roken vers

CFI_OVERRIDE=	-fno-sanitize=cfi-icall

.include <bsd.prog.mk>

.PATH: ${KRB5DIR}/appl/kf
