
PROG=	bhyveload
SRCS=	bhyveload.c
MAN=	bhyveload.8
PACKAGE=	bhyve

CFI_OVERRIDE=-fno-sanitize=cfi-icall

LIBADD=	vmmapi

CFLAGS+=-I${SRCTOP}/stand/userboot

.include <bsd.prog.mk>
