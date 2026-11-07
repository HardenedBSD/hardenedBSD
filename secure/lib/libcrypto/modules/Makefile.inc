SHLIBDIR=	${LIBDIR}/ossl-modules

<<<<<<< HEAD
LCRYPTO_SRC=	${SRCTOP}/crypto/openssl

SHARED_CFLAGS+=	-DOPENSSL_PIC

CFLAGS+=	-I${LCRYPTO_SRC}
CFLAGS+=	-I${LCRYPTO_SRC}/include
CFLAGS+=	-I${LCRYPTO_SRC}/providers/common/include
CFLAGS+=	-I${LCRYPTO_SRC}/providers/fips/include
CFLAGS+=	-I${LCRYPTO_SRC}/providers/implementations/include
=======
# Same compile flags as libcrypto (asm dispatch defines, NDEBUG, ...), as
# upstream builds its modules with the library flags.
.include "../Makefile.inc"
>>>>>>> rad/freebsd/current/main

WARNS?=		0
