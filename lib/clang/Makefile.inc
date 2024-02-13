
.include <bsd.compiler.mk>

PACKAGE=	clang
<<<<<<< HEAD
=======
MK_PIE:=	no	# Explicit libXXX.a references
>>>>>>> internal/freebsd/current/main

.if ${COMPILER_TYPE} == "clang"
DEBUG_FILES_CFLAGS= -gline-tables-only
.else
DEBUG_FILES_CFLAGS= -g1
.endif

WARNS?=		0
