
.include <bsd.compiler.mk>

PACKAGE=	clang

.if ${COMPILER_TYPE} == "clang"
DEBUG_FILES_CFLAGS= -gline-tables-only
.else
DEBUG_FILES_CFLAGS= -g1
.endif

WARNS?=		0
