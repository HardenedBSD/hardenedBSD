
.include <src.opts.mk>

<<<<<<< HEAD
=======
MK_PIE:=	no	# Explicit libXXX.a references

.if ${MK_LLVM_FULL_DEBUGINFO} == "no"
>>>>>>> origin/freebsd/14-stable/main
.if ${COMPILER_TYPE} == "clang"
DEBUG_FILES_CFLAGS= -gline-tables-only
.else
DEBUG_FILES_CFLAGS= -g1
.endif
.endif

WARNS?=		0

.include "../Makefile.inc"
