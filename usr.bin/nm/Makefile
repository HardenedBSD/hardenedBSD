
.include <src.opts.mk>

PACKAGE=	elftoolchain

ELFTCDIR=	${SRCTOP}/contrib/elftoolchain
NMDIR=		${ELFTCDIR}/nm

.PATH: ${NMDIR}

PROG=	elftc-nm
SRCS=	nm.c
MAN=	nm.1

LIBADD=	dwarf elftc elf

.if ${MK_CASPER} != "no" && !defined(BOOTSTRAPPING) && !defined(NXB_TARGET)
LIBADD+=	casper
LIBADD+=	cap_fileargs
CFLAGS+=	-DWITH_CASPER
.endif

CFLAGS+=-I${ELFTCDIR}/libelftc -I${ELFTCDIR}/common

.if ${MK_LLVM_BINUTILS} == "no"
SYMLINKS=	${BINDIR}/elftc-nm ${BINDIR}/nm
.endif

.include <bsd.prog.mk>
