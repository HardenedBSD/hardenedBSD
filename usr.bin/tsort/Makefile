#	@(#)Makefile	8.1 (Berkeley) 6/9/93

.include <src.opts.mk>

PROG=	tsort

HAS_TESTS=
SUBDIR.${MK_TESTS}=	tests

CFI_OVERRIDE=-fno-sanitize=cfi-icall

.include <bsd.prog.mk>
