# $FreeBSD$

MDSRCS+= \
	bcmp.S \
	memcmp.S \
	memmove.S \
	memset.S \
	strcat.S \
	strcmp.S \
	strlen.S \
	stpcpy.S

.if ${MK_SNMALLOC} == "no"
SRCS+= memcpy.S
.endif
