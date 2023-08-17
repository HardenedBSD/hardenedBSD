
.include <bsd.init.mk>

PROG=	jevents
SRCS=	jevents.c jsmn.c json.c
CFLAGS+= -Wno-cast-qual
MAN=

# This application is used to autogenerate C code during the build
# process. It segfaults when Cross-DSO CFI is enabled. So disable CFI,
# but keep LTO since the rest of world is compiled with LTO.
.if ${MK_CROSS_DSO_CFI} != "no"
CFLAGS+=	-flto
CXXFLAGS+=	-flto
LDFLAGS+=	-flto
NOCFI=		yes
.endif

build-tools: jevents

.include <bsd.prog.mk>
