.include <bsd.init.mk>
.include <bsd.compiler.mk>
.include <bsd.linker.mk>

.if !target(__<bsd.rust.mk>__)
__<bsd.rust.mk>__:	.NOTMAIN

.if defined(OPTIONAL_TOOLCHAIN) && ${OPTIONAL_TOOLCHAIN} == "rust-cargo"

LOCALBASE?=		/usr/local

.if !defined(TAGS) || ! ${TAGS:Mpackage=*}
TAGS+=		package=${PACKAGE:Uutilities}
.endif
TAG_ARGS=	-T ${TAGS:[*]:S/ /,/g}

CARGO?=			${LOCALBASE}/bin/cargo
CARGO_TARGET_DIR?=	${OBJROOT}${TARGET}.${TARGET_ARCH}/rust-cargo
.export CARGO_TARGET_DIR

RUSTC?=			${LOCALBASE}/bin/rustc
.export RUSTC

CARGO_PROFILE?=		release

.if defined(PROG)
CARGO_INSTALL_FLAGS+=	--root ${DESTDIR}${BINDIR}/${PROG}
.elif defined(LIB)
.error Building Rust library crates not currently required/supported.
#CARGO_INSTALL_FLAGS+=	--root ${DESTDIR}${LIBDIR}/${LIB}
.else
.error Can only build application crates
.endif

CARGO_FLAGS+=		--offline

all:
	env -C ${.CURDIR} ${CARGO} build ${CARGO_FLAGS} --profile ${CARGO_PROFILE}

install:
.if defined(PROG)
	${INSTALL} \
		${TAG_ARGS} \
		-o ${BINOWN} \
		-g ${BINGRP} \
		-m ${BINMODE} \
		${CARGO_TARGET_DIR}/${CARGO_PROFILE}/${PROG} \
		${DESTDIR}${BINDIR}/${PROG}
.endif

clean:
	env -C ${.CURDIR} ${CARGO} clean --profile ${CARGO_PROFILE}

cleandir: clean

.include <bsd.obj.mk>
.include <bsd.incs.mk>
.include <bsd.sys.mk>

.else

all:
clean:
cleandir:
depend:
includes:
install:
installconfig:
obj:

.endif
.endif
