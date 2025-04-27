.include <bsd.init.mk>
.include <bsd.compiler.mk>
.include <bsd.linker.mk>

.if !target(__<bsd.rust.mk>__)
__<bsd.rust.mk>__:	.NOTMAIN

.if defined(OPTIONAL_TOOLCHAINS) && ${OPTIONAL_TOOLCHAINS:Mrust-cargo}

.if !defined(PROG)
.error Rust-in-base support only targets applications
.endif

LOCALBASE?=		/usr/local

.if defined(NO_ROOT)
.if !defined(TAGS) || ! ${TAGS:Mpackage=*}
TAGS+=		package=${PACKAGE:Ubase-rust-utils}
.endif
TAG_ARGS=	-T ${TAGS:[*]:S/ /,/g}
.endif

CARGO?=			${LOCALBASE}/bin/cargo
RUSTC?=			${LOCALBASE}/bin/rustc
CARGO_TARGET_DIR?=	${OBJROOT}${TARGET}.${TARGET_ARCH}/rust-cargo
.export CARGO_TARGET_DIR
.export RUSTC

CARGO_PROFILE?=		release
CARGO_FLAGS+=		--offline
CARGO_FLAGS+=		--profile ${CARGO_PROFILE}
CARGO_FLAGS+=		--bin ${PROG}

.if !exists(${CARGO}) || !exists(${RUSTC})
.error Rust compiler toolchain not found
.endif

all:
	env -C ${.CURDIR} ${CARGO} build ${CARGO_FLAGS}

install:
	${INSTALL} \
		${TAG_ARGS} \
		-o ${BINOWN} \
		-g ${BINGRP} \
		-m ${BINMODE} \
		${CARGO_TARGET_DIR}/${CARGO_PROFILE}/${PROG} \
		${DESTDIR}${BINDIR}/${PROG}

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
