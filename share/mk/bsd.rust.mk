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

.if !defined(TAGS) || ! ${TAGS:Mpackage=*}
TAGS+=		package=${PACKAGE:Ubase-rust-utils}
.endif
TAG_ARGS=	-T ${TAGS:[*]:S/ /,/g}

CARGO?=			${LOCALBASE}/bin/cargo
CARGO_TARGET_DIR?=	${OBJROOT}${TARGET}.${TARGET_ARCH}/rust-cargo
.export CARGO_TARGET_DIR

RUSTC?=			${LOCALBASE}/bin/rustc
.export RUSTC

CARGO_PROFILE?=		release

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
