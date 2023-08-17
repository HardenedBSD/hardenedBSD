
.include <bsd.init.mk>

NOCFI=		yes
MK_LTOLIB=	no

LIB=		clang_rt.safestack-${CRTARCH}

SRCS+=		interception/interception_linux.cpp
SRCS+=		interception/interception_type_test.cpp
SRCS+=		safestack/safestack.cpp

.include <bsd.lib.mk>
