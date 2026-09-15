S=	${SRCTOP}/sys

.PATH: $S/dev/video

KMOD=	video
SRCS=	video.c \
	video_if.h video_if.c \
	device_if.h bus_if.h

EXPORT_SYMS=	YES

TRIVIAL_VAR_AUTO_INIT_ZERO_SAFE=	yes

.include <bsd.kmod.mk>
