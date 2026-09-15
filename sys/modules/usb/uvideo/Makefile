S=     ${SRCTOP}/sys

.PATH: $S/dev/usb/video $S/dev/video

KMOD=	uvideo
SRCS=	opt_bus.h opt_usb.h device_if.h \
	bus_if.h usb_if.h usbdevs.h \
	video_if.h \
	uvideo.c

TRIVIAL_VAR_AUTO_INIT_ZERO_SAFE=	yes

.include <bsd.kmod.mk>
