.PATH:	${SRCTOP}/sys/compat/linuxkpi/common/src

KMOD=	linuxkpi_wlan
SRCS=	linux_80211.c \
	linux_80211_macops.c

# QCA ath11k support.
SRCS+=	linux_mhi.c

SRCS+=	opt_wlan.h
SRCS+=	${LINUXKPI_GENSRCS}

CFLAGS+= ${LINUXKPI_INCLUDES}

EXPORT_SYMS=	YES

TRIVIAL_VAR_AUTO_INIT_ZERO_SAFE=	yes

.include <bsd.kmod.mk>
