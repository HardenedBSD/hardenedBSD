#

CFLAGS+=	-DCRT_IRELOC_RELA \
		-DINIT_IRELOCS="init_cpu_features()"

MK_LTOLIB=	no
