
.PATH: ${SRCTOP}/sys/fs/tmpfs

KMOD=	tmpfs
SRCS=	vnode_if.h \
	tmpfs_vnops.c tmpfs_fifoops.c tmpfs_vfsops.c tmpfs_subr.c \
	opt_tmpfs.h opt_ddb.h

TRIVIAL_VAR_AUTO_INIT_ZERO_SAFE=	yes

.include <bsd.kmod.mk>
