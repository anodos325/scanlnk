MK_MAN=	no

.include <bsd.own.mk>

PROG= scanlnk	
BINDIR=	/usr/bin
CFLAGS+=        -D_ACL_PRIVATE

.include <bsd.prog.mk>
