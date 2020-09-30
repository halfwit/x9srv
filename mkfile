<$PLAN9/src/mkhdr

TARG=\
    #authsrv\
    cpu\
    exportfs\
    #tlssrv\
    tlsclient

LIBMP=libmp/libmp.$O.a
LIBAUTHSRV=libauthsrv/libauthsrv.$O.a
LIBSEC=libsec/libsec.$O.a
LIBC9=libc9/libc9.$O.a

HFILES=\
    include/c9.h\
    include/authsrv.h\
    include/libsec.h\
    include/mp.h\

<$PLAN9/src/mkmany

$LIBC9:V:
    cd libc9
    mk

$LIBAUTHSRV:V: $LIBMP
    cd libauthsrv
    mk

$LIBMP:V:
    cd libmp
    mk

$LIBSEC:V:
    cd libsec
    mk

clean:V:
    cd libauthsrv; mk clean; cd ..
    cd libmp; mk clean; cd ..
    cd libsec; mk clean; cd ..
    cd libc9; mk clean; cd ..
	rm -f *.[$OS] [$OS].out $TARG

$O.authsrv: authsrv.$O  $LIBSEC $LIBAUTHSRV
    $LD -o $target $prereq

$O.cpu: cpu.$O $LIBC9
    $LD -o $target $prereq

$O.exportfs: exportfs.$O $LIBC9
    $LD -o $target $prereq

$O.tlssrv: tlssrv.$O $LIBMP $LIBSEC
    $LD -o $target $prereq

$O.tlsclient: tlsclient.$O $LIBMP $LIBSEC
    $LD -o $target $prereq