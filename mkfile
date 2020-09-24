<$PLAN9/src/mkhdr

TARG=\
    x9srv\
    x9tlssrv

LIBDRAW=libdraw/libdraw.$O.a
LIBC9=libc9/libc9.$O.a
LIB=$LIBDRAW $LIBC9

HFLAGS=\
    libdraw/x9draw.h\
    libc9/x9fs.h

<$PLAN9/src/mkmany

$LIBDRAW:V:
    cd libdraw
    mk

$LIBC9:V:
    cd libc9
    mk

clean:V:
    cd libdraw; mk clean; cd ..
    cd libc9; mk clean; cd ..
	rm -f *.[$OS] [$OS].out $TARG

$O.x9srv: srv.$O $LIB
    $LD -o $target $prereq

$O.x9tlssrv: tlssrv.$O $LIB
    $LD -o $target $prereq 