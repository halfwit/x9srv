<$PLAN9/src/mkhdr

TARG=\
    x9srv\
    x9tlssrv

DEVDRAWOBJ=\
    draw.$O\
    $PLAN9/src/cmd/devdraw/devdraw.$O\
    $PLAN9/src/cmd/devdraw/latin1.$O\
    $PLAN9/src/cmd/devdraw/mouseswap.$O\
    $PLAN9/src/cmd/devdraw/winsize.$O


HFILES=\
    fs.h\
    $PLAN9/include/draw.h\
    $PLAN9/src/cmd/devdraw/bigarrow.h\
    $PLAN9/src/cmd/devdraw/glendapng.h\
    $PLAN9/src/cmd/devdraw/devdraw.h

<$PLAN9/src/mkmany

$O.x9srv: srv.$O fs.$O #$DEVDRAWOBJ
    $LD -o $target $prereq

$O.x9tlssrv: tlssrv.$O fs.$O #$DEVDRAWOBJ
    $LD -o $target $prereq 

clean:V:
	rm -f *.[$OS] [$OS].out $TARG
