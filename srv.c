#include <u.h>
#include <libc.h>
#include <thread.h>
#include <draw.h>
#include <memdraw.h>
#include <keyboard.h>
#include <mouse.h>
#include <cursor.h>
#include <drawfcall.h>
#include "libc9/x9fs.h"
//#include "libdraw/draw.h"


/* stdin/stdout/stderr are attached to our client */
/* Flag to also listen for devdraw in a different thread and writes go through our 9p connection to /dev/draw */
void
threadmain(int argc, char *argv[])
{
    char *chroot;

    chroot = getenv("PLAN9");
    fs_main(chroot);

}
