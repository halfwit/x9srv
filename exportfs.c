#include <u.h>
#include <libc.h>
#include <thread.h>
#include "include/c9.h"

void
threadmain(int argc, char *argv[])
{
    /* TODO: handle all the flags and switches of a normal exportfs */
    fs_main("/");

    threadexitsall(0);
}
