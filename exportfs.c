#include <u.h>
#include <libc.h>
#include "include/c9.h"

void
main(int argc, char *argv[])
{
    char *chroot;
    
    chroot = getenv("PLAN9");
    fs_main(chroot);
}
