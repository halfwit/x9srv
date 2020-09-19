#include <u.h>
#include <libc.h>
#include "fs.c"

/* stdin/stdout/stderr are attached to our client */
/* Flag to also listen for devdraw in a different thread and writes go through our 9p connection to /dev/draw */
