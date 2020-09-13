#include <u.h>
#include <libc.h>
#import "fs.c"
/* masquerade as just a TLS listener but we handle all file calls internally */


/* File servers we need that we don't get */
//procfs
