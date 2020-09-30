#include <u.h>
#include <libc.h>
#include "../include/libsec.h"
#include "../include/authsrv.h"

void
hkdf_x_plan9(uchar crand[2*NONCELEN], uchar key[NONCELEN], uchar secret[256])
{
	static char info[] = "Plan 9 session secret";
	
	hkdf_x(crand, 2*NONCELEN,
		(uchar*)info, sizeof(info)-1,
		key, NONCELEN,
		secret, 256,
		hmac_sha2_256, SHA2_256dlen);
}
