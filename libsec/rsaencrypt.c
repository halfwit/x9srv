#include <u.h>
#include <libc.h>
#include "../include/mp.h"
#include "../include/libsec.h"

mpint*
rsaencrypt(RSApub *rsa, mpint *in, mpint *out)
{
	if(out == nil)
		out = mpnew(0);
	mpexp(in, rsa->ek, rsa->n, out);
	return out;
}
