#include <u.h>
#include <libc.h>
#include "../include/mp.h"
#include "dat.h"

/*
 *  this code assumes that mpdigit is at least as
 *  big as an int.
 */

mpint*
itomp(int i, mpint *b)
{
	if(b == nil){
		b = mpnew(0);
		setmalloctag(b, getcallerpc(&i));
	}
	b->sign = (i >> (sizeof(i)*8 - 1)) | 1;
	i *= b->sign;
	*b->p = i;
	b->top = 1;
	return mpnorm(b);
}

int
mptoi(mpint *b)
{
	uint x;

	if(b->top==0)
		return 0;
	x = *b->p;
	if(b->sign > 0){
		if(b->top > 1 || (x > MAXINT))
			x = (int)MAXINT;
		else
			x = (int)x;
	} else {
		if(b->top > 1 || x > MAXINT+1)
			x = (int)MININT;
		else
			x = -(int)x;
	}
	return x;
}
