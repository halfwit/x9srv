#include <u.h>
#include <libc.h>
#include "../include/mp.h"
#include "../include/libsec.h"

EGpub*
egprivtopub(EGpriv *priv)
{
	EGpub *pub;

	pub = egpuballoc();
	if(pub == nil)
		return nil;
	pub->p = mpcopy(priv->pub.p);
	pub->alpha = mpcopy(priv->pub.alpha);
	pub->key = mpcopy(priv->pub.key);
	return pub;
}
