/* Rework with libauthsrv + libsec */
#include <u.h>
#include <libc.h>
#include <thread.h>
#include <bio.h>
#include <ndb.h>
#include "include/libsec.h"
#include "include/authsrv.h"

#define AUTHLOG "auth"
#define KEYDB   "/adm"

enum {
	Maxpath = 256,
};

Ndb *db;
typedef struct Keyslot Keyslot;
struct Keyslot
{
	Authkey ak;
	char	id[ANAMELEN];
};
Keyslot hkey, akey, ukey;

uchar keyseed[SHA2_256dlen];
uchar zeros[32];
char raddr[128];
char ticketform;

/* auth functions */
void	pak(Ticketreq*);
void	ticketrequest(Ticketreq*);
void	changepasswd(Ticketreq*);

/* util functions */
void	mkkey(char*, Authkey*);
void	mkticket(Ticketreq*, Ticket*);
char*	okpasswd(char*);
void	replyerror(char*, ...);
void	safecpy(char*, char*, int);

/* readwrite */
int	findkey1(char*, char*, Authkey*);
int	readfile(char*, char*, int);
int	setkey1(char*, char*, Authkey*);
char*	setdeskey(char*, char*, char*);
uchar*	setaeskey(char*, char*, uchar*);
char*	setsecret1(char*, char*, char*);
int	writefile(char*, char*, int);

int		speaksfor(char*, char*);

void
threadmain(int argc, char *argv[])
{
	char buf[TICKREQLEN];
	Ticketreq tr;
	int n;

	srandom(time(NULL));

	db = ndbopen("/lib/ndb/auth");
	if(db == 0)
		syslog(0, AUTHLOG, "no /lib/ndb/auth");

	for(;;){
		n = readn(0, buf, sizeof(buf));
		if(n <= 0 || convM2TR(buf, n, &tr) <= 0)
			threadexitsall(0);
		switch(tr.type){
		case AuthTreq:
			ticketrequest(&tr);
			break;
		case AuthPass:
			changepasswd(&tr);
			break;
		case AuthPAK:
			pak(&tr);
			continue;
		default:
			syslog(0, AUTHLOG, "unknown ticket request type: %d", tr.type);
			threadexitsall(0);
		}
		/* invalidate pak keys */
		akey.id[0] = 0;
		hkey.id[0] = 0;
		ukey.id[0] = 0;
	}

	threadexitsall(0);
}


void
pak1(char *u, Keyslot *k)
{
	uchar y[PAKYLEN];
	PAKpriv p;

	safecpy(k->id, u, sizeof(k->id));

	if(!findkey1(KEYDB, k->id, &k->ak) || tsmemcmp(k->ak.aes, zeros, AESKEYLEN) == 0) {
		syslog(0, AUTHLOG, "pak-fail no AES key for id %s", k->id);
		/* make one up so caller doesn't know it was wrong */
		mkkey(k->id, &k->ak);
		authpak_hash(&k->ak, k->id);
	}
	authpak_new(&p, &k->ak, y, 0);
	if(write(1, y, PAKYLEN) != PAKYLEN)
		threadexitsall(0);
	if(readn(0, y, PAKYLEN) != PAKYLEN)
		threadexitsall(0);
	if(authpak_finish(&p, &k->ak, y))
		threadexitsall(0);
}

void
pak(Ticketreq *tr)
{
	static uchar ok[1] = {AuthOK};

	if(write(1, ok, 1) != 1)
		threadexitsall(0);

	/* invalidate pak keys */
	akey.id[0] = 0;
	hkey.id[0] = 0;
	ukey.id[0] = 0;

	if(tr->hostid[0]) {
		if(tr->authid[0])
			pak1(tr->authid, &akey);
		pak1(tr->hostid, &hkey);
	} else if(tr->uid[0]) {
		pak1(tr->uid, &ukey);
	}

	ticketform = 1;
}


int
getkey(char *u, Keyslot *k)
{
	/* empty user id is an error */
	if(*u == 0)
		threadexitsall(0);

	if(k == &hkey && strcmp(u, k->id) == 0)
		return 1;
	if(k == &akey && strcmp(u, k->id) == 0)
		return 1;
	if(k == &ukey && strcmp(u, k->id) == 0)
		return 1;

	if(ticketform != 0){
		syslog(0, AUTHLOG, "need DES key for %s, but DES is disabled", u);
		replyerror("DES is disabled");
		threadexitsall(0);
	}

	return findkey1(KEYDB, k->id, &k->ak);
}


void
ticketrequest(Ticketreq *tr)
{
	char tbuf[2*MAXTICKETLEN+1];
	Ticket t;
	int n;

	if(tr->uid[0] == 0)
		threadexitsall(0);
	if(!getkey(tr->authid, &akey)){
		/* make one up so caller doesn't know it was wrong */
		mkkey(tr->authid, &akey.ak);
		syslog(0, AUTHLOG, "tr-fail authid %s", tr->authid);
	}
	if(!getkey(tr->hostid, &hkey)){
		/* make one up so caller doesn't know it was wrong */
		mkkey(tr->hostid, &hkey.ak);
		syslog(0, AUTHLOG, "tr-fail hostid %s(%s)", tr->hostid, raddr);
	}
	mkticket(tr, &t);
	if(!speaksfor(tr->hostid, tr->uid)){
		mkkey(tr->authid, &akey.ak);
		mkkey(tr->hostid, &hkey.ak);
		syslog(0, AUTHLOG, "tr-fail %s@%s(%s) -> %s@%s no speaks for",
			tr->uid, tr->hostid, raddr, tr->uid, tr->authid);
	}
	n = 0;
	tbuf[n++] = AuthOK;
	t.num = AuthTc;
	n += convT2M(&t, tbuf+n, sizeof(tbuf)-n, &hkey.ak);
	t.num = AuthTs;
	n += convT2M(&t, tbuf+n, sizeof(tbuf)-n, &akey.ak);
	if(write(1, tbuf, n) != n)
		threadexitsall(0);

	syslog(0, AUTHLOG, "tr-ok %s@%s(%s) -> %s@%s", tr->uid, tr->hostid, raddr, tr->uid, tr->authid);
}


void
changepasswd(Ticketreq *tr)
{
	char tbuf[MAXTICKETLEN+1], prbuf[MAXPASSREQLEN], *err;
	Passwordreq pr;
	Authkey nkey;
	Ticket t;
	int n, m;

	if(!getkey(tr->uid, &ukey)){
		/* make one up so caller doesn't know it was wrong */
		mkkey(tr->uid, &ukey.ak);
		syslog(0, AUTHLOG, "cp-fail uid %s@%s", tr->uid, raddr);
	}

	/* send back a ticket with a new key */
	mkticket(tr, &t);
	t.num = AuthTp;
	n = 0;
	tbuf[n++] = AuthOK;
	n += convT2M(&t, tbuf+n, sizeof(tbuf)-n, &ukey.ak);
	if(write(1, tbuf, n) != n)
		threadexitsall(0);

	/* loop trying passwords out */
	for(;;){
		for(n=0; (m = convM2PR(prbuf, n, &pr, &t)) <= 0; n += m){
			m = -m;
			if(m <= n || m > sizeof(prbuf))
				threadexitsall(0);
			m -= n;
			if(readn(0, prbuf+n, m) != m)
				threadexitsall(0);
		}
		if(pr.num != AuthPass){
			replyerror("protocol botch1: %s", raddr);
			threadexitsall(0);
		}
		passtokey(&nkey, pr.old);
		if(tsmemcmp(ukey.ak.des, nkey.des, DESKEYLEN) != 0){
			replyerror("protocol botch2: %s", raddr);
			continue;
		}
		if(tsmemcmp(ukey.ak.aes, zeros, AESKEYLEN) != 0 && tsmemcmp(ukey.ak.aes, nkey.aes, AESKEYLEN) != 0){
			replyerror("protocol botch3: %s", raddr);
			continue;
		}
		if(*pr.new){
			err = okpasswd(pr.new);
			if(err){
				replyerror("%s %s", err, raddr);
				continue;
			}
			passtokey(&nkey, pr.new);
		}
		if(pr.changesecret && setsecret1(KEYDB, tr->uid, pr.secret) == 0){
			replyerror("can't write secret %s", raddr);
			continue;
		}
		if(*pr.new && setkey1(KEYDB, tr->uid, &nkey) == 0){
			replyerror("can't write key %s", raddr);
			continue;
		}
		memmove(ukey.ak.des, nkey.des, DESKEYLEN);
		memmove(ukey.ak.aes, nkey.aes, AESKEYLEN);
		break;
	}

	prbuf[0] = AuthOK;
	if(write(1, prbuf, 1) != 1)
		threadexitsall(0);
}

void
mkkey(char *id, Authkey *a)
{
	uchar h[SHA2_256dlen];

	genrandom((uchar*)a, sizeof(Authkey));

	/*
	 * the DES key has to be constant for a user in each response,
	 * so we make one up pseudo randomly from a keyseed and user name.
	 */
	hmac_sha2_256((uchar*)id, strlen(id), keyseed, sizeof(keyseed), h, nil);
	memmove(a->des, h, DESKEYLEN);
	memset(h, 0, sizeof(h));
}

void
mkticket(Ticketreq *tr, Ticket *t)
{
	memset(t, 0, sizeof(Ticket));
	memmove(t->chal, tr->chal, CHALLEN);
	safecpy(t->cuid, tr->uid, ANAMELEN);
	safecpy(t->suid, tr->uid, ANAMELEN);
	genrandom(t->key, NONCELEN);
	t->form = ticketform;
}

char *trivial[] = {
	"login",
	"guest",
	"change me",
	"passwd",
	"no passwd",
	"anonymous",
	0
};

char*
okpasswd(char *p)
{
	char passwd[PASSWDLEN];
	char back[PASSWDLEN];
	int i, n;

	strncpy(passwd, p, sizeof passwd - 1);
	passwd[sizeof passwd - 1] = '\0';
	n = strlen(passwd);
	while(n > 0 && passwd[n - 1] == ' ')
		n--;
	passwd[n] = '\0';
	for(i = 0; i < n; i++)
		back[i] = passwd[n - 1 - i];
	back[n] = '\0';
	if(n < 8)
		return "password must be at least 8 chars";

	for(i = 0; trivial[i]; i++)
		if(strcmp(passwd, trivial[i]) == 0
		|| strcmp(back, trivial[i]) == 0)
			return "trivial password";

	return 0;
}

/*
 *  return an error reply
 */
void
replyerror(char *fmt, ...)
{
	char buf[AERRLEN+1];
	va_list arg;

	memset(buf, 0, sizeof(buf));
	va_start(arg, fmt);
	vseprint(buf + 1, buf + sizeof(buf), fmt, arg);
	va_end(arg);
	buf[AERRLEN] = 0;
	buf[0] = AuthErr;
	write(1, buf, AERRLEN+1);
	syslog(0, AUTHLOG, buf+1);
}


void
safecpy(char *to, char *from, int len)
{
	strncpy(to, from, len);
	to[len-1] = 0;
}

/*
 *  return true of the speaker may speak for the user
 *
 *  a speaker may always speak for himself/herself
 */
int
speaksfor(char *speaker, char *user)
{
	Ndbtuple *tp, *ntp;
	Ndbs s;
	int ok;
	char notuser[Maxpath];

	if(strcmp(speaker, user) == 0)
		return 1;

	if(db == nil)
		return 0;

	tp = ndbsearch(db, &s, "hostid", speaker);
	if(tp == nil)
		return 0;

	ok = 0;
	snprint(notuser, sizeof notuser, "!%s", user);
	for(ntp = tp; ntp != nil; ntp = ntp->entry)
		if(strcmp(ntp->attr, "uid") == 0){
			if(strcmp(ntp->val, notuser) == 0){
				ok = 0;
				break;
			}
			if(*ntp->val == '*' || strcmp(ntp->val, user) == 0)
				ok = 1;
		}
	ndbfree(tp);
	return ok;
}

static uchar empty[16];

int
readfile(char *file, char *buf, int n)
{
	int fd;

	fd = open(file, OREAD);
	if(fd < 0){
		werrstr("%s: %r", file);
		return -1;
	}
	n = read(fd, buf, n);
	close(fd);
	return n;
}

int
writefile(char *file, char *buf, int n)
{
	int fd;

	fd = open(file, OWRITE);
	if(fd < 0)
		return -1;
	n = write(fd, buf, n);
	close(fd);
	return n;
}

char*
finddeskey1(char *db, char *user, char *key)
{
	char filename[Maxpath];

	snprint(filename, sizeof filename, "%s/%s/key", db, user);
	if(readfile(filename, key, DESKEYLEN) != DESKEYLEN)
		return nil;
	return key;
}

uchar*
findaeskey1(char *db, char *user, uchar *key)
{
	char filename[Maxpath];

	snprint(filename, sizeof filename, "%s/%s/aeskey", db, user);
	if(readfile(filename, (char*)key, AESKEYLEN) != AESKEYLEN)
		return nil;
	return key;
}

int
findkey1(char *db, char *user, Authkey *key)
{
	int ret;

	memset(key, 0, sizeof(Authkey));
	ret = findaeskey1(db, user, key->aes) != nil;
	if(ret && tsmemcmp(key->aes, empty, AESKEYLEN) != 0){
		char filename[Maxpath];

		snprint(filename, sizeof filename, "%s/%s/pakhash", db, user);
		if(readfile(filename, (char*)key->pakhash, PAKHASHLEN) != PAKHASHLEN)
			authpak_hash(key, user);
	}
	ret |= finddeskey1(db, user, key->des) != nil;
	return ret;
}

char*
findsecret(char *db, char *user, char *secret)
{
	int n;
	char filename[Maxpath];

	snprint(filename, sizeof filename, "%s/%s/secret", db, user);
	if((n = readfile(filename, secret, SECRETLEN-1)) <= 0)
		return nil;
	secret[n]=0;
	return secret;
}

char*
setdeskey(char *db, char *user, char *key)
{
	char filename[Maxpath];

	snprint(filename, sizeof filename, "%s/%s/key", db, user);
	if(writefile(filename, key, DESKEYLEN) != DESKEYLEN)
		return nil;
	return key;
}

uchar*
setaeskey(char *db, char *user, uchar *key)
{
	char filename[Maxpath];

	snprint(filename, sizeof filename, "%s/%s/aeskey", db, user);
	if(writefile(filename, (char*)key, AESKEYLEN) != AESKEYLEN)
		return nil;
	return key;
}

int
setkey1(char *db, char *user, Authkey *key)
{
	int ret;

	ret = setdeskey(db, user, key->des) != nil;
	if(tsmemcmp(key->aes, empty, AESKEYLEN) != 0)
		ret |= setaeskey(db, user, key->aes) != nil;
	return ret;
}

char*
setsecret1(char *db, char *user, char *secret)
{
	char filename[Maxpath];

	snprint(filename, sizeof filename, "%s/%s/secret", db, user);
	if(writefile(filename, secret, strlen(secret)) != strlen(secret))
		return nil;
	return secret;
}
