#define _FILE_OFFSET_BITS 64
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <inttypes.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>
#include "c9.h"

#define max(a,b) ((a)>(b)?(a):(b))
#define used(x) ((void)(x))
#define nelem(x) (int)(sizeof(x)/sizeof((x)[0]))

uint32_t crc32(const void *data, int len);

enum
{
	Canrd = 1<<0,
	Canwr = 1<<1,
};

typedef struct
{
	char *path; /* full path */
	char *name; /* base name */

	DIR *dir; /* set when it's an opened directory */
	uint64_t diroffset; /* to read dirs correctly */

	C9qid qid;
	C9fid fid;
	C9mode mode; /* mode in which the file was opened */
	uint32_t iounit;

	int fd; /* set when it's an opened file */
}Fid;

typedef struct
{
	C9tag tag;
}Tag;

typedef struct
{
	char *name;
	uint32_t id;
}Id;

static char *t2s[] = {
	[Tversion-Tversion] = "Tversion",
	[Tauth-Tversion] = "Tauth",
	[Tattach-Tversion] = "Tattach",
	[Tflush-Tversion] = "Tflush",
	[Twalk-Tversion] = "Twalk",
	[Topen-Tversion] = "Topen",
	[Tcreate-Tversion] = "Tcreate",
	[Tread-Tversion] = "Tread",
	[Twrite-Tversion] = "Twrite",
	[Tclunk-Tversion] = "Tclunk",
	[Tremove-Tversion] = "Tremove",
	[Tstat-Tversion] = "Tstat",
	[Twstat-Tversion] = "Twstat",
};

static char *modes[] = {
	"read", "write", "rdwr", "exec",
};

static char *Enoauth = "authentication not required";
static char *Eunknownfid = "unknown fid";
static char *Enowstat = "wstat prohibited";
static char *Eperm = "permission denied";
static char *Enowrite = "write prohibited";
static char *Enomem = "out of memory";
static char *Edupfid = "duplicate fid";
static char *Ewalknodir = "walk in non-directory";
static char *Enotfound = "file not found";
static char *Eduptag = "duplicate tag";
static char *Ebotch = "9P protocol botch";
static char *Enocreate = "create prohibited";
static char *Eisdir = "is a directory";
static char *Ebadoffset = "bad offset";

static int in, out, eof;
static C9ctx ctx;
static int debug, rootescape;
static Fid **fids;
static int numfids;
static Tag **tags;
static int numtags;
static char *rootpath;
static size_t rootlen;
static C9qid walkqids[C9maxpathel];
static uint8_t *rdbuf;
static uint8_t *wrbuf;
static uint32_t wroff, wrend, wrbufsz;
static Id *uids, *gids;
static int numuids, numgids;

__attribute__ ((format (printf, 1, 2)))
static void
trace(const char *fmt, ...)
{
	va_list ap;

	if (debug == 0)
		return;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
}

static int
canrw(int rdonly, int block)
{
	struct timeval t;
	fd_set r, w, e;
	int n, fl;

	FD_ZERO(&r);
	FD_SET(in, &r);
	FD_ZERO(&w);
	if (rdonly == 0)
		FD_SET(out, &w);
	FD_ZERO(&e);
	FD_SET(in, &e);
	FD_SET(out, &e);
	memset(&t, 0, sizeof(t));
	t.tv_usec = 1000;
	for (;;) {
		errno = 0;
		if ((n = select(max(in, out) + 1, &r, &w, &e, block ? NULL : &t)) < 0 || FD_ISSET(in, &e) || FD_ISSET(out, &e)) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		break;
	}

	fl = 0;
	if (FD_ISSET(in, &r))
		fl |= Canrd;
	if (FD_ISSET(out, &w))
		fl |= Canwr;

	return fl;
}

static int
wrsend(void)
{
	uint32_t n;
	int w;

	if (wrend == 0)
		return 0;
	for (n = 0; n < wrend; n += w) {
		errno = 0;
		if ((w = write(out, wrbuf+n, wrend-n)) <= 0) {
			if (errno == EINTR)
				continue;
			if (errno != EPIPE) /* remote end closed */
				perror("write");
			return -1;
		}
	}
	if (debug >= 2)
		trace("<- %d bytes, %d left\n", wrend, wroff-wrend);
	memmove(wrbuf, wrbuf+wrend, wroff-wrend);
	wroff = wroff - wrend;

	return 0;
}

static int
hastag(C9tag tag)
{
	int i;

	for (i = 0; i < numtags; i++) {
		if (tags[i] != NULL && tags[i]->tag == tag)
			return 1;
	}

	return 0;
}

static int
statpath(char *path, struct stat *st, char **err)
{
	if (stat(path, st) == 0)
		return 0;

	if (errno == EACCES)
		*err = Eperm;
	else if (errno == ENOMEM)
		*err = Enomem;
	else if (errno == ENOTDIR)
		*err = Ewalknodir;
	else if (errno == ENOENT)
		*err = Enotfound;
	else
		*err = strerror(errno);

	return -1;
}

static void
stat2qid(struct stat *st, C9qid *qid, uint32_t *iounit)
{
	int fmt;

	qid->path = st->st_ino;
	qid->version = crc32(&st->st_ctimespec, sizeof(st->st_ctime));
	qid->type = C9qtfile;
	fmt = st->st_mode & S_IFMT;
	if (fmt == S_IFDIR)
		qid->type |= C9qtdir;
	if ((st->st_mode & 0222) != 0 && (fmt == S_IFCHR || fmt == S_IFCHR || fmt == S_IFSOCK || fmt == S_IFIFO))
		qid->type |= C9qtappend;
	if (iounit != NULL)
		*iounit = st->st_blksize;
}

static Fid *
newfid(C9fid fid, char *path, char **err)
{
	Fid *f, **newfids;
	struct stat st;
	int i;

	for (i = 0; i < numfids; i++) {
		if (fids[i] != NULL && fids[i]->fid == fid) {
			*err = Edupfid;
			return NULL;
		}
	}

	if (statpath(path, &st, err) != 0)
		return NULL;

	if ((f = calloc(1, sizeof(*f))) == NULL) {
		*err = Enomem;
		return NULL;
	}
	f->fd = -1;
	f->path = strdup(path);
	f->name = strrchr(f->path, '/');
	if (f->name == NULL)
		f->name = f->path;
	else
		f->name++;
	if (f->name[0] == 0)
		fprintf(stderr, "%s -> empty file name\n", f->path);

	for (i = 0; i < numfids; i++) {
		if (fids[i] == NULL) {
			fids[i] = f;
			break;
		}
	}
	if (i >= numfids) {
		if ((newfids = realloc(fids, (numfids+1)*sizeof(*fids))) == NULL) {
			*err = Enomem;
			return NULL;
		}
		fids = newfids;
		fids[numfids++] = f;
	}

	f->fid = fid;
	stat2qid(&st, &f->qid, &f->iounit);

	return f;
}

static Fid *
findfid(C9fid fid, char **err)
{
	int i;

	for (i = 0; i < numfids; i++) {
		if (fids[i] != NULL && fids[i]->fid == fid) {
			return fids[i];
		}
	}

	*err = Eunknownfid;

	return NULL;
}

static int
delfid(C9fid fid, char **err)
{
	Fid *f;
	int i;

	for (i = 0; i < numfids; i++) {
		f = fids[i];
		if (f != NULL && f->fid == fid) {
			if (f->dir != NULL)
				closedir(f->dir);
			else if (f->fd >= 0)
				close(f->fd);
			free(f->path);
			free(f);
			fids[i] = NULL;
			return 0;
		}
	}

	*err = Eunknownfid;

	return -1;
}

static int
hasperm(struct stat *st, C9mode mode, char **err)
{
	int m, stm, fmt;

	m = mode & 0xf;
	stm = st->st_mode & 0777;
	*err = Eperm;
	if (((stm & 0111) == 0 || (stm & 0444) == 0) && m == C9exec) /* executing needs rx */
		return 0;
	if ((stm & 0222) == 0 && (m == C9write || m == C9rdwr)) /* writing needs w */
		return 0;
	if ((stm & 0444) == 0 && m != C9write) /* reading needs r */
		return 0;
	fmt = st->st_mode & S_IFMT;
	if (fmt == S_IFDIR && ((stm & 0111) == 0 || (stm & 0444) == 0)) /* dirs need rx */
		return 0;
	*err = NULL;

	return 1;
}

static Fid *
walk(C9fid fid, C9fid nfid, char *el[], C9qid *qids[], char **err)
{
	Fid *f;
	char *path, *real, *p;
	struct stat st;
	int i, plen, ellen;

	if ((f = findfid(fid, err)) == NULL)
		return NULL;

	if (el[0] == NULL) { /* nwname = 0 */
		qids[0] = NULL;
		if (fid == nfid)
			return f;
		return newfid(nfid, f->path, err);
	}

	if ((f->qid.type & C9qtdir) == 0) { /* has to be a dir */
		*err = Ewalknodir;
		return NULL;
	}

	p = strdup(f->path);
	f = NULL;
	for (i = 0; el[i] != NULL; i++) {
		plen = strlen(p);
		ellen = strlen(el[i]);
		path = malloc(plen + 1 + ellen + 1);
		memmove(path, p, plen);
		path[plen] = '/';
		memmove(path+plen+1, el[i], ellen);
		path[plen+1+ellen] = 0;

		if (!rootescape) {
			if ((real = realpath(path, NULL)) == NULL)
				break;
			free(path);
			if (strlen(real) < rootlen) { /* don't escape root */
				free(real);
				real = strdup(rootpath);
			}
		} else {
			real = path;
		}

		free(p);
		p = real;

		if (statpath(p, &st, err) != 0)
			break;
		if (el[i+1] != NULL && !hasperm(&st, C9read, err))
			break;

		qids[i] = &walkqids[i];
		stat2qid(&st, qids[i], NULL);
	}

	qids[i] = NULL;
	if (el[i] == NULL) { /* could walk all the way */
		f = newfid(nfid, p, err);
		if (f != NULL && f->name[0] == '/' && f->name[1] == 0) /* root */
			f->name = "/";
	} else if (i != 0) { /* didn't fail on the first one */
		*err = NULL;
	}
	free(p);

	return f;
}

static int
openfid(Fid *f, C9mode mode, char **err)
{
	struct stat st;
	int omode;

	if ((f->qid.type & C9qtdir) != 0) {
		if ((f->dir = opendir(f->path)) == NULL) {
			*err = strerror(errno);
			return -1;
		}
		f->fd = dirfd(f->dir);
	} else {
		omode = O_RDONLY;
		if ((f->qid.type & C9qtappend) != 0)
			omode |= O_APPEND;
		f->fd = open(f->path, omode);
	}

	if (f->fd < 0 || fstat(f->fd, &st) != 0 || !hasperm(&st, mode, err)) {
		if (*err == NULL)
			*err = strerror(errno);

		if (f->dir != NULL)
			closedir(f->dir);
		else if (f->fd >= 0)
			close(f->fd);

		f->dir = NULL;
		f->fd = -1;
		return -1;
	}
	stat2qid(&st, &f->qid, &f->iounit);
	f->mode = mode;

	return 0;
}

static char *
uid2str(uid_t uid, char **err)
{
	struct passwd *p;
	Id *newuids;
	int i;

	for (i = 0; i < numuids; i++) {
		if (uids[i].id == uid)
			return uids[i].name;
	}
	if ((p = getpwuid(uid)) == NULL) {
		*err = strerror(errno);
		return NULL;
	}
	if ((newuids = realloc(uids, sizeof(*uids)*(numuids+1))) == NULL) {
		*err = Enomem;
		return NULL;
	}
	uids = newuids;
	uids[numuids].id = uid;
	uids[numuids].name = strdup(p->pw_name);

	return uids[numuids++].name;
}

static char *
gid2str(gid_t gid, char **err)
{
	struct group *g;
	Id *newgids;
	int i;

	for (i = 0; i < numgids; i++) {
		if (gids[i].id == gid)
			return gids[i].name;
	}
	if ((g = getgrgid(gid)) == NULL) {
		*err = strerror(errno);
		return NULL;
	}
	if ((newgids = realloc(gids, sizeof(*gids)*(numgids+1))) == NULL) {
		*err = Enomem;
		return NULL;
	}
	gids = newgids;
	gids[numgids].id = gid;
	gids[numgids].name = strdup(g->gr_name);

	return gids[numgids++].name;
}

static int
stat2c9stat(char *name, struct stat *st, C9stat *stout, char **err)
{
	int fmt;

	memset(stout, 0, sizeof(*stout));
	stout->size = st->st_size;
	stat2qid(st, &stout->qid, NULL);
	stout->name = name;
	stout->atime = st->st_atime;
	stout->mtime = st->st_ctime;

	fmt = st->st_mode & S_IFMT;
	if (fmt == S_IFDIR)
		stout->mode |= C9stdir;
	if (fmt == S_IFCHR || fmt == S_IFCHR || fmt == S_IFSOCK || fmt == S_IFIFO)
		stout->mode |= C9stappend;
	stout->mode |= st->st_mode & 0x1ff;
	if ((stout->uid = uid2str(st->st_uid, err)) == NULL)
		return -1;
	if ((stout->gid = gid2str(st->st_gid, err)) == NULL)
		return -1;

	return 0;
}

static int
statfid(Fid *f, C9stat *stout, char **err)
{
	struct stat st;
	int r;

	if (f->fd >= 0)
		r = fstat(f->fd, &st);
	else
		r = stat(f->path, &st);
	if (r != 0) {
		*err = strerror(errno);
		return -1;
	}

	return stat2c9stat(f->name, &st, stout, err);
}

static uint8_t *
ctxread(C9ctx *c, uint32_t size, int *err)
{
	uint32_t n;
	int r;

	used(c);
	r = 0;
	*err = 0;
	for (n = 0; n < size; n += r) {
		errno = 0;
		if ((r = read(in, rdbuf+n, size-n)) <= 0) {
			if (r == EINTR)
				continue;
			if (r == 0) {
				eof = 1;
			} else {
				*err = 1;
				perror("ctxread");
			}
			return NULL;
		}
	}

	return rdbuf;
}

static uint8_t *
ctxbegin(C9ctx *c, uint32_t size)
{
	uint8_t *b;

	used(c);
	if (wroff + size > wrbufsz) {
		if (wrsend() != 0 || wroff + size > wrbufsz)
			return NULL;
	}
	b = wrbuf + wroff;
	wroff += size;

	return b;
}

static int
ctxend(C9ctx *c)
{
	used(c);
	wrend = wroff;
	return 0;
}

__attribute__ ((format (printf, 1, 2)))
static void
ctxerror(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vfprintf(stderr,  fmt, ap);
	fprintf(stderr,  "\n");
	va_end(ap);
}

static int
s9do(C9error e, char **err)
{
	if (e == 0) {
		*err = NULL;
		return 0;
	}

	switch (e) {
	case C9Einit: *err = "c9: initialization failed"; break;
	case C9Ever: *err = "c9: protocol version doesn't match"; break;
	case C9Epkt: *err = "c9: incoming packet error"; break;
	case C9Etag: *err = "c9: no free tags or bad tag"; break;
	case C9Ebuf: *err = Enomem; break;
	case C9Epath: *err = "c9: path is too long or just invalid"; break;
	case C9Eflush: *err = "c9: limit of outstanding flushes reached"; break;
	case C9Esize: *err = "c9: can't fit data in one message"; break;
	case C9Estr: *err = "c9: bad string"; break;
	default: *err = "c9: unknown error"; break;
	}

	return -1;
}

static int
readf(C9ctx *c, C9tag tag, Fid *f, uint64_t offset, uint32_t size, char **err)
{
	struct stat st;
	void *p;
	struct dirent *e;
	ssize_t n;
	C9stat c9st[16], *c9stp[16];
	long dirpos[16];
	int i, num, res;

	if (size > c->msize - 12) /* make sure it fits */
		size = c->msize - 12;

	if (f->dir == NULL) { /* a file */
		if ((p = malloc(size)) == NULL) {
			*err = Enomem;
			return -1;
		}
		if ((n = pread(f->fd, p, size, offset)) < 0) {
			*err = strerror(errno);
			free(p);
			return -1;
		}
		res = s9do(s9read(c, tag, p, n), err);
		free(p);
		if (res != 0)
			return -1;
		trace("<- Rread tag=%d count=%zd data=...\n", tag, n);
		return 0;
	}

	/* dir */
	if (offset != f->diroffset) {
		if (offset == 0) {
			rewinddir(f->dir);
			f->diroffset = 0;
		} else {
			*err = Ebadoffset;
			return -1;
		}
	}

	res = 0;
	num = 0;
	for (i = 0; i < nelem(c9st); i++) {
		dirpos[i] = telldir(f->dir); /* so we can rewind in case another stat doesn't fit */

		errno = 0;
		if ((e = readdir(f->dir)) == NULL && errno != 0) {
			*err = strerror(errno);
			res = -1;
			goto done;
		}
		if (e == NULL) /* eof */
			break;
		if (e->d_name[0] == '.' && (e->d_name[1] == 0 || ((e->d_name[1] == '.' && e->d_name[2] == 0))))
			continue;

		if (fstatat(f->fd, e->d_name, &st, 0) != 0) {
			*err = strerror(errno);
			if (fstatat(f->fd, e->d_name, &st, AT_SYMLINK_NOFOLLOW) != 0) { /* broken symlink, try to stat the link itself */
				res = -1;
				goto done;
			}
		}
		if (stat2c9stat(e->d_name, &st, &c9st[i], err) != 0) {
			res = -1;
			goto done;
		}
		c9st[i].name = strdup(c9st[i].name);
		c9stp[num++] = &c9st[i];
	}

	i = num;
	if (s9do(s9readdir(c, tag, c9stp, &num, &f->diroffset, size), err) != 0) {
		res = -1;
		goto done;
	}
	trace("<- Rread tag=%d count=%"PRIu64" data=...\n", tag, f->diroffset - offset);
	if (i != num)
		seekdir(f->dir, dirpos[num]);

done:
	for (i = 0; i < num; i++)
		free(c9stp[i]->name);
	return res;
}

static void
ctxt(C9ctx *c, C9t *t)
{
	Fid *f;
	C9qid *qids[C9maxpathel+1];
	char *err, *err2;
	C9stat st;
	int i;

	trace("-> %s tag=%d", t2s[t->type-Tversion], t->tag);

	err = NULL;
	if (hastag(t->tag)) {
		err = Eduptag;
	} else {
		switch (t->type){
		case Tversion:
			trace("\n");
			if (s9do(s9version(c), &err) == 0)
				trace("<- Rversion\n");
			break;
		case Tauth:
			trace(" afid=%d uname=\"%s\" aname=\"%s\"\n", t->auth.afid, t->auth.uname, t->auth.aname);
			err = Enoauth;
			break;
		case Tattach:
			trace(" afid=%d fid=%d uname=\"%s\" aname=\"%s\"\n", t->attach.afid, t->fid, t->attach.uname, t->attach.aname);
			if (t->attach.afid != C9nofid) {
				err = Eunknownfid;
			} else if ((f = newfid(t->fid, rootpath, &err)) != NULL) {
				f->name = "/";
				if (s9do(s9attach(c, t->tag, &f->qid), &err) == 0)
					trace("<- Rattach\n");
			}
			break;
		case Tflush:
			trace(" oldtag=%d\n", t->flush.oldtag);
			/* FIXME flush it for realz */
			if (s9do(s9flush(c, t->tag), &err) == 0)
				trace("<- Rflush tag=%d\n", t->tag);
			break;
		case Twalk:
			trace(" fid=%d newfid=%d", t->fid, t->walk.newfid);
			for (i = 0; t->walk.wname[i] != NULL; i++)
				trace(" \"%s\"", t->walk.wname[i]);
			trace("\n");
			walk(t->fid, t->walk.newfid, t->walk.wname, qids, &err);
			if (err == NULL && s9do(s9walk(c, t->tag, qids), &err) == 0) {
				trace("<- Rwalk tag=%d ", t->tag);
				for (i = 0; qids[i] != NULL; i++)
					trace("qid=[path=%"PRIu64" type=0x%02x version=%"PRIu32"] ", qids[i]->path, qids[i]->type, qids[i]->version);
				trace("\n");
			}
			break;
		case Topen:
			trace(" fid=%d mode=0x%02x\n", t->fid, t->open.mode);
			if ((f = findfid(t->fid, &err)) != NULL) {
				if (f->fd >= 0)
					err = Ebotch;
				else if (t->open.mode != C9read && t->open.mode != C9exec)
					err = Eperm;
				else if (t->open.mode != C9read && (f->qid.type & C9qtdir) != 0)
					err = Eisdir;
				else if (openfid(f, t->open.mode, &err) == 0 && s9do(s9open(c, t->tag, &f->qid, f->iounit), &err) == 0)
					trace("<- Ropen tag=%d qid=[path=%"PRIu64" type=0x%02x version=%"PRIu32"] iounit=%d\n", t->tag, f->qid.path, f->qid.type, f->qid.version, f->iounit);
			}
			break;
		case Tcreate:
			trace("...\n");
			err = Enocreate;
			break;
		case Tread:
			trace(" fid=%d offset=%"PRIu64" count=%"PRIu32"\n", t->fid, t->read.offset, t->read.size);
			if ((f = findfid(t->fid, &err)) != NULL) {
				if ((f->dir == NULL && f->fd < 0) || (f->mode & 0xf) == C9write)
					err = Ebotch;
				else if (readf(c, t->tag, f, t->read.offset, t->read.size, &err) != 0)
					trace("readf failed\n");
			}
			break;
		case Twrite:
			trace("...\n");
			err = Enowrite;
			break;
		case Tclunk:
			trace(" fid=%d\n", t->fid);
			if (delfid(t->fid, &err) == 0 && s9do(s9clunk(c, t->tag), &err) == 0)
				trace("<- Rclunk tag=%d\n", t->tag);
			break;
		case Tremove:
			trace("\n");
			err = Eperm;
			break;
		case Tstat:
			trace(" fid=%d\n", t->fid);
			if ((f = findfid(t->fid, &err)) != NULL && statfid(f, &st, &err) == 0 && s9do(s9stat(c, t->tag, &st), &err) == 0)
				trace("<- Rstat tag=%d ...\n", t->tag);
			break;
		case Twstat:
			trace("...\n");
			err = Enowstat;
			break;
		}
	}

	if (err != NULL) {
		if (s9do(s9error(c, t->tag, err), &err2) == 0)
			trace("<- Rerror tag=%d \"%s\"\n", t->tag, err);
		else
			fprintf(stderr,  "s9error: %s\n", err2);
	}
}

static void
sigdebug(int s)
{
	Fid *f;
	int i, n;

	used(s);
	n = 0;
	for (i = 0; i < numfids; i++) {
		f = fids[i];
		if (f == NULL)
			continue;

		fprintf(stderr,  "fid %u ", f->fid);

		if (f->dir != NULL)
			fprintf(stderr,  "open mode=dir ");
		else if (f->fd >= 0)
			fprintf(stderr,  "open mode=%s%s%s ", modes[(f->mode & 0xf)], (f->mode & C9trunc) ? ",trunc" : "", (f->mode & C9rclose) ? ",rclose" : "");

		fprintf(stderr,  "qid=[path=%"PRIu64" type=0x%02x version=%"PRIu32"] iounit=%d ", f->qid.path, f->qid.type, f->qid.version, f->iounit);
		fprintf(stderr,  " %s %s\n", f->path, f->name);
		n++;
	}

	fprintf(stderr,  "fids\t%d\n", n);
	fprintf(stderr,  "tags\t%d\n", numtags);
	fprintf(stderr,  "uids\t%d\n", numuids);
	fprintf(stderr,  "gids\t%d\n", numgids);
}

int
fs_main(char *dir)
{
	char *err;
	Fid *f;

	struct sigaction sa;
	int can, i, rdonly, block;

/* FLAGS */
	debug = 1;


	if (dir == NULL) {
		fprintf(stderr,  "no dir specified\n");
		return 1;
	}

	if ((rootpath = realpath(dir, NULL)) == NULL) {
		trace("%s: %s\n", dir, strerror(errno));
		return 1;
	}
	rootlen = strlen(rootpath);

	in = 0;
	out = 1;
	eof = 0;
	fids = NULL;
	numfids = 0;
	tags = NULL;
	numtags = 0;
	uids = NULL;
	numuids = 0;
	gids = NULL;
	numgids = 0;

	memset(&ctx, 0, sizeof(ctx));
	ctx.msize = 64*1024;
	ctx.read = ctxread;
	ctx.begin = ctxbegin;
	ctx.end = ctxend;
	ctx.t = ctxt;
	ctx.error = ctxerror;

	rdbuf = calloc(1, ctx.msize);
	wrbufsz = ctx.msize;
	wrbuf = calloc(1, wrbufsz);
	wroff = wrend = 0;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = SIG_IGN;
	sa.sa_flags = SA_RESTART;
	sigaction(SIGPIPE, &sa, NULL);

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sigdebug;
	sa.sa_flags = SA_RESTART;
	sigfillset(&sa.sa_mask);
	sigaction(SIGUSR1, &sa, NULL);

	err = NULL;
	rdonly = block = 1; /* at first we wait until the client sends in data */
	for (; !eof;) {
		if ((can = canrw(rdonly, block)) < 0)
			break;
		if ((can & Canrd) != 0) { /* if there is data, process it */
			if (s9do(s9proc(&ctx), &err) != 0)
				break;
			/* give it a chance to receive all the data first */
			rdonly = 1;
			block = 0;
		} else if (block == 0) { /* got all the data */
			if (rdonly != 0) { /* wait until we can send OR we get more data */
				rdonly = 0;
				block = 1;
			}
		} else if (rdonly == 0 && (can & Canwr) != 0) { /* can send */
			if (wrsend() != 0) /* send all the data */
				break;
			rdonly = 1; /* and go back to reading */
			block = 1;
		}
	}

	if (err != NULL)
		trace("s9proc: %s\n", err);

	for (i = 0; i < numfids; i++) {
		if ((f = fids[i]) != NULL) {
			if (f->dir != NULL)
				closedir(f->dir);
			else if (f->fd >= 0)
				close(f->fd);
			free(f->path);
			free(f);
		}
	}

	for (i = 0; i < numuids; i++)
		free(uids[i].name);
	free(uids);
	for (i = 0; i < numgids; i++)
		free(gids[i].name);
	free(gids);

	memset(wrbuf, 0, ctx.msize);
	free(wrbuf);
	memset(rdbuf, 0, ctx.msize);
	free(rdbuf);
	free(fids);
	free(rootpath);

	return 0;
}
