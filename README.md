# x9srv

* __*THIS IS A WORK IN PROGRESS *__

x9srv provides authsrv, bind, tlssrv, cpu and exportfs, suitable for interacting with 9front

libmp, libsec, libauthsrv are adapted from 9front and Aiju's code in [jsdrawterm](https://github.com/aiju/jsdrawterm)

libc9 is from sigrid's [c9](https://sr.ht/~ft/c9)

libexportfs is a statically linked lib pulled from 9front's drawterm. It was linked against amd64

## Building

Requires plan9port

```/bin/rc
mk all && mk install
```

### authsrv

authsrv expects there to be at least the following files and directories in the chroot:

* `/lib/ndb/auth`
* `/adm/$user`
* `/adm/$user/secret`
* `/adm/$user/key`

You can use `passtokey` from [authsrv9](https://github.com/mjl-/authsrv9) to generate keys, following the guide at https://www.ueber.net/who/mjl/plan9/plan9-obsd.html
This is an incomplete version of authsrv, but should suffice for simple file shares and sessions.

### exportfs

See [exportfs(4)](http://man.cat-v.org/9front/4/exportfs)

### tlssrv, tlsclient

See [tlssrv(8)](http://man.cat-v.org/9front/8/tlssrv)

## Usage

```/bin/rc
listen1 -t 'tcp!*!564' exportfs

# Start a normal cpu listener
listen1 -t 'tcp!*!17010' cpu -R

# Start an authsrv listener
listen1 -t 'tcp!*!567' authsrv
```

### rcpu listener setup - probably broken

```/bin/rc
#!/bin/rc

fn server {
	# WIP!
	tmp=`{mktemp -d}
	$PLAN9/bin/disk/mkfs -d $tmp /path/to/a/proto

	# Try to chroot and read commands from the remote connection
	/usr/sbin/chroot $tmp /bin/rc <{n=`{read} && ! ~ $#n 0 && read -c $n} >[2=]
}

listen1 -t 'tcp!*!17019' tlssrv -a /bin/rc -c server
```

