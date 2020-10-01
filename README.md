# x9srv

* __*THIS IS A WORK IN PROGRESS *__

x9srv provides authsrv, bind, tlssrv, cpu and exportfs, suitable for interacting with 9front

libmp, libsec, libauthsrv are adapted from 9front and Aiju's code in [jsdrawterm](https://github.com/aiju/jsdrawterm)

## Building

Requires plan9port - __* currently, exportfs is the only thing fully functional! *__

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

# WIP!
# Assuming X9SRV is set to where our binaries are
tmp=`{mktemp -d}
unionfs $X9SRV=RO:$PLAN9=RO $tmp

fn server {
	. <{n=`{read} && ! ~ $#n 0 && read -c $n} >[2=]
}

/usr/sbin/chroot $tmp /bin/sh << EOF
listen1 -t -v 'tcp!*!17019' tlssrv -a /bin/rc -c server
EOF
```

