# x9srv

* __*THIS IS A WORK IN PROGRESS *__

x9srv provides authsrv, tlssrv, cpu and exportfs, suitable for interacting with 9front
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

### cpu

See [cpu(1)](http://man.cat-v.org/9front/1/cpu)

### exportfs

See [exportfs(4)](http://man.cat-v.org/9front/4/exportfs)

### tlssrv, tlsclient

See [tlssrv(8)](http://man.cat-v.org/9front/8/tlssrv)

## Usage

* Currently, the binaries only act in server mode.

Add entries to your [inetd](https://www.freebsd.org/doc/handbook/network-inetd.html) as required, such as

```conf
# tlssrv for a cpu listener should be started from a listen1
192.168.1.189:564   stream  tcp nowait  root    /usr/sbin/chroot chroot /path/to/chroot /bin/exportfs -r /
192.168.1.189:567   stream  tcp nowait  root    /usr/sbin/chroot chroot /path/to/chroot /bin/auth/authsrv
192.168.1.188:17010 stream  tcp nowait  root    /usr/sbin/chroot chroot /path/to/chroot /bin/cpu -R
```

Or you can use listen1 from plan9port

```/bin/rc
# Serve your chroot on the network
listen1 -t 'tcp!*!564' exportfs -r /

# Start a normal cpu listener
listen1 -t 'tcp!*!17010' cpu -R

# Listen for incoming rcpu connections
fn server {
    . <{n=`{read} && ! ~ $#n 0 && read -c $n} >[2=1]
}

listen1 -t 'tcp!*!17019' tlssrv -a /bin/rc -c server

# Start an authsrv listener
listen1 -t 'tcp!*!567' authsrv
```
