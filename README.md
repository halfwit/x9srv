# x9srv

__*THIS IS A WORK IN PROGRESS *__

x9srv emulates srv and tlssrv from 9front, on POSIX systems.
The cputype will be set to $unix

## Building

Requires plan9port

```/bin/rc
mk && mk install
```

## Usage

`x9srv [-nd] [-k keypattern] [-x x9dev port] [dir]`
`x9tlssrv[-nd] [-k keypattern] [-x x9dev port] [dir]`

- `-n` reject all authentication attempts
- `-x` if specified, listens for incoming devdraw commands from plan9port binaries/x9dev
- `-k` if specified, select the key used for authentication
- `[dir]` is an optional path to chroot all reads and writes in. By default, it uses $PLAN9. It will be consulted first for a file lookup.

```/bin/rc
# Using plan9port's listen
listen1 -t 'tcp!*!564' x9srv /path/to/chroot

# Use TLS + dp9ik
listen1 -t 'tcp!*!17019' x9tlssrv /path/to/chroot

# With x9dev in your $PATH
listen1 -t 'tcp!*!17019' x9tlssrv -x /path/to/chroot
```
