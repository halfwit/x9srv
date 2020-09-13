# x9srv


***This is a work in progress ***

x9srv emulates srv and rvtls from 9front, on POSIX systems.

The cputype will be set to $unix

## Usage

`x9srv [-nd] [-k keypattern] [-x x9dev port] [dir]`
`x9srvtls[-nd] [-k keypattern] [-x x9dev port] [dir]`

- `-n` reject all authentication attempts
- `-x` if specified, listens on the provided port for commands from x9dev, and passes them along to the client /dev
- `-k` if specified, select the key used for authentication
- `[dir]` is an optional path to chroot all reads and writes in. By default, it uses $PLAN9. It will be consulted first for a file lookup.

```/bin/rc
# Using plan9port's listen
listen1 -t 'tcp!*!564' x9srv /path/to/chroot

# Use TLS + dp9ik
listen1 -t 'tcp!*!17019' x9srvtls

# With x9dev in your $PATH
listen1 -t 'tcp!*!17019' x9srvtls -x 49072 
```
