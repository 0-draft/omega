//go:build darwin || freebsd || netbsd || openbsd || dragonfly

package attestor

import "golang.org/x/sys/unix"

// getPeerCreds returns (uid, gid) of the peer connected to the unix socket fd.
//
// Darwin/BSD don't expose SO_PEERCRED. Instead we read the kernel-attested
// peer credentials via getsockopt(SOL_LOCAL, LOCAL_PEERCRED) which returns
// an xucred struct. xucred carries the effective UID and a list of GIDs;
// we surface the first GID as the peer GID for symmetry with Linux ucred.
func getPeerCreds(fd int) (uid, gid uint32, err error) {
	xu, err := unix.GetsockoptXucred(fd, unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	if err != nil {
		return 0, 0, err
	}
	uid = xu.Uid
	if xu.Ngroups > 0 {
		gid = xu.Groups[0]
	}
	return uid, gid, nil
}
