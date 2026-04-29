//go:build linux

package attestor

import "golang.org/x/sys/unix"

// getPeerCreds returns (uid, gid) of the peer connected to the unix socket fd.
func getPeerCreds(fd int) (uid, gid uint32, err error) {
	cred, err := unix.GetsockoptUcred(fd, unix.SOL_SOCKET, unix.SO_PEERCRED)
	if err != nil {
		return 0, 0, err
	}
	return cred.Uid, cred.Gid, nil
}
