//go:build !(darwin || linux)

package sing_tun

import "os"

func getTunnelName(_ int32) (string, error) {
	return "", os.ErrInvalid
}
