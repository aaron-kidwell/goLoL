//go:build !windows

package signverify

import "errors"

func IsUnsigned(path string) (bool, error) {
	return false, errors.New("signverify: windows only")
}

func MustLoad() error {
	return errors.New("signverify: windows only")
}
