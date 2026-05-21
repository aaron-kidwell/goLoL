//go:build !windows

package privileges

func IsLocalAdministrator() (bool, error) {
	return false, nil
}

func IsLocalSystem() (bool, error) {
	return false, nil
}

func IsElevated() (bool, error) {
	return false, nil
}
