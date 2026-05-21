//go:build windows

package privileges

import (
	"os"
	"os/exec"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

func IsLocalAdministrator() (bool, error) {
	username := os.Getenv("USERNAME")
	if username == "" {
		return false, nil
	}

	out, err := exec.Command("net", "localgroup", "administrators").Output()
	if err != nil {
		return false, err
	}

	inMembers := false
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.EqualFold(line, "Members") {
			inMembers = true
			continue
		}
		if !inMembers {
			continue
		}
		if strings.HasPrefix(line, "The command completed") {
			break
		}
		if strings.EqualFold(line, username) {
			return true, nil
		}
	}

	return false, nil
}

func IsLocalSystem() (bool, error) {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token); err != nil {
		return false, err
	}
	defer token.Close()

	user, err := token.GetTokenUser()
	if err != nil {
		return false, err
	}

	systemSID, err := windows.StringToSid("S-1-5-18")
	if err != nil {
		return false, err
	}

	return windows.EqualSid(user.User.Sid, systemSID), nil
}

func IsElevated() (bool, error) {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token); err != nil {
		return false, err
	}
	defer token.Close()

	var elevation uint32
	returnSize := uint32(0)
	err := windows.GetTokenInformation(
		token,
		windows.TokenElevation,
		(*byte)(unsafe.Pointer(&elevation)),
		uint32(unsafe.Sizeof(elevation)),
		&returnSize,
	)
	if err != nil {
		return false, err
	}
	return elevation != 0, nil
}
