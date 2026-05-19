//go:build windows

package signverify

import (
	"fmt"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// In-process WinVerifyTrust via wintrust.dll (no child process or PowerShell).
// https://gist.github.com/heaths/ebbca7d956f0b42bbb33193f0837e272
//
// System binaries under \Windows\ are often catalog-signed, not embedded-signed;
// filterOSPaths skips them to avoid false positives.

type wtdUI uint32
type wtdRevoke uint32
type wtdChoice uint32
type wtdStateAction uint32
type wtdFlags uint32
type wtdUIContext uint32

const (
	invalidHandleValue syscall.Handle = ^syscall.Handle(0)

	wtdUINone     wtdUI = 2
	wtdRevokeNone wtdRevoke = 0
	wtdChoiceFile wtdChoice = 1

	wtdStateVerify wtdStateAction = 1
	wtdStateClose  wtdStateAction = 2

	wtdRevocationCheckNone wtdFlags = 16

	trustENoSignature int32 = -2146762496 // TRUST_E_NOSIGNATURE (0x800B0100)
)

var (
	modWintrust = windows.NewLazySystemDLL("wintrust.dll")
	procVerify  = modWintrust.NewProc("WinVerifyTrust")

	actionGenericVerifyV2 = windows.GUID{
		Data1: 0xaac56b,
		Data2: 0xcd44,
		Data3: 0x11d0,
		Data4: [8]byte{0x8c, 0xc2, 0x00, 0xc0, 0x4f, 0xc2, 0x95, 0xee},
	}
)

type winTrustFileInfo struct {
	cbStruct       uint32
	pcwszFilePath  *uint16
	hFile          syscall.Handle
	pgKnownSubject *windows.GUID
}

type winTrustData struct {
	cbStruct             uint32
	pPolicyCallbackData  uintptr
	pSIPClientData       uintptr
	dwUIChoice           wtdUI
	fdwRevocationChecks  wtdRevoke
	dwUnionChoice        wtdChoice
	pFile                *winTrustFileInfo
	dwStateAction        wtdStateAction
	hWVTStateData        syscall.Handle
	pwszURLReference     *uint16
	dwProvFlags          wtdFlags
	dwUIContext          wtdUIContext
}

// IsUnsigned reports no embedded Authenticode signature.
// Catalog-signed files under \Windows\ are skipped (see filterOSPaths).
func IsUnsigned(path string) (bool, error) {
	if path == "" {
		return false, fmt.Errorf("signverify: empty path")
	}
	if filterOSPaths(path) {
		return false, nil
	}

	ret, err := verifyEmbedded(path)
	if err != nil {
		return false, err
	}
	return ret == trustENoSignature, nil
}

func verifyEmbedded(path string) (int32, error) {
	pathUTF16, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}

	fileInfo := &winTrustFileInfo{
		cbStruct:      uint32(unsafe.Sizeof(winTrustFileInfo{})),
		pcwszFilePath: pathUTF16,
	}

	data := &winTrustData{
		cbStruct:            uint32(unsafe.Sizeof(winTrustData{})),
		dwUIChoice:          wtdUINone,
		fdwRevocationChecks: wtdRevokeNone,
		dwUnionChoice:       wtdChoiceFile,
		pFile:               fileInfo,
		dwStateAction:       wtdStateVerify,
		dwProvFlags:         wtdRevocationCheckNone,
	}

	ret := callWinVerifyTrust(data)

	data.dwStateAction = wtdStateClose
	data.hWVTStateData = 0
	_ = callWinVerifyTrust(data)

	return ret, nil
}

func filterOSPaths(path string) bool {
	p := strings.ToLower(filepath.Clean(path))
	return strings.Contains(p, `\windows\`)
}

func callWinVerifyTrust(data *winTrustData) int32 {
	r0, _, _ := procVerify.Call(
		uintptr(invalidHandleValue),
		uintptr(unsafe.Pointer(&actionGenericVerifyV2)),
		uintptr(unsafe.Pointer(data)),
	)
	return int32(r0)
}

// MustLoad ensures wintrust.dll is available.
func MustLoad() error {
	return modWintrust.Load()
}
